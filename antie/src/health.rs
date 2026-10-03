//! ANTIE health endpoint — lightweight HTTP server for monitoring.
//!
//! Serves:
//! - `GET /health` -> `{"ok":B,"lambda_alive":B,"stalled":[…],"oldest_heartbeat_age_secs":N,
//!   "uptime_secs":N,"carriers_in_backoff":N,"carrier_consecutive_failures":N,
//!   "carrier_failures_total":N}` (always accessible, no auth; the carrier
//!   gauges are KI#141). **`ok = lambda_alive && no loop is stalled`** (KI#114,
//!   owner ruling 2026-10-01: NOT-OK on ANY stalled loop, naming it) — see
//!   [`health_verdict`]. ~~`ok = lambda_alive`~~ (KI#80 alone) read GREEN for
//!   11.5 h while zeta's ANTIE spun serving nothing (KI#114, 2026-08-26).
//! - `GET /status` -> Full stats JSON (from AntieStats)

use crate::config::OnStall;
use crate::stats::{AntieStats, HeartbeatSnapshot};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

/// KI#114 — the exit code of an `on_stall = "notify_and_restart"` exit, so a
/// supervisor log tells a stall restart from a crash.
pub const STALL_EXIT_CODE: i32 = 75;

/// KI#114 — the `/health` verdict at one instant. Pure; table-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub ok: bool,
    pub lambda_alive: bool,
    /// Every loop whose heartbeat is older than its bound, as `"<name> <age>s"`.
    pub stalled: Vec<String>,
    /// The oldest heartbeat's age (0 when no loop is registered).
    pub oldest_heartbeat_age_secs: u64,
}

/// KI#114 (b) — progress, not presence: `ok` iff the Lambda child is alive
/// (KI#80) AND no registered loop has been silent past its bound. ANY stalled
/// loop flips `ok` and is named (owner ruling 2026-10-01 — a stall can only be
/// an ANTIE defect once every carrier step is bounded, unlike a KI#141 backoff,
/// which keeps beating and only degrades a leg). A witness call to Lambda has
/// NO time limit (owner ruling); a hung one shows here as a stalled `dispatch`.
pub fn health_verdict(lambda_alive: bool, beats: &[HeartbeatSnapshot]) -> Verdict {
    let stalled: Vec<String> = beats.iter()
        .filter(|b| b.age_secs > b.max_silence_secs)
        .map(|b| format!("{} {}s", b.name, b.age_secs))
        .collect();
    Verdict {
        ok: lambda_alive && stalled.is_empty(),
        lambda_alive,
        stalled,
        oldest_heartbeat_age_secs: beats.iter().map(|b| b.age_secs).max().unwrap_or(0),
    }
}

/// The `/health` JSON for `stats` at its current heartbeat time.
pub fn health_body(stats: &AntieStats, lambda_alive: bool) -> (Verdict, String) {
    let v = health_verdict(lambda_alive, &stats.heartbeat_snapshot(stats.mono_now_secs()));
    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(stats.started_at);
    let o = std::sync::atomic::Ordering::Relaxed;
    let body = serde_json::json!({
        "ok": v.ok,
        "lambda_alive": v.lambda_alive,
        "stalled": v.stalled,
        "oldest_heartbeat_age_secs": v.oldest_heartbeat_age_secs,
        "uptime_secs": uptime,
        // KI#141 gauges — a provider refusing this host. NOT a liveness signal
        // (blind to a wedge, KI#114); `stalled` is.
        "carriers_in_backoff": stats.carriers_in_backoff.load(o),
        "carrier_consecutive_failures": stats.carrier_consecutive_failures.load(o),
        "carrier_failures_total": stats.carrier_failures_total.load(o),
    }).to_string();
    (v, body)
}

/// KI#114 — one pass of the stall watchdog (the gateway runs it every
/// `STALL_WATCH_INTERVAL`). A loop that is NEWLY stalled is logged at ERROR,
/// named (once per stall — `reported` remembers it until it recovers); with
/// `OnStall::NotifyAndRestart` the watchdog then calls `exit(STALL_EXIT_CODE)`
/// so the supervisor restarts ANTIE. `exit` is injected so tests never exit.
/// Returns the loops newly reported this pass.
pub fn stall_watchdog_tick(
    verdict: &Verdict,
    policy: OnStall,
    reported: &mut Vec<String>,
    exit: &dyn Fn(i32),
) -> Vec<String> {
    let name_of = |s: &String| s.rsplit_once(' ').map(|(n, _)| n.to_string()).unwrap_or_else(|| s.clone());
    let now_stalled: Vec<String> = verdict.stalled.iter().map(name_of).collect();
    reported.retain(|n| now_stalled.contains(n)); // recovered loops may report again
    let mut fresh = Vec::new();
    for (name, full) in now_stalled.iter().zip(verdict.stalled.iter()) {
        if !reported.contains(name) {
            tracing::error!(
                "[KI#114] ANTIE loop STALLED: {} (no progress past its bound) — /health is ok:false; \
                 on_stall = {:?}", full, policy);
            reported.push(name.clone());
            fresh.push(name.clone());
        }
    }
    if !fresh.is_empty() && policy == OnStall::NotifyAndRestart {
        tracing::error!("[KI#114] on_stall = notify_and_restart — exiting {} so the supervisor restarts ANTIE",
            STALL_EXIT_CODE);
        exit(STALL_EXIT_CODE);
    }
    fresh
}

/// Extract a query parameter value from a query string.
fn extract_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&')
        .find(|p| p.starts_with(key) && p.as_bytes().get(key.len()) == Some(&b'='))
        .map(|p| &p[key.len() + 1..])
}

/// Build a dual-format JSON error body (Phase 2c.3). The legacy
/// `error` string is preserved verbatim for existing clients; the
/// `error_response` object carries the structured wire format.
/// Factored out of the main request handler so it's unit-testable.
fn dual_format_error_body(
    code: &'static str,
    category: axiom_errors::ErrorCategory,
    message: &str,
) -> String {
    let resp = axiom_errors::ErrorResponse::new(
        axiom_errors::ErrorCode::from_static(code),
        category,
        message.to_string(),
    );
    serde_json::json!({
        "error": message,
        "error_response": resp,
    })
    .to_string()
}

/// Check bearer token auth. /health always allowed; other endpoints require token if configured.
fn check_auth(path: &str, query: Option<&str>, auth_token: &Option<String>) -> bool {
    if path == "/health" {
        return true;
    }
    let expected = match auth_token {
        Some(t) => t,
        None => return true,
    };
    matches!(query.and_then(|q| extract_query_param(q, "token")), Some(t) if t == expected)
}

/// Spawn the health endpoint on the given port.
/// Returns a JoinHandle that runs until dropped/cancelled.
///
/// `lambda_alive` is the KI#80 liveness flag maintained by the lambda
/// supervision loop: ANTIE's whole job is fronting its lambda, so a
/// validator with no live lambda must NOT read `ok: true` — that is
/// exactly the blind spot that let a lambda-less gamma serve
/// "healthy" for 28 minutes (2026-08-08 soak).
pub fn spawn_health_server(
    port: u16,
    stats: Arc<AntieStats>,
    auth_token: Option<String>,
    lambda_alive: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let addr = format!("127.0.0.1:{}", port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => {
                tracing::info!("Health endpoint listening on {}", addr);
                l
            }
            Err(e) => {
                warn!("Health endpoint failed to bind to {}: {}", addr, e);
                return;
            }
        };

        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let stats = stats.clone();
            let auth_token = auth_token.clone();
            let lambda_alive = lambda_alive.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    stream.read(&mut buf),
                ).await {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                };

                let request = String::from_utf8_lossy(&buf[..n]);
                let first_line = request.lines().next().unwrap_or("");

                // Extract path and query from "GET /path?query HTTP/1.1"
                let uri = first_line.split_whitespace().nth(1).unwrap_or("/");
                let (path, query) = if let Some(pos) = uri.find('?') {
                    (&uri[..pos], Some(&uri[pos + 1..]))
                } else {
                    (uri, None)
                };

                let (status, body) = if !check_auth(path, query, &auth_token) {
                    warn!("Health auth failed from client (path={})", path);
                    (
                        "401 Unauthorized",
                        dual_format_error_body(
                            axiom_errors::error_code::E_ANTIE_UNAUTHORIZED,
                            axiom_errors::ErrorCategory::ClientBug,
                            "unauthorized",
                        ),
                    )
                } else if path == "/health" {
                    // KI#114: `ok` = Lambda alive (KI#80) AND no stalled loop.
                    // Status stays 200 — the ENDPOINT is up; the payload
                    // carries the verdict.
                    let alive = lambda_alive.load(std::sync::atomic::Ordering::SeqCst);
                    ("200 OK", health_body(&stats, alive).1)
                } else if path == "/status" {
                    ("200 OK", String::from_utf8_lossy(&stats.to_json()).to_string())
                } else {
                    (
                        "404 Not Found",
                        dual_format_error_body(
                            axiom_errors::error_code::E_ANTIE_NOT_FOUND,
                            axiom_errors::ErrorCategory::ClientBug,
                            "not found",
                        ),
                    )
                };

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status, body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                debug!("Health request: {} -> {}", first_line, status);
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_endpoint_responds() {
        let stats = Arc::new(AntieStats::new());
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let _handle = spawn_health_server(0, stats.clone(), None, alive); // port 0 = OS picks
        // We can't easily test without knowing the port, but the function compiles
        // and spawns without panicking. Integration test would use a known port.
    }

    /// Phase 2c.3 wire contract: dual_format_error_body emits a JSON
    /// body with both legacy `error` and structured `error_response`.
    #[test]
    fn dual_format_error_body_has_both_fields() {
        let body = dual_format_error_body(
            axiom_errors::error_code::E_ANTIE_UNAUTHORIZED,
            axiom_errors::ErrorCategory::ClientBug,
            "unauthorized",
        );
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .expect("dual_format_error_body MUST emit valid JSON");
        assert_eq!(parsed["error"], "unauthorized");
        let er = &parsed["error_response"];
        assert_eq!(er["version"], 1);
        assert_eq!(er["code"], "E_ANTIE_UNAUTHORIZED");
        assert_eq!(er["category"], "client_bug");
        assert_eq!(er["message"], "unauthorized");
    }

    /// The body deserializes cleanly into an axiom_errors::ErrorResponse.
    #[test]
    fn dual_format_error_body_decodes_to_error_response() {
        let body = dual_format_error_body(
            axiom_errors::error_code::E_ANTIE_NOT_FOUND,
            axiom_errors::ErrorCategory::ClientBug,
            "not found",
        );
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let er: axiom_errors::ErrorResponse =
            serde_json::from_value(parsed["error_response"].clone())
                .expect("error_response must deserialize structurally");
        assert_eq!(er.code.as_str(), "E_ANTIE_NOT_FOUND");
        assert_eq!(er.category, axiom_errors::ErrorCategory::ClientBug);
    }

    #[test]
    fn test_health_auth_no_token_configured() {
        // No token configured => all requests pass
        assert!(check_auth("/health", None, &None));
        assert!(check_auth("/status", None, &None));
        assert!(check_auth("/status", Some("foo=bar"), &None));
    }

    #[test]
    fn test_health_auth_token_configured() {
        let token = Some("secret123".to_string());
        // /health always accessible
        assert!(check_auth("/health", None, &token));
        assert!(check_auth("/health", Some("token=wrong"), &token));
        // /status requires token
        assert!(!check_auth("/status", None, &token));
        assert!(!check_auth("/status", Some("token=wrong"), &token));
        assert!(check_auth("/status", Some("token=secret123"), &token));
        // token with other params
        assert!(check_auth("/status", Some("foo=bar&token=secret123"), &token));
    }

    // ── KI#114 (b) ─────────────────────────────────────────────────────

    fn hb(name: &str, age: u64, max: u64) -> HeartbeatSnapshot {
        HeartbeatSnapshot { name: name.into(), age_secs: age, max_silence_secs: max }
    }

    /// The verdict table. MUTATIONS (run 2026-10-01): `ok: lambda_alive`
    /// (ignore heartbeats) ⇒ red at "one loop past its bound"; `>=` for `>`
    /// ⇒ red at "exactly at the bound".
    #[test]
    fn health_verdict_table() {
        let fresh = [hb("dispatch", 1, 600), hb("imap#0(u@h)", 59, 900)];
        let v = health_verdict(true, &fresh);
        assert!(v.ok && v.stalled.is_empty(), "fresh loops + live Lambda ⇒ ok");
        assert_eq!(v.oldest_heartbeat_age_secs, 59);
        assert!(health_verdict(true, &[hb("dispatch", 600, 600)]).ok, "exactly at the bound is not stalled");
        let v = health_verdict(true, &[hb("dispatch", 2, 600), hb("imap#0(u@h)", 1900, 900)]);
        assert!(!v.ok, "one loop past its bound ⇒ NOT ok (owner ruling: ANY stalled loop)");
        assert_eq!(v.stalled, vec!["imap#0(u@h) 1900s".to_string()], "the stalled loop is NAMED");
        let v = health_verdict(false, &fresh);
        assert!(!v.ok && v.stalled.is_empty(), "Lambda dead ⇒ NOT ok (KI#80, unchanged)");
        assert!(health_verdict(true, &[]).ok, "no loops registered (yet) ⇒ Lambda decides");
    }

    /// `on_stall` — notify_only never exits; notify_and_restart exits with
    /// STALL_EXIT_CODE once per NEW stall (the hook is injected: no real exit).
    /// A recovered loop is forgotten and may report again. MUTATION (run
    /// 2026-10-01): drop the `policy == NotifyAndRestart` condition ⇒ red at
    /// "notify_only never exits".
    #[test]
    fn stall_watchdog_honours_on_stall() {
        let exits = std::sync::Mutex::new(Vec::<i32>::new());
        let exit = |c: i32| exits.lock().unwrap().push(c);
        let stalled = health_verdict(true, &[hb("pop3#1(u@h)", 1000, 900)]);
        let healthy = health_verdict(true, &[hb("pop3#1(u@h)", 3, 900)]);

        let mut reported = Vec::new();
        assert_eq!(stall_watchdog_tick(&stalled, OnStall::NotifyOnly, &mut reported, &exit), vec!["pop3#1(u@h)"]);
        assert!(stall_watchdog_tick(&stalled, OnStall::NotifyOnly, &mut reported, &exit).is_empty(),
            "reported once per stall, not every pass");
        assert!(exits.lock().unwrap().is_empty(), "notify_only never exits");

        let mut reported = Vec::new();
        stall_watchdog_tick(&stalled, OnStall::NotifyAndRestart, &mut reported, &exit);
        assert_eq!(*exits.lock().unwrap(), vec![STALL_EXIT_CODE], "notify_and_restart exits non-zero");
        assert_ne!(STALL_EXIT_CODE, 0);
        stall_watchdog_tick(&healthy, OnStall::NotifyAndRestart, &mut reported, &exit);
        assert!(reported.is_empty(), "a recovered loop is forgotten");
        stall_watchdog_tick(&stalled, OnStall::NotifyAndRestart, &mut reported, &exit);
        assert_eq!(exits.lock().unwrap().len(), 2, "a NEW stall after recovery acts again");
    }

    /// The `on_stall` key: absent ⇒ `notify_only` (an optional key with a
    /// default — never a rewritten operator toml); both spellings parse.
    #[test]
    fn on_stall_parses_and_defaults_to_notify_only() {
        #[derive(serde::Deserialize)]
        struct T { #[serde(default)] on_stall: OnStall }
        let t: T = toml::from_str("").unwrap();
        assert_eq!(t.on_stall, OnStall::NotifyOnly);
        let t: T = toml::from_str("on_stall = \"notify_and_restart\"").unwrap();
        assert_eq!(t.on_stall, OnStall::NotifyAndRestart);
        let t: T = toml::from_str("on_stall = \"notify_only\"").unwrap();
        assert_eq!(t.on_stall, OnStall::NotifyOnly);
        assert!(toml::from_str::<T>("on_stall = \"reboot\"").is_err(), "an unknown policy is refused");
        let c: crate::config::AntieConfig = toml::from_str("").unwrap();
        assert_eq!(c.on_stall, OnStall::NotifyOnly, "AntieConfig: absent key ⇒ notify_only");
    }

    #[test]
    fn test_extract_query_param() {
        assert_eq!(extract_query_param("token=abc", "token"), Some("abc"));
        assert_eq!(extract_query_param("foo=bar&token=xyz", "token"), Some("xyz"));
        assert_eq!(extract_query_param("foo=bar", "token"), None);
        assert_eq!(extract_query_param("tokenizer=bad", "token"), None);
    }
}
