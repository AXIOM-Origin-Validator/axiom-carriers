//! ANTIE health endpoint — lightweight HTTP server for monitoring.
//!
//! Serves:
//! - `GET /health` -> `{"ok":true,"uptime_secs":N}` (always accessible, no auth)
//! - `GET /status` -> Full stats JSON (from AntieStats)

use crate::stats::AntieStats;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

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
pub fn spawn_health_server(port: u16, stats: Arc<AntieStats>, auth_token: Option<String>) -> tokio::task::JoinHandle<()> {
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
                    let uptime = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .saturating_sub(stats.started_at);
                    ("200 OK", format!("{{\"ok\":true,\"uptime_secs\":{}}}", uptime))
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
        let _handle = spawn_health_server(0, stats.clone(), None); // port 0 = OS picks
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

    #[test]
    fn test_extract_query_param() {
        assert_eq!(extract_query_param("token=abc", "token"), Some("abc"));
        assert_eq!(extract_query_param("foo=bar&token=xyz", "token"), Some("xyz"));
        assert_eq!(extract_query_param("foo=bar", "token"), None);
        assert_eq!(extract_query_param("tokenizer=bad", "token"), None);
    }
}
