//! ANTIE metrics counters — thread-safe atomic stats.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// KI#114 (b) — one long-running loop's PROGRESS mark ("progress, not
/// presence"). Each loop beats as it advances (the maildir dispatch loop per
/// pass and per message; each IMAP/POP3 account per fetch, per quiet IDLE
/// slice, per backoff-sleep slice). `/health` derives `ok` from the AGE of every
/// beat at request time (`health::health_verdict`), so a loop that is wedged —
/// spinning, blocked or deadlocked, wherever it is stuck — ages its own beat
/// and flips `ok`, naming itself. Ages are on the monotonic tokio clock
/// (`AntieStats::mono_now_secs`), never the wall clock.
pub struct LoopHeartbeat {
    /// The loop's name as `/health` reports it (`dispatch`, `imap#0(user@host)`…).
    pub name: String,
    /// The longest legitimate silence for this loop; older ⇒ stalled.
    pub max_silence_secs: u64,
    base: tokio::time::Instant,
    last_beat: AtomicU64,
}

impl LoopHeartbeat {
    /// The loop made progress — now.
    pub fn beat(&self) {
        self.last_beat.store(self.base.elapsed().as_secs(), Ordering::Relaxed);
    }
}

/// A heartbeat read at one instant — the input of `health::health_verdict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatSnapshot {
    pub name: String,
    pub age_secs: u64,
    pub max_silence_secs: u64,
}

/// Gateway-wide statistics counters.
pub struct AntieStats {
    pub messages_received: AtomicU64,
    pub messages_processed: AtomicU64,
    pub messages_failed: AtomicU64,
    pub tcp_connections: AtomicU64,
    pub tcp_rate_limited: AtomicU64,
    pub lambda_requests: AtomicU64,
    pub lambda_errors: AtomicU64,
    pub emails_sent: AtomicU64,
    pub started_at: u64,
    /// Comma-separated list of active carrier names (e.g. "maildir,tcp")
    pub active_carriers: std::sync::RwLock<String>,

    // ── YPX-015 Backpressure ──

    /// Last known avg_witness_ms from Lambda /stats (updated by background poller)
    pub avg_witness_ms: AtomicU64,
    /// YPX-015 §2.1: `/stats` reads that failed (refused, unreachable, unparseable).
    /// Non-zero and growing = the busy gate has NO load data — backpressure is off.
    pub lambda_stats_poll_failures: AtomicU64,
    /// YPX-015 §2.1: the Lambda admin port the poller reads — must be THIS
    /// validator's own Lambda. 0 = unknown, the busy gate is NOT armed.
    pub lambda_stats_port: AtomicU64,
    /// Number of requests rejected with E_VALIDATOR_BUSY
    pub busy_rejections: AtomicU64,
    /// Number of requests rejected with E_WALLET_RATE_LIMITED (YPX-015 §2.3)
    pub rate_limited: AtomicU64,
    /// Number of requests rejected with E_WALLET_BANNED (YP §32-33)
    pub ban_rejected: AtomicU64,
    /// YP §32 / KI#228: ban checks that could NOT read the co-located Nabla's
    /// ban file (no path, file absent, unreadable) and let the request through
    /// (best-effort, RULE 7 part 2). Non-zero with no Nabla on this host is
    /// expected; on a co-located host it means the check is not running.
    pub ban_list_unavailable: AtomicU64,
    /// KI#175 (2026-09-25): inbound `fanout_relay` emails REFUSED at the door — a
    /// direct ANTIE→ANTIE hop is not a validator-to-validator channel (YP §28 ruling
    /// 2026-09-21); fan-out must arrive as a wallet-carried transaction. Nothing in
    /// the tree produces one today; non-zero here means someone is sending them.
    pub fanout_relay_refused: AtomicU64,
    /// Number of inbound UmpEnvelope::Encrypted messages that failed to
    /// decrypt (wrong recipient, tampered ciphertext, or sender used
    /// the wrong validator pubkey).  Counter only — no response is sent
    /// (§3.3): leaking "decrypt failed" to internet senders is a small
    /// information leak.
    pub decrypt_fail: AtomicU64,
    /// Inbound emails dropped because parse_email_outcome returned Err
    /// (malformed envelope, bad CBOR, header errors). KI#11 diagnostic.
    pub parse_fail: AtomicU64,
    /// Inbound emails dropped because they exceeded MAX_MESSAGE_BYTES
    /// (8 MB). KI#11 diagnostic — most likely an over-grown FACT chain
    /// in a real client scenario, useful to attribute the drop.
    pub oversize_dropped: AtomicU64,
    /// Core ELF fingerprint (BLAKE3 hash, hex, set at startup)
    pub core_version: std::sync::RwLock<String>,
    /// Number of files currently sitting in ANTIE's `skipped/`
    /// directory (sibling-carrier skip-list contract,
    /// `docs/AXIOM_DESIGN_AntieSkipList.md`). Default monitoring hook
    /// for the no-TTL reference behaviour described in §4 of the
    /// contract — operators alert on growth.
    ///
    /// 0 when the skip-list module is disabled (no `skip_list_path`
    /// or `skipped_dir_path` configured). Refreshed by a background
    /// task in the gateway every 30 seconds; reads from `/status`
    /// see the last-refreshed value, not a live `readdir`.
    pub skipped_dir_count: AtomicU64,

    // ── YPX-024 care-of addressing ──

    /// Receiver-bound artifacts REFUSED delivery because the address
    /// failed the fingerprint verify (care-of inner mismatch, or a plain
    /// `receiver_address` override with a bad checksum). RULE 3: a
    /// rejection needs a counter — this is the §3.1 defence-in-depth
    /// check firing.
    pub care_of_verify_rejects: AtomicU64,
    /// Artifacts deposited into the `[pickup]` directory (SUPPORT path).
    pub care_of_deposits: AtomicU64,
    /// Care-of addresses delivered to the verified inner email instead
    /// (understood, not supported here — the §3.2 default).
    pub care_of_default_deliveries: AtomicU64,

    // ── KI#141 pull-carrier health ──

    /// Pull-carrier (IMAP/POP3) fetches or IDLE sessions that could NOT
    /// reach the server, cumulative since start. RULE 3 §2: a liveness
    /// condition needs a counter, not a `warn!` — this is how "the provider
    /// has refused me for an hour" becomes visible from outside the log.
    pub carrier_failures_total: AtomicU64,
    /// Pull-carrier loops currently in backoff (≥ 1 consecutive failure).
    /// 0 = every declared pull carrier reached its server on its last try.
    pub carriers_in_backoff: AtomicU64,
    /// The longest current consecutive-failure streak across pull carriers
    /// (what the KI#141 backoff is keyed on); 0 when nothing is in backoff.
    /// ⚠ KI#114: these three gauges are BLIND to a wedge — `note_carrier_attempt`
    /// runs only after `idle_wait`/`check_new` RETURN, so a call that never
    /// returns leaves them at 0 ("healthy"). The heartbeats below are what see it.
    pub carrier_consecutive_failures: AtomicU64,

    // ── KI#114 progress surface ──

    /// The monotonic clock every heartbeat is measured on (tokio's, so a test
    /// with a paused clock can advance it).
    mono_base: tokio::time::Instant,
    /// Every registered long-running loop (registered once at spawn).
    heartbeats: std::sync::RwLock<Vec<Arc<LoopHeartbeat>>>,
    /// Wall-clock unix secs a message last ENTERED the inbox funnel — written
    /// by a pull carrier, or first seen in `inbox/new/` by the dispatcher. 0 =
    /// never. For watchers that KNOW traffic exists (a soak): alone it cannot
    /// tell "quiet" from "wedged" — the heartbeats can.
    pub last_inbox_write_unix: AtomicU64,
    /// Wall-clock unix secs a reply (a served round) was last handed to the
    /// outbound carrier. 0 = never. Same caveat as `last_inbox_write_unix`.
    pub last_round_served_unix: AtomicU64,
    /// mtime (unix secs) of the OLDEST file waiting in `maildir/inbox/new/`,
    /// 0 = none waiting; refreshed every 30 s (`inbox_scan_unix` stamps the
    /// last scan so a stale value is detectable, RULE 6). `/status` reports
    /// `inbox_oldest_unprocessed_age_secs` = now − this: work waiting and not
    /// taken is a "serving nothing" signal needing no traffic assumption.
    pub inbox_oldest_unprocessed_mtime_unix: AtomicU64,
    /// Wall-clock unix secs of the last `inbox/new/` scan (0 = never scanned).
    pub inbox_scan_unix: AtomicU64,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl AntieStats {
    /// KI#114 — register a long-running loop (beats once now). Call once when
    /// the loop starts; the loop then calls `beat()` as it progresses.
    pub fn register_heartbeat(&self, name: impl Into<String>, max_silence_secs: u64) -> Arc<LoopHeartbeat> {
        let hb = Arc::new(LoopHeartbeat {
            name: name.into(),
            max_silence_secs,
            base: self.mono_base,
            last_beat: AtomicU64::new(0),
        });
        hb.beat();
        if let Ok(mut v) = self.heartbeats.write() {
            v.push(hb.clone());
        }
        hb
    }

    /// Seconds on the heartbeat clock (monotonic, since this stats object).
    pub fn mono_now_secs(&self) -> u64 {
        self.mono_base.elapsed().as_secs()
    }

    /// Every heartbeat's age at `now` (`mono_now_secs` units).
    pub fn heartbeat_snapshot(&self, now: u64) -> Vec<HeartbeatSnapshot> {
        self.heartbeats.read().map(|v| v.iter().map(|h| HeartbeatSnapshot {
            name: h.name.clone(),
            age_secs: now.saturating_sub(h.last_beat.load(Ordering::Relaxed)),
            max_silence_secs: h.max_silence_secs,
        }).collect()).unwrap_or_default()
    }

    /// Stamp `last_inbox_write_unix` (a message entered the funnel).
    pub fn note_inbox_write(&self) {
        self.last_inbox_write_unix.store(unix_now(), Ordering::Relaxed);
    }

    /// Stamp `last_round_served_unix` (a reply was handed to the outbound carrier).
    pub fn note_round_served(&self) {
        self.last_round_served_unix.store(unix_now(), Ordering::Relaxed);
    }

    /// KI#141 — record one pull-carrier attempt. `failures` is the loop's
    /// own consecutive-failure count (the backoff key); this keeps the
    /// fleet-visible gauges consistent with it. Returns the new streak.
    pub fn note_carrier_attempt(&self, failures: &mut u32, reached: bool) -> u32 {
        if reached {
            if *failures > 0 {
                *failures = 0;
                if self.carriers_in_backoff.fetch_sub(1, Ordering::Relaxed) == 1 {
                    // the last loop left backoff: no streak is current any more
                    self.carrier_consecutive_failures.store(0, Ordering::Relaxed);
                }
            }
        } else {
            if *failures == 0 {
                self.carriers_in_backoff.fetch_add(1, Ordering::Relaxed);
            }
            *failures = failures.saturating_add(1);
            self.carrier_failures_total.fetch_add(1, Ordering::Relaxed);
            self.carrier_consecutive_failures.fetch_max(*failures as u64, Ordering::Relaxed);
        }
        *failures
    }
}

impl Default for AntieStats {
    fn default() -> Self {
        Self::new()
    }
}

impl AntieStats {
    pub fn new() -> Self {
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            messages_received: AtomicU64::new(0),
            messages_processed: AtomicU64::new(0),
            messages_failed: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
            tcp_rate_limited: AtomicU64::new(0),
            lambda_requests: AtomicU64::new(0),
            lambda_errors: AtomicU64::new(0),
            emails_sent: AtomicU64::new(0),
            started_at,
            active_carriers: std::sync::RwLock::new(String::new()),
            avg_witness_ms: AtomicU64::new(0),
            lambda_stats_poll_failures: AtomicU64::new(0),
            lambda_stats_port: AtomicU64::new(0),
            busy_rejections: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            ban_rejected: AtomicU64::new(0),
            ban_list_unavailable: AtomicU64::new(0),
            fanout_relay_refused: AtomicU64::new(0),
            decrypt_fail: AtomicU64::new(0),
            parse_fail: AtomicU64::new(0),
            oversize_dropped: AtomicU64::new(0),
            core_version: std::sync::RwLock::new(String::new()),
            skipped_dir_count: AtomicU64::new(0),
            care_of_verify_rejects: AtomicU64::new(0),
            care_of_deposits: AtomicU64::new(0),
            care_of_default_deliveries: AtomicU64::new(0),
            carrier_failures_total: AtomicU64::new(0),
            carriers_in_backoff: AtomicU64::new(0),
            carrier_consecutive_failures: AtomicU64::new(0),
            mono_base: tokio::time::Instant::now(),
            heartbeats: std::sync::RwLock::new(Vec::new()),
            last_inbox_write_unix: AtomicU64::new(0),
            last_round_served_unix: AtomicU64::new(0),
            inbox_oldest_unprocessed_mtime_unix: AtomicU64::new(0),
            inbox_scan_unix: AtomicU64::new(0),
        }
    }

    /// Serialize current stats to JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.started_at);
        let carriers = self.active_carriers.read()
            .map(|c| c.clone())
            .unwrap_or_default();
        format!(
            concat!(
                "{{",
                "\"uptime_secs\":{},",
                "\"messages_received\":{},",
                "\"messages_processed\":{},",
                "\"messages_failed\":{},",
                "\"tcp_connections\":{},",
                "\"tcp_rate_limited\":{},",
                "\"lambda_requests\":{},",
                "\"lambda_errors\":{},",
                "\"emails_sent\":{},",
                "\"active_carriers\":\"{}\",",
                "\"avg_witness_ms\":{},",
                "\"lambda_stats_poll_failures\":{},",
                "\"lambda_stats_port\":{},",
                "\"busy_rejections\":{},",
                "\"wallet_rate_limited\":{},",
                "\"ban_rejected\":{},",
                "\"ban_list_unavailable\":{},",
                "\"fanout_relay_refused\":{},",
                "\"decrypt_fail\":{},",
                "\"parse_fail\":{},",
                "\"oversize_dropped\":{},",
                "\"core_version\":\"{}\",",
                "\"skipped_dir_count\":{},",
                "\"care_of_verify_rejects\":{},",
                "\"care_of_deposits\":{},",
                "\"care_of_default_deliveries\":{},",
                "\"carrier_failures_total\":{},",
                "\"carriers_in_backoff\":{},",
                "\"carrier_consecutive_failures\":{},",
                "\"carrier_eof_mid_response\":{},",
                "\"last_inbox_write_unix\":{},",
                "\"last_round_served_unix\":{},",
                "\"inbox_oldest_unprocessed_age_secs\":{},",
                "\"inbox_scan_unix\":{}",
                "}}"
            ),
            uptime,
            self.messages_received.load(Ordering::Relaxed),
            self.messages_processed.load(Ordering::Relaxed),
            self.messages_failed.load(Ordering::Relaxed),
            self.tcp_connections.load(Ordering::Relaxed),
            self.tcp_rate_limited.load(Ordering::Relaxed),
            self.lambda_requests.load(Ordering::Relaxed),
            self.lambda_errors.load(Ordering::Relaxed),
            self.emails_sent.load(Ordering::Relaxed),
            carriers,
            self.avg_witness_ms.load(Ordering::Relaxed),
            self.lambda_stats_poll_failures.load(Ordering::Relaxed),
            self.lambda_stats_port.load(Ordering::Relaxed),
            self.busy_rejections.load(Ordering::Relaxed),
            self.rate_limited.load(Ordering::Relaxed),
            self.ban_rejected.load(Ordering::Relaxed),
            self.ban_list_unavailable.load(Ordering::Relaxed),
            self.fanout_relay_refused.load(Ordering::Relaxed),
            self.decrypt_fail.load(Ordering::Relaxed),
            self.parse_fail.load(Ordering::Relaxed),
            self.oversize_dropped.load(Ordering::Relaxed),
            self.core_version.read().map(|v| v.clone()).unwrap_or_default(),
            self.skipped_dir_count.load(Ordering::Relaxed),
            self.care_of_verify_rejects.load(Ordering::Relaxed),
            self.care_of_deposits.load(Ordering::Relaxed),
            self.care_of_default_deliveries.load(Ordering::Relaxed),
            self.carrier_failures_total.load(Ordering::Relaxed),
            self.carriers_in_backoff.load(Ordering::Relaxed),
            self.carrier_consecutive_failures.load(Ordering::Relaxed),
            crate::carrier::carrier_io::eof_mid_response(),
            self.last_inbox_write_unix.load(Ordering::Relaxed),
            self.last_round_served_unix.load(Ordering::Relaxed),
            match self.inbox_oldest_unprocessed_mtime_unix.load(Ordering::Relaxed) {
                0 => 0,
                m => unix_now().saturating_sub(m),
            },
            self.inbox_scan_unix.load(Ordering::Relaxed),
        ).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_new_zero() {
        let s = AntieStats::new();
        assert_eq!(s.messages_received.load(Ordering::Relaxed), 0);
        assert_eq!(s.messages_processed.load(Ordering::Relaxed), 0);
        assert!(s.started_at > 0);
    }

    #[test]
    fn test_stats_to_json() {
        let s = AntieStats::new();
        s.messages_received.store(5, Ordering::Relaxed);
        let json = String::from_utf8(s.to_json()).unwrap();
        assert!(json.contains("\"messages_received\":5"));
        assert!(json.contains("\"uptime_secs\":"));
    }

    #[test]
    fn test_stats_all_counters_increment() {
        let s = AntieStats::new();
        s.messages_received.fetch_add(1, Ordering::Relaxed);
        s.messages_processed.fetch_add(2, Ordering::Relaxed);
        s.messages_failed.fetch_add(3, Ordering::Relaxed);
        s.tcp_connections.fetch_add(4, Ordering::Relaxed);
        s.tcp_rate_limited.fetch_add(5, Ordering::Relaxed);
        s.lambda_requests.fetch_add(6, Ordering::Relaxed);
        s.lambda_errors.fetch_add(7, Ordering::Relaxed);
        s.emails_sent.fetch_add(8, Ordering::Relaxed);

        let json = String::from_utf8(s.to_json()).unwrap();
        assert!(json.contains("\"messages_received\":1"));
        assert!(json.contains("\"messages_processed\":2"));
        assert!(json.contains("\"messages_failed\":3"));
        assert!(json.contains("\"tcp_connections\":4"));
        assert!(json.contains("\"tcp_rate_limited\":5"));
        assert!(json.contains("\"lambda_requests\":6"));
        assert!(json.contains("\"lambda_errors\":7"));
        assert!(json.contains("\"emails_sent\":8"));
    }

    #[test]
    fn test_ban_rejected_counter() {
        let s = AntieStats::new();
        assert_eq!(s.ban_rejected.load(Ordering::Relaxed), 0);
        s.ban_rejected.fetch_add(3, Ordering::Relaxed);
        let json = String::from_utf8(s.to_json()).unwrap();
        assert!(json.contains("\"ban_rejected\":3"));
    }
}

#[cfg(test)]
mod ki141_counter_tests {
    use super::*;

    #[test]
    fn carrier_attempts_drive_the_three_gauges() {
        let st = AntieStats::new();
        let (mut a, mut b) = (0u32, 0u32);
        assert_eq!(st.note_carrier_attempt(&mut a, true), 0, "a healthy fetch is not a streak");
        assert_eq!(st.carriers_in_backoff.load(Ordering::Relaxed), 0);
        st.note_carrier_attempt(&mut a, false);
        st.note_carrier_attempt(&mut a, false);
        st.note_carrier_attempt(&mut b, false);
        assert_eq!((a, b), (2, 1));
        assert_eq!(st.carrier_failures_total.load(Ordering::Relaxed), 3);
        assert_eq!(st.carriers_in_backoff.load(Ordering::Relaxed), 2, "two loops in backoff");
        assert_eq!(st.carrier_consecutive_failures.load(Ordering::Relaxed), 2, "the longest streak");
        st.note_carrier_attempt(&mut a, true);
        assert_eq!(a, 0);
        assert_eq!(st.carriers_in_backoff.load(Ordering::Relaxed), 1);
        assert_eq!(st.carrier_consecutive_failures.load(Ordering::Relaxed), 2, "b is still failing; the gauge holds");
        st.note_carrier_attempt(&mut b, true);
        assert_eq!(st.carriers_in_backoff.load(Ordering::Relaxed), 0);
        assert_eq!(st.carrier_consecutive_failures.load(Ordering::Relaxed), 0, "nothing in backoff ⇒ no streak");
        assert_eq!(st.carrier_failures_total.load(Ordering::Relaxed), 3, "the total never decrements");
        let j = String::from_utf8(st.to_json()).unwrap();
        for k in ["carrier_failures_total", "carriers_in_backoff", "carrier_consecutive_failures"] {
            assert!(j.contains(&format!("\"{k}\":")), "/status carries {k}");
        }
    }
}

#[cfg(test)]
mod ki114_progress_tests {
    use super::*;

    /// KI#114 — the progress fields reach the JSON consumers read (RULE 6 §4),
    /// a never-stamped field reads 0 (= "never", not a fake time), and a
    /// heartbeat ages until it beats. MUTATION (run 2026-10-01): drop
    /// `carrier_eof_mid_response` from `to_json` ⇒ red.
    #[test]
    fn progress_fields_ride_on_status_and_heartbeats_age() {
        let st = AntieStats::new();
        let j = String::from_utf8(st.to_json()).unwrap();
        for k in ["carrier_eof_mid_response", "last_inbox_write_unix", "last_round_served_unix",
                  "inbox_oldest_unprocessed_age_secs", "inbox_scan_unix"] {
            assert!(j.contains(&format!("\"{k}\":")), "/status carries {k}: {j}");
        }
        assert!(j.contains("\"last_round_served_unix\":0"), "never served ⇒ 0");
        st.note_round_served();
        st.note_inbox_write();
        let j: serde_json::Value = serde_json::from_slice(&st.to_json()).unwrap();
        assert!(j["last_round_served_unix"].as_u64().unwrap() > 0);
        assert!(j["last_inbox_write_unix"].as_u64().unwrap() > 0);
        st.inbox_oldest_unprocessed_mtime_unix.store(unix_now() - 100, Ordering::Relaxed);
        let j: serde_json::Value = serde_json::from_slice(&st.to_json()).unwrap();
        assert!(j["inbox_oldest_unprocessed_age_secs"].as_u64().unwrap() >= 100);

        let hb = st.register_heartbeat("dispatch", 600);
        let now = st.mono_now_secs();
        assert_eq!(st.heartbeat_snapshot(now)[0].age_secs, 0, "registration beats");
        assert_eq!(st.heartbeat_snapshot(now + 700)[0].age_secs, 700, "ages until it beats");
        hb.beat();
        assert_eq!(st.heartbeat_snapshot(st.mono_now_secs())[0].age_secs, 0);
    }
}
