//! ANTIE metrics counters — thread-safe atomic stats.

use std::sync::atomic::{AtomicU64, Ordering};

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
    /// Number of requests rejected with E_VALIDATOR_BUSY
    pub busy_rejections: AtomicU64,
    /// Number of requests rejected with E_WALLET_RATE_LIMITED (YPX-015 §2.3)
    pub rate_limited: AtomicU64,
    /// Number of requests rejected with E_WALLET_BANNED (YP §32-33)
    pub ban_rejected: AtomicU64,
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
            busy_rejections: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            ban_rejected: AtomicU64::new(0),
            decrypt_fail: AtomicU64::new(0),
            parse_fail: AtomicU64::new(0),
            oversize_dropped: AtomicU64::new(0),
            core_version: std::sync::RwLock::new(String::new()),
            skipped_dir_count: AtomicU64::new(0),
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
                "\"busy_rejections\":{},",
                "\"wallet_rate_limited\":{},",
                "\"ban_rejected\":{},",
                "\"decrypt_fail\":{},",
                "\"parse_fail\":{},",
                "\"oversize_dropped\":{},",
                "\"core_version\":\"{}\",",
                "\"skipped_dir_count\":{}",
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
            self.busy_rejections.load(Ordering::Relaxed),
            self.rate_limited.load(Ordering::Relaxed),
            self.ban_rejected.load(Ordering::Relaxed),
            self.decrypt_fail.load(Ordering::Relaxed),
            self.parse_fail.load(Ordering::Relaxed),
            self.oversize_dropped.load(Ordering::Relaxed),
            self.core_version.read().map(|v| v.clone()).unwrap_or_default(),
            self.skipped_dir_count.load(Ordering::Relaxed),
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
