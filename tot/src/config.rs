//! TOT configuration — loaded once at startup, never reloaded.
//!
//! Everything the serve loop will ever need is resolved from this file
//! before the sandbox is sealed: the one writable inbox and the attested
//! Nabla node set the /nabla leg is bounded to. `deny_unknown_fields`
//! makes a typo in a sandbox-relevant key a hard startup error rather
//! than a silently ignored setting.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The single listen socket (e.g. "0.0.0.0:7400"). It serves both
    /// transports: a native client's raw-TCP intake frame and a browser
    /// `ws://` connection are demuxed by the first 4 bytes of the
    /// connection (AXIOM_DESIGN_TOT.md §3). No TLS — the UMP envelope is
    /// already end-to-end sealed to the validator key (§4).
    pub listen: SocketAddr,
    /// The ONE validator inbox TOT may write — its entire filesystem
    /// reach. Hardwired here at deploy time (AXIOM_DESIGN_TOT.md §3).
    pub maildir_inbox: PathBuf,
    /// The attested Nabla node set. The /nabla leg selects a node by
    /// 0-based index into this list; any other destination is refused.
    pub nabla: Vec<NablaNode>,
    /// DEV-ONLY (`dev-fatmama` feature): the FATMAMA endpoint set the
    /// `/fatmama/<n>` tunnel is bounded to — typically the dev SMTP port
    /// (XAXIOM-REGISTER) at index 0 and the POP3 port (mail pull) at index
    /// 1. Empty in production; the `/fatmama` route is compiled out of
    /// release builds entirely. FATMAMA is dev-scoped (AXIOM_DESIGN_TOT.md
    /// §8) — a browser dev wallet reaches it ONLY through this tunnel,
    /// never directly, and FATMAMA itself exposes no webhook.
    #[serde(default)]
    pub fatmama: Vec<NablaNode>,
    /// Intake rate limit — max submissions per WebSocket connection per
    /// second; 0 disables it. The raw-TCP leg is one frame per
    /// connection, so it is not rate-limited here.
    #[serde(default = "default_intake_rate")]
    pub intake_max_msgs_per_sec: u32,
    /// Hard cap on a single intake message, in bytes — applied to both
    /// the WebSocket leg and the raw-TCP leg.
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NablaNode {
    pub name: String,
    pub addr: SocketAddr,
}

fn default_intake_rate() -> u32 {
    8
}

fn default_max_message_bytes() -> usize {
    256 * 1024
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| format!("parse config {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.nabla.is_empty() {
            return Err("config: [[nabla]] is empty — no attested Nabla nodes".into());
        }
        if self.max_message_bytes == 0 {
            return Err("config: max_message_bytes must be greater than 0".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_complete_config() {
        let toml = r#"
listen = "0.0.0.0:7400"
maildir_inbox = "/var/lib/axiom/v/maildir/inbox"
[[nabla]]
name = "n0"
addr = "10.0.0.1:6000"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.nabla.len(), 1);
        assert_eq!(cfg.intake_max_msgs_per_sec, 8); // default applied
        assert_eq!(cfg.max_message_bytes, 256 * 1024); // default applied
    }

    #[test]
    fn rejects_empty_nabla_set() {
        let toml = r#"
listen = "0.0.0.0:7400"
maildir_inbox = "/m"
nabla = []
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_key() {
        let toml = r#"
listen = "0.0.0.0:7400"
maildir_inbox = "/m"
surprise = true
[[nabla]]
name = "n0"
addr = "10.0.0.1:6000"
"#;
        assert!(toml::from_str::<Config>(toml).is_err());
    }
}
