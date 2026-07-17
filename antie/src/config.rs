//! ANTIE Configuration

use crate::carrier::{CarriersConfig, MaildirConfig, ImapConfig, Pop3Config};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// SMTP outbound — for sending replies and receipts. Send-only; not a receive carrier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpOutboundConfig {
    pub server:       String,
    pub port:         u16,
    pub username:     Option<String>,
    pub password:     Option<String>,
    #[serde(default = "default_true_config")]
    pub use_tls:      bool,
    pub from_address: String,
}

fn default_true_config() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutboundConfig {
    pub smtp: Option<SmtpOutboundConfig>,

    /// Optional UNCLE sink — when set, ANTIE writes a copy of every
    /// witness/redeem response (i.e. responses carrying a txid via
    /// `witness_signature` or `cheque_for_receiver`) to
    /// `<uncle.outbox_path>/<txid_hex>.cbor` before the primary SMTP
    /// dispatch. UNCLE's `witness_observer` watches that dir and
    /// shepherds responses back to in-flight `SubmitSend` callers on
    /// the held TCP connection.
    ///
    /// This is a **tee**, not a replacement — SMTP delivery still
    /// happens, so non-UNCLE clients (regular wallet SMTP receive)
    /// keep working. When the field is `None`, ANTIE behaves
    /// identically to pre-3.1.0-beta2.
    ///
    /// Configured per-validator via env.py only on UNCLE-running
    /// penguins (those whose `carriers` column in
    /// seeds/validators.list contains `uncle:`).
    #[serde(default)]
    pub uncle: Option<UncleSinkConfig>,
}

/// Where ANTIE tees outbound witness responses for UNCLE to consume.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UncleSinkConfig {
    /// Directory ANTIE writes `<txid_hex>.cbor` files into. Must be
    /// the SAME path UNCLE's `[antie] witness_outbox` config points
    /// at — env.py wires both sides together.
    pub outbox_path: std::path::PathBuf,
}

/// ANTIE Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AntieConfig {
    /// Inbound carriers — at least one email carrier required
    pub carriers: CarriersConfig,

    /// Outbound — SMTP for sending replies
    pub outbound: OutboundConfig,

    /// Core IPC settings
    pub core: CoreConfig,

    /// Lambda settings
    pub lambda: LambdaConfig,

    /// Validator setup (keys, identity for S-ABR)
    pub validator: ValidatorConfig,

    /// Gateway identity
    pub identity: IdentityConfig,

    /// Logging settings
    pub logging: LoggingConfig,

    /// Poll interval in milliseconds
    pub poll_interval_ms: u64,

    /// Health endpoint port (serves /health and /status)
    pub health_port: u16,

    /// Bearer token for health endpoint authentication (optional).
    /// If set, /status requires ?token=<value>. /health is always accessible.
    #[serde(default)]
    pub health_token: Option<String>,

    /// Performance / backpressure settings (YPX-015)
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Per-wallet witness rate limit cooldown in ms (YPX-015 §2.3).
    /// Default 2000ms (0.5 req/sec/wallet). Set to 0 to disable.
    /// Production recommendation: 2000-5000ms depending on expected load.
    #[serde(default)]
    pub wallet_witness_cooldown_ms: Option<u64>,

    /// Path to ban list file written by Lambda (YP §32-33).
    /// Lambda receives bans from Nabla and writes banned wallet IDs
    /// (hex, one per line) to this file. ANTIE reads it before forwarding
    /// witness requests. Best-effort: if file missing, proceed.
    /// Example: "/home/axiom/axiom-first-penguin-alpha/ban_list.txt"
    #[serde(default)]
    pub nabla_ban_list_path: Option<String>,

    /// Sibling-carrier coordination (`docs/AXIOM_DESIGN_AntieSkipList.md`).
    /// Sibling carriers (UNCLE, COUSIN, future) register their client
    /// receiver_wallet_ids in this file; ANTIE reads it and diverts
    /// outbound cheques bound for skip-listed receivers into
    /// `<skipped_dir_path>/` (atomic `tmp/` → `rename(2)`) instead of
    /// dispatching via sendmail. Sibling carriers claim by atomic
    /// rename out. Both paths default to None — when either is None,
    /// the skip-list path is disabled and every outbound cheque goes
    /// through the existing email-only flow.
    ///
    /// File format: one receiver_wallet_id per line. Lines starting
    /// with `#` are comments; blank lines are ignored. Reloaded on
    /// SIGHUP and on atomic-rename of the file (sibling carrier picks
    /// whichever mechanism it prefers).
    #[serde(default)]
    pub skip_list_path: Option<String>,
    /// Directory ANTIE writes skip-listed cheques into. ANTIE does
    /// not garbage-collect this directory; per the contract, sibling
    /// carriers claim by atomic rename out. Operators monitor depth
    /// (the `skipped_dir_count` metric on /status surfaces it).
    #[serde(default)]
    pub skipped_dir_path: Option<String>,
}

/// Performance / backpressure configuration (YPX-015 §2.1)
///
/// ANTIE uses `queue_depth × avg_witness_ms` to estimate wait time for
/// incoming requests. If the estimate exceeds `busy_threshold_ms`, ANTIE
/// immediately rejects the request with `E_VALIDATOR_BUSY` — the request
/// never reaches Lambda or Core. The client retries on another validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceConfig {
    /// Reject incoming witness requests when estimated wait exceeds this (ms).
    /// Estimated wait = queue_depth × avg_witness_ms (from Lambda /stats).
    /// Default: 15000 (15 seconds). Operators adjust based on hardware.
    /// Set to 0 to disable backpressure.
    pub busy_threshold_ms: u64,

    /// How often ANTIE polls Lambda /stats for avg_witness_ms (ms).
    /// Default: 5000 (5 seconds).
    pub lambda_stats_poll_ms: u64,

    /// Lambda admin port for polling /stats. Must match Lambda's admin_port.
    /// Default: 7780 (alpha validator).
    pub lambda_admin_port: u16,

    /// Lambda admin auth token (must match Lambda's admin_token).
    #[serde(default)]
    pub lambda_admin_token: Option<String>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            busy_threshold_ms: 15_000,
            lambda_stats_poll_ms: 2_000,
            lambda_admin_port: 7780,
            lambda_admin_token: None,
        }
    }
}

/// Validator setup — keys and identity for Core's S-ABR gate
///
/// Core needs to know which validator it serves (via VBC).
/// In production, VBC is verified at axiom-core.elf load time.
/// In dev/mock mode, ANTIE creates a mock VBC from these fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidatorConfig {
    /// Validator's SPHINCS+ public key (hex-encoded, 64 chars = 32 bytes)
    /// This is the VBC identity key
    pub public_key_hex: String,
    
    /// Validator's Dilithium public key (hex-encoded, 3904 chars = 1952 bytes)
    /// Backup VBC identity, stored in VBC alongside SPHINCS+ PK
    #[serde(default)]
    pub dilithium_pk_hex: String,
    
    /// Validator ID (wallet-format name)
    /// e.g., "v1@axiom.validators/a3f7b201"
    pub validator_id: String,

    /// Path to VBC JSON file (generated by validator-setup)
    #[serde(default)]
    pub vbc_path: Option<String>,

    /// Path to the validator's Ed25519 secret seed (32 raw bytes, mode 0600).
    /// When set, ANTIE reads this at startup, derives an X25519 secret via
    /// `crypto_sign_ed25519_sk_to_curve25519`, and uses it to decrypt
    /// inbound `UmpEnvelope::Encrypted` payloads — forward-direction
    /// encryption per `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.4.
    /// Same file Lambda already reads for signing; mode 0600, validator-
    /// user-owned.  Leaving this `None` disables decryption (Plain
    /// envelopes still parse normally).
    #[serde(default)]
    pub private_key_path: Option<String>,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            public_key_hex: String::new(),
            dilithium_pk_hex: String::new(),
            validator_id: "validator@axiom.local".to_string(),
            vbc_path: None,
            private_key_path: None,
        }
    }
}

impl ValidatorConfig {
    /// Check if validator key is configured
    pub fn has_key(&self) -> bool {
        self.public_key_hex.len() == 64  // 32 bytes hex-encoded (SPHINCS+ PK)
    }
    
    /// Get SPHINCS+ public key bytes (returns None if not configured or invalid)
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        if !self.has_key() {
            return None;
        }
        hex::decode(&self.public_key_hex).ok()
    }
    
    /// Get Dilithium public key bytes (returns None if not configured or invalid)
    pub fn dilithium_pk_bytes(&self) -> Option<Vec<u8>> {
        if self.dilithium_pk_hex.is_empty() {
            return None;
        }
        hex::decode(&self.dilithium_pk_hex).ok()
    }
    
    /// Load VBC from file and convert to Core's VBCProofBundle
    pub fn load_vbc(&self) -> Option<axiom_core_logic::types::VBCProofBundle> {
        let path = self.vbc_path.as_ref()?;
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[VBC_LOAD] Failed to read {}: {}", path, e);
                return None;
            }
        };
        let file_vbc: VBCFile = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[VBC_LOAD] Failed to parse {}: {}", path, e);
                return None;
            }
        };
        
        let sphincs_pk = hex::decode(&file_vbc.subject_pubkey_sphincs_hex).unwrap_or_default();
        let validator_id = axiom_core_logic::compute::compute_validator_id(&sphincs_pk);
        
        let result = Some(axiom_core_logic::types::VBCProofBundle {
            target_vbc: axiom_core_logic::types::VBC {
                version: file_vbc.version.unwrap_or(0x09),
                // YPX-021 §7 — validator VBCs from vbc.json predate the
                // baseline field; 0 = no baseline (genesis-era exempt).
                network_size_baseline: 0,
                baseline_tick: 0,
                validator_id,
                subject_pubkey_sphincs: sphincs_pk,
                subject_pubkey_dilithium: hex::decode(&file_vbc.subject_pubkey_dilithium_hex).unwrap_or_default(),
                subject_pubkey_ed25519: hex::decode(&file_vbc.subject_pubkey_ed25519_hex).unwrap_or_default(),
                pgp_fingerprint: file_vbc.pgp_fingerprint_hex.as_ref()
                    .and_then(|h| hex::decode(h).ok())
                    .unwrap_or_default(),
                node_name: String::new(),
                proof_cap: String::new(),
                issued_at: file_vbc.issued_at,
                expires_at: file_vbc.expires_at,
                chain_depth: file_vbc.chain_depth.unwrap_or(0),
                issuer_set: file_vbc.issuer_set.iter()
                    .filter_map(|h| hex::decode(h).ok())
                    .collect(),
                signatures: file_vbc.signatures.iter()
                    .filter_map(|h| hex::decode(h).ok())
                    .collect(),
                max_tx: 0,
                founding_vbc_hash: file_vbc.founding_vbc_hash.as_ref()
                    .and_then(|h| {
                        let bytes = hex::decode(h).ok()?;
                        let arr: [u8; 32] = bytes.try_into().ok()?;
                        Some(arr)
                    })
                    .unwrap_or([0u8; 32]),
            },
            supporting_vbcs: vec![],
        });
        
        // Verify VBC structure (lightweight — no SPHINCS+ signature verification).
        // Full chain verification (with SPHINCS+) is Lambda's job at startup.
        // ANTIE verifies structure to catch corruption/misconfiguration early.
        // Note: supporting_vbcs is empty here — for genesis VBCs (chain_depth=0)
        // the issuers ARE root authorities, so no supporting chain is needed.
        if let Some(ref bundle) = result {
            if let Err(e) = axiom_core_logic::vbc::verify_vbc_bundle_structure_only_DANGER_no_sig(bundle) {
                eprintln!("╔══════════════════════════════════════════════════════════════╗");
                eprintln!("║  WARNING: VBC structure verification failed                  ║");
                eprintln!("║  Error: {:50}║", format!("{}", e));
                eprintln!("║  CL2 overlap detection will be DISABLED (my_pk=NONE)         ║");
                eprintln!("╚══════════════════════════════════════════════════════════════╝");
                return None;
            }
            eprintln!("[VBC] Loaded: ed25519_pk={}", hex::encode(&bundle.target_vbc.subject_pubkey_ed25519[..8.min(bundle.target_vbc.subject_pubkey_ed25519.len())]));
        }
        
        result
    }
}

/// VBC file format v0.9 (JSON from validator-setup, hex-encoded keys)
#[derive(Debug, Deserialize)]
struct VBCFile {
    #[serde(default)]
    version: Option<u8>,
    #[serde(default)]
    subject_pubkey_sphincs_hex: String,
    #[serde(default)]
    subject_pubkey_dilithium_hex: String,
    #[serde(default)]
    subject_pubkey_ed25519_hex: String,
    #[serde(default)]
    pgp_fingerprint_hex: Option<String>,
    #[serde(default)]
    issuer_set: Vec<String>,
    #[serde(default)]
    signatures: Vec<String>,
    #[serde(default)]
    issued_at: u64,
    #[serde(default = "default_expires")]
    expires_at: u64,
    #[serde(default)]
    chain_depth: Option<u8>,
    #[serde(default)]
    founding_vbc_hash: Option<String>,
}

fn default_expires() -> u64 { u64::MAX }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    /// [DEPRECATED] core-bin is no longer used. ANTIE uses AVM interpreter directly.
    /// The ELF is now named axiom-core.elf. Kept for config backwards compatibility —
    /// used as hint for finding AVM ELF.
    pub core_bin_path: Option<PathBuf>,

    /// Path to axiom-core.elf for AVM interpreter
    pub avm_elf_path: Option<PathBuf>,

    /// Use embedded AVM (dev mode)
    pub use_embedded_avm: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            core_bin_path: None,
            avm_elf_path: None,
            use_embedded_avm: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum LambdaConfig {
    /// TCP connection to remote Lambda
    #[serde(rename = "tcp")]
    Tcp {
        /// Lambda address
        address: String,
        /// Connection timeout in seconds
        timeout_secs: u64,
        /// TLS server name for verification (optional — enables TLS when set)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls_server_name: Option<String>,
        /// TLS CA cert path for server verification (optional — uses system roots if absent)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls_ca_cert_path: Option<String>,
    },
    /// Subprocess mode (preferred) - spawns Lambda as child process
    #[serde(rename = "subprocess")]
    Subprocess {
        /// Path to Lambda binary
        binary_path: PathBuf,
        /// Path to Lambda config file
        config_path: PathBuf,
    },
}

impl Default for LambdaConfig {
    fn default() -> Self {
        // Default: subprocess mode (stdio) for development
        // Use tcp mode for distributed deployment
        LambdaConfig::Subprocess {
            binary_path: PathBuf::from("./axiom-lambda/target/release/lambda"),
            config_path: PathBuf::from("./config/lambda-config.toml"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Gateway email address
    pub email: String,
    
    /// Validator name
    pub name: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            email: "validator@axiom.local".to_string(),
            name: "AXIOM Validator".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl Default for AntieConfig {
    fn default() -> Self {
        Self {
            carriers: CarriersConfig {
                maildir: Some(MaildirConfig {
                    inbox:  PathBuf::from("./maildir/inbox"),
                    outbox: PathBuf::from("./maildir/outbox"),
                }),
                ..Default::default()
            },
            outbound: OutboundConfig::default(),
            core: CoreConfig::default(),
            lambda: LambdaConfig::default(),
            validator: ValidatorConfig::default(),
            identity: IdentityConfig::default(),
            logging: LoggingConfig::default(),
            poll_interval_ms: 10,
            health_port: 7779,
            health_token: None,
            performance: PerformanceConfig::default(),
            wallet_witness_cooldown_ms: None,
            nabla_ban_list_path: None,
            skip_list_path: None,
            skipped_dir_path: None,
        }
    }
}

impl AntieConfig {
    /// Load from TOML file
    pub fn load(path: &std::path::Path) -> Result<Self, crate::error::AntieError> {
        let content = std::fs::read_to_string(path)?;
        let config: AntieConfig = toml::from_str(&content)
            .map_err(|e| crate::error::AntieError::ConfigError(e.to_string()))?;
        config.carriers.validate()?;
        Ok(config)
    }
    
    /// Save to TOML file
    pub fn save(&self, path: &std::path::Path) -> Result<(), crate::error::AntieError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::error::AntieError::ConfigError(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Generate default config file (Maildir only)
    pub fn generate_default() -> String {
        toml::to_string_pretty(&Self::default()).unwrap()
    }

    /// Generate example IMAP + SMTP config
    pub fn generate_imap_example() -> String {
        let config = Self {
            carriers: CarriersConfig {
                imap: Some(ImapConfig {
                    server:           "imap.example.com".into(),
                    port:             993,
                    username:         "validator@example.com".into(),
                    password:         "your-password".into(),
                    use_tls:          true,
                    inbox_folder:     "INBOX".into(),
                    processed_folder: "INBOX.Processed".into(),
                }),
                ..Default::default()
            },
            outbound: OutboundConfig {
                smtp: Some(SmtpOutboundConfig {
                    server:       "smtp.example.com".into(),
                    port:         587,
                    username:     Some("validator@example.com".into()),
                    password:     Some("your-password".into()),
                    use_tls:      true,
                    from_address: "validator@example.com".into(),
                }),
                uncle: None,
            },
            ..Default::default()
        };
        toml::to_string_pretty(&config).unwrap()
    }

    /// Generate example POP3 + SMTP config
    pub fn generate_pop3_example() -> String {
        let config = Self {
            carriers: CarriersConfig {
                pop3: Some(Pop3Config {
                    server:   "pop.example.com".into(),
                    port:     995,
                    username: "validator@example.com".into(),
                    password: "your-password".into(),
                    use_tls:  true,
                }),
                ..Default::default()
            },
            outbound: OutboundConfig {
                smtp: Some(SmtpOutboundConfig {
                    server:       "smtp.example.com".into(),
                    port:         587,
                    username:     Some("validator@example.com".into()),
                    password:     Some("your-password".into()),
                    use_tls:      true,
                    from_address: "validator@example.com".into(),
                }),
                uncle: None,
            },
            ..Default::default()
        };
        toml::to_string_pretty(&config).unwrap()
    }

    /// Generate example Maildir + TCP config (genesis node)
    /// Generate a maildir-plus-advertise example config. The
    /// previous tcp/ws/fatmama examples were removed when those
    /// carriers were dropped from ANTIE — operators now declare
    /// non-email transports via `[carriers] advertise = [...]`.
    pub fn generate_advertise_example() -> String {
        let config = Self {
            carriers: CarriersConfig {
                maildir: Some(MaildirConfig {
                    inbox:  PathBuf::from("/var/mail/axiom/inbox"),
                    outbox: PathBuf::from("/var/mail/axiom/outbox"),
                }),
                advertise: vec![
                    "fatmama:fatmama.example.com:2525".into(),
                    "tot:axiom-dev.mooo.com:7400".into(),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        toml::to_string_pretty(&config).unwrap()
    }

    /// Multi-email-carrier example (maildir + imap + pop3 + advertise).
    pub fn generate_all_carriers_example() -> String {
        let config = Self {
            carriers: CarriersConfig {
                maildir: Some(MaildirConfig {
                    inbox:  PathBuf::from("/var/mail/axiom/inbox"),
                    outbox: PathBuf::from("/var/mail/axiom/outbox"),
                }),
                imap: Some(ImapConfig {
                    server: "imap.example.com".into(), port: 993,
                    username: "node@example.com".into(), password: "secret".into(),
                    use_tls: true,
                    inbox_folder: "INBOX".into(), processed_folder: "INBOX.Processed".into(),
                }),
                pop3: Some(Pop3Config {
                    server: "pop.example.com".into(), port: 995,
                    username: "node@example.com".into(), password: "secret".into(),
                    use_tls: true,
                }),
                advertise: vec![
                    "fatmama:fatmama.example.com:2525".into(),
                    "tot:axiom-dev.mooo.com:7400".into(),
                ],
            },
            outbound: OutboundConfig {
                smtp: Some(SmtpOutboundConfig {
                    server: "smtp.example.com".into(), port: 587,
                    username: None, password: None, use_tls: true,
                    from_address: "node@example.com".into(),
                }),
                uncle: None,
            },
            ..Default::default()
        };
        toml::to_string_pretty(&config).unwrap()
    }
}
