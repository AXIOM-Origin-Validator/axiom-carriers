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

/// One row of the outbound routing table: a recipient domain and the outbox
/// directory ANTIE writes matching messages into.
///
/// AXIOM_DESIGN_AntieOutboundSplit.md (superseded mechanism / retained goal).
/// ANTIE's whole outbound job is: resolve the recipient's domain against this
/// table, write the file there. No connection, no retry, no host resolution —
/// an agent (FATMAMA or postfix, interchangeable) collects from the directory.
/// Design ruling, 2026-08-20: "ANTIE always do the same thing, write the outgoing to
/// the correct mailbox."
///
/// A TABLE rather than a hard-wired local/external pair so a future carrier is
/// a new directory plus a row, not new code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRoute {
    /// Recipient domain, matched EXACTLY and case-insensitively.
    ///
    /// ⚠ EXACT, never suffix or subdomain (YPX-019 §3.1). `evil-axiom.com` and
    /// `axiom.internal.evil.com` MUST NOT match `axiom` — both evasions were
    /// tested against FATMAMA's equivalent guard and rejected.
    pub domain: String,
    /// Maildir whose `new/` receives messages for this domain. Exactly ONE
    /// agent may collect from it: two collectors on one directory would either
    /// both take a message (double delivery) or each assume the other did
    /// (silent stranding).
    pub outbox: std::path::PathBuf,
}

impl OutboundConfig {
    /// Resolve a recipient address to the outbox directory ANTIE must write to.
    ///
    /// This is the WHOLE of ANTIE's outbound routing decision. It opens nothing,
    /// resolves no host, and performs no MTA logic — it is a table lookup, and
    /// the caller then writes a file. An agent (FATMAMA / postfix) collects.
    ///
    /// ⚠ **DO NOT DELETE THIS AS DEAD CODE (YPX-023 §2B.4, AXIOM Origin
    /// 2026-08-24).** When the `X-Custody` stamp becomes the routing key
    /// (YPX-023 RULE 3), this domain logic — including the dual-`@` inner-domain
    /// unwrap below — is **RETAINED as an independent second layer**. It stops
    /// being a router and becomes a GUARD: it can veto, never choose. Stamp and
    /// address must AGREE; disagreement REJECTS, never "prefer one" (a forged
    /// stamp would otherwise pull a normal message into the dev trust class).
    ///
    /// In correct operation it never changes an outcome, so it WILL look
    /// redundant. It is not: a message misrouted to the wrong FATMAMA is a
    /// containment failure, and dev traffic is more trusted inside the mesh —
    /// normal traffic entering the dev path is a privilege escalation.
    /// [[feedback_defense_in_depth_by_design]] — never retire a layered guard.
    ///
    /// `Ok(None)` means "table not in use" (no rows, no default) — the caller
    /// keeps the legacy SmtpCarrier path. `Err` means the table IS in use and
    /// this recipient has nowhere to go, which MUST reject the message rather
    /// than drop it (AntieOutboundSplit §4, fail-closed).
    pub fn outbox_for(&self, recipient: &str) -> Result<Option<&std::path::Path>, String> {
        if self.route.is_empty() {
            return Ok(None);                      // legacy path, table unused
        }
        // Domain = after the LAST '@', minus any `/fingerprint` suffix that a
        // wallet_id carries. Mirrors carrier::recipient_is_local so the two can
        // never disagree about what "the domain" means.
        // A DUAL-@ delivery address names the destination SITE in its outer
        // domain (`user@axiom.internal@some-host`, AXIOM_YPX-019 §5.2.1). The
        // outbox question is "which LOCAL directory does this go in", and that is
        // answered by the wallet's own cluster domain — FATMAMA performs the
        // cross-site hop afterwards by reading the To: header.
        //
        // Without this, the outer HOST is taken as the domain, matches no route,
        // and the message survives only because `default_outbox` happens to point
        // at the same directory. That is correct BY ACCIDENT: repoint or remove
        // the default and every cross-site cheque is rejected fail-closed.
        let addressed = recipient.split('/').next().unwrap_or(recipient);
        let inner = match addressed.rfind('@') {
            Some(i) => &addressed[..i],
            None => addressed,
        };
        let route_on = if inner.contains('@') { inner } else { addressed };
        let domain = match route_on.rfind('@') {
            Some(i) => route_on[i + 1..].split('/').next().unwrap_or("").to_ascii_lowercase(),
            None => {
                return Err(format!(
                    "outbound: recipient {recipient:?} has no '@' — cannot route, \
                     rejecting rather than dropping"
                ))
            }
        };
        // EXACT match only. A suffix/subdomain rule would let `evil-axiom.com`
        // or `axiom.internal.evil.com` claim a cluster route (YPX-019 §3.1).
        for r in &self.route {
            if r.domain.eq_ignore_ascii_case(&domain) {
                return Ok(Some(r.outbox.as_path()));
            }
        }
        // NO FALLBACK. Every domain routes explicitly or the message is refused.
        // Design ruling, 2026-08-20: *"our rules is strictly no fallback... your fallback
        // caused me a lot of valuable time."* A `default_outbox` made a broken
        // route look healthy — and worse, it MISROUTES: an external recipient
        // (@purelymail.com) written to a cluster outbox is collected by FATMAMA,
        // which only accepts @axiom/@axiom.internal, so it dies there instead of
        // failing loudly here. [[feedback_no_fallback_design]]
        Err(format!(
            "outbound: no route for domain {domain:?} — REJECTING this message. \
             Add an explicit [[outbound.route]] for it; there is no default \
             (fail-closed and LOUD; never a silent drop or a silent misroute)"
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutboundConfig {
    /// Domain → outbox routing table. When non-empty ANTIE writes files and
    /// opens NO connections; `local`/`external` below are then unused.
    /// Empty = legacy SplitCarrier behaviour (see the deviation note in
    /// YPX-019 §6). Not yet the default — the collectors must exist first.
    #[serde(default)]
    pub route: Vec<OutboundRoute>,

    // NOTE: there is deliberately NO `default_outbox`. Every domain routes
    // explicitly or the message is refused — [[feedback_no_fallback_design]].

    /// Local delivery target — the on-box FATMAMA. Required; carries
    /// `@axiom` / `@axiom.internal` recipients (which the client later POPs).
    /// See AXIOM_DESIGN_AntieOutboundSplit.md.
    pub local: Option<SmtpOutboundConfig>,

    /// Optional external relay for real (non-`@axiom`) domains. Unset =
    /// local-only mode (fine for bring-up/testing). A bare relay address;
    /// ANTIE does no MTA routing — it only splits local vs external by the
    /// recipient domain.
    #[serde(default)]
    pub external: Option<SmtpOutboundConfig>,

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

    /// Custody routing table (YPX-023 RULE 3) — `header -> outbox`.
    ///
    /// A client that cannot hold a mailbox (the webclient) reaches its
    /// validator over a held TOT session. TOT stamps the envelope with a
    /// custody header on the way into `maildir/inbox/`; ANTIE matches that
    /// header here and writes the reply into the row's `outbox` instead of
    /// mailing it, where TOT claims it and pushes it back down the socket.
    ///
    /// **ADDITIVE AND INERT BY DEFAULT.** An empty table (the default) means
    /// ANTIE behaves EXACTLY as before: nothing about the domain table, the
    /// skip list, or UNCLE's tee changes. A message carrying no configured
    /// custody header takes the ordinary path.
    ///
    /// A new path is a ROW, not code — the same reason `OutboundRoute` is a
    /// table (see its comment above).
    #[serde(default)]
    pub custody: Vec<CustodyRoute>,
}

/// One row of the custody routing table (YPX-023 §3.3).
/// YPX-024 `[pickup]` — see `AntieConfig::pickup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PickupConfig {
    /// Base directory; artifacts land in `<dir>/<pickup-domain>/new/`.
    pub dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyRoute {
    /// The header whose PRESENCE selects this row, e.g. `X-TOT-Session`.
    /// Matched case-insensitively (RFC 5322 header names are case-insensitive;
    /// a case-sensitive match would silently drop replies).
    pub header: String,
    /// Directory the reply is written into, as
    /// `<outbox>/<id>/<request_id>.cbor`.
    ///
    /// ⚠ Per-`id` SUBDIRECTORY, not a flat `<id>.cbor`: one k=3 round produces
    /// THREE replies for a single session id, so UNCLE's flat convention would
    /// collide three times. The subdirectory also makes the carrier's cleanup
    /// on disconnect one directory removal rather than a prefix scan.
    pub outbox: std::path::PathBuf,
    /// When true the ordinary mail dispatch is SKIPPED for a message matching
    /// this row — the reply goes only to `outbox`.
    ///
    /// This is the difference from UNCLE's sink, which is a TEE (a copy, mail
    /// still sent). Mailing a reply to a browser that cannot read mail is pure
    /// noise, so a session row sets this true. Kept per-ROW because it is a
    /// property of the path, never of the header (YPX-023 §3.4).
    #[serde(default)]
    pub suppress_email: bool,
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

    /// KI#114 — what ANTIE does when one of its loops STALLS (a heartbeat older
    /// than its bound: the maildir dispatch loop, or an IMAP/POP3 account).
    /// The OPERATOR's choice (owner ruling 2026-10-01); absent key = the
    /// default `notify_only` — an optional key, never a rewritten toml.
    /// * `"notify_only"` — `/health` answers `ok:false` naming the loop, and an
    ///   ERROR line names it in the log. The process keeps running.
    /// * `"notify_and_restart"` — the same, then ANTIE exits non-zero
    ///   (`health::STALL_EXIT_CODE`) so the supervisor (systemd / the env
    ///   driver) restarts it. A restart walks back nothing in the protocol —
    ///   the mail stays in `inbox/new/` or on the server.
    #[serde(default)]
    pub on_stall: OnStall,

    /// YPX-024 care-of pickup SUPPORT (operator-declared, default OFF —
    /// absent section = not supported). When set, a receiver-bound artifact
    /// whose VERIFIED `receiver_address` is care-of is deposited atomically
    /// into `<dir>/<pickup-domain>/new/` and ANTIE's obligation ends there;
    /// what collects it (MUMMY) is another carrier's problem, by design.
    /// Understanding (parse + fingerprint verify) is universal and does not
    /// depend on this.
    #[serde(default)]
    pub pickup: Option<PickupConfig>,

    /// Performance / backpressure settings (YPX-015)
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Per-wallet witness rate limit cooldown in ms (YPX-015 §2.3).
    /// Default 2000ms (0.5 req/sec/wallet). Set to 0 to disable.
    /// Production recommendation: 2000-5000ms depending on expected load.
    #[serde(default)]
    pub wallet_witness_cooldown_ms: Option<u64>,

    /// The ONE Nabla ban file (YP §32-33, KI#228; the owner 2026-09-29: "Nabla ban
    /// list should only have ONE file"). The co-located Nabla node writes it in
    /// its data dir (`nabla/src/ban.rs` `NABLA_BAN_FILE` /
    /// `BanTable::ban_file_contents`: every Nabla wallet ban, lowercase-hex SMT
    /// key per line). Validator-generated bans (§23.14 peer-audit, JFP freezes)
    /// are NOT in it. ANTIE reads it before forwarding a witness request.
    /// DEFAULT (set in `load` when absent): `<config dir>/../nabla_bans.txt` —
    /// the penguin dir `--data` Nabla runs in (`<dir>/config/antie.toml`
    /// beside `<dir>/nabla_bans.txt`). Best-effort (RULE 7 part 2): missing /
    /// unreadable → proceed, counted `ban_list_unavailable`.
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
    /// with `#` are comments; blank lines are ignored. Reloaded ONLY on
    /// SIGHUP — the fs-watch the design doc promised was never built, so
    /// a sibling carrier must signal ANTIE after rewriting the file
    /// (UNCLE's acl.rs does rename-then-SIGHUP).
    #[serde(default)]
    pub skip_list_path: Option<String>,
    /// Directory ANTIE writes skip-listed cheques into. ANTIE does
    /// not garbage-collect this directory; per the contract, sibling
    /// carriers claim by atomic rename out. Operators monitor depth
    /// (the `skipped_dir_count` metric on /status surfaces it).
    #[serde(default)]
    pub skipped_dir_path: Option<String>,
}

/// KI#114 — the operator's stall policy (`on_stall` in antie.toml).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnStall {
    /// `/health` not-ok + an ERROR log naming the stalled loop.
    #[default]
    NotifyOnly,
    /// As `NotifyOnly`, then exit non-zero so the supervisor restarts ANTIE.
    NotifyAndRestart,
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

    /// Lambda admin port for polling /stats. Optional in subprocess mode:
    /// `AntieConfig::resolve_lambda_admin_port` falls back to the `admin_port` of
    /// the Lambda config ANTIE already points at (YPX-015 §2.1 AS BUILT,
    /// 2026-09-26). ⚠ This used to DEFAULT to 7780 — alpha's port — and no
    /// generator ever wrote it, so on a 10-node host every ANTIE judged its own
    /// queue by ALPHA's witness time. There is no default port: unknown = the
    /// busy gate is not armed, logged at ERROR and shown as `lambda_stats_port: 0`.
    #[serde(default)]
    pub lambda_admin_port: Option<u16>,

    /// Lambda admin auth token (must match Lambda's admin_token). Optional in
    /// subprocess mode: `AntieConfig::resolve_lambda_admin_token` falls back to the
    /// `admin_token` of the Lambda config ANTIE already points at (YPX-015 §2.1
    /// AS BUILT, 2026-09-26) — ONE secret, not a copy per file.
    #[serde(default)]
    pub lambda_admin_token: Option<String>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            busy_threshold_ms: 15_000,
            lambda_stats_poll_ms: 2_000,
            lambda_admin_port: None,
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
    
    // (a "wallet-format" validator_id string lived here until 2026-09-09; it
    // was never read — the validator's id is BLAKE3 of its SPHINCS+ key, taken
    // from the certificate at load. Removed as duplicate, unbound information.)

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
        // ValidatorJoin §6b.12 (KI#171) — Core's typed bundle in CBOR (config/vbc-bundle.cbor),
        // decoded straight into the UMP type. The hand-rolled JSON struct that stood here
        // dropped node_name, proof_cap, the lineage, the OODS baseline and the issuer chain.
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[VBC_LOAD] Failed to read {}: {}", path, e);
                return None;
            }
        };
        let result: Option<axiom_core_logic::types::VBCProofBundle> = match ciborium::from_reader(bytes.as_slice()) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("[VBC_LOAD] {} is not a CBOR VBCProofBundle ({}) — vbc_path must name \
                           config/vbc-bundle.cbor (ValidatorJoin §6b.12)", path, e);
                return None;
            }
        };

        // Verify VBC structure (lightweight — no SPHINCS+ signature verification).
        // Full chain verification (with SPHINCS+) is Lambda's job at startup.
        // ANTIE verifies structure to catch corruption/misconfiguration early.
        // supporting_vbcs carries the issuer certificates for a non-genesis certificate (§6b.12).
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
            // 2000ms, NOT 10. This is the PULL-CARRIER loop interval — how often
            // ANTIE calls check_new() on POP3/IMAP, which for a real provider is a
            // request to SOMEONE ELSE'S SERVER. At 10ms that is ~100 req/s per
            // validator; three validators pointed at one provider is ~300 req/s,
            // sustained, forever. That is how a project gets blocklisted, and it was
            // the LIVE state on 2026-08-21 because a config regeneration silently
            // dropped the override. A default must be safe when the override is lost.
            poll_interval_ms: 2000,
            health_port: 7779,
            health_token: None,
            on_stall: OnStall::NotifyOnly,
            performance: PerformanceConfig::default(),
            wallet_witness_cooldown_ms: None,
            nabla_ban_list_path: None,
            skip_list_path: None,
            skipped_dir_path: None,
            pickup: None,
        }
    }
}

/// Mail credentials loaded from a SEPARATE local file (`mail-secrets.toml`, or
/// `$AXIOM_MAIL_SECRETS`), NOT the committed antie.toml — so IMAP/POP3/SMTP
/// passwords never enter version control. See
/// `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.7. Absent file = no-op.
#[derive(Debug, Clone, Deserialize, Default)]
struct MailSecrets {
    /// Credentials for the outbound external SMTP relay (real provider).
    #[serde(default)]
    external: Option<MailCred>,
    /// Credentials for the inbound accounts — `[inbound]` (one) or
    /// `[[inbound]]` (many, up to the carrier cap). Matched to
    /// `[[carriers.imap]]` / `[[carriers.pop3]]` entries by username.
    #[serde(default, deserialize_with = "one_or_many")]
    inbound: Vec<MailCred>,
}

impl MailSecrets {
    fn inbound_all(&self) -> &[MailCred] { &self.inbound }
}

/// Accept a single table or an array of tables for the same key.
fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<MailCred>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany { One(MailCred), Many(Vec<MailCred>) }
    Ok(match OneOrMany::deserialize(d)? { OneOrMany::One(c) => vec![c], OneOrMany::Many(v) => v })
}

#[derive(Debug, Clone, Deserialize)]
struct MailCred {
    username: String,
    password: String,
}

impl AntieConfig {
    /// The token ANTIE's YPX-015 `/stats` poller authenticates with: an explicit
    /// `[performance] lambda_admin_token` wins; otherwise, in subprocess mode,
    /// the top-level `admin_token` of `[lambda] config_path` (the Lambda this
    /// ANTIE spawns). `None` only when neither exists (e.g. tcp mode without
    /// the key) — the poller then counts every refused read (YPX-015 §2.1).
    pub fn resolve_lambda_admin_token(&self) -> Option<String> {
        if let Some(t) = self.performance.lambda_admin_token.as_ref().filter(|t| !t.is_empty()) {
            return Some(t.clone());
        }
        let LambdaConfig::Subprocess { config_path, .. } = &self.lambda else { return None };
        let text = std::fs::read_to_string(config_path).ok()?;
        let v: toml::Value = toml::from_str(&text).ok()?;
        v.get("admin_token").and_then(|t| t.as_str()).filter(|t| !t.is_empty()).map(String::from)
    }

    /// The port of the Lambda admin server ANTIE's YPX-015 `/stats` poller reads:
    /// an explicit `[performance] lambda_admin_port` wins; otherwise, in
    /// subprocess mode, the top-level `admin_port` of `[lambda] config_path` —
    /// THIS validator's own Lambda. `None` when neither exists (tcp mode
    /// without the key, or a Lambda with no admin server): the gate cannot know
    /// its own load, so it is not armed. Never a guessed default (it used to be
    /// 7780 = alpha, which made nine of ten validators read alpha's load).
    pub fn resolve_lambda_admin_port(&self) -> Option<u16> {
        if let Some(p) = self.performance.lambda_admin_port.filter(|p| *p != 0) {
            return Some(p);
        }
        let LambdaConfig::Subprocess { config_path, .. } = &self.lambda else { return None };
        let text = std::fs::read_to_string(config_path).ok()?;
        let v: toml::Value = toml::from_str(&text).ok()?;
        v.get("admin_port")
            .and_then(|p| p.as_integer())
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
    }

    /// Load from TOML file
    pub fn load(path: &std::path::Path) -> Result<Self, crate::error::AntieError> {
        let content = std::fs::read_to_string(path)?;
        let mut config: AntieConfig = toml::from_str(&content)
            .map_err(|e| crate::error::AntieError::ConfigError(e.to_string()))?;
        // Merge mail credentials from a SEPARATE local secrets file so passwords
        // never live in the committed antie.toml (design decision 2026-08-15). No-op when
        // the file is absent — the FATMAMA/loopback path needs no creds. §3.7.
        config.apply_mail_secrets(path)?;
        if config.nabla_ban_list_path.is_none() {
            config.nabla_ban_list_path = default_nabla_ban_list_path(path);
        }
        config.carriers.validate()?;
        // Design §5.2.2f: more than five inbound accounts = ANTIE will not start.
        config.carriers.validate_inbound_count()?;
        config.validate_poll_rate()?;
        Ok(config)
    }

    /// REFUSE a poll rate that would hammer someone else's mail server.
    ///
    /// `poll_interval_ms` drives the pull-carrier loop: one request per tick to
    /// whatever POP3/IMAP host a carrier names. At the old default of 10ms that
    /// is ~100 requests/second, per validator, forever — and on 2026-08-21 a
    /// config carrying exactly that was rendered onto a REMOTE box and ran until
    /// it was noticed by hand.
    ///
    /// ⚠ THIS LIVES AT CONFIG LOAD ON PURPOSE. The first version of this check
    /// sat inside the spawned polling task and returned Err — which the spawner
    /// merely logged (`error!("POP3 carrier exited: ...")`) before the task
    /// ended. The process kept running with no carrier and nothing enforced:
    /// a guard that reads as enforcement and prevents nothing
    /// ([[feedback_no_ghost_implementations]]). Failing here makes the value
    /// impossible to deploy: ANTIE will not start.
    fn validate_poll_rate(&self) -> Result<(), crate::error::AntieError> {
        const MIN_NETWORK_POLL_MS: u64 = 500;
        let has_network_pull = self.carriers.has_network_pull();
        if has_network_pull && self.poll_interval_ms < MIN_NETWORK_POLL_MS {
            return Err(crate::error::AntieError::ConfigError(format!(
                "poll_interval_ms = {} is below the {}ms floor. A POP3/IMAP carrier \
                 is configured, so this loop issues one request per tick to a \
                 third-party server — {}ms is ~{} requests/second, sustained. \
                 Raise poll_interval_ms.",
                self.poll_interval_ms, MIN_NETWORK_POLL_MS,
                self.poll_interval_ms, 1000 / self.poll_interval_ms.max(1),
            )));
        }
        Ok(())
    }

    /// Fill carrier usernames/passwords from a separate local file, never the
    /// committed config. Path: `$AXIOM_MAIL_SECRETS`, else `mail-secrets.toml`
    /// beside the config. Absent = no-op (loopback needs no creds).
    fn apply_mail_secrets(&mut self, config_path: &std::path::Path)
        -> Result<(), crate::error::AntieError>
    {
        use crate::error::AntieError;
        let secrets_path = std::env::var("AXIOM_MAIL_SECRETS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                config_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("mail-secrets.toml")
            });
        if !secrets_path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&secrets_path).map_err(|e| {
            AntieError::ConfigError(format!("mail-secrets read {}: {}", secrets_path.display(), e))
        })?;
        let secrets: MailSecrets = toml::from_str(&content)
            .map_err(|e| AntieError::ConfigError(format!("mail-secrets parse: {}", e)))?;
        // External SMTP relay (real provider) — only when the relay is configured.
        if let (Some(cred), Some(ext)) =
            (secrets.external.as_ref(), self.outbound.external.as_mut())
        {
            ext.username = Some(cred.username.clone());
            ext.password = Some(cred.password.clone());
        }
        // Inbound accounts (up to 5, design §5.2.2f). A credential applies to
        // every entry whose `username` matches it; an entry whose username
        // matches nothing keeps what antie.toml says. `[inbound]` (one) and
        // `[[inbound]]` (many) are both accepted — see `MailSecrets`.
        for cred in secrets.inbound_all() {
            for pop3 in self.carriers.pop3.iter_mut().filter(|c| c.username == cred.username) {
                pop3.password = cred.password.clone();
            }
            for imap in self.carriers.imap.iter_mut().filter(|c| c.username == cred.username) {
                imap.password = cred.password.clone();
            }
        }
        Ok(())
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
                // pop3/imap deliver INTO the maildir funnel — validate()
                // refuses them without it, so the example must carry it too.
                maildir: Some(MaildirConfig {
                    inbox:  "./maildir/inbox".into(),
                    outbox: "./maildir/outbox".into(),
                }),
                imap: vec![(ImapConfig {
                    enabled: true,
                    server:           "imap.example.com".into(),
                    port:             993,
                    username:         "validator@example.com".into(),
                    password:         "your-password".into(),
                    use_tls:          true,
                    inbox_folder:     "INBOX".into(),
                    use_idle:         true,
                })],
                ..Default::default()
            },
            outbound: OutboundConfig {
                custody: Vec::new(),
                route: Vec::new(),
                local: Some(SmtpOutboundConfig {
                    server:       "smtp.example.com".into(),
                    port:         587,
                    username:     Some("validator@example.com".into()),
                    password:     Some("your-password".into()),
                    use_tls:      true,
                    from_address: "validator@example.com".into(),
                }),
                external: None,
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
                maildir: Some(MaildirConfig {
                    inbox:  "./maildir/inbox".into(),
                    outbox: "./maildir/outbox".into(),
                }),
                pop3: vec![(Pop3Config {
                    enabled: true,
                    server:   "pop.example.com".into(),
                    port:     995,
                    username: "validator@example.com".into(),
                    password: "your-password".into(),
                    use_tls:  true,
                    spam_entropy_threshold: None,
                })],
                ..Default::default()
            },
            outbound: OutboundConfig {
                custody: Vec::new(),
                route: Vec::new(),
                local: Some(SmtpOutboundConfig {
                    server:       "smtp.example.com".into(),
                    port:         587,
                    username:     Some("validator@example.com".into()),
                    password:     Some("your-password".into()),
                    use_tls:      true,
                    from_address: "validator@example.com".into(),
                }),
                external: None,
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
                    // Documentation hosts ONLY (RFC 2606). This example is read
                    // by operators running their OWN deployment — every host,
                    // port and name here is theirs to choose, and a real domain
                    // belonging to this project would point their traffic at a
                    // stranger's box.
                    "fatmama:fatmama.example.com:2525".into(),
                    "tot:tot.example.com:7400".into(),
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
                imap: vec![(ImapConfig {
                    enabled: true,
                    server: "imap.example.com".into(), port: 993,
                    username: "node@example.com".into(), password: "secret".into(),
                    use_tls: true,
                    inbox_folder: "INBOX".into(), use_idle: true,
                })],
                pop3: vec![(Pop3Config {
                    enabled: true,
                    server: "pop.example.com".into(), port: 995,
                    username: "node@example.com".into(), password: "secret".into(),
                    use_tls: true,
                    spam_entropy_threshold: None,
                })],
                advertise: vec![
                    "fatmama:fatmama.example.com:2525".into(),
                    "tot:axiom-dev.mooo.com:7400".into(),
                ],
            },
            outbound: OutboundConfig {
                custody: Vec::new(),
                route: Vec::new(),
                local: Some(SmtpOutboundConfig {
                    server: "smtp.example.com".into(), port: 587,
                    username: None, password: None, use_tls: true,
                    from_address: "node@example.com".into(),
                }),
                external: None,
                uncle: None,
            },
            ..Default::default()
        };
        toml::to_string_pretty(&config).unwrap()
    }
}

/// File name of the ONE Nabla ban file — MUST equal `axiom_nabla::ban::NABLA_BAN_FILE`
/// (ANTIE does not depend on Nabla, RULE 7; the line format is pinned by the
/// shared golden `nabla/tests/fixtures/nabla_bans.golden`).
pub const NABLA_BAN_FILE: &str = "nabla_bans.txt";

/// KI#228 — the default ban-file path: the penguin dir that holds `config/`
/// (`<dir>/config/antie.toml` → `<dir>/nabla_bans.txt`), where a co-located
/// Nabla runs with `--data <dir>`. `None` when the config has no grandparent.
pub fn default_nabla_ban_list_path(config_path: &std::path::Path) -> Option<String> {
    let dir = config_path.parent()?.parent()?;
    Some(dir.join(NABLA_BAN_FILE).to_string_lossy().into_owned())
}

#[cfg(test)]
mod nabla_ban_file_default_tests {
    /// KI#228 — ON BY DEFAULT: `<dir>/config/antie.toml` reads the co-located
    /// Nabla's `<dir>/nabla_bans.txt` (the dir Nabla runs `--data` in); an
    /// explicit path wins. MUTATION: drop the default in `load` ⇒ red.
    #[test]
    fn ban_file_defaults_to_the_penguin_dir_nabla_writes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("config")).unwrap();
        let toml_path = dir.path().join("config").join("antie.toml");
        std::fs::write(&toml_path, "").unwrap();
        let c = super::AntieConfig::load(&toml_path).expect("empty antie.toml loads");
        assert_eq!(c.nabla_ban_list_path.as_deref(),
                   Some(dir.path().join("nabla_bans.txt").to_str().unwrap()));
        std::fs::write(&toml_path, "nabla_ban_list_path = \"/x/y.txt\"\n").unwrap();
        let c = super::AntieConfig::load(&toml_path).unwrap();
        assert_eq!(c.nabla_ban_list_path.as_deref(), Some("/x/y.txt"), "explicit path wins");
    }
}

#[cfg(test)]
mod poll_rate_tests {
    use super::*;

    fn cfg_with(poll_ms: u64, with_pop3: bool) -> AntieConfig {
        let mut c = AntieConfig::default();
        c.poll_interval_ms = poll_ms;
        if with_pop3 {
            c.carriers.pop3 = vec![(Pop3Config {
                enabled: true,
                server: "pop3.example.org".into(), port: 995,
                username: "u@example.org".into(), password: "x".into(),
                use_tls: true, spam_entropy_threshold: None,
            })];
        }
        c
    }

    /// The value that actually shipped to a remote box on 2026-08-21 and polled a
    /// third party ~100x/second. It must be IMPOSSIBLE to load.
    #[test]
    fn ten_milliseconds_with_a_network_carrier_is_refused() {
        let e = cfg_with(10, true).validate_poll_rate()
            .expect_err("10ms with a POP3 carrier must be refused at config load");
        let m = format!("{e}");
        assert!(m.contains("500"), "error must name the floor: {m}");
        assert!(m.contains("requests/second"), "error must state the cost: {m}");
    }

    #[test]
    fn safe_rate_with_a_network_carrier_loads() {
        assert!(cfg_with(2000, true).validate_poll_rate().is_ok());
        assert!(cfg_with(500, true).validate_poll_rate().is_ok(), "the floor itself is allowed");
    }

    /// No network carrier => nobody else's server is involved => not our business.
    #[test]
    fn fast_polling_without_a_network_carrier_is_allowed() {
        assert!(cfg_with(10, false).validate_poll_rate().is_ok());
    }
}

#[cfg(test)]
mod outbound_route_tests {
    /// A DUAL-@ delivery address must select the outbox by the wallet's own
    /// cluster domain, NOT the destination host — and must NOT depend on
    #[test]
    fn dual_at_routes_on_the_inner_domain_without_a_default() {
        use super::*;
        let cfg = OutboundConfig {
            route: vec![OutboundRoute {
                domain: "axiom.internal".into(),
                outbox: std::path::PathBuf::from("/tmp/ax-internal-outbox"),
            }],
            ..Default::default()
        };
        let got = cfg.outbox_for("alice@axiom.internal@node.example.com/a3f7b232")
            .expect("dual-@ must route, not reject");
        assert_eq!(got, Some(std::path::Path::new("/tmp/ax-internal-outbox")),
                   "routed on the destination host instead of the cluster domain");

        // Same address without a fingerprint.
        assert_eq!(cfg.outbox_for("alice@axiom.internal@node.example.com").unwrap(),
                   Some(std::path::Path::new("/tmp/ax-internal-outbox")));

        // A PLAIN cluster address is unaffected.
        assert_eq!(cfg.outbox_for("alice@axiom.internal/a3f7b232").unwrap(),
                   Some(std::path::Path::new("/tmp/ax-internal-outbox")));

        // A foreign domain still has no route and is REJECTED, not defaulted.
        assert!(cfg.outbox_for("bob@example.com").is_err(),
                "a domain with no route must fail closed");
    }


    use super::*;
    use std::path::{Path, PathBuf};

    // No `default` parameter: there is no fallback to configure any more.
    fn cfg(rows: &[(&str, &str)]) -> OutboundConfig {
        OutboundConfig {
            route: rows.iter().map(|(d, o)| OutboundRoute {
                domain: d.to_string(), outbox: PathBuf::from(o),
            }).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_table_means_legacy_path_not_an_error() {
        // Must be Ok(None), never Err — an empty table is "not in use", and
        // turning that into a rejection would strand every message the moment
        // the field shipped.
        assert!(matches!(cfg(&[]).outbox_for("a@axiom"), Ok(None)));
    }

    #[test]
    fn exact_domain_matches_and_is_case_insensitive() {
        let c = cfg(&[("axiom", "/out/local")]);
        assert_eq!(c.outbox_for("bob@axiom").unwrap().unwrap(), Path::new("/out/local"));
        assert_eq!(c.outbox_for("BOB@AXIOM").unwrap().unwrap(), Path::new("/out/local"));
        // wallet_id form: domain is taken before the /fingerprint suffix
        assert_eq!(c.outbox_for("bob@axiom/a3f7b2ff").unwrap().unwrap(), Path::new("/out/local"));
    }

    #[test]
    fn suffix_and_subdomain_evasions_do_not_match() {
        // The whole point of exact matching (YPX-019 §3.1). Both of these were
        // real evasions tested against FATMAMA's guard and rejected there too.
        let c = cfg(&[("axiom", "/out/local")]);
        // With NO fallback these must be REFUSED outright — a stronger property
        // than "lands in the external outbox", which is what the default used to
        // give us and what let a misroute look like success.
        for evasion in ["x@evil-axiom.com", "x@axiom.internal.evil.com", "x@myaxiom"] {
            assert!(c.outbox_for(evasion).is_err(),
                    "{evasion} must be REJECTED, not routed anywhere");
        }
        // And the genuine cluster domain still routes.
        assert_eq!(c.outbox_for("x@axiom").unwrap().unwrap(), Path::new("/out/local"));
    }

    #[test]
    fn unmatched_domain_without_default_REJECTS_never_drops() {
        // AntieOutboundSplit §4. The failure mode this guards against is silent
        // stranding — 7 of 10 validators, invisibly (see gateway.rs).
        let c = cfg(&[("axiom", "/out/local")]);
        let err = c.outbox_for("someone@example.com").unwrap_err();
        assert!(err.contains("REJECTING"), "must reject loudly, got: {err}");
    }

    #[test]
    fn malformed_recipient_rejects_rather_than_guessing() {
        let c = cfg(&[("axiom", "/out/local")]);
        assert!(c.outbox_for("no-at-sign").is_err());
    }
}

#[cfg(test)]
mod vbc_bundle_load_tests {
    //! ValidatorJoin §6b.12 (KI#171) — ANTIE loads the validator's certificate as Core's bundle, whole.
    use super::*;
    use axiom_core_logic::types::{VBCProofBundle, VBC};

    #[test]
    fn antie_loads_the_certificate_bundle_whole() {
        // Structurally valid shapes (ANTIE runs the structure-only check): validator_id = BLAKE3(sphincs),
        // three issuers + three signatures, issuers root-issued at depth 0.
        let roots: Vec<Vec<u8>> = axiom_core_logic::genesis::ROOT_AUTHORITY_PKS.iter().map(|r| r.to_vec()).collect();
        let mk = |k: u8| VBC {
            genesis_lineage: [0u8; 32], version: 0x09, validator_id: *blake3::hash(&[k; 32]).as_bytes(),
            subject_pubkey_sphincs: vec![k; 32], subject_pubkey_dilithium: vec![], subject_pubkey_ed25519: vec![2u8; 32],
            pgp_fingerprint: vec![], node_name: String::new(), proof_cap: String::new(), issued_at: 1, expires_at: 2,
            chain_depth: 0, issuer_set: roots.clone(), signatures: vec![vec![]; 3], max_tx: 0, founding_vbc_hash: [0u8; 32],
            network_size_baseline: 0, baseline_tick: 0, nabla_registration: None,
        };
        let mut target = mk(7);
        target.proof_cap = "dmap".into();
        target.genesis_lineage = [9u8; 32];
        target.network_size_baseline = 10;
        target.baseline_tick = 1_789_391_415;
        target.chain_depth = 1;
        target.node_name = "community-1".into();
        target.issuer_set = vec![vec![1u8; 32], vec![3u8; 32], vec![4u8; 32]];
        let bundle = VBCProofBundle { target_vbc: target, supporting_vbcs: vec![mk(1), mk(3), mk(4)], candidacy_pulse: None, renewal_work_receipt: None };
        let path = std::env::temp_dir().join(format!("antie_vbc_bundle_{}.cbor", std::process::id()));
        let mut cbor = Vec::new();
        ciborium::into_writer(&bundle, &mut cbor).unwrap();
        std::fs::write(&path, &cbor).unwrap();
        let cfg = ValidatorConfig { vbc_path: Some(path.to_string_lossy().into_owned()), ..ValidatorConfig::default() };
        let loaded = cfg.load_vbc();
        let _ = std::fs::remove_file(&path);
        let b = loaded.expect("ANTIE must load a CBOR certificate bundle");
        let t = &b.target_vbc;
        assert_eq!((t.proof_cap.as_str(), t.genesis_lineage, t.network_size_baseline, t.node_name.as_str()),
                   ("dmap", [9u8; 32], 10, "community-1"));
        assert_eq!(b.supporting_vbcs.len(), 3, "the issuer chain is loaded");
    }
}

#[cfg(test)]
mod lambda_admin_token_tests {
    //! YPX-015 §2.1 AS BUILT (2026-09-26): the /stats poller's token comes from
    //! ONE secret — antie.toml if set, else the spawned Lambda's own config.
    use super::*;

    fn cfg_with(lambda_toml: &str, antie_token: Option<&str>) -> (AntieConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lambda.toml");
        std::fs::write(&path, lambda_toml).unwrap();
        let mut c = AntieConfig::default();
        c.lambda = LambdaConfig::Subprocess { binary_path: PathBuf::from("/bin/true"), config_path: path };
        c.performance.lambda_admin_token = antie_token.map(String::from);
        (c, dir)
    }

    #[test]
    fn falls_back_to_the_lambda_config_admin_token() {
        let (c, _d) = cfg_with("admin_port = 7780\nadmin_token = \"lam-secret\"\n[network]\n", None);
        assert_eq!(c.resolve_lambda_admin_token().as_deref(), Some("lam-secret"));
    }

    #[test]
    fn explicit_antie_token_wins() {
        let (c, _d) = cfg_with("admin_token = \"lam-secret\"\n", Some("antie-secret"));
        assert_eq!(c.resolve_lambda_admin_token().as_deref(), Some("antie-secret"));
    }

    #[test]
    fn empty_antie_token_does_not_hide_the_lambda_one() {
        let (c, _d) = cfg_with("admin_token = \"lam-secret\"\n", Some(""));
        assert_eq!(c.resolve_lambda_admin_token().as_deref(), Some("lam-secret"));
    }

    #[test]
    fn port_comes_from_the_validators_own_lambda_config() {
        // Two validators on one host: each must resolve ITS OWN Lambda's port.
        let (alpha, _a) = cfg_with("admin_port = 7780\n", None);
        let (beta, _b) = cfg_with("admin_port = 7781\n", None);
        assert_eq!(alpha.resolve_lambda_admin_port(), Some(7780));
        assert_eq!(beta.resolve_lambda_admin_port(), Some(7781));
    }

    #[test]
    fn explicit_port_wins_and_zero_means_unset() {
        let (mut c, _d) = cfg_with("admin_port = 7781\n", None);
        c.performance.lambda_admin_port = Some(7799);
        assert_eq!(c.resolve_lambda_admin_port(), Some(7799));
        c.performance.lambda_admin_port = Some(0);
        assert_eq!(c.resolve_lambda_admin_port(), Some(7781));
    }

    #[test]
    fn no_port_is_none_never_a_guessed_default() {
        let (c, _d) = cfg_with("admin_token = \"x\"\n", None);
        assert_eq!(c.resolve_lambda_admin_port(), None, "a Lambda without admin_port has no /stats to read");
        assert_eq!(AntieConfig::default().performance.lambda_admin_port, None);
        let mut tcp = AntieConfig::default();
        tcp.lambda = LambdaConfig::Tcp {
            address: "127.0.0.1:9001".into(), timeout_secs: 30,
            tls_server_name: None, tls_ca_cert_path: None,
        };
        assert_eq!(tcp.resolve_lambda_admin_port(), None);
    }

    #[test]
    fn none_when_neither_has_a_token() {
        let (c, _d) = cfg_with("admin_port = 7780\n", None);
        assert_eq!(c.resolve_lambda_admin_token(), None);
        let mut tcp = AntieConfig::default();
        tcp.lambda = LambdaConfig::Tcp {
            address: "127.0.0.1:9001".into(), timeout_secs: 30,
            tls_server_name: None, tls_ca_cert_path: None,
        };
        assert_eq!(tcp.resolve_lambda_admin_token(), None);
    }
}
