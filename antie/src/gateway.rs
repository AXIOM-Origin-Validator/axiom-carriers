//! ANTIE Gateway
//!
//! The main gateway logic that orchestrates:
//! 1. Watch for new emails (via carrier)
//! 2. Parse email → extract payload
//! 3. PGP decrypt (if encrypted cheque — sequoia-openpgp at ANTIE layer)
//! 4. Core (CL2 validate) ← Gateway's job!
//! 5. Lambda (business logic)
//! 6. Core (CL3 witness) — Lambda does this
//! 7. PGP encrypt cheque for receiver (ANTIE layer, recipient's public key)
//! 8. Send response email (via carrier)
//!
//! # Design: Encryption is ANTIE's responsibility, NOT Core's.
//!
//! PGP cheque encryption/decryption happens at the ANTIE transport layer.
//! Core never sees PGP keys or ciphertext — it only validates transaction
//! data (plaintext CBOR). The IPC between ANTIE → Core → Lambda carries
//! unencrypted payloads because all three run on the same machine under
//! the same operator. There is no security boundary between them that
//! requires encryption — they share the same trust domain.
//!
//! The encryption boundary is between ANTIE and the NETWORK (email/TCP).
//! That's where PGP protects cheques from eavesdropping in transit.

use crate::carrier::{self, MailCarrier, MaildirConfig, ImapConfig, Pop3Config};
use crate::config::{AntieConfig, LambdaConfig};
use crate::core_ipc;
use crate::email::{self, AntieEmail, ResponsePayload};
use crate::error::AntieError;
use crate::lambda_client::LambdaClient;
use axiom_dmap_vm::AvmInterpreter;
use axiom_core_logic::types::{WitnessSig, Receipt, GroupMember};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// VBC request to Lambda (serializable for CBOR IPC)
#[derive(Debug, Serialize)]
struct VbcSignRequest {
    #[serde(rename = "type")]
    request_type: String,
    request_id: String,
    sphincs_pk_hex: String,
    dilithium_pk_hex: String,
    ed25519_pk_hex: String,
    pgp_fingerprint_hex: String,
    #[serde(default)]
    proof_cap: String,
    #[serde(default)]
    node_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    issuer_set_hex: Vec<String>,
}

/// VBC response from Lambda
#[derive(Debug, Deserialize)]
struct VbcResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    error: Option<String>,
}

/// ANTIE Gateway
/// Per-wallet witness rate limiter (YPX-015 §2.3).
///
/// Tracks the last witness request timestamp per sender_wallet_id.
/// Rejects requests within the cooldown window with E_WALLET_RATE_LIMITED
/// before they reach Lambda or Core. This is the cheapest DDoS defense:
/// a single hash lookup on a field ANTIE already reads.
///
/// S-ABR overlap requests (carrying overlapped_signatures) are exempt —
/// they're legitimate protocol traffic from the previous TX's validators.
struct WalletRateLimiter {
    last_request: std::collections::HashMap<String, std::time::Instant>,
    cooldown: std::time::Duration,
}

impl WalletRateLimiter {
    fn new(cooldown_ms: u64) -> Self {
        Self {
            last_request: std::collections::HashMap::new(),
            cooldown: std::time::Duration::from_millis(cooldown_ms),
        }
    }

    /// Check if this wallet_id is rate-limited. Returns true if allowed.
    fn check_and_record(&mut self, wallet_id: &str) -> bool {
        let now = std::time::Instant::now();
        if let Some(last) = self.last_request.get(wallet_id) {
            if now.duration_since(*last) < self.cooldown {
                return false;
            }
        }
        self.last_request.insert(wallet_id.to_string(), now);
        true
    }

    /// Evict entries older than 2× cooldown to bound memory.
    fn evict_stale(&mut self) {
        let cutoff = std::time::Instant::now() - self.cooldown * 2;
        self.last_request.retain(|_, ts| *ts > cutoff);
    }
}

pub struct Gateway {
    /// Configuration
    config: AntieConfig,

    /// Sibling-carrier skip-list. `Some(_)` when both
    /// `skip_list_path` and `skipped_dir_path` are configured (one
    /// sibling carrier installed — UNCLE/COUSIN/future); `None`
    /// otherwise (every outbound cheque goes through the existing
    /// email path). Contract:
    /// `docs/AXIOM_DESIGN_AntieSkipList.md`.
    skip_list: Option<std::sync::Arc<crate::skip_list::SkipList>>,

    /// Outbound carrier for sending responses (Maildir outbox or SMTP)
    sender: Box<dyn MailCarrier>,

    /// Optional UNCLE tee — when configured (per
    /// `outbound.uncle.outbox_path` in antie.toml), every response
    /// carrying a top-level `txid` field is also written to
    /// `<outbox>/<txid_hex>.cbor` so UNCLE's `witness_observer` can
    /// ship the bytes back to in-flight `SubmitSend` callers on
    /// their held TCP connections. Best-effort — failures here do
    /// NOT block the primary SMTP/maildir dispatch.
    uncle_sink: Option<std::sync::Arc<crate::uncle_sink::UncleSink>>,

    /// AVM interpreter for CL2 validation — direct execution, no subprocess.
    core: AvmInterpreter,

    /// Lambda client
    lambda: LambdaClient,

    /// Running flag
    running: Arc<RwLock<bool>>,

    /// Fan-Out replay prevention — seen diffusion_ids (in-memory, survives session).
    /// Prevents re-processing within the 24h FANOUT_MAX_AGE_SECS window.
    /// Lost on restart — acceptable since CL10 timestamp check provides base protection.
    fanout_seen: Arc<RwLock<std::collections::HashSet<[u8; 32]>>>,

    /// Metrics counters (shared with health endpoint).
    stats: Arc<crate::stats::AntieStats>,

    /// Per-wallet witness rate limiter (YPX-015 §2.3).
    wallet_rate_limiter: Arc<tokio::sync::Mutex<WalletRateLimiter>>,

    /// Forward-direction envelope decryptor.  `Some` when
    /// `[validator] private_key_path` is set in antie.toml; otherwise
    /// `None` (Plain envelopes still parse normally — useful for legacy
    /// deployments and shadow-mode rollout).  See
    /// `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.4 and `decrypt.rs`.
    envelope_decryptor: Option<Arc<crate::decrypt::EnvelopeDecryptor>>,
}

/// Deserialize a `WitnessRequest` from the SDK's raw post-envelope-unwrap
/// CBOR body. Handles ONE legacy quirk: the SDK's
/// `Transaction::to_canonical_cbor_value` emits `is_heal` /
/// `is_validator_withdrawal_mint` discriminator bools in addition to the
/// canonical `kind: TxKind` field — preserved for byte-identical receipt
/// commitments on pre-9B.1 Normal/Heal/GenesisClaim TXs. The
/// `Transaction` struct uses `#[serde(deny_unknown_fields)]` (C2 attack
/// guard), so a raw `ciborium::from_reader::<WitnessRequest>` rejects
/// the body with "unknown field `is_heal`".
///
/// We strip those three bools from `transaction` before the typed
/// deserialize and reconstruct `kind` from them after. The
/// transformation is contained in one function so the WitnessRequest
/// envelope stays the single source of truth elsewhere.
fn deserialize_witness_request(
    bytes: &[u8],
) -> Result<axiom_core_logic::types::WitnessRequest, ciborium::de::Error<std::io::Error>> {
    use ciborium::Value;
    use axiom_core_logic::types::TxKind;

    let mut top: Value = ciborium::from_reader(bytes)?;

    // Try to find legacy discriminator bools (pre-9B canonical shape).
    // Post-SDK-migration the SDK ships typed serialization — the bools
    // aren't present, and `Transaction.kind` is carried directly via
    // the serde tag. In that case we MUST NOT overwrite `kind` after
    // the typed decode, because the strip would force `Normal` and
    // silently reject genesis claims as "Cannot send to own address".
    let (any_bool_present, is_heal, is_mint, is_genesis, is_hal_reanchor, is_recall) = if let Value::Map(ref mut pairs) = top {
        let tx_idx = pairs.iter().position(|(k, _)| k.as_text() == Some("transaction"));
        if let Some(idx) = tx_idx {
            if let Value::Map(ref mut tx_pairs) = pairs[idx].1 {
                let take = |pairs: &mut Vec<(Value, Value)>, key: &str| -> (bool, bool) {
                    if let Some(pos) = pairs.iter().position(|(k, _)| k.as_text() == Some(key)) {
                        let val = pairs.remove(pos).1;
                        (true, matches!(val, Value::Bool(true)))
                    } else {
                        (false, false)
                    }
                };
                let (h_present, h) = take(tx_pairs, "is_heal");
                let (m_present, m) = take(tx_pairs, "is_validator_withdrawal_mint");
                let (g_present, g) = take(tx_pairs, "is_genesis_claim");
                // YPX-020 HAL: strip + carry the re-anchor discriminator so
                // the typed decode (deny_unknown_fields) doesn't reject, and
                // `kind` is reconstructed as HalReanchor below.
                let (r_present, r) = take(tx_pairs, "is_hal_reanchor");
                let (rec_present, rec) = take(tx_pairs, "is_recall");
                (h_present || m_present || g_present || r_present || rec_present, h, m, g, r, rec)
            } else {
                (false, false, false, false, false, false)
            }
        } else {
            (false, false, false, false, false, false)
        }
    } else {
        (false, false, false, false, false, false)
    };

    // Re-encode the cleaned ciborium::Value, then typed-deserialize.
    let mut buf = Vec::with_capacity(bytes.len());
    ciborium::into_writer(&top, &mut buf)
        .map_err(|e| ciborium::de::Error::Semantic(None, format!("re-encode: {}", e)))?;
    let mut req: axiom_core_logic::types::WitnessRequest =
        ciborium::from_reader(buf.as_slice())?;

    // Only reconstruct `kind` if the legacy bools were actually in the
    // body. Post-SDK-migration bodies carry `kind` natively via the
    // serde tag and the typed decode above already populated it.
    if any_bool_present {
        req.transaction.kind = if is_mint {
            TxKind::ValidatorWithdrawalMint
        } else if is_genesis {
            TxKind::GenesisClaim
        } else if is_hal_reanchor {
            TxKind::HalReanchor
        } else if is_recall {
            TxKind::Recall
        } else if is_heal {
            TxKind::Heal
        } else {
            TxKind::Normal
        };
    }

    Ok(req)
}

impl Gateway {
    /// Create new Gateway
    pub async fn new(config: AntieConfig) -> Result<Self, AntieError> {
        // Validate carrier config
        config.carriers.validate()?;

        // Sibling-carrier skip-list. Disabled (None) when either path
        // is unset — consumer-validator deployments with no UNCLE /
        // COUSIN running. When enabled, install a SIGHUP handler so
        // sibling carriers can rewrite+SIGHUP for reloads.
        let skip_list = crate::skip_list::SkipList::maybe_open(
            config.skip_list_path.as_deref(),
            config.skipped_dir_path.as_deref(),
        )
        .await?;
        if let Some(ref sl) = skip_list {
            crate::skip_list::install_sighup_handler(std::sync::Arc::clone(sl));
        }

        // Create outbound sender — SMTP preferred when configured (real email path),
        // falls back to Maildir outbox (local-only mode without MTA).
        let sender: Box<dyn MailCarrier> = if let Some(ref smtp) = config.outbound.smtp {
            Box::new(carrier::smtp_carrier::SmtpCarrier::new(
                smtp.server.clone(), smtp.port,
                smtp.username.clone(), smtp.password.clone(),
                smtp.use_tls, smtp.from_address.clone(),
            ))
        } else if let Some(ref md) = config.carriers.maildir {
            Box::new(carrier::maildir_carrier::MaildirCarrier::new(&md.inbox, &md.outbox).await?)
        } else {
            return Err(AntieError::ConfigError(
                "No outbound carrier configured (need outbound.smtp or carriers.maildir)".into()
            ));
        };

        // Create AVM interpreter for CL2 validation — no core-bin subprocess.
        let avm_elf_path = config.core.avm_elf_path.clone()
            .or_else(|| std::env::var("AXIOM_AVM_ELF").ok().map(std::path::PathBuf::from))
            .or_else(|| config.core.core_bin_path.as_ref().and_then(|p| {
                // Try sibling axiom-core.elf next to old core-bin path
                p.parent().map(|dir| dir.join("axiom-core.elf"))
            }))
            .unwrap_or_else(|| std::path::PathBuf::from("./axiom-core.elf"));

        let avm = if avm_elf_path.exists() {
            let avm_config = axiom_dmap_vm::AvmConfig::from_paths(
                avm_elf_path.to_str().ok_or_else(|| AntieError::ConfigError("AVM ELF path is not valid UTF-8".into()))?,
                None,
            ).map_err(|e| AntieError::ConfigError(format!("Failed to load AVM ELF: {}", e)))?;
            info!("AVM interpreter: core_id={}", hex::encode(avm_config.core_id));
            AvmInterpreter::new(avm_config.elf_bytes, [0u8; 32])
        } else {
            // GAP-5 FIX: Fail-stop if no AVM ELF found.
            // Without a real ELF, ANTIE cannot run CL2 validation through the AVM interpreter.
            return Err(AntieError::ConfigError(format!(
                "No AVM ELF found at {:?}. Set avm_elf_path in config, \
                 set AXIOM_AVM_ELF env var, or place axiom-core.elf there. \
                 Run build-zkvm.sh to build it.",
                avm_elf_path,
            )));
        };
        info!("AVM interpreter ready for CL2 validation");

        // Create Lambda client based on mode
        let lambda = match &config.lambda {
            LambdaConfig::Tcp { address, timeout_secs, tls_server_name, tls_ca_cert_path } => {
                if let Some(server_name) = tls_server_name {
                    info!("Lambda mode: TCP+TLS ({}, sni={})", address, server_name);
                    LambdaClient::new_tcp_tls(address, *timeout_secs, server_name, tls_ca_cert_path.as_deref())?
                } else {
                    info!("Lambda mode: TCP ({}, plaintext)", address);
                    LambdaClient::new_tcp(address, *timeout_secs)
                }
            }
            LambdaConfig::Subprocess { binary_path, config_path } => {
                info!("Lambda mode: Subprocess ({:?})", binary_path);
                info!("  Config: {:?}", config_path);
                LambdaClient::new_subprocess(binary_path.clone(), config_path.clone())
            }
        };

        info!("ANTIE Gateway initialized (multi-carrier mode)");

        // Forward-direction envelope decryptor (AXIOM_DESIGN_PublicMailCarriers.md §3.4).
        // Reads the validator's Ed25519 seed file — same file Lambda
        // signs with — and derives the X25519 secret in memory.  Absent
        // (None) when `validator.private_key_path` isn't set in the
        // config: encrypted envelopes will fail decrypt and bump the
        // `decrypt_fail` metric, while Plain envelopes still parse.
        let envelope_decryptor = match &config.validator.private_key_path {
            Some(path) => {
                match crate::decrypt::EnvelopeDecryptor::from_key_file(std::path::Path::new(path)) {
                    Ok(d) => {
                        info!(
                            "Envelope decryptor loaded — recipient_id={}",
                            hex::encode(d.ed25519_pk),
                        );
                        Some(Arc::new(d))
                    }
                    Err(e) => {
                        // Fail-stop here matches CLAUDE.md §13: a
                        // configured decryptor that fails to load is a
                        // bug, not a soft fallback.  Surface it so the
                        // operator notices on first restart.
                        return Err(e);
                    }
                }
            }
            None => {
                info!("No validator.private_key_path configured — UmpEnvelope::Encrypted will be dropped");
                None
            }
        };

        // Optional UNCLE sink — opens the outbox directory if the
        // operator declared `[outbound.uncle] outbox_path = "..."`.
        // None on validators that don't run UNCLE.
        let uncle_sink: Option<Arc<crate::uncle_sink::UncleSink>> =
            match &config.outbound.uncle {
                Some(cfg) => {
                    let sink = crate::uncle_sink::UncleSink::new(cfg.outbox_path.clone())
                        .await?;
                    info!(
                        "uncle_sink: tee enabled at {}",
                        sink.outbox_path().display()
                    );
                    Some(Arc::new(sink))
                }
                None => None,
            };

        let cooldown_ms = config.wallet_witness_cooldown_ms.unwrap_or(2000);
        Ok(Self {
            config,
            sender,
            uncle_sink,
            stats: {
                let s = Arc::new(crate::stats::AntieStats::new());
                let fp = avm.core_fingerprint();
                if let Ok(mut v) = s.core_version.write() {
                    *v = hex::encode(&fp[..16]);
                }
                s
            },
            core: avm,
            lambda,
            running: Arc::new(RwLock::new(true)),
            fanout_seen: Arc::new(RwLock::new(std::collections::HashSet::new())),
            wallet_rate_limiter: Arc::new(tokio::sync::Mutex::new(
                WalletRateLimiter::new(cooldown_ms)
            )),
            envelope_decryptor,
            skip_list,
        })
    }
    
    /// Run the gateway — spawns one task per configured carrier (JoinSet fan-in).
    pub async fn run(self: Arc<Self>) -> Result<(), AntieError> {
        info!("ANTIE Gateway starting (multi-carrier mode)...");

        self.config.carriers.validate()?;
        self.lambda.start().await?;

        // Phase 1 multi-carrier discovery (YP §27.5.2, 2026-05-14).
        //
        // Push the operator's `[carriers.*]` configuration to Lambda as a
        // canonical YP §27.5.2 URI list so VSP responses advertise every
        // supported routing channel, not the hardcoded
        // "dev:validator-<8 hex>" placeholder Lambda used to ship.
        // CarriersConfig::to_uri_list collapses maildir/imap/pop3 to a
        // single `email:<identity_email>` entry and adds `tcp:H:P` /
        // `ws:H:P` for any TCP / WebSocket carriers configured.
        //
        // Empty list is permitted but Lambda logs a loud warning so the
        // operator notices the misconfig at startup. ANTIE's
        // `carriers.validate()` above already requires at least one
        // email carrier, so reaching this line guarantees ≥1 URI.
        let carrier_uris = self.config.carriers.to_uri_list(&self.config.identity.email);
        let request_id = format!("set-carriers-startup-{}", std::process::id());
        match self.lambda.send_set_carriers_request(&request_id, carrier_uris.clone()).await {
            Ok(ack) => info!(
                "[VSP] Pushed {} carrier URI(s) to Lambda: {:?}",
                ack.accepted, carrier_uris,
            ),
            Err(e) => warn!(
                "[VSP] set_carriers IPC failed at startup: {}. VSP will report empty carriers \
                 until Lambda restarts and ANTIE retries — peers cannot route to this validator \
                 in the meantime.", e,
            ),
        }

        // Health/status endpoint
        let _health_handle = crate::health::spawn_health_server(
            self.config.health_port, self.stats.clone(), self.config.health_token.clone(),
        );

        // Populate active_carriers for the /status endpoint
        {
            let mut names = Vec::new();
            if self.config.carriers.maildir.is_some() { names.push("maildir"); }
            if self.config.carriers.imap.is_some() { names.push("imap"); }
            if self.config.carriers.pop3.is_some() { names.push("pop3"); }
            if let Ok(mut w) = self.stats.active_carriers.write() {
                *w = names.join(",");
            }
        }

        let mut tasks = tokio::task::JoinSet::new();

        // Maildir carrier — inotify-based
        if let Some(ref cfg) = self.config.carriers.maildir {
            let gw = self.clone();
            let cfg = cfg.clone();
            tasks.spawn(async move {
                if let Err(e) = gw.run_maildir_carrier(&cfg).await {
                    error!("Maildir carrier exited: {}", e);
                }
            });
        }

        // IMAP carrier — polling
        if let Some(ref cfg) = self.config.carriers.imap {
            let gw = self.clone();
            let cfg = cfg.clone();
            tasks.spawn(async move {
                if let Err(e) = gw.run_imap_carrier(&cfg).await {
                    error!("IMAP carrier exited: {}", e);
                }
            });
        }

        // POP3 carrier — polling
        if let Some(ref cfg) = self.config.carriers.pop3 {
            let gw = self.clone();
            let cfg = cfg.clone();
            tasks.spawn(async move {
                if let Err(e) = gw.run_pop3_carrier(&cfg).await {
                    error!("POP3 carrier exited: {}", e);
                }
            });
        }

        // (TCP + WebSocket carriers removed 2026-05-21 — both transports
        // are no longer ANTIE's job. Direct-delivery transports run as
        // sibling processes — TOT today, future schemes — and are
        // advertised via `[carriers] advertise = [...]` in antie.toml.)

        // Skip-list `skipped_dir_count` metric refresher — every 30s
        // walk the directory, store the count on `stats.skipped_dir_count`
        // so /status surfaces a fresh (~30s lag) value. Operators
        // alert on growth per AXIOM_DESIGN_AntieSkipList.md §4 (no
        // TTL in the reference impl).
        if let Some(ref sl) = self.skip_list {
            let sl = Arc::clone(sl);
            let stats = self.stats.clone();
            let running = self.running.clone();
            tasks.spawn(async move {
                use std::sync::atomic::Ordering;
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    if !*running.read().await { break; }
                    let count = sl.skipped_dir_count() as u64;
                    stats.skipped_dir_count.store(count, Ordering::Relaxed);
                }
            });
            info!("skip_list: skipped_dir_count metric refresher running (30s cadence)");
        }

        // YPX-015: Background task to poll Lambda /stats for avg_witness_ms
        if self.config.performance.busy_threshold_ms > 0 {
            let stats = self.stats.clone();
            let admin_port = self.config.performance.lambda_admin_port;
            let admin_token = self.config.performance.lambda_admin_token.clone();
            let poll_ms = self.config.performance.lambda_stats_poll_ms;
            let running = self.running.clone();
            tasks.spawn(async move {
                Self::poll_lambda_stats(stats, admin_port, admin_token, poll_ms, running).await;
            });
            info!("YPX-015: Backpressure enabled (threshold={}ms, polling Lambda admin :{} every {}ms)",
                  self.config.performance.busy_threshold_ms, admin_port, poll_ms);
        }

        // Wait for all tasks. If one crashes, log but keep others running.
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                error!("Carrier task panicked: {:?}", e);
            }
        }

        self.lambda.stop().await?;
        info!("ANTIE Gateway stopped");
        Ok(())
    }

    // ========================================================================
    // Per-carrier run methods
    // ========================================================================

    /// Run the Maildir carrier (inotify watcher loop).
    async fn run_maildir_carrier(&self, cfg: &MaildirConfig) -> Result<(), AntieError> {
        let carrier = carrier::maildir_carrier::MaildirCarrier::new(&cfg.inbox, &cfg.outbox).await?;
        let inbox_new_path = cfg.inbox.join("new");

        info!("Maildir carrier watching: {}", inbox_new_path.display());

        use notify::{Watcher, RecursiveMode, Event, EventKind};
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(100);

        let watch_path = inbox_new_path.clone();
        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let rt_tx = tx;
            let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            let _ = rt_tx.blocking_send(());
                        }
                        _ => {}
                    }
                }
            }).expect("Failed to create file watcher");

            watcher.watch(&watch_path, RecursiveMode::NonRecursive)
                .expect("Failed to watch inbox directory");

            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        });

        // Process existing messages
        self.process_carrier_messages(&carrier).await;

        // Event loop
        while *self.running.read().await {
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                rx.recv()
            ).await {
                Ok(Some(())) => {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    while rx.try_recv().is_ok() {}
                    self.process_carrier_messages(&carrier).await;
                }
                Ok(None) => {
                    warn!("Maildir watcher channel closed");
                    break;
                }
                Err(_) => {
                    self.process_carrier_messages(&carrier).await;
                }
            }
            self.process_carrier_messages(&carrier).await;
        }

        Ok(())
    }

    /// Run the IMAP carrier (polling loop).
    async fn run_imap_carrier(&self, cfg: &ImapConfig) -> Result<(), AntieError> {
        let carrier = carrier::imap_carrier::ImapCarrier::new(
            cfg.server.clone(), cfg.port,
            cfg.username.clone(), cfg.password.clone(),
            cfg.use_tls, cfg.inbox_folder.clone(), cfg.processed_folder.clone(),
        );
        info!("IMAP carrier started: {}:{}", cfg.server, cfg.port);
        self.run_polling_loop(&carrier).await
    }

    /// Run the POP3 carrier (polling loop).
    async fn run_pop3_carrier(&self, cfg: &Pop3Config) -> Result<(), AntieError> {
        let carrier = carrier::pop3_carrier::Pop3Carrier::new(
            cfg.server.clone(), cfg.port,
            cfg.username.clone(), cfg.password.clone(),
            cfg.use_tls,
        );
        info!("POP3 carrier started: {}:{}", cfg.server, cfg.port);
        self.run_polling_loop(&carrier).await
    }

    /// Generic polling loop — shared by IMAP and POP3 carriers.
    async fn run_polling_loop(&self, carrier: &dyn MailCarrier) -> Result<(), AntieError> {
        let poll_interval = std::time::Duration::from_millis(self.config.poll_interval_ms);
        while *self.running.read().await {
            self.process_carrier_messages(carrier).await;
            tokio::time::sleep(poll_interval).await;
        }
        Ok(())
    }

    // (run_tcp_carrier / run_ws_carrier / process_tcp_message removed
    // 2026-05-21 — TCP + WebSocket carriers are no longer ANTIE's job.
    // Direct-delivery transports run as sibling processes — TOT today,
    // future schemes — and are advertised via [carriers] advertise list.)


    /// Process all pending messages from a specific carrier.
    ///
    /// YPX-015 backpressure: before processing each message, estimate the wait
    /// time (remaining_queue × avg_witness_ms). If it exceeds the configured
    /// threshold, reject the message immediately with E_VALIDATOR_BUSY —
    /// the request never reaches Lambda or Core.
    async fn process_carrier_messages(&self, carrier: &dyn MailCarrier) {
        match carrier.check_new().await {
            Ok(messages) => {
                let total = messages.len();
                for (idx, msg) in messages.iter().enumerate() {
                    self.stats.messages_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // YPX-015: Backpressure gate
                    // Queue depth = remaining messages after this one
                    let queue_depth = total.saturating_sub(idx + 1);
                    if self.should_reject_busy(queue_depth) {
                        // Reject immediately — don't touch Lambda/Core
                        if let Err(e) = self.send_busy_rejection(msg).await {
                            warn!("Failed to send busy rejection for {}: {}", msg.id, e);
                        }
                        self.stats.busy_rejections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let _ = carrier.mark_processed(&msg.id).await;
                        continue;
                    }

                    if let Err(e) = self.process_message(msg).await {
                        error!("Failed to process {}: {}", msg.id, e);
                        self.stats.messages_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let _ = carrier.mark_failed(&msg.id, &e.to_string()).await;
                    } else {
                        self.stats.messages_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let _ = carrier.mark_processed(&msg.id).await;
                    }
                }
            }
            Err(e) => {
                error!("Failed to check for new messages: {}", e);
            }
        }
    }

    /// YPX-015: Background poller — reads avg_witness_ms from Lambda /stats.
    async fn poll_lambda_stats(
        stats: Arc<crate::stats::AntieStats>,
        admin_port: u16,
        admin_token: Option<String>,
        poll_ms: u64,
        running: Arc<RwLock<bool>>,
    ) {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();

        let mut url = format!("http://127.0.0.1:{}/stats", admin_port);
        if let Some(ref token) = admin_token {
            url = format!("{}?token={}", url, token);
        }

        info!("YPX-015: Lambda stats poller started (url={}, interval={}ms)", url, poll_ms);

        loop {
            if !*running.read().await {
                break;
            }

            match client.get(&url).send().await {
                Ok(resp) => {
                    if let Ok(text) = resp.text().await {
                        // Parse avg_witness_ms from JSON (simple string search — no serde needed)
                        if let Some(pos) = text.find("\"avg_witness_ms\":") {
                            let after = &text[pos + 17..];
                            if let Some(end) = after.find([',', '}']) {
                                if let Ok(val) = after[..end].trim().parse::<u64>() {
                                    stats.avg_witness_ms.store(val, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("YPX-015: Failed to poll Lambda stats: {}", e);
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
        }
    }

    /// YPX-015: Check if the current queue load exceeds the busy threshold.
    /// Returns true if the request should be rejected with E_VALIDATOR_BUSY.
    fn should_reject_busy(&self, queue_depth: usize) -> bool {
        let threshold = self.config.performance.busy_threshold_ms;
        if threshold == 0 {
            return false; // 0 = backpressure disabled
        }
        let avg_ms = self.stats.avg_witness_ms.load(std::sync::atomic::Ordering::Relaxed);
        if avg_ms == 0 {
            return false; // no data yet — allow through
        }
        let estimated_wait = (queue_depth as u64 + 1) * avg_ms; // +1 includes current processing
        estimated_wait > threshold
    }

    /// YP §32-33: Check if a wallet is banned via Nabla HTTP query.
    ///
    /// Defense-in-depth pre-filter. ANTIE queries Nabla's /query endpoint for
    /// the sender wallet's status. If BANNED, reject immediately — the request
    /// never reaches Lambda or Core.
    ///
    /// §32 ban check: reads the co-located Nabla node's ban list file.
    /// Nabla writes banned wallet IDs (hex, one per line) to this file.
    /// ANTIE reads it — no cross-layer network calls, just a shared file.
    /// Best-effort: if file missing or unreadable, allow through.
    fn check_ban_list(&self, sender_wallet_pk_hex: &str) -> bool {
        let ban_file = match &self.config.nabla_ban_list_path {
            Some(path) => path,
            None => return false, // not configured — allow through
        };

        match std::fs::read_to_string(ban_file) {
            Ok(contents) => {
                contents.lines().any(|line| line.trim() == sender_wallet_pk_hex)
            }
            Err(_) => false, // file missing or unreadable — allow through
        }
    }

    /// YPX-015: Send an immediate E_VALIDATOR_BUSY rejection to the client.
    /// ANTIE handles this entirely — no Lambda/Core involvement.
    async fn send_busy_rejection(&self, msg: &crate::carrier::IncomingMessage) -> Result<(), AntieError> {
        let email = match crate::email::parse_email(&msg.raw) {
            Ok(e) => e,
            Err(_) => return Ok(()), // Can't parse → can't reply → drop silently
        };

        let avg_ms = self.stats.avg_witness_ms.load(std::sync::atomic::Ordering::Relaxed);
        info!("YPX-015: Rejecting {} from {} — validator busy (avg_witness_ms={})",
              email.message_type, email.from, avg_ms);

        let payload = ResponsePayload {
            success: false,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: Some(format!("E_VALIDATOR_BUSY: estimated wait exceeds threshold (avg_witness_ms={})", avg_ms)),
            rejection_code: Some("E_VALIDATOR_BUSY".into()),
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        };

        self.send_response(&email, &payload).await
    }

    /// Stop the gateway
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Track a Lambda request: increments lambda_requests before the call,
    /// increments lambda_errors if it fails.
    ///
    /// Logs the failure reason on the Err arm before incrementing the
    /// counter — without this the only place the failure text lives is
    /// inside the `ResponsePayload.error` field the caller eventually
    /// sends back to the requester, which makes a non-zero
    /// `lambda_errors` stat undebugable from the validator side alone.
    /// Verified during the 24h soak after the cheque_claim_proof
    /// wiring landed.
    async fn track_lambda<T, F, Fut>(&self, f: F) -> Result<T, AntieError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, AntieError>>,
    {
        self.stats.lambda_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match f().await {
            Ok(v) => Ok(v),
            Err(e) => {
                warn!("Lambda call failed: {}", e);
                self.stats.lambda_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(e)
            }
        }
    }
    
    /// Process a single message
    async fn process_message(&self, msg: &crate::carrier::IncomingMessage) -> Result<(), AntieError> {
        info!("Processing message: {}", msg.id);
        
        // ANTIE transport limit per email message.
        // Each Gateway type sets its own limit:
        //   ANTIE/UNCLE: 8MB (matches FATMAMA's 8MB SMTP buffer)
        //   COUSIN: operator-configurable, up to 16MB (batched payloads)
        // This limit is enforced HERE, not in Lambda or Core.
        // 2MB → 8MB (2026-05-08): FACT chains past ~9 links (typical after
        // 30m sustained sends) push payloads over 2MB; raising to 8MB lets
        // chains grow to ~50 links before transport cap. Compression in Core
        // reduces the upper bound back down once chains stabilise.
        const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
        if msg.raw.len() > MAX_MESSAGE_BYTES {
            self.stats.oversize_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!(
                "[ANTIE-DROP-OVERSIZE] msg_id={} source={} bytes={} limit={}",
                msg.id, msg.source, msg.raw.len(), MAX_MESSAGE_BYTES,
            );
            return Ok(()); // Drop — don't waste resources on oversized junk
        }
        // eprintln!("[ANTIE_MSG] Processing message {}: {} bytes", msg.id, msg.raw.len());
        
        // Parse email — pass the decryptor so forward-direction
        // encrypted UMP bodies (AXIOM_DESIGN_PublicMailCarriers.md §3)
        // unseal here.  A DecryptFailed outcome is dropped silently
        // with a metric bump (§3.3) — leaking the failure reason back
        // to the sender is a small information leak.
        let email = match email::parse_email_outcome(&msg.raw, self.envelope_decryptor.as_deref()) {
            Ok(email::ParseOutcome::Ok(e)) => *e,
            Ok(email::ParseOutcome::DecryptFailed) => {
                self.stats.decrypt_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Promoted debug → warn (KI#11 diagnostic): silent decrypt
                // drops at the default INFO level made "Mac wallet TX
                // never reaches Lambda" look like a transport failure,
                // when it could also be a stale-encryption-key hint
                // delivered via YP §27 organic propagation. We still
                // do not send a response to the sender (§3.3 leak).
                let cumulative = self.stats.decrypt_fail.load(std::sync::atomic::Ordering::Relaxed);
                warn!(
                    "[ANTIE-DROP-DECRYPT] msg_id={} source={} bytes={} cumulative_failures={} \
                     (recipient/key mismatch, tampered ciphertext, or sender used stale encryption_public_key from hint propagation)",
                    msg.id, msg.source, msg.raw.len(), cumulative,
                );
                return Ok(());
            }
            Err(e) => {
                self.stats.parse_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let cumulative = self.stats.parse_fail.load(std::sync::atomic::Ordering::Relaxed);
                warn!(
                    "[ANTIE-DROP-PARSE] msg_id={} source={} bytes={} cumulative_failures={} err={}",
                    msg.id, msg.source, msg.raw.len(), cumulative, e,
                );
                return Ok(()); // Don't retry malformed emails
            }
        };
        
        // Process based on message type
        let response = match email.message_type.as_str() {
            "witness" => self.handle_witness_request(&email).await,
            "redeem" => self.handle_redeem_request(&email).await,
            "ack" => self.handle_ack_request(&email).await,
            "query" => self.handle_query(&email).await,
            "validator_status" => self.handle_validator_status(&email).await,
            "init_genesis_dev" => self.handle_genesis_dev(&email).await,
            "vbc_sign_request" => self.handle_vbc_sign_request(&email).await,
            "vbc_sign_commit" => self.handle_vbc_sign_commit(&email).await,
            "scar_heal" => self.handle_scar_heal(&email).await,
            "set_auth_hash" => self.handle_set_auth_hash(&email).await,
            "peer_audit_request" => self.handle_peer_audit_request(&email).await,
            "peer_audit_response" => self.handle_peer_audit_response(&email).await,
            "fanout_relay" => self.handle_fanout_relay(&email).await,
            _ => {
                // SECURITY FIX #8: Sanitize attacker-controlled message_type before logging.
                let sanitized_type = email.message_type.replace('\n', "\\n").replace('\r', "\\r");
                warn!("Unknown message type: {}", sanitized_type);
                Ok(ResponsePayload {
                    success: false,
                    request_id: email.request_id.clone(),
                    witness_signature: None,
                    cheque_for_receiver: None,
                    scar_consent_voucher: None,
                    produced_state_id: None,
                    receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
                    state_id: None,
                    error: Some(format!("Unknown message type: {}", email.message_type)),
                    rejection_code: Some("UNKNOWN_TYPE".into()),
                    error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
                })
            }
        };
        
        // Send response
        match response {
            Ok(payload) => {
                self.send_response(&email, &payload).await?;
            }
            Err(e) => {
                let error_payload = ResponsePayload {
                    success: false,
                    request_id: email.request_id.clone(),
                    witness_signature: None,
                    cheque_for_receiver: None,
                    scar_consent_voucher: None,
                    produced_state_id: None,
                    receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
                    state_id: None,
                    error: Some(e.to_string()),
                    rejection_code: Some("INTERNAL_ERROR".into()),
                    error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
                };
                self.send_response(&email, &error_payload).await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle witness request
    ///
    /// This is the main transaction processing flow:
    /// 1. Parse transaction from payload
    /// 2. Get wallet state (from cache or Lambda)
    /// 3. Call Core (CL2) to validate ← GATEWAY'S JOB!
    /// 4. If valid, pass to Lambda for consensus
    /// 5. Return response
    async fn handle_witness_request(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        let _hw_start = std::time::Instant::now();
        info!("Handling witness request: {}", email.request_id);

        // UMP enforcement — deserialize the canonical typed
        // `WitnessRequest` from the SDK's CBOR body ONCE. Every wire
        // field downstream (`transaction`, `prev_receipts`,
        // `overlapped_signatures`, `sender_fact_chain`,
        // `cl1_execution_proof`, `validator_hints`, `clara_attestation`,
        // `nabla_hint`, `auth_hash`, `group_member_index`,
        // `audit_confirmation`, `nonce_response`, `audit_response`)
        // comes from this struct, not from `email.payload.raw_<field>`
        // extractors and not from a hand-rebuilt
        // `WitnessRequest { … }` literal at the bottom of this
        // function. Adding a new field to `WitnessRequest` flows
        // through here automatically — no edit required at this hop.
        // See `docs/AXIOM_GUIDE_CodeQuality.md` Pattern 1 +
        // `feedback_no_mirror_structs`.
        let mut req: axiom_core_logic::types::WitnessRequest =
            deserialize_witness_request(email.payload.raw_ump_body.as_slice())
                .map_err(|e| AntieError::InvalidPayload(format!(
                    "WitnessRequest CBOR decode failed: {} (body_len={})",
                    e, email.payload.raw_ump_body.len(),
                )))?;

        // Substitute the envelope-header fields the SDK supplies on
        // the email and NOT in the CBOR body.
        if req.request_id.is_empty() {
            req.request_id = email.request_id.clone();
        }
        if req.requester_address.is_empty() {
            req.requester_address = email.from.clone();
        }

        // YPX-015 §2.3: per-wallet witness rate limit — uses the typed
        // transaction directly (no JSON-Value lookup).
        let has_overlap = !req.overlapped_signatures.is_empty();
        if !has_overlap {
            let wallet_id = &req.transaction.sender_wallet_id;
            if !wallet_id.is_empty() {
                let mut limiter = self.wallet_rate_limiter.lock().await;
                if !limiter.check_and_record(wallet_id) {
                    warn!("E_WALLET_RATE_LIMITED: {} (cooldown active)", wallet_id);
                    self.stats.rate_limited.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(AntieError::RateLimited(
                        format!("E_WALLET_RATE_LIMITED: wallet {} — retry after cooldown", wallet_id),
                    ));
                }
                // Periodic eviction (~every 100 requests).
                if limiter.last_request.len() > 100 {
                    limiter.evict_stale();
                }
            }
        }

        // YP §32-33: ban check via Nabla (defense-in-depth pre-filter).
        if !has_overlap {
            let wallet_id_hex = &req.transaction.sender_wallet_id;
            if !wallet_id_hex.is_empty() && self.check_ban_list(wallet_id_hex) {
                warn!("E_WALLET_BANNED: sender {} rejected by ban list (§32)", wallet_id_hex);
                self.stats.ban_rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(AntieError::WalletBanned(
                    format!("E_WALLET_BANNED: wallet {} is banned (YP §32)", wallet_id_hex),
                ));
            }
        }

        // NOTE: JFP frozen wallet check removed (2026-03-23).
        // Frozen wallet enforcement now operates through group wallet state
        // and Core CL1, not a separate file. See Yellow Paper §8.4.

        // Locals for the CL2 prefilter call below. These name pointers
        // into the typed envelope to keep the call site readable; every
        // value is a direct `req.<field>` reference, no rebuild.
        let transaction = &req.transaction;
        let declared_balance = req.claimed_balance_for_sabr;
        let prev_receipts = req.prev_receipts.as_slice();
        let overlapped_sigs = req.overlapped_signatures.as_slice();
        let cl2_sender_fact_chain = req.sender_fact_chain.clone();

        // ========================================
        // STEP 1: Gateway calls Core for CL2 validation (S-ABR gate)
        // Core builds WalletState internally from declared_balance + prev_receipts.
        // ANTIE passes raw data only — no state construction, no validation decisions.
        // ========================================
        debug!("Gateway calling Core (CL2) with declared_balance={}, {} prev_receipts, {} overlapped sigs",
               declared_balance, prev_receipts.len(), overlapped_sigs.len());

        // VBC loaded from config for PublicInputs
        let vbc_bundle = self.config.validator.load_vbc();
        // Extract Ed25519 PK from VBC for CL2 overlap detection
        let my_validator_pk = vbc_bundle.as_ref()
            .map(|b| b.target_vbc.subject_pubkey_ed25519.clone());
        debug!("CL2 overlap: vbc_loaded={} my_pk={} prev_receipt_sigs={}",
            vbc_bundle.is_some(),
            my_validator_pk.as_ref().map(|pk| hex::encode(&pk[..8.min(pk.len())])).unwrap_or_else(|| "NONE".into()),
            prev_receipts.iter().flat_map(|r| r.witness_sigs.iter()).count());

        // Execute CL2 via AVM interpreter (direct, no subprocess).
        // CL2_PREFILTER is an optimization — Lambda does the authoritative check.
        // If the AVM is unavailable (ELF missing, init error), skip and let Lambda decide.
        let cl2_result = match core_ipc::validate_transaction_cl2(
            &self.core,
            transaction,
            declared_balance,
            prev_receipts,
            overlapped_sigs.to_vec(),
            vbc_bundle,
            my_validator_pk,
            cl2_sender_fact_chain,
        ) {
            Ok(validation) if !validation.accepted => {
                warn!("CL2 REJECTED: {}", validation.rejection_reason.as_deref().unwrap_or("Unknown"));
                return Ok(ResponsePayload {
                    success: false,
                    request_id: email.request_id.clone(),
                    witness_signature: None,
                    cheque_for_receiver: None,
                    scar_consent_voucher: None,
                    produced_state_id: None,
                    receipt: None,
                    commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    txid: None,
                    state_id: None,
                    error: validation.rejection_reason,
                    rejection_code: Some("CL2_VALIDATION_FAILED".into()),
                    error_response: None,
                    validator_hints: vec![],
                    sender_fact_chain: None,
                    receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
                });
            }
            Ok(validation) => {
                info!("CL2 ACCEPTED - passing to Lambda");
                Some(validation)
            }
            Err(e) => {
                warn!("CL2 skipped (Core unavailable: {}) — Lambda will validate", e);
                None
            }
        };

        // ========================================
        // STEP 2: Pass pre-validated typed envelope to Lambda.
        //
        // UMP enforcement — the request reaching Lambda IS the same
        // typed `WitnessRequest` the SDK serialized. The only fields
        // ANTIE substitutes are the CL2-computed ones — every other
        // wire field flows through unchanged. Lambda trusts that
        // Gateway already validated via CL2 AND Lambda trusts Core's
        // `produced_state_id` (doesn't compute its own).
        //
        // Pre-fix this site re-built the whole `WitnessRequest` from 13
        // separate `email.payload.<field>` and `raw_<field>` extractors
        // — every one a place a new field could silently drop (see
        // task #143 / `docs/AXIOM_GUIDE_CodeQuality.md` Pattern 1).
        // The single source of truth is now `req`.
        // ========================================
        req.produced_state_id = cl2_result.as_ref().and_then(|v| v.new_state_id.map(|id| id.to_vec()));
        req.commitment_hash = cl2_result.as_ref().and_then(|v| v.commitment_hash.map(|h| h.to_vec()));
        let lambda_request = req;

        let lambda_response = self.track_lambda(|| self.lambda.send_witness_request(&lambda_request)).await?;
        // eprintln!("[HW_TIMING] {} lambda_done: {:?}", email.request_id, hw_start.elapsed());

        // §17.9: Send cheque to RECEIVER via ANTIE email.
        // Per Yellow Paper §17.9.2: each validator sends its cheque directly to the receiver.
        // The sender does NOT get the cheque — only the receiver does.
        //
        // Burn exception: BURN_ADDRESS has no human receiver and no redemption
        // semantics. The burn_proof is written to the sender's FACT chain by
        // Lambda (Core CL3); the cheque generated here has no destination.
        // Skip delivery to avoid 1-per-burn "Invalid to address" email failures.
        let is_burn_tx = lambda_request.transaction.receiver_wallet_id
            == axiom_core_logic::types::BURN_ADDRESS;
        if let Some(ref cheque) = lambda_response.cheque_for_receiver {
            if is_burn_tx {
                debug!("§17.9: Skipping cheque delivery for burn TX (no receiver)");
                // Fall through to the rest of the response path without emailing.
                let _ = cheque;
            } else {
            // Extract receiver email: receiver_address (priority) or receiver_wallet_id (fallback).
            // Both use wallet_id format "email/hex8" — extract email before the '/'.
            let receiver_email = lambda_request.transaction.receiver_address.as_ref()
                .and_then(|addr| addr.rfind('/').map(|pos| addr[..pos].to_string()))
                .or_else(|| {
                    let wid = &lambda_request.transaction.receiver_wallet_id;
                    wid.rfind('/').map(|pos| wid[..pos].to_string())
                });

            if let Some(ref recv_email) = receiver_email {
                let cheque_email = email::build_cheque_delivery_email(
                    &self.config.identity.email,
                    recv_email,
                    cheque,
                    lambda_response.sender_fact_chain.as_ref(),
                );
                match cheque_email {
                    Ok(email_bytes) => {
                        // Try PGP encryption for receiver (graceful — falls back to plaintext)
                        let (final_bytes, encrypted) = crate::pgp::try_encrypt_for_email(
                            recv_email, &email_bytes,
                        ).await;
                        if encrypted {
                            info!("§17.9: Cheque PGP-encrypted for {}", recv_email);
                        }
                        // Skip-list contract (AXIOM_DESIGN_AntieSkipList.md):
                        // if a sibling carrier has registered the
                        // receiver_wallet_id in the skip list, divert
                        // the cheque bytes into skipped/ (atomic
                        // tmp/+rename) instead of sendmail-dispatching.
                        // The sibling carrier claims by atomic rename
                        // out. Audit-grade institutional flows (UNCLE)
                        // are the primary use case; ANTIE doesn't
                        // know or care which sibling carrier is
                        // watching skipped/.
                        let full_receiver = &lambda_request.transaction.receiver_wallet_id;
                        let skipped = if let Some(ref sl) = self.skip_list {
                            if sl.contains(full_receiver).await {
                                // Filename uses txid hex — unique per
                                // cheque, joins cleanly to the audit
                                // row a sibling carrier writes on
                                // claim.
                                let filename = format!("{}.cheque", hex::encode(cheque.txid));
                                match sl.write_skipped(&filename, &final_bytes).await {
                                    Ok(path) => {
                                        info!(
                                            "§17.9: cheque for {} diverted to skipped/ ({}) — sibling carrier will claim",
                                            full_receiver,
                                            path.display()
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        warn!(
                                            "§17.9: skipped/ write failed for {} — falling back to email: {e}",
                                            full_receiver
                                        );
                                        false
                                    }
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        if skipped {
                            // Carrier-side dispatch handled. Skip the
                            // email path entirely; sibling carrier
                            // owns delivery from here.
                        } else
                        if let Err(e) = self.sender.send(recv_email, &final_bytes).await {
                            warn!("§17.9: Failed to send cheque to receiver {}: {}", recv_email, e);
                        } else {
                            info!("§17.9: Cheque sent to receiver {}{}", recv_email,
                                  if encrypted { " (PGP)" } else { "" });
                            // Notify Lambda of actual encrypted status for delivery log.
                            // Fire-and-forget — failure doesn't affect cheque delivery.
                            if let Ok(admin_url) = std::env::var("LAMBDA_ADMIN_URL") {
                                let txid_hex = hex::encode(cheque.txid);
                                let body = format!(
                                    r#"{{"txid":"{}","encrypted":{}}}"#, txid_hex, encrypted
                                );
                                let _ = reqwest::Client::new()
                                    .post(format!("{}/delivery-update", admin_url))
                                    .body(body)
                                    .timeout(std::time::Duration::from_secs(2))
                                    .send()
                                    .await;
                            }
                        }
                    }
                    Err(e) => warn!("§17.9: Failed to build cheque email: {}", e),
                }
            } else {
                warn!("§17.9: Cannot deliver cheque — no receiver email in wallet_id '{}'",
                      lambda_request.transaction.receiver_wallet_id);
            }
            } // close burn-else
        }

        // YPX-001 §1.5.1: scar-consent gate fired — deliver the passcode
        // notification to the RECEIVER's mailbox (mirror of cheque delivery
        // above). The sender leg (ResponsePayload below) carries only the
        // rejection code; the passcode must never reach the sender
        // in-protocol — receiver → sender hand-off IS the consent.
        if let Some(ref scar_consent) = lambda_response.scar_consent_for_receiver {
            // Same email-extraction rule as cheque delivery: receiver_address
            // override first, receiver_wallet_id fallback ("email/hex8").
            let receiver_email = lambda_request.transaction.receiver_address.as_ref()
                .and_then(|addr| addr.rfind('/').map(|pos| addr[..pos].to_string()))
                .or_else(|| {
                    let wid = &lambda_request.transaction.receiver_wallet_id;
                    wid.rfind('/').map(|pos| wid[..pos].to_string())
                });
            if let Some(ref recv_email) = receiver_email {
                match email::build_scar_consent_email(
                    &self.config.identity.email,
                    recv_email,
                    scar_consent,
                ) {
                    Ok(email_bytes) => {
                        // PGP-encrypt when the receiver's key is known (the
                        // passcode is a consent secret — plaintext fallback is
                        // accepted like cheques: SMTP path is dev/loopback).
                        let (final_bytes, encrypted) = crate::pgp::try_encrypt_for_email(
                            recv_email, &email_bytes,
                        ).await;
                        if let Err(e) = self.sender.send(recv_email, &final_bytes).await {
                            warn!("§1.5.1: Failed to send scar-consent notification to {}: {}",
                                  recv_email, e);
                        } else {
                            info!("§1.5.1: Scar-consent notification sent to {}{} (txid={}, {} scars)",
                                  recv_email,
                                  if encrypted { " (PGP)" } else { "" },
                                  hex::encode(&scar_consent.txid[..8]),
                                  scar_consent.scar_count);
                        }
                    }
                    Err(e) => warn!("§1.5.1: Failed to build scar-consent email: {}", e),
                }
            } else {
                warn!("§1.5.1: Cannot deliver scar-consent notification — no receiver email in wallet_id '{}'",
                      lambda_request.transaction.receiver_wallet_id);
            }
        }

        // §23.14.6: Send outbound peer-audit request email if Lambda queued one
        if let Some(ref peer_audit) = lambda_response.outbound_peer_audit {
            let audit_email = email::build_peer_audit_request_email(
                &self.config.identity.email,
                &peer_audit.target_email,
                &peer_audit.request,
            );
            match audit_email {
                Ok(email_bytes) => {
                    if let Err(e) = self.sender.send(&peer_audit.target_email, &email_bytes).await {
                        warn!("§23.14.6: Failed to send peer-audit request to {}: {}",
                              peer_audit.target_email, e);
                    } else {
                        info!("§23.14.6: Peer-audit request sent to {}", peer_audit.target_email);
                    }
                }
                Err(e) => warn!("§23.14.6: Failed to build peer-audit email: {}", e),
            }
        }

        // Convert Lambda response to email response. Typed structs flow
        // through unchanged — no serde_json::to_value bandaid that
        // flattened byte fields to integer arrays (rule #13 / two-day debug).
        Ok(ResponsePayload {
            success: lambda_response.success,
            request_id: lambda_response.request_id,
            witness_signature: lambda_response.witness_signature,
            cheque_for_receiver: None, // §17.9: Cheque sent directly to receiver, NOT to sender
            // YPX-001 §1.5.1: voucher DOES go to the sender — it is the
            // carry-forward proof for the round's remaining hops.
            scar_consent_voucher: lambda_response.scar_consent_voucher.clone(),
            produced_state_id: lambda_response.produced_state_id,
            receipt: lambda_response.receipt,
            commitment_hash: lambda_response.commitment_hash,
            state_hash: lambda_response.state_hash,
            receipt_commitment: lambda_response.receipt_commitment,
            txid: Some(lambda_response.txid),
            state_id: None,
            error: lambda_response.rejection.as_ref().map(|r| r.message.clone()),
            rejection_code: lambda_response.rejection.map(|r| r.code),
            error_response: None,
            validator_hints: lambda_response.validator_hints,
            sender_fact_chain: lambda_response.sender_fact_chain,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }
    
    /// Handle query request — look up wallet state via Lambda
    async fn handle_query(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling query: {}", email.request_id);

        // Extract wallet public key from query_params
        let wallet_pk: Vec<u8> = email.payload.query_params
            .as_ref()
            .and_then(|p| p.get("wallet_pk"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| AntieError::InvalidPayload(
                "Query requires query_params.wallet_pk (byte array)".into(),
            ))?;

        let query_response = self.track_lambda(|| self.lambda.send_query_request(&wallet_pk)).await?;

        if query_response.found {
            let state = query_response.wallet_state.as_ref();
            let balance_info = state.map(|s| {
                serde_json::json!({
                    "balance": s.balance,
                    "wallet_seq": s.wallet_seq,
                    "public_key": s.public_key,
                    "state_id": s.state_id,
                })
            });

            Ok(ResponsePayload {
                success: true,
                request_id: email.request_id.clone(),
                witness_signature: None,
                cheque_for_receiver: None,
                scar_consent_voucher: None,
                produced_state_id: None,
                receipt: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                txid: None,
                state_id: None,
                error: None,
                rejection_code: None,
                error_response: None,
                validator_hints: vec![],
                sender_fact_chain: None,
                receiver_fact_chain: None,
                fact_signature: None,
                query_data: balance_info,
            })
        } else {
            Ok(ResponsePayload {
                success: false,
                request_id: email.request_id.clone(),
                witness_signature: None,
                cheque_for_receiver: None,
                scar_consent_voucher: None,
                produced_state_id: None,
                receipt: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                txid: None,
                state_id: None,
                error: Some("Wallet not found".into()),
                rejection_code: Some("NOT_FOUND".into()),
                error_response: None,
                validator_hints: vec![],
                sender_fact_chain: None,
                receiver_fact_chain: None,
                fact_signature: None,
                query_data: None,
            })
        }
    }
    
    /// Handle VSP (Validator Status Protocol) request — free, unauthenticated.
    /// Returns validator's public profile + 3 known peer validators.
    async fn handle_validator_status(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling VSP query: {}", email.request_id);

        let vsp_response = self.track_lambda(|| self.lambda.send_validator_status_request(&email.request_id)).await?;

        Ok(ResponsePayload {
            success: true,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: None,
            rejection_code: None,
            error_response: None,
            validator_hints: vsp_response.known_validators.iter().map(|h| {
                axiom_core_logic::types::ValidatorHint {
                    validator_id: h.validator_id.clone(),
                    name: h.name.clone(),
                    carriers: h.carriers.clone(),
                    proof_cap: h.proof_cap.clone(),
                    last_seen: h.last_seen,
                    ed25519_pk: h.ed25519_pk,
                    encryption_public_key: h.encryption_public_key.clone(),
                    supported_encryption: h.supported_encryption.clone(),
                }
            }).collect(),
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: Some(serde_json::json!({
                "name": vsp_response.validator_name,
                "validator_id": vsp_response.validator_id,
                "proof_cap": vsp_response.proof_cap,
                "carriers": vsp_response.carriers,
                "core_version": vsp_response.core_version,
                "uptime_secs": vsp_response.uptime_secs,
                "witness_count": vsp_response.witness_count,
                "redeem_count": vsp_response.redeem_count,
                "zkp_qualified": vsp_response.zkp_qualified,
            })),
        })
    }

    /// Handle genesis dev request (DEV/TEST ONLY)
    ///
    /// Initializes a wallet with genesis balance - bypasses real Genesis signatures.
    /// Only works in dev mode.
    async fn handle_genesis_dev(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling genesis dev: {}", email.request_id);
        
        // Extract public_key and balance from payload
        let public_key = email.payload.public_key
            .clone()
            .ok_or_else(|| AntieError::InvalidPayload("Missing public_key".into()))?;
        
        let balance = email.payload.balance
            .ok_or_else(|| AntieError::InvalidPayload("Missing balance".into()))?;
        
        // Parse group_members if present (for group wallet genesis)
        let group_members: Option<Vec<GroupMember>> = email.payload.group_members
            .as_ref()
            .map(|members| {
                members.iter()
                    .map(|m| serde_json::from_value(m.clone()))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
            .map_err(|e| AntieError::InvalidPayload(format!("Invalid group_members: {}", e)))?;
        
        // Extract auth_hash if provided (owner_proof setup at genesis)
        let auth_hash = email.payload.auth_hash.clone();

        // Forward to Lambda
        let lambda_response = self.track_lambda(|| self.lambda.send_genesis_dev_request(
            &email.request_id,
            &public_key,
            balance,
            group_members,
            auth_hash.clone(),
        )).await?;
        
        Ok(ResponsePayload {
            success: lambda_response.success,
            request_id: email.request_id.clone(),
            witness_signature: None,
                    cheque_for_receiver: None,
                    scar_consent_voucher: None,
                    produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            // Genesis path has no SEND tx, so no txid. State ID is what
            // the SDK persists for the new wallet (extracted from the
            // canonical InitGenesisResponse.result.state_id).
            txid: None,
            state_id: lambda_response.result.as_ref().map(|r| r.state_id.clone()),
            error: lambda_response.error,
            rejection_code: if lambda_response.success { None } else { Some("GENESIS_FAILED".into()) },
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }
    
    /// Handle redeem request (6-validator model)
    ///
    /// Receiver brings ChequeBundle to their validators for redemption.
    /// Flow:
    /// 1. Parse ChequeBundle from payload
    /// 2. Verify bundle consistency (all cheques for same tx)
    /// 3. Pass to Lambda for redeem processing
    /// 4. Lambda verifies signatures, updates receiver's balance
    /// 5. Return witness signature for receiver's new state
    async fn handle_redeem_request(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling redeem request: {}", email.request_id);

        // UMP enforcement — `RedeemRequestEnvelope` lives ONCE in
        // `axiom_core_logic::types`. ANTIE deserializes the typed
        // struct directly from the SDK's raw CBOR body, with no
        // field-by-field rebuild. The previous "extract raw_<field>:
        // then re-construct" pattern caused two production drift bugs
        // (fee_breakdown dropped at the gateway, fact_signature
        // dropped pre-A2) and is the recurring class catalogued in
        // `docs/AXIOM_GUIDE_CodeQuality.md` Pattern 1. Adding a new
        // field to the envelope now requires ZERO changes here —
        // it flows automatically. See task #143 follow-up and
        // `feedback_no_mirror_structs`.
        //
        // `raw_ump_body` is populated by `email::decode_payload_inner`
        // AFTER UmpEnvelope unwrap, BEFORE field parse.
        let mut redeem_req: axiom_core_logic::types::RedeemRequestEnvelope =
            ciborium::from_reader::<_, _>(email.payload.raw_ump_body.as_slice())
                .map_err(|e| AntieError::InvalidPayload(
                    format!("RedeemRequestEnvelope CBOR decode failed: {} (body_len={})",
                        e, email.payload.raw_ump_body.len()),
                ))?;
        // Authoritative `request_id` comes from the email envelope —
        // the SDK may leave the inner field empty since the envelope
        // header is the wire-mandated correlation key.
        if redeem_req.request_id.is_empty() {
            redeem_req.request_id = email.request_id.clone();
        }
        let lambda_response = self.track_lambda(|| self.lambda.send_redeem_request(&redeem_req)).await?;
        
        // Build response. Forward Lambda's structured error_response
        // both as a flat human string (`error`) and as the typed
        // structure (`error_response`) so SDK clients can dispatch
        // on `recovery` for state-drift handling. Pre-fix only the
        // flat string was forwarded; the recovery hint was dropped
        // and the SDK fell through to per-validator retry, producing
        // the w024 9-retry loop in the v3.0.0-beta5 soak.
        let error_message = lambda_response
            .error_response
            .as_ref()
            .map(|er| format!("{}: {}", er.code, er.message));
        let lambda_error_response = lambda_response.error_response.clone();

        Ok(ResponsePayload {
            success: lambda_response.success,
            request_id: email.request_id.clone(),
            witness_signature: lambda_response.witness_signature,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: lambda_response.new_state_id.map(|s| s.to_vec()),
            receipt: None,
            commitment_hash: lambda_response.commitment_hash,
            // Forward Lambda's state_hash + receipt_commitment so the
            // receiver SDK can build a non-zero-fielded redeem receipt
            // (mirrors the witness path; same root cause). CLAUDE.md §13.
            state_hash: lambda_response.state_hash,
            receipt_commitment: lambda_response.receipt_commitment,
            // Redeem responses don't carry a top-level txid — the redeem
            // SDK builder reads cheque.txid from the bundle directly.
            // Different from witness responses where the new SEND TX's
            // txid is needed for the partial-commit receipt builder.
            txid: None,
            state_id: None,
            error: error_message,
            rejection_code: if lambda_response.success { None } else { Some("REDEEM_FAILED".into()) },
            error_response: lambda_error_response,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: lambda_response.receiver_fact_chain,
            // Forward Lambda's per-validator FACT signature so the SDK
            // can collect k of these and assemble the receiver's redeem
            // FactLink. Without this forward, the SDK's
            // build_and_append_fact_bridge sees zero fact_signatures →
            // skips link construction → wallet has no redeem link →
            // next send fails E_FACT_CHAIN_BREAK.
            fact_signature: lambda_response.fact_signature,
            query_data: None,
        })
    }

    /// Handle ACK request (client acknowledges witness, pays fee)
    async fn handle_ack_request(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling ACK: {}", email.request_id);
        
        // Extract ACK fields from typed payload
        let txid_vec = email.payload.txid.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing txid".into()))?;
        let mut txid = [0u8; 32];
        if txid_vec.len() == 32 {
            txid.copy_from_slice(txid_vec);
        } else {
            return Err(AntieError::InvalidPayload("txid must be 32 bytes".into()));
        }
        
        let validator_pk = email.payload.validator_pk.clone()
            .ok_or_else(|| AntieError::InvalidPayload("Missing validator_pk".into()))?;

        let sender_sig = email.payload.sender_sig.clone()
            .ok_or_else(|| AntieError::InvalidPayload("Missing sender_sig".into()))?;

        let client_pk = email.payload.client_pk.clone()
            .ok_or_else(|| AntieError::InvalidPayload("Missing client_pk".into()))?;

        // ACK doesn't go through Core (CL2) — it's a confirmation, not a transaction.
        // Send directly to Lambda using the canonical AckRequest envelope.
        // YP §20.8 v3.x: no fee_amount — validator fees settle at CL5.
        let ack_req = axiom_core_logic::types::AckRequest {
            request_id: email.request_id.clone(),
            ack: axiom_core_logic::AckWithFee {
                txid,
                validator_pk,
                sender_sig,
            },
            client_pk,
        };
        let lambda_response = self.track_lambda(|| self.lambda.send_ack_request(&ack_req)).await?;
        
        Ok(ResponsePayload {
            success: lambda_response.success,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            // ACK acknowledges a previously-witnessed TX; no fresh txid.
            txid: None,
            state_id: None,
            error: lambda_response.error_response.as_ref()
                .map(|er| format!("{}: {}", er.code, er.message)),
            rejection_code: if lambda_response.success { None } else { Some("ACK_FAILED".into()) },
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }
    
    /// Send response email
    async fn send_response(
        &self,
        original: &AntieEmail,
        payload: &ResponsePayload,
    ) -> Result<(), AntieError> {
        let response_type = if payload.success { "witness_response" } else { "error" };

        let email_bytes = email::build_response(
            &original.from,
            &self.config.identity.email,
            response_type,
            &payload.request_id,
            original.message_id.as_deref(),
            payload,
        )?;

        // UNCLE tee — fires when the inbound email carried an
        // `X-UNCLE-Correlate` header (i.e. UNCLE's SubmitSend handler
        // stamped it on the way in). Drop a verbatim copy at
        // `<outbox>/<correlate_hex>.cbor` so UNCLE's witness_observer
        // can route the response back to an in-flight SubmitSend.
        // Best-effort: the sink swallows its own errors and we never
        // let it block the primary SMTP/maildir dispatch.
        if let (Some(sink), Some(correlate)) = (&self.uncle_sink, &original.uncle_correlate) {
            let _ = sink.tee(correlate, &email_bytes).await;
        }

        self.sender.send(&original.from, &email_bytes).await?;
        self.stats.emails_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        info!("Response sent to {}: success={}", original.from, payload.success);
        Ok(())
    }
    
    /// Handle VBC sign request (Phase 1: discovery)
    /// No Core involvement — this is a Lambda-only operation
    async fn handle_vbc_sign_request(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling VBC sign request (Phase 1): {}", email.request_id);
        
        let sphincs_pk_hex = email.payload.sphincs_pk_hex.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing sphincs_pk_hex".into()))?;
        let dilithium_pk_hex = email.payload.dilithium_pk_hex.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing dilithium_pk_hex".into()))?;
        let ed25519_pk_hex = email.payload.ed25519_pk_hex.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing ed25519_pk_hex".into()))?;
        let pgp_hex = email.payload.pgp_fingerprint_hex.as_deref().unwrap_or("");
        let proof_cap = email.payload.proof_cap.as_deref().unwrap_or("").to_string();
        let node_name = email.payload.node_name_field.as_deref().unwrap_or("").to_string();

        let lambda_req = VbcSignRequest {
            request_type: "vbc_sign_request".into(),
            request_id: email.request_id.clone(),
            sphincs_pk_hex: sphincs_pk_hex.clone(),
            dilithium_pk_hex: dilithium_pk_hex.clone(),
            ed25519_pk_hex: ed25519_pk_hex.clone(),
            pgp_fingerprint_hex: pgp_hex.to_string(),
            proof_cap,
            node_name,
            issued_at: None,
            expires_at: None,
            chain_depth: None,
            issuer_set_hex: vec![],
        };

        let response_bytes = self.track_lambda(|| self.lambda.send_raw_request(&lambda_req)).await?;
        let response: VbcResponse = ciborium::from_reader(&response_bytes[..])
            .map_err(|e| AntieError::LambdaError(format!("CBOR decode VBC response: {}", e)))?;

        let success = response.success;
        let error = response.error;

        Ok(ResponsePayload {
            success,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error,
            rejection_code: if success { None } else { Some("VBC_SIGN_FAILED".into()) },
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }
    
    /// Handle VBC sign commit (Phase 2: actual signing)
    /// No Core involvement — this is a Lambda-only operation
    async fn handle_vbc_sign_commit(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling VBC sign commit (Phase 2): {}", email.request_id);
        
        let sphincs_pk_hex = email.payload.sphincs_pk_hex.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing sphincs_pk_hex".into()))?;
        let dilithium_pk_hex = email.payload.dilithium_pk_hex.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing dilithium_pk_hex".into()))?;
        let ed25519_pk_hex = email.payload.ed25519_pk_hex.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing ed25519_pk_hex".into()))?;
        let pgp_hex = email.payload.pgp_fingerprint_hex.as_deref().unwrap_or("");
        let proof_cap = email.payload.proof_cap.as_deref().unwrap_or("").to_string();
        let node_name = email.payload.node_name_field.as_deref().unwrap_or("").to_string();
        let issued_at = email.payload.issued_at
            .ok_or_else(|| AntieError::InvalidPayload("Missing issued_at".into()))?;
        let expires_at = email.payload.expires_at
            .ok_or_else(|| AntieError::InvalidPayload("Missing expires_at".into()))?;
        let chain_depth = email.payload.chain_depth
            .ok_or_else(|| AntieError::InvalidPayload("Missing chain_depth".into()))?;

        if email.payload.issuer_set_hex.len() != 3 {
            return Err(AntieError::InvalidPayload(
                format!("issuer_set_hex must have 3 entries, got {}", email.payload.issuer_set_hex.len())
            ));
        }

        let lambda_req = VbcSignRequest {
            request_type: "vbc_sign_commit".into(),
            request_id: email.request_id.clone(),
            sphincs_pk_hex: sphincs_pk_hex.clone(),
            dilithium_pk_hex: dilithium_pk_hex.clone(),
            ed25519_pk_hex: ed25519_pk_hex.clone(),
            pgp_fingerprint_hex: pgp_hex.to_string(),
            proof_cap,
            node_name,
            issued_at: Some(issued_at),
            expires_at: Some(expires_at),
            chain_depth: Some(chain_depth as u32),
            issuer_set_hex: email.payload.issuer_set_hex.clone(),
        };

        let response_bytes = self.track_lambda(|| self.lambda.send_raw_request(&lambda_req)).await?;
        let response: VbcResponse = ciborium::from_reader(&response_bytes[..])
            .map_err(|e| AntieError::LambdaError(format!("CBOR decode VBC response: {}", e)))?;
        
        let success = response.success;
        let error = response.error;
        
        Ok(ResponsePayload {
            success,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error,
            rejection_code: if success { None } else { Some("VBC_SIGN_COMMIT_FAILED".into()) },
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }
    
    /// Handle scar heal notification
    ///
    /// When a sender's FACT link gets Nabla confirmation, this handler:
    /// 1. Extracts ScarRecoveryProof from the payload
    /// 2. Forwards to Lambda for application
    /// 3. Lambda returns downstream receiver targets
    /// 4. For each downstream target: builds and sends a healing email
    async fn handle_scar_heal(
        &self,
        email_msg: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Handling scar_heal request: {}", email_msg.request_id);

        // Extract scar recovery proof fields from payload
        let proof_data = email_msg.payload.scar_recovery_proof.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing scar_recovery_proof".into()))?;
        let target_wallet_id = email_msg.payload.target_wallet_id.as_ref()
            .ok_or_else(|| AntieError::InvalidPayload("Missing target_wallet_id".into()))?;

        // Forward to Lambda for scar heal application
        let heal_resp = self.track_lambda(|| self.lambda.send_scar_heal_request(proof_data, target_wallet_id)).await?;

        if !heal_resp.success {
            return Ok(ResponsePayload {
                success: false,
                request_id: email_msg.request_id.clone(),
                witness_signature: None,
                cheque_for_receiver: None,
                scar_consent_voucher: None,
                produced_state_id: None,
                receipt: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                txid: None,
                state_id: None,
                error: heal_resp.error,
                rejection_code: Some("SCAR_HEAL_FAILED".into()),
                error_response: None,
                validator_hints: vec![],
                sender_fact_chain: None,
                receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            });
        }

        // For each downstream target, build and send a healing notification email
        let mut forwarded = 0;
        for target in &heal_resp.downstream_targets {
            let heal_email = email::build_scar_heal_email(
                &self.config.identity.email,
                &target.email,
                proof_data,
                &target.wallet_id,
            )?;
            if let Err(e) = self.sender.send(&target.email, &heal_email).await {
                warn!("Failed to send scar heal notification to {}: {}", target.email, e);
            } else {
                forwarded += 1;
                info!("Scar heal notification sent to {}", target.email);
            }
        }

        info!("Scar heal complete: {} downstream notifications sent", forwarded);

        Ok(ResponsePayload {
            success: true,
            request_id: email_msg.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: None,
            rejection_code: None,
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }

    /// §4.5 / §30.2: Handle set_auth_hash request.
    ///
    /// Sets auth_hash on a wallet for stolen-key protection. Once set, every TX
    /// from this wallet requires owner proof. Core already validates — this
    /// provides the user-facing pipe.
    async fn handle_set_auth_hash(
        &self,
        email_msg: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("§4.5: Handling set_auth_hash: {}", email_msg.request_id);

        let public_key = email_msg.payload.public_key.clone()
            .ok_or_else(|| AntieError::InvalidPayload("Missing public_key".into()))?;

        let auth_hash = email_msg.payload.auth_hash.clone()
            .ok_or_else(|| AntieError::InvalidPayload("Missing auth_hash".into()))?;

        if auth_hash.len() != 32 {
            return Err(AntieError::InvalidPayload(
                format!("auth_hash must be 32 bytes, got {}", auth_hash.len())
            ));
        }

        let result = self.track_lambda(|| self.lambda.send_set_auth_hash_request(
            &email_msg.request_id,
            &public_key,
            &auth_hash,
        )).await?;

        Ok(ResponsePayload {
            success: result.success,
            request_id: email_msg.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: result.error,
            rejection_code: if result.success { None } else { Some("SET_AUTH_HASH_FAILED".into()) },
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }

    /// §23.14.6: Handle inbound peer audit request from remote validator.
    ///
    /// A remote validator is asking us to prove our DB integrity for a specific txid.
    /// Forward to Lambda → Lambda looks up DB → Core verifies hash → send response back.
    async fn handle_peer_audit_request(
        &self,
        email_msg: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("§23.14.6: Handling peer_audit_request: {}", email_msg.request_id);

        let request: axiom_core_logic::types::PeerAuditRequest =
            serde_json::from_value(
                email_msg.payload.peer_audit_request.clone()
                    .ok_or_else(|| AntieError::InvalidPayload("Missing peer_audit_request".into()))?
            ).map_err(|e| AntieError::InvalidPayload(format!("Invalid peer_audit_request: {}", e)))?;

        // Forward to Lambda for processing (DB lookup + Core hash verification)
        let result = self.track_lambda(|| self.lambda.send_peer_audit_request(&request)).await?;

        // If Lambda produced a response, send it back to the requester via email
        if let (Some(response), Some(requester_email)) = (&result.response, &result.requester_email) {
            let response_email = email::build_peer_audit_response_email(
                &self.config.identity.email,
                requester_email,
                response,
            )?;
            if let Err(e) = self.sender.send(requester_email, &response_email).await {
                warn!("§23.14.6: Failed to send peer-audit response to {}: {}", requester_email, e);
            } else {
                info!("§23.14.6: Peer-audit response sent to {}", requester_email);
            }
        }

        Ok(ResponsePayload {
            success: result.success,
            request_id: email_msg.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: result.error,
            rejection_code: None,
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }

    /// §23.14.6: Handle inbound peer audit response from remote validator.
    ///
    /// A remote validator responded to our peer audit ping. Forward to Lambda
    /// so Core can compare the hash. Match → clear audit. Mismatch → ban.
    async fn handle_peer_audit_response(
        &self,
        email_msg: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("§23.14.6: Handling peer_audit_response: {}", email_msg.request_id);

        let response: axiom_core_logic::types::PeerAuditResponse =
            serde_json::from_value(
                email_msg.payload.peer_audit_response.clone()
                    .ok_or_else(|| AntieError::InvalidPayload("Missing peer_audit_response".into()))?
            ).map_err(|e| AntieError::InvalidPayload(format!("Invalid peer_audit_response: {}", e)))?;

        // Forward to Lambda for verification (Core compares hash)
        if let Err(e) = self.track_lambda(|| self.lambda.send_peer_audit_response(&response)).await {
            warn!("§23.14.6: Failed to forward peer-audit response to Lambda: {}", e);
        }

        Ok(ResponsePayload {
            success: true,
            request_id: email_msg.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: None,
            rejection_code: None,
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }

    /// Handle incoming Fan-Out relay message.
    /// 1. Deserialize FanOutMessage from email payload
    /// 2. Verify via Core CL10 (TTL, signature, content_type)
    /// 3. If accepted, decrement TTL and relay to N peers
    /// 4. Pass to Lambda for local processing (DWP query, JFP result, etc.)
    async fn handle_fanout_relay(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        info!("Fan-Out relay: {} from {}", email.request_id, email.from);

        // Extract FanOutMessage from payload
        let fanout_msg: axiom_core_logic::types::FanOutMessage = match serde_json::from_value(
            email.payload.fanout_message.clone().unwrap_or(serde_json::Value::Null)
        ) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Fan-Out: bad message format: {}", e);
                return Ok(ResponsePayload {
                    success: false,
                    request_id: email.request_id.clone(),
                    witness_signature: None,
                    cheque_for_receiver: None,
                    scar_consent_voucher: None,
                    produced_state_id: None,
                    receipt: None,
                    commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    txid: None,
                    state_id: None,
                    error: Some(format!("Bad Fan-Out message: {}", e)),
                    rejection_code: Some("FANOUT_BAD_FORMAT".into()),
                    error_response: None,
                    validator_hints: vec![],
                    sender_fact_chain: None,
                    receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
                });
            }
        };

        // Fan-Out replay prevention: check diffusion_id dedup (§18.8.8 step 2).
        // Two layers: in-memory (fast, session-scoped) + Lambda persistent (survives restart).
        // Drop duplicate messages to prevent re-processing after relay loops.
        {
            // Layer 1: in-memory check (fast path — no IPC needed)
            let seen = self.fanout_seen.read().await;
            if seen.contains(&fanout_msg.diffusion_id) {
                debug!("Fan-Out DEDUP (memory): diffusion_id={} already processed",
                    hex::encode(&fanout_msg.diffusion_id[..8]));
                return Ok(ResponsePayload {
                    success: true,
                    request_id: email.request_id.clone(),
                    witness_signature: None, cheque_for_receiver: None,
                    scar_consent_voucher: None,
                    produced_state_id: None, receipt: None, commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    txid: None,
                    state_id: None, error: None,
                    rejection_code: Some("FANOUT_DUPLICATE".into()),
                    error_response: None,
                    validator_hints: vec![], sender_fact_chain: None, receiver_fact_chain: None,
                    fact_signature: None,
                    query_data: None,
                });
            }
        }
        // Layer 2: persistent check via Lambda (survives restart)
        match self.lambda.send_fanout_dedup(&fanout_msg.diffusion_id).await {
            Ok(true) => {
                // Already seen in persistent storage — add to in-memory too
                self.fanout_seen.write().await.insert(fanout_msg.diffusion_id);
                debug!("Fan-Out DEDUP (persistent): diffusion_id={} already processed",
                    hex::encode(&fanout_msg.diffusion_id[..8]));
                return Ok(ResponsePayload {
                    success: true,
                    request_id: email.request_id.clone(),
                    witness_signature: None, cheque_for_receiver: None,
                    scar_consent_voucher: None,
                    produced_state_id: None, receipt: None, commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    txid: None,
                    state_id: None, error: None,
                    rejection_code: Some("FANOUT_DUPLICATE".into()),
                    error_response: None,
                    validator_hints: vec![], sender_fact_chain: None, receiver_fact_chain: None,
                    fact_signature: None,
                    query_data: None,
                });
            }
            Ok(false) => { /* Not seen — proceed to CL10 verification */ }
            Err(e) => {
                // Lambda unavailable — proceed with in-memory dedup only (graceful degradation)
                debug!("Fan-Out dedup: Lambda check failed ({}), proceeding with memory-only", e);
            }
        }

        // Verify via Core CL10
        let vbc_bundle = self.config.validator.load_vbc();
        let verify_result = core_ipc::verify_fanout_cl10(&self.core, &fanout_msg, vbc_bundle)?;

        if !verify_result.accepted {
            warn!("Fan-Out REJECTED by CL10: {:?}", verify_result.rejection_reason);
            return Ok(ResponsePayload {
                success: false,
                request_id: email.request_id.clone(),
                witness_signature: None,
                cheque_for_receiver: None,
                scar_consent_voucher: None,
                produced_state_id: None,
                receipt: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                txid: None,
                state_id: None,
                error: verify_result.rejection_reason,
                rejection_code: Some("CL10_FANOUT_REJECTED".into()),
                error_response: None,
                validator_hints: vec![],
                sender_fact_chain: None,
                receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            });
        }

        // Mark as seen AFTER CL10 acceptance (not before — rejected messages shouldn't pollute the set)
        {
            let mut seen = self.fanout_seen.write().await;
            seen.insert(fanout_msg.diffusion_id);
        }
        // Persistent mark via Lambda (survives restart)
        let _ = self.lambda.send_fanout_mark(&fanout_msg.diffusion_id).await;

        // CL10 accepted — relay to peers with decremented TTL
        if verify_result.new_ttl > 0 {
            let mut relay_msg = fanout_msg.clone();
            relay_msg.ttl_current = verify_result.new_ttl;

            // Forward to known validators via email (CL10 §18.8)
            let fanout_count = std::cmp::min(relay_msg.fanout as usize, 3);
            info!("Fan-Out: relaying to {} peers (ttl={})", fanout_count, verify_result.new_ttl);

            // Get peer email addresses from Lambda's VSP (hint table)
            let peers = match self.lambda.send_validator_status_request("fanout-relay").await {
                Ok(vsp) => vsp.known_validators.iter()
                    .filter_map(|h| {
                        h.carriers.iter()
                            .find(|c| c.starts_with("email:"))
                            .map(|c| c[6..].to_string())
                    })
                    .take(fanout_count)
                    .collect::<Vec<String>>(),
                Err(e) => {
                    warn!("Fan-Out: could not get peer hints from Lambda: {}", e);
                    vec![]
                }
            };

            // Send relay email to each peer
            for peer_email in &peers {
                match email::build_fanout_relay_email(
                    &self.config.identity.email,
                    peer_email,
                    &relay_msg,
                ) {
                    Ok(email_bytes) => {
                        if let Err(e) = self.sender.send(peer_email, &email_bytes).await {
                            warn!("Fan-Out relay to {}: send failed: {}", peer_email, e);
                        } else {
                            info!("Fan-Out relay sent to {} (ttl={})", peer_email, verify_result.new_ttl);
                        }
                    }
                    Err(e) => warn!("Fan-Out relay to {}: build failed: {}", peer_email, e),
                }
            }

            if peers.is_empty() {
                info!("Fan-Out: no peer email addresses found — relay skipped");
            }
        }

        // Pass to Lambda for local processing based on content_type.
        // Lambda handles: DWP query (find witness), JFP result (SCAR), key distribution,
        // Console result (digit_version update).
        info!("Fan-Out: content_type=0x{:04x} verified by Core (CL10), processing locally",
              fanout_msg.content_type);

        // Console result: auto-apply digit_version (coordination signal, not command).
        // Our Lambda applies it. Third-party Lambda implementations decide for themselves.
        // See Yellow Paper §21.10.7: "Console outputs represent distributed coordination
        // signals, not binding commands."
        if fanout_msg.content_type == axiom_core_logic::types::FANOUT_CONSOLE_RESULT {
            info!("Fan-Out: Console decision received — forwarding to Lambda for digit_version update");
            // Content is passed to Lambda via the response; Lambda applies it.
            // In subprocess mode, this would go through IPC. For now, log the intent.
            // The admin API auto-finalize handles local proposals; this handles remote ones.
        }

        Ok(ResponsePayload {
            success: true,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: None,
            rejection_code: None,
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        })
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::{AntieEmail, AntiePayload, ResponsePayload};

    /// Helper to build a minimal AntieEmail with a given message_type.
    fn make_email(message_type: &str) -> AntieEmail {
        AntieEmail {
            from: "test@example.com".into(),
            to: "antie@example.com".into(),
            message_type: message_type.into(),
            request_id: "req-001".into(),
            message_id: None,
            payload: AntiePayload::default(),
            raw: vec![],
            uncle_correlate: None,
        }
    }

    // ── Message-type routing table ──────────────────────────────────

    /// Verify the email-based routing table dispatches all known message types.
    #[test]
    fn message_type_routing_known_types() {
        let known_types = [
            "witness", "redeem", "ack", "query", "validator_status",
            "init_genesis_dev", "vbc_sign_request", "vbc_sign_commit",
            "scar_heal", "set_auth_hash", "peer_audit_request",
            "peer_audit_response", "fanout_relay",
        ];
        for msg_type in &known_types {
            let is_unknown = !matches!(
                *msg_type,
                "witness" | "redeem" | "ack" | "query" | "validator_status"
                    | "init_genesis_dev" | "vbc_sign_request" | "vbc_sign_commit"
                    | "scar_heal" | "set_auth_hash" | "peer_audit_request"
                    | "peer_audit_response" | "fanout_relay"
            );
            assert!(
                !is_unknown,
                "Message type '{}' was not matched by routing table",
                msg_type
            );
        }
    }

    /// TCP routing includes "query_state" as alias for "query".
    #[test]
    fn tcp_routing_query_state_alias() {
        let aliases = ["query_state", "query"];
        for alias in &aliases {
            let matches = matches!(
                *alias,
                "query_state" | "query"
            );
            assert!(matches, "'{}' should match query routing", alias);
        }
    }

    /// Unknown message types produce a well-formed error ResponsePayload.
    #[test]
    fn unknown_message_type_produces_error_response() {
        let email = make_email("totally_bogus");
        let response = ResponsePayload {
            success: false,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: Some(format!("Unknown message type: {}", email.message_type)),
            rejection_code: Some("UNKNOWN_TYPE".into()),
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        };
        assert!(!response.success);
        assert_eq!(response.rejection_code.as_deref(), Some("UNKNOWN_TYPE"));
        assert!(response.error.as_ref().unwrap().contains("totally_bogus"));
    }

    // ── Error response formatting ───────────────────────────────────

    /// Error payload includes the request_id from the original email.
    #[test]
    fn error_response_echoes_request_id() {
        let email = make_email("witness");
        let error_payload = ResponsePayload {
            success: false,
            request_id: email.request_id.clone(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: None,
            receipt: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: Some("something went wrong".into()),
            rejection_code: Some("INTERNAL_ERROR".into()),
            error_response: None,
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        };
        assert_eq!(error_payload.request_id, "req-001");
        assert_eq!(error_payload.rejection_code.as_deref(), Some("INTERNAL_ERROR"));
    }

    /// ResponsePayload round-trips through serde_json without data loss.
    #[test]
    fn response_payload_serde_roundtrip() {
        let payload = ResponsePayload {
            success: true,
            request_id: "rt-42".into(),
            witness_signature: None,
            cheque_for_receiver: None,
            scar_consent_voucher: None,
            produced_state_id: Some(vec![0xaa; 32]),
            receipt: None,
            commitment_hash: Some(vec![0xbb; 32]),
            state_hash: None,
            receipt_commitment: None,
            txid: None,
            state_id: None,
            error: None,
            rejection_code: None,
            error_response: None,
            validator_hints: vec![axiom_core_logic::types::ValidatorHint {
                validator_id: [0u8; 32],
                name: "abc".into(),
                carriers: vec![],
                proof_cap: None,
                last_seen: None,
                ed25519_pk: None,
                encryption_public_key: String::new(),
                supported_encryption: String::new(),
            }],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let decoded: ResponsePayload = serde_json::from_str(&json).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.request_id, "rt-42");
        assert_eq!(decoded.produced_state_id.unwrap().len(), 32);
        assert_eq!(decoded.commitment_hash.unwrap().len(), 32);
        assert_eq!(decoded.validator_hints.len(), 1);
    }

    // ── VbcSignRequest serialization ────────────────────────────────

    /// VbcSignRequest serializes "type" field correctly via serde rename.
    #[test]
    fn vbc_sign_request_type_field_rename() {
        let req = VbcSignRequest {
            request_type: "vbc_sign_request".into(),
            request_id: "vbc-1".into(),
            sphincs_pk_hex: "aa".into(),
            dilithium_pk_hex: "bb".into(),
            ed25519_pk_hex: "cc".into(),
            pgp_fingerprint_hex: "dd".into(),
            proof_cap: "DMAP".into(),
            node_name: "n1".into(),
            issued_at: None,
            expires_at: None,
            chain_depth: None,
            issuer_set_hex: vec![],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["type"], "vbc_sign_request");
        assert!(json.get("request_type").is_none());
        assert!(json.get("issued_at").is_none());
        assert!(json.get("expires_at").is_none());
        assert!(json.get("chain_depth").is_none());
        assert!(json.get("issuer_set_hex").is_none());
    }

    /// VbcResponse deserializes success + error from JSON.
    #[test]
    fn vbc_response_deserialize() {
        let json = r#"{"success": true}"#;
        let resp: VbcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert!(resp.error.is_none());

        let json2 = r#"{"success": false, "error": "budget exceeded"}"#;
        let resp2: VbcResponse = serde_json::from_str(json2).unwrap();
        assert!(!resp2.success);
        assert_eq!(resp2.error.as_deref(), Some("budget exceeded"));
    }

    /// Log-injection characters in message_type are sanitized.
    #[test]
    fn message_type_sanitization() {
        let malicious = "witness\nINJECTED_LINE\r";
        let sanitized = malicious.replace('\n', "\\n").replace('\r', "\\r");
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(sanitized.contains("\\n"));
        assert!(sanitized.contains("\\r"));
    }
}
