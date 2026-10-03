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

/// KI#141 — the longest a pull carrier waits between reconnect attempts.
pub(crate) const CARRIER_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30 * 60);

// ── KI#114 (b) heartbeat bounds — the longest LEGITIMATE silence per loop ──
/// The maildir dispatch loop beats every pass (≤ 500 ms idle) and per message,
/// so its only unbeaten stretch is ONE message's round — a Lambda witness call
/// has no time limit (owner ruling 2026-10-01), so a hung one surfaces here.
pub(crate) const DISPATCH_MAX_SILENCE_SECS: u64 = 600;
/// A pull account beats per fetch, per quiet IDLE slice and per backoff-sleep
/// slice (≤ 60 s each); its unbeaten stretch is one `check_new` (every carrier
/// step bounded by `carrier_io::IO_STEP_TIMEOUT`, but a backlog of large
/// messages is many steps) or one message's `mark_processed`.
pub(crate) const PULL_MAX_SILENCE_SECS: u64 = 900;
/// The slice every carrier wait (backoff, poll interval) beats on.
pub(crate) const BEAT_SLICE: std::time::Duration = std::time::Duration::from_secs(60);
/// How often the stall watchdog evaluates the heartbeats.
pub(crate) const STALL_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Sleep `total`, beating `hb` at least every [`BEAT_SLICE`] — a carrier in
/// KI#141 backoff (up to 30 min) is waiting on purpose, not stalled.
pub(crate) async fn sleep_beating(total: std::time::Duration, hb: &crate::stats::LoopHeartbeat) {
    let end = tokio::time::Instant::now() + total;
    loop {
        hb.beat();
        let now = tokio::time::Instant::now();
        if now >= end {
            return;
        }
        tokio::time::sleep(std::cmp::min(end - now, BEAT_SLICE)).await;
    }
}

use crate::carrier::{self, MailCarrier, MaildirConfig, ImapConfig, Pop3Config};
use crate::config::{AntieConfig, LambdaConfig};
use crate::core_ipc;
use crate::email::{self, AntieEmail, ResponsePayload};
use crate::error::AntieError;
use crate::lambda_client::LambdaClient;
use axiom_dmap_vm::AvmInterpreter;
use axiom_core_logic::types::GroupMember;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};


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

    // (`fanout_seen` — DELETED 2026-10-02, KI#242 wave: a "Fan-Out replay
    // prevention" set that nothing ever read or wrote (RULE 3 shape 3). Fan-out
    // relay is refused at the door by message type since KI#175, so there is no
    // replay to prevent here.)

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

/// ⚠ **DELETED 2026-09-07 — ANTIE no longer touches the transaction payload.**
///
/// A `fn deserialize_witness_request` used to live here. It walked the raw CBOR
/// map, REMOVED seven `is_*` discriminator bools from inside `transaction`,
/// re-encoded the map, typed-decoded it, and then rebuilt `Transaction.kind`
/// from the bools it had taken out. It existed because the canonical encoder
/// emitted those bools while `Transaction` is `#[serde(deny_unknown_fields)]`,
/// so a plain `ciborium::from_reader` died with "unknown field `is_heal`".
///
/// It was a **layer violation on the ANTIE rule** (CLAUDE.md §8): *"ANTIE is a
/// carrier + executor … ANTIE does NOT read, interpret, synthesize, or strip
/// fields from the transaction payload itself."* The owner, 2026-09-07: *"ANTIE is
/// just a delivery agent, why it is reading core's lib?"* — the answer was that
/// the wire format forced it to. It was also one of FOUR such decoders, and the
/// three others disagreed with each other on the priority order of the bools.
///
/// The wire carries `kind` itself now (see the note on `TxKind` in core/logic),
/// so the call site is a plain `ciborium::from_reader::<WitnessRequest>` and
/// this carrier interprets nothing. **Do not reintroduce a fixup here.** If a
/// payload does not decode, that is the sender's problem to fix at the sender —
/// repairing it in transit is how a carrier becomes an authority.

/// Message types whose handler sends its own answer mail (validator↔validator
/// §23.14.6 peer audit). The generic dispatch reply is suppressed for these —
/// the other validator cannot parse it (see the call site).
pub(crate) fn answers_out_of_band(message_type: &str) -> bool {
    matches!(message_type, "peer_audit_request" | "peer_audit_response")
}

/// YPX-015 §2.1: `avg_witness_ms` from Lambda's `/stats` JSON (string scan —
/// no serde needed). `None` when the field is absent or not a number.
pub(crate) fn parse_avg_witness_ms(body: &str) -> Option<u64> {
    let pos = body.find("\"avg_witness_ms\":")?;
    let after = &body[pos + 17..];
    let end = after.find([',', '}'])?;
    after[..end].trim().parse::<u64>().ok()
}

/// YPX-015 §2.1 AS BUILT: apply one poll outcome to the stats. A good read stores
/// the value and ends a failure streak; a failed read (refused, unreachable,
/// unparseable) is COUNTED — it must never look like "no data yet". Returns the
/// reason to WARN on for the first failure and every 100th, else `None`.
pub(crate) fn record_stats_poll(
    stats: &crate::stats::AntieStats,
    outcome: Result<u64, String>,
) -> Option<String> {
    use std::sync::atomic::Ordering;
    match outcome {
        Ok(v) => {
            stats.avg_witness_ms.store(v, Ordering::Relaxed);
            None
        }
        Err(reason) => {
            let n = stats.lambda_stats_poll_failures.fetch_add(1, Ordering::Relaxed) + 1;
            (n == 1 || n % 100 == 0).then_some(reason)
        }
    }
}

/// YPX-015 §2.1 — does the estimated wait exceed the busy threshold?
///
/// ╔═══════════════════════════════════════════════════════════════════╗
/// ║  QUEUE DEPTH, NOT queue_depth + 1                                  ║
/// ╚═══════════════════════════════════════════════════════════════════╝
/// The spec's formula is `estimated_wait = queue_depth × avg_witness_ms`. The
/// `+1` this used to carry ("includes current processing") turned the gate into
/// a SELF-LOCK:
///
///   `avg_witness_ms` is a LIFETIME average (`witness_time_us /
///   witness_success`, `lambda/src/admin.rs`) and never decays. A validator
///   that served a few slow rounds reports a high average forever. With the
///   `+1`, an ENTIRELY IDLE node still predicted one round's wait — above the
///   threshold — so it refused every request; refusing meant no new fast
///   samples; no samples meant the average could never come down. The only
///   exit was a process restart.
///
/// Observed live 2026-09-04: three ~70s CL8 certificate signs left idle
/// validators reporting ~40,000ms against a 15,000ms threshold, refusing even a
/// plain genesis airdrop. It cost three separate runs before it was diagnosed.
///
/// Backpressure exists to shed a BACKLOG, not to punish a node that was once
/// slow. With nothing queued there is nothing to shed, so an idle validator
/// accepts work, takes fast samples, and recovers on its own — self-clearing
/// instead of self-locking, which is what the spec already said.
///
/// Free-standing so it can be driven directly by a test; the method below is a
/// thin wrapper that supplies the live numbers.
pub(crate) fn busy_estimate_exceeds(queue_depth: usize, avg_ms: u64, threshold_ms: u64) -> bool {
    (queue_depth as u64) * avg_ms > threshold_ms
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

        // Create outbound sender — SplitCarrier routes by recipient domain
        // (@axiom/@axiom.internal → local FATMAMA, else → external relay); see
        // AXIOM_DESIGN_AntieOutboundSplit.md. Falls back to Maildir outbox
        // (local-only mode without MTA).
        // ── ROUTE TABLE FIRST (AntieOutboundSplit, superseded mechanism) ──
        // When `[[outbound.route]]` is configured, ANTIE's
        // outbound job is to WRITE A FILE and stop; an agent (FATMAMA/postfix)
        // collects. Checked BEFORE `outbound.local` so a configured table wins
        // over the legacy SMTP push without needing the old sections removed —
        // which keeps rollback to "delete the block, restart".
        //
        // ⚠ The collector MUST be running before this is enabled. An outbox
        // nothing drains is a DEAD END: replies strand silently and clients
        // time out (this bit 7 of 10 validators — see the fallback arm below).
        let sender: Box<dyn MailCarrier> = if !config.outbound.route.is_empty() {
            let md = config.carriers.maildir.as_ref().ok_or_else(|| {
                AntieError::ConfigError(
                    "outbound.route requires [carriers.maildir] for the inbox side".into(),
                )
            })?;
            tracing::info!(
                "[OUTBOUND-ROUTED] writing to outbox directories by domain table ({} route(s); NO default — an unrouted domain is REFUSED)",
                config.outbound.route.len(),
            );
            Box::new(
                carrier::routed_carrier::RoutedCarrier::new(
                    &md.inbox,
                    config.outbound.clone(),
                )
                .await?,
            )
        } else if let Some(ref local) = config.outbound.local {
            let local_carrier = carrier::smtp_carrier::SmtpCarrier::new(
                local.server.clone(), local.port,
                local.username.clone(), local.password.clone(),
                local.use_tls, local.from_address.clone(),
            );
            let external_carrier = config.outbound.external.as_ref().map(|ext| {
                carrier::smtp_carrier::SmtpCarrier::new(
                    ext.server.clone(), ext.port,
                    ext.username.clone(), ext.password.clone(),
                    ext.use_tls, ext.from_address.clone(),
                )
            });
            Box::new(carrier::split_carrier::SplitCarrier::new(local_carrier, external_carrier))
        } else if let Some(ref ext) = config.outbound.external {
            // An operator with ONLY a mail provider (no on-box FATMAMA — every
            // validator that is not our dev fleet): the provider carries
            // everything, dev-domain recipients included (they bounce there,
            // which is correct — @axiom is nobody's real domain). Before
            // 2026-09-10 this shape fell through to the maildir dead-end
            // below, so `validator-setup`'s real-mail config could never send.
            tracing::info!("[OUTBOUND-EXTERNAL] no [outbound.local]; every recipient goes via {}:{}", ext.server, ext.port);
            let mk = || carrier::smtp_carrier::SmtpCarrier::new(
                ext.server.clone(), ext.port, ext.username.clone(), ext.password.clone(),
                ext.use_tls, ext.from_address.clone(),
            );
            Box::new(carrier::split_carrier::SplitCarrier::new(mk(), Some(mk())))
        } else if let Some(ref md) = config.carriers.maildir {
            // RULE 3 / KI-outbound-strand (2026-08-16): reaching here means
            // `outbound.local` is UNSET, so witness/redeem responses are written
            // to the maildir outbox and NOTHING drains it back to a carrier —
            // every k-witness reply strands silently and clients time out. This
            // is a dead-end "sender", not local-only delivery, in any env whose
            // MTA is FATMAMA (i.e. all of them). It bit 7 of 10 validators that
            // still carried the pre-SplitCarrier `[outbound.smtp]` section (the
            // new binary reads `[outbound.local]` and ignores `[outbound.smtp]`),
            // and the failure was invisible because this fallback runs happily.
            // Shout at startup so a misconfigured validator is obvious, not a
            // silent black hole.
            tracing::warn!(
                "[OUTBOUND-STRAND] no [outbound.local] configured — falling back to the \
                 maildir outbox at {}, which NOTHING delivers. Witness/redeem responses \
                 will be written there and NEVER reach the wallet unless an external \
                 drainer runs. If this is a validator on a FATMAMA mesh, its antie.toml \
                 is stale: rename [outbound.smtp] -> [outbound.local] (server 127.0.0.1:2525).",
                md.outbox.display(),
            );
            Box::new(carrier::maildir_carrier::MaildirCarrier::new(&md.inbox, &md.outbox).await?)
        } else {
            return Err(AntieError::ConfigError(
                "No outbound carrier configured (need outbound.local or carriers.maildir)".into()
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

        // KI#80: supervise the lambda child — detect exit, reap, respawn
        // with backoff. Before this, an OOM-killed lambda left the
        // validator a black hole until a human rolled it.
        {
            let gw = self.clone();
            tokio::spawn(async move { gw.lambda.supervision_loop().await });
        }

        // Health/status endpoint
        let _health_handle = crate::health::spawn_health_server(
            self.config.health_port, self.stats.clone(), self.config.health_token.clone(),
            self.lambda.lambda_alive_handle(),
        );

        // Populate active_carriers for the /status endpoint
        {
            let mut names = Vec::new();
            if self.config.carriers.maildir.is_some() { names.push("maildir"); }
            if !self.config.carriers.imap.is_empty() { names.push("imap"); }
            if !self.config.carriers.pop3.is_empty() { names.push("pop3"); }
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

        // Inbound accounts — up to MAX_INBOUND_ACCOUNTS (design §5.2.2f), one
        // task each. `enabled = false` (the owner, 2026-09-08): the entry stays, no
        // connection is opened, and the log says so. The count cap was checked
        // at config load; ANTIE does not reach here with more than five.
        for (idx, cfg) in self.config.carriers.imap.iter().cloned().enumerate() {
            if !cfg.enabled {
                warn!("IMAP carrier {}:{} ({}) is DISABLED by config (enabled = false) — no connection will be opened", cfg.server, cfg.port, cfg.username);
                continue;
            }
            let gw = self.clone();
            tasks.spawn(async move {
                if let Err(e) = gw.run_imap_carrier(&cfg, idx).await {
                    error!("IMAP carrier {}:{} ({}) exited: {}", cfg.server, cfg.port, cfg.username, e);
                }
            });
        }
        for (idx, cfg) in self.config.carriers.pop3.iter().cloned().enumerate() {
            if !cfg.enabled {
                warn!("POP3 carrier {}:{} ({}) is DISABLED by config (enabled = false) — no connection will be opened", cfg.server, cfg.port, cfg.username);
                continue;
            }
            let gw = self.clone();
            tasks.spawn(async move {
                if let Err(e) = gw.run_pop3_carrier(&cfg, idx).await {
                    error!("POP3 carrier {}:{} ({}) exited: {}", cfg.server, cfg.port, cfg.username, e);
                }
            });
        }

        // (TCP + WebSocket carriers removed 2026-05-21 — both transports
        // are no longer ANTIE's job. Direct-delivery transports run as
        // sibling processes — TOT today, future schemes — and are
        // advertised via `[carriers] advertise = [...]` in antie.toml.)

        // KI#114 (b) — the stall watchdog: every STALL_WATCH_INTERVAL, judge
        // the heartbeats with the SAME verdict /health serves; a newly stalled
        // loop is logged at ERROR by name, and `on_stall = "notify_and_restart"`
        // exits non-zero for the supervisor. It runs on its own task, so a
        // wedged carrier cannot silence it (a wedge that starved EVERY worker
        // would also time out the /health probe, which driver.py counts as down).
        {
            let stats = self.stats.clone();
            let alive = self.lambda.lambda_alive_handle();
            let policy = self.config.on_stall;
            let running = self.running.clone();
            info!("KI#114 stall watchdog running ({:?} cadence, on_stall = {:?})", STALL_WATCH_INTERVAL, policy);
            tasks.spawn(async move {
                let mut reported: Vec<String> = Vec::new();
                let mut ticker = tokio::time::interval(STALL_WATCH_INTERVAL);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    if !*running.read().await { break; }
                    let (v, _) = crate::health::health_body(&stats, alive.load(std::sync::atomic::Ordering::SeqCst));
                    crate::health::stall_watchdog_tick(&v, policy, &mut reported, &|code| std::process::exit(code));
                }
            });
        }

        // KI#114 — the oldest message waiting in inbox/new/ (work not taken is
        // a "serving nothing" signal that needs no traffic assumption). /status
        // reports its age; `inbox_scan_unix` stamps the scan (RULE 6).
        if let Some(ref md) = self.config.carriers.maildir {
            let new_dir = md.inbox.join("new");
            let stats = self.stats.clone();
            let running = self.running.clone();
            tasks.spawn(async move {
                use std::sync::atomic::Ordering;
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    if !*running.read().await { break; }
                    let dir = new_dir.clone();
                    let oldest = tokio::task::spawn_blocking(move || oldest_mtime_unix(&dir)).await.unwrap_or(None);
                    stats.inbox_oldest_unprocessed_mtime_unix.store(oldest.unwrap_or(0), Ordering::Relaxed);
                    stats.inbox_scan_unix.store(
                        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_secs(),
                        Ordering::Relaxed);
                }
            });
        }

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
        // The port is THIS validator's own Lambda (resolve_lambda_admin_port) —
        // never a default: 7780 was alpha's, and nine of ten co-hosted
        // validators judged their queue by alpha's witness time (2026-09-26).
        if self.config.performance.busy_threshold_ms > 0 {
            match self.config.resolve_lambda_admin_port() {
                Some(admin_port) => {
                    let stats = self.stats.clone();
                    stats.lambda_stats_port.store(admin_port as u64, std::sync::atomic::Ordering::Relaxed);
                    let admin_token = self.config.resolve_lambda_admin_token();
                    let poll_ms = self.config.performance.lambda_stats_poll_ms;
                    let running = self.running.clone();
                    tasks.spawn(async move {
                        Self::poll_lambda_stats(stats, admin_port, admin_token, poll_ms, running).await;
                    });
                    info!("YPX-015: Backpressure enabled (threshold={}ms, polling Lambda admin :{} every {}ms)",
                          self.config.performance.busy_threshold_ms, admin_port, poll_ms);
                }
                None => error!(
                    "YPX-015: backpressure NOT ARMED — busy_threshold_ms={} but this validator's Lambda admin \
                     port is unknown (no [performance] lambda_admin_port, no admin_port in the Lambda config). \
                     Set one, or busy_threshold_ms = 0 to disable on purpose. /status lambda_stats_port = 0.",
                    self.config.performance.busy_threshold_ms),
            }
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

        // KI#114 (b) — THE dispatch funnel heartbeat: every pass and every
        // message beats it; a hung witness round (no time limit, owner ruling)
        // or any wedge on this path ages it and flips /health.
        let hb = self.stats.register_heartbeat("dispatch", DISPATCH_MAX_SILENCE_SECS);

        // Process existing messages
        self.process_carrier_messages(&carrier, Some(&hb)).await;

        // Event loop
        while *self.running.read().await {
            hb.beat();
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                rx.recv()
            ).await {
                Ok(Some(())) => {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    while rx.try_recv().is_ok() {}
                    self.process_carrier_messages(&carrier, Some(&hb)).await;
                }
                Ok(None) => {
                    warn!("Maildir watcher channel closed");
                    break;
                }
                Err(_) => {
                    self.process_carrier_messages(&carrier, Some(&hb)).await;
                }
            }
            self.process_carrier_messages(&carrier, Some(&hb)).await;
        }

        Ok(())
    }

    /// Run the IMAP carrier (polling loop).
    /// IMAP: IDLE is PRIMARY, poll is the declared fallback (ruled 2026-08-21).
    ///
    /// IDLE mode drains the mailbox, then holds an authenticated session until
    /// the server pushes `* n EXISTS` — a couple of logins per half hour
    /// instead of one per tick, which is what keeps the KI#110 per-account
    /// auth budget quiet. If the server does not advertise IDLE, fall back to
    /// the poll loop LOUDLY: one WARN at startup naming the mode and rate.
    /// Never a silent degradation.
    async fn run_imap_carrier(&self, cfg: &ImapConfig, idx: usize) -> Result<(), AntieError> {
        let carrier = carrier::imap_carrier::ImapCarrier::new(
            cfg.server.clone(), cfg.port,
            cfg.username.clone(), cfg.password.clone(),
            cfg.use_tls, cfg.inbox_folder.clone(),
        );
        // KI#114 (b) — this account's heartbeat, named as /health reports it.
        let hb = self.stats.register_heartbeat(
            format!("imap#{}({}@{})", idx, cfg.username, cfg.server), PULL_MAX_SILENCE_SECS);
        if !cfg.use_idle {
            info!("IMAP carrier started: {}:{} (poll mode by config, every {}ms)",
                  cfg.server, cfg.port, self.config.poll_interval_ms);
            return self.run_polling_loop(&carrier, None, &hb).await;
        }

        info!("IMAP carrier started: {}:{} (IDLE primary)", cfg.server, cfg.port);
        let inbox_dir = match &self.config.carriers.maildir {
            Some(md) => md.inbox.clone(),
            None => return Err(AntieError::ConfigError(
                "imap carrier requires [carriers.maildir] as the delivery target".into())),
        };
        let inbox = crate::maildir::Maildir::open(&inbox_dir).await?;
        // Re-issue IDLE well inside the RFC 2177 ~29-minute guidance.
        let recycle = std::time::Duration::from_secs(25 * 60);
        // On an idle-session error, wait one poll interval before reconnecting —
        // the reconnect pace equals the poll rate the config already declared
        // safe, so a flapping server degrades to exactly poll-mode cost.
        let retry = std::time::Duration::from_millis(self.config.poll_interval_ms);
        let mut failures: u32 = 0;

        while *self.running.read().await {
            hb.beat();
            // Drain first: covers mail that arrived while not connected.
            let fetched = Self::deliver_carrier_messages(&carrier, &inbox, None, &self.stats, Some(&hb)).await;
            hb.beat();
            // KI#114 (b): the IDLE wait beats every quiet 60 s slice.
            let beat = || hb.beat();
            match carrier.idle_wait(recycle, &beat).await {
                Ok(_saw_mail) => { self.stats.note_carrier_attempt(&mut failures, true); } // loop: drain, then idle again
                Err(e) => {
                    let msg = format!("{}", e);
                    if msg.contains("IdleNotSupported") {
                        warn!("{} — FALLING BACK to poll mode every {}ms (declared \
                               fallback, not an error)", msg, self.config.poll_interval_ms);
                        return self.run_polling_loop(&carrier, None, &hb).await;
                    }
                    // KI#141 — back off on CONSECUTIVE failures; a fetch that
                    // reached the server in between resets the count. The
                    // counters on /health and /status move with it.
                    if fetched { self.stats.note_carrier_attempt(&mut failures, true); }
                    self.stats.note_carrier_attempt(&mut failures, false);
                    let wait = Self::carrier_backoff(retry, failures);
                    Self::report_carrier_failure("IMAP idle session", &cfg.server, &msg, wait, failures);
                    sleep_beating(wait, &hb).await;
                }
            }
        }
        Ok(())
    }

    /// Run the POP3 carrier (polling loop).
    async fn run_pop3_carrier(&self, cfg: &Pop3Config, idx: usize) -> Result<(), AntieError> {
        let carrier = carrier::pop3_carrier::Pop3Carrier::new(
            cfg.server.clone(), cfg.port,
            cfg.username.clone(), cfg.password.clone(),
            cfg.use_tls,
        );
        match cfg.spam_entropy_threshold {
            Some(thr) => info!("POP3 carrier started: {}:{} (entropy spam-drop < {:.2} bits/byte)",
                               cfg.server, cfg.port, thr),
            None => info!("POP3 carrier started: {}:{}", cfg.server, cfg.port),
        }
        let hb = self.stats.register_heartbeat(
            format!("pop3#{}({}@{})", idx, cfg.username, cfg.server), PULL_MAX_SILENCE_SECS);
        self.run_polling_loop(&carrier, cfg.spam_entropy_threshold, &hb).await
    }

    /// Generic polling loop — shared by IMAP and POP3 carriers.
    ///
    /// Inbox-funnel model (AXIOM_DESIGN_AntieInboxFunnel.md): pull carriers are
    /// *delivery agents*, not dispatchers. Each fetched message is written into
    /// the maildir `inbox/new/` — the single inbound funnel — and the Maildir
    /// carrier is the sole path to CL2/Lambda. This loop never touches Core.
    async fn run_polling_loop(
        &self,
        carrier: &dyn MailCarrier,
        spam_threshold: Option<f32>,
        hb: &crate::stats::LoopHeartbeat,
    ) -> Result<(), AntieError> {
        // The maildir inbox is the delivery target and the one dispatch path.
        // Enforced by CarriersConfig::validate(); guard again here in case a
        // carrier is spawned without it.
        let inbox_dir = match &self.config.carriers.maildir {
            Some(md) => md.inbox.clone(),
            None => return Err(AntieError::ConfigError(format!(
                "{} carrier requires [carriers.maildir] as the delivery target — \
                 pop3/imap fetch into inbox/new/, they do not dispatch directly",
                carrier.name()
            ))),
        };
        let inbox = crate::maildir::Maildir::open(&inbox_dir).await?;

        // Rate is validated at CONFIG LOAD (AntieConfig::validate_poll_rate) so a
        // dangerous value cannot start the process at all. It is NOT checked here:
        // an Err from this spawned task is only logged by the spawner, which is
        // enforcement that does not enforce.
        let poll_interval = std::time::Duration::from_millis(self.config.poll_interval_ms);
        Self::pull_loop(carrier, &inbox, spam_threshold, poll_interval, &self.stats, &self.running, hb).await;
        Ok(())
    }

    /// The poll loop body — an associated fn so the KI#114 test can run the
    /// REAL loop against a carrier that never returns.
    pub(crate) async fn pull_loop(
        carrier: &dyn MailCarrier,
        inbox: &crate::maildir::Maildir,
        spam_threshold: Option<f32>,
        poll_interval: std::time::Duration,
        stats: &crate::stats::AntieStats,
        running: &RwLock<bool>,
        hb: &crate::stats::LoopHeartbeat,
    ) {
        let mut failures: u32 = 0;
        while *running.read().await {
            hb.beat();
            // KI#141 — a poll that cannot reach the server backs off
            // (doubling, capped) instead of hammering at the poll rate.
            let reached = Self::deliver_carrier_messages(carrier, inbox, spam_threshold, stats, Some(hb)).await;
            stats.note_carrier_attempt(&mut failures, reached);
            let wait = Self::carrier_backoff(poll_interval, failures);
            if !reached {
                Self::report_carrier_failure(carrier.name(), "", "fetch failed", wait, failures);
            }
            sleep_beating(wait, hb).await;
        }
    }

    /// KI#141 — the "degrade loudly" policy. Every failure is a `warn!` with
    /// the streak; the FIRST time a loop reaches the backoff cap it is an
    /// `error!` — the carrier has been refused for long enough that the next
    /// attempt is 30 min away, and an operator reading the log tail (or the
    /// `carriers_in_backoff` gauge) must see it without grepping 5,000 lines.
    fn report_carrier_failure(what: &str, server: &str, why: &str, wait: std::time::Duration, failures: u32) {
        let at_cap = wait >= CARRIER_BACKOFF_MAX;
        let prev = if failures > 1 { Self::carrier_backoff(std::time::Duration::from_millis(1), failures - 1) } else { std::time::Duration::ZERO };
        if at_cap && prev < CARRIER_BACKOFF_MAX {
            error!("[KI#141] {} {} DOWN: {} consecutive failures, backoff at its cap ({:?}) — \
                    the provider is refusing this host; check /health carriers_in_backoff, \
                    credentials and IP reputation ({})", what, server, failures, wait, why);
        } else {
            warn!("{} {} error: {} — retrying in {:?} (consecutive failures: {})", what, server, why, wait, failures);
        }
    }

    /// KI#141 — the reconnect/poll delay after `failures` CONSECUTIVE carrier
    /// failures: the configured interval, doubled per failure, capped at
    /// `CARRIER_BACKOFF_MAX`. A flat interval (the code until 2026-09-08)
    /// reconnected ~5,100 times per node in 5.3 h against a provider that was
    /// refusing this host — the storm that keeps an IP block latched. Success
    /// resets the count, so a healthy carrier pays nothing. Pure, tested as a table.
    pub(crate) fn carrier_backoff(base: std::time::Duration, failures: u32) -> std::time::Duration {
        if failures == 0 {
            return base;
        }
        base.checked_mul(1u32 << failures.min(16)).unwrap_or(CARRIER_BACKOFF_MAX).min(CARRIER_BACKOFF_MAX)
    }

    /// Fetch → deliver-to-inbox loop for pull carriers (POP3/IMAP).
    ///
    /// Writes each retrieved message atomically into the maildir `inbox/new/`,
    /// then marks it processed on the server (POP3 DELE / IMAP EXPUNGE). The
    /// inbox write happens BEFORE the server delete, so a crash re-fetches into
    /// the inbox (at-least-once — identical to the prior direct-dispatch path;
    /// see AXIOM_DESIGN_AntieInboxFunnel.md §3.1). Never calls Core/Lambda.
    /// Returns `true` when the carrier could be reached (a fetch happened, even
    /// if it delivered nothing); `false` on a fetch failure — the signal the
    /// KI#141 backoff keys on.
    async fn deliver_carrier_messages(
        carrier: &dyn MailCarrier,
        inbox: &crate::maildir::Maildir,
        spam_threshold: Option<f32>,
        stats: &crate::stats::AntieStats,
        hb: Option<&crate::stats::LoopHeartbeat>,
    ) -> bool {
        match carrier.check_new().await {
            Ok(messages) => {
                for msg in messages.iter() {
                    if let Some(hb) = hb { hb.beat(); } // KI#114 — per message
                    // Minimal, marker-free anti-spam (opt-in via
                    // [carriers.pop3] spam_entropy_threshold): a low-entropy body
                    // is natural-language text (newsletter/welcome mail), never a
                    // base64-crypto UMP. Delete it from the server WITHOUT staging
                    // it in the inbox funnel. Bias toward keep; hygiene only, NOT
                    // a trust gate (Core validates). See email::body_entropy_bits.
                    if let Some(thr) = spam_threshold {
                        let bits = crate::email::body_entropy_bits(&msg.raw);
                        if bits < thr {
                            info!("[ANTIE-SPAM-DROP] {} body_entropy={:.2} < {:.2} bits/byte \
                                   — low-entropy text, deleting without staging", msg.id, bits, thr);
                            let _ = carrier.mark_processed(&msg.id).await;
                            continue;
                        }
                    }
                    match inbox.write_message(&msg.raw).await {
                        Ok(_) => {
                            stats.note_inbox_write(); // KI#114 — /status last_inbox_write_unix
                            // Staged in the inbox funnel — safe to delete from
                            // the server. The Maildir carrier dispatches it.
                            let _ = carrier.mark_processed(&msg.id).await;
                        }
                        Err(e) => {
                            error!("{}: inbox delivery failed for {}: {} — \
                                    left on server for retry", carrier.name(), msg.id, e);
                            let _ = carrier.mark_failed(&msg.id, &e.to_string()).await;
                        }
                    }
                }
                true
            }
            Err(e) => {
                warn!("{}: check_new failed: {}", carrier.name(), e);
                false
            }
        }
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
    async fn process_carrier_messages(&self, carrier: &dyn MailCarrier, hb: Option<&crate::stats::LoopHeartbeat>) {
        match carrier.check_new().await {
            Ok(messages) => {
                let total = messages.len();
                if total > 0 {
                    // KI#114 — a message the dispatcher sees in inbox/new/ has
                    // entered the funnel (whoever wrote it: an MDA, FATMAMA, a
                    // pull carrier).
                    self.stats.note_inbox_write();
                }
                for (idx, msg) in messages.iter().enumerate() {
                    if let Some(hb) = hb { hb.beat(); } // KI#114 — per message
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

        // YPX-015 §2.1 AS BUILT: never log the token.
        info!("YPX-015: Lambda stats poller started (port={}, token={}, interval={}ms)",
              admin_port, if admin_token.is_some() { "set" } else { "NONE" }, poll_ms);
        if admin_token.is_none() {
            warn!("YPX-015: no Lambda admin token (antie [performance] lambda_admin_token, nor admin_token \
                   in the lambda config) — /stats will be refused and backpressure will have NO load data");
        }

        loop {
            if !*running.read().await {
                break;
            }

            let outcome = match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    match resp.text().await {
                        Ok(text) if status.is_success() => match parse_avg_witness_ms(&text) {
                            Some(v) => Ok(v),
                            None => Err(format!("HTTP {status} without avg_witness_ms")),
                        },
                        Ok(_) => Err(format!("HTTP {status}")),
                        Err(e) => Err(format!("HTTP {status}, body unreadable: {e}")),
                    }
                }
                Err(e) => Err(format!("unreachable: {e}")),
            };
            if let Some(reason) = record_stats_poll(&stats, outcome) {
                warn!("YPX-015: Lambda /stats read failed ({reason}) — {} failure(s); the busy gate has NO \
                       load data, backpressure is OFF until a read succeeds",
                      stats.lambda_stats_poll_failures.load(std::sync::atomic::Ordering::Relaxed));
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
        busy_estimate_exceeds(queue_depth, avg_ms, threshold)
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
            error_response: antie_rejection(
                axiom_errors::error_code::E_ANTIE_VALIDATOR_BUSY,
                axiom_errors::ErrorCategory::Operational,
                format!("validator busy: estimated wait exceeds threshold (avg_witness_ms={})", avg_ms),
                &email.request_id,
            ),
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
            vbc_signature: None,
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
    /// §5.2.2f — file a received certificate mail into the stake wallet's own
    /// maildir (`<vdir>/wallets/<Name>_Stake/maildir/inbox/new`), where the
    /// SDK's `collect_delivered_signatures` reads it. `<vdir>` is derived from
    /// the maildir funnel (`<vdir>/maildir/inbox`). With no single stake wallet
    /// on disk it goes to `<vdir>/maildir/vbc/new` and the log says so — the
    /// operator brings it into the webclient by hand (design §5.2.2f).
    fn file_vbc_delivery(&self, raw: &[u8], sig: &axiom_core_logic::types::VbcIssuerSignature) {
        let Some(md) = self.config.carriers.maildir.as_ref() else {
            warn!("§5.2.2f: certificate mail received but no [carriers.maildir] — dropped"); return;
        };
        let vdir = md.inbox.parent().and_then(|p| p.parent()).map(|p| p.to_path_buf())
            .unwrap_or_else(|| md.inbox.clone());
        let stake_dirs: Vec<std::path::PathBuf> = std::fs::read_dir(vdir.join("wallets")).ok()
            .map(|rd| rd.flatten().map(|e| e.path())
                 .filter(|p| p.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.ends_with("_Stake"))).collect())
            .unwrap_or_default();
        let dest_dir = if stake_dirs.len() == 1 {
            stake_dirs[0].join("maildir/inbox/new")
        } else {
            warn!("§5.2.2f: {} stake wallet dir(s) under {} — filing the certificate under maildir/vbc/new instead",
                  stake_dirs.len(), vdir.join("wallets").display());
            vdir.join("maildir/vbc/new")
        };
        let name = format!("{}.vbc-{}.eml", chrono::Utc::now().timestamp(), hex::encode(&sig.signer_sphincs_pk[..8.min(sig.signer_sphincs_pk.len())]));
        let path = dest_dir.join(&name);
        match std::fs::create_dir_all(&dest_dir).and_then(|_| std::fs::write(&path, raw)) {
            Ok(()) => info!("§5.2.2f: certificate signature RECEIVED by mail — filed at {}", path.display()),
            Err(e) => warn!("§5.2.2f: could not file certificate mail at {}: {}", path.display(), e),
        }
    }

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
        // §5.2.2f — a certificate delivery is recognised by BODY, before any
        // subject parsing (the subject is free-form). It is not a transaction:
        // file it where the stake wallet's SDK collector reads, and stop.
        if let Some(sig) = email::try_parse_vbc_delivery(&msg.raw) {
            self.file_vbc_delivery(&msg.raw, &sig);
            return Ok(());
        }
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
            "set_auth_hash" => self.handle_set_auth_hash(&email).await,
            // ⚠ KI#175 (the owner 2026-09-21, RE-SCOPED after reading the code):
            // These are peer-directed, but the TRANSPORT is fine — they arrive as
            // EMAIL into this same gateway request dispatch (not a direct ANTIE↔ANTIE
            // socket), so "an ANTIE never connects to another ANTIE" is not violated.
            // The real gap is AUTHENTICATION: PeerAuditRequest/Response carry
            // requester_pk/responder_pk as UNPROVEN claims and are signed by NOTHING
            // (audit.rs verify_* is pure hash comparison), yet a mismatch/non-response
            // drives a ban (RULE 3 shape 5). FOLLOW-ON OWED: sign peer-audit
            // request+response with the OPERATIONAL WALLET and verify before banning —
            // NOT "wrap in a Transaction". Signing closes third-party FRAMING only;
            // a lying peer that echoes the request's expected_hash is KI#207.
            // fanout_relay's payload/signing is not yet verified. See KI#175 + KI#207.
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
                    error_response: antie_rejection(
                        axiom_errors::error_code::E_ANTIE_UNKNOWN_MESSAGE_TYPE,
                        axiom_errors::ErrorCategory::ClientBug,
                        format!("Unknown message type: {}", email.message_type),
                        &email.request_id,
                    ),
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
                    vbc_signature: None,
                })
            }
        };
        
        // §23.14.6 peer-audit mail is validator↔validator and carries its OWN
        // answer (peer_audit_response / NotHeld, sent by the handler). A generic
        // `witness_response`/`error` reply on top of it is not a message the other
        // validator can read: its ANTIE dropped every one as "requires UmpEnvelope,
        // body parses as raw CBOR" (35 ANTIE-DROP-PARSE on trustmesh, 2026-09-26).
        // Log the outcome locally; send nothing.
        if answers_out_of_band(email.message_type.as_str()) {
            match &response {
                Ok(p) if p.success => debug!("§23.14.6: {} {} handled — answer travels on its own mail, no generic reply",
                                             email.message_type, email.request_id),
                Ok(p) => warn!("§23.14.6: {} {} not answered: {}", email.message_type, email.request_id,
                               p.error.as_deref().unwrap_or("no detail")),
                Err(e) => warn!("§23.14.6: {} {} failed: {}", email.message_type, email.request_id, e),
            }
            return Ok(());
        }

        // Send response
        match response {
            Ok(payload) => {
                self.send_response(&email, &payload).await?;
            }
            Err(e) => {
                // Forward Lambda's TYPED verdict verbatim; only a genuine
                // ANTIE-internal fault is INTERNAL_ERROR. Before 2026-07-27
                // every error here was stamped INTERNAL_ERROR with
                // error_response dropped, so a protocol rejection
                // (E_INVALID_STATE_ID, or a RecoverableDrift carrying a
                // recovery hint) was indistinguishable from a crash — the
                // client could not dispatch on code as §"Phase 2 error stack"
                // requires, and heal hints were lost.
                let typed = match &e {
                    AntieError::LambdaRejected(er) => Some(er.clone()),
                    _ => None,
                };
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
                    rejection_code: Some(match &typed {
                        Some(er) => er.code.to_string(),
                        None => "INTERNAL_ERROR".to_string(),
                    }),
                    // KI#157: a non-Lambda fault still carries its structured form.
                    error_response: typed.or_else(|| Some(
                        axiom_errors::ErrorResponse::from(&e).with_request_id(email.request_id.as_str()),
                    )),
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
                    vbc_signature: None,
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
            ciborium::from_reader::<axiom_core_logic::types::WitnessRequest, _>(
                email.payload.raw_ump_body.as_slice())
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

        // YP §32-33: the co-located Nabla's ban file (defense-in-depth
        // pre-filter, before Lambda/Core). Keyed on the sender's Ed25519 pk
        // and its SMT bucket — what Nabla's BanTable keys on — never on the
        // `sender_wallet_id` address string (KI#228: the old check compared
        // that address to hex lines, and nothing wrote the file).
        if !has_overlap
            && nabla_ban_file_lists(
                self.config.nabla_ban_list_path.as_deref(),
                &nabla_ban_keys(&req.transaction),
                &self.stats,
            )
        {
            let wallet_id = &req.transaction.sender_wallet_id;
            warn!("E_WALLET_BANNED: sender {} rejected by the Nabla ban file (§32)", wallet_id);
            self.stats.ban_rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(AntieError::WalletBanned(
                format!("E_WALLET_BANNED: wallet {} is banned (YP §32)", wallet_id),
            ));
        }

        // ── CHEAP SIGNATURE PRE-FILTER (opt-in) ────────────────────────────
        //
        // A crafted message with the right subject, valid CBOR and a RANDOM
        // sender_wallet_id passes every gate above — the rate limiter has no
        // history for a fresh id, the ban list has never seen it — and then
        // costs SECONDS of AVM in validate_transaction_cl2 to reject. Cheap to
        // generate, expensive to verify: a DoS asymmetry that matters the
        // moment this host accepts internet mail (MX on).
        //
        // ── THE NUMBERS, SO AN OPERATOR CAN DECIDE ────────────────────────
        //   Ed25519 verify      ~125 us   (measured 2026-08-23; constant-time,
        //                                  so a FORGERY costs the same as a
        //                                  valid signature — no early exit)
        //   Core / AVM op       ~357,000,000 instructions ~= 300-400 ms
        //                                 (measured from live soak JIT-STATS)
        //
        //   => on a FORGED message this saves ~100% of a ~350ms execution.
        //   => on every GENUINE message it is PURE OVERHEAD (~0.03%), because
        //      Core verifies the same signature again afterwards. We pay twice.
        //
        // WHETHER THAT TRADE IS WORTH IT DEPENDS ENTIRELY ON YOUR TRAFFIC:
        //
        //   * If an MTA fronts this validator (postfix with DNSBL + connection
        //     and message rate limits), the spam/DDoS layer is ALREADY handled
        //     there and junk never gets this far — ordinary spam has no
        //     `AXIOM/<type>/<id>` subject, so it dies at the subject gate for
        //     microseconds. In that setup this filter buys little and costs a
        //     little. LEAVE IT OFF.
        //
        //   * It earns its keep only against a TARGETED attacker who crafts
        //     well-formed AXIOM messages with broken signatures.
        //
        //   * ⚠ It does NOT stop a determined attacker. Generating a keypair
        //     and signing your own worthless transaction is microseconds of
        //     work; that message passes this check honestly and Core still
        //     burns the full ~357M instructions to reject it. This narrows one
        //     cheap attack, it is NOT DoS resistance. Do not treat it as such.
        //
        // Turn it on when the LOGS show crafted-message floods, not on
        // suspicion. The transaction already carries client_pk and client_sig,
        // so nothing new goes on the wire either way.
        //
        // ⚠ PRE-FILTER, NOT A TRUST DECISION. It only makes rejection CHEAPER
        // for messages Core would reject anyway. It proves "someone holding
        // client_pk signed these bytes"; it does NOT bind that key to the
        // wallet — that stays Core's job and still runs in full on everything
        // that passes. Same shape as the ban-list pre-filter above.
        //
        // DEFAULT OFF (AXIOM_ANTIE_SIG_PREFILTER=1). A bug here rejects REAL
        // transactions, which is worse than the DoS it prevents, so it is
        // enabled deliberately after being watched — never as a side effect of
        // deploying. Uses Core's OWN builder and verifier: a second copy of
        // the signing-message rule would drift and reject valid traffic.
        if !has_overlap
            && std::env::var("AXIOM_ANTIE_SIG_PREFILTER").as_deref() == Ok("1")
        {
            let tx = &req.transaction;
            if !tx.client_sig.is_empty() && !tx.client_pk.is_empty() {
                let msg = axiom_core_logic::validation::compute_signing_message_public(tx);
                // Core's SANCTIONED gateway verification API (lib.rs `pub mod verify`:
                // "Lambda/Gateway may verify signatures but MUST NOT access hashing,
                // commitment computation, or other crypto internals"). Not a private
                // reach-around into crypto.
                if axiom_core_logic::verify::verify_ed25519(
                    &tx.client_pk, &msg, &tx.client_sig).is_err()
                {
                    warn!("E_SIG_PREFILTER: client_sig failed cheap verification for {} — \
                           refused before Core", tx.sender_wallet_id);
                    self.stats.parse_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(AntieError::EmailParseError(
                        "E_SIG_PREFILTER: client signature did not verify".into(),
                    ));
                }
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
        let cl2_fact_certificates = req.fact_certificates.clone(); // YP §26.17.6.5 B4

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
            cl2_fact_certificates,
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
                    error: validation.rejection_reason.clone(),
                    rejection_code: Some("CL2_VALIDATION_FAILED".into()),
                    // KI#157: Core's own code, not a string.
                    error_response: match validation.rejection {
                        Some(v) => Some(axiom_errors::ErrorResponse::from(v).with_request_id(email.request_id.as_str())),
                        None => antie_rejection(
                            axiom_errors::error_code::E_ANTIE_VALIDATION_FAILED,
                            axiom_errors::ErrorCategory::ProtocolReject,
                            validation.rejection_reason.unwrap_or_else(|| "CL2 rejected".into()),
                            &email.request_id,
                        ),
                    },
                    validator_hints: vec![],
                    sender_fact_chain: None,
                    receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
                    vbc_signature: None,
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
            // YPX-024: receiver delivery is planned ONCE — care-of parse +
            // MANDATORY fingerprint verify (also for a plain
            // receiver_address override), then email vs pickup-deposit by
            // the operator's [pickup] declaration. Refuse ⇒ delivered
            // NOWHERE (§3.1) with the counter bumped.
            let delivery_plan = crate::care_of::plan_receiver_delivery(
                lambda_request.transaction.receiver_address.as_deref(),
                &lambda_request.transaction.receiver_wallet_id,
                self.config.pickup.is_some(),
            );
            let receiver_email = match &delivery_plan {
                crate::care_of::DeliveryPlan::Email(e) => Some(e.clone()),
                crate::care_of::DeliveryPlan::Deposit { inner, .. } => Some(inner.clone()),
                crate::care_of::DeliveryPlan::Refuse { reason } => {
                    self.stats.care_of_verify_rejects
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!("YPX-024 §3.1: cheque delivery REFUSED — {}", reason);
                    None
                }
            };

            if let Some(ref recv_email) = receiver_email {
                // KI#241 F-2: the cheque's origin rides ANTIE's own payload —
                // built by Core's ONE constructor from the transaction just
                // witnessed; `build_cheque_delivery_email` refuses one that does
                // not reproduce the cheque txid (→ the warn below).
                let cheque_email = axiom_core_logic::nabla_wire::LegPreimage::origin_of(&lambda_request.transaction)
                    .map_err(|e| crate::error::AntieError::InvalidPayload(format!("cheque send_origin: {e:?}")))
                    .and_then(|send_origin| email::build_cheque_delivery_email(
                        &self.config.identity.email,
                        recv_email,
                        cheque,
                        lambda_response.sender_fact_chain.as_ref(),
                        &send_origin,
                    ));
                match cheque_email {
                    Ok(email_bytes) => {
                        // Try PGP encryption for receiver (graceful — falls back to plaintext)
                        let (final_bytes, encrypted) = crate::pgp::try_encrypt_for_email(
                            recv_email, &email_bytes,
                        ).await;
                        if encrypted {
                            info!("§17.9: Cheque PGP-encrypted for {}", recv_email);
                        }
                        // YPX-024 §3.2 SUPPORT path: deposit into
                        // `<dir>/<pickup-domain>/new/` and ANTIE's job ENDS —
                        // MUMMY (or any pickup agent) owns it from here.
                        // Deposit failure falls back to the verified inner
                        // email: support must never LOSE a delivery.
                        let mut deposited = false;
                        if let crate::care_of::DeliveryPlan::Deposit { ref domain, .. } = delivery_plan {
                            let base = self.config.pickup.as_ref()
                                .map(|p| std::path::PathBuf::from(&p.dir))
                                .expect("Deposit plan only exists with [pickup] set");
                            let filename = format!("{}.cheque.eml", hex::encode(cheque.txid));
                            match crate::care_of::deposit_atomic(&base, domain, &filename, &final_bytes) {
                                Ok(path) => {
                                    self.stats.care_of_deposits
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    info!("YPX-024: cheque for {} deposited at {} — \
                                           another carrier's problem from here",
                                          recv_email, path.display());
                                    deposited = true;
                                }
                                Err(e) => {
                                    warn!("YPX-024: pickup deposit failed for {} ({}) — \
                                           falling back to email delivery", recv_email, e);
                                }
                            }
                        } else if matches!(delivery_plan, crate::care_of::DeliveryPlan::Email(_))
                            && lambda_request.transaction.receiver_address.as_deref()
                                .map(|a| crate::care_of::parse_care_of(a).is_some())
                                .unwrap_or(false)
                        {
                            // Care-of understood but not supported here —
                            // ordinary mail to the verified inner (§3.2).
                            self.stats.care_of_default_deliveries
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                        // (never checked once deposited — a skip-list divert
                        // AND a pickup deposit would be double delivery)
                        let skipped = if deposited {
                            false
                        } else if let Some(ref sl) = self.skip_list {
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
                        if deposited {
                            // YPX-024: pickup deposit handled — the email
                            // path is skipped by design (single-path by
                            // capability, never duplicated).
                        } else
                        if skipped {
                            // Carrier-side dispatch handled. Skip the
                            // email path entirely; sibling carrier
                            // owns delivery from here.
                        } else
                        // ╔══════════════════════════════════════════════════════════════════════╗
                        // ║  ⚠⚠⚠  A CHEQUE IS A **DELIVERY**, NOT A **REPLY**.  ⚠⚠⚠              ║
                        // ║                                                                      ║
                        // ║  IT IS *SUPPOSED* TO BYPASS `send_response` AND ITS CUSTODY /        ║
                        // ║  `X-TOT-Session` LOGIC. THAT IS NOT A BUG. DO NOT "FIX" IT.          ║
                        // ╚══════════════════════════════════════════════════════════════════════╝
                        //
                        // A REPLY goes back to whoever ASKED (the requester's open session, if
                        // any) — that is `send_response`, and custody deposits it into the
                        // session directory so TOT can pump it down the held socket.
                        //
                        // A CHEQUE goes to the RECEIVER named in the transaction, who is a
                        // DIFFERENT PARTY with their OWN carrier and may not be online, may not
                        // be a client of this validator, and may not exist yet. It therefore
                        // goes out through the ordinary outbound carrier, below.
                        //
                        // ── HOW OUTBOUND ROUTING ACTUALLY WORKS (it is TOML-driven) ────────────
                        // `SplitCarrier` (carrier.rs, "Outbound router"):
                        //     @axiom / @axiom.internal  ->  [outbound.local]     on-box FATMAMA
                        //     every other domain        ->  [outbound.external]  real SMTP
                        // On a real-email validator `[outbound.external]` is the provider
                        // (e.g. smtp.purelymail.com:465 + AUTH) or the box's own postfix.
                        // `[[outbound.route]]` rows can pin a domain to a maildir outbox
                        // instead. NOTHING here is hardcoded — read the node's antie.toml.
                        //
                        // ── THE MISREADING THIS BANNER EXISTS TO PREVENT (2026-09-07) ──────────
                        // A browser wallet was given a made-up real-looking address, its claim
                        // ran, and no cheque came back. The chain of wrong conclusions was:
                        //   1. "the cheque doesn't go through send_response"      — TRUE
                        //   2. "...so it can never reach a session client"        — true, BY DESIGN
                        //   3. "...so this is an architectural gap in ANTIE"      — **FALSE**
                        // The cheque was delivered CORRECTLY: SplitCarrier saw a non-@axiom
                        // domain, handed it to the external SMTP relay, and mailed it to an
                        // address that HAS NO MAILBOX. ANTIE did exactly the right thing.
                        //
                        // The owner, 2026-09-07: *"we have designed it properly before already. i
                        // dont even know when we had problem now ... if its not dev email, it
                        // should goes to local postfix or imap if it was setup"*. Correct.
                        //
                        // ── SO IF A CHEQUE SEEMS "LOST", CHECK THESE, IN ORDER ─────────────────
                        //   1. Does the receiver address have a REAL MAILBOX someone can read?
                        //      A browser has none — that is a CLIENT limitation, not an ANTIE
                        //      one. The designed answer is YPX-024 care-of addressing
                        //      (`identity@pickup/fingerprint`), which reaches the
                        //      `DeliveryPlan::Deposit` arm ABOVE — note that non-mail cheque
                        //      delivery ALREADY EXISTS there. Add a pickup, not a custody hack.
                        //   2. Is `[outbound.external]` configured on THIS node? Without it a
                        //      real domain is refused — the no-fallback rule working.
                        //   3. Is the receiver simply offline / slow? Mail is asynchronous.
                        //
                        // ⚠ ROUTING A CHEQUE INTO THE REQUESTER'S SESSION WOULD BE WRONG even
                        // when sender == receiver: it makes delivery depend on a socket being
                        // open, silently drops the cheque when it is not, and makes a
                        // FUND-BEARING artifact contingent on a transport detail. The cheque
                        // must be durable and carrier-agnostic. Leave this alone.
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
        // §5.2.2f — THE CERTIFICATE IS A DELIVERY, NOT A REPLY (RULED 2026-09-09).
        // Same route as a cheque: the ordinary outbound router (`SplitCarrier`,
        // TOML-driven — @axiom → FATMAMA on the dev fleet, anything else →
        // [outbound.external]). NEVER the session custody, NEVER a care-of
        // deposit: a real validator's certificate must exist only in a real
        // mailbox it can read — that arrival is the proof its mail works.
        // The address is DERIVED from the bond: sender wallet id = stake email
        // ‖ key-derived suffix; certificate subject key = that wallet's key.
        if let Some(ref sig) = lambda_response.vbc_signature {
            let to = lambda_request.transaction.sender_wallet_id
                .split('/').next().unwrap_or("").to_string();
            if !to.contains('@') {
                warn!("§5.2.2f: cannot deliver certificate — no email in sender wallet id '{}'",
                      lambda_request.transaction.sender_wallet_id);
            } else {
                match email::build_vbc_delivery_email(&self.config.identity.email, &to, sig) {
                    Ok(bytes) => {
                        let (final_bytes, encrypted) = crate::pgp::try_encrypt_for_email(&to, &bytes).await;
                        match self.sender.send(&to, &final_bytes).await {
                            Ok(()) => info!("§5.2.2f: certificate signature DELIVERED to stake mailbox {}{}",
                                            to, if encrypted { " (PGP)" } else { "" }),
                            Err(e) => warn!("§5.2.2f: certificate delivery to {} FAILED: {}", to, e),
                        }
                    }
                    Err(e) => warn!("§5.2.2f: failed to build certificate delivery: {}", e),
                }
            }
        }

        if let Some(ref scar_consent) = lambda_response.scar_consent_for_receiver {
            // Same delivery rule as cheque delivery above (YPX-024): plan
            // once — verify, then email / pickup-deposit / refuse.
            let delivery_plan = crate::care_of::plan_receiver_delivery(
                lambda_request.transaction.receiver_address.as_deref(),
                &lambda_request.transaction.receiver_wallet_id,
                self.config.pickup.is_some(),
            );
            let receiver_email = match &delivery_plan {
                crate::care_of::DeliveryPlan::Email(e) => Some(e.clone()),
                crate::care_of::DeliveryPlan::Deposit { inner, .. } => Some(inner.clone()),
                crate::care_of::DeliveryPlan::Refuse { reason } => {
                    self.stats.care_of_verify_rejects
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!("YPX-024 §3.1: scar-consent delivery REFUSED — {}", reason);
                    None
                }
            };
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
                        // YPX-024 §3.2: supported care-of deposits the
                        // notification too — the pickup point carries ALL
                        // receiver-bound artifacts, not just cheques.
                        let mut deposited = false;
                        if let crate::care_of::DeliveryPlan::Deposit { ref domain, .. } = delivery_plan {
                            let base = self.config.pickup.as_ref()
                                .map(|p| std::path::PathBuf::from(&p.dir))
                                .expect("Deposit plan only exists with [pickup] set");
                            let filename = format!("{}.scar_consent.eml",
                                hex::encode(scar_consent.txid));
                            match crate::care_of::deposit_atomic(&base, domain, &filename, &final_bytes) {
                                Ok(path) => {
                                    self.stats.care_of_deposits
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    info!("YPX-024: scar-consent for {} deposited at {}",
                                          recv_email, path.display());
                                    deposited = true;
                                }
                                Err(e) => {
                                    warn!("YPX-024: pickup deposit failed for {} ({}) — \
                                           falling back to email delivery", recv_email, e);
                                }
                            }
                        }
                        if deposited {
                            // Pickup agent owns delivery from here.
                        } else
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
                        // §23.14.3 (KI#211 residual): the request never left this node —
                        // tell Lambda so B is not timed and the send is retried.
                        if let Err(e2) = self.lambda.send_peer_audit_dispatch_failed(&peer_audit.target_email, &e.to_string()).await {
                            warn!("§23.14.3: could not relay the dispatch failure to Lambda: {}", e2);
                        }
                    } else {
                        info!("§23.14.6: Peer-audit request sent to {}", peer_audit.target_email);
                    }
                }
                Err(e) => warn!("§23.14.6: Failed to build peer-audit email: {}", e),
            }
        }

        // KI#173 — the ONE conversion lives beside both types in Core; it
        // holds the sender-leg drops (§17.9 cheque, §1.5.1 consent
        // notification, §5.2.2f certificate) and carries `sender_state`.
        Ok(ResponsePayload::sender_leg(lambda_response))
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
            .and_then(query_wallet_pk)
            .ok_or_else(|| AntieError::InvalidPayload(
                "Query requires query_params.wallet_pk (byte array)".into(),
            ))?;

        let query_response = self.track_lambda(|| self.lambda.send_query_request(&wallet_pk)).await?;

        if query_response.found {
            let balance_info = match query_response.wallet_state.as_ref() {
                Some(s) => Some(wallet_query_projection(s)?),
                None => None,
            };

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
                sender_state: None,
                vbc_signature: None,
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
                error_response: antie_rejection(
                    axiom_errors::error_code::E_ANTIE_NOT_FOUND,
                    axiom_errors::ErrorCategory::ProtocolReject,
                    "Wallet not found",
                    &email.request_id,
                ),
                validator_hints: vec![],
                sender_fact_chain: None,
                receiver_fact_chain: None,
                fact_signature: None,
                query_data: None,
                sender_state: None,
                vbc_signature: None,
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
        vsp_reply(&email.request_id, &vsp_response)
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
        // KI#242: already the Core type — decoded typed with the body (a malformed
        // member list fails the body decode, before any handler runs).
        let group_members: Option<Vec<GroupMember>> = email.payload.group_members.clone();
        
        // Extract auth_hash if provided (stored into WalletState.auth_hash; unread since KI#108)
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
            error: lambda_response.error.clone(),
            rejection_code: if lambda_response.success { None } else { Some("GENESIS_FAILED".into()) },
            error_response: if lambda_response.success { None } else {
                antie_rejection(
                    axiom_errors::error_code::E_ANTIE_GENESIS_FAILED,
                    axiom_errors::ErrorCategory::ProtocolReject,
                    lambda_response.error.unwrap_or_else(|| "genesis refused".into()),
                    &email.request_id,
                )
            },
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
            vbc_signature: None,
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
            sender_state: None,
            vbc_signature: None,
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
            // KI#157: Lambda's typed verdict forwarded verbatim (was flattened and dropped).
            error_response: if lambda_response.success { None } else { lambda_response.error_response.clone() },
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
            vbc_signature: None,
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
        // `X-UNCLE-Correlate` header
        //
        // ⚠ YPX-023 §3.4: this joins the shared custody routing table
        // (decided 2026-08-24, deferred — no wire change). Note this is a TEE — a
        // COPY, the email below still goes out. A TOT browser session needs the
        // opposite (suppress the mail, since the client cannot read it), so
        // copy-vs-suppress belongs to the accepting component's table row, NOT
        // to the header itself. (i.e. UNCLE's SubmitSend handler
        // stamped it on the way in). Drop a verbatim copy at
        // `<outbox>/<correlate_hex>.cbor` so UNCLE's witness_observer
        // can route the response back to an in-flight SubmitSend.
        // Best-effort: the sink swallows its own errors and we never
        // let it block the primary SMTP/maildir dispatch.
        if let (Some(sink), Some(correlate)) = (&self.uncle_sink, &original.uncle_correlate) {
            let _ = sink.tee(correlate, &email_bytes).await;
        }

        // ── Custody routing (YPX-023 RULE 3) ─────────────────────────────
        //
        // A client that cannot hold a mailbox (the webclient) reached us over a
        // held TOT session; TOT stamped the envelope on the way in. Match that
        // header against the configured table and DEPOSIT the reply in the
        // row's outbox, where the carrier claims it and pushes it back down the
        // socket it is still holding.
        //
        // ANTIE learns nothing about sessions here. It matches a header name it
        // was configured with and writes a file — deliberately not a security
        // check (YPX-023 §3.2); the stamp is routing, never authentication.
        //
        // ADDITIVE: `custody` is None on every ordinary path and the table is
        // empty by default, so this whole block is skipped and behaviour is
        // byte-identical to before.
        // ╔══════════════════════════════════════════════════════════════════╗
        // ║  ⚠  CUSTODY IS FOR **REPLIES ONLY**. CHEQUES DO NOT COME HERE.   ║
        // ╚══════════════════════════════════════════════════════════════════╝
        // This deposits the RESPONSE to the request that carried the stamp, so
        // TOT can pump it back down the requester's held socket. A CHEQUE is a
        // delivery to the RECEIVER and deliberately goes out through the
        // ordinary outbound carrier instead — see the full banner at the cheque
        // dispatch in `handle_witness_request` before concluding that is a gap.
        // (It was mistaken for one on 2026-09-07.)
        if let Some((ref hdr, ref id)) = original.custody {
            // ── RULE 4 (YPX-023 §2B.4): stamp and address must AGREE ─────
            //
            // `X-TOT-Session` is the NORMAL-wallet session stamp. TOT decodes
            // nothing, so the route is the client's declaration — this is the
            // cross-check against what the address actually says.
            //
            // A dev wallet arriving stamped as a normal session would enter the
            // normal path while carrying the dev class's higher in-mesh trust:
            // a privilege escalation, and the worse of the two misroute
            // directions. Refuse, never "prefer one" — preferring the stamp
            // trusts a header that is explicitly NOT authentication (§3.2).
            //
            // Dev traffic gets its own stamp later; today it must not be
            // stamped at all.
            if hdr.eq_ignore_ascii_case("X-TOT-Session")
                && axiom_core_logic::wallet_id::is_dev_wallet(&original.from)
            {
                warn!("custody: REFUSING {} from DEV wallet {} — a dev message \
                       must never ride the normal session path (YPX-023 §2B.4)",
                      hdr, original.from);
                return Err(AntieError::InvalidPayload(format!(
                    "custody: {hdr} is the normal-wallet stamp; sender {} is a \
                     dev wallet — stamp and address disagree", original.from
                )));
            }

            if let Some(row) = self.config.outbound.custody.iter()
                .find(|r| r.header.eq_ignore_ascii_case(hdr))
            {
                // <outbox>/<id>/<request_id>.cbor — per-id SUBDIRECTORY because
                // one k=3 round yields THREE replies for a single session id;
                // UNCLE's flat <hex>.cbor would collide three times.
                let dir = row.outbox.join(id);
                let name = format!("{}.cbor", payload.request_id);
                match crate::custody::deposit(&dir, &name, &email_bytes).await {
                    Ok(path) => {
                        info!("custody: {} reply for {} deposited at {}",
                              hdr, original.from, path.display());
                        if row.suppress_email {
                            // The client cannot read mail — mailing it as well
                            // is noise. This is the difference from UNCLE's
                            // tee, and it is a property of the ROW, not the
                            // header (YPX-023 §3.4).
                            self.stats.emails_sent
                                .fetch_add(0, std::sync::atomic::Ordering::Relaxed);
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        // Deposit failed. Do NOT swallow it into the mail path
                        // when the row suppresses email: that would look like a
                        // delivery while the client waits forever. Fail loudly;
                        // the round is recoverable (YP-SDK §4.6a) but a silent
                        // drop is not.
                        warn!("custody: {} deposit FAILED for {} ({e}) — \
                               reply not delivered to the session", hdr, original.from);
                        if row.suppress_email {
                            return Err(AntieError::MaildirError(format!(
                                "custody deposit failed for {hdr}: {e}"
                            )));
                        }
                    }
                }
            }
        }

        self.sender.send(&original.from, &email_bytes).await?;
        self.stats.emails_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.note_round_served(); // KI#114 — /status last_round_served_unix

        // ⚠ LOG THE KEY, NOT JUST THE EVENT (2026-08-25).
        //
        // This line used to say only "Response sent to <addr>: success=true".
        // That records THAT a reply went out, never WHICH one — and the question
        // that actually matters is "was the reply carrying txid X ever sent?".
        //
        // Measured the same night: a redeem's FACT chain was built and confirmed
        // by Lambda (`with_fact_signature=3`, `fact_chain=BUILT`, 4 links) while
        // the client received three signed responses carrying no chain. Whether
        // ANTIE ever held that reply was UNANSWERABLE, because ANTIE keys its
        // logs on the request UUID and Lambda keys its own on the txid, and
        // NOTHING carried both. 435 successful sends could not be tied to the
        // one that mattered. Absence of a log line in a time window is not
        // evidence a reply was never posted — it is only absence of a join.
        //
        // So log the txid (the key Lambda uses), whether the reply actually
        // carries a chain, and the request_id (the key ANTIE uses). One line
        // that both sides can be joined on turns the next occurrence into a
        // query instead of an argument.
        info!(
            "Response sent to {}: success={} txid={} chain={} request_id={}",
            original.from,
            payload.success,
            payload.txid.as_ref()
                .map(|t| hex::encode(&t[..core::cmp::min(8, t.len())]))
                .unwrap_or_else(|| "none".into()),
            payload.receiver_fact_chain.as_ref()
                .map(|c| format!("{}links", c.links.len()))
                .unwrap_or_else(|| "NONE".into()),
            payload.request_id,
        );
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

        // KI#173 — the Core request and response types (Lambda decodes exactly these).
        let payload = axiom_core_logic::types::VBCSignRequestPayload {
            request_id: email.request_id.clone(),
            sphincs_pk_hex: sphincs_pk_hex.clone(),
            dilithium_pk_hex: dilithium_pk_hex.clone(),
            ed25519_pk_hex: ed25519_pk_hex.clone(),
            pgp_fingerprint_hex: pgp_hex.to_string(),
            proof_cap,
            node_name,
        };
        let approval = self.track_lambda(|| self.lambda.send_vbc_sign_request(payload.clone())).await?.approval;
        let success = approval.approved;
        let error = approval.reason;

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
            error: error.clone(),
            rejection_code: if success { None } else { Some("VBC_SIGN_FAILED".into()) },
            error_response: if success { None } else {
                antie_rejection(
                    axiom_errors::error_code::E_ANTIE_VBC_SIGN_FAILED,
                    axiom_errors::ErrorCategory::ProtocolReject,
                    error.unwrap_or_else(|| "certificate sign refused".into()),
                    &email.request_id,
                )
            },
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
            vbc_signature: None,
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

        let payload = axiom_core_logic::types::VBCSignCommitPayload {
            request_id: email.request_id.clone(),
            sphincs_pk_hex: sphincs_pk_hex.clone(),
            dilithium_pk_hex: dilithium_pk_hex.clone(),
            ed25519_pk_hex: ed25519_pk_hex.clone(),
            pgp_fingerprint_hex: pgp_hex.to_string(),
            proof_cap,
            node_name,
            issued_at,
            expires_at,
            chain_depth,
            issuer_set_hex: email.payload.issuer_set_hex.clone(),
            previous_vbc: None,
        };
        let commit = self.track_lambda(|| self.lambda.send_vbc_sign_commit(payload.clone())).await?;
        let success = commit.success;
        let error = commit.error;
        
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
            error: error.clone(),
            rejection_code: if success { None } else { Some("VBC_SIGN_COMMIT_FAILED".into()) },
            error_response: if success { None } else {
                antie_rejection(
                    axiom_errors::error_code::E_ANTIE_VBC_SIGN_COMMIT_FAILED,
                    axiom_errors::ErrorCategory::ProtocolReject,
                    error.unwrap_or_else(|| "certificate commit refused".into()),
                    &email.request_id,
                )
            },
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
            vbc_signature: None,
        })
    }
    
    /// §4.5 / §30.2: Handle set_auth_hash request.
    ///
    /// Sets `auth_hash` on a wallet — a Lambda storage write, nothing more.
    ///
    /// ⚠ TWO CORRECTIONS TO WHAT THIS COMMENT USED TO SAY (2026-08-20):
    ///
    /// 1. It is NOT stolen-key protection. The owner key is derived from the
    ///    wallet private key (`SHA3-256("AXIOM_OWNER_KEY" || private_key)`), so
    ///    whoever holds the wallet key derives it in one step. The `owner_proof`
    ///    it keyed proved exactly what `client_sig` already proves — see KI#108.
    ///    **2026-09-25: `owner_proof` is DELETED (KI#108 item 2).** Core now
    ///    reads `auth_hash` nowhere; the column survives only as Lambda storage.
    /// 2. "Core already validates" was FALSE and it is what kept KI#107 hidden.
    ///    Core never sees THIS request, which is a direct Lambda storage write
    ///    with no authorisation of any kind. Do not read that sentence back
    ///    into this path.
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
            error: result.error.clone(),
            rejection_code: if result.success { None } else { Some("SET_AUTH_HASH_FAILED".into()) },
            error_response: if result.success { None } else {
                antie_rejection(
                    axiom_errors::error_code::E_ANTIE_SET_AUTH_HASH_FAILED,
                    axiom_errors::ErrorCategory::ProtocolReject,
                    result.error.unwrap_or_else(|| "set_auth_hash refused".into()),
                    &email_msg.request_id,
                )
            },
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
            vbc_signature: None,
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
            email_msg.payload.peer_audit_request.clone()
                .ok_or_else(|| AntieError::InvalidPayload("Missing peer_audit_request".into()))?;

        // Forward to Lambda for processing (DB lookup + Core hash verification)
        let result = self.track_lambda(|| self.lambda.send_peer_audit_request(&request)).await?;

        // §23.14 AS BUILT §5 / KI#229 (the owner ruled OPTION A, 2026-09-29): the
        // reply goes to A's hint address; when B holds NO hint for A (a fresh
        // lambda.db after a wipe — hints spread only as wallets carry them),
        // it goes to the request's envelope `From:` instead of being dropped.
        // Dropping it made B's answer read as silence and A banned an innocent
        // B `NonResponds` (§23.14.1 silence ruling). The reply is signed and
        // nonce-bound; A accepts it only if `responder_pk == target` and the
        // signature verifies. ACCEPTED RESIDUAL: `From:` is unauthenticated —
        // a replayed captured request under a forged `From:` gets B's signed
        // reply (sender/receiver balance, state id, amount) mailed to the
        // forger, one mail per replay.
        let reply_to = peer_audit_reply_address(result.requester_email.as_deref(), &email_msg.from);
        if result.requester_email.is_none() && (result.response.is_some() || result.not_held.is_some()) {
            warn!("§23.14.6: no hint resolves the requester — replying to the request's From: {:?} (KI#229)",
                  reply_to);
        }
        if let (Some(response), Some(requester_email)) = (&result.response, &reply_to) {
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
        // KI#213: "I hold nothing for that txid" is ALSO an answer — signed, mailed
        // back under the same message type. Before this, Lambda's None became a
        // generic failure that A's audit handler never saw, and A banned B for
        // silence after 600 s.
        if let (Some(not_held), Some(requester_email)) = (&result.not_held, &reply_to) {
            let nh_email = email::build_peer_audit_not_held_email(
                &self.config.identity.email,
                requester_email,
                not_held,
            )?;
            if let Err(e) = self.sender.send(requester_email, &nh_email).await {
                warn!("§23.14.6: Failed to send peer-audit NotHeld to {}: {}", requester_email, e);
            } else {
                info!("§23.14.6: Peer-audit NotHeld sent to {}", requester_email);
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
            sender_state: None,
            vbc_signature: None,
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

        // KI#213: the same message type carries EITHER the raw-fields reply OR
        // the signed NotHeld. Both are answers; Lambda judges.
        if let Some(not_held) = email_msg.payload.peer_audit_not_held.clone() {
            if let Err(e) = self.track_lambda(|| self.lambda.send_peer_audit_not_held(&not_held)).await {
                warn!("§23.14.6: Failed to forward peer-audit NotHeld to Lambda: {}", e);
            }
        } else {
            let response: axiom_core_logic::types::PeerAuditResponse =
                email_msg.payload.peer_audit_response.clone()
                    .ok_or_else(|| AntieError::InvalidPayload("Missing peer_audit_response".into()))?;

            // Forward to Lambda for verification (Core compares hash)
            if let Err(e) = self.track_lambda(|| self.lambda.send_peer_audit_response(&response)).await {
                warn!("§23.14.6: Failed to forward peer-audit response to Lambda: {}", e);
            }
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
            sender_state: None,
            vbc_signature: None,
        })
    }

    /// `fanout_relay` — REFUSED at the door (KI#175, ruled 2026-09-21, code 2026-09-25).
    ///
    /// This handler used to deserialize a `FanOutMessage`, verify it through Core
    /// CL10 and then RE-RELAY it by mail to up to three peer validators' ANTIEs —
    /// a direct ANTIE→ANTIE hop, which the Yellow Paper rules out ("a validator never
    /// connects to another validator, and an ANTIE never connects to another ANTIE;
    /// the only way anything reaches a peer validator is a wallet-carried transaction
    /// signed by the operational wallet", §28). The one sanctioned carve-out is the
    /// §23.14 peer-audit mail, which has its own signed request/reply/NotHeld shape.
    /// Nothing in the tree PRODUCES a fan-out today (`fanout_message: None` at every
    /// Lambda site), so the arm was a receiver with no sender (RULE 3) whose only
    /// live behaviour was the forbidden re-relay. Until fan-out is rebuilt as a
    /// wallet-carried transaction (KI#175), an inbound `fanout_relay` is refused
    /// with its own reason and counted on /health (`fanout_relay_refused`). Core's
    /// CL10 verify mode is retained for that rebuild.
    async fn handle_fanout_relay(
        &self,
        email: &AntieEmail,
    ) -> Result<ResponsePayload, AntieError> {
        self.stats.fanout_relay_refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        warn!(
            "Fan-Out relay REFUSED: {} from {} — a direct ANTIE→ANTIE relay is not a \
             validator-to-validator channel (YP §28, KI#175); fan-out must arrive as a \
             wallet-carried transaction",
            email.request_id, email.from
        );
        let reason = "fan-out relay refused: ANTIE is a gateway, not a validator-to-validator \
                      channel (YP §28, KI#175) — send fan-out as a wallet-carried transaction";
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
            error: Some(reason.to_string()),
            rejection_code: Some("FANOUT_RELAY_REFUSED".into()),
            error_response: antie_rejection(
                axiom_errors::error_code::E_ANTIE_INVALID_PAYLOAD,
                axiom_errors::ErrorCategory::ClientBug,
                reason.to_string(),
                &email.request_id,
            ),
            validator_hints: vec![],
            sender_fact_chain: None,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: None,
            vbc_signature: None,
        })
    }

}

/// KI#157 — the structured twin of a rejection ANTIE itself originates. The
/// `rejection_code` / `error` strings beside it stay unchanged.
/// KI#114 — the mtime (unix secs) of the oldest regular file in `dir`;
/// `None` when the directory is empty or unreadable.
pub(crate) fn oldest_mtime_unix(dir: &std::path::Path) -> Option<u64> {
    std::fs::read_dir(dir).ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()))
        .filter_map(|m| m.modified().ok())
        .filter_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .min()
}

fn antie_rejection(
    code: &'static str,
    category: axiom_errors::ErrorCategory,
    message: impl Into<String>,
    request_id: &str,
) -> Option<axiom_errors::ErrorResponse> {
    Some(
        axiom_errors::ErrorResponse::new(axiom_errors::ErrorCode::from_static(code), category, message)
            .with_request_id(request_id),
    )
}

/// KI#173 — one `query_data` entry, encoded by serde exactly as the field's
/// own type encodes (a `Vec<u8>` / `[u8; 32]` becomes an integer array, as it
/// did under the former `serde_json::json!`).
fn query_value<T: serde::Serialize>(value: &T) -> Result<ciborium::Value, AntieError> {
    ciborium::Value::serialized(value)
        .map_err(|e| AntieError::SerializationError(format!("query_data: {e}")))
}

/// YP §27.11.2.2 (AS BUILT, KI#179, 2026-10-01) — the VSP reply.
///
/// `query_data` is the Core `ValidatorStatusResponse` serialized WHOLE, with the
/// type's own field names. ANTIE is a carrier: it does not choose which public
/// fields a client may see, and it does not rename them.
///
/// ⚠ RULE 0 §4 — the reading this replaces: until 2026-10-01 this site picked 9
/// of the ~20 fields and renamed `validator_name`→`name`, so the fee,
/// jurisdiction, operator, encryption, stake and notes fields §27.11.2.3
/// specifies never left ANTIE (YP §27.11.1.1 says clients shop on fees via VSP),
/// and the SDK's reader found no validator in any reply. Every field is public by
/// §27.11.3.3 and the type's own docs — serializing the type adds no disclosure.
/// `validator_hints` repeats `known_validators` on the generic §27.5 channel
/// (stated in the YP).
fn vsp_reply(
    request_id: &str,
    vsp: &axiom_core_logic::types::ValidatorStatusResponse,
) -> Result<ResponsePayload, AntieError> {
    Ok(ResponsePayload {
        success: true,
        request_id: request_id.to_string(),
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
        validator_hints: vsp.known_validators.clone(),
        sender_fact_chain: None,
        receiver_fact_chain: None,
        fact_signature: None,
        query_data: Some(query_value(vsp)?),
        sender_state: None,
        vbc_signature: None,
    })
}

/// `query_params.wallet_pk` out of the inbound `query` body (KI#242: a CBOR map,
/// read with `ciborium` — no JSON intermediate). Accepts the key's value as a
/// CBOR byte string or an array of u8, exactly the two forms the former
/// `serde_json::from_value::<Vec<u8>>` accepted (a byte string arrived there as
/// an integer array). `None` ⇒ the handler's "requires query_params.wallet_pk".
pub(crate) fn query_wallet_pk(params: &ciborium::Value) -> Option<Vec<u8>> {
    params.as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some("wallet_pk"))
        .and_then(|(_, v)| match v {
            // ciborium's `Value` deserializer hands a byte string to `visit_bytes`,
            // which `Vec<u8>` does not take — so the byte-string form is read here,
            // and the integer-array form through serde.
            ciborium::Value::Bytes(b) => Some(b.clone()),
            other => other.deserialized::<Vec<u8>>().ok(),
        })
}

/// The `"query"` reply's `query_data` — a DELIBERATE PRIVACY PROJECTION of
/// `StoredWalletState`, not field-picking by accident (KI#179 ruling A,
/// 2026-10-01).
///
/// ⚠ RULE 0 §4 — do NOT "fix" this into serializing the whole type the way the
/// VSP reply above was fixed. The asker is UNAUTHENTICATED (any `wallet_pk`), and
/// `StoredWalletState` also carries `auth_hash`, `group_members`, `status` and
/// `wallet_id`: serializing it would ADD disclosure (new attack surface) where
/// VSP's fields are all public by §27.11.3.3. Pinned by
/// `wallet_query_projection_is_exactly_four_public_fields`.
fn wallet_query_projection(
    s: &axiom_core_logic::types::StoredWalletState,
) -> Result<ciborium::Value, AntieError> {
    Ok(query_data_map(vec![
        ("balance", query_value(&s.balance)?),
        ("wallet_seq", query_value(&s.wallet_seq)?),
        ("public_key", query_value(&s.public_key)?),
        ("state_id", query_value(&s.state_id)?),
    ]))
}

/// KI#173 — the `query_data` map. Keys are sorted, as the former
/// `serde_json::json!` map sorted them, so the reply bytes are unchanged.
fn query_data_map(mut entries: Vec<(&str, ciborium::Value)>) -> ciborium::Value {
    entries.sort_by(|a, b| a.0.cmp(b.0));
    ciborium::Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (ciborium::Value::Text(k.to_string()), v))
            .collect(),
    )
}

/// §23.14 AS BUILT §5 / KI#229 — where B mails its peer-audit answer: the
/// requester's hint address when one resolves, else the request's envelope
/// `From:` (never dropped — a dropped answer is read by A as silence and bans
/// an innocent B `NonResponds`). `None` only when neither exists.
/// Residual (accepted, the owner 2026-09-29): `From:` is unauthenticated.
pub(crate) fn peer_audit_reply_address(hint_email: Option<&str>, envelope_from: &str) -> Option<String> {
    match hint_email {
        Some(e) => Some(e.to_string()),
        None if !envelope_from.trim().is_empty() => Some(envelope_from.trim().to_string()),
        None => None,
    }
}

#[cfg(test)]
mod peer_audit_reply_address_tests {
    use super::peer_audit_reply_address;

    /// KI#229 — no hint for the requester → the answer goes to the request's
    /// `From:` instead of being dropped. MUTATION: return `None` when no hint
    /// resolves (the pre-fix drop) ⇒ red.
    #[test]
    fn no_hint_reply_goes_to_the_request_from_address() {
        assert_eq!(peer_audit_reply_address(None, "zeta@trustmesh.org").as_deref(),
                   Some("zeta@trustmesh.org"));
    }

    #[test]
    fn a_resolved_hint_still_wins_and_nothing_is_invented() {
        assert_eq!(peer_audit_reply_address(Some("a@x.org"), "b@y.org").as_deref(), Some("a@x.org"));
        assert_eq!(peer_audit_reply_address(None, "  "), None);
    }
}

/// YP §32 / KI#228 — the keys Nabla's `BanTable` would hold for this sender,
/// as the ban file writes them (`axiom_nabla::ban::BanTable::ban_file_contents`:
/// lowercase hex of a 32-byte SMT key). Nabla bans the client's Ed25519 pk
/// (`fork_ban_keys` always includes it; for every online tier the bucket IS
/// the pk) and, for an Ark-tier address, its tier bucket
/// `smt_bucket(pk, k_tier)` — derived exactly as the SDK signs its register
/// (`sdk/core/src/state_sig.rs`: tier from `sender_wallet_id`, Standard on a
/// parse failure). A non-32-byte key has no Nabla row: no keys.
pub(crate) fn nabla_ban_keys(tx: &axiom_core_logic::types::Transaction) -> Vec<String> {
    let Ok(pk) = <[u8; 32]>::try_from(tx.client_pk.as_slice()) else { return vec![] };
    let k_tier = axiom_core_logic::wallet_id::extract_security_level(&tx.sender_wallet_id)
        .map(|(k, _)| k)
        .unwrap_or(3);
    let bucket = axiom_core_logic::compute::smt_bucket(&pk, k_tier);
    let mut keys = vec![hex::encode(pk)];
    if bucket != pk {
        keys.push(hex::encode(bucket));
    }
    keys
}

/// YP §32 / KI#228 — does the co-located Nabla's ban file (`nabla_bans.txt`,
/// Nabla's data dir; format `BanTable::ban_file_contents`, one lowercase-hex
/// key per line) list any of `keys`? BEST-EFFORT by RULE 7 part 2 — a
/// validator MAY receive Nabla information but must never NEED it: no path
/// configured, a missing file (no Nabla on this host) or an unreadable one
/// allows the request through, and is COUNTED `ban_list_unavailable` on
/// `/status` (RULE 3 §2 — "0 rejected" must be distinguishable from "never
/// looked"). A present, empty file is a real "nobody banned".
pub(crate) fn nabla_ban_file_lists(
    path: Option<&str>,
    keys: &[String],
    stats: &crate::stats::AntieStats,
) -> bool {
    let contents = match path.map(std::fs::read_to_string) {
        Some(Ok(c)) => c,
        _ => {
            stats.ban_list_unavailable.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
    };
    contents.lines().map(str::trim).any(|line| keys.iter().any(|k| k == line))
}

#[cfg(test)]
mod nabla_ban_file_tests {
    use super::{nabla_ban_file_lists, nabla_ban_keys};
    use crate::stats::AntieStats;
    use std::sync::atomic::Ordering;

    fn tx_from(pk: [u8; 32]) -> axiom_core_logic::types::Transaction {
        axiom_core_logic::types::Transaction {
            client_pk: pk.to_vec(),
            sender_wallet_id: "alice@example.com/a1b2c3d4".into(),
            ..Default::default()
        }
    }

    /// KI#228 — the golden file Nabla's writer is pinned to
    /// (`nabla/src/ban.rs` `ban_file_contents_match_the_golden_file_antie_reads`)
    /// is matched by THIS reader for a sender whose pk is listed, and a sender
    /// not listed passes — before any Lambda/Core work (the call site returns
    /// `E_WALLET_BANNED` ahead of CL2). MUTATION: make `nabla_ban_file_lists`
    /// ignore the file (return false) ⇒ red; key on `sender_wallet_id` (the
    /// pre-fix check) ⇒ red.
    #[test]
    fn nabla_ban_file_golden_is_matched_by_antie() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("nabla_bans.txt");
        std::fs::write(&file, include_str!("../../nabla/tests/fixtures/nabla_bans.golden")).unwrap();
        let path = file.to_str();
        let stats = AntieStats::new();
        assert!(nabla_ban_file_lists(path, &nabla_ban_keys(&tx_from([0xAB; 32])), &stats),
                "a banned sender (pk in Nabla's file) is rejected");
        assert!(nabla_ban_file_lists(path, &nabla_ban_keys(&tx_from([0x01; 32])), &stats));
        assert!(!nabla_ban_file_lists(path, &nabla_ban_keys(&tx_from([0x02; 32])), &stats),
                "an unlisted sender passes");
        assert_eq!(stats.ban_list_unavailable.load(Ordering::Relaxed), 0, "the file was read");
    }

    /// KI#228 — RULE 7 part 2: no Nabla file = allow through, but COUNTED.
    #[test]
    fn absent_ban_file_allows_through_and_is_counted() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nabla_bans.txt");
        let stats = AntieStats::new();
        let keys = nabla_ban_keys(&tx_from([0xAB; 32]));
        assert!(!nabla_ban_file_lists(missing.to_str(), &keys, &stats), "absent file must not block");
        assert!(!nabla_ban_file_lists(None, &keys, &stats), "unconfigured must not block");
        assert_eq!(stats.ban_list_unavailable.load(Ordering::Relaxed), 2, "both counted");
        assert!(String::from_utf8(stats.to_json()).unwrap().contains("\"ban_list_unavailable\":2"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::{AntieEmail, AntiePayload, ResponsePayload};

    /// KI#157 — an ANTIE-originated rejection carries a structured twin with
    /// its registered code, category and the request id; a CL2/CL10 refusal
    /// carries Core's OWN code (not an ANTIE wrapper), so the client can
    /// dispatch on it and read the recovery hint.
    #[test]
    fn antie_rejections_carry_structured_error_responses() {
        use axiom_errors::{error_code, ErrorCategory, ErrorResponse};
        let busy = antie_rejection(error_code::E_ANTIE_VALIDATOR_BUSY, ErrorCategory::Operational, "busy", "req-1")
            .expect("busy twin");
        assert_eq!(busy.code.as_str(), "E_ANTIE_VALIDATOR_BUSY");
        assert_eq!(busy.category, ErrorCategory::Operational);
        assert_eq!(busy.request_id.as_deref(), Some("req-1"));

        let v = axiom_core_logic::types::ValidationError::InsufficientBalance;
        let expected_code = ErrorResponse::from(v.clone()).code;
        let core_twin = ErrorResponse::from(v).with_request_id("req-2");
        assert_eq!(core_twin.code, expected_code);
        assert!(!core_twin.code.as_str().starts_with("E_ANTIE_"), "CL2/CL10 refusals keep Core's code");

        for code in [
            error_code::E_ANTIE_VALIDATOR_BUSY, error_code::E_ANTIE_UNKNOWN_MESSAGE_TYPE,
            error_code::E_ANTIE_GENESIS_FAILED, error_code::E_ANTIE_VBC_SIGN_FAILED,
            error_code::E_ANTIE_VBC_SIGN_COMMIT_FAILED, error_code::E_ANTIE_SET_AUTH_HASH_FAILED,
        ] {
            assert!(code.starts_with("E_ANTIE_"));
        }
    }

    /// KI#173 — `query_data` moved from `serde_json::Value` to a CBOR value.
    /// The reply bytes must not change: the same map built the old way
    /// (`json!`) and the new way encode identically.
    #[test]
    fn query_data_cbor_map_encodes_like_the_former_json_map() {
        let public_key: Vec<u8> = vec![1, 2, 250];
        let state_id: [u8; 32] = [7u8; 32];
        let old = serde_json::json!({
            "balance": 505_000_000_000u64,
            "wallet_seq": 12u64,
            "public_key": public_key,
            "state_id": state_id,
        });
        let new = query_data_map(vec![
            ("balance", query_value(&505_000_000_000u64).unwrap()),
            ("wallet_seq", query_value(&12u64).unwrap()),
            ("public_key", query_value(&public_key).unwrap()),
            ("state_id", query_value(&state_id).unwrap()),
        ]);
        let mut old_bytes = Vec::new();
        ciborium::into_writer(&old, &mut old_bytes).unwrap();
        let mut new_bytes = Vec::new();
        ciborium::into_writer(&new, &mut new_bytes).unwrap();
        assert_eq!(old_bytes, new_bytes);
    }

    /// A `ValidatorStatusResponse` with EVERY field non-default, so a dropped or
    /// renamed field cannot hide behind a default value.
    fn full_vsp() -> axiom_core_logic::types::ValidatorStatusResponse {
        let hint = |n: u8| axiom_core_logic::types::ValidatorHint {
            validator_id: [n; 32],
            name: format!("peer-{n}"),
            carriers: vec![format!("email:peer{n}@vsp.test"), format!("tot:peer{n}.vsp.test:443")],
            proof_cap: Some("dmap".into()),
            last_seen: Some(1_700_000_000 + n as u64),
            ed25519_pk: Some([n ^ 0x55; 32]),
            encryption_public_key: format!("PGP-{n}"),
            supported_encryption: "PGP".into(),
        };
        axiom_core_logic::types::ValidatorStatusResponse {
            zkp_qualification: None,
            request_id: "vsp-req-1".into(),
            validator_name: "validator-alpha".into(),
            validator_id: "ab".repeat(32),
            proof_cap: "dmap".into(),
            carriers: vec!["email:alpha@vsp.test".into()],
            core_version: "Kyoto/1.1/GENESIS".into(),
            uptime_secs: 86_400,
            witness_count: 12_345,
            redeem_count: 6_789,
            zkp_qualified: true,
            known_validators: vec![hint(1), hint(2)],
            fee_rate_bps: 50,
            fee_valid_until: 1_800_000_000,
            fee_min_amount: 1_000,
            jurisdiction: "SG".into(),
            operator_name: "Alpha Ops".into(),
            operator_contact: "ops@vsp.test".into(),
            supported_encryption: "PGP".into(),
            encryption_public_key: "-----BEGIN PGP-----".into(),
            stake: 500_000_000_000,
            notes: "maintenance sundays".into(),
            digit_version: 2,
        }
    }

    fn cbor(v: &impl serde::Serialize) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    /// KI#179 / YP §27.11.2.2 — `query_data` IS the Core type, whole and under
    /// its own field names. Mutation (2026-10-01): re-introducing the hand-picked
    /// 9-field map with the `name` rename turns this red on the decode
    /// (`validator_name` missing).
    #[test]
    fn vsp_query_data_is_the_core_type() {
        let vsp = full_vsp();
        let reply = vsp_reply("vsp-req-1", &vsp).unwrap();
        assert!(reply.success);
        assert_eq!(reply.request_id, "vsp-req-1");
        let qd = reply.query_data.clone().expect("VSP reply carries query_data");
        let back: axiom_core_logic::types::ValidatorStatusResponse =
            qd.deserialized().expect("query_data decodes as the Core ValidatorStatusResponse");
        assert_eq!(cbor(&back), cbor(&vsp), "every field survives, byte for byte");
        // The §27.5 envelope channel repeats the peers (stated in the YP).
        assert_eq!(cbor(&reply.validator_hints), cbor(&vsp.known_validators));
        // And the whole reply round-trips through the envelope type the SDK decodes.
        let wire = cbor(&reply);
        let decoded: ResponsePayload = ciborium::from_reader(wire.as_slice()).unwrap();
        assert!(decoded.query_data.is_some());
    }

    /// KI#179 ruling A — the wallet `query` reply is a PRIVACY projection: an
    /// unauthenticated asker gets exactly these four fields and never
    /// `auth_hash` / `group_members` / `status` / `wallet_id`. Mutation
    /// (2026-10-01): adding `("auth_hash", …)` to the projection turns this red.
    #[test]
    fn wallet_query_projection_is_exactly_four_public_fields() {
        let s = axiom_core_logic::types::StoredWalletState {
            public_key: vec![9u8; 32],
            balance: 505,
            wallet_seq: 7,
            state_id: [3u8; 32],
            last_tx_id: Some([4u8; 32]),
            status: axiom_core_logic::types::WalletStateStatus::Pending,
            group_members: Some(vec![]),
            auth_hash: Some([5u8; 32]),
            wallet_id: Some("secret@vsp.test/0000000042".into()),
            hibernation_until: 11,
            wall_clock_lock: 12,
            emission_claimed_epoch: 13,
            stake_floor_until: 14,
            wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
        };
        let v = wallet_query_projection(&s).unwrap();
        let keys: Vec<String> = v.as_map().expect("a map").iter()
            .map(|(k, _)| k.as_text().expect("text key").to_string())
            .collect();
        assert_eq!(keys, ["balance", "public_key", "state_id", "wallet_seq"],
            "the query projection discloses exactly these fields (sorted)");
    }

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
            custody: None,
        }
    }

    // ── Inbox-funnel delivery (AXIOM_DESIGN_AntieInboxFunnel.md) ─────

    /// Mock pull carrier: returns a canned batch from check_new(), and
    /// records which message ids were marked processed / failed.
    struct MockPullCarrier {
        batch: Vec<crate::carrier::IncomingMessage>,
        processed: std::sync::Mutex<Vec<String>>,
        failed: std::sync::Mutex<Vec<String>>,
    }

    impl MockPullCarrier {
        fn new(msgs: &[(&str, &[u8])]) -> Self {
            let batch = msgs.iter().map(|(id, raw)| crate::carrier::IncomingMessage {
                id: (*id).to_string(),
                raw: raw.to_vec(),
                source: "mock".to_string(),
            }).collect();
            Self {
                batch,
                processed: std::sync::Mutex::new(vec![]),
                failed: std::sync::Mutex::new(vec![]),
            }
        }
    }

    #[async_trait::async_trait]
    impl MailCarrier for MockPullCarrier {
        fn name(&self) -> &str { "mock-pull" }
        async fn check_new(&self) -> Result<Vec<crate::carrier::IncomingMessage>, AntieError> {
            Ok(self.batch.clone())
        }
        async fn mark_processed(&self, id: &str) -> Result<(), AntieError> {
            self.processed.lock().unwrap().push(id.to_string());
            Ok(())
        }
        async fn mark_failed(&self, id: &str, _reason: &str) -> Result<(), AntieError> {
            self.failed.lock().unwrap().push(id.to_string());
            Ok(())
        }
        async fn send(&self, _to: &str, _raw: &[u8]) -> Result<(), AntieError> {
            Err(AntieError::ConfigError("mock cannot send".into()))
        }
    }

    /// A pull carrier writes each fetched message into inbox/new/ and DELEs it
    /// from the server — it never dispatches to Lambda itself. The Maildir
    /// carrier (elsewhere) is the sole reader of that inbox.
    #[tokio::test]
    async fn pull_carrier_delivers_into_inbox_and_marks_processed() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = crate::maildir::Maildir::open(dir.path()).await.unwrap();
        let carrier = MockPullCarrier::new(&[
            ("m1", b"raw-email-1"),
            ("m2", b"raw-email-2"),
        ]);

        let stats = crate::stats::AntieStats::new();
        Gateway::deliver_carrier_messages(&carrier, &inbox, None, &stats, None).await;
        assert!(stats.last_inbox_write_unix.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "KI#114: a pull-carrier inbox write stamps last_inbox_write_unix");

        // Both messages landed in inbox/new/ as distinct files.
        let n = std::fs::read_dir(dir.path().join("new")).unwrap().count();
        assert_eq!(n, 2, "both fetched messages written to inbox/new/");
        // Both were DELE'd from the server; none failed.
        assert_eq!(*carrier.processed.lock().unwrap(), vec!["m1", "m2"]);
        assert!(carrier.failed.lock().unwrap().is_empty());
    }

    /// KI#114 AS A TEST — alive process, live Lambda, a pull loop whose fetch
    /// NEVER returns. The REAL `pull_loop` runs under a paused clock; after the
    /// clock passes `PULL_MAX_SILENCE_SECS`, `/health` must answer `ok:false`
    /// naming the account. The pre-KI#114 endpoint (`ok = lambda_alive`)
    /// answered `ok:true` here — the 2026-08-26 picture. A healthy loop beside
    /// it (fetch returns, then the poll sleep beats in slices) stays fresh
    /// through the same advance — including a 30-min KI#141 backoff sleep.
    /// MUTATIONS (run 2026-10-01): `health_verdict` ignores heartbeats ⇒ red at
    /// "wedged ⇒ ok:false"; `sleep_beating` beats only once before sleeping
    /// the whole wait ⇒ red at "only the wedged loop" (the healthy one stalls too).
    #[tokio::test(start_paused = true)]
    async fn ki114_a_pull_loop_that_never_returns_flips_health_naming_it() {
        struct NeverReturns;
        #[async_trait::async_trait]
        impl MailCarrier for NeverReturns {
            fn name(&self) -> &str { "never" }
            async fn check_new(&self) -> Result<Vec<crate::carrier::IncomingMessage>, AntieError> {
                std::future::pending().await
            }
            async fn mark_processed(&self, _: &str) -> Result<(), AntieError> { Ok(()) }
            async fn mark_failed(&self, _: &str, _: &str) -> Result<(), AntieError> { Ok(()) }
            async fn send(&self, _: &str, _: &[u8]) -> Result<(), AntieError> { Ok(()) }
        }
        let stats = Arc::new(crate::stats::AntieStats::new());
        let running = Arc::new(RwLock::new(true));
        let dir = tempfile::tempdir().unwrap();
        let inbox = Arc::new(crate::maildir::Maildir::open(dir.path()).await.unwrap());

        let wedged_hb = stats.register_heartbeat("pop3#0(u@wedged)", PULL_MAX_SILENCE_SECS);
        let healthy_hb = stats.register_heartbeat("pop3#1(u@fine)", PULL_MAX_SILENCE_SECS);
        {
            let (stats, running, inbox) = (stats.clone(), running.clone(), inbox.clone());
            tokio::spawn(async move {
                Gateway::pull_loop(&NeverReturns, &inbox, None, std::time::Duration::from_secs(2),
                    &stats, &running, &wedged_hb).await;
            });
        }
        {
            let (stats, running, inbox) = (stats.clone(), running.clone(), inbox.clone());
            tokio::spawn(async move {
                // 30-min poll interval: the sleep itself must keep beating.
                Gateway::pull_loop(&MockPullCarrier::new(&[]), &inbox, None, CARRIER_BACKOFF_MAX,
                    &stats, &running, &healthy_hb).await;
            });
        }
        tokio::task::yield_now().await;
        let (v, body) = crate::health::health_body(&stats, true);
        assert!(v.ok, "at start every loop is fresh: {body}");

        tokio::time::sleep(std::time::Duration::from_secs(PULL_MAX_SILENCE_SECS + 5)).await;
        let (v, body) = crate::health::health_body(&stats, true);
        assert!(!v.ok, "wedged ⇒ ok:false even with Lambda alive: {body}");
        assert_eq!(v.stalled.len(), 1, "only the wedged loop: {body}");
        assert!(v.stalled[0].starts_with("pop3#0(u@wedged) "), "names it: {body}");
        assert!(body.contains("\"ok\":false") && body.contains("pop3#0(u@wedged)"), "on the wire: {body}");
        assert!(!body.contains("pop3#1(u@fine)"), "healthy stays fresh through its long sleep: {body}");
        *running.write().await = false;
    }

    // ── Message-type routing table ──────────────────────────────────

    /// Verify the email-based routing table dispatches all known message types.
    #[test]
    fn message_type_routing_known_types() {
        let known_types = [
            "witness", "redeem", "ack", "query", "validator_status",
            "init_genesis_dev", "vbc_sign_request", "vbc_sign_commit",
            "set_auth_hash", "peer_audit_request",
            "peer_audit_response", "fanout_relay",
        ];
        for msg_type in &known_types {
            let is_unknown = !matches!(
                *msg_type,
                "witness" | "redeem" | "ack" | "query" | "validator_status"
                    | "init_genesis_dev" | "vbc_sign_request" | "vbc_sign_commit"
                    | "set_auth_hash" | "peer_audit_request"
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
            sender_state: None,
            vbc_signature: None,
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
            sender_state: None,
            vbc_signature: None,
        };
        assert_eq!(error_payload.request_id, "req-001");
        assert_eq!(error_payload.rejection_code.as_deref(), Some("INTERNAL_ERROR"));
    }

    /// A Lambda VERDICT must reach the client with its own code + typed
    /// error_response — never flattened to INTERNAL_ERROR with the structure
    /// dropped. Regression for the 2026-07-27 fix: before it, every Lambda
    /// error became `LambdaError(String)` at the parse_*_response sites and was
    /// stamped INTERNAL_ERROR here, so a protocol refusal (E_INVALID_STATE_ID
    /// declining a double-spend) was indistinguishable from an ANTIE crash and
    /// recovery hints (ClaraHealNextSend) were lost. Clients dispatch on
    /// `error_response.code` (§"Phase 2 error stack"), so flattening breaks
    /// dispatch, not just cosmetics.
    #[test]
    fn lambda_verdict_is_forwarded_not_flattened() {
        use axiom_errors::{error_code, ErrorCategory, ErrorCode, ErrorResponse, RecoveryHint};

        // A typed rejection as Lambda would emit it.
        let verdict = ErrorResponse {
            code: ErrorCode::from_static(error_code::E_SABR_HASH_MISMATCH),
            category: ErrorCategory::RecoverableDrift,
            message: "Wallet state does not match validator's stored state".into(),
            detail: None,
            recovery: Some(RecoveryHint::ClaraHealNextSend),
            retry_after_secs: None,
            yp_reference: None,
            request_id: None,
            version: Default::default(),
        };
        let err = AntieError::LambdaRejected(verdict.clone());

        // The gateway's Err-branch mapping (mirrors process_message).
        let typed = match &err {
            AntieError::LambdaRejected(er) => Some(er.clone()),
            _ => None,
        };
        let code = match &typed {
            Some(er) => er.code.to_string(),
            None => "INTERNAL_ERROR".to_string(),
        };

        assert_ne!(code, "INTERNAL_ERROR", "Lambda verdict must not be flattened");
        assert_eq!(code, verdict.code.to_string());
        let fwd = typed.expect("typed error_response must be forwarded");
        assert_eq!(fwd.category, ErrorCategory::RecoverableDrift);
        assert_eq!(fwd.recovery, Some(RecoveryHint::ClaraHealNextSend),
                   "recovery hint must survive — the SDK dispatches heal on it");

        // Conversion must return Lambda's verdict UNCHANGED (no re-coding).
        let converted: ErrorResponse = (&err).into();
        assert_eq!(converted.code, verdict.code);
        assert_eq!(converted.recovery, verdict.recovery);

        // A genuine ANTIE-internal fault still maps to an ANTIE code.
        let internal = AntieError::CoreError("ipc blew up".into());
        let internal_typed = match &internal {
            AntieError::LambdaRejected(er) => Some(er.clone()),
            _ => None,
        };
        assert!(internal_typed.is_none(), "internal faults carry no Lambda verdict");
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
            sender_state: None,
            vbc_signature: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let decoded: ResponsePayload = serde_json::from_str(&json).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.request_id, "rt-42");
        assert_eq!(decoded.produced_state_id.unwrap().len(), 32);
        assert_eq!(decoded.commitment_hash.unwrap().len(), 32);
        assert_eq!(decoded.validator_hints.len(), 1);
    }

    // ── VBC sign messages use the Core wire types (KI#173) ──────────

    /// The certificate-sign request ANTIE sends IS Core's `GatewayRequest` variant: same
    /// discriminant Lambda dispatches on, and it decodes back into the Core payload.
    #[test]
    fn vbc_sign_request_is_the_core_gateway_variant() {
        use axiom_core_logic::types::{GatewayRequest, VBCSignRequestPayload};
        let req = GatewayRequest::VBCSignRequest(VBCSignRequestPayload {
            request_id: "vbc-1".into(), sphincs_pk_hex: "aa".into(), dilithium_pk_hex: "bb".into(),
            ed25519_pk_hex: "cc".into(), pgp_fingerprint_hex: "dd".into(), proof_cap: "dmap".into(), node_name: "n1".into(),
        });
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["type"], "vbc_sign_request");
        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor).unwrap();
        match ciborium::from_reader::<GatewayRequest, _>(cbor.as_slice()).unwrap() {
            GatewayRequest::VBCSignRequest(p) => assert_eq!(p.node_name, "n1"),
            _ => panic!("decoded as another variant"),
        }
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

#[cfg(test)]
mod busy_gate_tests {
    use super::busy_estimate_exceeds;

    const THRESHOLD: u64 = 15_000; // config default, ms

    /// ⚠ THE SELF-LOCK. An IDLE validator must accept work no matter how slow
    /// it once was.
    ///
    /// `avg_witness_ms` is a LIFETIME average and never decays, so a validator
    /// that served a few slow rounds reports a high number permanently. If an
    /// idle node rejects on that alone it can never take the fast samples that
    /// would clear it — the only exit is a restart.
    ///
    /// 40,000ms is the figure three ~70s CL8 certificate signs actually
    /// produced on the mesh (2026-09-04), against a 15,000ms threshold, while
    /// the validators were doing nothing.
    #[test]
    fn an_idle_validator_accepts_work_however_slow_it_once_was() {
        assert!(
            !busy_estimate_exceeds(0, 40_000, THRESHOLD),
            "an IDLE validator (queue_depth 0) has no backlog to shed and MUST \
             accept work — rejecting here is the self-lock: it refuses, so it \
             gets no fast samples, so its lifetime average never recovers",
        );
    }

    /// The gate must still fire on a real backlog — otherwise removing the
    /// self-lock would have removed the protection with it.
    #[test]
    fn a_real_backlog_is_still_shed() {
        // Eight queued rounds at a normal 5s each = 40s of work waiting.
        assert!(
            busy_estimate_exceeds(8, 5_000, THRESHOLD),
            "a genuine backlog MUST still be shed — the fix removes the \
             idle-node false positive, not the backpressure",
        );
    }

    /// The boundary is the spec's, not an approximation of it:
    /// `estimated_wait = queue_depth × avg_witness_ms` (YPX-015 §2.1).
    #[test]
    fn the_estimate_is_queue_depth_times_average() {
        // Exactly at the threshold is NOT over it.
        assert!(!busy_estimate_exceeds(3, 5_000, THRESHOLD));
        // One millisecond of average more, and it is.
        assert!(busy_estimate_exceeds(3, 5_001, THRESHOLD));
    }
}

#[cfg(test)]
mod ki141_backoff_tests {
    use super::*;
    use std::time::Duration;

    /// KI#141 — the schedule as a table: flat at zero failures, doubling per
    /// consecutive failure, capped at 30 minutes, never overflowing.
    #[test]
    fn carrier_backoff_doubles_and_caps() {
        let base = Duration::from_millis(5_000);
        assert_eq!(Gateway::carrier_backoff(base, 0), base, "a healthy carrier pays nothing");
        assert_eq!(Gateway::carrier_backoff(base, 1), Duration::from_millis(10_000));
        assert_eq!(Gateway::carrier_backoff(base, 3), Duration::from_millis(40_000));
        assert_eq!(Gateway::carrier_backoff(base, 9), CARRIER_BACKOFF_MAX, "5s * 2^9 = 42.7 min caps at 30 min");
        assert_eq!(Gateway::carrier_backoff(base, 60), CARRIER_BACKOFF_MAX, "no overflow past the cap");
        // 5.3 h at the old flat 5 s pace = ~3,800 attempts; capped doubling makes ~15.
        let mut t = Duration::ZERO; let mut n = 0u32;
        while t < Duration::from_secs(5 * 3600 + 18 * 60) { t += Gateway::carrier_backoff(base, n); n += 1; }
        assert!(n < 20, "capped backoff must make a blocked provider see a handful of attempts, saw {n}");
    }
}

#[cfg(test)]
mod stats_poll_tests {
    //! YPX-015 §2.1 AS BUILT (2026-09-26): a refused /stats read must be counted
    //! and loud, never read as "no data yet — allow through".
    use super::{answers_out_of_band, parse_avg_witness_ms, record_stats_poll};
    use crate::stats::AntieStats;
    use std::sync::atomic::Ordering;

    #[test]
    fn peer_audit_mail_gets_no_generic_reply_but_client_mail_does() {
        assert!(answers_out_of_band("peer_audit_request"));
        assert!(answers_out_of_band("peer_audit_response"));
        for t in ["witness", "redeem", "ack", "query", "fanout_relay", "vbc_sign_request"] {
            assert!(!answers_out_of_band(t), "{t} must still get its reply");
        }
    }

    #[test]
    fn parses_avg_witness_ms() {
        assert_eq!(parse_avg_witness_ms("{\"queue\":3,\"avg_witness_ms\": 1234,\"x\":1}"), Some(1234));
        assert_eq!(parse_avg_witness_ms("{\"avg_witness_ms\":7}"), Some(7));
        assert_eq!(parse_avg_witness_ms("{\"error\":\"unauthorized\"}"), None);
        assert_eq!(parse_avg_witness_ms("{\"avg_witness_ms\":\"n/a\"}"), None);
    }

    #[test]
    fn refused_read_is_counted_and_warned_first_and_every_100th() {
        let s = AntieStats::new();
        assert_eq!(record_stats_poll(&s, Err("HTTP 401".into())).as_deref(), Some("HTTP 401"));
        for _ in 2..100 { assert!(record_stats_poll(&s, Err("HTTP 401".into())).is_none()); }
        assert!(record_stats_poll(&s, Err("HTTP 401".into())).is_some(), "100th failure warns again");
        assert_eq!(s.lambda_stats_poll_failures.load(Ordering::Relaxed), 100);
        assert_eq!(s.avg_witness_ms.load(Ordering::Relaxed), 0, "a failure never invents load data");
    }

    #[test]
    fn good_read_stores_the_value() {
        let s = AntieStats::new();
        assert!(record_stats_poll(&s, Ok(850)).is_none());
        assert_eq!(s.avg_witness_ms.load(Ordering::Relaxed), 850);
        assert_eq!(s.lambda_stats_poll_failures.load(Ordering::Relaxed), 0);
    }
}
