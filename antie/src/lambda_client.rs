//! Lambda Client
//!
//! Gateway's interface to Lambda for business logic processing.
//!
//! Supports two modes:
//! - Subprocess (preferred): Spawns Lambda as child process, uses stdin/stdout
//! - TCP: Connects to remote Lambda server
//!
//! IMPORTANT: Gateway MUST validate via Core (CL2) BEFORE calling Lambda.
//! Lambda receives pre-validated transactions only.

use crate::error::AntieError;
use axiom_core_logic::types::GroupMember;
// KI#173 batch 4: the Lambda IPC envelopes are Core's — ANTIE keeps no copy.
use axiom_core_logic::types::{GatewayRequest, GatewayResponse};
// UMP: wire types live in axiom_core_logic. ANTIE imports them as aliases
// (LambdaWitnessResponse / LambdaRedeemResponse / OutboundPeerAuditInfo)
// for backward compat with internal callers, but the underlying type is
// the SAME definition Lambda uses. There is no ANTIE mirror struct —
// adding a field to the canonical type propagates to ANTIE automatically
// (CLAUDE.md §13 — closes the mirror-drift bug class structurally).
pub use axiom_core_logic::types::{
    WitnessResponse as LambdaWitnessResponse,
    RedeemResponse as LambdaRedeemResponse,
    OutboundPeerAudit as OutboundPeerAuditInfo,
    RejectionInfo,
    SetAuthHashResponse as LambdaSetAuthHashResponse,
    FanOutDedupResponse as LambdaFanOutDedupResponse,
    FanOutMarkResponse as LambdaFanOutMarkResponse,
    PeerAuditResultPayload as LambdaPeerAuditResult,
    AckResponse as LambdaAckResponse,
    InitGenesisResponse as LambdaGenesisResponse,
    StateQueryResponse as LambdaQueryResponse,
    StoredWalletState as LambdaWalletState,
    ValidatorStatusResponse as LambdaValidatorStatusResponse,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use std::process::Stdio;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info};

/// Encode a value to CBOR bytes for IPC (Yellow Paper §16.8.5.3 — CBOR everywhere)
fn ipc_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AntieError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| AntieError::LambdaError(format!("CBOR encode error: {}", e)))?;
    Ok(buf)
}

/// Decode CBOR bytes from IPC (Yellow Paper §16.8.5.3 — CBOR everywhere)
fn ipc_decode<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, AntieError> {
    ciborium::from_reader(data)
        .map_err(|e| AntieError::LambdaError(format!("CBOR decode error: {}", e)))
}

/// Lambda client for Gateway
pub struct LambdaClient {
    /// Connection mode
    mode: LambdaMode,
    /// KI#80: whether the lambda child is believed alive. Subprocess mode
    /// only — the supervision loop is the writer. TCP mode has no child to
    /// supervise and leaves this `true`.
    lambda_alive: Arc<AtomicBool>,
    /// KI#80: set by `stop()` so the supervision loop never respawns a
    /// child that was killed on purpose.
    shutting_down: Arc<AtomicBool>,
    /// KI#80: the carrier URI list last pushed via
    /// `send_set_carriers_request`, re-pushed to a respawned child.
    /// Lambda persists everything else it needs in its own storage; the
    /// carrier list is the one piece of boot-time state that only ANTIE
    /// holds (gateway.rs pushes it exactly once at startup).
    carrier_uris: Mutex<Option<Vec<String>>>,
}

/// Lambda connection mode
#[allow(clippy::large_enum_variant)]
enum LambdaMode {
    /// TCP connection to remote Lambda (optionally with TLS)
    Tcp {
        address: String,
        timeout: std::time::Duration,
        tls_connector: Option<tokio_rustls::TlsConnector>,
        tls_server_name: Option<rustls::pki_types::ServerName<'static>>,
    },
    /// Subprocess with stdin/stdout
    Subprocess {
        child: Mutex<Option<Child>>,
        binary_path: PathBuf,
        config_path: PathBuf,
    },
}

impl LambdaClient {
    /// Shared constructor body — every mode starts believed-alive and
    /// not shutting down.
    fn with_mode(mode: LambdaMode) -> Self {
        Self {
            mode,
            lambda_alive: Arc::new(AtomicBool::new(true)),
            shutting_down: Arc::new(AtomicBool::new(false)),
            carrier_uris: Mutex::new(None),
        }
    }

    /// Create Lambda client in TCP mode
    pub fn new_tcp(address: &str, timeout_secs: u64) -> Self {
        Self::with_mode(LambdaMode::Tcp {
            address: address.to_string(),
            timeout: std::time::Duration::from_secs(timeout_secs),
            tls_connector: None,
            tls_server_name: None,
        })
    }

    pub fn new_tcp_tls(
        address: &str,
        timeout_secs: u64,
        server_name: &str,
        ca_cert_path: Option<&str>,
    ) -> Result<Self, AntieError> {
        let mut root_store = rustls::RootCertStore::empty();
        if let Some(ca_path) = ca_cert_path {
            let file = std::fs::File::open(ca_path)
                .map_err(|e| AntieError::ConfigError(format!("TLS CA cert {ca_path}: {e}")))?;
            let mut reader = std::io::BufReader::new(file);
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|e| AntieError::ConfigError(format!("TLS CA parse: {e}")))?;
                root_store.add(cert)
                    .map_err(|e| AntieError::ConfigError(format!("TLS CA add: {e}")))?;
            }
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let sni = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| AntieError::ConfigError(format!("TLS server name '{server_name}': {e}")))?;
        Ok(Self::with_mode(LambdaMode::Tcp {
            address: address.to_string(),
            timeout: std::time::Duration::from_secs(timeout_secs),
            tls_connector: Some(connector),
            tls_server_name: Some(sni),
        }))
    }

    /// Create Lambda client in subprocess mode (preferred)
    pub fn new_subprocess(binary_path: PathBuf, config_path: PathBuf) -> Self {
        Self::with_mode(LambdaMode::Subprocess {
            child: Mutex::new(None),
            binary_path,
            config_path,
        })
    }
    
    /// Create from config
    pub fn from_config(config: &LambdaClientConfig) -> Self {
        match &config.mode {
            LambdaConnectionMode::Tcp { address, timeout_secs } => {
                Self::new_tcp(address, *timeout_secs)
            }
            LambdaConnectionMode::Subprocess { binary_path, config_path } => {
                Self::new_subprocess(binary_path.clone(), config_path.clone())
            }
        }
    }
    
    /// Start Lambda subprocess (if in subprocess mode)
    pub async fn start(&self) -> Result<(), AntieError> {
        if let LambdaMode::Subprocess { child, binary_path, config_path } = &self.mode {
            let mut guard = child.lock().await;
            if guard.is_some() {
                return Ok(()); // Already running
            }
            Self::spawn_child_into(&mut *guard, binary_path, config_path)?;
            self.lambda_alive.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Spawn the lambda child into `guard`. Factored out of `start()` so
    /// the KI#80 supervision loop respawns through the SAME path (log
    /// sink discovery included) instead of a copy.
    fn spawn_child_into(
        guard: &mut Option<Child>,
        binary_path: &PathBuf,
        config_path: &PathBuf,
    ) -> Result<(), AntieError> {
        info!("Starting Lambda subprocess: {:?}", binary_path);
        info!("  Config: {:?}", config_path);
        {
            // Pipe Lambda's stderr to a dedicated `lambda.log` file
            // alongside antie.log. Pre-fix, this was `Stdio::inherit()`,
            // which on paper inherits ANTIE's redirected fd 2 — but in
            // practice it produced silent INTERNAL_ERROR cascades on
            // smoke startup (CLAUDE.md "Outstanding" #1, ~10% smoke
            // success rate). Lambda's panics + tracing went somewhere
            // unreachable: when ANTIE was launched under tokio with
            // its own stderr redirected to antie.log by the parent
            // axiom-env.py, Lambda's inherited fd 2 didn't always
            // reach the same file (re-redirects, buffering, daemon-
            // style fd-table reset, depending on host). A dedicated
            // log file with the env-var override gives us:
            //   1. A guaranteed sink (this open + Stdio::from(...)).
            //   2. A predictable path operators can `tail -f`.
            //   3. Separation of ANTIE vs Lambda diagnostics.
            //
            // Discovery order (axiom-env.py sets the env var; ANTIE
            // falls back to a path next to the config file otherwise):
            //   1. $AXIOM_LAMBDA_LOG (explicit)
            //   2. <config_path's dir>/../logs/lambda.log
            //   3. <cwd>/lambda.log
            let lambda_log_path = if let Ok(p) = std::env::var("AXIOM_LAMBDA_LOG") {
                std::path::PathBuf::from(p)
            } else {
                config_path.parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.join("logs").join("lambda.log"))
                    .unwrap_or_else(|| std::path::PathBuf::from("lambda.log"))
            };
            if let Some(parent) = lambda_log_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let lambda_log = std::fs::OpenOptions::new()
                .create(true).append(true)
                .open(&lambda_log_path)
                .map_err(|e| AntieError::LambdaError(format!(
                    "Failed to open Lambda log {:?}: {}", lambda_log_path, e,
                )))?;
            let lambda_log_stderr = lambda_log
                .try_clone()
                .map_err(|e| AntieError::LambdaError(format!(
                    "Failed to clone Lambda log fd: {}", e,
                )))?;
            info!("Lambda stderr → {:?}", lambda_log_path);

            // NOTE: Don't pass --stdio, the default (no --listen, no --stdio) is stdio-framed
            // which uses length-prefixed frames matching our protocol
            let process = Command::new(binary_path)
                .arg("--config")
                .arg(config_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::from(lambda_log_stderr))
                .spawn()
                .map_err(|e| AntieError::LambdaError(format!("Failed to spawn Lambda: {}", e)))?;

            *guard = Some(process);
            info!("Lambda subprocess started");
        }
        Ok(())
    }

    /// Stop Lambda subprocess
    pub async fn stop(&self) -> Result<(), AntieError> {
        // KI#80: mark the shutdown as deliberate BEFORE killing, so the
        // supervision loop never races us into respawning the child we
        // are about to kill.
        self.shutting_down.store(true, Ordering::SeqCst);
        if let LambdaMode::Subprocess { child, .. } = &self.mode {
            let mut guard = child.lock().await;
            if let Some(mut process) = guard.take() {
                info!("Stopping Lambda subprocess");
                let _ = process.kill().await;
            }
        }
        Ok(())
    }

    /// KI#80: handle to the liveness flag, for the /health endpoint.
    pub fn lambda_alive_handle(&self) -> Arc<AtomicBool> {
        self.lambda_alive.clone()
    }

    /// KI#80: supervise the lambda child — detect exit, reap the corpse,
    /// respawn with backoff, re-push the carrier list.
    ///
    /// Before this loop existed, an OOM-killed lambda left antie holding a
    /// stale handle to a zombie: every IPC call returned `Broken pipe`, the
    /// unreaped corpse kept `pgrep | wc -l` reading full-strength, and the
    /// validator was a black hole until a human rolled it (gamma 28 min,
    /// zeta 13 min, 2026-08-08 soak). A process dying is survivable; a
    /// supervisor that never notices is not.
    ///
    /// Backoff is bounded in RATE, not in attempts: 1s doubling to a 60s
    /// cap, reset once a child survives `RESPAWN_STABLE_SECS`. Giving up
    /// permanently after N attempts would recreate the outage this exists
    /// to close (an OOM storm in hour 1 would kill the validator for the
    /// rest of the run) — instead a persistently-dying child costs one
    /// spawn per minute, stays ERROR-loud, and reads `lambda_alive: false`
    /// on /health throughout.
    ///
    /// TCP mode returns immediately: there is no child to supervise.
    pub async fn supervision_loop(&self) {
        let (child, binary_path, config_path) = match &self.mode {
            LambdaMode::Subprocess { child, binary_path, config_path } =>
                (child, binary_path, config_path),
            LambdaMode::Tcp { .. } => return,
        };

        /// How often the child is checked for having exited.
        const RESPAWN_POLL_SECS: u64 = 2;
        /// First respawn delay after a death.
        const RESPAWN_BACKOFF_MIN_SECS: u64 = 1;
        /// Backoff ceiling — a persistently-dying child costs one spawn
        /// attempt per minute, never a hot loop.
        const RESPAWN_BACKOFF_MAX_SECS: u64 = 60;
        /// A child that survives this long resets the backoff.
        const RESPAWN_STABLE_SECS: u64 = 60;

        let mut backoff_secs = RESPAWN_BACKOFF_MIN_SECS;
        let mut last_spawn = std::time::Instant::now();

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(RESPAWN_POLL_SECS)).await;
            if self.shutting_down.load(Ordering::SeqCst) {
                return;
            }

            // Check (and reap — try_wait waits on an exited child, so the
            // zombie that fooled every `pgrep` count disappears here).
            let needs_spawn = {
                let mut guard = child.lock().await;
                match guard.as_mut() {
                    None => true, // stop() then start() race, or a failed respawn
                    Some(process) => match process.try_wait() {
                        Ok(Some(status)) => {
                            tracing::error!(
                                "[KI#80] lambda child EXITED (status: {status}) — \
                                 reaped; will respawn in {backoff_secs}s",
                            );
                            *guard = None;
                            true
                        }
                        Ok(None) => false,
                        Err(e) => {
                            tracing::error!("[KI#80] lambda child try_wait failed: {e}");
                            false
                        }
                    },
                }
            };

            if !needs_spawn {
                self.lambda_alive.store(true, Ordering::SeqCst);
                if last_spawn.elapsed().as_secs() >= RESPAWN_STABLE_SECS {
                    backoff_secs = RESPAWN_BACKOFF_MIN_SECS;
                }
                continue;
            }

            self.lambda_alive.store(false, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            if self.shutting_down.load(Ordering::SeqCst) {
                return;
            }

            {
                let mut guard = child.lock().await;
                if guard.is_none() {
                    match Self::spawn_child_into(&mut *guard, binary_path, config_path) {
                        Ok(()) => {
                            drop(guard);
                            last_spawn = std::time::Instant::now();
                            self.lambda_alive.store(true, Ordering::SeqCst);
                            tracing::warn!("[KI#80] lambda child RESPAWNED");
                            // Re-push the carrier list the gateway pushed at
                            // startup — the one boot-time input lambda does
                            // not recover from its own storage. Without it a
                            // respawned lambda serves VSP with the hardcoded
                            // placeholder and peers cannot route here.
                            let uris = self.carrier_uris.lock().await.clone();
                            if let Some(uris) = uris {
                                let rid = format!("set-carriers-respawn-{}", std::process::id());
                                match self.send_set_carriers_request(&rid, uris).await {
                                    Ok(ack) => tracing::warn!(
                                        "[KI#80] re-pushed {} carrier URI(s) to respawned lambda",
                                        ack.accepted,
                                    ),
                                    Err(e) => tracing::error!(
                                        "[KI#80] set_carriers re-push to respawned lambda \
                                         failed: {e} — VSP will report empty carriers",
                                    ),
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("[KI#80] lambda respawn FAILED: {e}");
                        }
                    }
                }
            }
            backoff_secs = (backoff_secs * 2).min(RESPAWN_BACKOFF_MAX_SECS);
        }
    }
    
    /// Send witness request to Lambda
    ///
    /// PRECONDITION: Transaction has ALREADY been validated by Core (CL2).
    /// Gateway is responsible for calling Core before this.
    pub async fn send_witness_request(
        &self,
        request: &axiom_core_logic::types::WitnessRequest,
    ) -> Result<LambdaWitnessResponse, AntieError> {
        // Wrap canonical request in the GatewayRequest envelope. Serde's
        // `tag = "type"` adds the `"witness"` discriminant on the wire.
        let envelope = axiom_core_logic::types::GatewayRequest::Witness(request.clone());
        match &self.mode {
            LambdaMode::Tcp { address, timeout, tls_connector, tls_server_name } => {
                debug!("Sending witness request to Lambda at {}", address);

                let stream = tokio::time::timeout(
                    *timeout,
                    TcpStream::connect(address)
                ).await
                    .map_err(|_| AntieError::LambdaError("Connection timeout".into()))?
                    .map_err(|e| AntieError::LambdaError(format!("Connect failed: {}", e)))?;

                if let (Some(connector), Some(sni)) = (tls_connector, tls_server_name) {
                    let tls_stream = connector.connect(sni.clone(), stream).await
                        .map_err(|e| AntieError::LambdaError(format!("TLS handshake: {}", e)))?;
                    self.send_request_framed(tls_stream, &envelope).await
                } else {
                    self.send_request_framed(stream, &envelope).await
                }
            }
            LambdaMode::Subprocess { child, .. } => {
                debug!("Sending witness request to Lambda subprocess");
                self.send_witness_request_stdio(child, &envelope, &request.request_id).await
            }
        }
    }
    
    /// Send redeem request to Lambda (6-validator model)
    ///
    /// Receiver brings ChequeBundle to their validators for redemption.
    pub async fn send_redeem_request(
        &self,
        request: &axiom_core_logic::types::RedeemRequestEnvelope,
    ) -> Result<LambdaRedeemResponse, AntieError> {
        let envelope = axiom_core_logic::types::GatewayRequest::Redeem(request.clone());
        match &self.mode {
            LambdaMode::Tcp { address, timeout, .. } => {
                debug!("Sending redeem request to Lambda at {}", address);

                let stream = tokio::time::timeout(
                    *timeout,
                    TcpStream::connect(address)
                ).await
                    .map_err(|_| AntieError::LambdaError("Connection timeout".into()))?
                    .map_err(|e| AntieError::LambdaError(format!("Connect failed: {}", e)))?;

                self.send_redeem_request_tcp(stream, &envelope).await
            }
            LambdaMode::Subprocess { child, .. } => {
                debug!("Sending redeem request to Lambda subprocess");
                self.send_redeem_request_stdio(child, &envelope).await
            }
        }
    }
    
    /// Send ACK request to Lambda
    pub async fn send_ack_request(
        &self,
        request: &axiom_core_logic::types::AckRequest,
    ) -> Result<LambdaAckResponse, AntieError> {
        let envelope = axiom_core_logic::types::GatewayRequest::Ack(request.clone());
        match &self.mode {
            LambdaMode::Tcp { address, timeout, .. } => {
                debug!("Sending ACK to Lambda at {}", address);

                let stream = tokio::time::timeout(
                    *timeout,
                    TcpStream::connect(address)
                ).await
                    .map_err(|_| AntieError::LambdaError("Connection timeout".into()))?
                    .map_err(|e| AntieError::LambdaError(format!("Connect failed: {}", e)))?;

                self.send_ack_request_tcp(stream, &envelope).await
            }
            LambdaMode::Subprocess { child, .. } => {
                debug!("Sending ACK to Lambda subprocess");
                self.send_ack_request_stdio(child, &envelope).await
            }
        }
    }
    
    /// Send genesis dev request to Lambda (DEV/TEST ONLY)
    pub async fn send_genesis_dev_request(
        &self,
        request_id: &str,
        public_key: &[u8],
        balance: u64,
        group_members: Option<Vec<GroupMember>>,
        auth_hash: Option<Vec<u8>>,
    ) -> Result<LambdaGenesisResponse, AntieError> {
        let request = axiom_core_logic::types::GatewayRequest::InitGenesis(
            axiom_core_logic::types::InitGenesisRequest {
                request_id: request_id.to_string(),
                public_key: public_key.to_vec(),
                balance,
                group_members,
                auth_hash,
            }
        );
        
        match &self.mode {
            LambdaMode::Tcp { address, timeout, .. } => {
                debug!("Sending genesis request to Lambda at {}", address);
                
                let stream = tokio::time::timeout(
                    *timeout,
                    TcpStream::connect(address)
                ).await
                    .map_err(|_| AntieError::LambdaError("Connection timeout".into()))?
                    .map_err(|e| AntieError::LambdaError(format!("Connect failed: {}", e)))?;
                
                self.send_genesis_request_tcp(stream, &request).await
            }
            LambdaMode::Subprocess { child, .. } => {
                debug!("Sending genesis request to Lambda subprocess");
                self.send_genesis_request_stdio(child, &request).await
            }
        }
    }
    
    /// §4.5: Send set_auth_hash request to Lambda.
    /// Sets `auth_hash` on a wallet. NOT stolen-key protection — the owner key
    /// is derived from the wallet private key, so it proves what `client_sig`
    /// already proves (KI#108). Unauthenticated on this path (KI#107).
    /// Phase 1 multi-carrier discovery (YP §27.5.2, 2026-05-14).
    ///
    /// Push the operator's configured `[carriers.*]` set to Lambda as a
    /// canonical YP §27.5.2 URI list (`tcp:H:P`, `ws:H:P`, `email:<addr>`).
    /// Called once at gateway startup. Lambda stores the list and emits
    /// it through `validator_status` (VSP) so peers and clients can
    /// discover all supported routing channels.
    ///
    /// Empty list is permitted but Lambda logs a loud warning so the
    /// operator notices the misconfig at startup.
    pub async fn send_set_carriers_request(
        &self,
        request_id: &str,
        carriers: Vec<String>,
    ) -> Result<axiom_core_logic::types::SetCarriersAck, AntieError> {
        // KI#80: remember the list so the supervision loop can re-push it
        // to a respawned child. Cached even if this send fails — the
        // respawn re-push is then the retry.
        *self.carrier_uris.lock().await = Some(carriers.clone());
        let envelope = axiom_core_logic::types::GatewayRequest::SetCarriers(
            axiom_core_logic::types::SetCarriersRequest {
                request_id: request_id.to_string(),
                carriers,
            },
        );
        let response_bytes = self.send_raw_request(&envelope).await?;
        let response: GatewayResponse = ipc_decode(&response_bytes)?;
        match response {
            GatewayResponse::SetCarriersAck(ack) => Ok(ack),
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError(
                "Unexpected response type for set_carriers".into(),
            )),
        }
    }

    /// ValidatorJoin §5 Phase 1 (KI#173) — the Core `GatewayRequest::VBCSignRequest`, decoded as
    /// the Core `GatewayResponse`. The hand-rolled request/response copies that stood in the
    /// gateway read the approval as a failure (no `success` field on `VBCSignApprovalResponse`).
    pub async fn send_vbc_sign_request(
        &self,
        payload: axiom_core_logic::types::VBCSignRequestPayload,
    ) -> Result<axiom_core_logic::types::VBCSignApprovalResponse, AntieError> {
        let response_bytes = self.send_raw_request(&GatewayRequest::VBCSignRequest(payload)).await?;
        match ipc_decode::<GatewayResponse>(&response_bytes)? {
            GatewayResponse::VBCSignApprovalResult(r) => Ok(r),
            GatewayResponse::Error(env) => Err(AntieError::LambdaRejected(env.error_response)),
            _ => Err(AntieError::LambdaError("Unexpected response type for vbc_sign_request".into())),
        }
    }

    /// ValidatorJoin §5 Phase 2 (KI#173) — the Core `GatewayRequest::VBCSignCommit`.
    pub async fn send_vbc_sign_commit(
        &self,
        payload: axiom_core_logic::types::VBCSignCommitPayload,
    ) -> Result<axiom_core_logic::types::VBCSignCommitResponse, AntieError> {
        let response_bytes = self.send_raw_request(&GatewayRequest::VBCSignCommit(payload)).await?;
        match ipc_decode::<GatewayResponse>(&response_bytes)? {
            GatewayResponse::VBCSignCommitResult(r) => Ok(r),
            GatewayResponse::Error(env) => Err(AntieError::LambdaRejected(env.error_response)),
            _ => Err(AntieError::LambdaError("Unexpected response type for vbc_sign_commit".into())),
        }
    }

    pub async fn send_set_auth_hash_request(
        &self,
        request_id: &str,
        public_key: &[u8],
        auth_hash: &[u8],
    ) -> Result<LambdaSetAuthHashResponse, AntieError> {
        let request = GatewayRequest::SetAuthHash(axiom_core_logic::types::SetAuthHashRequest {
            request_id: request_id.to_string(),
            public_key: public_key.to_vec(),
            auth_hash: auth_hash.to_vec(),
        });

        let response_bytes = self.send_raw_request(&request).await?;
        let response: GatewayResponse = ipc_decode(&response_bytes)?;

        match response {
            GatewayResponse::SetAuthHashResult(result) => Ok(result),
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for set_auth_hash".into())),
        }
    }

    /// Check Fan-Out dedup via Lambda's persistent storage (READ-ONLY).
    /// Returns true if diffusion_id was already seen (duplicate — drop it).
    /// Does NOT mark — call send_fanout_mark after CL10 acceptance.
    pub async fn send_fanout_dedup(
        &self,
        diffusion_id: &[u8; 32],
    ) -> Result<bool, AntieError> {
        let request = GatewayRequest::FanOutDedup(axiom_core_logic::types::FanOutDedupRequest {
            request_id: format!("dedup-{}", hex::encode(&diffusion_id[..8])),
            diffusion_id: diffusion_id.to_vec(),
        });

        let response_bytes = self.send_raw_request(&request).await?;
        let response: GatewayResponse = ipc_decode(&response_bytes)?;

        match response {
            GatewayResponse::FanOutDedupResult(result) => Ok(result.already_seen),
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for fanout_dedup".into())),
        }
    }

    /// Mark Fan-Out diffusion_id as seen in Lambda's persistent storage.
    /// Called AFTER CL10 verification succeeds. Prevents dedup poisoning
    /// by invalid/forged messages (only CL10-verified messages get marked).
    pub async fn send_fanout_mark(
        &self,
        diffusion_id: &[u8; 32],
    ) -> Result<(), AntieError> {
        let request = GatewayRequest::FanOutMark(axiom_core_logic::types::FanOutMarkRequest {
            request_id: format!("mark-{}", hex::encode(&diffusion_id[..8])),
            diffusion_id: diffusion_id.to_vec(),
        });

        let response_bytes = self.send_raw_request(&request).await?;
        let response: GatewayResponse = ipc_decode(&response_bytes)?;

        match response {
            GatewayResponse::FanOutMarkResult(_) => Ok(()),
            GatewayResponse::Error(env) => Err(AntieError::LambdaRejected(env.error_response)),
            _ => Err(AntieError::LambdaError("Unexpected response for fanout_mark".into())),
        }
    }

    /// §23.14.6: Send inbound peer audit request to Lambda for processing.
    /// Lambda looks up the txid in its DB, feeds raw data to Core for hash verification.
    /// Returns a PeerAuditResponse (computed hash) to send back to the requester.
    pub async fn send_peer_audit_request(
        &self,
        request: &axiom_core_logic::types::PeerAuditRequest,
    ) -> Result<LambdaPeerAuditResult, AntieError> {
        let ipc_request = axiom_core_logic::types::GatewayRequest::PeerAuditRequest(
            axiom_core_logic::types::PeerAuditRequestEnvelope {
                request_id: uuid::Uuid::new_v4().to_string(),
                peer_audit_request: request.clone(),
            }
        );

        let response_bytes = self.send_raw_request(&ipc_request).await?;
        let response: GatewayResponse = ipc_decode(&response_bytes)?;

        match response {
            GatewayResponse::PeerAuditResult(result) => Ok(result),
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for peer_audit_request".into())),
        }
    }

    /// §23.14.3: tell Lambda our carrier failed to send its peer-audit request,
    /// so it un-marks the dispatch (B is not timed) and retries on the next witness.
    pub async fn send_peer_audit_dispatch_failed(&self, target_email: &str, error: &str) -> Result<(), AntieError> {
        let ipc_request = axiom_core_logic::types::GatewayRequest::PeerAuditDispatchFailed(
            axiom_core_logic::types::PeerAuditDispatchFailedEnvelope {
                request_id: uuid::Uuid::new_v4().to_string(),
                target_email: target_email.to_string(),
                error: error.to_string(),
            }
        );
        let response_bytes = self.send_raw_request(&ipc_request).await?;
        let _response: GatewayResponse = ipc_decode(&response_bytes)?;
        Ok(())
    }

    /// §23.14.6 (KI#213): forward the audited validator's signed NotHeld to
    /// Lambda — an ANSWER to our pending audit (clears it, or bans a proven
    /// co-witness), never silence.
    pub async fn send_peer_audit_not_held(
        &self,
        not_held: &axiom_core_logic::types::PeerAuditNotHeld,
    ) -> Result<(), AntieError> {
        let ipc_request = axiom_core_logic::types::GatewayRequest::PeerAuditNotHeld(
            axiom_core_logic::types::PeerAuditNotHeldEnvelope {
                request_id: uuid::Uuid::new_v4().to_string(),
                peer_audit_not_held: not_held.clone(),
            }
        );

        let response_bytes = self.send_raw_request(&ipc_request).await?;
        let _response: GatewayResponse = ipc_decode(&response_bytes)?;
        Ok(())
    }

    /// §23.14.6: Send inbound peer audit response to Lambda for verification.
    /// Lambda passes it to Core (AVM) to compare against expected hash.
    /// If mismatch → ban. If match → clear pending audit.
    pub async fn send_peer_audit_response(
        &self,
        response: &axiom_core_logic::types::PeerAuditResponse,
    ) -> Result<(), AntieError> {
        let ipc_request = axiom_core_logic::types::GatewayRequest::PeerAuditResponse(
            axiom_core_logic::types::PeerAuditResponseEnvelope {
                request_id: uuid::Uuid::new_v4().to_string(),
                peer_audit_response: response.clone(),
            }
        );

        let response_bytes = self.send_raw_request(&ipc_request).await?;
        let _response: GatewayResponse = ipc_decode(&response_bytes)?;
        Ok(())
    }

    /// Send query request to Lambda for wallet state lookup
    pub async fn send_query_request(
        &self,
        wallet_pk: &[u8],
    ) -> Result<LambdaQueryResponse, AntieError> {
        // Wrap in canonical GatewayRequest envelope; serde tag adds the
        // "type": "query_state" discriminant on the wire.
        let request = axiom_core_logic::types::GatewayRequest::QueryState(
            axiom_core_logic::types::StateQueryRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                wallet_pk: wallet_pk.to_vec(),
            }
        );

        let response_bytes = self.send_raw_request(&request).await?;
        let response: GatewayResponse = ipc_decode(&response_bytes)?;

        match response {
            GatewayResponse::StateResult(qr) => Ok(qr),
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for query".into())),
        }
    }

    /// Send VSP (Validator Status Protocol) request to Lambda.
    /// Free service, no authentication required.
    pub async fn send_validator_status_request(
        &self,
        request_id: &str,
    ) -> Result<LambdaValidatorStatusResponse, AntieError> {
        let request = GatewayRequest::ValidatorStatus(axiom_core_logic::types::ValidatorStatusRequest {
            request_id: request_id.to_string(),
        });

        let response_bytes = self.send_raw_request(&request).await?;
        let response: GatewayResponse = ipc_decode(&response_bytes)?;

        match response {
            GatewayResponse::ValidatorStatusResult(vsp) => Ok(vsp),
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for VSP".into())),
        }
    }

    /// Send any serializable request to Lambda and return raw response bytes
    /// Used for VBC signing and other extensible request types
    pub async fn send_raw_request<T: serde::Serialize>(
        &self,
        request: &T,
    ) -> Result<Vec<u8>, AntieError> {
        let ipc_buf = ipc_encode(request)?;
        
        match &self.mode {
            LambdaMode::Tcp { address, timeout, .. } => {
                let stream = tokio::time::timeout(
                    *timeout,
                    TcpStream::connect(address)
                ).await
                    .map_err(|_| AntieError::LambdaError("Connection timeout".into()))?
                    .map_err(|e| AntieError::LambdaError(format!("Connect failed: {}", e)))?;
                
                let (mut reader, mut writer) = stream.into_split();
                
                let len = (ipc_buf.len() as u32).to_be_bytes();
                writer.write_all(&len).await?;
                writer.write_all(&ipc_buf).await?;
                writer.flush().await?;
                
                let mut len_buf = [0u8; 4];
                reader.read_exact(&mut len_buf).await?;
                let response_len = u32::from_be_bytes(len_buf) as usize;
                if response_len > 10 * 1024 * 1024 {
                    return Err(AntieError::LambdaError("Response too large".into()));
                }
                let mut response_buf = vec![0u8; response_len];
                reader.read_exact(&mut response_buf).await?;
                Ok(response_buf)
            }
            LambdaMode::Subprocess { child, .. } => {
                let mut guard = child.lock().await;
                let process = guard.as_mut()
                    .ok_or_else(|| AntieError::LambdaError("Lambda subprocess not running".into()))?;

                let stdin = process.stdin.as_mut()
                    .ok_or_else(|| AntieError::LambdaError("No stdin".into()))?;
                let stdout = process.stdout.as_mut()
                    .ok_or_else(|| AntieError::LambdaError("No stdout".into()))?;

                let len = (ipc_buf.len() as u32).to_be_bytes();
                stdin.write_all(&len).await?;
                stdin.write_all(&ipc_buf).await?;
                stdin.flush().await?;

                // Timeout on subprocess response (prevents hung Lambda from blocking Gateway)
                let read_future = async {
                    let mut len_buf = [0u8; 4];
                    stdout.read_exact(&mut len_buf).await?;
                    let response_len = u32::from_be_bytes(len_buf) as usize;
                    if response_len > 10 * 1024 * 1024 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData, "Response too large"));
                    }
                    let mut response_buf = vec![0u8; response_len];
                    stdout.read_exact(&mut response_buf).await?;
                    Ok(response_buf)
                };

                // 300s (was 30s): a timeout here does NOT cancel the child's
                // late response — the frame stays in the pipe and every later
                // call reads its predecessor's response ("Unexpected response
                // type", permanent desync). Observed live 2026-07-07: Lambda's
                // boot-time WAL recovery on a retained lambda.db took 31s, the
                // startup set_carriers timed out at 30s, and the whole
                // validator pair's IPC was off-by-one until restart. A slow
                // child must be WAITED OUT, not abandoned mid-frame; 300s
                // bounds a true hang. Proper fix (follow-up): correlation IDs
                // on the stdio frames, or kill+respawn the child on timeout.
                match tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    read_future,
                ).await {
                    Ok(result) => result.map_err(|e| AntieError::LambdaError(
                        format!("Subprocess read error: {}", e))),
                    Err(_) => Err(AntieError::LambdaError(
                        "Lambda subprocess response timeout (300s) — pipe state now                          suspect, restart this validator pair".into())),
                }
            }
        }
    }
    
    /// Send witness request over TCP stream
    async fn send_request_framed<S: AsyncReadExt + AsyncWriteExt + Unpin, T: serde::Serialize>(
        &self,
        mut stream: S,
        request: &T,
    ) -> Result<LambdaWitnessResponse, AntieError> {
        let buf = ipc_encode(request)?;
        let len = (buf.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        debug!("Sent {} bytes to Lambda", buf.len());
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        if response_len > 10 * 1024 * 1024 {
            return Err(AntieError::LambdaError("Response too large".into()));
        }
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await?;
        debug!("Received {} bytes from Lambda", response_len);
        self.parse_witness_response(&response_buf)
    }

    #[allow(dead_code)]
    async fn send_witness_request_tcp<T: serde::Serialize>(
        &self,
        mut stream: TcpStream,
        request: &T,
    ) -> Result<LambdaWitnessResponse, AntieError> {
        // Serialize request
        let buf = ipc_encode(request)?;
        
        // Send frame: 4-byte length + payload
        let len = (buf.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        
        debug!("Sent {} bytes to Lambda (TCP)", buf.len());
        
        // Read response frame
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        if response_len > 10 * 1024 * 1024 {
            return Err(AntieError::LambdaError("Response too large".into()));
        }
        
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await?;
        
        debug!("Received {} bytes from Lambda (TCP)", response_len);
        
        self.parse_witness_response(&response_buf)
    }
    
    /// Send witness request over stdio (subprocess mode)
    async fn send_witness_request_stdio<T: serde::Serialize>(
        &self,
        child: &Mutex<Option<Child>>,
        request: &T,
        request_id: &str,
    ) -> Result<LambdaWitnessResponse, AntieError> {
        let ipc_start = std::time::Instant::now();
        let mut guard = child.lock().await;
        eprintln!("[IPC_TIMING] {} lock: {:?}", request_id, ipc_start.elapsed());
        let process = guard.as_mut()
            .ok_or_else(|| AntieError::LambdaError("Lambda subprocess not running".into()))?;

        let stdin = process.stdin.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdin".into()))?;
        let stdout = process.stdout.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdout".into()))?;

        // Serialize request
        let buf = ipc_encode(request)?;
        eprintln!("[IPC_TIMING] {} encode({}bytes): {:?}", request_id, buf.len(), ipc_start.elapsed());

        // Send frame: 4-byte length + payload
        let len = (buf.len() as u32).to_be_bytes();
        stdin.write_all(&len).await?;
        stdin.write_all(&buf).await?;
        stdin.flush().await?;
        eprintln!("[IPC_TIMING] {} write_done: {:?}", request_id, ipc_start.elapsed());
        
        debug!("Sent {} bytes to Lambda (stdio)", buf.len());
        
        // Read response frame
        let mut len_buf = [0u8; 4];
        stdout.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        eprintln!("[IPC_TIMING] {} read_len({}): {:?}", request_id, response_len, ipc_start.elapsed());
        
        if response_len > 10 * 1024 * 1024 {
            return Err(AntieError::LambdaError("Response too large".into()));
        }
        
        let mut response_buf = vec![0u8; response_len];
        stdout.read_exact(&mut response_buf).await?;
        eprintln!("[IPC_TIMING] {} read_done: {:?}", request_id, ipc_start.elapsed());
        
        debug!("Received {} bytes from Lambda (stdio)", response_len);
        
        self.parse_witness_response(&response_buf)
    }
    
    /// Parse Lambda witness response
    fn parse_witness_response(&self, data: &[u8]) -> Result<LambdaWitnessResponse, AntieError> {
        let response: GatewayResponse = ipc_decode(data)?;

        match response {
            GatewayResponse::WitnessResult(wr) => {
                info!("Lambda witness response: success={}", wr.success);
                Ok(*wr)
            }
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for witness".into())),
        }
    }
    
    /// Parse Lambda redeem response
    fn parse_redeem_response(&self, data: &[u8]) -> Result<LambdaRedeemResponse, AntieError> {
        let response: GatewayResponse = ipc_decode(data)?;

        match response {
            GatewayResponse::RedeemResult(rr) => {
                info!("Lambda redeem response: success={}", rr.success);
                Ok(rr)
            }
            GatewayResponse::Error(env) => {
                Err(AntieError::LambdaRejected(env.error_response))
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for redeem".into())),
        }
    }
    
    /// Send redeem request over TCP stream
    async fn send_redeem_request_tcp<T: serde::Serialize>(
        &self,
        mut stream: TcpStream,
        request: &T,
    ) -> Result<LambdaRedeemResponse, AntieError> {
        // Serialize request
        let buf = ipc_encode(request)?;
        
        // Send frame: 4-byte length + payload
        let len = (buf.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        
        debug!("Sent {} bytes to Lambda (TCP redeem)", buf.len());
        
        // Read response frame
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        if response_len > 10 * 1024 * 1024 {
            return Err(AntieError::LambdaError("Response too large".into()));
        }
        
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await?;
        
        debug!("Received {} bytes from Lambda (TCP redeem)", response_len);
        
        self.parse_redeem_response(&response_buf)
    }
    
    /// Send genesis request over TCP
    async fn send_genesis_request_tcp<T: serde::Serialize>(
        &self,
        mut stream: TcpStream,
        request: &T,
    ) -> Result<LambdaGenesisResponse, AntieError> {
        let buf = ipc_encode(request)?;
        
        let len = (buf.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await?;
        
        self.parse_genesis_response(&response_buf)
    }
    
    /// Send genesis request over stdio (subprocess mode)
    async fn send_genesis_request_stdio<T: serde::Serialize>(
        &self,
        child: &Mutex<Option<Child>>,
        request: &T,
    ) -> Result<LambdaGenesisResponse, AntieError> {
        info!("send_genesis_request_stdio: acquiring lock");
        let mut guard = child.lock().await;
        let process = guard.as_mut()
            .ok_or_else(|| AntieError::LambdaError("Lambda subprocess not running".into()))?;
        
        let stdin = process.stdin.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdin".into()))?;
        let stdout = process.stdout.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdout".into()))?;
        
        let buf = ipc_encode(request)?;
        info!("send_genesis_request_stdio: sending {} bytes", buf.len());
        
        let len = (buf.len() as u32).to_be_bytes();
        stdin.write_all(&len).await?;
        stdin.write_all(&buf).await?;
        stdin.flush().await?;
        
        info!("send_genesis_request_stdio: waiting for response...");
        
        let mut reader = BufReader::new(stdout);
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        info!("send_genesis_request_stdio: response length = {}", response_len);
        
        if response_len > 10 * 1024 * 1024 {
            return Err(AntieError::LambdaError("Response too large".into()));
        }
        
        let mut response_buf = vec![0u8; response_len];
        reader.read_exact(&mut response_buf).await?;
        
        info!("send_genesis_request_stdio: received {} bytes", response_len);
        
        self.parse_genesis_response(&response_buf)
    }
    
    /// Parse Lambda genesis response. Lambda sends a full GatewayResponse
    /// envelope (the canonical one in `axiom_core_logic::types`); we expect
    /// the InitGenesisResult variant. Anything else is reported as a Lambda
    /// error rather than silently mapped.
    fn parse_genesis_response(&self, data: &[u8]) -> Result<LambdaGenesisResponse, AntieError> {
        use axiom_core_logic::types::GatewayResponse as CanonicalGatewayResponse;
        let response: CanonicalGatewayResponse = ipc_decode(data)
            .map_err(|e| AntieError::LambdaError(format!("Parse genesis response failed: {}", e)))?;
        match response {
            CanonicalGatewayResponse::InitGenesisResult(payload) => Ok(payload),
            CanonicalGatewayResponse::Error(env) => Err(AntieError::LambdaRejected(env.error_response)),
            _ => Err(AntieError::LambdaError("Unexpected response type for genesis".into())),
        }
    }
    
    /// Send redeem request over stdio (subprocess mode)
    async fn send_redeem_request_stdio<T: serde::Serialize>(
        &self,
        child: &Mutex<Option<Child>>,
        request: &T,
    ) -> Result<LambdaRedeemResponse, AntieError> {
        let mut guard = child.lock().await;
        let process = guard.as_mut()
            .ok_or_else(|| AntieError::LambdaError("Lambda subprocess not running".into()))?;
        
        let stdin = process.stdin.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdin".into()))?;
        let stdout = process.stdout.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdout".into()))?;
        
        // Serialize request
        let buf = ipc_encode(request)?;
        
        // Send frame: 4-byte length + payload
        let len = (buf.len() as u32).to_be_bytes();
        stdin.write_all(&len).await?;
        stdin.write_all(&buf).await?;
        stdin.flush().await?;
        
        debug!("Sent {} bytes to Lambda (stdio redeem)", buf.len());
        
        // Read response frame
        let mut reader = BufReader::new(stdout);
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        if response_len > 10 * 1024 * 1024 {
            return Err(AntieError::LambdaError("Response too large".into()));
        }
        
        let mut response_buf = vec![0u8; response_len];
        reader.read_exact(&mut response_buf).await?;
        
        debug!("Received {} bytes from Lambda (stdio redeem)", response_len);
        
        self.parse_redeem_response(&response_buf)
    }
    
    /// Parse ACK response from Lambda
    fn parse_ack_response(&self, data: &[u8]) -> Result<LambdaAckResponse, AntieError> {
        let response: GatewayResponse = ipc_decode(data)
            .map_err(|e| {
                AntieError::LambdaError(format!("Parse ACK response failed: {}", e))
            })?;
        
        match response {
            GatewayResponse::AckResult(ack_resp) => Ok(ack_resp),
            GatewayResponse::Error(env) => {
                Ok(LambdaAckResponse {
                    request_id: String::new(),
                    success: false,
                    new_status: None,
                    error_response: Some(env.error_response),
                })
            }
            _ => Err(AntieError::LambdaError("Unexpected response type for ACK".into())),
        }
    }
    
    /// Send ACK via TCP
    async fn send_ack_request_tcp<T: serde::Serialize>(
        &self,
        stream: TcpStream,
        request: &T,
    ) -> Result<LambdaAckResponse, AntieError> {
        let buf = ipc_encode(request)?;
        
        let mut stream = stream;
        let len = (buf.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        
        let mut reader = BufReader::new(&mut stream);
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        let mut response_buf = vec![0u8; response_len];
        reader.read_exact(&mut response_buf).await?;
        
        self.parse_ack_response(&response_buf)
    }
    
    /// Send ACK via stdio subprocess
    async fn send_ack_request_stdio<T: serde::Serialize>(
        &self,
        child: &Mutex<Option<Child>>,
        request: &T,
    ) -> Result<LambdaAckResponse, AntieError> {
        let mut guard = child.lock().await;
        let process = guard.as_mut()
            .ok_or_else(|| AntieError::LambdaError("Lambda subprocess not running".into()))?;
        
        let stdin = process.stdin.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdin".into()))?;
        let stdout = process.stdout.as_mut()
            .ok_or_else(|| AntieError::LambdaError("No stdout".into()))?;
        
        let buf = ipc_encode(request)?;
        
        let len = (buf.len() as u32).to_be_bytes();
        stdin.write_all(&len).await?;
        stdin.write_all(&buf).await?;
        stdin.flush().await?;
        
        debug!("Sent {} bytes to Lambda (stdio ack)", buf.len());
        
        let mut reader = BufReader::new(stdout);
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        if response_len > 10 * 1024 * 1024 {
            return Err(AntieError::LambdaError("Response too large".into()));
        }
        
        let mut response_buf = vec![0u8; response_len];
        reader.read_exact(&mut response_buf).await?;
        
        debug!("Received {} bytes from Lambda (stdio ack)", response_len);
        
        self.parse_ack_response(&response_buf)
    }
    
    /// Check Lambda health
    pub async fn health_check(&self) -> Result<bool, AntieError> {
        match &self.mode {
            LambdaMode::Tcp { address, .. } => {
                let stream = TcpStream::connect(address).await
                    .map_err(|e| AntieError::LambdaError(format!("Connect failed: {}", e)))?;
                
                let request = GatewayRequest::Health(axiom_core_logic::types::HealthRequest {
                    request_id: format!("health-{}", uuid::Uuid::new_v4()),
                });
                
                let buf = ipc_encode(&request)?;
                
                let mut stream = stream;
                let len = (buf.len() as u32).to_be_bytes();
                stream.write_all(&len).await?;
                stream.write_all(&buf).await?;
                stream.flush().await?;
                
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return Ok(false);
                }
                
                Ok(true)
            }
            LambdaMode::Subprocess { child, .. } => {
                let guard = child.lock().await;
                Ok(guard.is_some())
            }
        }
    }
}

/// Lambda client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaClientConfig {
    #[serde(flatten)]
    pub mode: LambdaConnectionMode,
}

/// Lambda connection mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum LambdaConnectionMode {
    /// TCP connection
    #[serde(rename = "tcp")]
    Tcp {
        address: String,
        timeout_secs: u64,
    },
    /// Subprocess (preferred)
    #[serde(rename = "subprocess")]
    Subprocess {
        binary_path: PathBuf,
        config_path: PathBuf,
    },
}
























// === §23.14.6: Peer Audit IPC Types ===




#[cfg(test)]
mod tests {
    use super::*;

    // ── ipc_encode / ipc_decode roundtrip ───────────────────────────

    /// Simple string round-trips through CBOR encode/decode.
    #[test]
    fn ipc_encode_decode_string_roundtrip() {
        let original = "hello AXIOM".to_string();
        let encoded = ipc_encode(&original).unwrap();
        let decoded: String = ipc_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    /// Structured data round-trips through CBOR encode/decode.
    #[test]
    fn ipc_encode_decode_struct_roundtrip() {
        let req = GatewayRequest::Health(axiom_core_logic::types::HealthRequest {
            request_id: "h-42".into(),
        });
        let encoded = ipc_encode(&req).unwrap();
        assert!(!encoded.is_empty());

        // KI#173 batch 4: the Core variant carries the same keys ANTIE's
        // deleted `HealthRequest` copy sent — `type` + `request_id`.
        let value: ciborium::Value = ipc_decode(&encoded).unwrap();
        let map = value.as_map().unwrap();
        let text = |key: &str| map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .and_then(|(_, v)| v.as_text().map(str::to_string));
        assert_eq!(text("type").as_deref(), Some("health"));
        assert_eq!(text("request_id").as_deref(), Some("h-42"));
        assert!(matches!(ipc_decode::<GatewayRequest>(&encoded).unwrap(), GatewayRequest::Health(_)));
    }

    /// Large nested payload round-trips correctly.
    #[test]
    fn ipc_encode_decode_large_payload() {
        let large_vec: Vec<u8> = vec![0xAB; 100_000];
        let encoded = ipc_encode(&large_vec).unwrap();
        let decoded: Vec<u8> = ipc_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 100_000);
        assert!(decoded.iter().all(|&b| b == 0xAB));
    }

    /// Decoding garbage bytes returns a LambdaError, not a panic.
    #[test]
    fn ipc_decode_garbage_returns_error() {
        let garbage = vec![0xFF, 0xFE, 0x00, 0x01];
        let result: Result<String, _> = ipc_decode(&garbage);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CBOR decode error"));
    }

    // ── Frame size limits ───────────────────────────────────────────

    /// The 10MB frame size limit is consistently enforced across all code paths.
    /// This test documents the constant used throughout the module.
    #[test]
    fn frame_size_limit_constant() {
        // Every read path in the module checks: response_len > 10 * 1024 * 1024
        let limit: usize = 10 * 1024 * 1024;
        assert_eq!(limit, 10_485_760);

        // A frame of exactly 10MB should be accepted (the check is >)
        assert!(limit <= 10_485_760); // 10MB is within limit
        // A frame of 10MB + 1 should be rejected
        assert!(limit + 1 > 10_485_760);
    }

    // ── GatewayResponse variant parsing ─────────────────────────────

    fn text(s: &str) -> ciborium::Value {
        ciborium::Value::Text(s.to_string())
    }

    fn cbor_map(entries: Vec<(&str, ciborium::Value)>) -> ciborium::Value {
        ciborium::Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
    }

    /// KI#173 batch 4 — the error frame Lambda writes (`type: "error"`,
    /// `request_id`, `error_response` at the top level) decodes as Core's
    /// `GatewayResponse::Error(ErrorEnvelope)`, the shape ANTIE's deleted
    /// copy spelled as a struct variant. Built as a CBOR map, not from Core's
    /// type, so the test pins the wire keys independently.
    #[test]
    fn gateway_response_error_variant_cbor() {
        let frame = cbor_map(vec![
            ("type", text("error")),
            ("request_id", text("err-1")),
            ("error_response", cbor_map(vec![
                ("version", ciborium::Value::Integer(1.into())),
                ("code", text("E_LAMBDA_INVALID_REQUEST")),
                ("category", text("client_bug")),
                ("message", text("something failed")),
            ])),
        ]);
        let cbor_buf = ipc_encode(&frame).unwrap();

        match ipc_decode::<GatewayResponse>(&cbor_buf).unwrap() {
            GatewayResponse::Error(env) => {
                assert_eq!(env.request_id, "err-1");
                assert_eq!(env.error_response.message, "something failed");
                assert_eq!(env.error_response.code.as_str(), "E_LAMBDA_INVALID_REQUEST");
            }
            other => panic!("Expected Error variant, got {:?}", other),
        }
    }

    /// KI#173 batch 4 — the Core request variants that replaced ANTIE's local
    /// copies put the same bytes on the pipe: the tag first, then the fields
    /// in the order the deleted structs declared them.
    #[test]
    fn core_request_variants_encode_like_the_deleted_local_structs() {
        let bytes_list = |xs: &[u8]| ciborium::Value::Array(
            xs.iter().map(|b| ciborium::Value::Integer((*b).into())).collect());
        let old_set_auth_hash = cbor_map(vec![
            ("type", text("set_auth_hash")),
            ("request_id", text("r-1")),
            ("public_key", bytes_list(&[1, 2, 3])),
            ("auth_hash", bytes_list(&[9, 8])),
        ]);
        let new_set_auth_hash = GatewayRequest::SetAuthHash(axiom_core_logic::types::SetAuthHashRequest {
            request_id: "r-1".into(), public_key: vec![1, 2, 3], auth_hash: vec![9, 8],
        });
        assert_eq!(ipc_encode(&old_set_auth_hash).unwrap(), ipc_encode(&new_set_auth_hash).unwrap());

        let old_mark = cbor_map(vec![
            ("type", text("fanout_mark")),
            ("request_id", text("mark-1")),
            ("diffusion_id", bytes_list(&[7; 32])),
        ]);
        let new_mark = GatewayRequest::FanOutMark(axiom_core_logic::types::FanOutMarkRequest {
            request_id: "mark-1".into(), diffusion_id: vec![7; 32],
        });
        assert_eq!(ipc_encode(&old_mark).unwrap(), ipc_encode(&new_mark).unwrap());

        let old_vsp = cbor_map(vec![("type", text("validator_status")), ("request_id", text("v-1"))]);
        let new_vsp = GatewayRequest::ValidatorStatus(axiom_core_logic::types::ValidatorStatusRequest {
            request_id: "v-1".into(),
        });
        assert_eq!(ipc_encode(&old_vsp).unwrap(), ipc_encode(&new_vsp).unwrap());
    }

    /// KI#173 batch 4 — Lambda answers `health` with `HealthResult(HealthResponse)`
    /// (`server.rs` → `engine.health()`). ANTIE's deleted copy expected
    /// `{ request_id, status }`, a shape Lambda never sends.
    #[test]
    fn gateway_response_health_variant_cbor() {
        let frame = cbor_map(vec![
            ("type", text("health_result")),
            ("status", text("ok")),
            ("core_connected", ciborium::Value::Bool(true)),
            ("pending_transactions", ciborium::Value::Integer(0.into())),
        ]);
        let cbor_buf = ipc_encode(&frame).unwrap();

        match ipc_decode::<GatewayResponse>(&cbor_buf).unwrap() {
            GatewayResponse::HealthResult(h) => assert_eq!(h.status, "ok"),
            other => panic!("Expected HealthResult variant, got {:?}", other),
        }
    }

    // ── Request type structs ────────────────────────────────────────

    /// GatewayRequest::InitGenesis serializes with "type" rename.
    #[test]
    fn genesis_request_type_rename() {
        let req = axiom_core_logic::types::GatewayRequest::InitGenesis(
            axiom_core_logic::types::InitGenesisRequest {
                request_id: "gen-1".into(),
                public_key: vec![1, 2, 3],
                balance: 1_000_000,
                group_members: None,
                auth_hash: None,
            }
        );
        let encoded = ipc_encode(&req).unwrap();
        let value: serde_json::Value = ciborium::from_reader(&encoded[..]).unwrap();
        assert_eq!(value["type"], "init_genesis_dev");
        assert_eq!(value["balance"], 1_000_000);
    }

    /// GatewayRequest::Ack serializes txid as byte array.
    #[test]
    fn ack_request_serialization() {
        let req = axiom_core_logic::types::GatewayRequest::Ack(
            axiom_core_logic::types::AckRequest {
                request_id: "ack-1".into(),
                ack: axiom_core_logic::AckWithFee {
                    txid: [0xAA; 32],
                    validator_pk: vec![0xBB; 32],
                    sender_sig: vec![0xCC; 64],
                },
                client_pk: vec![0xDD; 32],
            }
        );
        let encoded = ipc_encode(&req).unwrap();
        assert!(!encoded.is_empty());
        // Verify we can decode back
        let value: serde_json::Value = ciborium::from_reader(&encoded[..]).unwrap();
        assert_eq!(value["type"], "ack");
        assert!(value["ack"]["fee_amount"].is_null(),
            "v3.x ACK envelope must not carry fee_amount");
    }

    // ── Client construction ─────────────────────────────────────────

    /// TCP client can be constructed with address and timeout.
    #[test]
    fn lambda_client_new_tcp() {
        let _client = LambdaClient::new_tcp("127.0.0.1:9000", 30);
        // No panic = success. Mode is private, so we just verify construction.
    }

    /// Subprocess client can be constructed with paths.
    #[test]
    fn lambda_client_new_subprocess() {
        let _client = LambdaClient::new_subprocess(
            PathBuf::from("/usr/bin/lambda"),
            PathBuf::from("/etc/lambda.toml"),
        );
    }

    // ── KI#80: lambda child supervision ─────────────────────────────
    //
    // Real-process tests: a shell script that ignores its `--config`
    // arg stands in for the lambda binary. The supervisor's job —
    // detect exit, reap, respawn, honor stop() — is exercised against
    // genuine child processes and genuine SIGKILL, exactly the event
    // the 2026-08-08 soak produced. Timings are generous multiples of
    // the loop's 2s poll.

    /// Write an executable script that ignores args and sleeps — and return
    /// only once it is EXEC-ABLE.
    ///
    /// KI#238 (test-only): while `fs::write` holds the stub's write descriptor,
    /// another test thread in this binary may `fork()`; the child inherits the
    /// descriptor until its own `exec` closes it (O_CLOEXEC), and in that window
    /// `execve(stub)` fails with ETXTBSY — `ki80_supervisor_respawns_killed_child`
    /// failed once that way in a full preflight. A temp-name + `rename` alone does
    /// NOT close it (the inherited descriptor is on the same inode). What does:
    /// after our own descriptor is closed no NEW fork can inherit it, so ONE
    /// successful exec proves no writer remains. The helper probes the stub
    /// (`--stub-probe` exits at once) and retries ONLY on ETXTBSY, so
    /// `LambdaClient` (the code under test) never sees the race — and is not
    /// changed for it.
    fn write_stub_lambda(dir: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        const ETXTBSY: i32 = 26;
        let path = dir.join("stub-lambda.sh");
        std::fs::write(&path, "#!/bin/sh\n[ \"$1\" = \"--stub-probe\" ] && exit 0\nexec sleep 300\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        for _ in 0..500 {
            match std::process::Command::new(&path).arg("--stub-probe").status() {
                Ok(st) => {
                    assert!(st.success(), "stub probe exited {st}");
                    return path;
                }
                Err(e) if e.raw_os_error() == Some(ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("stub probe: {e}"),
            }
        }
        panic!("stub {} stayed ETXTBSY for 5 s", path.display());
    }

    async fn child_pid(client: &LambdaClient) -> Option<u32> {
        match &client.mode {
            LambdaMode::Subprocess { child, .. } =>
                child.lock().await.as_ref().and_then(|c| c.id()),
            _ => None,
        }
    }

    /// SIGKILL the child (the OOM killer's signal); the supervisor must
    /// reap it, respawn a NEW child, and restore lambda_alive.
    /// Mutation check performed during development: with the
    /// `spawn_child_into` call replaced by a constant Err, this test
    /// fails (no new pid ever appears) — verified red 2026-08-08.
    #[tokio::test]
    async fn ki80_supervisor_respawns_killed_child() {
        let tmp = std::env::temp_dir().join(format!("ki80-respawn-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("config")).unwrap();
        let stub = write_stub_lambda(&tmp);
        let client = Arc::new(LambdaClient::new_subprocess(
            stub, tmp.join("config").join("antie.toml"),
        ));
        client.start().await.unwrap();
        let first_pid = child_pid(&client).await.expect("child spawned");

        let sup = client.clone();
        let task = tokio::spawn(async move { sup.supervision_loop().await });

        // The OOM killer's exact move.
        std::process::Command::new("kill")
            .args(["-9", &first_pid.to_string()])
            .status().unwrap();

        // Within poll(2s) + backoff(1s) + margin the supervisor must have
        // reaped the corpse and spawned a REPLACEMENT process.
        let mut respawned = None;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Some(pid) = child_pid(&client).await {
                if pid != first_pid {
                    respawned = Some(pid);
                    break;
                }
            }
        }
        let new_pid = respawned.expect("supervisor never respawned the killed child");
        assert_ne!(new_pid, first_pid);
        assert!(client.lambda_alive.load(Ordering::SeqCst),
                "lambda_alive must read true after a successful respawn");

        client.stop().await.unwrap();
        task.abort();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// stop() is deliberate: the supervisor must NOT resurrect a child
    /// that was killed on purpose.
    #[tokio::test]
    async fn ki80_stop_prevents_respawn() {
        let tmp = std::env::temp_dir().join(format!("ki80-stop-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("config")).unwrap();
        let stub = write_stub_lambda(&tmp);
        let client = Arc::new(LambdaClient::new_subprocess(
            stub, tmp.join("config").join("antie.toml"),
        ));
        client.start().await.unwrap();

        let sup = client.clone();
        let task = tokio::spawn(async move { sup.supervision_loop().await });

        client.stop().await.unwrap();

        // Give the supervisor several poll cycles to (wrongly) act.
        tokio::time::sleep(std::time::Duration::from_secs(7)).await;
        assert!(child_pid(&client).await.is_none(),
                "supervisor respawned a deliberately-stopped child");

        task.abort();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

