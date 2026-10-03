//! Mail Carriers
//!
//! ANTIE supports multiple mail carriers:
//! - **Maildir** (default, production) - Filesystem-based, works with sendmail/postfix
//! - **POP3** - Pull emails from POP3 server (TLS, async)
//! - **IMAP** - Pull emails from IMAP server (TLS, UID semantics, async)
//! - **SMTP** - Send emails via SMTP (outbound only, via lettre, STARTTLS)
//!
//! All carriers implement the same trait, so ANTIE can switch between them.

use crate::error::AntieError;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::path::PathBuf;

// ============================================================================
// Shared carrier I/O — KI#114 (the ANTIE spin-wedge)
// ============================================================================

/// KI#114 — the ONE line/byte reader, connect path and per-step bound every
/// IMAP / POP3 / SMTP session uses (RULE 1). Before 2026-10-01 each read site
/// re-implemented the EOF rule and two forgot it: `imap_carrier::fetch_message`
/// and `pop3_carrier::read_multiline` treated `read_line → Ok(0)` (EOF) as an
/// empty line and looped forever. Over TLS, after the peer's close_notify,
/// OpenSSL returns 0 WITHOUT a syscall, so the future never returned `Pending`
/// and one tokio worker spun at 100% CPU, silently — the most likely cause of
/// the 2026-08-26 zeta wedge (MEASURED: the defect; INFERRED: the trigger —
/// `carrier_eof_mid_response` on /status is how production confirms it).
/// ⚠ A `tokio::time::timeout` CANNOT rescue a future that never returns
/// `Pending`; the EOF check is the cure, the timeouts below only bound the
/// BLOCKED (not spinning) shapes: a connect / TLS handshake / read / write
/// that never completes (KI#114 investigation §3 rows 3 and 7).
pub mod carrier_io {
    use crate::error::AntieError;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Bound on TCP connect, and separately on the TLS handshake.
    pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    /// Bound on ONE read or write step (a line, a literal chunk, a command).
    /// Progress-based: a slow transpacific 1.5 MB FETCH makes progress every
    /// chunk, so only a step that delivers NOTHING for this long fails.
    pub const IO_STEP_TIMEOUT: Duration = Duration::from_secs(60);

    /// KI#114 — every EOF met in the MIDDLE of a carrier response (a server
    /// that closed the session before completing what it was sending).
    /// Process-global because carriers are constructed without the stats
    /// handle; `/status` reads it as `carrier_eof_mid_response`. RULE 3 §2:
    /// "0" means it never happened, not that nobody looked.
    static EOF_MID_RESPONSE: AtomicU64 = AtomicU64::new(0);

    /// The `/status` value of [`EOF_MID_RESPONSE`].
    pub fn eof_mid_response() -> u64 {
        EOF_MID_RESPONSE.load(Ordering::Relaxed)
    }

    fn eof(what: &str) -> AntieError {
        EOF_MID_RESPONSE.fetch_add(1, Ordering::Relaxed);
        AntieError::ConfigError(format!("{what}: connection closed by server mid-response"))
    }

    /// Streams a carrier session runs over: plain TCP or TLS. ONE trait for
    /// IMAP / POP3 / SMTP (was three identical private copies).
    pub trait CarrierStream: AsyncRead + AsyncWrite + Unpin + Send {}
    impl CarrierStream for TcpStream {}
    impl CarrierStream for tokio_native_tls::TlsStream<TcpStream> {}

    /// TCP connect (bounded) + keepalive + optional TLS handshake (bounded).
    /// Keepalive on EVERY carrier (was IMAP only, KI#114 §6 (a).3): a NAT that
    /// drops a quiet flow leaves a half-dead socket whose read blocks forever
    /// — keepalive makes the OS probe it so the session fails LOUDLY (measured
    /// 2026-08-21 on zeta/iota for IMAP IDLE).
    pub async fn connect(proto: &str, server: &str, port: u16, use_tls: bool)
        -> Result<Box<dyn CarrierStream>, AntieError>
    {
        let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((server, port))).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return Err(AntieError::ConfigError(format!("{proto} connect {server}:{port}: {e}"))),
            Err(_) => return Err(AntieError::ConfigError(format!(
                "{proto} connect {server}:{port}: timed out after {CONNECT_TIMEOUT:?}"))),
        };
        {
            let ka = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(30));
            socket2::SockRef::from(&tcp).set_tcp_keepalive(&ka)
                .map_err(|e| AntieError::ConfigError(format!("{proto} keepalive: {e}")))?;
        }
        if !use_tls {
            return Ok(Box::new(tcp));
        }
        let connector = tokio_native_tls::native_tls::TlsConnector::new()
            .map_err(|e| AntieError::ConfigError(format!("TLS init: {e}")))?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server, tcp)).await {
            Ok(Ok(tls)) => Ok(Box::new(tls)),
            Ok(Err(e)) => Err(AntieError::ConfigError(format!("{proto} TLS handshake: {e}"))),
            Err(_) => Err(AntieError::ConfigError(format!(
                "{proto} TLS handshake {server}:{port}: timed out after {CONNECT_TIMEOUT:?}"))),
        }
    }

    /// Read ONE line into `line` (cleared first). EOF (`Ok(0)`) is an ERROR,
    /// never an empty line — the KI#114 cure. Bounded by [`IO_STEP_TIMEOUT`].
    pub async fn read_line<R: AsyncBufRead + Unpin + ?Sized>(r: &mut R, line: &mut String, what: &str)
        -> Result<usize, AntieError>
    {
        line.clear();
        match tokio::time::timeout(IO_STEP_TIMEOUT, r.read_line(line)).await {
            Ok(Ok(0)) => Err(eof(what)),
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(AntieError::ConfigError(format!("{what} read: {e}"))),
            Err(_) => Err(AntieError::ConfigError(format!(
                "{what} read: no data for {IO_STEP_TIMEOUT:?}"))),
        }
    }

    /// Read EXACTLY `buf.len()` bytes (an IMAP literal) — byte-exact, no UTF-8
    /// assumption. EOF names how many bytes were still owed (`detail` should
    /// name the message, e.g. `uid=7`). Each chunk bounded by [`IO_STEP_TIMEOUT`].
    pub async fn read_exact<R: AsyncRead + Unpin + ?Sized>(r: &mut R, buf: &mut [u8], what: &str, detail: &str)
        -> Result<(), AntieError>
    {
        let mut got = 0usize;
        while got < buf.len() {
            match tokio::time::timeout(IO_STEP_TIMEOUT, r.read(&mut buf[got..])).await {
                Ok(Ok(0)) => {
                    EOF_MID_RESPONSE.fetch_add(1, Ordering::Relaxed);
                    return Err(AntieError::ConfigError(format!(
                        "{what}: connection closed by server mid-response {detail} (literal {} bytes short)",
                        buf.len() - got)));
                }
                Ok(Ok(n)) => got += n,
                Ok(Err(e)) => return Err(AntieError::ConfigError(format!("{what} read {detail}: {e}"))),
                Err(_) => return Err(AntieError::ConfigError(format!(
                    "{what} read {detail}: no data for {IO_STEP_TIMEOUT:?} ({} bytes short)", buf.len() - got))),
            }
        }
        Ok(())
    }

    /// `write_all` + flush, bounded by [`IO_STEP_TIMEOUT`].
    pub async fn write_all<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, bytes: &[u8], what: &str)
        -> Result<(), AntieError>
    {
        let step = async {
            w.write_all(bytes).await?;
            w.flush().await
        };
        match tokio::time::timeout(IO_STEP_TIMEOUT, step).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(AntieError::ConfigError(format!("{what} write: {e}"))),
            Err(_) => Err(AntieError::ConfigError(format!("{what} write: stalled for {IO_STEP_TIMEOUT:?}"))),
        }
    }
}

/// A received email message
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// Unique ID for this message
    pub id: String,
    
    /// Raw email bytes
    pub raw: Vec<u8>,
    
    /// Source path or identifier (for logging/debugging)
    pub source: String,
}

/// Carrier trait - abstraction over different mail sources
#[async_trait]
pub trait MailCarrier: Send + Sync {
    /// Get carrier name
    fn name(&self) -> &str;
    
    /// Check for new messages
    async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError>;
    
    /// Mark message as processed
    async fn mark_processed(&self, message_id: &str) -> Result<(), AntieError>;
    
    /// Mark message as failed (for retry or dead-letter)
    async fn mark_failed(&self, message_id: &str, reason: &str) -> Result<(), AntieError>;
    
    /// Send outgoing message
    async fn send(&self, to: &str, raw_email: &[u8]) -> Result<(), AntieError>;
}

/// Maildir carrier — MDA delivers to inbox/new/; ANTIE watches with inotify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaildirConfig {
    pub inbox:  PathBuf,
    pub outbox: PathBuf,
}

/// IMAP carrier — ANTIE pulls a remote IMAP mailbox.
///
/// Two wait strategies, one carrier (ruled 2026-08-21):
/// - `use_idle = true` (default): IDLE is PRIMARY. The carrier holds an
///   authenticated session and the server pushes `* n EXISTS` when mail
///   arrives — roughly two logins per half hour instead of one per poll tick,
///   which is what makes the KI#110 per-account auth budget a non-issue.
/// - If the server does not advertise the IDLE capability, the gateway FALLS
///   BACK to the poll loop — loudly (WARN at startup names the mode and the
///   rate). The fallback is declared behaviour, never silent degradation.
/// - `use_idle = false`: poll only, no capability probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    /// The owner, 2026-09-08: *"we should have a flag in the TOML to disable it."*
    /// `enabled = false` keeps the section (credentials, server) in place but
    /// never opens a connection — the switch for a provider that is blocking
    /// this host, or for a fleet whose real-email leg is deliberately off.
    /// Logged at startup as DISABLED so a silent leg is never mistaken for a
    /// broken one. Default true: an absent key changes nothing.
    #[serde(default = "default_true")]
    pub enabled:          bool,
    pub server:           String,
    pub port:             u16,
    pub username:         String,
    pub password:         String,
    #[serde(default = "default_true")]
    pub use_tls:          bool,
    #[serde(default = "default_inbox")]
    pub inbox_folder:     String,
    #[serde(default = "default_true")]
    pub use_idle:         bool,
}

fn default_true()      -> bool   { true }
fn default_inbox()     -> String { "INBOX".into() }

/// True when a host string names the local machine. Used by the plaintext-IMAP
/// refusal: credentials on loopback cannot be sniffed off a wire.
fn host_is_loopback(host: &str) -> bool {
    host == "localhost"
        || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// POP3 carrier — ANTIE polls a remote POP3 mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pop3Config {
    /// Same switch as `ImapConfig::enabled` (the owner, 2026-09-08).
    #[serde(default = "default_true")]
    pub enabled:  bool,
    pub server:   String,
    pub port:     u16,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub use_tls:  bool,
    /// Minimal anti-spam (opt-in). If set, POP3 mail whose BODY Shannon entropy
    /// is BELOW this many bits/byte is treated as natural-language text spam and
    /// deleted from the server WITHOUT being staged/parsed. A real UMP body
    /// (base64 crypto CBOR) is ~5.5–6 bits/byte; newsletters/welcome mail
    /// ~4–4.5. Recommended ~4.5 (conservative — bias toward keep). `None`
    /// (default) = off. Marker-free by design (no magic, no subject) so it
    /// can't help a censor fingerprint AXIOM. Hygiene only, NOT spam filtering
    /// (that's the MTA's job) and NOT a trust gate (Core validates). See
    /// `email::body_entropy_bits`.
    #[serde(default)]
    pub spam_entropy_threshold: Option<f32>,
}

/// All inbound carriers. At least one email carrier must be present.
///
/// ANTIE's job is mail-shaped intake: maildir / imap / pop3 are the
/// three implementations of that one shape. Everything else (TOT,
/// any future direct-delivery transport) runs as a sibling process
/// outside ANTIE and is advertised to peers via the freeform
/// `advertise` list. ANTIE itself does NOT open TCP / WebSocket
/// listeners — those are deliberately not its responsibility.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CarriersConfig {
    pub maildir: Option<MaildirConfig>,
    /// Inbound accounts — `[[carriers.imap]]` / `[[carriers.pop3]]` arrays
    /// (design §5.2.2f, RULED 2026-09-09: "allow operators to setup multiple
    /// imap and pop3. But up to 5 as maximum"; "Would not start more than 5").
    /// Each entry has its own `enabled` flag; the shipped antie.toml carries
    /// the slots empty. The cap is enforced at config load — see
    /// `CarriersConfig::validate_inbound_count`. No account is special: the
    /// stake wallet's mailbox is simply one of them (no VBC puller exists).
    #[serde(default)]
    pub imap:    Vec<ImapConfig>,
    #[serde(default)]
    pub pop3:    Vec<Pop3Config>,

    /// Operator-declared carrier URIs advertised in the VSP
    /// discovery list. ANTIE does NOT parse the scheme — strings
    /// ride through verbatim into `to_uri_list` and propagate to
    /// peers as opaque hint entries. Any transport the operator
    /// runs (TOT, FATMAMA, future schemes) is declared here.
    ///
    /// Validators receiving these strings act as honest pipes —
    /// they store and forward them in their own hint emissions
    /// without understanding the scheme. The SDK on the client
    /// side decides what to do with each URI.
    ///
    /// Cross-version compat: older ANTIE versions that don't have
    /// this field ignore it (serde(default) returns an empty Vec);
    /// newer ANTIE versions reading an older config without
    /// `advertise =` simply emit no extra URIs. Email floor stays
    /// in effect either way.
    #[serde(default)]
    pub advertise: Vec<String>,
}

/// Hard ceiling on inbound accounts (design §5.2.2f). Six or more = ANTIE
/// refuses to start; a half-honoured config would be a silent ghost.
pub const MAX_INBOUND_ACCOUNTS: usize = 5;

impl CarriersConfig {
    /// Enabled + disabled entries both count: a disabled slot is still an
    /// operator statement about an account, and the cap is about the file.
    pub fn validate_inbound_count(&self) -> Result<(), AntieError> {
        let n = self.imap.len() + self.pop3.len();
        if n > MAX_INBOUND_ACCOUNTS {
            return Err(AntieError::ConfigError(format!(
                "{} inbound accounts configured ([[carriers.imap]] + [[carriers.pop3]]); \
                 the maximum is {}. ANTIE will not start — remove entries (design §5.2.2f).",
                n, MAX_INBOUND_ACCOUNTS)));
        }
        Ok(())
    }
    /// Any inbound network pull configured (enabled or not) — the poll-rate
    /// floor applies to the file, not to the moment.
    pub fn has_network_pull(&self) -> bool { !self.imap.is_empty() || !self.pop3.is_empty() }
}

impl CarriersConfig {
    /// Fail-stop validation. Called at gateway startup.
    pub fn validate(&self) -> Result<(), crate::error::AntieError> {
        let has_email = self.maildir.is_some() || self.has_network_pull();
        if !has_email {
            return Err(crate::error::AntieError::ConfigError(
                "at least one email carrier (maildir, imap, or pop3) must be configured \
                 — tcp alone is not valid; email is required for fan-out".into()
            ));
        }
        // Inbox-funnel invariant (AXIOM_DESIGN_AntieInboxFunnel.md §4): POP3/IMAP
        // are delivery agents that write into the maildir inbox/new/; the Maildir
        // carrier is the single reader that dispatches to Lambda. So a maildir
        // inbox must exist whenever pop3 or imap is enabled.
        if self.has_network_pull() && self.maildir.is_none() {
            return Err(crate::error::AntieError::ConfigError(
                "pop3/imap carriers deliver into [carriers.maildir] inbox/new/ (the single \
                 inbound funnel) — configure [carriers.maildir] when using pop3 or imap".into()
            ));
        }
        // IMAP always LOGINs (there is no anonymous mode and no FATMAMA-style
        // local IMAP), so plaintext IMAP can only ever ship a real credential to
        // a real network. Refuse it at CONFIG LOAD — same idiom as the poll-rate
        // floor: an unsafe value cannot start the process. Loopback is exempt
        // (nothing to sniff; also what the mock-server tests use).
        for imap in &self.imap {
            if !imap.use_tls && !host_is_loopback(&imap.server) {
                return Err(crate::error::AntieError::ConfigError(format!(
                    "IMAP to {} with use_tls = false: LOGIN would send the mailbox \
                     password in cleartext to a non-loopback host. Enable TLS.",
                    imap.server
                )));
            }
        }
        Ok(())
    }

    /// True if any carrier is configured.
    pub fn any_enabled(&self) -> bool {
        self.maildir.is_some() || self.has_network_pull()
    }

    /// Translate the configured carriers into canonical YP §27.5.2 URI
    /// strings for VSP discovery (Phase 1, 2026-05-14).
    ///
    /// Rules:
    /// - `maildir` / `imap` / `pop3` collapse to a single `email:<addr>`
    ///   entry (three inbound implementations of the same advertised
    ///   endpoint — the operator's mailbox).
    /// - All other carriers ride through `advertise` verbatim. ANTIE
    ///   does not parse scheme prefixes — `tot:` today, future schemes
    ///   like `qrcode:`, whatever, all pass through as opaque strings.
    /// - Order is deterministic: email first, then `advertise` entries
    ///   in declaration order.
    /// - Empty input (no carriers configured) returns an empty Vec.
    ///   Lambda's `set_carriers` logs a loud warning in that case.
    ///
    /// `identity_email` is the operator's `[identity].email` and is
    /// only consumed when an email-shaped carrier is enabled.
    pub fn to_uri_list(&self, identity_email: &str) -> Vec<String> {
        let mut uris = Vec::new();
        if self.maildir.is_some() || self.has_network_pull() {
            uris.push(format!("email:{}", identity_email));
        }
        uris.extend(self.advertise.iter().cloned());
        uris
    }
}

// ============================================================================
// Maildir Carrier Implementation
// ============================================================================

pub mod maildir_carrier {
    use super::*;
    use crate::maildir::Maildir;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    /// Maildir-based carrier
    pub struct MaildirCarrier {
        inbox: Arc<RwLock<Maildir>>,
        outbox: Arc<RwLock<Maildir>>,
    }
    
    impl MaildirCarrier {
        pub async fn new(inbox_path: &std::path::Path, outbox_path: &std::path::Path) -> Result<Self, AntieError> {
            let inbox = Maildir::open(inbox_path).await?;
            let outbox = Maildir::open(outbox_path).await?;
            
            Ok(Self {
                inbox: Arc::new(RwLock::new(inbox)),
                outbox: Arc::new(RwLock::new(outbox)),
            })
        }
    }
    
    #[async_trait]
    impl MailCarrier for MaildirCarrier {
        fn name(&self) -> &str {
            "maildir"
        }
        
        async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError> {
            let inbox = self.inbox.read().await;
            let paths = inbox.list_new().await?;
            
            let mut messages = Vec::new();
            for path in paths {
                let raw = inbox.read_message(&path).await?;
                let id = path.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                
                messages.push(IncomingMessage {
                    id,
                    raw,
                    source: path.display().to_string(),
                });
            }
            
            Ok(messages)
        }
        
        async fn mark_processed(&self, message_id: &str) -> Result<(), AntieError> {
            let inbox = self.inbox.read().await;
            let path = inbox.path().join("new").join(message_id);
            
            if path.exists() {
                inbox.mark_processed(&path).await?;
            }
            
            Ok(())
        }
        
        async fn mark_failed(&self, message_id: &str, _reason: &str) -> Result<(), AntieError> {
            // For maildir, we just mark as processed (move to cur/)
            // Could add a "failed" folder in the future
            self.mark_processed(message_id).await
        }
        
        async fn send(&self, _to: &str, raw_email: &[u8]) -> Result<(), AntieError> {
            let outbox = self.outbox.read().await;
            outbox.write_message(raw_email).await?;
            Ok(())
        }
    }
}

// ============================================================================
// POP3 Carrier
// ============================================================================

pub mod pop3_carrier {
    use super::*;
    use super::carrier_io::{self, CarrierStream};
    use tokio::io::BufReader;

    /// POP3-based carrier — inbound only.
    ///
    /// Connects to POP3 server, authenticates with USER/PASS, retrieves messages
    /// via RETR, marks as deleted via DELE. QUIT commits deletions.
    pub struct Pop3Carrier {
        server: String,
        port: u16,
        username: String,
        password: String,
        use_tls: bool,
    }

    impl Pop3Carrier {
        pub fn new(
            server: String,
            port: u16,
            username: String,
            password: String,
            use_tls: bool,
        ) -> Self {
            Self { server, port, username, password, use_tls }
        }

        /// Open a POP3 session (bounded connect + keepalive + TLS — the ONE
        /// `carrier_io::connect`, KI#114).
        async fn connect(&self) -> Result<Box<dyn CarrierStream>, AntieError> {
            carrier_io::connect("POP3", &self.server, self.port, self.use_tls).await
        }
    }

    /// Read a POP3 response line. +OK or -ERR prefix. EOF is an error (KI#114).
    async fn read_line(reader: &mut BufReader<&mut dyn CarrierStream>) -> Result<String, AntieError> {
        let mut line = String::new();
        carrier_io::read_line(reader, &mut line, "POP3").await?;
        Ok(line)
    }

    /// Send a POP3 command and read the response. ~~EOF read as `Ok("")`~~ —
    /// an EOF is an error now (KI#114, the shared reader).
    async fn command(stream: &mut dyn CarrierStream, cmd: &str) -> Result<String, AntieError> {
        carrier_io::write_all(stream, format!("{}\r\n", cmd).as_bytes(), "POP3").await?;
        let mut reader = BufReader::new(stream);
        let line = read_line(&mut reader).await?;
        if line.starts_with("-ERR") {
            return Err(AntieError::ConfigError(format!("POP3: {}", line.trim())));
        }
        Ok(line)
    }

    /// Read a multi-line POP3 response (terminated by ".\r\n").
    ///
    /// KI#114 (RULE 0 §4): ~~`read_line` result ignored — an EOF before the
    /// terminating "." read as an empty line forever~~ (the same spin as IMAP
    /// `fetch_message`; live on zeta's POP3 leg). The shared reader turns EOF
    /// into an error naming the message.
    async fn read_multiline(stream: &mut dyn CarrierStream, which: &str) -> Result<Vec<u8>, AntieError> {
        let mut reader = BufReader::new(stream);
        let mut data = Vec::new();
        let mut line = String::new();
        let what = format!("POP3 RETR {which}");
        loop {
            carrier_io::read_line(&mut reader, &mut line, &what).await?;
            if line.trim() == "." {
                break;
            }
            // Byte-stuff: lines starting with ".." have one dot removed
            let content = if line.starts_with("..") { &line[1..] } else { &line };
            data.extend_from_slice(content.as_bytes());
        }
        Ok(data)
    }

    #[async_trait]
    impl MailCarrier for Pop3Carrier {
        fn name(&self) -> &str {
            "pop3"
        }

        async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError> {
            let mut stream = self.connect().await?;
            let s = stream.as_mut();

            // Read greeting
            let mut reader = BufReader::new(s as &mut dyn CarrierStream);
            let _greeting = read_line(&mut reader).await?;
            drop(reader);

            // Authenticate
            command(s, &format!("USER {}", self.username)).await?;
            command(s, &format!("PASS {}", self.password)).await?;

            // LIST messages
            let stat_line = command(s, "STAT").await?;
            let count: usize = stat_line.split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let mut messages = Vec::new();
            for i in 1..=count {
                // RETR message
                command(s, &format!("RETR {}", i)).await?;
                let raw = read_multiline(s, &format!("msg={}", i)).await?;
                messages.push(IncomingMessage {
                    id: i.to_string(),
                    raw,
                    source: format!("pop3://{}:{}/{}", self.server, self.port, i),
                });
            }

            // Don't QUIT yet — mark_processed will DELE, then we QUIT
            // For now, QUIT to release the connection
            let _ = command(s, "QUIT").await;

            Ok(messages)
        }

        async fn mark_processed(&self, message_id: &str) -> Result<(), AntieError> {
            // POP3 DELE must happen in the same session as RETR.
            // In practice: connect, DELE the message, QUIT to commit.
            let mut stream = self.connect().await?;
            let s = stream.as_mut();

            let mut reader = BufReader::new(s as &mut dyn CarrierStream);
            let _greeting = read_line(&mut reader).await?;
            drop(reader);

            command(s, &format!("USER {}", self.username)).await?;
            command(s, &format!("PASS {}", self.password)).await?;
            command(s, &format!("DELE {}", message_id)).await?;
            let _ = command(s, "QUIT").await;

            Ok(())
        }

        async fn mark_failed(&self, _message_id: &str, _reason: &str) -> Result<(), AntieError> {
            // Leave message on server for retry — no action needed
            Ok(())
        }

        async fn send(&self, _to: &str, _raw_email: &[u8]) -> Result<(), AntieError> {
            Err(AntieError::ConfigError("POP3 cannot send — use SMTP for outbound".into()))
        }
    }
}

// ============================================================================
// IMAP Carrier
// ============================================================================

pub mod imap_carrier {
    use super::*;
    use super::carrier_io::{self, CarrierStream};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// IMAP-based carrier — inbound only.
    ///
    /// Connects to IMAP server, authenticates, SELECTs inbox, searches for
    /// UNSEEN messages, FETCHes them, and supports mark_processed via
    /// STORE +FLAGS \Seen + COPY to processed folder + EXPUNGE.
    pub struct ImapCarrier {
        server: String,
        port: u16,
        username: String,
        password: String,
        use_tls: bool,
        inbox_folder: String,
        /// IMAP tag counter (monotonic per session).
        tag_counter: AtomicU32,
    }

    impl ImapCarrier {
        pub fn new(
            server: String,
            port: u16,
            username: String,
            password: String,
            use_tls: bool,
            inbox_folder: String,
        ) -> Self {
            Self {
                server, port, username, password, use_tls,
                inbox_folder,
                tag_counter: AtomicU32::new(1),
            }
        }

        fn next_tag(&self) -> String {
            let n = self.tag_counter.fetch_add(1, Ordering::Relaxed);
            format!("A{:04}", n)
        }

        /// greeting → LOGIN → SELECT: the shared session preamble.
        async fn open_session(&self, s: &mut dyn CarrierStream) -> Result<(), AntieError> {
            read_greeting(s).await?;
            let tag = self.next_tag();
            imap_command(s, &tag, &format!("LOGIN {} {}",
                imap_quote(&self.username)?, imap_quote(&self.password)?)).await?;
            let tag = self.next_tag();
            imap_command(s, &tag, &format!("SELECT {}", imap_quote(&self.inbox_folder)?)).await?;
            Ok(())
        }

        /// IDLE until the server signals new mail, the recycle window lapses, or
        /// the connection drops. One authenticated session per call.
        ///
        /// Returns Ok(true) if the server pushed activity (`* n EXISTS` /
        /// `RECENT`), Ok(false) on a quiet recycle (RFC 2177 recommends
        /// re-issuing IDLE within ~29 min; we recycle earlier), and
        /// Err(IdleNotSupported…) if the server does not advertise IDLE — the
        /// gateway uses that specific failure to fall back to poll mode, loudly.
        ///
        /// KI#114 (b) — the quiet wait is cut into [`IDLE_BEAT_SLICE`] slices and
        /// `beat` is called on every quiet slice, so the account's heartbeat
        /// stays fresh through a legitimate 25-minute idle and a WEDGED session
        /// ages it. The slice waits on `fill_buf` (cancel-safe: a slice boundary
        /// never loses a half-read `* n EXISTS` line), then reads the line.
        pub async fn idle_wait(&self, recycle: std::time::Duration, beat: &(dyn Fn() + Send + Sync))
            -> Result<bool, AntieError>
        {
            let mut stream = self.connect().await?;
            let s = stream.as_mut();
            self.open_session(s).await?;

            // Capability check — declared fallback needs a definite answer, so
            // ask rather than try-and-guess from an error string.
            let tag = self.next_tag();
            let caps = imap_command(s, &tag, "CAPABILITY").await?;
            if !caps.iter().any(|l| l.starts_with("* CAPABILITY")
                    && l.split_whitespace().any(|w| w == "IDLE")) {
                return Err(AntieError::ConfigError(format!(
                    "IdleNotSupported: {}:{} does not advertise IDLE", self.server, self.port)));
            }

            // Anything already waiting? IDLE only pushes for arrivals AFTER it
            // starts, so mail landing between the caller's drain and this
            // session's IDLE would otherwise sit until the next recycle.
            let tag = self.next_tag();
            let hits = imap_command(s, &tag, "UID SEARCH UNSEEN").await?;
            if hits.iter().any(|l| l.starts_with("* SEARCH")
                    && l.split_whitespace().nth(2).is_some()) {
                let tag = self.next_tag();
                let _ = imap_command(s, &tag, "LOGOUT").await;
                return Ok(true);            // caller drains immediately
            }

            let tag = self.next_tag();
            carrier_io::write_all(s, format!("{} IDLE\r\n", tag).as_bytes(), "IMAP").await?;

            // The server answers "+ idling", then pushes untagged lines as
            // things happen. Wait for mail-shaped activity or the recycle
            // deadline, then DONE to end the idle cleanly either way.
            let mut reader = BufReader::new(&mut *s);
            let mut saw_mail = false;
            let deadline = tokio::time::Instant::now() + recycle;
            let mut line = String::new();
            loop {
                let slice_end = std::cmp::min(deadline, tokio::time::Instant::now() + IDLE_BEAT_SLICE);
                match tokio::time::timeout_at(slice_end, reader.fill_buf()).await {
                    Err(_elapsed) => {
                        if tokio::time::Instant::now() >= deadline { break; } // quiet recycle
                        beat();                                   // a quiet slice: still alive
                        continue;
                    }
                    Ok(Err(e)) => return Err(AntieError::ConfigError(format!("IMAP idle read: {}", e))),
                    // An idle close is the provider dropping a quiet session
                    // (Purelymail does) — not a response cut short, so not counted
                    // as carrier_eof_mid_response; still an error → reconnect.
                    Ok(Ok(buf)) if buf.is_empty() => return Err(AntieError::ConfigError(
                        "IMAP: server closed the idle connection".into())),
                    Ok(Ok(_)) => {}
                }
                carrier_io::read_line(&mut reader, &mut line, "IMAP idle").await?;
                let t = line.trim();
                if t.starts_with("+") { continue; }       // "+ idling"
                if t.starts_with("* ") && (t.ends_with("EXISTS") || t.ends_with("RECENT")) {
                    saw_mail = true;
                    break;
                }
                // other untagged noise (EXPUNGE, FLAGS…) — keep idling
            }

            carrier_io::write_all(s, b"DONE\r\n", "IMAP").await?;
            // Read until the tagged completion of IDLE; best-effort LOGOUT. An
            // EOF here is still an EOF mid-response (counted) — then stop.
            let mut reader = BufReader::new(&mut *s);
            loop {
                match carrier_io::read_line(&mut reader, &mut line, "IMAP idle DONE").await {
                    Err(_) => break,
                    Ok(_) => { if line.trim().starts_with(&tag) { break; } }
                }
            }
            let tag = self.next_tag();
            let _ = imap_command(s, &tag, "LOGOUT").await;
            Ok(saw_mail)
        }

        /// Open an IMAP connection (optionally TLS) — the ONE bounded
        /// `carrier_io::connect` (TCP keepalive included: IDLE holds the socket
        /// quiet for minutes, and a NAT that drops the quiet flow left a
        /// half-dead socket whose EXISTS push was lost — measured 2026-08-21 on
        /// zeta and iota; keepalive makes the dead session fail LOUDLY).
        async fn connect(&self) -> Result<Box<dyn CarrierStream>, AntieError> {
            carrier_io::connect("IMAP", &self.server, self.port, self.use_tls).await
        }
    }

    /// KI#114 (b) — the longest an IDLE wait goes without calling `beat`.
    pub const IDLE_BEAT_SLICE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Quote a string per RFC 9051 §4.3 for use as an IMAP astring argument.
    /// Refuses CR/LF outright — a newline in a credential is command injection,
    /// not a password.
    fn imap_quote(s: &str) -> Result<String, AntieError> {
        if s.contains('\r') || s.contains('\n') {
            return Err(AntieError::ConfigError(
                "IMAP argument contains CR/LF — refusing (command injection)".into()));
        }
        Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
    }

    /// Send an IMAP command and read lines until we get the tagged response.
    ///
    /// The tagged line must be exactly `<tag> OK …` to succeed. The old parser
    /// matched `NO`/`BAD` as SUBSTRINGS anywhere in the line, so a benign
    /// completion text containing them ("NOOP completed") read as an error.
    async fn imap_command(stream: &mut dyn CarrierStream, tag: &str, cmd: &str)
        -> Result<Vec<String>, AntieError>
    {
        carrier_io::write_all(stream, format!("{} {}\r\n", tag, cmd).as_bytes(), "IMAP").await?;

        let mut reader = BufReader::new(stream);
        let mut lines = Vec::new();
        let mut line = String::new();
        loop {
            carrier_io::read_line(&mut reader, &mut line, "IMAP").await?;
            let trimmed = line.trim().to_string();
            if let Some(rest) = trimmed.strip_prefix(tag) {
                if let Some(status) = rest.strip_prefix(' ') {
                    lines.push(trimmed.clone());
                    return if status.starts_with("OK") {
                        Ok(lines)
                    } else {
                        Err(AntieError::ConfigError(format!("IMAP: {}", trimmed)))
                    };
                }
            }
            lines.push(trimmed);
        }
    }

    /// Read the server greeting (untagged * OK).
    async fn read_greeting(stream: &mut dyn CarrierStream) -> Result<(), AntieError> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        carrier_io::read_line(&mut reader, &mut line, "IMAP greeting").await?;
        if !line.contains("OK") {
            return Err(AntieError::ConfigError(format!("IMAP bad greeting: {}", line.trim())));
        }
        Ok(())
    }

    /// Fetch a single message body by UID. Returns raw bytes.
    ///
    /// KI#114 (RULE 0 §4) — ~~the `read_line` result was ignored; an EOF (`Ok(0)`)
    /// read as an empty line: inside a literal `literal_remaining` never reached
    /// 0, outside it the tag never matched — an infinite loop that, over TLS
    /// after close_notify, never yielded (one worker at 100% CPU, zeta
    /// 2026-08-26, 11.5 h)~~. Now: lines through the shared EOF-checking reader;
    /// the literal is read BYTE-EXACT with `carrier_io::read_exact` (no UTF-8
    /// assumption), and an EOF names the uid and the missing bytes, e.g.
    /// `IMAP FETCH: connection closed by server mid-response uid=7 (literal
    /// 4012 bytes short)` — the first production sighting confirms the trigger.
    /// The earlier "a lock held by the spinner starved the siblings"
    /// speculation is not needed: idle tokio workers park in futex anyway
    /// (KI#114 investigation §3 row 4).
    async fn fetch_message(stream: &mut dyn CarrierStream, tag: &str, uid: &str)
        -> Result<Vec<u8>, AntieError>
    {
        // BODY.PEEK[], never BODY[]: a plain BODY[] fetch implicitly sets \Seen,
        // and check_new finds mail via SEARCH UNSEEN — so a crash between fetch
        // and maildir delivery would make the message invisible FOREVER (silent
        // mail loss). PEEK leaves flags untouched; \Seen is set in
        // mark_processed AFTER the inbox write, mirroring POP3's RETR-then-DELE.
        carrier_io::write_all(stream, format!("{} UID FETCH {} BODY.PEEK[]\r\n", tag, uid).as_bytes(), "IMAP").await?;

        let mut reader = BufReader::new(stream);
        let mut data = Vec::new();
        let mut line = String::new();
        let detail = format!("uid={uid}");
        let what = format!("IMAP FETCH {detail}");

        loop {
            carrier_io::read_line(&mut reader, &mut line, &what).await?;
            let trimmed = line.trim();
            if trimmed.starts_with(tag) {
                break;
            }

            // Literal: "* N FETCH ... {SIZE}" — then exactly SIZE bytes follow.
            if trimmed.ends_with('}') {
                if let Some(pos) = trimmed.rfind('{') {
                    if let Ok(size) = trimmed[pos + 1..trimmed.len() - 1].parse::<usize>() {
                        let mut lit = vec![0u8; size];
                        carrier_io::read_exact(&mut reader, &mut lit, "IMAP FETCH", &detail).await?;
                        data.extend_from_slice(&lit);
                    }
                }
            }
        }

        Ok(data)
    }

    /// KI#114 — the EXACT zeta shape: a stream that returns 0 bytes at once,
    /// forever, without touching any tokio resource (OpenSSL after
    /// close_notify), so the reading future never returns `Pending` and no
    /// `tokio::time::timeout` can fire. Run on its own OS thread with its own
    /// current-thread runtime; the test waits on a channel with a 5 s
    /// `recv_timeout`. Pre-fix the thread spins at 100% and the test fails at
    /// 5 s (the thread leaks until the process exits); post-fix it errors at
    /// once. MUTATION (run 2026-10-01): delete the EOF arm of
    /// `carrier_io::read_line` ⇒ red ("SPUN").
    #[cfg(test)]
    mod no_yield_tests {
        use super::*;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct EofForever;
        impl tokio::io::AsyncRead for EofForever {
            fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut tokio::io::ReadBuf<'_>)
                -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
        }
        impl tokio::io::AsyncWrite for EofForever {
            fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
                Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
        }
        impl CarrierStream for EofForever {}

        #[test]
        fn fetch_on_a_never_yielding_eof_stream_errors_instead_of_spinning() {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                let r = rt.block_on(async { fetch_message(&mut EofForever, "A0001", "7").await });
                let _ = tx.send(r.map(|d| d.len()).map_err(|e| format!("{e}")));
            });
            match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(Err(e)) => assert!(e.contains("closed") && e.contains("uid=7"), "names the uid: {e}"),
                Ok(Ok(n)) => panic!("EOF must be an error, got {n} bytes"),
                Err(_) => panic!("KI#114: fetch_message SPUN on a never-yielding EOF stream (5 s)"),
            }
        }
    }

    #[async_trait]
    impl MailCarrier for ImapCarrier {
        fn name(&self) -> &str {
            "imap"
        }

        async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError> {
            let mut stream = self.connect().await?;
            let s = stream.as_mut();
            self.open_session(s).await?;

            // SEARCH UNSEEN
            let tag = self.next_tag();
            let search_lines = imap_command(s, &tag, "UID SEARCH UNSEEN").await?;

            // Parse UIDs from "* SEARCH 1 2 3" line
            let mut uids = Vec::new();
            for line in &search_lines {
                if line.starts_with("* SEARCH") {
                    for part in line.split_whitespace().skip(2) {
                        uids.push(part.to_string());
                    }
                }
            }

            let mut messages = Vec::new();
            for uid in &uids {
                let tag = self.next_tag();
                let raw = fetch_message(s, &tag, uid).await?;
                messages.push(IncomingMessage {
                    id: uid.clone(),
                    raw,
                    source: format!("imap://{}:{}/{}/{}", self.server, self.port, self.inbox_folder, uid),
                });
            }

            // LOGOUT
            let tag = self.next_tag();
            let _ = imap_command(s, &tag, "LOGOUT").await;

            Ok(messages)
        }

        async fn mark_processed(&self, message_id: &str) -> Result<(), AntieError> {
            let mut stream = self.connect().await?;
            let s = stream.as_mut();
            self.open_session(s).await?;

            // Same shape as POP3 (design decision 2026-08-21: no separate processed
            // store — the ONE local maildir funnel is the record): the message
            // is already written to inbox/new/, so just delete it upstream.
            let tag = self.next_tag();
            imap_command(s, &tag, &format!("UID STORE {} +FLAGS (\\Deleted)", message_id)).await?;

            let tag = self.next_tag();
            imap_command(s, &tag, "EXPUNGE").await?;

            let tag = self.next_tag();
            let _ = imap_command(s, &tag, "LOGOUT").await;

            Ok(())
        }

        async fn mark_failed(&self, _message_id: &str, _reason: &str) -> Result<(), AntieError> {
            // Leave in inbox for manual intervention
            Ok(())
        }

        async fn send(&self, _to: &str, _raw_email: &[u8]) -> Result<(), AntieError> {
            Err(AntieError::ConfigError("IMAP send not supported — use SMTP for outbound".into()))
        }
    }
}

// ============================================================================
// SMTP Carrier for Outbound
// ============================================================================

pub mod smtp_carrier {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use super::carrier_io::{self, CarrierStream};
    use tokio::io::BufReader;

    /// SMTP carrier for outbound mail.
    ///
    /// Raw TCP/TLS SMTP — no lettre. Sends EHLO/[AUTH LOGIN]/MAIL/RCPT/DATA/QUIT
    /// manually (lettre's AsyncSmtpTransport returned Ok while silently dropping
    /// the DATA). TLS is FORCED whenever credentials are present — see
    /// `AXIOM_DESIGN_PublicMailCarriers.md` §3.7 (AUTH ⟹ TLS); the only plain
    /// path is the no-auth trusted loopback (FATMAMA / localhost).
    pub struct SmtpCarrier {
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        use_tls: bool,
        from_address: String,
    }

    impl SmtpCarrier {
        pub fn new(
            server: String,
            port: u16,
            username: Option<String>,
            password: Option<String>,
            use_tls: bool,
            from_address: String,
        ) -> Self {
            Self { server, port, username, password, use_tls, from_address }
        }

        /// Open an SMTP session — plain TCP, or TLS-wrapped when `use_tls`
        /// (implicit TLS, 465-style); the no-auth loopback (FATMAMA /
        /// localhost) runs plain. The ONE bounded `carrier_io::connect`
        /// (KI#114: connect/handshake timeouts + keepalive).
        async fn connect(&self) -> Result<Box<dyn CarrierStream>, AntieError> {
            carrier_io::connect("SMTP", &self.server, self.port, self.use_tls).await
        }
    }

    #[async_trait]
    impl MailCarrier for SmtpCarrier {
        fn name(&self) -> &str {
            "smtp"
        }

        async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError> {
            // SMTP is outbound-only — no inbound messages
            Ok(vec![])
        }

        async fn mark_processed(&self, _message_id: &str) -> Result<(), AntieError> {
            Ok(()) // No-op for outbound-only carrier
        }

        async fn mark_failed(&self, _message_id: &str, _reason: &str) -> Result<(), AntieError> {
            Ok(()) // No-op for outbound-only carrier
        }

        async fn send(&self, to: &str, raw_email: &[u8]) -> Result<(), AntieError> {
            // Raw TCP/TLS SMTP — no lettre (its AsyncSmtpTransport returned Ok
            // while silently dropping the DATA). EHLO/[AUTH LOGIN]/MAIL/RCPT/DATA.
            //
            // AUTH ⟹ TLS (AXIOM_DESIGN_PublicMailCarriers.md §3.7): AUTH LOGIN
            // sends the password as base64 (encoding, not encryption), so
            // credentials must never cross a plaintext link. A creds-with-
            // use_tls=false config is a misconfiguration — refused here, never
            // silently downgraded. The only plain path is the no-auth loopback.
            let has_creds = self.username.is_some() && self.password.is_some();
            if has_creds && !self.use_tls {
                return Err(AntieError::ConfigError(
                    "SMTP credentials set but use_tls=false — refusing to send AUTH in plaintext (AUTH implies TLS)".into()));
            }

            let stream = self.connect().await?;
            let (rd, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(rd);
            let mut line = String::new();

            // Read one COMPLETE SMTP reply. Real servers send multi-line replies
            // ("250-CAP\r\n" … "250 END\r\n"); the final line has a SPACE (not
            // '-') as the 4th byte. Reading only the first line (as the old code
            // did) desyncs against any real provider — it worked only because
            // FATMAMA returns a single-line EHLO.
            macro_rules! read_reply {
                () => {{
                    loop {
                        // KI#114: the shared reader — EOF is an error, each
                        // read bounded (was a local copy of the EOF rule).
                        carrier_io::read_line(&mut reader, &mut line, "SMTP").await?;
                        let ok = line.starts_with('2') || line.starts_with('3');
                        let more = line.as_bytes().get(3) == Some(&b'-');
                        if !more {
                            if !ok {
                                return Err(AntieError::ConfigError(
                                    format!("SMTP error: {}", line.trim())));
                            }
                            break;
                        }
                    }
                }};
            }
            macro_rules! send_cmd {
                ($bytes:expr) => {{
                    carrier_io::write_all(&mut writer, $bytes, "SMTP").await?;
                }};
            }

            read_reply!(); // 220 greeting
            send_cmd!(format!("EHLO {}\r\n", self.server).as_bytes());
            read_reply!();

            // AUTH LOGIN — only when credentials are set (TLS already established).
            if has_creds {
                let user = self.username.as_deref().unwrap_or_default();
                let pass = self.password.as_deref().unwrap_or_default();
                send_cmd!(b"AUTH LOGIN\r\n");
                read_reply!(); // 334 (base64 "Username:")
                send_cmd!(format!("{}\r\n", BASE64.encode(user)).as_bytes());
                read_reply!(); // 334 (base64 "Password:")
                send_cmd!(format!("{}\r\n", BASE64.encode(pass)).as_bytes());
                read_reply!(); // 235 authentication successful
            }

            send_cmd!(format!("MAIL FROM:<{}>\r\n", self.from_address).as_bytes());
            read_reply!();
            send_cmd!(format!("RCPT TO:<{}>\r\n", to).as_bytes());
            read_reply!();
            send_cmd!(b"DATA\r\n");
            read_reply!(); // 354
            send_cmd!(raw_email);
            send_cmd!(b"\r\n.\r\n"); // `carrier_io::write_all` flushes
            read_reply!(); // 250 OK
            send_cmd!(b"QUIT\r\n");
            Ok(())
        }
    }
}

// ============================================================================
// Split Carrier — outbound router (AXIOM_DESIGN_AntieOutboundSplit.md)
// ============================================================================

pub mod split_carrier {
    use super::*;

    /// True if `to` is a **local** recipient — its domain (the part after the
    /// last `@`, before any wallet_id `/…hex` tail) is exactly `axiom` or
    /// `axiom.internal`. Everything else is external.
    pub(crate) fn recipient_is_local(to: &str) -> bool {
        let domain = match to.rfind('@') {
            Some(i) => &to[i + 1..],
            None => return false,
        };
        let domain = domain.split('/').next().unwrap_or(domain);
        domain == "axiom" || domain == "axiom.internal"
    }

    /// Outbound router: `@axiom` / `@axiom.internal` → the on-box FATMAMA
    /// (`local`); every other domain → the optional `external` relay.
    /// Outbound-only; ANTIE does no MTA routing beyond this binary split.
    pub struct SplitCarrier {
        local: super::smtp_carrier::SmtpCarrier,
        external: Option<super::smtp_carrier::SmtpCarrier>,
    }

    impl SplitCarrier {
        pub fn new(
            local: super::smtp_carrier::SmtpCarrier,
            external: Option<super::smtp_carrier::SmtpCarrier>,
        ) -> Self {
            Self { local, external }
        }
    }

    #[async_trait]
    impl MailCarrier for SplitCarrier {
        fn name(&self) -> &str { "split" }

        async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError> {
            Ok(vec![]) // outbound-only
        }
        async fn mark_processed(&self, _message_id: &str) -> Result<(), AntieError> { Ok(()) }
        async fn mark_failed(&self, _message_id: &str, _reason: &str) -> Result<(), AntieError> { Ok(()) }

        async fn send(&self, to: &str, raw_email: &[u8]) -> Result<(), AntieError> {
            if recipient_is_local(to) {
                self.local.send(to, raw_email).await
            } else if let Some(ref ext) = self.external {
                ext.send(to, raw_email).await
            } else {
                Err(AntieError::ConfigError(format!(
                    "no external relay configured ([outbound.external]) — cannot \
                     deliver to external recipient {}", to
                )))
            }
        }
    }
}

// (TCP + WebSocket carriers removed 2026-05-21 — both transports
// are now handled outside ANTIE. Operators declaring direct-delivery
// transports go through CarriersConfig::advertise.)

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    /// `maildir` + `imap` + `pop3` are three implementations of the
    /// same advertised endpoint — they collapse to a single
    /// `email:<identity>` URI regardless of how many are configured.
    #[test]
    fn to_uri_list_email_carriers_collapse() {
        let cfg = CarriersConfig {
            maildir: Some(MaildirConfig {
                inbox:  std::path::PathBuf::from("/tmp/in"),
                outbox: std::path::PathBuf::from("/tmp/out"),
            }),
            imap: vec![(ImapConfig {
                enabled: true,
                server: "imap.example.com".into(), port: 993,
                username: "alpha".into(), password: "x".into(),
                use_tls: true,
                inbox_folder: "INBOX".into(), use_idle: true,
            })],
            ..Default::default()
        };
        let uris = cfg.to_uri_list("alpha@axiom.network");
        assert_eq!(uris, vec!["email:alpha@axiom.network".to_string()]);
    }

    // Inbox-funnel invariant (AXIOM_DESIGN_AntieInboxFunnel.md §4): pop3/imap
    // deliver into the maildir inbox, so a maildir carrier MUST be configured
    // when either is enabled.

    #[test]
    fn validate_maildir_only_ok() {
        let cfg = CarriersConfig {
            maildir: Some(MaildirConfig {
                inbox:  std::path::PathBuf::from("/tmp/in"),
                outbox: std::path::PathBuf::from("/tmp/out"),
            }),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_pop3_without_maildir_rejected() {
        let cfg = CarriersConfig {
            pop3: vec![(Pop3Config {
                enabled: true,
                server: "pop3.example.com".into(), port: 995,
                username: "alpha".into(), password: "x".into(), use_tls: true,
                spam_entropy_threshold: None,
            })],
            ..Default::default()
        };
        assert!(cfg.validate().is_err(), "pop3 without maildir must be rejected");
    }

    #[test]
    fn validate_imap_without_maildir_rejected() {
        let cfg = CarriersConfig {
            imap: vec![(ImapConfig {
                enabled: true,
                server: "imap.example.com".into(), port: 993,
                username: "alpha".into(), password: "x".into(), use_tls: true,
                inbox_folder: "INBOX".into(), use_idle: true,
            })],
            ..Default::default()
        };
        assert!(cfg.validate().is_err(), "imap without maildir must be rejected");
    }

    #[test]
    fn validate_pop3_with_maildir_ok() {
        let cfg = CarriersConfig {
            maildir: Some(MaildirConfig {
                inbox:  std::path::PathBuf::from("/tmp/in"),
                outbox: std::path::PathBuf::from("/tmp/out"),
            }),
            pop3: vec![(Pop3Config {
                enabled: true,
                server: "pop3.example.com".into(), port: 995,
                username: "alpha".into(), password: "x".into(), use_tls: true,
                spam_entropy_threshold: None,
            })],
            ..Default::default()
        };
        assert!(cfg.validate().is_ok(), "pop3 + maildir satisfies the funnel invariant");
    }

    // Outbound split (AXIOM_DESIGN_AntieOutboundSplit.md): local vs external
    // is decided by the recipient DOMAIN, ignoring any wallet_id /hex tail.
    #[test]
    fn split_recipient_is_local_by_domain() {
        use split_carrier::recipient_is_local;
        // local — @axiom / @axiom.internal, bare or with a wallet_id /hex tail
        assert!(recipient_is_local("alpha@axiom"));            // validator
        assert!(recipient_is_local("s2r123@axiom"));           // wallet, bare
        assert!(recipient_is_local("alice@axiom/6c8f19ab"));   // wallet_id with hex
        assert!(recipient_is_local("dev1@axiom.internal"));    // dev fund
        assert!(recipient_is_local("dev1@axiom.internal/deadbeef"));
        // external — real domains, look-alikes, or malformed → NOT local
        assert!(!recipient_is_local("bob@example.com"));
        assert!(!recipient_is_local("x@axiom.network"));       // not exactly axiom
        assert!(!recipient_is_local("x@axiom.evil.com"));
        assert!(!recipient_is_local("no-at-sign"));
    }

    /// Operator-declared `advertise = [...]` URIs ride through the
    /// discovery list verbatim. ANTIE does NOT parse the scheme
    /// prefix — any scheme (`tot:`, `fatmama:`, future `qrcode:` …)
    /// works without an ANTIE source change. Email floor still
    /// enforced by `validate()` (covered separately).
    #[test]
    fn advertise_list_rides_through_to_uri_list_verbatim() {
        let cfg = CarriersConfig {
            maildir: Some(MaildirConfig {
                inbox:  std::path::PathBuf::from("/tmp/in"),
                outbox: std::path::PathBuf::from("/tmp/out"),
            }),
            advertise: vec![
                "tot:axiom-dev.mooo.com:7400".into(),
                "fatmama:axiom-dev.mooo.com:2525".into(),
                "qrcode:https://example.com/qr/alpha".into(), // future scheme
            ],
            ..Default::default()
        };
        let uris = cfg.to_uri_list("alpha@axiom.network");
        assert_eq!(uris, vec![
            "email:alpha@axiom.network".to_string(),
            "tot:axiom-dev.mooo.com:7400".to_string(),
            "fatmama:axiom-dev.mooo.com:2525".to_string(),
            "qrcode:https://example.com/qr/alpha".to_string(),
        ]);
        assert!(cfg.validate().is_ok(), "maildir email floor satisfied");
    }

    /// `[carriers] advertise = [...]` parses cleanly from TOML.
    /// Operator-facing shape: a flat array of URI strings.
    #[test]
    fn advertise_deserialises_from_toml() {
        let toml_str = r#"
            [carriers.maildir]
            inbox  = "/tmp/in"
            outbox = "/tmp/out"

            [carriers]
            advertise = [
                "fatmama:axiom-dev.mooo.com:2525",
                "tot:axiom-dev.mooo.com:7400",
            ]
        "#;
        #[derive(serde::Deserialize)]
        struct Wrap { carriers: CarriersConfig }
        let w: Wrap = toml::from_str(toml_str).expect("parses");
        assert_eq!(w.carriers.advertise, vec![
            "fatmama:axiom-dev.mooo.com:2525".to_string(),
            "tot:axiom-dev.mooo.com:7400".to_string(),
        ]);
        let uris = w.carriers.to_uri_list("alpha@axiom.network");
        assert_eq!(uris, vec![
            "email:alpha@axiom.network".to_string(),
            "fatmama:axiom-dev.mooo.com:2525".to_string(),
            "tot:axiom-dev.mooo.com:7400".to_string(),
        ]);
    }

    /// Older configs without `advertise =` parse fine and emit
    /// only the email URI — cross-version compat.
    #[test]
    fn missing_advertise_field_back_compat() {
        let toml_str = r#"
            [carriers.maildir]
            inbox  = "/tmp/in"
            outbox = "/tmp/out"
        "#;
        #[derive(serde::Deserialize)]
        struct Wrap { carriers: CarriersConfig }
        let w: Wrap = toml::from_str(toml_str).expect("parses without advertise");
        assert!(w.carriers.advertise.is_empty());
        let uris = w.carriers.to_uri_list("alpha@axiom.network");
        assert_eq!(uris, vec!["email:alpha@axiom.network".to_string()]);
    }

    /// Email-only is the production floor: any one of maildir / imap
    /// / pop3 satisfies validate().
    #[test]
    fn maildir_only_passes_validation() {
        let cfg = CarriersConfig {
            maildir: Some(MaildirConfig {
                inbox:  std::path::PathBuf::from("/tmp/in"),
                outbox: std::path::PathBuf::from("/tmp/out"),
            }),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    /// No email carrier → rejected. `advertise = [...]` alone is
    /// NOT enough — those are advertise-only, no inbound delivery.
    #[test]
    fn no_email_carrier_fails_validation() {
        let cfg = CarriersConfig {
            advertise: vec!["tot:axiom-dev.mooo.com:7400".into()],
            ..Default::default()
        };
        assert!(cfg.validate().is_err(),
            "advertise-only must fail — at least one email-shaped carrier required");
    }

    /// Empty configuration fails validation.
    #[test]
    fn empty_config_fails_validation() {
        let cfg = CarriersConfig::default();
        assert!(cfg.validate().is_err());
    }

    /// AUTH ⟹ TLS invariant (AXIOM_DESIGN_PublicMailCarriers.md §3.7): a carrier
    /// with credentials but use_tls=false must REFUSE — before any connect —
    /// rather than send the password in plaintext. No network needed; the guard
    /// fires first.
    #[tokio::test]
    async fn smtp_refuses_auth_without_tls() {
        let c = smtp_carrier::SmtpCarrier::new(
            "127.0.0.1".into(), 1,                       // port irrelevant: guard fires first
            Some("axiom000alpha@example.com".into()),
            Some("secret".into()),
            false,                                        // use_tls = false
            "axiom000alpha@example.com".into(),
        );
        let err = c.send("to@example.com", b"body").await
            .expect_err("must refuse plaintext AUTH");
        let msg = format!("{:?}", err);
        assert!(msg.contains("AUTH implies TLS"),
            "expected AUTH⟹TLS refusal, got: {msg}");
    }

    /// Real providers return a MULTI-LINE EHLO ("250-CAP" … "250 END"). The old
    /// single-line reader desynced on that (worked only with FATMAMA's one-line
    /// reply). This drives the new reader through a mock that speaks multi-line,
    /// on the plain no-auth (loopback) path.
    #[tokio::test]
    async fn smtp_send_handles_multiline_ehlo() {
        use tokio::net::TcpListener;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            sock.write_all(b"220 mock ESMTP\r\n").await.unwrap();
            let _ = sock.read(&mut buf).await.unwrap();  // EHLO
            sock.write_all(b"250-mock hi\r\n250-SIZE 52428800\r\n250 OK\r\n").await.unwrap();
            let _ = sock.read(&mut buf).await.unwrap();  // MAIL FROM
            sock.write_all(b"250 OK\r\n").await.unwrap();
            let _ = sock.read(&mut buf).await.unwrap();  // RCPT TO
            sock.write_all(b"250 OK\r\n").await.unwrap();
            let _ = sock.read(&mut buf).await.unwrap();  // DATA
            sock.write_all(b"354 go\r\n").await.unwrap();
            // read until the DATA terminator "\r\n.\r\n" (robust to segmentation)
            let mut acc = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(5).any(|w| w == b"\r\n.\r\n") { break; }
            }
            sock.write_all(b"250 queued\r\n").await.unwrap();
            let _ = sock.read(&mut buf).await;           // QUIT (best effort)
        });
        let c = smtp_carrier::SmtpCarrier::new(
            "127.0.0.1".into(), port, None, None, false, "from@axiom".into());
        c.send("to@axiom", b"SGVsbG8=").await
            .expect("send should complete against a multi-line EHLO");
        let _ = server.await;
    }

    // ── IMAP: mock-server tests (plaintext on loopback — the validate()
    //    exemption exists exactly so these can run without TLS scaffolding) ──

    /// Minimal scripted IMAP server: sends greeting, then per client command
    /// line sends the scripted replies in order. Returns what the client sent.
    async fn mock_imap(script: Vec<Vec<String>>) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::net::TcpListener;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut reader = BufReader::new(r);
            let mut got = Vec::new();
            w.write_all(b"* OK mock IMAP ready\r\n").await.unwrap();
            for replies in script {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 { break; }
                got.push(line.trim().to_string());
                let tag = line.split_whitespace().next().unwrap_or("*").to_string();
                for rep in replies {
                    let rep = rep.replace("{TAG}", &tag);
                    w.write_all(format!("{}\r\n", rep).as_bytes()).await.unwrap();
                }
            }
            got
        });
        (port, handle)
    }

    fn imap_client(port: u16) -> imap_carrier::ImapCarrier {
        imap_carrier::ImapCarrier::new(
            "127.0.0.1".into(), port,
            "user@example.org".into(), r#"pa ss"wo\rd"#.into(),
            false, "INBOX".into())
    }

    /// The old parser flagged any tagged line CONTAINING "NO"/"BAD" — so an OK
    /// completion mentioning them read as an error. Strict parse must accept.
    #[tokio::test]
    async fn imap_tagged_ok_containing_no_substring_is_success() {
        let (port, server) = mock_imap(vec![
            vec!["{TAG} OK NOOP-like LOGIN done (NO BAD words here)".into()],
            vec!["{TAG} OK [READ-WRITE] SELECT done".into()],
            vec!["* SEARCH".into(), "{TAG} OK Search done".into()],
            vec!["{TAG} OK Logout done".into()],
        ]).await;
        let msgs = imap_client(port).check_new().await
            .expect("OK lines containing the substrings NO/BAD must not error");
        assert!(msgs.is_empty());
        let _ = server.await;
    }

    /// And a genuine tagged NO must still fail.
    #[tokio::test]
    async fn imap_tagged_no_is_error() {
        let (port, server) = mock_imap(vec![
            vec!["{TAG} NO [AUTHENTICATIONFAILED] bad creds".into()],
        ]).await;
        imap_client(port).check_new().await
            .expect_err("a tagged NO must be an error");
        let _ = server.await;
    }

    /// LOGIN arguments are quoted (password here contains space, quote and
    /// backslash) and FETCH uses BODY.PEEK[] so \Seen is never set pre-delivery.
    #[tokio::test]
    async fn imap_login_quoted_and_fetch_peeks() {
        let (port, server) = mock_imap(vec![
            vec!["{TAG} OK login".into()],
            vec!["{TAG} OK select".into()],
            vec!["* SEARCH 7".into(), "{TAG} OK search".into()],
            vec!["* 7 FETCH (UID 7 BODY[] {5}".into(), "hello".into(),
                 ")".into(), "{TAG} OK fetch".into()],
            vec!["{TAG} OK logout".into()],
        ]).await;
        let msgs = imap_client(port).check_new().await.expect("fetch flow");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, "7");
        let got = server.await.unwrap();
        let login = got.iter().find(|l| l.contains("LOGIN")).expect("saw LOGIN");
        assert!(login.contains(r#""user@example.org" "pa ss\"wo\\rd""#),
                "LOGIN must quote+escape args, got: {login}");
        let fetch = got.iter().find(|l| l.contains("FETCH")).expect("saw FETCH");
        assert!(fetch.contains("BODY.PEEK[]"),
                "FETCH must use BODY.PEEK[] (BODY[] sets \\Seen and a crash \
                 before delivery loses the message forever), got: {fetch}");
        let _ = server;
    }

    /// IDLE primary: server advertises IDLE, pushes EXISTS, client wakes.
    #[tokio::test]
    async fn imap_idle_wakes_on_exists() {
        let (port, server) = mock_imap(vec![
            vec!["{TAG} OK login".into()],
            vec!["{TAG} OK select".into()],
            vec!["* CAPABILITY IMAP4rev1 IDLE".into(), "{TAG} OK caps".into()],
            vec!["* SEARCH".into(), "{TAG} OK search".into()],  // pre-IDLE check: empty
            vec!["+ idling".into(), "* 3 EXISTS".into()],   // push after IDLE
            vec!["{TAG} OK logout".into()],                  // DONE→completion read is lenient
        ]).await;
        let saw = imap_client(port)
            .idle_wait(std::time::Duration::from_secs(20), &|| {}).await
            .expect("idle flow");
        assert!(saw, "EXISTS push must report mail waiting");
        let _ = server.await;
    }

    /// Declared fallback: no IDLE capability → the distinguishable error the
    /// gateway uses to switch to poll mode (loudly). Never a silent guess.
    #[tokio::test]
    async fn imap_idle_missing_capability_is_distinguishable() {
        let (port, server) = mock_imap(vec![
            vec!["{TAG} OK login".into()],
            vec!["{TAG} OK select".into()],
            vec!["* CAPABILITY IMAP4rev1 LITERAL+".into(), "{TAG} OK caps".into()],
        ]).await;
        let err = imap_client(port)
            .idle_wait(std::time::Duration::from_secs(5), &|| {}).await
            .expect_err("must refuse to idle without the capability");
        assert!(format!("{err}").contains("IdleNotSupported"),
                "the gateway keys its declared fallback on this marker");
        let _ = server.await;
    }

    /// Mail already waiting when the session opens must short-circuit to a
    /// drain — IDLE only pushes for arrivals AFTER it starts, so entering IDLE
    /// here would strand the message until the next recycle.
    #[tokio::test]
    async fn imap_idle_short_circuits_when_mail_already_waiting() {
        let (port, server) = mock_imap(vec![
            vec!["{TAG} OK login".into()],
            vec!["{TAG} OK select".into()],
            vec!["* CAPABILITY IMAP4rev1 IDLE".into(), "{TAG} OK caps".into()],
            vec!["* SEARCH 4 9".into(), "{TAG} OK search".into()],  // backlog!
            vec!["{TAG} OK logout".into()],
        ]).await;
        let saw = imap_client(port)
            .idle_wait(std::time::Duration::from_secs(5), &|| {}).await
            .expect("pre-idle backlog flow");
        assert!(saw, "waiting mail must return true WITHOUT entering IDLE");
        let _ = server.await;
    }

    // ── KI#114 (a) — EOF mid-response is an ERROR, never a spin ──────────
    //
    // `mock_imap` drops the socket when its script runs out: that drop IS the
    // server closing mid-FETCH. Each test is bounded (5 s) so the pre-fix code
    // fails "timed out" instead of hanging the suite (plain TCP makes a
    // syscall per pass, so tokio co-op still lets the timeout fire).
    // MUTATIONS (run 2026-10-01): `carrier_io::read_line` reads EOF as an empty
    // line again (`Ok(Ok(0)) => Ok(0)`) ⇒ red: `imap_fetch_eof_before_literal_
    // is_an_error`, `pop3_retr_eof_mid_multiline_is_an_error`,
    // `imap_carrier::no_yield_tests::…` (and the IDLE tests then HANG in the
    // post-DONE drain — the defect itself); `carrier_io::read_exact` retries
    // on EOF (`continue`) ⇒ red: `imap_fetch_eof_mid_literal_is_an_error_not_a_spin`.

    /// The FETCH literal is cut short: the error names the uid and how many
    /// literal bytes were still owed — the string that, seen once in
    /// production, confirms the KI#114 trigger.
    #[tokio::test]
    async fn imap_fetch_eof_mid_literal_is_an_error_not_a_spin() {
        let before = carrier_io::eof_mid_response();
        let (port, server) = mock_imap(vec![
            vec!["{TAG} OK login".into()],
            vec!["{TAG} OK select".into()],
            vec!["* SEARCH 7".into(), "{TAG} OK search".into()],
            vec!["* 1 FETCH (UID 7 BODY[] {4096}".into(), "partial".into()],
        ]).await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), imap_client(port).check_new()).await;
        let e = match r {
            Ok(Err(e)) => format!("{e}"),
            Ok(Ok(m)) => panic!("an EOF mid-literal must be an error, got {} message(s)", m.len()),
            Err(_) => panic!("KI#114: check_new SPUN on EOF mid-literal (timed out)"),
        };
        assert!(e.contains("closed") && e.contains("uid=7") && e.contains("bytes short"),
            "the error names the uid and the missing bytes: {e}");
        assert!(carrier_io::eof_mid_response() > before, "counted on /status (carrier_eof_mid_response)");
        let _ = server.await;
    }

    /// EOF before any literal (the not-in-literal branch: the tag never comes).
    #[tokio::test]
    async fn imap_fetch_eof_before_literal_is_an_error() {
        let (port, server) = mock_imap(vec![
            vec!["{TAG} OK login".into()],
            vec!["{TAG} OK select".into()],
            vec!["* SEARCH 7".into(), "{TAG} OK search".into()],
            vec!["* 1 FETCH (UID 7".into()],
        ]).await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), imap_client(port).check_new()).await;
        match r {
            Ok(Err(e)) => {
                let e = format!("{e}");
                assert!(e.contains("closed") && e.contains("uid=7"), "names the uid: {e}");
            }
            Ok(Ok(m)) => panic!("EOF before the tag must be an error, got {} message(s)", m.len()),
            Err(_) => panic!("KI#114: check_new SPUN on EOF before the literal (timed out)"),
        }
        let _ = server.await;
    }

    /// A minimal POP3 server: greeting, then one scripted reply per command;
    /// the socket drops when the script runs out.
    async fn mock_pop3(script: Vec<Vec<String>>) -> u16 {
        use tokio::net::TcpListener;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut reader = BufReader::new(r);
            w.write_all(b"+OK mock POP3 ready\r\n").await.unwrap();
            for replies in script {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 { break; }
                for rep in replies {
                    w.write_all(format!("{}\r\n", rep).as_bytes()).await.unwrap();
                }
            }
        });
        port
    }

    /// POP3 twin: RETR's multi-line body is cut before the terminating ".".
    #[tokio::test]
    async fn pop3_retr_eof_mid_multiline_is_an_error() {
        let port = mock_pop3(vec![
            vec!["+OK user".into()],
            vec!["+OK pass".into()],
            vec!["+OK 1 100".into()],
            vec!["+OK message follows".into(), "Subject: half".into()],
        ]).await;
        let c = pop3_carrier::Pop3Carrier::new("127.0.0.1".into(), port, "u".into(), "p".into(), false);
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), c.check_new()).await;
        match r {
            Ok(Err(e)) => {
                let e = format!("{e}");
                assert!(e.contains("closed") && e.contains("msg=1"), "names the message: {e}");
            }
            Ok(Ok(m)) => panic!("EOF mid-RETR must be an error, got {} message(s)", m.len()),
            Err(_) => panic!("KI#114: POP3 read_multiline SPUN on EOF (timed out)"),
        }
    }

    /// Plaintext IMAP to a non-loopback host is refused at CONFIG LOAD.
    #[test]
    fn validate_imap_plaintext_nonloopback_rejected() {
        let cfg = CarriersConfig {
            maildir: Some(MaildirConfig {
                inbox: "/tmp/in".into(), outbox: "/tmp/out".into(),
            }),
            imap: vec![(ImapConfig {
                enabled: true,
                server: "imap.example.com".into(), port: 143,
                username: "u".into(), password: "p".into(),
                use_tls: false, inbox_folder: "INBOX".into(), use_idle: true,
            })],
            ..Default::default()
        };
        assert!(cfg.validate().is_err(),
                "plaintext LOGIN to a non-loopback host must be refused");
        let mut ok = cfg;
        ok.imap[0].server = "127.0.0.1".into();
        assert!(ok.validate().is_ok(), "loopback plaintext is the test exemption");
    }
}

// ============================================================================
// Routed Carrier — write a file to the outbox the domain table names
// ============================================================================

/// ANTIE's outbound job, in full: resolve the recipient's domain against the
/// `[[outbound.route]]` table and WRITE THE FILE THERE. It opens no connection,
/// resolves no host, retries nothing. An agent — FATMAMA or postfix,
/// interchangeable — collects from that directory.
///
/// Design ruling, 2026-08-20: *"ANTIE always do the same thing, write the outgoing to
/// the correct mailbox, and FATMAMA or postfix decided which mail to pickup."*
///
/// Replaces `SplitCarrier` (which opened SMTP connections); see
/// `AXIOM_DESIGN_AntieOutboundSplit.md` — goal retained, mechanism superseded.
pub mod routed_carrier {
    use super::*;
    use crate::config::OutboundConfig;
    use crate::maildir::Maildir;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    pub struct RoutedCarrier {
        /// Inbound side is unchanged — the maildir inbox this ANTIE reads.
        inbox: Arc<RwLock<Maildir>>,
        cfg: OutboundConfig,
        /// One Maildir per distinct outbox directory, opened once. Keyed by
        /// path so two domains sharing a directory share the handle.
        outboxes: HashMap<PathBuf, Arc<RwLock<Maildir>>>,
    }

    impl RoutedCarrier {
        pub async fn new(inbox: &Path, cfg: OutboundConfig) -> Result<Self, AntieError> {
            let mut outboxes = HashMap::new();
            let wanted: Vec<PathBuf> =
                cfg.route.iter().map(|r| r.outbox.clone()).collect();
            for p in wanted {
                if outboxes.contains_key(&p) {
                    continue;
                }
                // Fail at STARTUP if a configured directory is unusable — a
                // missing outbox must never become a per-message surprise.
                let md = Maildir::open(&p).await?;
                outboxes.insert(p, Arc::new(RwLock::new(md)));
            }
            Ok(Self {
                inbox: Arc::new(RwLock::new(Maildir::open(inbox).await?)),
                cfg,
                outboxes,
            })
        }
    }

    #[async_trait]
    impl MailCarrier for RoutedCarrier {
        fn name(&self) -> &str {
            "routed"
        }

        async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError> {
            let inbox = self.inbox.read().await;
            let mut out = Vec::new();
            for path in inbox.list_new().await? {
                let raw = inbox.read_message(&path).await?;
                let id = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                out.push(IncomingMessage { id, raw, source: path.display().to_string() });
            }
            Ok(out)
        }

        async fn mark_processed(&self, message_id: &str) -> Result<(), AntieError> {
            // Same as MaildirCarrier — the inbound side is unchanged by this
            // carrier; only the OUTBOUND side differs (file write vs SMTP push).
            let inbox = self.inbox.read().await;
            let path = inbox.path().join("new").join(message_id);
            if path.exists() {
                inbox.mark_processed(&path).await?;
            }
            Ok(())
        }

        async fn mark_failed(&self, message_id: &str, _reason: &str) -> Result<(), AntieError> {
            self.mark_processed(message_id).await
        }

        async fn send(&self, to: &str, raw_email: &[u8]) -> Result<(), AntieError> {
            // Fail-closed: an unroutable recipient is REJECTED, never dropped
            // (AntieOutboundSplit §4). The error propagates to the caller.
            let dir = self
                .cfg
                .outbox_for(to)
                .map_err(AntieError::ConfigError)?
                .ok_or_else(|| {
                    AntieError::ConfigError(format!(
                        "outbound route table empty while RoutedCarrier active (to={to})"
                    ))
                })?;
            let md = self.outboxes.get(dir).ok_or_else(|| {
                AntieError::ConfigError(format!(
                    "no open outbox for {} — startup should have created it",
                    dir.display()
                ))
            })?;
            md.read().await.write_message(raw_email).await?;
            tracing::debug!("[OUTBOUND-ROUTED] {} -> {}", to, dir.display());
            Ok(())
        }
    }
}

#[cfg(test)]
mod inbound_cap_tests {
    use super::*;
    fn imap(n: u16) -> ImapConfig {
        let base: ImapConfig = toml::from_str(&format!(
            "server = \"127.0.0.1\"\nport = {}\nusername = \"u{}\"\npassword = \"p\"\nuse_tls = false", 1000 + n, n)).unwrap();
        base
    }
    #[test]
    fn five_inbound_accounts_are_allowed_six_are_refused() {
        let mut c = CarriersConfig::default();
        c.imap = (0..3).map(imap).collect();
        c.pop3 = (0..2).map(|n| toml::from_str::<Pop3Config>(&format!(
            "server = \"127.0.0.1\"\nport = {}\nusername = \"q{}\"\npassword = \"p\"", 2000 + n, n)).unwrap()).collect();
        assert!(c.validate_inbound_count().is_ok(), "5 is the maximum, allowed");
        c.imap.push(imap(9));
        let e = c.validate_inbound_count().unwrap_err().to_string();
        assert!(e.contains("maximum is 5"), "{}", e);
    }
    #[test]
    fn an_array_of_tables_parses_and_a_disabled_slot_counts() {
        let c: CarriersConfig = toml::from_str(
            "[[imap]]\nenabled = false\nserver = \"imap.x\"\nport = 993\nusername = \"a\"\npassword = \"\"\n[[imap]]\nserver = \"imap.y\"\nport = 993\nusername = \"b\"\npassword = \"\"\n").unwrap();
        assert_eq!(c.imap.len(), 2);
        assert!(!c.imap[0].enabled && c.imap[1].enabled);
    }
}
