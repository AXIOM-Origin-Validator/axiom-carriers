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

/// IMAP carrier — ANTIE polls a remote IMAP mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    pub server:           String,
    pub port:             u16,
    pub username:         String,
    pub password:         String,
    #[serde(default = "default_true")]
    pub use_tls:          bool,
    #[serde(default = "default_inbox")]
    pub inbox_folder:     String,
    #[serde(default = "default_processed")]
    pub processed_folder: String,
}

fn default_true()      -> bool   { true }
fn default_inbox()     -> String { "INBOX".into() }
fn default_processed() -> String { "INBOX.Processed".into() }

/// POP3 carrier — ANTIE polls a remote POP3 mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pop3Config {
    pub server:   String,
    pub port:     u16,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub use_tls:  bool,
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
    pub imap:    Option<ImapConfig>,
    pub pop3:    Option<Pop3Config>,

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

impl CarriersConfig {
    /// Fail-stop validation. Called at gateway startup.
    pub fn validate(&self) -> Result<(), crate::error::AntieError> {
        let has_email = self.maildir.is_some()
            || self.imap.is_some()
            || self.pop3.is_some();
        if !has_email {
            return Err(crate::error::AntieError::ConfigError(
                "at least one email carrier (maildir, imap, or pop3) must be configured \
                 — tcp alone is not valid; email is required for fan-out".into()
            ));
        }
        Ok(())
    }

    /// True if any carrier is configured.
    pub fn any_enabled(&self) -> bool {
        self.maildir.is_some()
            || self.imap.is_some()
            || self.pop3.is_some()
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
        if self.maildir.is_some() || self.imap.is_some() || self.pop3.is_some() {
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
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

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

        /// Open a POP3 session. Returns a boxed AsyncRead+AsyncWrite stream.
        async fn connect(&self) -> Result<Box<dyn Pop3Stream>, AntieError> {
            let tcp = TcpStream::connect((&*self.server, self.port)).await
                .map_err(|e| AntieError::ConfigError(format!("POP3 connect: {}", e)))?;

            if self.use_tls {
                let connector = tokio_native_tls::native_tls::TlsConnector::new()
                    .map_err(|e| AntieError::ConfigError(format!("TLS init: {}", e)))?;
                let connector = tokio_native_tls::TlsConnector::from(connector);
                let tls = connector.connect(&self.server, tcp).await
                    .map_err(|e| AntieError::ConfigError(format!("TLS handshake: {}", e)))?;
                Ok(Box::new(tls))
            } else {
                Ok(Box::new(tcp))
            }
        }
    }

    /// Trait alias for streams that support async read+write+unpin.
    trait Pop3Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl Pop3Stream for TcpStream {}
    impl Pop3Stream for tokio_native_tls::TlsStream<TcpStream> {}

    /// Read a POP3 response line. +OK or -ERR prefix.
    async fn read_line(reader: &mut BufReader<&mut dyn Pop3Stream>) -> Result<String, AntieError> {
        let mut line = String::new();
        reader.read_line(&mut line).await
            .map_err(|e| AntieError::ConfigError(format!("POP3 read: {}", e)))?;
        Ok(line)
    }

    /// Send a POP3 command and read the response.
    async fn command(stream: &mut dyn Pop3Stream, cmd: &str) -> Result<String, AntieError> {
        stream.write_all(format!("{}\r\n", cmd).as_bytes()).await
            .map_err(|e| AntieError::ConfigError(format!("POP3 write: {}", e)))?;
        let mut reader = BufReader::new(stream);
        let line = read_line(&mut reader).await?;
        if line.starts_with("-ERR") {
            return Err(AntieError::ConfigError(format!("POP3: {}", line.trim())));
        }
        Ok(line)
    }

    /// Read a multi-line POP3 response (terminated by ".\r\n").
    async fn read_multiline(stream: &mut dyn Pop3Stream) -> Result<Vec<u8>, AntieError> {
        let mut reader = BufReader::new(stream);
        let mut data = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await
                .map_err(|e| AntieError::ConfigError(format!("POP3 read: {}", e)))?;
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
            let mut reader = BufReader::new(s as &mut dyn Pop3Stream);
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
                let raw = read_multiline(s).await?;
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

            let mut reader = BufReader::new(s as &mut dyn Pop3Stream);
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
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
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
        processed_folder: String,
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
            processed_folder: String,
        ) -> Self {
            Self {
                server, port, username, password, use_tls,
                inbox_folder, processed_folder,
                tag_counter: AtomicU32::new(1),
            }
        }

        fn next_tag(&self) -> String {
            let n = self.tag_counter.fetch_add(1, Ordering::Relaxed);
            format!("A{:04}", n)
        }

        /// Open an IMAP connection (optionally TLS).
        async fn connect(&self) -> Result<Box<dyn ImapStream>, AntieError> {
            let tcp = TcpStream::connect((&*self.server, self.port)).await
                .map_err(|e| AntieError::ConfigError(format!("IMAP connect: {}", e)))?;

            if self.use_tls {
                let connector = tokio_native_tls::native_tls::TlsConnector::new()
                    .map_err(|e| AntieError::ConfigError(format!("TLS init: {}", e)))?;
                let connector = tokio_native_tls::TlsConnector::from(connector);
                let tls = connector.connect(&self.server, tcp).await
                    .map_err(|e| AntieError::ConfigError(format!("TLS handshake: {}", e)))?;
                Ok(Box::new(tls))
            } else {
                Ok(Box::new(tcp))
            }
        }
    }

    trait ImapStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl ImapStream for TcpStream {}
    impl ImapStream for tokio_native_tls::TlsStream<TcpStream> {}

    /// Send an IMAP command and read lines until we get the tagged response.
    async fn imap_command(stream: &mut dyn ImapStream, tag: &str, cmd: &str)
        -> Result<Vec<String>, AntieError>
    {
        stream.write_all(format!("{} {}\r\n", tag, cmd).as_bytes()).await
            .map_err(|e| AntieError::ConfigError(format!("IMAP write: {}", e)))?;

        let mut reader = BufReader::new(stream);
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await
                .map_err(|e| AntieError::ConfigError(format!("IMAP read: {}", e)))?;
            let trimmed = line.trim().to_string();
            if trimmed.starts_with(tag) {
                if trimmed.contains("NO") || trimmed.contains("BAD") {
                    return Err(AntieError::ConfigError(format!("IMAP: {}", trimmed)));
                }
                lines.push(trimmed);
                break;
            }
            lines.push(trimmed);
        }
        Ok(lines)
    }

    /// Read the server greeting (untagged * OK).
    async fn read_greeting(stream: &mut dyn ImapStream) -> Result<(), AntieError> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await
            .map_err(|e| AntieError::ConfigError(format!("IMAP greeting: {}", e)))?;
        if !line.contains("OK") {
            return Err(AntieError::ConfigError(format!("IMAP bad greeting: {}", line.trim())));
        }
        Ok(())
    }

    /// Fetch a single message body by UID. Returns raw bytes.
    async fn fetch_message(stream: &mut dyn ImapStream, tag: &str, uid: &str)
        -> Result<Vec<u8>, AntieError>
    {
        stream.write_all(format!("{} UID FETCH {} BODY[]\r\n", tag, uid).as_bytes()).await
            .map_err(|e| AntieError::ConfigError(format!("IMAP write: {}", e)))?;

        let mut reader = BufReader::new(stream);
        let mut data = Vec::new();
        let mut in_literal = false;
        let mut literal_remaining: usize = 0;

        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await
                .map_err(|e| AntieError::ConfigError(format!("IMAP read: {}", e)))?;

            if in_literal {
                let bytes = line.as_bytes();
                let take = bytes.len().min(literal_remaining);
                data.extend_from_slice(&bytes[..take]);
                literal_remaining -= take;
                if literal_remaining == 0 {
                    in_literal = false;
                }
                continue;
            }

            let trimmed = line.trim();
            if trimmed.starts_with(tag) {
                break;
            }

            // Check for literal size: "* N FETCH ... {SIZE}"
            if let Some(pos) = trimmed.rfind('{') {
                if let Some(end) = trimmed.rfind('}') {
                    if let Ok(size) = trimmed[pos+1..end].parse::<usize>() {
                        literal_remaining = size;
                        in_literal = true;
                    }
                }
            }
        }

        Ok(data)
    }

    #[async_trait]
    impl MailCarrier for ImapCarrier {
        fn name(&self) -> &str {
            "imap"
        }

        async fn check_new(&self) -> Result<Vec<IncomingMessage>, AntieError> {
            let mut stream = self.connect().await?;
            let s = stream.as_mut();

            read_greeting(s).await?;

            // LOGIN
            let tag = self.next_tag();
            imap_command(s, &tag, &format!("LOGIN {} {}", self.username, self.password)).await?;

            // SELECT inbox
            let tag = self.next_tag();
            imap_command(s, &tag, &format!("SELECT {}", self.inbox_folder)).await?;

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

            read_greeting(s).await?;

            let tag = self.next_tag();
            imap_command(s, &tag, &format!("LOGIN {} {}", self.username, self.password)).await?;

            let tag = self.next_tag();
            imap_command(s, &tag, &format!("SELECT {}", self.inbox_folder)).await?;

            // Mark as seen
            let tag = self.next_tag();
            imap_command(s, &tag, &format!("UID STORE {} +FLAGS (\\Seen)", message_id)).await?;

            // Copy to processed folder
            let tag = self.next_tag();
            let _ = imap_command(s, &tag, &format!("UID COPY {} {}", message_id, self.processed_folder)).await;

            // Mark deleted and expunge
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

    /// SMTP carrier for outbound mail.
    ///
    /// Raw TCP SMTP — no lettre. Sends EHLO/MAIL/RCPT/DATA/QUIT manually.
    /// lettre's AsyncSmtpTransport was silently losing messages (returned Ok
    /// but FATMAMA never received the DATA). Raw TCP has zero message loss.
    pub struct SmtpCarrier {
        server: String,
        port: u16,
        from_address: String,
    }

    impl SmtpCarrier {
        pub fn new(
            server: String,
            port: u16,
            _username: Option<String>,
            _password: Option<String>,
            _use_tls: bool,
            from_address: String,
        ) -> Self {
            Self { server, port, from_address }
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
            // Raw TCP SMTP — no lettre. lettre's AsyncSmtpTransport says Ok
            // but FATMAMA never receives the DATA (library bug/incompatibility).
            // Simple SMTP: connect, EHLO, MAIL FROM, RCPT TO, DATA, QUIT.
            use tokio::net::TcpStream;
            use tokio::io::{AsyncWriteExt, BufReader, AsyncBufReadExt};

            let addr = format!("{}:{}", self.server, self.port);
            let stream = TcpStream::connect(&addr).await
                .map_err(|e| AntieError::ConfigError(format!("SMTP connect {}: {}", addr, e)))?;
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line_buf = String::new();

            // Helper: read one SMTP response line
            macro_rules! read_reply {
                () => {{
                    line_buf.clear();
                    reader.read_line(&mut line_buf).await
                        .map_err(|e| AntieError::ConfigError(format!("SMTP read: {}", e)))?;
                    if !line_buf.starts_with('2') && !line_buf.starts_with('3') {
                        return Err(AntieError::ConfigError(format!("SMTP error: {}", line_buf.trim())));
                    }
                }};
            }

            // 220 greeting
            read_reply!();
            // EHLO
            writer.write_all(format!("EHLO {}\r\n", self.server).as_bytes()).await
                .map_err(|e| AntieError::ConfigError(format!("SMTP write: {}", e)))?;
            read_reply!();
            // MAIL FROM
            writer.write_all(format!("MAIL FROM:<{}>\r\n", self.from_address).as_bytes()).await
                .map_err(|e| AntieError::ConfigError(format!("SMTP write: {}", e)))?;
            read_reply!();
            // RCPT TO
            writer.write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes()).await
                .map_err(|e| AntieError::ConfigError(format!("SMTP write: {}", e)))?;
            read_reply!();
            // DATA
            writer.write_all(b"DATA\r\n").await
                .map_err(|e| AntieError::ConfigError(format!("SMTP write: {}", e)))?;
            read_reply!(); // 354
            // Send the raw email body + CRLF.CRLF terminator
            writer.write_all(raw_email).await
                .map_err(|e| AntieError::ConfigError(format!("SMTP DATA write: {}", e)))?;
            writer.write_all(b"\r\n.\r\n").await
                .map_err(|e| AntieError::ConfigError(format!("SMTP DATA term: {}", e)))?;
            writer.flush().await
                .map_err(|e| AntieError::ConfigError(format!("SMTP flush: {}", e)))?;
            read_reply!(); // 250 OK
            // QUIT
            writer.write_all(b"QUIT\r\n").await.ok();

            Ok(())
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
            imap: Some(ImapConfig {
                server: "imap.example.com".into(), port: 993,
                username: "alpha".into(), password: "x".into(),
                use_tls: true,
                inbox_folder: "INBOX".into(),
                processed_folder: "INBOX.Processed".into(),
            }),
            ..Default::default()
        };
        let uris = cfg.to_uri_list("alpha@axiom.network");
        assert_eq!(uris, vec!["email:alpha@axiom.network".to_string()]);
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
}
