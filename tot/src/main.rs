//! AXIOM TOT — Tiny Outbound Tunnel.
//!
//! Per-validator release inbound carrier. One listen port serves both
//! transports, demuxed by the first 4 bytes of each connection:
//!   - a raw-TCP YPX-019 frame -> written to the validator's
//!     `maildir/inbox/` for ANTIE (native clients);
//!   - a `GET ` WebSocket handshake -> `/intake` (same maildir write,
//!     for browser/WASM clients) or `/nabla/<n>` (an opaque WS<->TCP
//!     tunnel to the attested Nabla node at index `n`).
//!
//! TOT decodes no protocol bytes, holds no key, terminates no TLS, and
//! is never trusted — see docs/AXIOM_DESIGN_TOT.md.

mod config;
mod maildir;
mod sandbox;
mod tunnel;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use config::Config;

/// A WebSocket served over the demux wrapper (§3) — see `PrefixedStream`.
type Ws = WebSocketStream<PrefixedStream>;

fn main() {
    // Decorative boot charm. TTY-gated, no-op under systemd/journald.
    // Lives in axiom-denomination so every native binary that links
    // the AXC/L$/atom conversion lib also gets the canary — see
    // denomination/src/lib.rs. Purely for luck; zero functional effect.
    axiom_denomination::print_if_tty("tot");

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = run() {
        log::error!("tot: fatal: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cfg_path = std::env::args().nth(1).ok_or("usage: tot <config.toml>")?;
    let cfg = Config::load(Path::new(&cfg_path))?;
    log::info!("tot: config loaded from {cfg_path}");

    // Resolve every resource the serve loop will ever touch — now, while
    // still single-threaded and before the sandbox is sealed. After this
    // point TOT opens no new files and resolves no DNS (§4 layer 3).
    let inbox = maildir::Inbox::open(&cfg.maildir_inbox)
        .map_err(|e| format!("open maildir inbox {}: {e}", cfg.maildir_inbox.display()))?;
    let listener = std::net::TcpListener::bind(cfg.listen)
        .map_err(|e| format!("bind {}: {e}", cfg.listen))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("listener set_nonblocking: {e}"))?;
    log::info!("tot: listening on {} (raw-TCP intake + ws://)", cfg.listen);
    log::info!("tot: intake inbox = {}", cfg.maildir_inbox.display());
    log::info!("tot: {} attested nabla node(s)", cfg.nabla.len());

    // Sweep any session directories left by a PREVIOUS process. The Drop guard
    // removes a session's directory on every exit path the process controls —
    // but a `kill -9`, an OOM kill, or a power cut runs no destructor, and that
    // directory would then live forever. At startup NO session can be live, so
    // everything under custody_outbox is garbage by definition.
    //
    // Ephemeral means ephemeral: undelivered replies in there are DELETED, not
    // preserved (AXIOM Origin, 2026-08-25: *"Anything happen, when dropped,
    // clean up. Do not need to consider recovery."*). Nothing is lost that
    // matters — Lambda's YPX-016 cache is the authoritative copy and re-asking
    // with the same request_id replays the same signed response
    // (AXIOM_DESIGN_TOT.md §5.4).
    //
    // Done HERE, before the sandbox is sealed, because afterwards TOT may not
    // touch the filesystem this way (§4 layer 3).
    if let Some(ref outbox) = cfg.custody_outbox {
        match sweep_stale_sessions(outbox) {
            Ok(0) => log::info!("tot: custody outbox {} clean", outbox.display()),
            Ok(n) => log::warn!(
                "tot: swept {n} stale session dir(s) from {} — a previous process \
                 was killed without running its cleanup", outbox.display()),
            // Fail closed on the SESSION route only: if the sweep cannot run,
            // the directory state is unknown, and a session minted into an
            // unknown directory can collide with a stale one.
            Err(e) => return Err(format!(
                "custody outbox {} unusable: {e}", outbox.display())),
        }
    }

    // Seal the sandbox — layer 2 (in-process seccomp). Installed on the
    // main thread before the tokio runtime spawns any worker; seccomp
    // filters are inherited across clone(), so every worker is covered.
    sandbox::install()?;
    log::info!("tot: seccomp filter installed");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("build tokio runtime: {e}"))?;
    rt.block_on(serve(Arc::new(cfg), Arc::new(inbox), listener))
}

async fn serve(
    cfg: Arc<Config>,
    inbox: Arc<maildir::Inbox>,
    listener: std::net::TcpListener,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| format!("adopt listener: {e}"))?;

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("tot: accept failed: {e}");
                continue;
            }
        };
        let cfg = cfg.clone();
        let inbox = inbox.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(sock, cfg, inbox).await {
                log::debug!("tot: conn {peer}: {e}");
            }
        });
    }
}

/// Read the first 4 bytes and demux (§3): a browser's WebSocket
/// handshake opens with `GET `; a native client's raw intake frame
/// opens with a `u32-LE length`, which cannot spell `GET ` under the
/// size cap. The 4 bytes are consumed here — the WebSocket path replays
/// them via `PrefixedStream` so the handshake parser sees a whole `GET`.
async fn handle_conn(
    mut sock: TcpStream,
    cfg: Arc<Config>,
    inbox: Arc<maildir::Inbox>,
) -> Result<(), String> {
    let mut head = [0u8; 4];
    sock.read_exact(&mut head)
        .await
        .map_err(|e| format!("read demux head: {e}"))?;

    if &head == b"GET " {
        websocket_conn(PrefixedStream::new(head.to_vec(), sock), &cfg, &inbox).await
    } else {
        tcp_intake_leg(sock, head, cfg.max_message_bytes, &inbox).await
    }
}

/// A WebSocket connection: complete the handshake, then dispatch by the
/// request path captured during it.
async fn websocket_conn(
    stream: PrefixedStream,
    cfg: &Config,
    inbox: &Arc<maildir::Inbox>,
) -> Result<(), String> {
    let path_slot: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let path_capture = path_slot.clone();
    let ws = tokio_tungstenite::accept_hdr_async(
        stream,
        move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
            if let Ok(mut slot) = path_capture.lock() {
                *slot = req.uri().path().to_string();
            }
            Ok(resp)
        },
    )
    .await
    .map_err(|e| format!("websocket handshake: {e}"))?;

    let path = path_slot.lock().map(|s| s.clone()).unwrap_or_default();
    match Route::parse(&path) {
        Some(Route::Intake) => intake_leg(ws, cfg, inbox).await,
        Some(Route::Session) => session_leg(ws, cfg, inbox).await,
        Some(Route::Nabla(idx)) => nabla_leg(ws, idx, cfg).await,
        #[cfg(feature = "dev-fatmama")]
        Some(Route::Fatmama(idx)) => fatmama_leg(ws, idx, cfg).await,
        None => Err(format!("unknown route {path:?}")),
    }
}

/// `/intake` (WebSocket) — every binary message is one TX submission,
/// written to the validator's `maildir/inbox/`.
async fn intake_leg(mut ws: Ws, cfg: &Config, inbox: &Arc<maildir::Inbox>) -> Result<(), String> {
    let mut limiter = RateLimiter::new(cfg.intake_max_msgs_per_sec);
    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| format!("websocket recv: {e}"))?;
        match msg {
            Message::Binary(bytes) => {
                if bytes.len() > cfg.max_message_bytes {
                    return Err(format!(
                        "intake message {} bytes exceeds cap {}",
                        bytes.len(),
                        cfg.max_message_bytes
                    ));
                }
                if !limiter.allow() {
                    return Err("intake rate limit exceeded".into());
                }
                let inbox = inbox.clone();
                let payload = bytes.to_vec();
                tokio::task::spawn_blocking(move || inbox.deliver(&payload))
                    .await
                    .map_err(|e| format!("deliver task: {e}"))?
                    .map_err(|e| format!("maildir deliver: {e}"))?;
            }
            Message::Close(_) => break,
            _ => {} // ignore text / ping / pong
        }
    }
    Ok(())
}

/// Remove every session directory under `outbox`, returning how many went.
///
/// Only ever called at startup, where "no session is live" is guaranteed, so
/// this cannot race a running session. It creates `outbox` if absent — a fresh
/// deploy has no directory yet and that is not an error.
///
/// Files sitting directly in `outbox` (not directories) are left alone: they
/// are not ours, and deleting an operator's file because it shares a directory
/// would be worse than leaving it.
fn sweep_stale_sessions(outbox: &Path) -> std::io::Result<usize> {
    std::fs::create_dir_all(outbox)?;
    let mut n = 0;
    for entry in std::fs::read_dir(outbox)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
            n += 1;
        }
    }
    Ok(n)
}

/// How often a session checks its own directory for replies. A poll rather
/// than an inotify watch: one directory per connection, written by exactly one
/// writer, and 100 ms is invisible next to a witness round that takes seconds.
/// Polling also keeps TOT free of a watch descriptor per connection, which is
/// the resource a busy validator would run out of first.
const REPLY_POLL_MS: u64 = 100;

/// Send every reply sitting in this session's directory, oldest first, and
/// delete each one once it is on the socket.
///
/// ANTIE writes tmp -> fsync -> rename, so a file visible here is COMPLETE —
/// there is no torn-read to guard against. This directory has exactly one
/// reader (the task that minted the id), so no claim protocol is needed
/// either: read, send, remove.
///
/// Delete-after-send is deliberate and matches the ephemeral rule: a reply
/// that fails to send is dropped with the session, not retried and not kept.
/// Nothing is lost that matters — Lambda's YPX-016 cache replays the same
/// signed response for the same request_id.
async fn pump_replies<S>(tx: &mut S, dir: &Path) -> Result<(), String>
where
    S: futures_util::SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        // The directory is created at session open and removed at session
        // close; if it is missing mid-session something external took it, and
        // that ends the session rather than being papered over.
        Err(e) => return Err(format!("session dir unreadable: {e}")),
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "cbor"))
        .collect();
    files.sort();               // stable order; request_ids sort deterministically
    for f in files {
        let bytes = match std::fs::read(&f) {
            Ok(b) => b,
            Err(e) => return Err(format!("read reply {}: {e}", f.display())),
        };
        tx.send(Message::Binary(bytes))
            .await
            .map_err(|e| format!("send reply {}: {e}", f.display()))?;
        let _ = std::fs::remove_file(&f);
    }
    Ok(())
}

/// Owns one session's reply directory for exactly as long as the connection
/// lives, and removes it on EVERY exit path — clean close, error, or panic.
///
/// ⚠ A `Drop` guard rather than cleanup at the end of `session_leg`, because
/// "clean up when the loop finishes" misses the paths that matter: an early
/// `return Err(...)` on a rate limit, an oversized frame, a websocket error, or
/// an unwind. A leaked directory is a slow disk fill, which is exactly how
/// iota crash-looped 1,287 times on 2026-08-24 after a 44 GB log filled its
/// disk. Nothing is retained past the socket (YPX-023 / TOT §5.4: the carrier
/// is EPHEMERAL — no store-and-forward, no mailbox).
struct SessionDir {
    path: PathBuf,
    id_short: String,
}

impl SessionDir {
    /// Create `<custody_outbox>/<id>/`. Fails closed: if the directory cannot
    /// be created there is nowhere for replies to land, so the session must
    /// not open at all rather than run and silently swallow every reply.
    fn create(outbox: &Path, id: &str) -> Result<SessionDir, String> {
        let path = outbox.join(id);
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("session dir {}: {e}", path.display()))?;
        Ok(SessionDir { path, id_short: id[..16].to_string() })
    }
}

impl Drop for SessionDir {
    fn drop(&mut self) {
        // Best-effort: a failure here must not mask whatever ended the session,
        // but it IS logged — a directory that survives its session is the
        // leak this guard exists to prevent, and silence would hide it.
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("tot: session {} dir cleanup FAILED ({e}) — {} may leak",
                           self.id_short, self.path.display());
            }
        } else {
            log::debug!("tot: session {} dir removed", self.id_short);
        }
    }
}

/// `/session` (WebSocket) — NORMAL-wallet client that holds the connection
/// open and receives its own replies on it (AXIOM_DESIGN_TOT.md §5.4).
///
/// Same maildir delivery as `/intake`, plus ONE addition: the envelope is
/// stamped `X-TOT-Session: <id>` so ANTIE routes the reply into this session's
/// directory instead of mailing it (YPX-023 RULE 3).
///
/// ⚠ **This is the one place TOT modifies what a client sent.** It adds a
/// header to the ENVELOPE and reads no UMP payload — the §2 invariants "holds
/// no key", "terminates no TLS", "reads no protocol bytes" and "reaches only
/// its own validator" all still hold, but "writes client bytes verbatim" no
/// longer does. Stated deliberately; see YPX-023 §3.1.
///
/// ⚠ **NEVER stamped for a DEV wallet.** TOT decodes nothing and so cannot
/// tell a dev wallet from a normal one; the route IS the client's declaration,
/// and ANTIE cross-checks it against the sender address and REJECTS a
/// disagreement (YPX-023 §2B.4). Dev traffic is FATMAMA-to-FATMAMA only and
/// gets its own stamp later.
async fn session_leg(mut ws: Ws, cfg: &Config, inbox: &Arc<maildir::Inbox>) -> Result<(), String> {
    // 32 random bytes as 64 hex — the width and strict parse
    // `X-UNCLE-Correlate` already uses. It names WHERE a signed reply is
    // deposited, so it must be unguessable: a guessable id would let one
    // client's reply be directed into another's session directory.
    let session_id = {
        // /dev/urandom directly rather than adding a dependency to a binary
        // whose whole point is to be tiny and auditable (§2). Fails closed:
        // no entropy ⇒ no session, never a predictable id.
        use std::io::Read;
        let mut b = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut b))
            .map_err(|e| format!("session id entropy: {e}"))?;
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    };
    // Fail closed: no configured outbox ⇒ no session. Minting a session whose
    // replies have nowhere to land would hang the client with nothing in any
    // log to explain it.
    let outbox = cfg.custody_outbox.as_ref().ok_or_else(|| {
        "session route requires custody_outbox in tot config — refusing".to_string()
    })?;
    // This directory IS the client mapping: the task that minted the id also
    // holds the socket, so it watches only its own directory and never has to
    // work out whose reply is whose.
    let _dir = SessionDir::create(outbox, &session_id)?;
    log::info!("tot: session {} opened, replies at {}",
               &session_id[..16], _dir.path.display());

    // Split so a reply going out never waits on the client's next frame, and
    // vice versa. Both halves stay in this one task — no shared state, nothing
    // to lock, and the session ends when either side does.
    let (mut tx, mut rx) = ws.split();
    let mut limiter = RateLimiter::new(cfg.intake_max_msgs_per_sec);
    let mut poll = tokio::time::interval(std::time::Duration::from_millis(REPLY_POLL_MS));

    loop {
        tokio::select! {
            // the client sent us something
            incoming = rx.next() => {
                let Some(msg) = incoming else { break };   // stream closed
                let msg = msg.map_err(|e| format!("websocket recv: {e}"))?;
                match msg {
                    Message::Binary(bytes) => {
                        if bytes.len() > cfg.max_message_bytes {
                            return Err(format!(
                                "session message {} bytes exceeds cap {}",
                                bytes.len(),
                                cfg.max_message_bytes
                            ));
                        }
                        if !limiter.allow() {
                            return Err("session rate limit exceeded".into());
                        }
                        let stamped = stamp_session(&bytes, &session_id)?;
                        let inbox = inbox.clone();
                        tokio::task::spawn_blocking(move || inbox.deliver(&stamped))
                            .await
                            .map_err(|e| format!("deliver task: {e}"))?
                            .map_err(|e| format!("maildir deliver: {e}"))?;
                    }
                    Message::Close(_) => break,
                    _ => {} // ignore text / ping / pong
                }
            }
            // time to look for replies ANTIE has deposited for THIS session
            _ = poll.tick() => {
                pump_replies(&mut tx, &_dir.path).await?;
            }
        }
    }
    log::info!("tot: session {} closed", &session_id[..16]);
    Ok(())
}

/// Insert `X-TOT-Session: <id>` at the top of an RFC-5322 header block.
///
/// Prepending is deliberate: it needs no parse of the existing headers, so a
/// malformed or unusual envelope cannot make TOT mis-splice. The message must
/// still LOOK like an email — a body with no header block is refused rather
/// than guessed at.
///
/// ⚠ Any custody header the client supplied is DROPPED, not merged. A client
/// must not be able to choose where its reply is deposited (nor anyone else's):
/// the stamp is TOT's assertion about a connection it owns, never a value the
/// client hands up. This is also the strip-then-add rule YPX-023 §3.3 requires
/// so two custody headers can never coexist.
fn stamp_session(raw: &[u8], id: &str) -> Result<Vec<u8>, String> {
    // Refuse anything that is not header-block shaped. A stamped non-email
    // would be delivered and then fail to parse deep inside ANTIE, which is a
    // much worse place to discover it.
    if !raw.windows(4).any(|w| w == b"\r\n\r\n") && !raw.windows(2).any(|w| w == b"\n\n") {
        return Err("session message has no header block — refusing to stamp".into());
    }
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len() + 96);
    out.push_str(&format!("X-TOT-Session: {id}\r\n"));
    // Drop any client-supplied custody header (see the warning above).
    let mut in_headers = true;
    for line in text.split_inclusive('\n') {
        if in_headers {
            let l = line.trim_end_matches(['\r', '\n']);
            if l.is_empty() {
                in_headers = false;           // end of the header block
            } else if l.to_ascii_lowercase().starts_with("x-tot-session:") {
                continue;                      // client tried to set it — drop
            }
        }
        out.push_str(line);
    }
    Ok(out.into_bytes())
}

/// Raw-TCP intake — one YPX-019 frame: a `u32-LE length` (already read
/// into `len_prefix` by the demux) followed by that many CBOR-UMP bytes,
/// written verbatim to the validator's `maildir/inbox/`. One frame per
/// connection (AXIOM_DESIGN_TOT.md §5.1).
async fn tcp_intake_leg(
    mut sock: TcpStream,
    len_prefix: [u8; 4],
    max_message_bytes: usize,
    inbox: &Arc<maildir::Inbox>,
) -> Result<(), String> {
    let len = u32::from_le_bytes(len_prefix) as usize;
    if len == 0 {
        return Err("tcp intake: zero-length frame".into());
    }
    if len > max_message_bytes {
        return Err(format!(
            "tcp intake frame {len} bytes exceeds cap {max_message_bytes}"
        ));
    }
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body)
        .await
        .map_err(|e| format!("tcp intake read body: {e}"))?;

    let inbox = inbox.clone();
    tokio::task::spawn_blocking(move || inbox.deliver(&body))
        .await
        .map_err(|e| format!("deliver task: {e}"))?
        .map_err(|e| format!("maildir deliver: {e}"))?;
    Ok(())
}

/// `/nabla/<n>` — opaque tunnel to the attested Nabla node at index `n`.
async fn nabla_leg(ws: Ws, idx: usize, cfg: &Config) -> Result<(), String> {
    let node = cfg.nabla.get(idx).ok_or_else(|| {
        format!(
            "nabla index {idx} outside the attested set (0..{})",
            cfg.nabla.len()
        )
    })?;
    let tcp = TcpStream::connect(node.addr)
        .await
        .map_err(|e| format!("connect nabla {} ({}): {e}", node.name, node.addr))?;
    tunnel::pump(ws, tcp)
        .await
        .map_err(|e| format!("nabla tunnel: {e}"))
}

/// `/fatmama/<n>` — DEV-ONLY opaque tunnel to the configured FATMAMA
/// endpoint at index `n` (SMTP for XAXIOM-REGISTER, POP3 for mail pull).
/// A browser dev wallet drives the line protocol (mirroring AxiomKiddo's
/// Pop3Client / FatmamaRegister); TOT pumps bytes and decodes nothing,
/// exactly like the `/nabla` leg. Compiled out of release builds entirely
/// (`dev-fatmama` feature). FATMAMA is dev-scoped — AXIOM_DESIGN_TOT.md §8.
#[cfg(feature = "dev-fatmama")]
async fn fatmama_leg(ws: Ws, idx: usize, cfg: &Config) -> Result<(), String> {
    let node = cfg.fatmama.get(idx).ok_or_else(|| {
        format!(
            "fatmama index {idx} outside the configured set (0..{})",
            cfg.fatmama.len()
        )
    })?;
    let tcp = TcpStream::connect(node.addr)
        .await
        .map_err(|e| format!("connect fatmama {} ({}): {e}", node.name, node.addr))?;
    tunnel::pump(ws, tcp)
        .await
        .map_err(|e| format!("fatmama tunnel: {e}"))
}

enum Route {
    Intake,
    /// `/session` — a NORMAL-wallet client holding the connection open for its
    /// replies (YPX-023, AXIOM_DESIGN_TOT.md §5.4). Stamped `X-TOT-Session`.
    ///
    /// ⚠ DEV wallets MUST NOT use this route. A dev wallet's traffic is
    /// FATMAMA-to-FATMAMA only and carries a different (later) stamp; a dev
    /// message stamped as a normal session would enter the normal path
    /// carrying the dev class's higher in-mesh trust. TOT cannot tell the two
    /// apart — it decodes nothing — so the route is the client's declaration
    /// and ANTIE cross-checks it against the sender address (YPX-023 §2B.4:
    /// stamp and address must AGREE, disagreement REJECTS). On a real-email
    /// validator the dev path does not even exist: `dev-fatmama` is compiled
    /// out (verified 2026-08-24 — zeta's tot has zero fatmama symbols).
    Session,
    Nabla(usize),
    #[cfg(feature = "dev-fatmama")]
    Fatmama(usize),
}

impl Route {
    fn parse(path: &str) -> Option<Route> {
        if path == "/intake" {
            return Some(Route::Intake);
        }
        if path == "/session" {
            return Some(Route::Session);
        }
        if let Some(idx) = path.strip_prefix("/nabla/") {
            return idx.parse::<usize>().ok().map(Route::Nabla);
        }
        #[cfg(feature = "dev-fatmama")]
        if let Some(idx) = path.strip_prefix("/fatmama/") {
            return idx.parse::<usize>().ok().map(Route::Fatmama);
        }
        None
    }
}

/// A `TcpStream` with a small byte prefix pushed back in front of it:
/// the demux (`handle_conn`) consumes the first 4 bytes to pick a leg,
/// and the WebSocket handshake parser then needs to see them again.
/// `poll_read` drains the saved prefix before delegating to the socket;
/// writes pass straight through.
struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> PrefixedStream {
        PrefixedStream {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A per-connection fixed-window rate limiter for the WebSocket intake
/// leg.
struct RateLimiter {
    max_per_sec: u32,
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    fn new(max_per_sec: u32) -> RateLimiter {
        RateLimiter {
            max_per_sec,
            window_start: Instant::now(),
            count: 0,
        }
    }

    /// Returns false once the per-second budget for the current window
    /// is spent. `max_per_sec == 0` disables the limit.
    fn allow(&mut self) -> bool {
        if self.max_per_sec == 0 {
            return true;
        }
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= self.max_per_sec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio::io::AsyncWriteExt;

    const MINIMAL_CFG: &str = r#"
listen = "127.0.0.1:0"
maildir_inbox = "/unused-by-these-tests"
[[nabla]]
name = "n0"
addr = "127.0.0.1:1"
"#;

    #[test]
    fn route_parsing() {
        assert!(matches!(Route::parse("/intake"), Some(Route::Intake)));
        assert!(matches!(Route::parse("/nabla/0"), Some(Route::Nabla(0))));
        assert!(matches!(Route::parse("/nabla/7"), Some(Route::Nabla(7))));
        assert!(Route::parse("/nabla/x").is_none());
        assert!(Route::parse("/nabla/").is_none());
        assert!(Route::parse("/").is_none());
        assert!(Route::parse("/intake/").is_none());
    }

    #[test]
    fn rate_limiter_caps_the_window() {
        let mut rl = RateLimiter::new(3);
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(!rl.allow(), "4th call in the window must be denied");
    }

    #[test]
    fn rate_limiter_zero_is_unlimited() {
        let mut rl = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(rl.allow());
        }
    }

    /// A non-`GET ` connection demuxes to the raw-TCP intake leg and the
    /// YPX-019 frame lands in the inbox.
    #[tokio::test]
    async fn raw_tcp_frame_demuxes_to_intake_and_delivers() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Arc::new(maildir::Inbox::open(dir.path()).unwrap());
        let cfg: Arc<Config> = Arc::new(toml::from_str(MINIMAL_CFG).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let inbox_srv = inbox.clone();
        let cfg_srv = cfg.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_conn(sock, cfg_srv, inbox_srv).await
        });

        let body: &[u8] = b"axiom-ump-envelope-bytes";
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&(body.len() as u32).to_le_bytes())
            .await
            .unwrap();
        client.write_all(body).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap().expect("handle_conn");

        let new: Vec<_> = std::fs::read_dir(dir.path().join("new"))
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        assert_eq!(new.len(), 1, "one delivered message");
        assert_eq!(std::fs::read(new[0].path()).unwrap(), body);
    }

    /// A `GET ` connection demuxes to the WebSocket path (via
    /// `PrefixedStream`); a binary `/intake` message lands in the inbox.
    #[tokio::test]
    async fn ws_get_demuxes_to_intake_and_delivers() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Arc::new(maildir::Inbox::open(dir.path()).unwrap());
        let cfg: Arc<Config> = Arc::new(toml::from_str(MINIMAL_CFG).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let inbox_srv = inbox.clone();
        let cfg_srv = cfg.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_conn(sock, cfg_srv, inbox_srv).await
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut ws, _resp) = tokio_tungstenite::client_async("ws://localhost/intake", tcp)
            .await
            .unwrap();
        ws.send(Message::Binary(b"ws-submitted-tx".to_vec()))
            .await
            .unwrap();
        ws.send(Message::Close(None)).await.unwrap();

        server.await.unwrap().expect("handle_conn");

        let new: Vec<_> = std::fs::read_dir(dir.path().join("new"))
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        assert_eq!(new.len(), 1, "one delivered message");
        assert_eq!(std::fs::read(new[0].path()).unwrap(), b"ws-submitted-tx");
    }

    /// A raw-TCP frame whose length exceeds the cap is rejected before
    /// the body is read — nothing reaches the inbox.
    #[tokio::test]
    async fn raw_tcp_frame_over_cap_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Arc::new(maildir::Inbox::open(dir.path()).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // frame claims 1000 bytes; cap is 16 -> rejected pre-read.
            tcp_intake_leg(sock, 1000u32.to_le_bytes(), 16, &inbox).await
        });

        let _client = TcpStream::connect(addr).await.unwrap();
        let result = server.await.unwrap();
        assert!(result.is_err(), "over-cap frame must be rejected");
        assert_eq!(
            std::fs::read_dir(dir.path().join("new")).unwrap().count(),
            0
        );
    }
}

#[cfg(test)]
mod session_tests {
    use super::{pump_replies, stamp_session, sweep_stale_sessions, SessionDir};
    use tokio_tungstenite::tungstenite::Message;
    /// The session directory IS the client mapping, so its lifetime must match
    /// the connection exactly: created on open, gone on EVERY exit.
    #[test]
    fn session_dir_is_created_and_removed_on_drop() {
        let root = std::env::temp_dir().join(format!("tot_sd_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let id = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
        let path = {
            let d = SessionDir::create(&root, id).expect("create");
            assert!(d.path.is_dir(), "session dir must exist while the session lives");
            d.path.clone()
        }; // dropped here
        assert!(!path.exists(),
                "session dir MUST be gone once the guard drops — a directory \
                 outliving its session is the leak the guard exists to prevent");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Cleanup must survive the paths that actually happen: an early error
    /// return, not just a tidy end-of-loop.
    #[test]
    fn session_dir_removed_even_on_early_error() {
        let root = std::env::temp_dir().join(format!("tot_sd_err_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let id = "bb11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
        let path = root.join(id);
        let r: Result<(), String> = (|| {
            let d = SessionDir::create(&root, id)?;
            assert!(d.path.is_dir());
            Err("rate limit exceeded".into())   // the shape of a real early return
        })();
        assert!(r.is_err());
        assert!(!path.exists(), "an error return must still clean the session dir");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Collect what the pump sends, so a test can assert on the wire bytes.
    #[derive(Default)]
    struct Collector(Vec<Vec<u8>>);
    impl futures_util::Sink<Message> for Collector {
        type Error = std::convert::Infallible;
        fn poll_ready(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>)
            -> std::task::Poll<Result<(), Self::Error>> { std::task::Poll::Ready(Ok(())) }
        fn start_send(mut self: std::pin::Pin<&mut Self>, item: Message)
            -> Result<(), Self::Error> {
            if let Message::Binary(b) = item { self.0.push(b.to_vec()); }
            Ok(())
        }
        fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>)
            -> std::task::Poll<Result<(), Self::Error>> { std::task::Poll::Ready(Ok(())) }
        fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>)
            -> std::task::Poll<Result<(), Self::Error>> { std::task::Poll::Ready(Ok(())) }
    }

    /// A k=3 round deposits three replies; all three must reach the client and
    /// none may be sent twice.
    #[tokio::test]
    async fn pump_sends_every_reply_then_deletes_it() {
        let dir = std::env::temp_dir().join(format!("tot_pump_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (n, body) in [("req-a.cbor", "AAA"), ("req-b.cbor", "BBB"), ("req-c.cbor", "CCC")] {
            std::fs::write(dir.join(n), body).unwrap();
        }
        let mut c = Collector::default();
        pump_replies(&mut c, &dir).await.expect("pump");
        assert_eq!(c.0.len(), 3, "all three replies of a k=3 round must be sent");

        // Sent replies are GONE, so a second pass sends nothing — no duplicates.
        let mut c2 = Collector::default();
        pump_replies(&mut c2, &dir).await.expect("pump again");
        assert!(c2.0.is_empty(), "a sent reply must be deleted, never re-sent");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only `.cbor` is ours. ANTIE writes through `tmp/`, and that
    /// subdirectory must never be mistaken for a reply.
    #[tokio::test]
    async fn pump_ignores_non_cbor_and_the_tmp_dir() {
        let dir = std::env::temp_dir().join(format!("tot_pump_x_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tmp")).unwrap();
        std::fs::write(dir.join("tmp/partial.cbor"), "half-written").unwrap();
        std::fs::write(dir.join("notes.txt"), "not a reply").unwrap();
        std::fs::write(dir.join("real.cbor"), "REAL").unwrap();

        let mut c = Collector::default();
        pump_replies(&mut c, &dir).await.expect("pump");
        assert_eq!(c.0, vec![b"REAL".to_vec()],
                   "only top-level .cbor files are replies — never tmp/, never \
                    other files");
        assert!(dir.join("notes.txt").exists(), "a non-reply must not be deleted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `kill -9` runs no destructor, so the Drop guard cannot be the whole
    /// story. At startup nothing can be live, so every session directory there
    /// is garbage — INCLUDING undelivered replies inside it. Ephemeral means
    /// ephemeral; recovery is not attempted and nothing that matters is lost
    /// (Lambda's YPX-016 cache is authoritative and replays on the same
    /// request_id).
    #[test]
    fn startup_sweeps_dirs_left_by_a_killed_process() {
        let root = std::env::temp_dir().join(format!("tot_sweep_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // two orphans, one holding an undelivered reply
        let orphan_a = root.join("aa".repeat(32));
        let orphan_b = root.join("bb".repeat(32));
        std::fs::create_dir_all(&orphan_a).unwrap();
        std::fs::create_dir_all(&orphan_b).unwrap();
        std::fs::write(orphan_a.join("undelivered.cbor"), b"reply").unwrap();
        // an operator's own file sharing the directory must NOT be touched
        std::fs::write(root.join("README"), b"not ours").unwrap();

        let n = sweep_stale_sessions(&root).expect("sweep");
        assert_eq!(n, 2, "both orphaned session dirs must go");
        assert!(!orphan_a.exists() && !orphan_b.exists(),
                "an undelivered reply is DELETED with its dir — no recovery, \
                 by design");
        assert!(root.join("README").exists(),
                "a non-directory entry is not ours to delete");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A fresh deploy has no directory yet — that is not an error.
    #[test]
    fn sweep_creates_a_missing_outbox() {
        let root = std::env::temp_dir().join(format!("tot_sweep_new_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(sweep_stale_sessions(&root).expect("sweep"), 0);
        assert!(root.is_dir(), "outbox must be created when absent");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Two browser tabs on ONE wallet are two sessions and two directories.
    /// This is what the skip list (keyed on receiver_wallet_id) could not do.
    #[test]
    fn two_sessions_get_two_directories() {
        let root = std::env::temp_dir().join(format!("tot_sd_two_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let da = SessionDir::create(&root, &a).unwrap();
        let db = SessionDir::create(&root, &b).unwrap();
        assert_ne!(da.path, db.path, "distinct sessions must not share a directory");
        assert!(da.path.is_dir() && db.path.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }


    const ID: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

    #[test]
    fn stamps_the_header_and_keeps_the_body() {
        let raw = b"From: a@b.com\r\nSubject: hello\r\n\r\nBODY-BYTES\r\n";
        let out = String::from_utf8(stamp_session(raw, ID).unwrap()).unwrap();
        assert!(out.starts_with(&format!("X-TOT-Session: {ID}\r\n")),
                "stamp must be present and first");
        assert!(out.contains("From: a@b.com"), "original headers preserved");
        assert!(out.contains("BODY-BYTES"), "body preserved byte-for-byte");
    }

    /// A client must not be able to choose where its reply is deposited — nor
    /// anyone else's. A client-supplied X-TOT-Session is DROPPED, never merged.
    /// Mutation: delete the `continue` in stamp_session and this goes red with
    /// two stamps present.
    #[test]
    fn client_supplied_stamp_is_dropped() {
        let raw = b"X-TOT-Session: deadbeef\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        let out = String::from_utf8(stamp_session(raw, ID).unwrap()).unwrap();
        assert_eq!(out.matches("X-TOT-Session:").count(), 1,
                   "exactly ONE custody header may survive — two is the \
                    ambiguity YPX-023 3.3 forbids");
        assert!(!out.contains("deadbeef"),
                "the CLIENT's id must not survive — the stamp is TOT's \
                 assertion about a connection it owns, never a client value");
        assert!(out.contains(ID), "TOT's own id must be the one that stands");
    }

    /// Refuse rather than guess: a payload with no header block would be
    /// delivered and then fail to parse deep inside ANTIE.
    #[test]
    fn refuses_a_non_email_payload() {
        assert!(stamp_session(b"just-some-cbor-bytes", ID).is_err());
    }

    #[test]
    fn handles_bare_lf_headers() {
        let raw = b"From: a@b.com\nSubject: x\n\nbody\n";
        let out = String::from_utf8(stamp_session(raw, ID).unwrap()).unwrap();
        assert!(out.contains("From: a@b.com") && out.contains("body"));
        assert_eq!(out.matches("X-TOT-Session:").count(), 1);
    }
}
