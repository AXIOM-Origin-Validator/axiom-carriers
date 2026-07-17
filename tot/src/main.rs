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

use std::path::Path;
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
    Nabla(usize),
    #[cfg(feature = "dev-fatmama")]
    Fatmama(usize),
}

impl Route {
    fn parse(path: &str) -> Option<Route> {
        if path == "/intake" {
            return Some(Route::Intake);
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
