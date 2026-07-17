//! The /nabla leg — an opaque WebSocket<->TCP byte pump.
//!
//! TOT terminates nothing and decodes nothing here: bytes from the
//! webclient's WebSocket are written to the Nabla TCP socket and back,
//! verbatim. All framing and all protocol meaning live above this
//! layer (AXIOM_DESIGN_TOT.md §5).

use futures_util::{SinkExt, StreamExt};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// Relay bytes both ways between a WebSocket and a TCP stream until
/// either side closes.
pub async fn pump<S>(ws: WebSocketStream<S>, tcp: TcpStream) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();

    let client_to_nabla = async {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(b)) => tcp_tx.write_all(&b).await?,
                Ok(Message::Close(_)) => break,
                Ok(_) => {} // text / ping / pong are not tunnel payload
                Err(_) => break,
            }
        }
        let _ = tcp_tx.shutdown().await;
        Ok::<(), io::Error>(())
    };

    let nabla_to_client = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = tcp_rx.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if ws_tx
                .send(Message::Binary(buf[..n].to_vec()))
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = ws_tx.close().await;
        Ok::<(), io::Error>(())
    };

    tokio::try_join!(client_to_nabla, nabla_to_client)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pump_relays_bytes_both_ways() {
        // A TCP echo server stands in for a Nabla node.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nabla_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // A WebSocket pair over an in-memory duplex.
        let (a, b) = tokio::io::duplex(16 * 1024);
        let (server_ws, (mut client_ws, _resp)) = tokio::join!(
            async { tokio_tungstenite::accept_async(a).await.unwrap() },
            async {
                tokio_tungstenite::client_async("ws://localhost/nabla/0", b)
                    .await
                    .unwrap()
            },
        );

        let nabla = TcpStream::connect(nabla_addr).await.unwrap();
        tokio::spawn(async move {
            let _ = pump(server_ws, nabla).await;
        });

        client_ws
            .send(Message::Binary(b"ping-axiom".to_vec()))
            .await
            .unwrap();
        let got = client_ws.next().await.unwrap().unwrap();
        assert_eq!(got.into_data().as_slice(), b"ping-axiom");
    }
}
