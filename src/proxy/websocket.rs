use hyper::body::Incoming;
use hyper::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

/
///
/
/
/
/
pub struct WebSocketProxy;

impl WebSocketProxy {
    /
    ///
    /
    /
    /
    pub fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
        let has_upgrade_header = req
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        let has_connection_upgrade = req
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false);

        has_upgrade_header && has_connection_upgrade
    }

    /
    /
    /
    ///
    /
    ///
    /
    /
    /
    /
    /
    /
    /
    pub async fn proxy_websocket<S>(
        mut client_stream: S,
        upstream_addr: &str,
        req_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let mut upstream_stream =
            tokio::net::TcpStream::connect(upstream_addr).await.map_err(|err| {
                error!(
                    upstream = %upstream_addr,
                    error = %err,
                    "WebSocket: failed to connect to upstream"
                );
                err
            })?;

        info!(upstream = %upstream_addr, "WebSocket: connected to upstream");

        upstream_stream.write_all(req_bytes).await?;
        upstream_stream.flush().await?;
        debug!("WebSocket: forwarded upgrade request ({} bytes)", req_bytes.len());

        let mut resp_buf = vec![0u8; 4096];
        let mut resp_len: usize = 0;
        let mut header_complete = false;

        loop {
            let n = upstream_stream.read(&mut resp_buf[resp_len..]).await?;
            if n == 0 {
                warn!("WebSocket: upstream closed before completing handshake");
                return Err("Upstream closed during WebSocket handshake".into());
            }
            resp_len += n;

            if resp_len >= 4 {
                for i in 0..=(resp_len - 4) {
                    if &resp_buf[i..i + 4] == b"\r\n\r\n" {
                        header_complete = true;
                        break;
                    }
                }
            }

            if header_complete {
                break;
            }

            if resp_len == resp_buf.len() {
                if resp_buf.len() >= 65536 {
                    return Err("WebSocket: upstream handshake response too large".into());
                }
                resp_buf.resize(resp_buf.len() * 2, 0);
            }
        }

        client_stream.write_all(&resp_buf[..resp_len]).await?;
        client_stream.flush().await?;
        debug!(
            "WebSocket: forwarded upstream handshake response ({} bytes)",
            resp_len
        );

        let resp_header = String::from_utf8_lossy(&resp_buf[..resp_len.min(64)]);
        if !resp_header.contains("101") {
            warn!(
                "WebSocket: upstream did not return 101, got: {}",
                resp_header.lines().next().unwrap_or("(empty)")
            );
            return Err("Upstream rejected WebSocket upgrade".into());
        }

        info!("WebSocket: handshake complete, starting bidirectional relay");

        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_stream);

        let client_to_upstream = async {
            let result = tokio::io::copy(&mut client_read, &mut upstream_write).await;
            let _ = upstream_write.shutdown().await;
            result
        };

        let upstream_to_client = async {
            let result = tokio::io::copy(&mut upstream_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
            result
        };

        let (c2u, u2c) = tokio::join!(client_to_upstream, upstream_to_client);

        match (&c2u, &u2c) {
            (Ok(sent), Ok(received)) => {
                info!(
                    sent_bytes = sent,
                    received_bytes = received,
                    "WebSocket: connection closed normally"
                );
            }
            _ => {
                if let Err(ref err) = c2u {
                    debug!("WebSocket: client->upstream copy error: {}", err);
                }
                if let Err(ref err) = u2c {
                    debug!("WebSocket: upstream->client copy error: {}", err);
                }
            }
        }

        Ok(())
    }
}
