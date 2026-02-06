use hyper::body::Incoming;
use hyper::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

/// WebSocket upgrade detection and raw TCP proxying.
///
/// Once a WebSocket handshake is detected the proxy forwards the initial
/// upgrade request to the upstream backend and then performs a bidirectional
/// byte-level copy for the lifetime of the connection.  No WebSocket frame
/// parsing takes place -- the proxy is completely transparent.
pub struct WebSocketProxy;

impl WebSocketProxy {
    /// Check whether the given HTTP request is a WebSocket upgrade.
    ///
    /// A request is treated as a WebSocket upgrade when it carries both:
    /// - `Connection: Upgrade`
    /// - `Upgrade: websocket`
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

    /// Proxy a WebSocket connection by forwarding the initial upgrade request
    /// bytes and then performing bidirectional I/O between the client and
    /// upstream streams.
    ///
    /// # Arguments
    ///
    /// * `client_stream` -- the raw TCP (or already-decrypted TLS) stream
    ///   from the connecting client.  The initial HTTP request bytes should
    ///   **not** have been consumed from this stream yet; instead they are
    ///   passed separately via `req_bytes`.
    /// * `upstream_addr` -- the `host:port` of the backend server.
    /// * `req_bytes` -- the raw bytes of the HTTP upgrade request that were
    ///   already read from `client_stream`.
    pub async fn proxy_websocket<S>(
        mut client_stream: S,
        upstream_addr: &str,
        req_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        // 1. Connect to the upstream backend.
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

        // 2. Forward the original upgrade request to the upstream.
        upstream_stream.write_all(req_bytes).await?;
        upstream_stream.flush().await?;
        debug!("WebSocket: forwarded upgrade request ({} bytes)", req_bytes.len());

        // 3. Read the upstream's response to the upgrade request and forward
        //    it back to the client.  We read until we see the end-of-headers
        //    marker (\r\n\r\n).
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

            // Check for end-of-headers.
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

            // Grow the buffer if needed.
            if resp_len == resp_buf.len() {
                if resp_buf.len() >= 65536 {
                    return Err("WebSocket: upstream handshake response too large".into());
                }
                resp_buf.resize(resp_buf.len() * 2, 0);
            }
        }

        // Forward the handshake response to the client.
        client_stream.write_all(&resp_buf[..resp_len]).await?;
        client_stream.flush().await?;
        debug!(
            "WebSocket: forwarded upstream handshake response ({} bytes)",
            resp_len
        );

        // Verify we got a 101 Switching Protocols.
        let resp_header = String::from_utf8_lossy(&resp_buf[..resp_len.min(64)]);
        if !resp_header.contains("101") {
            warn!(
                "WebSocket: upstream did not return 101, got: {}",
                resp_header.lines().next().unwrap_or("(empty)")
            );
            return Err("Upstream rejected WebSocket upgrade".into());
        }

        info!("WebSocket: handshake complete, starting bidirectional relay");

        // 4. Bidirectional byte copy.
        //    We split both streams and copy in both directions concurrently.
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_stream);

        let client_to_upstream = async {
            let result = tokio::io::copy(&mut client_read, &mut upstream_write).await;
            // Shut down the write side so the upstream sees EOF.
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
