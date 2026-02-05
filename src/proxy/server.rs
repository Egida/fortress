use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::Request;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::settings::Settings;
use crate::protection::l4_tracker::{L4Action, L4Tracker};
use crate::protection::slowloris::SlowlorisDetector;
use crate::storage::sqlite::SqliteStore;

use super::connection::ConnectionTracker;
use super::http_handler::HttpHandler;
use super::tls::extract_ja3_from_client_hello;
use super::websocket::WebSocketProxy;

/
pub struct ProxyServer {
    settings: Arc<Settings>,
    tls_config: Arc<rustls::ServerConfig>,
    handler: Arc<HttpHandler>,
    connections: Arc<ConnectionTracker>,
    l4_tracker: Option<Arc<L4Tracker>>,
    sqlite: Arc<SqliteStore>,
    slowloris: Arc<SlowlorisDetector>,
}

impl ProxyServer {
    pub fn new(
        settings: Arc<Settings>,
        tls_config: Arc<rustls::ServerConfig>,
        handler: Arc<HttpHandler>,
        connections: Arc<ConnectionTracker>,
        l4_tracker: Option<Arc<L4Tracker>>,
        sqlite: Arc<SqliteStore>,
        slowloris: Arc<SlowlorisDetector>,
    ) -> Self {
        Self {
            settings,
            tls_config,
            handler,
            connections,
            l4_tracker,
            sqlite,
            slowloris,
        }
    }

    /
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let https_addr = &self.settings.server.bind_https;
        let http_addr = &self.settings.server.bind_http;

        let https_listener = bind_tcp_listener(https_addr)?;
        let https_listener = TcpListener::from_std(https_listener.into())?;
        info!(addr = %https_addr, "HTTPS listener started");

        let http_listener = bind_tcp_listener(http_addr)?;
        let http_listener = TcpListener::from_std(http_listener.into())?;
        info!(addr = %http_addr, "HTTP listener started (redirect-to-HTTPS)");

        let tls_acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
        let max_connections = self.settings.server.max_connections;

        let cleanup_connections = Arc::clone(&self.connections);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_connections.cleanup_stale(Duration::from_secs(3600));
            }
        });

        let _http_redirect_handle = tokio::spawn(run_http_redirect(http_listener));

        info!("Fortress proxy is ready to accept connections");

        loop {
            let (stream, peer_addr) = match https_listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    warn!("Failed to accept TCP connection: {}", err);
                    continue;
                }
            };

            let peer_ip = peer_addr.ip();

            if self.connections.active_count() >= max_connections as u64 {
                debug!(client_ip = %peer_ip, "Max connections reached, dropping");
                drop(stream);
                continue;
            }

            let l4_tracker_clone = self.l4_tracker.clone();
            let sqlite_clone = self.sqlite.clone();
            if let Some(ref l4) = l4_tracker_clone {
                match l4.check_connection(peer_ip) {
                    L4Action::Allow => {
                        l4.register_connection(peer_ip);
                    }
                    L4Action::Drop => {
                        let ip_str = peer_ip.to_string();
                        let sqlite = sqlite_clone.clone();
                        let metrics = l4.get_metrics();
                        tokio::spawn(async move {
                            let _ = sqlite.insert_l4_event(
                                &ip_str,
                                "drop",
                                Some("connection_limit_exceeded"),
                                Some(metrics.total_allowed as i64),
                                None,
                            );
                        });
                        drop(stream);
                        continue;
                    }
                    L4Action::Tarpit => {
                        let ip_str = peer_ip.to_string();
                        let sqlite = sqlite_clone.clone();
                        tokio::spawn(async move {
                            let _ = sqlite.insert_l4_event(
                                &ip_str,
                                "tarpit",
                                Some("rate_limit_exceeded"),
                                None,
                                None,
                            );
                        });
                        let delay = l4.tarpit_delay();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            drop(stream);
                        });
                        continue;
                    }
                }
            }

            let slowloris = self.slowloris.clone();
            slowloris.track_connection(peer_ip);

            let acceptor = tls_acceptor.clone();
            let handler = Arc::clone(&self.handler);
            let connections = Arc::clone(&self.connections);
            let slowloris_check = self.slowloris.clone();

            tokio::spawn(async move {
                let result =
                    handle_tls_connection(stream, acceptor, handler, connections, peer_ip).await;

                if let Some(ref l4) = l4_tracker_clone {
                    l4.unregister_connection(peer_ip);
                }

                if let Err(err) = result {
                    if slowloris_check.is_slowloris(&peer_ip) {
                        warn!(
                            client_ip = %peer_ip,
                            "Slowloris attack detected and connection closed"
                        );
                    }

                    debug!(
                        client_ip = %peer_ip,
                        error = %err,
                        "TLS connection handling ended with error"
                    );
                }
            });
        }
    }
}


fn bind_tcp_listener(addr: &str) -> Result<std::net::TcpListener, Box<dyn std::error::Error>> {
    let sock_addr: std::net::SocketAddr = addr.parse()?;

    let domain = if sock_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    {
        socket.set_reuse_port(true)?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(8192)?;

    Ok(socket.into())
}


async fn handle_tls_connection(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    handler: Arc<HttpHandler>,
    connections: Arc<ConnectionTracker>,
    peer_ip: IpAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut peek_buf = [0u8; 1500];
    let peek_len = stream.peek(&mut peek_buf).await.unwrap_or(0);
    let ja3_hash = if peek_len > 0 {
        extract_ja3_from_client_hello(&peek_buf[..peek_len])
    } else {
        None
    };

    if let Some(ref hash) = ja3_hash {
        debug!(client_ip = %peer_ip, ja3 = %hash, "JA3 fingerprint extracted");
    }

    let tls_stream = tls_acceptor.accept(stream).await.map_err(|err| {
        debug!(client_ip = %peer_ip, error = %err, "TLS handshake failed");
        err
    })?;

    let conn_id = connections.register(peer_ip, ja3_hash.clone());

    let _guard = ConnectionGuard {
        connections: Arc::clone(&connections),
        id: conn_id,
    };

    debug!(client_ip = %peer_ip, connection_id = conn_id, "TLS connection established");

    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let io = TokioIo::new(tls_stream);
    let handler = Arc::clone(&handler);
    let ja3 = ja3_hash.clone();

    let service = service_fn(move |req: Request<Incoming>| {
        let h = Arc::clone(&handler);
        let j = ja3.clone();
        async move {
            if WebSocketProxy::is_websocket_upgrade(&req) {
                info!(
                    client_ip = %peer_ip,
                    path = %req.uri().path(),
                    "WebSocket upgrade detected (will be handled after response)"
                );
            }

            let resp = h.handle(req, peer_ip, j, conn_id).await;
            Ok::<_, hyper::Error>(resp)
        }
    });

    let conn = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service);

    if let Err(err) = conn.await {
        debug!(
            client_ip = %peer_ip,
            connection_id = conn_id,
            error = %err,
            "HTTP connection error"
        );
    }

    Ok(())
}


async fn run_http_redirect(listener: TcpListener) {
    loop {
        let (mut stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                warn!("HTTP redirect listener accept error: {}", err);
                continue;
            }
        };

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;

            loop {
                match stream.read(&mut buf[total..]).await {
                    Ok(0) => return,
                    Ok(n) => {
                        total += n;
                        if total >= 4
                            && buf[..total]
                                .windows(4)
                                .any(|w| w == b"\r\n\r\n")
                        {
                            break;
                        }
                        if total >= buf.len() {
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }

            let raw = String::from_utf8_lossy(&buf[..total]);
            let mut host = String::new();
            let mut path = String::from("/");

            for (i, line) in raw.lines().enumerate() {
                if i == 0 {
                    let mut parts = line.split_whitespace();
                    let _method = parts.next();
                    if let Some(p) = parts.next() {
                        path = p.to_string();
                    }
                } else if let Some((name, value)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case("host") {
                        host = value.trim().to_string();
                    }
                }
            }

            let redirect_host = host.split(':').next().unwrap_or(&host);
            let location = format!("https://{}{}", redirect_host, path);
            let body = format!(
                "<html><body><h1>301 Moved Permanently</h1>\
                 <p><a href=\"{loc}\">{loc}</a></p></body></html>",
                loc = location
            );

            let response = format!(
                "HTTP/1.1 301 Moved Permanently\r\n\
                 Location: {location}\r\n\
                 Content-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {len}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                location = location,
                len = body.len(),
                body = body,
            );

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;

            debug!(
                client_ip = %peer_addr.ip(),
                redirect_to = %location,
                "HTTP -> HTTPS redirect"
            );
        });
    }
}


struct ConnectionGuard {
    connections: Arc<ConnectionTracker>,
    id: u64,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.connections.remove(self.id);
    }
}
