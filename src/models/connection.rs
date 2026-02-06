use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Tracks the state of a single client connection throughout its lifetime.
#[derive(Debug)]
pub struct ConnectionInfo {
    /// Unique connection identifier.
    pub id: u64,

    /// Remote client IP address.
    pub client_ip: IpAddr,

    /// Timestamp when the connection was established.
    pub connected_at: Instant,

    /// Total bytes sent to the client.
    pub bytes_sent: AtomicU64,

    /// Total bytes received from the client.
    pub bytes_received: AtomicU64,

    /// Number of HTTP requests served on this connection.
    pub requests: AtomicU64,

    /// JA3 TLS fingerprint hash (populated after TLS handshake).
    pub ja3_hash: Option<String>,

    /// Negotiated TLS version string (e.g. "TLSv1.3").
    pub tls_version: Option<String>,
}

impl ConnectionInfo {
    /// Create a new connection tracker.
    pub fn new(id: u64, client_ip: IpAddr) -> Self {
        Self {
            id,
            client_ip,
            connected_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            ja3_hash: None,
            tls_version: None,
        }
    }

    /// Record bytes sent to the client.
    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Record bytes received from the client.
    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment the request counter and return the new value.
    pub fn increment_requests(&self) -> u64 {
        self.requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Elapsed time since the connection was established.
    pub fn duration(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    /// Get the current bytes-sent counter.
    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get the current bytes-received counter.
    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get the current request count.
    pub fn get_requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}
