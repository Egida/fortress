use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/
#[derive(Debug)]
pub struct ConnectionInfo {
    /
    pub id: u64,

    /
    pub client_ip: IpAddr,

    /
    pub connected_at: Instant,

    /
    pub bytes_sent: AtomicU64,

    /
    pub bytes_received: AtomicU64,

    /
    pub requests: AtomicU64,

    /
    pub ja3_hash: Option<String>,

    /
    pub tls_version: Option<String>,
}

impl ConnectionInfo {
    /
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

    /
    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /
    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /
    pub fn increment_requests(&self) -> u64 {
        self.requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    /
    pub fn duration(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    /
    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /
    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /
    pub fn get_requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}
