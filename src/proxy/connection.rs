use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, info};

/// Snapshot of a single connection suitable for serialisation / API responses.
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub id: u64,
    pub client_ip: IpAddr,
    pub connected_at_secs_ago: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests: u64,
    pub ja3_hash: Option<String>,
    pub host: Option<String>,
}

/// Per-connection live state.
pub struct ConnectionInfo {
    pub id: u64,
    pub client_ip: IpAddr,
    pub connected_at: Instant,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub requests: AtomicU64,
    pub ja3_hash: Option<String>,
    pub host: Option<String>,
}

/// Thread-safe tracker for all active proxy connections.
///
/// Connections are identified by a monotonically increasing `u64` ID.
pub struct ConnectionTracker {
    next_id: AtomicU64,
    active: DashMap<u64, ConnectionInfo>,
}

impl ConnectionTracker {
    /// Create a new, empty tracker.
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            active: DashMap::new(),
        }
    }

    /// Register a new connection and return its unique ID.
    pub fn register(&self, ip: IpAddr, ja3: Option<String>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let info = ConnectionInfo {
            id,
            client_ip: ip,
            connected_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            ja3_hash: ja3,
            host: None,
        };

        self.active.insert(id, info);
        debug!(connection_id = id, client_ip = %ip, "Connection registered");
        id
    }

    /// Remove a connection by ID (called on disconnect).
    pub fn remove(&self, id: u64) {
        if let Some((_, info)) = self.active.remove(&id) {
            debug!(
                connection_id = id,
                client_ip = %info.client_ip,
                duration_secs = info.connected_at.elapsed().as_secs(),
                bytes_sent = info.bytes_sent.load(Ordering::Relaxed),
                bytes_received = info.bytes_received.load(Ordering::Relaxed),
                requests = info.requests.load(Ordering::Relaxed),
                "Connection removed"
            );
        }
    }

    /// Increment the byte counters for a given connection.
    pub fn update_bytes(&self, id: u64, sent: u64, received: u64) {
        if let Some(entry) = self.active.get(&id) {
            entry.bytes_sent.fetch_add(sent, Ordering::Relaxed);
            entry.bytes_received.fetch_add(received, Ordering::Relaxed);
        }
    }

    /// Increment the request counter for a given connection.
    pub fn increment_requests(&self, id: u64) {
        if let Some(entry) = self.active.get(&id) {
            entry.requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Associate a Host header value with a connection.
    pub fn set_host(&self, id: u64, host: String) {
        if let Some(mut entry) = self.active.get_mut(&id) {
            entry.host = Some(host);
        }
    }

    /// Return the number of currently active connections.
    pub fn active_count(&self) -> u64 {
        self.active.len() as u64
    }

    /// Count active connections from a specific IP.
    pub fn count_by_ip(&self, ip: &IpAddr) -> u64 {
        self.active.iter().filter(|entry| entry.value().client_ip == *ip).count() as u64
    }

    /// Return a snapshot of every active connection (safe to serialise).
    pub fn get_all(&self) -> Vec<ConnectionSnapshot> {
        let now = Instant::now();

        self.active
            .iter()
            .map(|entry| {
                let info = entry.value();
                ConnectionSnapshot {
                    id: info.id,
                    client_ip: info.client_ip,
                    connected_at_secs_ago: now
                        .duration_since(info.connected_at)
                        .as_secs(),
                    bytes_sent: info.bytes_sent.load(Ordering::Relaxed),
                    bytes_received: info.bytes_received.load(Ordering::Relaxed),
                    requests: info.requests.load(Ordering::Relaxed),
                    ja3_hash: info.ja3_hash.clone(),
                    host: info.host.clone(),
                }
            })
            .collect()
    }

    /// Remove connections that have been open longer than `max_age`.
    pub fn cleanup_stale(&self, max_age: Duration) {
        let now = Instant::now();
        let mut removed: u64 = 0;

        self.active.retain(|_id, info| {
            let alive = now.duration_since(info.connected_at) < max_age;
            if !alive {
                removed += 1;
            }
            alive
        });

        if removed > 0 {
            info!(
                removed = removed,
                remaining = self.active.len(),
                "Cleaned up stale connections"
            );
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}
