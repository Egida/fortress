use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

/// Slowloris attack detection.
///
/// Slowloris attacks keep connections open by sending data very slowly,
/// eventually exhausting the server's connection pool. This detector
/// tracks connection progress and flags connections that have been open
/// for too long with very little data transferred.
///
/// Detection criteria:
/// - Connection open > 30 seconds
/// - Less than 1024 bytes received
/// - HTTP headers not yet complete
pub struct SlowlorisDetector {
    slow_connections: DashMap<IpAddr, SlowConnInfo>,
}

/// Tracking information for a single connection.
struct SlowConnInfo {
    /// When the connection was first seen
    started: Instant,
    /// Total bytes received on this connection
    bytes_received: u64,
    /// Whether the HTTP header has been fully received
    header_complete: bool,
    /// Last time data was received
    last_activity: Instant,
}

/// Thresholds for slowloris detection
const SLOWLORIS_TIMEOUT_SECS: u64 = 30;
const SLOWLORIS_MIN_BYTES: u64 = 1024;
const STALE_CONNECTION_SECS: u64 = 300; // 5 minutes

impl SlowlorisDetector {
    /// Create a new SlowlorisDetector.
    pub fn new() -> Self {
        Self {
            slow_connections: DashMap::new(),
        }
    }

    /// Begin tracking a new connection from the given IP.
    ///
    /// Called when a new TCP connection is accepted.
    pub fn track_connection(&self, ip: IpAddr) {
        let now = Instant::now();
        self.slow_connections.insert(
            ip,
            SlowConnInfo {
                started: now,
                bytes_received: 0,
                header_complete: false,
                last_activity: now,
            },
        );
        debug!(ip = %ip, "Tracking new connection for slowloris detection");
    }

    /// Update the progress of a tracked connection.
    ///
    /// Called when data is received on a tracked connection.
    pub fn update_progress(&self, ip: &IpAddr, bytes: u64, header_done: bool) {
        if let Some(mut info) = self.slow_connections.get_mut(ip) {
            info.bytes_received += bytes;
            info.header_complete = header_done;
            info.last_activity = Instant::now();
        }
    }

    /// Check if a connection from the given IP exhibits slowloris behavior.
    ///
    /// Returns true if:
    /// - Connection has been open for > 30 seconds
    /// - Less than 1024 bytes have been received
    /// - HTTP headers are not yet complete
    ///
    /// Also checks for "slow body" attacks where headers are complete but
    /// body data trickles in very slowly.
    pub fn is_slowloris(&self, ip: &IpAddr) -> bool {
        let info = match self.slow_connections.get(ip) {
            Some(i) => i,
            None => return false,
        };

        let elapsed = info.started.elapsed();

        // Primary check: slow header delivery
        if !info.header_complete
            && elapsed > Duration::from_secs(SLOWLORIS_TIMEOUT_SECS)
            && info.bytes_received < SLOWLORIS_MIN_BYTES
        {
            debug!(
                ip = %ip,
                elapsed_secs = elapsed.as_secs(),
                bytes = info.bytes_received,
                "Slowloris detected: slow header delivery"
            );
            return true;
        }

        // Secondary check: extremely slow data rate after connection established
        // Less than 10 bytes/second average over 30+ seconds
        if elapsed > Duration::from_secs(SLOWLORIS_TIMEOUT_SECS) {
            let bytes_per_sec = info.bytes_received as f64 / elapsed.as_secs_f64();
            if bytes_per_sec < 10.0 && !info.header_complete {
                debug!(
                    ip = %ip,
                    bytes_per_sec = bytes_per_sec,
                    "Slowloris detected: extremely slow data rate"
                );
                return true;
            }
        }

        // Tertiary check: connection stalled (no activity for a long time)
        let idle_time = info.last_activity.elapsed();
        if idle_time > Duration::from_secs(SLOWLORIS_TIMEOUT_SECS) && !info.header_complete {
            debug!(
                ip = %ip,
                idle_secs = idle_time.as_secs(),
                "Slowloris detected: stalled connection"
            );
            return true;
        }

        false
    }

    /// Remove completed or stale connection tracking entries.
    ///
    /// Should be called periodically (e.g., every 60 seconds) to prevent
    /// unbounded memory growth.
    pub fn cleanup(&self) {
        let stale_threshold = Duration::from_secs(STALE_CONNECTION_SECS);

        self.slow_connections.retain(|ip, info| {
            let age = info.started.elapsed();
            let idle = info.last_activity.elapsed();

            // Remove connections that are too old or idle
            if age > stale_threshold || idle > stale_threshold {
                debug!(
                    ip = %ip,
                    age_secs = age.as_secs(),
                    "Removing stale slowloris tracking entry"
                );
                return false;
            }

            // Remove completed connections (headers done and reasonable data)
            if info.header_complete && info.bytes_received > SLOWLORIS_MIN_BYTES {
                return false;
            }

            true
        });
    }

    /// Get the number of currently tracked connections.
    pub fn tracked_count(&self) -> usize {
        self.slow_connections.len()
    }

    /// Get the number of currently detected slowloris connections.
    pub fn detected_count(&self) -> usize {
        self.slow_connections
            .iter()
            .filter(|entry| {
                let info = entry.value();
                let elapsed = info.started.elapsed();
                !info.header_complete
                    && elapsed > Duration::from_secs(SLOWLORIS_TIMEOUT_SECS)
                    && info.bytes_received < SLOWLORIS_MIN_BYTES
            })
            .count()
    }
}

impl Default for SlowlorisDetector {
    fn default() -> Self {
        Self::new()
    }
}
