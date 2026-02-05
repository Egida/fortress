use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

/
///
/
/
/
/
///
/
/
/
/
pub struct SlowlorisDetector {
    slow_connections: DashMap<IpAddr, SlowConnInfo>,
}

/
struct SlowConnInfo {
    /
    started: Instant,
    /
    bytes_received: u64,
    /
    header_complete: bool,
    /
    last_activity: Instant,
}

/
const SLOWLORIS_TIMEOUT_SECS: u64 = 30;
const SLOWLORIS_MIN_BYTES: u64 = 1024;
const STALE_CONNECTION_SECS: u64 = 300;

impl SlowlorisDetector {
    /
    pub fn new() -> Self {
        Self {
            slow_connections: DashMap::new(),
        }
    }

    /
    ///
    /
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

    /
    ///
    /
    pub fn update_progress(&self, ip: &IpAddr, bytes: u64, header_done: bool) {
        if let Some(mut info) = self.slow_connections.get_mut(ip) {
            info.bytes_received += bytes;
            info.header_complete = header_done;
            info.last_activity = Instant::now();
        }
    }

    /
    ///
    /
    /
    /
    /
    ///
    /
    /
    pub fn is_slowloris(&self, ip: &IpAddr) -> bool {
        let info = match self.slow_connections.get(ip) {
            Some(i) => i,
            None => return false,
        };

        let elapsed = info.started.elapsed();

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

    /
    ///
    /
    /
    pub fn cleanup(&self) {
        let stale_threshold = Duration::from_secs(STALE_CONNECTION_SECS);

        self.slow_connections.retain(|ip, info| {
            let age = info.started.elapsed();
            let idle = info.last_activity.elapsed();

            if age > stale_threshold || idle > stale_threshold {
                debug!(
                    ip = %ip,
                    age_secs = age.as_secs(),
                    "Removing stale slowloris tracking entry"
                );
                return false;
            }

            if info.header_complete && info.bytes_received > SLOWLORIS_MIN_BYTES {
                return false;
            }

            true
        });
    }

    /
    pub fn tracked_count(&self) -> usize {
        self.slow_connections.len()
    }

    /
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
