use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::settings::L4ProtectionConfig;
use crate::models::metrics::L4MetricsSnapshot;

/// Action the proxy should take for a new TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Action {
    Allow,
    Drop,
    Tarpit,
}

/// Per-IP tracking state.
struct IpState {
    concurrent: AtomicU64,
    /// Ring of recent connection timestamps (second-granularity).
    recent_connects: std::sync::Mutex<Vec<Instant>>,
}

/// TCP-level (Layer 4) connection tracker and rate limiter.
///
/// Operates *before* the TLS handshake so it can shed load from
/// volumetric attacks without wasting CPU on crypto.
pub struct L4Tracker {
    config: L4ProtectionConfig,
    ip_states: DashMap<IpAddr, IpState>,
    total_allowed: AtomicU64,
    total_dropped: AtomicU64,
    total_tarpitted: AtomicU64,
}

impl L4Tracker {
    /// Create a new tracker with the given configuration.
    pub fn new(config: L4ProtectionConfig) -> Self {
        Self {
            config,
            ip_states: DashMap::new(),
            total_allowed: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_tarpitted: AtomicU64::new(0),
        }
    }

    /// Decide whether to allow, drop, or tarpit a new connection from `ip`.
    pub fn check_connection(&self, ip: IpAddr) -> L4Action {
        let state = self.ip_states.entry(ip).or_insert_with(|| IpState {
            concurrent: AtomicU64::new(0),
            recent_connects: std::sync::Mutex::new(Vec::new()),
        });

        let concurrent = state.concurrent.load(Ordering::Relaxed);

        // Check concurrent connection limit.
        if concurrent >= self.config.max_concurrent_per_ip {
            warn!(client_ip = %ip, concurrent = concurrent, "L4: max concurrent connections exceeded");
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return L4Action::Drop;
        }

        // Check connection rate.
        if let Ok(mut recent) = state.recent_connects.lock() {
            let now = Instant::now();
            let one_sec_ago = now - Duration::from_secs(1);
            recent.retain(|t| *t > one_sec_ago);
            let rate = recent.len() as u64;

            if rate >= self.config.connection_rate_per_ip_per_sec {
                if self.config.tarpit_enabled {
                    debug!(client_ip = %ip, rate = rate, "L4: connection rate exceeded, tarpitting");
                    self.total_tarpitted.fetch_add(1, Ordering::Relaxed);
                    return L4Action::Tarpit;
                } else {
                    debug!(client_ip = %ip, rate = rate, "L4: connection rate exceeded, dropping");
                    self.total_dropped.fetch_add(1, Ordering::Relaxed);
                    return L4Action::Drop;
                }
            }

            recent.push(now);
        }

        self.total_allowed.fetch_add(1, Ordering::Relaxed);
        L4Action::Allow
    }

    /// Register that a connection from `ip` is now active.
    pub fn register_connection(&self, ip: IpAddr) {
        if let Some(state) = self.ip_states.get(&ip) {
            state.concurrent.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Unregister that a connection from `ip` has closed.
    pub fn unregister_connection(&self, ip: IpAddr) {
        if let Some(state) = self.ip_states.get(&ip) {
            // Use compare_exchange loop to prevent atomic underflow
            loop {
                let current = state.concurrent.load(Ordering::Relaxed);
                if current == 0 {
                    break;
                }
                if state.concurrent.compare_exchange(current, current - 1, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    break;
                }
            }
        }
    }

    /// Return the tarpit delay duration from the config.
    pub fn tarpit_delay(&self) -> Duration {
        Duration::from_millis(self.config.tarpit_delay_ms)
    }

    /// Get a snapshot of L4 metrics.
    pub fn get_metrics(&self) -> L4MetricsSnapshot {
        L4MetricsSnapshot {
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            total_dropped: self.total_dropped.load(Ordering::Relaxed),
            total_tarpitted: self.total_tarpitted.load(Ordering::Relaxed),
            tracked_ips: self.ip_states.len() as u64,
        }
    }

    /// Remove IP entries that have zero concurrent connections and no recent
    /// activity. Called periodically from the cleanup loop.
    pub fn cleanup(&self) {
        let before = self.ip_states.len();
        self.ip_states.retain(|_ip, state| {
            let concurrent = state.concurrent.load(Ordering::Relaxed);
            if concurrent > 0 {
                return true;
            }
            if let Ok(recent) = state.recent_connects.lock() {
                let cutoff = Instant::now() - Duration::from_secs(60);
                recent.iter().any(|t| *t > cutoff)
            } else {
                false
            }
        });
        let removed = before - self.ip_states.len();
        if removed > 0 {
            info!(removed = removed, remaining = self.ip_states.len(), "L4 tracker cleanup");
        }
    }
}
