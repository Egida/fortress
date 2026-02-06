use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Rate-limit configuration (expected to be defined elsewhere; redeclared here
// so the module is self-contained).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub ip_per_second: u64,
    pub subnet_per_second: u64,
    pub asn_per_second: u64,
    pub country_per_second: u64,
}

// ---------------------------------------------------------------------------
// SlidingWindow – per-key counter that only keeps data inside the window.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SlidingWindow {
    counts: VecDeque<(Instant, u64)>,
    window_secs: u64,
}

impl SlidingWindow {
    pub fn new(window_secs: u64) -> Self {
        Self {
            counts: VecDeque::new(),
            window_secs,
        }
    }

    pub fn increment(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.counts.back_mut() {
            // Coalesce increments that arrive within 1 ms of each other.
            if now.duration_since(last.0) < Duration::from_millis(1) {
                last.1 += 1;
                return;
            }
        }
        self.counts.push_back((now, 1));
    }

    pub fn count(&self) -> u64 {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(self.window_secs);
        self.counts
            .iter()
            .filter(|(ts, _)| *ts >= cutoff)
            .map(|(_, c)| c)
            .sum()
    }

    pub fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(self.window_secs);
        while let Some(front) = self.counts.front() {
            if front.0 < cutoff {
                self.counts.pop_front();
            } else {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BehaviorProfile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    pub request_intervals: VecDeque<Duration>,
    pub paths_visited: HashSet<u64>, // hashed paths
    pub methods_used: HashMap<String, u32>,
    pub total_requests: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub ja3_hash: Option<String>,
    pub user_agent: Option<String>,
    pub consistency_violations: u32,
}

impl BehaviorProfile {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            request_intervals: VecDeque::new(),
            paths_visited: HashSet::new(),
            methods_used: HashMap::new(),
            total_requests: 0,
            first_seen: now,
            last_seen: now,
            ja3_hash: None,
            user_agent: None,
            consistency_violations: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BlockedEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BlockedEntry {
    pub reason: String,
    pub expires_at: Option<Instant>,
    pub source: String,
}

// ---------------------------------------------------------------------------
// Helper: map IPv4 to /24 represented as u32
// ---------------------------------------------------------------------------

pub fn ip_to_subnet(ip: IpAddr, mask_bits: u8) -> u32 {
    match ip {
        IpAddr::V4(v4) => {
            let ip_u32 = u32::from(v4);
            let mask = if mask_bits >= 32 {
                0xFFFFFFFFu32
            } else {
                !((1u32 << (32 - mask_bits)) - 1)
            };
            ip_u32 & mask
        }
        IpAddr::V6(_) => {
            // For IPv6 we just return 0; real subnet handling for v6 would
            // require larger key types.
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Simple non-crypto hash for path strings (FNV-1a 64-bit)
// ---------------------------------------------------------------------------

fn hash_path(path: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in path.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// MemoryStore
// ---------------------------------------------------------------------------

pub struct MemoryStore {
    // Rate limiting
    ip_requests: DashMap<IpAddr, SlidingWindow>,
    subnet_requests: DashMap<u32, SlidingWindow>,
    asn_requests: DashMap<u32, SlidingWindow>,
    country_requests: DashMap<String, SlidingWindow>,

    // Behavioral profiles
    behavior_profiles: DashMap<IpAddr, BehaviorProfile>,

    // Blocked IPs (runtime cache from SQLite)
    blocked_ips: DashMap<IpAddr, BlockedEntry>,

    // Challenge clearances
    clearances: DashMap<IpAddr, Instant>, // IP -> expiry

    // Active connections
    active_connections: AtomicU64,

    // Metrics counters
    total_requests: AtomicU64,
    passed_requests: AtomicU64,
    blocked_requests: AtomicU64,
    challenged_requests: AtomicU64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            ip_requests: DashMap::new(),
            subnet_requests: DashMap::new(),
            asn_requests: DashMap::new(),
            country_requests: DashMap::new(),
            behavior_profiles: DashMap::new(),
            blocked_ips: DashMap::new(),
            clearances: DashMap::new(),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            passed_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            challenged_requests: AtomicU64::new(0),
        }
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    /// Increment sliding-window counters for every dimension.
    pub fn record_request(&self, ip: IpAddr, subnet: u32, asn: u32, country: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        self.ip_requests
            .entry(ip)
            .or_insert_with(|| SlidingWindow::new(1))
            .increment();

        self.subnet_requests
            .entry(subnet)
            .or_insert_with(|| SlidingWindow::new(1))
            .increment();

        self.asn_requests
            .entry(asn)
            .or_insert_with(|| SlidingWindow::new(1))
            .increment();

        self.country_requests
            .entry(country.to_string())
            .or_insert_with(|| SlidingWindow::new(1))
            .increment();
    }

    /// Returns `Some(reason)` if any rate limit is exceeded.
    pub fn check_rate_limit(
        &self,
        ip: IpAddr,
        subnet: u32,
        asn: u32,
        country: &str,
        limits: &RateLimitConfig,
    ) -> Option<String> {
        if let Some(window) = self.ip_requests.get(&ip) {
            let count = window.count();
            if count > limits.ip_per_second {
                return Some(format!(
                    "IP rate limit exceeded: {} req/s (limit {})",
                    count, limits.ip_per_second
                ));
            }
        }

        if let Some(window) = self.subnet_requests.get(&subnet) {
            let count = window.count();
            if count > limits.subnet_per_second {
                return Some(format!(
                    "Subnet /24 rate limit exceeded: {} req/s (limit {})",
                    count, limits.subnet_per_second
                ));
            }
        }

        if let Some(window) = self.asn_requests.get(&asn) {
            let count = window.count();
            if count > limits.asn_per_second {
                return Some(format!(
                    "ASN {} rate limit exceeded: {} req/s (limit {})",
                    asn,
                    count,
                    limits.asn_per_second
                ));
            }
        }

        if let Some(window) = self.country_requests.get(country) {
            let count = window.count();
            if count > limits.country_per_second {
                return Some(format!(
                    "Country {} rate limit exceeded: {} req/s (limit {})",
                    country, count, limits.country_per_second
                ));
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // Block-list cache
    // -----------------------------------------------------------------------

    pub fn is_blocked(&self, ip: &IpAddr) -> Option<BlockedEntry> {
        if let Some(entry) = self.blocked_ips.get(ip) {
            let e = entry.value();
            // Check expiry
            if let Some(exp) = e.expires_at {
                if Instant::now() >= exp {
                    drop(entry);
                    self.blocked_ips.remove(ip);
                    return None;
                }
            }
            return Some(e.clone());
        }
        None
    }

    pub fn block_ip(&self, ip: IpAddr, reason: String, duration: Option<Duration>) {
        let expires_at = duration.map(|d| Instant::now() + d);
        self.blocked_ips.insert(
            ip,
            BlockedEntry {
                reason,
                expires_at,
                source: "auto".to_string(),
            },
        );
    }

    pub fn unblock_ip(&self, ip: &IpAddr) {
        self.blocked_ips.remove(ip);
    }

    // -----------------------------------------------------------------------
    // Challenge clearances
    // -----------------------------------------------------------------------

    pub fn has_clearance(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.clearances.get(ip) {
            if Instant::now() < *entry.value() {
                return true;
            }
            drop(entry);
            self.clearances.remove(ip);
        }
        false
    }

    pub fn grant_clearance(&self, ip: IpAddr, duration: Duration) {
        self.clearances.insert(ip, Instant::now() + duration);
    }

    // -----------------------------------------------------------------------
    // Behavioral profiling
    // -----------------------------------------------------------------------

    /// Update the behavioral profile for `ip` and return a suspicion score
    /// in the range `[0.0, 1.0]`.  Higher means more suspicious.
    pub fn update_behavior(
        &self,
        ip: IpAddr,
        path: &str,
        method: &str,
        ja3: Option<&str>,
        ua: Option<&str>,
    ) -> f64 {
        let mut profile = self
            .behavior_profiles
            .entry(ip)
            .or_insert_with(BehaviorProfile::new);

        let now = Instant::now();
        let interval = now.duration_since(profile.last_seen);
        profile.last_seen = now;
        profile.total_requests += 1;

        // Record inter-request interval (keep last 100).
        if profile.request_intervals.len() >= 100 {
            profile.request_intervals.pop_front();
        }
        profile.request_intervals.push_back(interval);

        // Record path and method
        profile.paths_visited.insert(hash_path(path));
        *profile.methods_used.entry(method.to_string()).or_insert(0) += 1;

        // Check JA3 / UA consistency
        if let Some(j) = ja3 {
            match &profile.ja3_hash {
                Some(prev) if prev != j => {
                    profile.consistency_violations += 1;
                    profile.ja3_hash = Some(j.to_string());
                }
                None => {
                    profile.ja3_hash = Some(j.to_string());
                }
                _ => {}
            }
        }

        if let Some(u) = ua {
            match &profile.user_agent {
                Some(prev) if prev != u => {
                    profile.consistency_violations += 1;
                    profile.user_agent = Some(u.to_string());
                }
                None => {
                    profile.user_agent = Some(u.to_string());
                }
                _ => {}
            }
        }

        // --- Compute suspicion score ---
        let mut score: f64 = 0.0;

        // 1. Request-interval regularity: very uniform intervals are suspicious
        //    (bots often fire at fixed intervals).
        if profile.request_intervals.len() >= 5 {
            let intervals: Vec<f64> = profile
                .request_intervals
                .iter()
                .map(|d| d.as_secs_f64())
                .collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean > 0.0 {
                let variance = intervals
                    .iter()
                    .map(|v| (v - mean).powi(2))
                    .sum::<f64>()
                    / intervals.len() as f64;
                let cv = variance.sqrt() / mean; // coefficient of variation
                // Very low CV => regular intervals => mildly suspicious
                // (Reduced: monitoring systems and health checks are legitimate)
                if cv < 0.05 {
                    score += 0.15;
                } else if cv < 0.15 {
                    score += 0.05;
                }
            }
        }

        // 2. Very high request rate
        if profile.total_requests > 100 {
            let elapsed = now.duration_since(profile.first_seen).as_secs_f64();
            if elapsed > 0.0 {
                let rps = profile.total_requests as f64 / elapsed;
                if rps > 50.0 {
                    score += 0.3;
                } else if rps > 20.0 {
                    score += 0.15;
                }
            }
        }

        // 3. Path diversity: very few distinct paths with many requests
        // (Raised from 20 to 50 to avoid penalizing single-endpoint APIs)
        if profile.total_requests > 50 && profile.paths_visited.len() <= 2 {
            score += 0.10;
        }

        // 4. Consistency violations
        if profile.consistency_violations > 0 {
            score += (profile.consistency_violations as f64 * 0.1).min(0.25);
        }

        score.min(1.0)
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------

    /// Remove expired entries from every map.
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Sliding windows
        self.ip_requests.iter_mut().for_each(|mut entry| entry.value_mut().cleanup());
        self.subnet_requests.iter_mut().for_each(|mut entry| entry.value_mut().cleanup());
        self.asn_requests.iter_mut().for_each(|mut entry| entry.value_mut().cleanup());
        self.country_requests.iter_mut().for_each(|mut entry| entry.value_mut().cleanup());

        // Remove empty sliding windows
        self.ip_requests.retain(|_, v| !v.counts.is_empty());
        self.subnet_requests.retain(|_, v| !v.counts.is_empty());
        self.asn_requests.retain(|_, v| !v.counts.is_empty());
        self.country_requests.retain(|_, v| !v.counts.is_empty());

        // Expired blocked IPs
        self.blocked_ips.retain(|_, v| {
            v.expires_at.map_or(true, |exp| now < exp)
        });

        // Expired clearances
        self.clearances.retain(|_, exp| now < *exp);

        // Stale behavior profiles (no activity in the last 10 minutes)
        let stale_cutoff = now - Duration::from_secs(600);
        self.behavior_profiles
            .retain(|_, v| v.last_seen >= stale_cutoff);
    }

    // -----------------------------------------------------------------------
    // Metrics
    // -----------------------------------------------------------------------

    /// Returns `(total, passed, blocked, challenged)`.
    pub fn get_metrics(&self) -> (u64, u64, u64, u64) {
        (
            self.total_requests.load(Ordering::Relaxed),
            self.passed_requests.load(Ordering::Relaxed),
            self.blocked_requests.load(Ordering::Relaxed),
            self.challenged_requests.load(Ordering::Relaxed),
        )
    }

    pub fn reset_metrics(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.passed_requests.store(0, Ordering::Relaxed);
        self.blocked_requests.store(0, Ordering::Relaxed);
        self.challenged_requests.store(0, Ordering::Relaxed);
    }

    // -----------------------------------------------------------------------
    // Convenience counter helpers (used externally)
    // -----------------------------------------------------------------------

    pub fn inc_passed(&self) {
        self.passed_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_blocked(&self) {
        self.blocked_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_challenged(&self) {
        self.challenged_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}
