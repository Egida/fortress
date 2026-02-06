use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{debug, info};

/// Tracks traffic patterns to detect distributed/coordinated attacks.
///
/// Detection signals (need >= 2 to trigger):
/// 1. Path concentration: >70% of requests hit the same path
/// 2. UA entropy: Low user-agent diversity (< 5 unique UAs for 50+ requests)
/// 3. New IP ratio: >80% of IPs are first-time visitors
pub struct DistributedDetector {
    /// Per-path request counts in current window
    path_counts: DashMap<String, u32>,
    /// Per-UA counts in current window
    ua_counts: DashMap<String, u32>,
    /// Total requests in current window
    total_requests: std::sync::atomic::AtomicU32,
    /// IPs seen in current window
    window_ips: DashMap<IpAddr, ()>,
    /// IPs seen before this window (known IPs)
    known_ips: DashMap<IpAddr, Instant>,
    /// New IPs in current window (not in known_ips)
    new_ip_count: std::sync::atomic::AtomicU32,
    /// Window start time
    window_start: RwLock<Instant>,
    /// Window duration
    window_duration: Duration,
    /// Whether we're currently detecting an attack
    attack_active: AtomicBool,
    /// Attack details for the current/last detection
    last_attack: RwLock<Option<AttackInfo>>,
}

#[derive(Debug, Clone)]
pub struct AttackInfo {
    pub detected_at: Instant,
    pub signals: Vec<String>,
    pub top_path: String,
    pub request_count: u32,
    pub unique_ips: u32,
    pub new_ip_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct DistributedCheckResult {
    pub is_attack: bool,
    pub score_modifier: f64,
    pub is_new_ip: bool,
}

impl DistributedDetector {
    pub fn new() -> Self {
        Self {
            path_counts: DashMap::new(),
            ua_counts: DashMap::new(),
            total_requests: std::sync::atomic::AtomicU32::new(0),
            window_ips: DashMap::new(),
            known_ips: DashMap::with_capacity(100_000),
            new_ip_count: std::sync::atomic::AtomicU32::new(0),
            window_start: RwLock::new(Instant::now()),
            window_duration: Duration::from_secs(30),
            attack_active: AtomicBool::new(false),
            last_attack: RwLock::new(None),
        }
    }

    /// Record a request and check for distributed attack patterns.
    /// Returns a score modifier and whether this is a new IP during an attack.
    pub fn check(&self, ip: IpAddr, path: &str, user_agent: Option<&str>) -> DistributedCheckResult {
        self.maybe_rotate_window();

        // Record request
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        *self.path_counts.entry(path.to_string()).or_insert(0) += 1;
        let ua = user_agent.unwrap_or("").to_string();
        *self.ua_counts.entry(ua).or_insert(0) += 1;

        // Track IP novelty
        let is_new = !self.known_ips.contains_key(&ip);
        if is_new {
            self.new_ip_count.fetch_add(1, Ordering::Relaxed);
        }
        self.window_ips.insert(ip, ());
        // Mark IP as known for future windows
        self.known_ips.insert(ip, Instant::now());

        let total = self.total_requests.load(Ordering::Relaxed);

        // Need minimum 50 requests in window to evaluate
        if total < 50 {
            return DistributedCheckResult {
                is_attack: false,
                score_modifier: 0.0,
                is_new_ip: is_new,
            };
        }

        // Evaluate signals
        let mut signals: Vec<String> = Vec::new();

        // Signal 1: Path concentration (>70% same path)
        let top_path = self.get_top_path();
        if let Some((ref path_name, count)) = top_path {
            let concentration = count as f64 / total as f64;
            if concentration > 0.70 {
                signals.push(format!("path_concentration:{:.0}%:{}", concentration * 100.0, path_name));
            }
        }

        // Signal 2: Low UA diversity (< 5 unique UAs for 50+ requests)
        let unique_uas = self.ua_counts.len();
        if unique_uas < 5 {
            signals.push(format!("low_ua_diversity:{}", unique_uas));
        }

        // Signal 3: High new IP ratio (>80% new IPs)
        let new_count = self.new_ip_count.load(Ordering::Relaxed);
        let total_ips = self.window_ips.len() as u32;
        let new_ratio = if total_ips > 0 {
            new_count as f64 / total_ips as f64
        } else {
            0.0
        };
        if new_ratio > 0.80 && total_ips >= 20 {
            signals.push(format!("high_new_ip_ratio:{:.0}%", new_ratio * 100.0));
        }

        // Need >= 2 signals to declare attack (false positive prevention)
        let is_attack = signals.len() >= 2;

        if is_attack && !self.attack_active.load(Ordering::Relaxed) {
            self.attack_active.store(true, Ordering::Relaxed);
            let attack_info = AttackInfo {
                detected_at: Instant::now(),
                signals: signals.clone(),
                top_path: top_path.map(|(p, _)| p).unwrap_or_default(),
                request_count: total,
                unique_ips: total_ips,
                new_ip_ratio: new_ratio,
            };
            info!(
                signals = ?attack_info.signals,
                requests = total,
                ips = total_ips,
                new_ratio = format!("{:.0}%", new_ratio * 100.0),
                "Distributed attack detected"
            );
            *self.last_attack.write() = Some(attack_info);
        } else if !is_attack && self.attack_active.load(Ordering::Relaxed) {
            // Attack subsided
            self.attack_active.store(false, Ordering::Relaxed);
            info!("Distributed attack subsided");
        }

        // Score modifier: attack + new IP = +30, attack + existing IP = +10
        let score_modifier = if is_attack {
            if is_new { 30.0 } else { 10.0 }
        } else {
            0.0
        };

        DistributedCheckResult {
            is_attack,
            score_modifier,
            is_new_ip: is_new,
        }
    }

    /// Check if a distributed attack is currently active.
    pub fn is_attack_active(&self) -> bool {
        self.attack_active.load(Ordering::Relaxed)
    }

    /// Get the last detected attack info.
    pub fn get_last_attack(&self) -> Option<AttackInfo> {
        self.last_attack.read().clone()
    }

    /// Cleanup old known IPs (keep for 1 hour).
    pub fn cleanup(&self) {
        let now = Instant::now();
        let stale = Duration::from_secs(3600);
        self.known_ips.retain(|_, seen| now.duration_since(*seen) < stale);
    }

    /// Get current window stats for admin API.
    pub fn get_stats(&self) -> (u32, usize, u32, bool) {
        let total = self.total_requests.load(Ordering::Relaxed);
        let unique_ips = self.window_ips.len();
        let new_ips = self.new_ip_count.load(Ordering::Relaxed);
        let active = self.attack_active.load(Ordering::Relaxed);
        (total, unique_ips, new_ips, active)
    }

    // --- Private helpers ---

    fn maybe_rotate_window(&self) {
        let now = Instant::now();
        let should_rotate = {
            let start = self.window_start.read();
            now.duration_since(*start) >= self.window_duration
        };

        if should_rotate {
            let mut start = self.window_start.write();
            // Double-check after acquiring write lock
            if now.duration_since(*start) >= self.window_duration {
                *start = now;
                self.path_counts.clear();
                self.ua_counts.clear();
                self.total_requests.store(0, Ordering::Relaxed);
                self.window_ips.clear();
                self.new_ip_count.store(0, Ordering::Relaxed);
                debug!("Distributed detector window rotated");
            }
        }
    }

    fn get_top_path(&self) -> Option<(String, u32)> {
        let mut top: Option<(String, u32)> = None;
        for entry in self.path_counts.iter() {
            let count = *entry.value();
            match &top {
                Some((_, tc)) if count > *tc => {
                    top = Some((entry.key().clone(), count));
                }
                None => {
                    top = Some((entry.key().clone(), count));
                }
                _ => {}
            }
        }
        top
    }
}
