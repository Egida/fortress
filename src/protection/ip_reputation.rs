use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::config::settings::IpReputationConfig;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReputationCategory {
    TorExit,
    KnownProxy,
    Scanner,
    BruteForce,
    DDoS,
}

#[derive(Debug, Clone)]
struct IpEntry {
    score: f64,
    total_requests: u64,
    blocked_count: u64,
    challenged_count: u64,
    passed_count: u64,
    first_seen: Instant,
    last_seen: Instant,
    last_decay: Instant,
    categories: HashSet<ReputationCategory>,
    ban_count: u32,
}

impl IpEntry {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            score: 0.0,
            total_requests: 0,
            blocked_count: 0,
            challenged_count: 0,
            passed_count: 0,
            first_seen: now,
            last_seen: now,
            last_decay: now,
            categories: HashSet::new(),
            ban_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IpReputationManager
// ---------------------------------------------------------------------------

pub struct IpReputationManager {
    entries: DashMap<IpAddr, IpEntry>,
    tor_exits: DashMap<IpAddr, ()>,
    config: IpReputationConfig,
}

impl IpReputationManager {
    pub fn new(config: &IpReputationConfig) -> Self {
        let manager = Self {
            entries: DashMap::with_capacity(100_000),
            tor_exits: DashMap::new(),
            config: config.clone(),
        };

        if config.tor_detection {
            manager.load_tor_exit_nodes();
        }

        info!(
            "IP reputation system initialized (tor_detection={}, block_threshold={})",
            config.tor_detection, config.block_threshold
        );

        manager
    }

    /// Check an IP and return the reputation score contribution for the pipeline.
    /// Returns (score_to_add, should_block).
    pub fn check(&self, ip: &IpAddr) -> (f64, bool) {
        if !self.config.enabled {
            return (0.0, false);
        }

        let mut score = 0.0;

        // Check if Tor exit node
        if self.config.tor_detection && self.tor_exits.contains_key(ip) {
            score += self.config.tor_score;
        }

        // Check reputation score
        if let Some(entry) = self.entries.get(ip) {
            // Apply decay first
            let now = Instant::now();
            let decay_interval = Duration::from_secs(self.config.decay_interval_secs);
            let elapsed_since_decay = now.duration_since(entry.last_decay);

            let mut rep_score = entry.score;
            if elapsed_since_decay > decay_interval {
                let decay_periods = elapsed_since_decay.as_secs() / self.config.decay_interval_secs;
                let decay_factor = (1.0 - self.config.decay_percent / 100.0).powi(decay_periods as i32);
                rep_score *= decay_factor;
            }

            // Block threshold
            if rep_score >= self.config.block_threshold {
                return (rep_score, true);
            }

            // High reputation adds score
            if rep_score >= 50.0 {
                score += self.config.high_reputation_score;
            } else if rep_score >= 25.0 {
                score += self.config.high_reputation_score * 0.5;
            }

            // Category-based scoring
            if entry.categories.contains(&ReputationCategory::KnownProxy) {
                score += 10.0;
            }
            if entry.categories.contains(&ReputationCategory::Scanner) {
                score += 15.0;
            }
        }

        (score, false)
    }

    /// Record a block event for an IP.
    pub fn record_block(&self, ip: &IpAddr) {
        if !self.config.enabled {
            return;
        }
        let mut entry = self.entries.entry(*ip).or_insert_with(IpEntry::new);
        self.apply_decay(&mut entry);
        entry.total_requests += 1;
        entry.blocked_count += 1;
        entry.score = (entry.score + 5.0).min(100.0);
        entry.last_seen = Instant::now();
    }

    /// Record a challenge event for an IP.
    pub fn record_challenge(&self, ip: &IpAddr) {
        if !self.config.enabled {
            return;
        }
        let mut entry = self.entries.entry(*ip).or_insert_with(IpEntry::new);
        self.apply_decay(&mut entry);
        entry.total_requests += 1;
        entry.challenged_count += 1;
        entry.score = (entry.score + 2.0).min(100.0);
        entry.last_seen = Instant::now();
    }

    /// Record a pass event for an IP (slight reputation improvement).
    pub fn record_pass(&self, ip: &IpAddr) {
        if !self.config.enabled {
            return;
        }
        // Only update existing entries (don't create entries for every passing IP)
        if let Some(mut entry) = self.entries.get_mut(ip) {
            self.apply_decay(&mut entry);
            entry.total_requests += 1;
            entry.passed_count += 1;
            entry.score = (entry.score - 0.5).max(0.0);
            entry.last_seen = Instant::now();
        }
    }

    /// Add a category to an IP's reputation.
    pub fn add_category(&self, ip: &IpAddr, category: ReputationCategory) {
        let mut entry = self.entries.entry(*ip).or_insert_with(IpEntry::new);
        entry.categories.insert(category);
    }

    /// Get the reputation score for an IP (for admin API).
    pub fn get_score(&self, ip: &IpAddr) -> f64 {
        self.entries
            .get(ip)
            .map(|e| e.score)
            .unwrap_or(0.0)
    }

    /// Get the blocked count for an IP.
    pub fn get_blocked_count(&self, ip: &IpAddr) -> u64 {
        self.entries
            .get(ip)
            .map(|e| e.blocked_count)
            .unwrap_or(0)
    }

    /// Get the ban count for an IP (used by auto-ban).
    pub fn get_ban_count(&self, ip: &IpAddr) -> u32 {
        self.entries
            .get(ip)
            .map(|e| e.ban_count)
            .unwrap_or(0)
    }

    /// Increment the ban count for an IP.
    pub fn increment_ban_count(&self, ip: &IpAddr) {
        let mut entry = self.entries.entry(*ip).or_insert_with(IpEntry::new);
        entry.ban_count += 1;
    }

    /// Check if an IP is a known Tor exit node.
    pub fn is_tor_exit(&self, ip: &IpAddr) -> bool {
        self.tor_exits.contains_key(ip)
    }

    /// Get top IPs by reputation score (for admin API).
    pub fn get_top_ips(&self, limit: usize) -> Vec<(IpAddr, f64, u64, u64, Vec<String>)> {
        let mut entries: Vec<_> = self.entries.iter().map(|e| {
            let cats: Vec<String> = e.categories.iter().map(|c| format!("{:?}", c)).collect();
            (*e.key(), e.score, e.total_requests, e.blocked_count, cats)
        }).collect();
        entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        entries.truncate(limit);
        entries
    }

    /// Cleanup old entries with zero score and no recent activity.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let stale_threshold = Duration::from_secs(3600); // 1 hour

        self.entries.retain(|_, entry| {
            let age = now.duration_since(entry.last_seen);
            // Keep entries with score > 1 or seen in the last hour
            entry.score > 1.0 || age < stale_threshold
        });
    }

    /// Total tracked IPs count.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn apply_decay(&self, entry: &mut IpEntry) {
        let now = Instant::now();
        let decay_interval = Duration::from_secs(self.config.decay_interval_secs);

        if now.duration_since(entry.last_decay) >= decay_interval {
            let periods = now.duration_since(entry.last_decay).as_secs() / self.config.decay_interval_secs;
            let factor = (1.0 - self.config.decay_percent / 100.0).powi(periods as i32);
            entry.score *= factor;
            entry.last_decay = now;
        }
    }

    /// Load well-known Tor exit node IPs.
    /// These are a representative sample of commonly used exit nodes.
    /// In production, this should be updated from a live feed periodically.
    fn load_tor_exit_nodes(&self) {
        // Well-known Tor exit node IPs (representative sample)
        let tor_exits = [
            "185.220.100.240", "185.220.100.241", "185.220.100.242", "185.220.100.243",
            "185.220.100.244", "185.220.100.245", "185.220.100.246", "185.220.100.247",
            "185.220.100.248", "185.220.100.249", "185.220.100.250", "185.220.100.251",
            "185.220.100.252", "185.220.100.253", "185.220.100.254", "185.220.100.255",
            "185.220.101.1", "185.220.101.2", "185.220.101.3", "185.220.101.4",
            "185.220.101.5", "185.220.101.6", "185.220.101.7", "185.220.101.8",
            "185.220.101.32", "185.220.101.33", "185.220.101.34", "185.220.101.35",
            "185.220.101.36", "185.220.101.37", "185.220.101.38", "185.220.101.39",
            "185.220.101.40", "185.220.101.41", "185.220.101.42", "185.220.101.43",
            "185.220.101.44", "185.220.101.45", "185.220.101.46", "185.220.101.47",
            "185.220.101.48", "185.220.101.49", "185.220.101.50", "185.220.101.51",
            "185.220.101.52", "185.220.101.53", "185.220.101.54", "185.220.101.55",
            "185.220.102.240", "185.220.102.241", "185.220.102.242", "185.220.102.243",
            "185.220.102.244", "185.220.102.245", "185.220.102.246", "185.220.102.247",
            "185.220.102.248", "185.220.102.249", "185.220.102.250", "185.220.102.251",
            "185.220.102.252", "185.220.102.253", "185.220.102.254",
            "199.249.230.65", "199.249.230.66", "199.249.230.67", "199.249.230.68",
            "199.249.230.69", "199.249.230.70", "199.249.230.71", "199.249.230.72",
            "199.249.230.73", "199.249.230.74", "199.249.230.75", "199.249.230.76",
            "199.249.230.77", "199.249.230.78", "199.249.230.79", "199.249.230.80",
            "199.249.230.81", "199.249.230.82", "199.249.230.83", "199.249.230.84",
            "199.249.230.85", "199.249.230.86", "199.249.230.87", "199.249.230.88",
            "204.85.191.30", "204.85.191.31",
            "109.70.100.2", "109.70.100.3", "109.70.100.4", "109.70.100.5",
            "109.70.100.6", "109.70.100.7", "109.70.100.8", "109.70.100.9",
            "109.70.100.10", "109.70.100.11", "109.70.100.12", "109.70.100.13",
            "109.70.100.14", "109.70.100.15", "109.70.100.16", "109.70.100.17",
            "109.70.100.18", "109.70.100.19", "109.70.100.20", "109.70.100.21",
            "109.70.100.22", "109.70.100.23", "109.70.100.24", "109.70.100.25",
            "109.70.100.26", "109.70.100.27", "109.70.100.28", "109.70.100.29",
            "109.70.100.30", "109.70.100.31", "109.70.100.32", "109.70.100.33",
            "162.247.74.2", "162.247.74.7", "162.247.74.27", "162.247.74.74",
            "162.247.74.200", "162.247.74.201", "162.247.74.202", "162.247.74.206",
            "162.247.74.207", "162.247.74.213", "162.247.74.216", "162.247.74.217",
            "45.33.32.156", "45.33.48.204",
            "51.15.43.205", "51.75.64.23", "51.75.144.43",
            "62.102.148.68", "62.102.148.69",
            "77.247.181.162", "77.247.181.163", "77.247.181.165",
            "89.234.157.254",
            "91.203.5.146", "91.203.5.147",
            "95.128.43.164",
            "104.244.73.93", "104.244.73.94", "104.244.73.95", "104.244.73.96",
            "104.244.76.13", "104.244.76.14",
            "176.10.99.200", "176.10.104.240", "176.10.104.243",
            "193.218.118.183",
            "198.98.51.189", "198.98.56.149",
            "209.127.17.234", "209.127.17.242",
        ];

        let mut count = 0;
        for ip_str in &tor_exits {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                self.tor_exits.insert(ip, ());
                count += 1;
            }
        }
        info!("Loaded {} Tor exit node IPs", count);
    }
}
