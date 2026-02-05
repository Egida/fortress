use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::models::metrics::MetricsSnapshot;

/
#[derive(Clone, Debug)]
pub struct SecondSnapshot {
    pub timestamp: u64,
    pub requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub passed: u64,
}

/
///
/
/
/
/
pub struct MetricsCollector {
    current_second_requests: AtomicU64,
    current_second_blocked: AtomicU64,
    current_second_challenged: AtomicU64,
    current_second_passed: AtomicU64,

    second_snapshots: RwLock<Vec<SecondSnapshot>>,

    ip_counts: DashMap<IpAddr, u64>,

    country_counts: DashMap<String, u64>,

    asn_counts: DashMap<u32, u64>,

    ja3_counts: DashMap<String, u64>,

    total_latency_us: AtomicU64,
    latency_count: AtomicU64,

    unique_ips: DashMap<IpAddr, ()>,

    total_requests: AtomicU64,
    total_blocked: AtomicU64,

    start_time: Instant,
}

const MAX_SNAPSHOTS: usize = 3600;

impl MetricsCollector {
    /
    pub fn new() -> Self {
        Self {
            current_second_requests: AtomicU64::new(0),
            current_second_blocked: AtomicU64::new(0),
            current_second_challenged: AtomicU64::new(0),
            current_second_passed: AtomicU64::new(0),

            second_snapshots: RwLock::new(Vec::with_capacity(MAX_SNAPSHOTS)),

            ip_counts: DashMap::new(),
            country_counts: DashMap::new(),
            asn_counts: DashMap::new(),
            ja3_counts: DashMap::new(),

            total_latency_us: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),

            unique_ips: DashMap::new(),

            total_requests: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),

            start_time: Instant::now(),
        }
    }

    /
    ///
    /
    pub fn record_request(
        &self,
        ip: IpAddr,
        country: Option<&str>,
        asn: Option<u32>,
        ja3: Option<&str>,
        action: &str,
        latency_us: u64,
    ) {
        self.current_second_requests.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        match action {
            "blocked" => {
                self.current_second_blocked.fetch_add(1, Ordering::Relaxed);
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
            }
            "challenged" => {
                self.current_second_challenged.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.current_second_passed.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.ip_counts
            .entry(ip)
            .and_modify(|c| *c += 1)
            .or_insert(1);

        self.unique_ips.entry(ip).or_insert(());

        if let Some(cc) = country {
            self.country_counts
                .entry(cc.to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        if let Some(asn_id) = asn {
            self.asn_counts
                .entry(asn_id)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        if let Some(fingerprint) = ja3 {
            self.ja3_counts
                .entry(fingerprint.to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        self.total_latency_us.fetch_add(latency_us, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /
    /
    pub fn tick(&self) {
        let requests = self.current_second_requests.swap(0, Ordering::Relaxed);
        let blocked = self.current_second_blocked.swap(0, Ordering::Relaxed);
        let challenged = self.current_second_challenged.swap(0, Ordering::Relaxed);
        let passed = self.current_second_passed.swap(0, Ordering::Relaxed);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let snapshot = SecondSnapshot {
            timestamp: now,
            requests,
            blocked,
            challenged,
            passed,
        };

        let mut snapshots = self.second_snapshots.write();
        if snapshots.len() >= MAX_SNAPSHOTS {
            snapshots.remove(0);
        }
        snapshots.push(snapshot);
    }

    /
    pub fn get_current_rps(&self) -> f64 {
        let snapshots = self.second_snapshots.read();
        snapshots.last().map(|s| s.requests as f64).unwrap_or(0.0)
    }

    /
    pub fn get_snapshot(&self) -> MetricsSnapshot {
        let latency_count = self.latency_count.load(Ordering::Relaxed);
        let avg_latency_us = if latency_count > 0 {
            self.total_latency_us.load(Ordering::Relaxed) as f64 / latency_count as f64
        } else {
            0.0
        };

        MetricsSnapshot {
            rps: self.get_current_rps(),
            blocked_per_sec: {
                let snaps = self.second_snapshots.read();
                snaps.last().map(|s| s.blocked as f64).unwrap_or(0.0)
            },
            challenged_per_sec: {
                let snaps = self.second_snapshots.read();
                snaps.last().map(|s| s.challenged as f64).unwrap_or(0.0)
            },
            passed_per_sec: {
                let snaps = self.second_snapshots.read();
                snaps.last().map(|s| s.passed as f64).unwrap_or(0.0)
            },
            unique_ips: self.unique_ips.len() as u64,
            avg_latency_ms: avg_latency_us / 1000.0,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /
    pub fn get_top_ips(&self, limit: usize) -> Vec<(IpAddr, u64)> {
        let mut entries: Vec<(IpAddr, u64)> = self
            .ip_counts
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(limit);
        entries
    }

    /
    pub fn get_top_countries(&self, limit: usize) -> Vec<(String, u64)> {
        let mut entries: Vec<(String, u64)> = self
            .country_counts
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(limit);
        entries
    }

    /
    pub fn get_top_asns(&self, limit: usize) -> Vec<(u32, u64)> {
        let mut entries: Vec<(u32, u64)> = self
            .asn_counts
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(limit);
        entries
    }

    /
    pub fn get_top_fingerprints(&self, limit: usize) -> Vec<(String, u64)> {
        let mut entries: Vec<(String, u64)> = self
            .ja3_counts
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(limit);
        entries
    }

    /
    pub fn get_second_history(&self, last_n: usize) -> Vec<SecondSnapshot> {
        let snapshots = self.second_snapshots.read();
        let len = snapshots.len();
        if last_n >= len {
            snapshots.clone()
        } else {
            snapshots[(len - last_n)..].to_vec()
        }
    }

    /
    pub fn reset_hourly(&self) {
        self.ip_counts.clear();
        self.country_counts.clear();
        self.asn_counts.clear();
        self.ja3_counts.clear();
        self.unique_ips.clear();
        self.total_latency_us.store(0, Ordering::Relaxed);
        self.latency_count.store(0, Ordering::Relaxed);
        self.second_snapshots.write().clear();
    }

    /
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /
    pub fn total_blocked(&self) -> u64 {
        self.total_blocked.load(Ordering::Relaxed)
    }

    /
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
