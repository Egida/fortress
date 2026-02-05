use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{debug, info};

/
///
/
/
/
/
pub struct DistributedDetector {
    /
    path_counts: DashMap<String, u32>,
    /
    ua_counts: DashMap<String, u32>,
    /
    total_requests: std::sync::atomic::AtomicU32,
    /
    window_ips: DashMap<IpAddr, ()>,
    /
    known_ips: DashMap<IpAddr, Instant>,
    /
    new_ip_count: std::sync::atomic::AtomicU32,
    /
    window_start: RwLock<Instant>,
    /
    window_duration: Duration,
    /
    attack_active: AtomicBool,
    /
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

    /
    /
    pub fn check(&self, ip: IpAddr, path: &str, user_agent: Option<&str>) -> DistributedCheckResult {
        self.maybe_rotate_window();

        self.total_requests.fetch_add(1, Ordering::Relaxed);
        *self.path_counts.entry(path.to_string()).or_insert(0) += 1;
        let ua = user_agent.unwrap_or("").to_string();
        *self.ua_counts.entry(ua).or_insert(0) += 1;

        let is_new = !self.known_ips.contains_key(&ip);
        if is_new {
            self.new_ip_count.fetch_add(1, Ordering::Relaxed);
        }
        self.window_ips.insert(ip, ());
        self.known_ips.insert(ip, Instant::now());

        let total = self.total_requests.load(Ordering::Relaxed);

        if total < 50 {
            return DistributedCheckResult {
                is_attack: false,
                score_modifier: 0.0,
                is_new_ip: is_new,
            };
        }

        let mut signals: Vec<String> = Vec::new();

        let top_path = self.get_top_path();
        if let Some((ref path_name, count)) = top_path {
            let concentration = count as f64 / total as f64;
            if concentration > 0.70 {
                signals.push(format!("path_concentration:{:.0}%:{}", concentration * 100.0, path_name));
            }
        }

        let unique_uas = self.ua_counts.len();
        if unique_uas < 5 {
            signals.push(format!("low_ua_diversity:{}", unique_uas));
        }

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
            self.attack_active.store(false, Ordering::Relaxed);
            info!("Distributed attack subsided");
        }

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

    /
    pub fn is_attack_active(&self) -> bool {
        self.attack_active.load(Ordering::Relaxed)
    }

    /
    pub fn get_last_attack(&self) -> Option<AttackInfo> {
        self.last_attack.read().clone()
    }

    /
    pub fn cleanup(&self) {
        let now = Instant::now();
        let stale = Duration::from_secs(3600);
        self.known_ips.retain(|_, seen| now.duration_since(*seen) < stale);
    }

    /
    pub fn get_stats(&self) -> (u32, usize, u32, bool) {
        let total = self.total_requests.load(Ordering::Relaxed);
        let unique_ips = self.window_ips.len();
        let new_ips = self.new_ip_count.load(Ordering::Relaxed);
        let active = self.attack_active.load(Ordering::Relaxed);
        (total, unique_ips, new_ips, active)
    }


    fn maybe_rotate_window(&self) {
        let now = Instant::now();
        let should_rotate = {
            let start = self.window_start.read();
            now.duration_since(*start) >= self.window_duration
        };

        if should_rotate {
            let mut start = self.window_start.write();
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
