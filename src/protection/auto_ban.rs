use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::config::settings::AutoBanConfig;


#[derive(Debug, Clone)]
struct BlockRecord {
    timestamp: Instant,
}

#[derive(Debug, Clone)]
struct BanEntry {
    banned_at: Instant,
    duration: Duration,
    reason: String,
    block_count: u32,
}

#[derive(Debug, Clone)]
struct IpBlockHistory {
    blocks: VecDeque<BlockRecord>,
    ban_count: u32,
}

impl IpBlockHistory {
    fn new() -> Self {
        Self {
            blocks: VecDeque::new(),
            ban_count: 0,
        }
    }

    /
    fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(3600);
        while let Some(front) = self.blocks.front() {
            if front.timestamp < cutoff {
                self.blocks.pop_front();
            } else {
                break;
            }
        }
    }

    /
    fn count_in_window(&self, window_secs: u64) -> u32 {
        let cutoff = Instant::now() - Duration::from_secs(window_secs);
        self.blocks.iter().filter(|b| b.timestamp >= cutoff).count() as u32
    }
}


pub struct AutoBanManager {
    /
    bans: DashMap<IpAddr, BanEntry>,
    /
    history: DashMap<IpAddr, IpBlockHistory>,
    /
    subnet_bans: DashMap<String, u32>,
    config: AutoBanConfig,
}

impl AutoBanManager {
    pub fn new(config: &AutoBanConfig) -> Self {
        info!(
            "Auto-ban system initialized (enabled={}, 5m_threshold={}, 15m_threshold={}, 1h_threshold={})",
            config.enabled, config.ban_threshold_5m, config.ban_threshold_15m, config.ban_threshold_1h
        );
        Self {
            bans: DashMap::new(),
            history: DashMap::with_capacity(10_000),
            subnet_bans: DashMap::new(),
            config: config.clone(),
        }
    }

    /
    /
    pub fn is_banned(&self, ip: &IpAddr) -> Option<String> {
        if !self.config.enabled {
            return None;
        }

        if let Some(entry) = self.bans.get(ip) {
            let elapsed = Instant::now().duration_since(entry.banned_at);
            if elapsed < entry.duration {
                return Some(entry.reason.clone());
            }
        }

        None
    }

    /
    /
    pub fn record_block(&self, ip: &IpAddr) -> bool {
        if !self.config.enabled {
            return false;
        }

        if self.is_banned(ip).is_some() {
            return false;
        }

        let mut history = self.history.entry(*ip).or_insert_with(IpBlockHistory::new);
        history.cleanup();
        history.blocks.push_back(BlockRecord {
            timestamp: Instant::now(),
        });

        let blocks_1h = history.count_in_window(3600);
        let blocks_15m = history.count_in_window(900);
        let blocks_5m = history.count_in_window(300);
        let ban_count = history.ban_count;

        let ban_duration = if ban_count >= self.config.repeat_ban_threshold {
            Some((Duration::from_secs(86400), format!("repeat_offender_ban_{}", ban_count + 1)))
        } else if blocks_1h >= self.config.ban_threshold_1h {
            Some((Duration::from_secs(7200), format!("1h_threshold_{}_blocks", blocks_1h)))
        } else if blocks_15m >= self.config.ban_threshold_15m {
            Some((Duration::from_secs(1800), format!("15m_threshold_{}_blocks", blocks_15m)))
        } else if blocks_5m >= self.config.ban_threshold_5m {
            Some((Duration::from_secs(300), format!("5m_threshold_{}_blocks", blocks_5m)))
        } else {
            None
        };

        if let Some((duration, reason)) = ban_duration {
            history.ban_count += 1;
            drop(history);

            self.bans.insert(*ip, BanEntry {
                banned_at: Instant::now(),
                duration,
                reason: reason.clone(),
                block_count: blocks_5m.max(blocks_15m).max(blocks_1h),
            });

            let subnet = ip_to_subnet_str(ip);
            let mut count = self.subnet_bans.entry(subnet).or_insert(0);
            *count += 1;

            info!(
                ip = %ip,
                duration_secs = duration.as_secs(),
                reason = %reason,
                "Auto-banned IP"
            );

            return true;
        }

        false
    }

    /
    pub fn unban(&self, ip: &IpAddr) -> bool {
        if self.bans.remove(ip).is_some() {
            let subnet = ip_to_subnet_str(ip);
            if let Some(mut count) = self.subnet_bans.get_mut(&subnet) {
                *count = count.saturating_sub(1);
            }
            info!(ip = %ip, "Manually unbanned IP");
            true
        } else {
            false
        }
    }

    /
    pub fn get_active_bans(&self) -> Vec<(IpAddr, String, u64, u64)> {
        let now = Instant::now();
        let mut bans = Vec::new();

        for entry in self.bans.iter() {
            let elapsed = now.duration_since(entry.banned_at);
            if elapsed < entry.duration {
                let remaining = (entry.duration - elapsed).as_secs();
                bans.push((
                    *entry.key(),
                    entry.reason.clone(),
                    entry.duration.as_secs(),
                    remaining,
                ));
            }
        }

        bans.sort_by(|a, b| b.3.cmp(&a.3));
        bans
    }

    /
    pub fn active_ban_count(&self) -> usize {
        let now = Instant::now();
        self.bans.iter().filter(|e| {
            now.duration_since(e.banned_at) < e.duration
        }).count()
    }

    /
    pub fn cleanup(&self) {
        let now = Instant::now();

        self.bans.retain(|ip, entry| {
            let expired = now.duration_since(entry.banned_at) >= entry.duration;
            if expired {
                debug!(ip = %ip, "Auto-ban expired");
                let subnet = ip_to_subnet_str(ip);
                if let Some(mut count) = self.subnet_bans.get_mut(&subnet) {
                    *count = count.saturating_sub(1);
                }
            }
            !expired
        });

        let stale = Duration::from_secs(7200);
        self.history.retain(|_, h| {
            if let Some(last) = h.blocks.back() {
                now.duration_since(last.timestamp) < stale
            } else {
                false
            }
        });

        self.subnet_bans.retain(|_, count| *count > 0);
    }
}

/
fn ip_to_subnet_str(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}
