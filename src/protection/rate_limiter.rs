use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

use crate::config::settings::Settings;
use crate::models::threat::{ProtectionLevel, ThreatReason};
use crate::storage::memory::{MemoryStore, RateLimitConfig};

/
///
/
/
///
/
/
pub struct RateLimiter {
    memory: Arc<MemoryStore>,
}

impl RateLimiter {
    pub fn new(memory: Arc<MemoryStore>) -> Self {
        Self { memory }
    }

    /
    ///
    /
    /
    pub fn check(
        &self,
        ip: IpAddr,
        subnet: u32,
        asn: u32,
        country: &str,
        level: &ProtectionLevel,
        settings: &Settings,
    ) -> Option<ThreatReason> {
        let limits = self.get_limits_for_level(level, settings);

        debug!(
            ip = %ip,
            subnet = subnet,
            asn = asn,
            country = country,
            level = ?level,
            ip_per_second = limits.ip_per_second,
            subnet_per_second = limits.subnet_per_second,
            "Rate limiter check"
        );

        if let Some(reason_msg) = self.memory.check_rate_limit(ip, subnet, asn, country, &limits) {
            debug!(ip = %ip, reason = %reason_msg, "Rate limit exceeded");
            return Some(ThreatReason::RateLimit);
        }

        None
    }

    /
    /
    ///
    /
    /
    fn get_limits_for_level(&self, level: &ProtectionLevel, settings: &Settings) -> RateLimitConfig {
        let rate_limits = &settings.protection.rate_limits;

        match level {
            ProtectionLevel::L0 => Self::config_to_per_second(&rate_limits.level_0),
            ProtectionLevel::L1 => Self::config_to_per_second(&rate_limits.level_1),
            ProtectionLevel::L2 => Self::config_to_per_second(&rate_limits.level_2),
            ProtectionLevel::L3 => Self::config_to_per_second(&rate_limits.level_3),
            ProtectionLevel::L4 => {
                RateLimitConfig {
                    ip_per_second: 5,
                    subnet_per_second: 20,
                    asn_per_second: 100,
                    country_per_second: 500,
                }
            }
        }
    }

    /
    /
    /
    fn config_to_per_second(
        cfg: &crate::config::settings::RateLimitConfig,
    ) -> RateLimitConfig {
        RateLimitConfig {
            ip_per_second: (cfg.ip_per_10s / 10).max(1),
            subnet_per_second: (cfg.subnet_per_10s / 10).max(1),
            asn_per_second: (cfg.asn_per_10s / 10).max(1),
            country_per_second: (cfg.country_per_10s / 10).max(1),
        }
    }
}
