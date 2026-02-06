use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

use crate::config::settings::Settings;
use crate::models::threat::{ProtectionLevel, ThreatReason};
use crate::storage::memory::{MemoryStore, RateLimitConfig};

/// Multi-tier rate limiter using the MemoryStore's sliding window counters.
///
/// Delegates to `MemoryStore::check_rate_limit()` which checks per-IP,
/// per-subnet, per-ASN, and per-country sliding windows in a single call.
///
/// The rate-limit thresholds scale with the current protection level.
/// Higher protection levels have lower thresholds.
pub struct RateLimiter {
    memory: Arc<MemoryStore>,
}

impl RateLimiter {
    pub fn new(memory: Arc<MemoryStore>) -> Self {
        Self { memory }
    }

    /// Check all rate limit tiers for the given request context.
    ///
    /// Returns `Some(ThreatReason::RateLimit)` if any tier is exceeded,
    /// `None` if all pass.
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

    /// Build a `RateLimitConfig` (per-second thresholds) for the current
    /// protection level by dividing the settings' per-10s values by 10.
    ///
    /// For L4 (emergency lockdown) there is no settings entry, so we use
    /// very restrictive hard-coded defaults.
    fn get_limits_for_level(&self, level: &ProtectionLevel, settings: &Settings) -> RateLimitConfig {
        let rate_limits = &settings.protection.rate_limits;

        match level {
            ProtectionLevel::L0 => Self::config_to_per_second(&rate_limits.level_0),
            ProtectionLevel::L1 => Self::config_to_per_second(&rate_limits.level_1),
            ProtectionLevel::L2 => Self::config_to_per_second(&rate_limits.level_2),
            ProtectionLevel::L3 => Self::config_to_per_second(&rate_limits.level_3),
            ProtectionLevel::L4 => {
                // L4 (emergency): restrictive but still allows some traffic
                RateLimitConfig {
                    ip_per_second: 5,
                    subnet_per_second: 20,
                    asn_per_second: 100,
                    country_per_second: 500,
                }
            }
        }
    }

    /// Convert a settings-level `RateLimitConfig` (per-10s) into the
    /// memory-store `RateLimitConfig` (per-second) by dividing by 10,
    /// with a floor of 1 to avoid zero limits.
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
