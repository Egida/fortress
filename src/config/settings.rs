use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

use super::defaults;

/// Top-level configuration for the Fortress anti-DDoS proxy.
/// Deserializes from a TOML configuration file.
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default = "defaults::default_server_config")]
    pub server: ServerConfig,

    #[serde(default = "defaults::default_tls_config")]
    pub tls: TlsConfig,

    #[serde(default = "defaults::default_upstream_config")]
    pub upstream: UpstreamConfig,

    #[serde(default = "defaults::default_admin_api_config")]
    pub admin_api: AdminApiConfig,

    #[serde(default = "defaults::default_geoip_config")]
    pub geoip: GeoipConfig,

    #[serde(default = "defaults::default_protection_config")]
    pub protection: ProtectionConfig,

    #[serde(default = "defaults::default_challenge_config")]
    pub challenge: ChallengeConfig,

    #[serde(default = "defaults::default_blocklist_config")]
    pub blocklist: BlocklistConfig,

    #[serde(default = "defaults::default_behavioral_config")]
    pub behavioral: BehavioralConfig,

    #[serde(default = "defaults::default_escalation_config")]
    pub escalation: EscalationConfig,

    #[serde(default = "defaults::default_logging_config")]
    pub logging: LoggingConfig,

    #[serde(default = "defaults::default_storage_config")]
    pub storage: StorageConfig,

    #[serde(default = "defaults::default_l4_protection_config")]
    pub l4_protection: L4ProtectionConfig,

    #[serde(default = "defaults::default_alerting_config")]
    pub alerting: AlertingConfig,

    #[serde(default = "defaults::default_bot_whitelist_config")]
    pub bot_whitelist: BotWhitelistConfig,

    #[serde(default = "defaults::default_mobile_proxy_config")]
    pub mobile_proxy: MobileProxyConfig,

    #[serde(default = "defaults::default_asn_scoring_config")]
    pub asn_scoring: AsnScoringConfig,

    #[serde(default = "defaults::default_ip_reputation_config")]
    pub ip_reputation: IpReputationConfig,

    #[serde(default = "defaults::default_auto_ban_config")]
    pub auto_ban: AutoBanConfig,

    #[serde(default = "defaults::default_cloudflare_config")]
    pub cloudflare: CloudflareConfig,

    #[serde(default)]
    pub services: Vec<crate::config::service::ServiceConfig>,
}

impl Settings {
    /// Load configuration from a TOML file at the given path.
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        let settings: Settings = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path))?;
        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: defaults::default_server_config(),
            tls: defaults::default_tls_config(),
            upstream: defaults::default_upstream_config(),
            admin_api: defaults::default_admin_api_config(),
            geoip: defaults::default_geoip_config(),
            protection: defaults::default_protection_config(),
            challenge: defaults::default_challenge_config(),
            blocklist: defaults::default_blocklist_config(),
            behavioral: defaults::default_behavioral_config(),
            escalation: defaults::default_escalation_config(),
            logging: defaults::default_logging_config(),
            storage: defaults::default_storage_config(),
            l4_protection: defaults::default_l4_protection_config(),
            alerting: defaults::default_alerting_config(),
            bot_whitelist: defaults::default_bot_whitelist_config(),
            mobile_proxy: defaults::default_mobile_proxy_config(),
            asn_scoring: defaults::default_asn_scoring_config(),
            ip_reputation: defaults::default_ip_reputation_config(),
            auto_ban: defaults::default_auto_ban_config(),
            cloudflare: defaults::default_cloudflare_config(),
            services: Vec::new(),
        }
    }
}

/// HTTP/HTTPS server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "defaults::default_bind_http")]
    pub bind_http: String,

    #[serde(default = "defaults::default_bind_https")]
    pub bind_https: String,

    #[serde(default = "defaults::default_workers")]
    pub workers: usize,

    #[serde(default = "defaults::default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "defaults::default_connection_timeout_secs")]
    pub connection_timeout_secs: u64,

    #[serde(default = "defaults::default_request_timeout_secs")]
    pub request_timeout_secs: u64,

    #[serde(default = "defaults::default_keepalive_timeout_secs")]
    pub keepalive_timeout_secs: u64,
}

/// TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "defaults::default_cert_dir")]
    pub cert_dir: String,

    #[serde(default = "defaults::default_tls_min_version")]
    pub min_version: String,
}

/// Upstream backend server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default = "defaults::default_upstream_address")]
    pub address: String,

    #[serde(default = "defaults::default_upstream_max_connections")]
    pub max_connections: usize,

    #[serde(default = "defaults::default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    #[serde(default = "defaults::default_response_timeout_ms")]
    pub response_timeout_ms: u64,
}

/// Admin API configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminApiConfig {
    #[serde(default = "defaults::default_admin_bind")]
    pub bind: String,

    #[serde(default = "defaults::default_api_key")]
    pub api_key: String,
}

/// GeoIP database configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GeoipConfig {
    #[serde(default = "defaults::default_city_db")]
    pub city_db: String,

    #[serde(default = "defaults::default_asn_db")]
    pub asn_db: String,
}

/// Protection configuration with nested rate-limit levels.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectionConfig {
    #[serde(default)]
    pub default_level: u8,

    #[serde(default = "defaults::default_auto_escalation")]
    pub auto_escalation: bool,

    #[serde(default = "defaults::default_rate_limits")]
    pub rate_limits: RateLimitLevels,

    #[serde(default = "defaults::default_ipv4_subnet_mask")]
    pub ipv4_subnet_mask: u8,

    #[serde(default)]
    pub whitelisted_ips: Vec<String>,

    #[serde(default)]
    pub whitelisted_subnets: Vec<String>,
}

/// Rate-limit thresholds for each protection level.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitLevels {
    #[serde(default = "defaults::default_rate_limit_level_0")]
    pub level_0: RateLimitConfig,

    #[serde(default = "defaults::default_rate_limit_level_1")]
    pub level_1: RateLimitConfig,

    #[serde(default = "defaults::default_rate_limit_level_2")]
    pub level_2: RateLimitConfig,

    #[serde(default = "defaults::default_rate_limit_level_3")]
    pub level_3: RateLimitConfig,
}

/// Per-level rate-limit thresholds (requests per 10-second window).
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "defaults::default_ip_per_10s")]
    pub ip_per_10s: u64,

    #[serde(default = "defaults::default_subnet_per_10s")]
    pub subnet_per_10s: u64,

    #[serde(default = "defaults::default_asn_per_10s")]
    pub asn_per_10s: u64,

    #[serde(default = "defaults::default_country_per_10s")]
    pub country_per_10s: u64,
}

/// Challenge (proof-of-work) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeConfig {
    #[serde(default = "defaults::default_pow_difficulty_l1")]
    pub pow_difficulty_l1: u8,

    #[serde(default = "defaults::default_pow_difficulty_l2")]
    pub pow_difficulty_l2: u8,

    #[serde(default = "defaults::default_pow_difficulty_l3")]
    pub pow_difficulty_l3: u8,

    #[serde(default = "defaults::default_cookie_name")]
    pub cookie_name: String,

    #[serde(default = "defaults::default_cookie_max_age_secs")]
    pub cookie_max_age_secs: u64,

    #[serde(default = "defaults::default_hmac_secret")]
    pub hmac_secret: String,

    #[serde(default)]
    pub exempt_paths: Vec<String>,

    #[serde(default)]
    pub cookie_subnet_binding: bool,

    #[serde(default)]
    pub nojs_fallback_enabled: bool,
}

/// Blocklist configuration for countries, ASNs, and IPs.
#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub blocked_countries: Vec<String>,

    #[serde(default)]
    pub challenged_countries: Vec<String>,

    #[serde(default)]
    pub blocked_asns: Vec<u32>,

    #[serde(default = "defaults::default_country_challenge_score")]
    pub country_challenge_score: f64,
}

/// Behavioral analysis configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct BehavioralConfig {
    #[serde(default = "defaults::default_scoring_window_secs")]
    pub scoring_window_secs: u64,

    #[serde(default = "defaults::default_max_profiles")]
    pub max_profiles: usize,

    #[serde(default = "defaults::default_regularity_weight")]
    pub regularity_weight: f64,

    #[serde(default = "defaults::default_path_diversity_min_requests")]
    pub path_diversity_min_requests: u64,
}

/// Automatic escalation/de-escalation configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct EscalationConfig {
    #[serde(default = "defaults::default_check_interval_secs")]
    pub check_interval_secs: u64,

    #[serde(default = "defaults::default_deescalation_cooldown_secs")]
    pub deescalation_cooldown_secs: u64,

    #[serde(default = "defaults::default_l0_to_l1_rps")]
    pub l0_to_l1_rps: u64,

    #[serde(default = "defaults::default_l1_to_l2_rps")]
    pub l1_to_l2_rps: u64,

    #[serde(default = "defaults::default_l2_to_l3_rps")]
    pub l2_to_l3_rps: u64,

    #[serde(default = "defaults::default_l3_to_l4_rps")]
    pub l3_to_l4_rps: u64,

    #[serde(default = "defaults::default_sustained_checks_required")]
    pub sustained_checks_required: u8,

    #[serde(default = "defaults::default_block_ratio_threshold")]
    pub block_ratio_threshold: f64,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "defaults::default_log_level")]
    pub level: String,

    #[serde(default = "defaults::default_log_file")]
    pub file: String,

    #[serde(default = "defaults::default_access_log")]
    pub access_log: String,
}

/// Storage configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "defaults::default_sqlite_path")]
    pub sqlite_path: String,
}

/// L4 (TCP-level) protection configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct L4ProtectionConfig {
    #[serde(default = "defaults::default_l4_enabled")]
    pub enabled: bool,

    #[serde(default = "defaults::default_syn_rate")]
    pub syn_rate_per_ip_per_sec: u64,

    #[serde(default = "defaults::default_conn_rate")]
    pub connection_rate_per_ip_per_sec: u64,

    #[serde(default = "defaults::default_max_concurrent")]
    pub max_concurrent_per_ip: u64,

    #[serde(default = "defaults::default_tarpit_enabled")]
    pub tarpit_enabled: bool,

    #[serde(default = "defaults::default_tarpit_delay")]
    pub tarpit_delay_ms: u64,
}

/// Alerting configuration (webhook notifications).
#[derive(Debug, Clone, Deserialize)]
pub struct AlertingConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub webhook_url: Option<String>,
}

/// Bot whitelist configuration for known search engine crawlers.
#[derive(Debug, Clone, Deserialize)]
pub struct BotWhitelistConfig {
    #[serde(default = "defaults::default_bot_whitelist_enabled")]
    pub enabled: bool,

    #[serde(default = "defaults::default_bot_verify_ip")]
    pub verify_ip: bool,
}

/// Mobile proxy detection tuning.
#[derive(Debug, Clone, Deserialize)]
pub struct MobileProxyConfig {
    #[serde(default = "defaults::default_mobile_proxy_min_signals")]
    pub min_signals: u32,

    #[serde(default = "defaults::default_mobile_proxy_score_threshold")]
    pub score_threshold: f64,
}

/// ASN reputation scoring configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AsnScoringConfig {
    #[serde(default = "defaults::default_datacenter_score")]
    pub datacenter_score: f64,

    #[serde(default = "defaults::default_vpn_score")]
    pub vpn_score: f64,

    #[serde(default = "defaults::default_residential_proxy_score")]
    pub residential_proxy_score: f64,
}

/// IP reputation system configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct IpReputationConfig {
    #[serde(default = "defaults::default_ip_reputation_enabled")]
    pub enabled: bool,

    #[serde(default = "defaults::default_tor_detection")]
    pub tor_detection: bool,

    #[serde(default = "defaults::default_tor_score")]
    pub tor_score: f64,

    #[serde(default = "defaults::default_decay_interval_secs")]
    pub decay_interval_secs: u64,

    #[serde(default = "defaults::default_decay_percent")]
    pub decay_percent: f64,

    #[serde(default = "defaults::default_reputation_block_threshold")]
    pub block_threshold: f64,

    #[serde(default = "defaults::default_high_reputation_score")]
    pub high_reputation_score: f64,
}

/// Auto-ban configuration for repeated offenders.
#[derive(Debug, Clone, Deserialize)]
pub struct AutoBanConfig {
    #[serde(default = "defaults::default_auto_ban_enabled")]
    pub enabled: bool,

    #[serde(default = "defaults::default_ban_threshold_5m")]
    pub ban_threshold_5m: u32,

    #[serde(default = "defaults::default_ban_threshold_15m")]
    pub ban_threshold_15m: u32,

    #[serde(default = "defaults::default_ban_threshold_1h")]
    pub ban_threshold_1h: u32,

    #[serde(default = "defaults::default_repeat_ban_threshold")]
    pub repeat_ban_threshold: u32,

    #[serde(default = "defaults::default_subnet_ban_ratio")]
    pub subnet_ban_ratio: f64,
}

/// Cloudflare compatibility configuration.
/// When enabled, Fortress trusts CF-Connecting-IP headers from Cloudflare IP ranges.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareConfig {
    #[serde(default)]
    pub enabled: bool,
}
