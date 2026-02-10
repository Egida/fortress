use super::settings::{
    AdminApiConfig, AsnScoringConfig, AutoBanConfig, BehavioralConfig, BlocklistConfig,
    BotWhitelistConfig, ChallengeConfig, CloudflareConfig, AlertingConfig, EscalationConfig,
    GeoipConfig, IpReputationConfig, L4ProtectionConfig, LoggingConfig, MobileProxyConfig,
    ProtectionConfig, RateLimitConfig, RateLimitLevels, ServerConfig, StorageConfig, TlsConfig,
    UpstreamConfig,
};

// ---------------------------------------------------------------------------
// Top-level struct defaults
// ---------------------------------------------------------------------------

pub fn default_server_config() -> ServerConfig {
    ServerConfig {
        bind_http: default_bind_http(),
        bind_https: default_bind_https(),
        workers: default_workers(),
        max_connections: default_max_connections(),
        connection_timeout_secs: default_connection_timeout_secs(),
        request_timeout_secs: default_request_timeout_secs(),
        keepalive_timeout_secs: default_keepalive_timeout_secs(),
    }
}

pub fn default_tls_config() -> TlsConfig {
    TlsConfig {
        cert_dir: default_cert_dir(),
        min_version: default_tls_min_version(),
    }
}

pub fn default_upstream_config() -> UpstreamConfig {
    UpstreamConfig {
        address: default_upstream_address(),
        max_connections: default_upstream_max_connections(),
        connect_timeout_ms: default_connect_timeout_ms(),
        response_timeout_ms: default_response_timeout_ms(),
    }
}

pub fn default_admin_api_config() -> AdminApiConfig {
    AdminApiConfig {
        bind: default_admin_bind(),
        api_key: default_api_key(),
    }
}

pub fn default_geoip_config() -> GeoipConfig {
    GeoipConfig {
        city_db: default_city_db(),
        asn_db: default_asn_db(),
    }
}

pub fn default_protection_config() -> ProtectionConfig {
    ProtectionConfig {
        default_level: 0,
        auto_escalation: default_auto_escalation(),
        rate_limits: default_rate_limits(),
        ipv4_subnet_mask: default_ipv4_subnet_mask(),
        whitelisted_ips: Vec::new(),
        whitelisted_subnets: Vec::new(),
    }
}

pub fn default_challenge_config() -> ChallengeConfig {
    ChallengeConfig {
        pow_difficulty_l1: default_pow_difficulty_l1(),
        pow_difficulty_l2: default_pow_difficulty_l2(),
        pow_difficulty_l3: default_pow_difficulty_l3(),
        cookie_name: default_cookie_name(),
        cookie_max_age_secs: default_cookie_max_age_secs(),
        hmac_secret: default_hmac_secret(),
        exempt_paths: Vec::new(),
        cookie_subnet_binding: false,
        nojs_fallback_enabled: false,
    }
}

pub fn default_blocklist_config() -> BlocklistConfig {
    BlocklistConfig {
        blocked_countries: Vec::new(),
        challenged_countries: Vec::new(),
        blocked_asns: Vec::new(),
        country_challenge_score: default_country_challenge_score(),
    }
}

pub fn default_behavioral_config() -> BehavioralConfig {
    BehavioralConfig {
        scoring_window_secs: default_scoring_window_secs(),
        max_profiles: default_max_profiles(),
        regularity_weight: default_regularity_weight(),
        path_diversity_min_requests: default_path_diversity_min_requests(),
    }
}

pub fn default_escalation_config() -> EscalationConfig {
    EscalationConfig {
        check_interval_secs: default_check_interval_secs(),
        deescalation_cooldown_secs: default_deescalation_cooldown_secs(),
        l0_to_l1_rps: default_l0_to_l1_rps(),
        l1_to_l2_rps: default_l1_to_l2_rps(),
        l2_to_l3_rps: default_l2_to_l3_rps(),
        l3_to_l4_rps: default_l3_to_l4_rps(),
        sustained_checks_required: default_sustained_checks_required(),
        block_ratio_threshold: default_block_ratio_threshold(),
    }
}

pub fn default_logging_config() -> LoggingConfig {
    LoggingConfig {
        level: default_log_level(),
        file: default_log_file(),
        access_log: default_access_log(),
    }
}

pub fn default_storage_config() -> StorageConfig {
    StorageConfig {
        sqlite_path: default_sqlite_path(),
    }
}

// ---------------------------------------------------------------------------
// ServerConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_bind_http() -> String {
    "0.0.0.0:80".to_string()
}

pub fn default_bind_https() -> String {
    "0.0.0.0:443".to_string()
}

pub fn default_workers() -> usize {
    num_cpus()
}

pub fn default_max_connections() -> usize {
    50_000
}

pub fn default_connection_timeout_secs() -> u64 {
    30
}

pub fn default_request_timeout_secs() -> u64 {
    60
}

pub fn default_keepalive_timeout_secs() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// TlsConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_cert_dir() -> String {
    "/etc/letsencrypt/live".to_string()
}

pub fn default_tls_min_version() -> String {
    "1.2".to_string()
}

// ---------------------------------------------------------------------------
// UpstreamConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_upstream_address() -> String {
    "127.0.0.1:8080".to_string()
}

pub fn default_upstream_max_connections() -> usize {
    10_000
}

pub fn default_connect_timeout_ms() -> u64 {
    5_000
}

pub fn default_response_timeout_ms() -> u64 {
    60_000
}

// ---------------------------------------------------------------------------
// AdminApiConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_admin_bind() -> String {
    "127.0.0.1:9090".to_string()
}

pub fn default_api_key() -> String {
    // INSECURE DEFAULT: Must be overridden in production config.
    // Startup validation in main.rs will panic if this is left empty.
    String::new()
}

// ---------------------------------------------------------------------------
// GeoipConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_city_db() -> String {
    "/opt/fortress/data/GeoLite2-City.mmdb".to_string()
}

pub fn default_asn_db() -> String {
    "/opt/fortress/data/GeoLite2-ASN.mmdb".to_string()
}

// ---------------------------------------------------------------------------
// ProtectionConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_auto_escalation() -> bool {
    true
}

pub fn default_rate_limits() -> RateLimitLevels {
    RateLimitLevels {
        level_0: default_rate_limit_level_0(),
        level_1: default_rate_limit_level_1(),
        level_2: default_rate_limit_level_2(),
        level_3: default_rate_limit_level_3(),
    }
}

pub fn default_rate_limit_level_0() -> RateLimitConfig {
    RateLimitConfig {
        ip_per_10s: 500,
        subnet_per_10s: 2_000,
        asn_per_10s: 10_000,
        country_per_10s: 50_000,
    }
}

pub fn default_rate_limit_level_1() -> RateLimitConfig {
    RateLimitConfig {
        ip_per_10s: 300,
        subnet_per_10s: 1_000,
        asn_per_10s: 5_000,
        country_per_10s: 20_000,
    }
}

pub fn default_rate_limit_level_2() -> RateLimitConfig {
    RateLimitConfig {
        ip_per_10s: 150,
        subnet_per_10s: 500,
        asn_per_10s: 2_000,
        country_per_10s: 10_000,
    }
}

pub fn default_rate_limit_level_3() -> RateLimitConfig {
    RateLimitConfig {
        ip_per_10s: 50,
        subnet_per_10s: 200,
        asn_per_10s: 1_000,
        country_per_10s: 5_000,
    }
}

pub fn default_ip_per_10s() -> u64 {
    100
}

pub fn default_subnet_per_10s() -> u64 {
    500
}

pub fn default_asn_per_10s() -> u64 {
    2_000
}

pub fn default_country_per_10s() -> u64 {
    10_000
}

// ---------------------------------------------------------------------------
// ChallengeConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_pow_difficulty_l1() -> u8 {
    16
}

pub fn default_pow_difficulty_l2() -> u8 {
    18
}

pub fn default_pow_difficulty_l3() -> u8 {
    20
}

pub fn default_cookie_name() -> String {
    "__fortress_clearance".to_string()
}

pub fn default_cookie_max_age_secs() -> u64 {
    1_800
}

pub fn default_hmac_secret() -> String {
    // INSECURE DEFAULT: Must be overridden in production config.
    // Startup validation in main.rs will panic if this is left empty.
    String::new()
}

// ---------------------------------------------------------------------------
// BehavioralConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_scoring_window_secs() -> u64 {
    60
}

pub fn default_max_profiles() -> usize {
    1_000_000
}

// ---------------------------------------------------------------------------
// EscalationConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_check_interval_secs() -> u64 {
    5
}

pub fn default_deescalation_cooldown_secs() -> u64 {
    300
}

pub fn default_l0_to_l1_rps() -> u64 {
    5_000
}

pub fn default_l1_to_l2_rps() -> u64 {
    15_000
}

pub fn default_l2_to_l3_rps() -> u64 {
    50_000
}

pub fn default_l3_to_l4_rps() -> u64 {
    100_000
}

// ---------------------------------------------------------------------------
// LoggingConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_log_level() -> String {
    "info".to_string()
}

pub fn default_log_file() -> String {
    "/var/log/fortress/fortress.log".to_string()
}

pub fn default_access_log() -> String {
    "/var/log/fortress/access.log".to_string()
}

// ---------------------------------------------------------------------------
// StorageConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_sqlite_path() -> String {
    "/opt/fortress/data/fortress.db".to_string()
}

// ---------------------------------------------------------------------------
// L4ProtectionConfig field defaults
// ---------------------------------------------------------------------------

pub fn default_l4_protection_config() -> L4ProtectionConfig {
    L4ProtectionConfig {
        enabled: default_l4_enabled(),
        syn_rate_per_ip_per_sec: default_syn_rate(),
        connection_rate_per_ip_per_sec: default_conn_rate(),
        max_concurrent_per_ip: default_max_concurrent(),
        tarpit_enabled: default_tarpit_enabled(),
        tarpit_delay_ms: default_tarpit_delay(),
    }
}

pub fn default_l4_enabled() -> bool { true }
pub fn default_syn_rate() -> u64 { 50 }
pub fn default_conn_rate() -> u64 { 30 }
pub fn default_max_concurrent() -> u64 { 100 }
pub fn default_tarpit_enabled() -> bool { true }
pub fn default_tarpit_delay() -> u64 { 5000 }

// ---------------------------------------------------------------------------
// AlertingConfig defaults
// ---------------------------------------------------------------------------

pub fn default_alerting_config() -> AlertingConfig {
    AlertingConfig {
        enabled: false,
        webhook_url: None,
    }
}

// ---------------------------------------------------------------------------
// BotWhitelistConfig defaults
// ---------------------------------------------------------------------------

pub fn default_bot_whitelist_config() -> BotWhitelistConfig {
    BotWhitelistConfig {
        enabled: default_bot_whitelist_enabled(),
        verify_ip: default_bot_verify_ip(),
    }
}

pub fn default_bot_whitelist_enabled() -> bool { true }
pub fn default_bot_verify_ip() -> bool { true }

// ---------------------------------------------------------------------------
// MobileProxyConfig defaults
// ---------------------------------------------------------------------------

pub fn default_mobile_proxy_config() -> MobileProxyConfig {
    MobileProxyConfig {
        min_signals: default_mobile_proxy_min_signals(),
        score_threshold: default_mobile_proxy_score_threshold(),
    }
}

pub fn default_mobile_proxy_min_signals() -> u32 { 3 }
pub fn default_mobile_proxy_score_threshold() -> f64 { 80.0 }

// ---------------------------------------------------------------------------
// AsnScoringConfig defaults
// ---------------------------------------------------------------------------

pub fn default_asn_scoring_config() -> AsnScoringConfig {
    AsnScoringConfig {
        datacenter_score: default_datacenter_score(),
        vpn_score: default_vpn_score(),
        residential_proxy_score: default_residential_proxy_score(),
    }
}

pub fn default_datacenter_score() -> f64 { 5.0 }
pub fn default_vpn_score() -> f64 { 5.0 }
pub fn default_residential_proxy_score() -> f64 { 25.0 }

// ---------------------------------------------------------------------------
// New field defaults (added to existing structs)
// ---------------------------------------------------------------------------

pub fn default_country_challenge_score() -> f64 { 20.0 }
pub fn default_regularity_weight() -> f64 { 0.5 }
pub fn default_path_diversity_min_requests() -> u64 { 50 }
pub fn default_sustained_checks_required() -> u8 { 3 }
pub fn default_block_ratio_threshold() -> f64 { 0.3 }
pub fn default_ipv4_subnet_mask() -> u8 { 24 }

// ---------------------------------------------------------------------------
// IpReputationConfig defaults
// ---------------------------------------------------------------------------

pub fn default_ip_reputation_config() -> IpReputationConfig {
    IpReputationConfig {
        enabled: default_ip_reputation_enabled(),
        tor_detection: default_tor_detection(),
        tor_score: default_tor_score(),
        decay_interval_secs: default_decay_interval_secs(),
        decay_percent: default_decay_percent(),
        block_threshold: default_reputation_block_threshold(),
        high_reputation_score: default_high_reputation_score(),
    }
}

pub fn default_ip_reputation_enabled() -> bool { true }
pub fn default_tor_detection() -> bool { true }
pub fn default_tor_score() -> f64 { 15.0 }
pub fn default_decay_interval_secs() -> u64 { 600 }
pub fn default_decay_percent() -> f64 { 10.0 }
pub fn default_reputation_block_threshold() -> f64 { 80.0 }
pub fn default_high_reputation_score() -> f64 { 20.0 }

// ---------------------------------------------------------------------------
// AutoBanConfig defaults
// ---------------------------------------------------------------------------

pub fn default_auto_ban_config() -> AutoBanConfig {
    AutoBanConfig {
        enabled: default_auto_ban_enabled(),
        ban_threshold_5m: default_ban_threshold_5m(),
        ban_threshold_15m: default_ban_threshold_15m(),
        ban_threshold_1h: default_ban_threshold_1h(),
        repeat_ban_threshold: default_repeat_ban_threshold(),
        subnet_ban_ratio: default_subnet_ban_ratio(),
    }
}

pub fn default_auto_ban_enabled() -> bool { true }
pub fn default_ban_threshold_5m() -> u32 { 10 }
pub fn default_ban_threshold_15m() -> u32 { 25 }
pub fn default_ban_threshold_1h() -> u32 { 50 }
pub fn default_repeat_ban_threshold() -> u32 { 3 }
pub fn default_subnet_ban_ratio() -> f64 { 0.3 }

// ---------------------------------------------------------------------------
// CloudflareConfig defaults
// ---------------------------------------------------------------------------

pub fn default_cloudflare_config() -> CloudflareConfig {
    CloudflareConfig {
        enabled: false,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the number of logical CPUs, falling back to 4 if detection fails.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
