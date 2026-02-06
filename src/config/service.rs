use serde::{Deserialize, Serialize};

/// Configuration for a single protected service/backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub upstream_address: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub protection_level_override: Option<u8>,
    #[serde(default)]
    pub always_challenge: bool,
    #[serde(default = "default_rate_limit_multiplier")]
    pub rate_limit_multiplier: f64,
    #[serde(default = "default_service_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_service_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_service_response_timeout")]
    pub response_timeout_ms: u64,
    #[serde(default)]
    pub exempt_paths: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

fn default_enabled() -> bool { true }
fn default_rate_limit_multiplier() -> f64 { 1.0 }
fn default_service_max_connections() -> usize { 10_000 }
fn default_service_connect_timeout() -> u64 { 5_000 }
fn default_service_response_timeout() -> u64 { 60_000 }
