use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::threat::{ThreatAction, ThreatReason};

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /
    pub rps: f64,

    /
    pub blocked_per_sec: f64,

    /
    pub challenged_per_sec: f64,

    /
    pub passed_per_sec: f64,

    /
    pub unique_ips: u64,

    /
    pub avg_latency_ms: f64,

    /
    pub total_requests: u64,

    /
    pub total_blocked: u64,

    /
    pub uptime_secs: u64,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4MetricsSnapshot {
    pub total_allowed: u64,
    pub total_dropped: u64,
    pub total_tarpitted: u64,
    pub tracked_ips: u64,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveTrafficEvent {
    /
    pub timestamp: DateTime<Utc>,

    /
    pub client_ip: IpAddr,

    /
    pub country_code: Option<String>,

    /
    pub asn: Option<u32>,

    /
    pub method: String,

    /
    pub path: String,

    /
    pub host: String,

    /
    pub status_code: u16,

    /
    pub action: ThreatAction,

    /
    pub reason: Option<ThreatReason>,

    /
    pub latency_ms: Option<f64>,

    /
    pub user_agent: Option<String>,

    /
    pub ja3_hash: Option<String>,

    /
    pub behavioral_score: f64,
}

impl LiveTrafficEvent {
    /
    pub fn new(
        client_ip: IpAddr,
        method: String,
        path: String,
        host: String,
        status_code: u16,
        action: ThreatAction,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            client_ip,
            country_code: None,
            asn: None,
            method,
            path,
            host,
            status_code,
            action,
            reason: None,
            latency_ms: None,
            user_agent: None,
            ja3_hash: None,
            behavioral_score: 0.0,
        }
    }
}
