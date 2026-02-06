use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::threat::{ThreatAction, ThreatReason};

/// A point-in-time snapshot of system-wide metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Requests per second averaged over the snapshot window.
    pub rps: f64,

    /// Blocked requests per second.
    pub blocked_per_sec: f64,

    /// Challenged requests per second.
    pub challenged_per_sec: f64,

    /// Passed requests per second.
    pub passed_per_sec: f64,

    /// Number of unique client IPs seen in the snapshot window.
    pub unique_ips: u64,

    /// Average upstream response latency in milliseconds.
    pub avg_latency_ms: f64,

    /// Total requests received since start.
    pub total_requests: u64,

    /// Total requests blocked since start.
    pub total_blocked: u64,

    /// Seconds since the service started.
    pub uptime_secs: u64,
}

/// L4 protection metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4MetricsSnapshot {
    pub total_allowed: u64,
    pub total_dropped: u64,
    pub total_tarpitted: u64,
    pub tracked_ips: u64,
}

/// A single traffic event for real-time WebSocket streaming to the admin UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveTrafficEvent {
    /// ISO-8601 timestamp of the event.
    pub timestamp: DateTime<Utc>,

    /// Client IP address.
    pub client_ip: IpAddr,

    /// ISO country code (if resolved).
    pub country_code: Option<String>,

    /// ASN number (if resolved).
    pub asn: Option<u32>,

    /// HTTP method.
    pub method: String,

    /// Request path.
    pub path: String,

    /// Host header value.
    pub host: String,

    /// HTTP status code returned to the client.
    pub status_code: u16,

    /// The action taken by the proxy.
    pub action: ThreatAction,

    /// The reason for the action, if any.
    pub reason: Option<ThreatReason>,

    /// Upstream response latency in milliseconds (None if blocked/challenged).
    pub latency_ms: Option<f64>,

    /// User-Agent header value.
    pub user_agent: Option<String>,

    /// JA3 fingerprint hash (if available).
    pub ja3_hash: Option<String>,

    /// Behavioral anomaly score at the time of the request.
    pub behavioral_score: f64,
}

impl LiveTrafficEvent {
    /// Create a new live traffic event with the given fields.
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
