use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Full context for an incoming request, enriched with GeoIP data,
/// fingerprint information, and behavioral scoring.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The client's IP address (after X-Forwarded-For resolution).
    pub client_ip: IpAddr,

    /// JA3 TLS fingerprint hash, if available.
    pub ja3_hash: Option<String>,

    /// ISO 3166-1 alpha-2 country code from GeoIP lookup.
    pub country_code: Option<String>,

    /// Autonomous System Number from GeoIP lookup.
    pub asn: Option<u32>,

    /// Human-readable ASN organization name.
    pub asn_name: Option<String>,

    /// User-Agent header value.
    pub user_agent: Option<String>,

    /// HTTP method (GET, POST, etc.).
    pub method: String,

    /// Request path (e.g. "/api/v1/users").
    pub path: String,

    /// Host header value.
    pub host: String,

    /// All request headers as key-value pairs.
    pub headers: HashMap<String, String>,

    /// Whether the IP belongs to a known datacenter/hosting provider.
    pub is_datacenter: bool,

    /// Whether the IP is a known residential proxy.
    pub is_residential_proxy: bool,

    /// Behavioral anomaly score (0.0 = benign, 1.0 = highly suspicious).
    pub behavioral_score: f64,

    /// Whether this request came through Cloudflare (detected via CF headers).
    pub is_behind_cloudflare: bool,

    /// Timestamp when the request was received.
    pub timestamp: Instant,
}

impl RequestContext {
    /// Create a new RequestContext with minimal required fields;
    /// optional fields are initialized to None / defaults.
    pub fn new(client_ip: IpAddr, method: String, path: String, host: String) -> Self {
        Self {
            client_ip,
            ja3_hash: None,
            country_code: None,
            asn: None,
            asn_name: None,
            user_agent: None,
            method,
            path,
            host,
            headers: HashMap::new(),
            is_datacenter: false,
            is_residential_proxy: false,
            behavioral_score: 0.0,
            is_behind_cloudflare: false,
            timestamp: Instant::now(),
        }
    }

    /// Returns the /24 (IPv4) or /48 (IPv6) subnet string for this client.
    pub fn subnet_key(&self) -> String {
        match self.client_ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
            }
        }
    }
}
