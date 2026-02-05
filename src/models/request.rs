use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/
/
#[derive(Debug, Clone)]
pub struct RequestContext {
    /
    pub client_ip: IpAddr,

    /
    pub ja3_hash: Option<String>,

    /
    pub country_code: Option<String>,

    /
    pub asn: Option<u32>,

    /
    pub asn_name: Option<String>,

    /
    pub user_agent: Option<String>,

    /
    pub method: String,

    /
    pub path: String,

    /
    pub host: String,

    /
    pub headers: HashMap<String, String>,

    /
    pub is_datacenter: bool,

    /
    pub is_residential_proxy: bool,

    /
    pub behavioral_score: f64,

    /
    pub is_behind_cloudflare: bool,

    /
    pub timestamp: Instant,
}

impl RequestContext {
    /
    /
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

    /
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
