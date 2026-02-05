//! Cloudflare IP range detection.
//!
//! Contains hardcoded Cloudflare IPv4 and IPv6 ranges for trusted proxy detection.
//! Source: https://www.cloudflare.com/ips/

use std::net::IpAddr;

/
const CF_IPV4_RANGES: &[(&str, u8)] = &[
    ("173.245.48.0", 20),
    ("103.21.244.0", 22),
    ("103.22.200.0", 22),
    ("103.31.4.0", 22),
    ("141.101.64.0", 18),
    ("108.162.192.0", 18),
    ("190.93.240.0", 20),
    ("188.114.96.0", 20),
    ("197.234.240.0", 22),
    ("198.41.128.0", 17),
    ("162.158.0.0", 15),
    ("104.16.0.0", 13),
    ("104.24.0.0", 14),
    ("172.64.0.0", 13),
    ("131.0.72.0", 22),
];

/
pub fn is_cloudflare_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let ip_u32 = u32::from(v4);
            for &(base_str, prefix_len) in CF_IPV4_RANGES {
                if let Ok(base) = base_str.parse::<std::net::Ipv4Addr>() {
                    let base_u32 = u32::from(base);
                    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
                    if (ip_u32 & mask) == (base_u32 & mask) {
                        return true;
                    }
                }
            }
            false
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let first4 = [octets[0], octets[1], octets[2], octets[3]];
            matches!(
                first4,
                [0x24, 0x00, ..] |
                [0x26, 0x06, ..] |
                [0x28, 0x03, ..] |
                [0x24, 0x05, ..] |
                [0x2a, 0x06, ..] |
                [0x2c, 0x0f, ..]
            )
        }
    }
}
