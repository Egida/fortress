use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

use crate::config::settings::BotWhitelistConfig;

/// Known-good search engine bot whitelist.
///
/// Prevents false positives by allowing verified search engine crawlers
/// to bypass the protection pipeline entirely (after blocklist checks).
pub struct BotWhitelist {
    enabled: bool,
    verify_ip: bool,
    /// Cache of verified bot IPs: IP -> (bot_name, verified_at)
    verified_cache: DashMap<IpAddr, (String, Instant)>,
}

struct KnownBot {
    name: &'static str,
    ua_contains: &'static str,
    dns_suffixes: &'static [&'static str],
}

const KNOWN_BOTS: &[KnownBot] = &[
    KnownBot {
        name: "Googlebot",
        ua_contains: "googlebot",
        dns_suffixes: &[".googlebot.com.", ".google.com."],
    },
    KnownBot {
        name: "Bingbot",
        ua_contains: "bingbot",
        dns_suffixes: &[".search.msn.com."],
    },
    KnownBot {
        name: "YandexBot",
        ua_contains: "yandexbot",
        dns_suffixes: &[".yandex.ru.", ".yandex.net.", ".yandex.com."],
    },
    KnownBot {
        name: "Baiduspider",
        ua_contains: "baiduspider",
        dns_suffixes: &[".baidu.com.", ".baidu.jp."],
    },
    KnownBot {
        name: "DuckDuckBot",
        ua_contains: "duckduckbot",
        dns_suffixes: &[".duckduckgo.com."],
    },
    KnownBot {
        name: "Slurp",
        ua_contains: "slurp",
        dns_suffixes: &[".crawl.yahoo.net."],
    },
    KnownBot {
        name: "Applebot",
        ua_contains: "applebot",
        dns_suffixes: &[".apple.com."],
    },
    KnownBot {
        name: "AhrefsBot",
        ua_contains: "ahrefsbot",
        dns_suffixes: &[".ahrefs.com."],
    },
];

/// Cache entry TTL: 1 hour
const CACHE_TTL: Duration = Duration::from_secs(3600);

impl BotWhitelist {
    pub fn new(config: &BotWhitelistConfig) -> Self {
        Self {
            enabled: config.enabled,
            verify_ip: config.verify_ip,
            verified_cache: DashMap::new(),
        }
    }

    /// Check if the request is from a known search engine bot.
    /// Returns Some(bot_name) if whitelisted, None otherwise.
    pub fn check(&self, ua: Option<&str>, ip: &IpAddr) -> Option<String> {
        if !self.enabled {
            return None;
        }

        let ua_str = ua?;
        let ua_lower = ua_str.to_lowercase();

        // Check cache first
        if let Some(entry) = self.verified_cache.get(ip) {
            let (ref name, verified_at) = *entry.value();
            if verified_at.elapsed() < CACHE_TTL {
                return Some(name.clone());
            }
            // Cache expired, remove and re-check
            drop(entry);
            self.verified_cache.remove(ip);
        }

        // Find matching bot by UA
        for bot in KNOWN_BOTS {
            if ua_lower.contains(bot.ua_contains) {
                if self.verify_ip {
                    // Attempt reverse DNS verification
                    if self.verify_bot_ip(ip, bot.dns_suffixes) {
                        let name = bot.name.to_string();
                        self.verified_cache
                            .insert(*ip, (name.clone(), Instant::now()));
                        debug!(ip = %ip, bot = bot.name, "Bot verified via reverse DNS");
                        return Some(name);
                    }
                    // IP verification failed - UA claims bot but IP doesn't match
                    debug!(ip = %ip, bot = bot.name, "Bot UA claimed but IP verification failed");
                    return None;
                } else {
                    // Trust UA without IP verification
                    let name = bot.name.to_string();
                    self.verified_cache
                        .insert(*ip, (name.clone(), Instant::now()));
                    return Some(name);
                }
            }
        }

        None
    }

    /// Verify a bot IP via reverse DNS lookup + forward verification.
    fn verify_bot_ip(&self, ip: &IpAddr, valid_suffixes: &[&str]) -> bool {
        use std::net::ToSocketAddrs;

        // Reverse DNS lookup: convert IP to hostname
        let hostname = match dns_lookup_reverse(ip) {
            Some(h) => h,
            None => return false, // DNS lookup failed, fail-open = don't whitelist
        };

        // Check if hostname ends with one of the valid suffixes
        let hostname_lower = hostname.to_lowercase();
        let suffix_match = valid_suffixes
            .iter()
            .any(|suffix| hostname_lower.ends_with(suffix) || hostname_lower.ends_with(&suffix[..suffix.len()-1]));

        if !suffix_match {
            return false;
        }

        // Forward verification: resolve hostname back to IP
        match (hostname.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => addrs.into_iter().any(|addr| &addr.ip() == ip),
            Err(_) => false,
        }
    }

    /// Cleanup expired cache entries.
    pub fn cleanup(&self) {
        self.verified_cache
            .retain(|_, (_, verified_at)| verified_at.elapsed() < CACHE_TTL);
    }
}

/// Perform reverse DNS lookup using libc getnameinfo.
fn dns_lookup_reverse(ip: &IpAddr) -> Option<String> {
    use std::net::SocketAddr;

    let socket_addr = SocketAddr::new(*ip, 0);

    // Use std::net::ToSocketAddrs in reverse is not possible directly.
    // We'll use the dns-lookup approach via libc.
    // Since we can't add external crates easily, use a blocking DNS resolution
    // by spawning a subprocess or using libc directly.
    
    // Simplest approach: try to resolve via system DNS
    // We use the fact that gethostbyaddr equivalent can be done
    // through a simple reverse lookup pattern.
    
    // Use std command for now (works on Linux)
    let output = std::process::Command::new("dig")
        .args(&[
            "+short",
            "-x",
            &ip.to_string(),
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let hostname = String::from_utf8(output.stdout).ok()?;
    let hostname = hostname.trim().to_string();

    if hostname.is_empty() || hostname == "." {
        return None;
    }

    Some(hostname)
}
