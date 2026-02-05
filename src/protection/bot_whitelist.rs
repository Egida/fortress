use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

use crate::config::settings::BotWhitelistConfig;

/
///
/
/
pub struct BotWhitelist {
    enabled: bool,
    verify_ip: bool,
    /
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

/
const CACHE_TTL: Duration = Duration::from_secs(3600);

impl BotWhitelist {
    pub fn new(config: &BotWhitelistConfig) -> Self {
        Self {
            enabled: config.enabled,
            verify_ip: config.verify_ip,
            verified_cache: DashMap::new(),
        }
    }

    /
    /
    pub fn check(&self, ua: Option<&str>, ip: &IpAddr) -> Option<String> {
        if !self.enabled {
            return None;
        }

        let ua_str = ua?;
        let ua_lower = ua_str.to_lowercase();

        if let Some(entry) = self.verified_cache.get(ip) {
            let (ref name, verified_at) = *entry.value();
            if verified_at.elapsed() < CACHE_TTL {
                return Some(name.clone());
            }
            drop(entry);
            self.verified_cache.remove(ip);
        }

        for bot in KNOWN_BOTS {
            if ua_lower.contains(bot.ua_contains) {
                if self.verify_ip {
                    if self.verify_bot_ip(ip, bot.dns_suffixes) {
                        let name = bot.name.to_string();
                        self.verified_cache
                            .insert(*ip, (name.clone(), Instant::now()));
                        debug!(ip = %ip, bot = bot.name, "Bot verified via reverse DNS");
                        return Some(name);
                    }
                    debug!(ip = %ip, bot = bot.name, "Bot UA claimed but IP verification failed");
                    return None;
                } else {
                    let name = bot.name.to_string();
                    self.verified_cache
                        .insert(*ip, (name.clone(), Instant::now()));
                    return Some(name);
                }
            }
        }

        None
    }

    /
    fn verify_bot_ip(&self, ip: &IpAddr, valid_suffixes: &[&str]) -> bool {
        use std::net::ToSocketAddrs;

        let hostname = match dns_lookup_reverse(ip) {
            Some(h) => h,
            None => return false,
        };

        let hostname_lower = hostname.to_lowercase();
        let suffix_match = valid_suffixes
            .iter()
            .any(|suffix| hostname_lower.ends_with(suffix) || hostname_lower.ends_with(&suffix[..suffix.len()-1]));

        if !suffix_match {
            return false;
        }

        match (hostname.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => addrs.into_iter().any(|addr| &addr.ip() == ip),
            Err(_) => false,
        }
    }

    /
    pub fn cleanup(&self) {
        self.verified_cache
            .retain(|_, (_, verified_at)| verified_at.elapsed() < CACHE_TTL);
    }
}

/
fn dns_lookup_reverse(ip: &IpAddr) -> Option<String> {
    use std::net::SocketAddr;

    let socket_addr = SocketAddr::new(*ip, 0);

    
    
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
