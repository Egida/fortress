use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::info;

use crate::models::request::RequestContext;

/
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuleAction {
    Block,
    Challenge,
    Score(f64),
}

/
#[derive(Debug, Clone)]
pub struct ManagedRuleResult {
    pub matched_rule: Option<String>,
    pub action: RuleAction,
    pub rule_id: u32,
}

/
struct EndpointRateTracker {
    /
    counters: DashMap<(String, String), (u32, Instant)>,
}

impl EndpointRateTracker {
    fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    fn check(&self, ip: &str, path_prefix: &str, limit: u32, window_secs: u64) -> bool {
        let key = (ip.to_string(), path_prefix.to_string());
        let now = Instant::now();
        let mut entry = self.counters.entry(key).or_insert((0, now));

        if now.duration_since(entry.1) > Duration::from_secs(window_secs) {
            entry.0 = 1;
            entry.1 = now;
            false
        } else {
            entry.0 += 1;
            entry.0 > limit
        }
    }

    fn cleanup(&self) {
        let now = Instant::now();
        let stale = Duration::from_secs(300);
        self.counters.retain(|_, (_, start)| now.duration_since(*start) < stale);
    }
}

/
pub struct ManagedRulesEngine {
    /
    enabled_rules: DashMap<u32, bool>,
    /
    endpoint_rates: EndpointRateTracker,
    /
    ua_flood: DashMap<String, (u32, Instant)>,
}

impl ManagedRulesEngine {
    pub fn new() -> Self {
        let engine = Self {
            enabled_rules: DashMap::new(),
            endpoint_rates: EndpointRateTracker::new(),
            ua_flood: DashMap::new(),
        };

        for id in 1..=20 {
            engine.enabled_rules.insert(id, id != 19);
        }

        info!("Managed rules engine initialized with 20 rules (19 enabled by default)");
        engine
    }

    /
    /
    pub fn check(&self, ctx: &RequestContext) -> Option<ManagedRuleResult> {
        let path = ctx.path.as_str();
        let method = ctx.method.as_str();
        let ua = ctx.user_agent.as_deref().unwrap_or("");
        let ip_str = ctx.client_ip.to_string();
        let headers = &ctx.headers;

        if self.is_enabled(1) {
            if path.contains("../") || path.contains("..%2f") || path.contains("..%2F")
                || path.contains("%2e%2e/") || path.contains("%2e%2e%2f") {
                return Some(ManagedRuleResult {
                    matched_rule: Some("path_traversal".to_string()),
                    action: RuleAction::Block,
                    rule_id: 1,
                });
            }
        }

        if self.is_enabled(2) {
            let sensitive = path == "/.env" || path.starts_with("/.env.")
                || path.starts_with("/.git/") || path == "/.git"
                || path.starts_with("/wp-admin") || path.starts_with("/wp-login")
                || path.starts_with("/phpmyadmin") || path.starts_with("/pma")
                || path.starts_with("/adminer") || path == "/wp-config.php"
                || path == "/xmlrpc.php" || path == "/wp-cron.php"
                || path.starts_with("/.svn/") || path.starts_with("/.hg/")
                || path == "/config.php" || path == "/configuration.php"
                || path.starts_with("/vendor/") && path.ends_with(".php");
            if sensitive {
                return Some(ManagedRuleResult {
                    matched_rule: Some("sensitive_files".to_string()),
                    action: RuleAction::Block,
                    rule_id: 2,
                });
            }
        }

        if self.is_enabled(3) {
            if path.ends_with(".bak") || path.ends_with(".old") || path.ends_with(".swp")
                || path.ends_with(".sql") || path.ends_with(".sql.gz")
                || path.ends_with(".tar.gz") || path.ends_with(".zip")
                && (path.contains("backup") || path.contains("dump") || path.contains("db")) {
                return Some(ManagedRuleResult {
                    matched_rule: Some("backup_files".to_string()),
                    action: RuleAction::Block,
                    rule_id: 3,
                });
            }
        }

        if self.is_enabled(4) {
            if path.starts_with("/.") && !path.starts_with("/.well-known") {
                return Some(ManagedRuleResult {
                    matched_rule: Some("hidden_files".to_string()),
                    action: RuleAction::Block,
                    rule_id: 4,
                });
            }
        }

        if self.is_enabled(5) {
            if (path.starts_with("/login") || path.starts_with("/signin") || path == "/auth/login")
                && (method == "POST" || method == "GET") {
                if self.endpoint_rates.check(&ip_str, "/login", 5, 60) {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("login_rate_limit".to_string()),
                        action: RuleAction::Challenge,
                        rule_id: 5,
                    });
                }
            }
        }

        if self.is_enabled(6) {
            if (path.starts_with("/register") || path.starts_with("/signup")) && method == "POST" {
                if self.endpoint_rates.check(&ip_str, "/register", 3, 60) {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("registration_limit".to_string()),
                        action: RuleAction::Challenge,
                        rule_id: 6,
                    });
                }
            }
        }

        if self.is_enabled(7) {
            if (path.starts_with("/forgot-password") || path.starts_with("/reset-password")
                || path.starts_with("/password/reset")) && method == "POST" {
                if self.endpoint_rates.check(&ip_str, "/password-reset", 2, 60) {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("password_reset_limit".to_string()),
                        action: RuleAction::Challenge,
                        rule_id: 7,
                    });
                }
            }
        }

        if self.is_enabled(8) {
            if let Some(cl) = headers.get("content-length") {
                if let Ok(size) = cl.parse::<u64>() {
                    if size > 10_485_760 {
                        return Some(ManagedRuleResult {
                            matched_rule: Some("large_payload".to_string()),
                            action: RuleAction::Block,
                            rule_id: 8,
                        });
                    }
                }
            }
        }

        if self.is_enabled(9) {
            if (method == "POST" || method == "PUT") && !headers.contains_key("content-type") {
                return Some(ManagedRuleResult {
                    matched_rule: Some("missing_content_type".to_string()),
                    action: RuleAction::Score(15.0),
                    rule_id: 9,
                });
            }
        }

        if self.is_enabled(10) {
            if ua.is_empty() && method == "POST" {
                return Some(ManagedRuleResult {
                    matched_rule: Some("empty_ua_post".to_string()),
                    action: RuleAction::Block,
                    rule_id: 10,
                });
            }
        }

        if self.is_enabled(11) {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("googlebot") || ua_lower.contains("google-inspectiontool") {
                let ip = ctx.client_ip;
                let is_google = match ip {
                    std::net::IpAddr::V4(v4) => {
                        let octets = v4.octets();
                        (octets[0] == 66 && octets[1] == 249)
                            || (octets[0] == 64 && octets[1] == 233)
                            || (octets[0] == 72 && octets[1] == 14)
                            || (octets[0] == 209 && octets[1] == 85)
                            || (octets[0] == 216 && octets[1] == 239)
                    }
                    _ => false,
                };
                if !is_google {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("fake_google_bot".to_string()),
                        action: RuleAction::Block,
                        rule_id: 11,
                    });
                }
            }
        }

        if self.is_enabled(12) {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("bingbot") || ua_lower.contains("msnbot") {
                let ip = ctx.client_ip;
                let is_bing = match ip {
                    std::net::IpAddr::V4(v4) => {
                        let octets = v4.octets();
                        octets[0] == 40 || octets[0] == 13
                            || (octets[0] == 157 && octets[1] == 55)
                            || (octets[0] == 207 && octets[1] == 46)
                            || (octets[0] == 65 && octets[1] == 55)
                            || (octets[0] == 199 && octets[1] == 30)
                    }
                    _ => false,
                };
                if !is_bing {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("fake_bing_bot".to_string()),
                        action: RuleAction::Block,
                        rule_id: 12,
                    });
                }
            }
        }

        if self.is_enabled(13) {
            if method == "TRACE" || method == "TRACK" || method == "CONNECT" || method == "DEBUG" {
                return Some(ManagedRuleResult {
                    matched_rule: Some("http_method_restrict".to_string()),
                    action: RuleAction::Block,
                    rule_id: 13,
                });
            }
        }

        if self.is_enabled(14) {
            if headers.contains_key("transfer-encoding") && headers.contains_key("content-length") {
                return Some(ManagedRuleResult {
                    matched_rule: Some("request_smuggling".to_string()),
                    action: RuleAction::Block,
                    rule_id: 14,
                });
            }
        }

        if self.is_enabled(15) {
            if let Some(host) = headers.get("host") {
                if host.contains('@') || host.contains(' ') || host.contains('\t') {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("host_header_injection".to_string()),
                        action: RuleAction::Block,
                        rule_id: 15,
                    });
                }
            }
        }

        if self.is_enabled(16) {
            if let Some(referer) = headers.get("referer") {
                let ref_lower = referer.to_lowercase();
                let spam_patterns = [
                    "semalt.com", "buttons-for-website.com", "darodar.com",
                    "ilovevitaly.com", "priceg.com", "hulfingtonpost.com",
                    "bestwebsitesawards.com", "o-o-6-o-o.com", "cenoval.ru",
                ];
                for pattern in &spam_patterns {
                    if ref_lower.contains(pattern) {
                        return Some(ManagedRuleResult {
                            matched_rule: Some("referer_spam".to_string()),
                            action: RuleAction::Block,
                            rule_id: 16,
                        });
                    }
                }
            }
        }

        if self.is_enabled(17) && !ua.is_empty() {
            let now = Instant::now();
            let mut entry = self.ua_flood.entry(ua.to_string()).or_insert((0, now));
            if now.duration_since(entry.1) > Duration::from_secs(60) {
                entry.0 = 1;
                entry.1 = now;
            } else {
                entry.0 += 1;
                if entry.0 > 1000 {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("connection_flood_ua".to_string()),
                        action: RuleAction::Score(25.0),
                        rule_id: 17,
                    });
                }
            }
        }


        if self.is_enabled(19) {
            if path.starts_with("/api/") {
                if self.endpoint_rates.check(&ip_str, "/api/", 100, 60) {
                    return Some(ManagedRuleResult {
                        matched_rule: Some("api_rate_limit".to_string()),
                        action: RuleAction::Block,
                        rule_id: 19,
                    });
                }
            }
        }

        if self.is_enabled(20) {
            let valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                               "TRACE", "CONNECT"];
            if !valid_methods.contains(&method) {
                return Some(ManagedRuleResult {
                    matched_rule: Some("invalid_method".to_string()),
                    action: RuleAction::Block,
                    rule_id: 20,
                });
            }
        }

        None
    }

    /
    pub fn set_rule_enabled(&self, rule_id: u32, enabled: bool) -> bool {
        if rule_id >= 1 && rule_id <= 20 {
            self.enabled_rules.insert(rule_id, enabled);
            info!(rule_id = rule_id, enabled = enabled, "Managed rule toggled");
            true
        } else {
            false
        }
    }

    /
    pub fn get_rules(&self) -> Vec<(u32, String, String, bool)> {
        let rule_info = [
            (1, "path_traversal", "Block path traversal attempts (../)"),
            (2, "sensitive_files", "Block access to sensitive files (.env, .git, wp-admin)"),
            (3, "backup_files", "Block access to backup files (.bak, .sql, .old)"),
            (4, "hidden_files", "Block access to hidden files (except .well-known)"),
            (5, "login_rate_limit", "Rate limit login attempts (5/min/IP)"),
            (6, "registration_limit", "Rate limit registrations (3/min/IP)"),
            (7, "password_reset_limit", "Rate limit password resets (2/min/IP)"),
            (8, "large_payload", "Block payloads > 10MB"),
            (9, "missing_content_type", "Score POST/PUT without Content-Type (+15)"),
            (10, "empty_ua_post", "Block POST with empty User-Agent"),
            (11, "fake_google_bot", "Block fake Googlebot (UA spoofing)"),
            (12, "fake_bing_bot", "Block fake Bingbot (UA spoofing)"),
            (13, "http_method_restrict", "Block TRACE/TRACK/CONNECT/DEBUG methods"),
            (14, "request_smuggling", "Block TE + CL header combo (smuggling)"),
            (15, "host_header_injection", "Block Host header injection"),
            (16, "referer_spam", "Block known referer spam domains"),
            (17, "connection_flood_ua", "Score same-UA flood (1000+/min, +25)"),
            (18, "slow_post", "Slow POST detection (handled by slowloris detector)"),
            (19, "api_rate_limit", "API rate limit (100/min/IP, disabled by default)"),
            (20, "invalid_method", "Block unknown HTTP methods"),
        ];

        rule_info.iter().map(|(id, name, desc)| {
            let enabled = self.enabled_rules.get(id).map(|v| *v).unwrap_or(false);
            (*id, name.to_string(), desc.to_string(), enabled)
        }).collect()
    }

    /
    fn is_enabled(&self, rule_id: u32) -> bool {
        self.enabled_rules.get(&rule_id).map(|v| *v).unwrap_or(false)
    }

    /
    pub fn cleanup(&self) {
        self.endpoint_rates.cleanup();
        let now = Instant::now();
        let stale = Duration::from_secs(120);
        self.ua_flood.retain(|_, (_, start)| now.duration_since(*start) < stale);
    }
}
