use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::models::request::RequestContext;
use crate::models::threat::ThreatAction;
use crate::storage::sqlite::SqliteStore;

/// A cached custom rule loaded from the database.
#[derive(Debug, Clone)]
pub struct CachedRule {
    pub id: i64,
    pub name: String,
    pub priority: i32,
    pub condition: RuleCondition,
    pub action: ThreatAction,
    pub enabled: bool,
}

/// Parsed rule condition supporting path, method, country, IP, user-agent matching.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleCondition {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub header: Option<std::collections::HashMap<String, String>>,
}

impl RuleCondition {
    /// Check if the request matches ALL specified conditions (AND logic).
    pub fn matches(&self, ctx: &RequestContext) -> bool {
        if let Some(ref path_pattern) = self.path {
            if !pattern_matches(path_pattern, &ctx.path) {
                return false;
            }
        }

        if let Some(ref method) = self.method {
            if !method.eq_ignore_ascii_case(&ctx.method) {
                return false;
            }
        }

        if let Some(ref country) = self.country {
            let ctx_country = ctx.country_code.as_deref().unwrap_or("");
            if !country.eq_ignore_ascii_case(ctx_country) {
                return false;
            }
        }

        if let Some(ref ip_pattern) = self.ip {
            let ip_str = ctx.client_ip.to_string();
            if !pattern_matches(ip_pattern, &ip_str) {
                return false;
            }
        }

        if let Some(ref ua_pattern) = self.user_agent {
            let ua = ctx.user_agent.as_deref().unwrap_or("");
            if !ua.to_lowercase().contains(&ua_pattern.to_lowercase()) {
                return false;
            }
        }

        if let Some(ref host_pattern) = self.host {
            if !pattern_matches(host_pattern, &ctx.host) {
                return false;
            }
        }

        if let Some(ref header_map) = self.header {
            for (key, expected_val) in header_map {
                let actual = ctx.headers.get(&key.to_lowercase()).map(|s| s.as_str()).unwrap_or("");
                if !actual.to_lowercase().contains(&expected_val.to_lowercase()) {
                    return false;
                }
            }
        }

        true
    }
}

/// Simple wildcard pattern matching supporting `*` at start/end.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with('*') && pattern.ends_with('*') {
        let inner = &pattern[1..pattern.len() - 1];
        return value.to_lowercase().contains(&inner.to_lowercase());
    }
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return value.starts_with(prefix);
    }
    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        return value.ends_with(suffix);
    }
    value == pattern
}

fn parse_action(action: &str) -> ThreatAction {
    match action.to_lowercase().as_str() {
        "pass" | "allow" => ThreatAction::Pass,
        "challenge" => ThreatAction::Challenge,
        "tarpit" => ThreatAction::Tarpit,
        _ => ThreatAction::Block,
    }
}

/// Engine that caches custom rules from the database and evaluates them.
pub struct CustomRulesEngine {
    sqlite: Arc<SqliteStore>,
    rules: RwLock<Vec<CachedRule>>,
    last_reload: RwLock<Instant>,
    reload_interval: Duration,
}

impl CustomRulesEngine {
    pub fn new(sqlite: Arc<SqliteStore>) -> Self {
        let engine = Self {
            sqlite,
            rules: RwLock::new(Vec::new()),
            last_reload: RwLock::new(Instant::now() - Duration::from_secs(999)),
            reload_interval: Duration::from_secs(5),
        };
        engine.reload_rules();
        engine
    }

    /// Reload rules from the database (called periodically).
    fn reload_rules(&self) {
        match self.sqlite.get_rules() {
            Ok(rows) => {
                let mut rules = Vec::new();
                for row in rows {
                    let condition: RuleCondition = match serde_json::from_str(&row.conditions_json) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(rule_id = row.id, error = %e, "Failed to parse rule condition JSON");
                            continue;
                        }
                    };
                    rules.push(CachedRule {
                        id: row.id,
                        name: row.name,
                        priority: row.priority,
                        condition,
                        action: parse_action(&row.action),
                        enabled: row.enabled,
                    });
                }
                // Sort by priority (lower = higher priority)
                rules.sort_by_key(|r| r.priority);
                *self.rules.write() = rules;
                *self.last_reload.write() = Instant::now();
            }
            Err(e) => {
                warn!(error = %e, "Failed to reload custom rules from database");
            }
        }
    }

    /// Ensure rules are up-to-date (reload if stale).
    fn ensure_fresh(&self) {
        let elapsed = self.last_reload.read().elapsed();
        if elapsed >= self.reload_interval {
            self.reload_rules();
        }
    }

    /// Evaluate all enabled custom rules against a request.
    /// Returns the first matching rule's action, or None.
    pub fn check(&self, ctx: &RequestContext) -> Option<(ThreatAction, String)> {
        self.ensure_fresh();

        let rules = self.rules.read();
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            if rule.condition.matches(ctx) {
                debug!(
                    ip = %ctx.client_ip,
                    rule_name = %rule.name,
                    rule_id = rule.id,
                    action = ?rule.action,
                    "Custom rule matched"
                );
                return Some((
                    rule.action.clone(),
                    format!("Custom rule: {}", rule.name),
                ));
            }
        }

        None
    }
}
