use tracing::debug;

use crate::models::request::RequestContext;
use crate::models::threat::ThreatReason;

/// HTTP header validation and anomaly detection.
///
/// Analyzes request headers for signs of automated attack tools,
/// misconfigured clients, or intentional evasion. Legitimate automation
/// tools (curl, python-requests, etc.) are NOT penalized.
pub struct HeaderAnalyzer {}

impl HeaderAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    /// Analyze request headers for anomalies.
    pub fn analyze(&self, ctx: &RequestContext) -> (f64, Option<ThreatReason>) {
        let mut score: f64 = 0.0;
        let mut primary_reason: Option<ThreatReason> = None;

        // Check 1: Missing Host header
        if ctx.host.is_empty() {
            debug!(ip = %ctx.client_ip, "Missing Host header");
            score += 20.0;
            if primary_reason.is_none() {
                primary_reason = Some(ThreatReason::HeaderAnomaly);
            }
        }

        // Check 2: Missing or empty User-Agent (reduced penalty for API clients)
        match &ctx.user_agent {
            None => {
                debug!(ip = %ctx.client_ip, "Missing User-Agent header");
                score += 10.0;
                if primary_reason.is_none() {
                    primary_reason = Some(ThreatReason::HeaderAnomaly);
                }
            }
            Some(ua) if ua.is_empty() => {
                debug!(ip = %ctx.client_ip, "Empty User-Agent header");
                score += 10.0;
                if primary_reason.is_none() {
                    primary_reason = Some(ThreatReason::HeaderAnomaly);
                }
            }
            _ => {}
        }

        // Determine if UA claims to be a browser for checks 3-4
        let is_browser_ua = ctx
            .user_agent
            .as_ref()
            .map(|ua| self.is_browser_user_agent(ua))
            .unwrap_or(false);

        // Check 3: Missing Accept header on browser requests ONLY
        if is_browser_ua && !ctx.headers.contains_key("accept") {
            debug!(ip = %ctx.client_ip, "Browser UA but missing Accept header");
            score += 15.0;
        }

        // Check 4: Missing Accept-Language on browser requests ONLY
        if is_browser_ua && !ctx.headers.contains_key("accept-language") {
            debug!(ip = %ctx.client_ip, "Browser UA but missing Accept-Language header");
            score += 15.0;
        }

        // Check 5: Impossible header combinations
        if self.has_impossible_headers(ctx) {
            debug!(ip = %ctx.client_ip, "Impossible header combination detected");
            score += 30.0;
            if primary_reason.is_none() {
                primary_reason = Some(ThreatReason::HeaderAnomaly);
            }
        }

        // Check 6: Known ATTACK tool user agents (NOT legitimate tools)
        if let Some(ref ua) = ctx.user_agent {
            if let Some((tool, is_attack)) = self.detect_known_bot_ua(ua) {
                if is_attack {
                    debug!(ip = %ctx.client_ip, tool = tool, "Known attack tool User-Agent");
                    score += 40.0;
                    if primary_reason.is_none() {
                        primary_reason = Some(ThreatReason::HeaderAnomaly);
                    }
                } else {
                    debug!(ip = %ctx.client_ip, tool = tool, "Known legitimate automation tool (no penalty)");
                }
            }
        }

        // Check 7: Very long or malformed headers
        if self.has_malformed_headers(ctx) {
            debug!(ip = %ctx.client_ip, "Malformed or excessively long headers");
            score += 20.0;
            if primary_reason.is_none() {
                primary_reason = Some(ThreatReason::HeaderAnomaly);
            }
        }

        // Check 8: Transfer-Encoding + Content-Length (request smuggling)
        if ctx.headers.contains_key("transfer-encoding") && ctx.headers.contains_key("content-length") {
            debug!(ip = %ctx.client_ip, "Duplicate Content-Length / Transfer-Encoding (smuggling indicator)");
            score += 50.0;
            if primary_reason.is_none() {
                primary_reason = Some(ThreatReason::HeaderAnomaly);
            }
        }

        let clamped = score.min(100.0);

        if clamped < 15.0 {
            primary_reason = None;
        }

        (clamped, primary_reason)
    }

    fn is_browser_user_agent(&self, ua: &str) -> bool {
        let lower = ua.to_lowercase();
        lower.contains("mozilla/5.0")
            && (lower.contains("applewebkit")
                || lower.contains("gecko")
                || lower.contains("trident")
                || lower.contains("chrome")
                || lower.contains("firefox")
                || lower.contains("safari"))
    }

    /// Returns (tool_name, is_attack_tool).
    /// Attack tools get +40 score. Legitimate tools get +0.
    fn detect_known_bot_ua(&self, ua: &str) -> Option<(&'static str, bool)> {
        let lower = ua.to_lowercase();

        // Attack / scanning tools — high score
        if lower.contains("nikto") { return Some(("nikto", true)); }
        if lower.contains("sqlmap") { return Some(("sqlmap", true)); }
        if lower.contains("nmap") || lower.contains("masscan") { return Some(("nmap/masscan", true)); }
        if lower.contains("dirbuster") || lower.contains("gobuster") || lower.contains("ffuf") {
            return Some(("directory-scanner", true));
        }
        if lower.contains("nuclei") { return Some(("nuclei", true)); }
        if lower.contains("scrapy") { return Some(("scrapy", true)); }
        if lower.contains("slowhttptest") || lower.contains("slowloris") {
            return Some(("slowhttp-tool", true));
        }

        // Legitimate automation tools — NO penalty
        if lower.starts_with("python-requests") || lower.starts_with("python-urllib") {
            return Some(("python-requests", false));
        }
        if lower.starts_with("go-http-client") || lower.starts_with("go/") {
            return Some(("Go-http-client", false));
        }
        if lower.starts_with("curl/") { return Some(("curl", false)); }
        if lower.starts_with("wget/") { return Some(("wget", false)); }
        if lower.starts_with("java/") || lower.contains("apache-httpclient") {
            return Some(("java-http", false));
        }
        if lower.starts_with("libwww-perl") || lower.starts_with("lwp-") {
            return Some(("libwww-perl", false));
        }
        if lower.starts_with("node-fetch") || lower.starts_with("axios") || lower.starts_with("undici") {
            return Some(("node-http", false));
        }
        if lower.starts_with("ruby") || lower.starts_with("faraday") {
            return Some(("ruby-http", false));
        }
        if lower.starts_with("php") || lower.contains("guzzle") {
            return Some(("php-http", false));
        }

        None
    }

    fn has_impossible_headers(&self, ctx: &RequestContext) -> bool {
        ctx.headers.contains_key(":method")
            || ctx.headers.contains_key(":path")
            || ctx.headers.contains_key(":authority")
            || ctx.headers.contains_key(":scheme")
    }

    fn has_malformed_headers(&self, ctx: &RequestContext) -> bool {
        if let Some(ref ua) = ctx.user_agent {
            if ua.len() > 1024 {
                return true;
            }
        }
        if let Some(referer) = ctx.headers.get("referer") {
            if referer.len() > 2048 {
                return true;
            }
        }
        if let Some(cookie) = ctx.headers.get("cookie") {
            if cookie.len() > 8192 {
                return true;
            }
        }
        if let Some(accept) = ctx.headers.get("accept") {
            if accept.len() > 1024 {
                return true;
            }
        }
        if ctx.headers.len() > 100 {
            return true;
        }
        false
    }
}

impl Default for HeaderAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
