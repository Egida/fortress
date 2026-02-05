use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::config::service::ServiceConfig;
use crate::config::settings::Settings;
use crate::models::request::RequestContext;
use crate::models::threat::{ThreatAction, ProtectionLevel, ThreatReason};
use crate::storage::blocklist::BlocklistManager;
use crate::storage::memory::MemoryStore;

use super::auto_ban::AutoBanManager;
use super::behavioral::BehavioralAnalyzer;
use super::challenge::ChallengeSystem;
use super::distributed::DistributedDetector;
use super::escalation::EscalationEngine;
use super::custom_rules::CustomRulesEngine;
use super::managed_rules::{ManagedRulesEngine, RuleAction};
use super::fingerprint::FingerprintAnalyzer;
use super::geoip::GeoIpLookup;
use super::header_analysis::HeaderAnalyzer;
use super::ip_reputation::IpReputationManager;
use super::mobile_proxy::MobileProxyDetector;
use super::asn::AsnClassifier;
use super::bot_whitelist::BotWhitelist;
use super::rate_limiter::RateLimiter;

/
/
pub struct ProtectionPipeline {
    pub rate_limiter: Arc<RateLimiter>,
    pub geoip: Arc<GeoIpLookup>,
    pub fingerprint: Arc<FingerprintAnalyzer>,
    pub challenge: Arc<ChallengeSystem>,
    pub behavioral: Arc<BehavioralAnalyzer>,
    pub mobile_proxy: Arc<MobileProxyDetector>,
    pub header_analysis: Arc<HeaderAnalyzer>,
    pub escalation: Arc<EscalationEngine>,
    pub blocklist: Arc<BlocklistManager>,
    pub memory: Arc<MemoryStore>,
    pub bot_whitelist: Arc<BotWhitelist>,
    pub asn_classifier: Arc<AsnClassifier>,
    pub ip_reputation: Arc<IpReputationManager>,
    pub auto_ban: Arc<AutoBanManager>,
    pub distributed: Arc<DistributedDetector>,
    pub managed_rules: Arc<ManagedRulesEngine>,
    pub custom_rules: Arc<CustomRulesEngine>,
}

/
pub struct PipelineResult {
    pub action: ThreatAction,
    pub reason: Option<ThreatReason>,
    pub score: f64,
    pub challenge_html: Option<String>,
}

impl PipelineResult {
    fn allow() -> Self {
        Self {
            action: ThreatAction::Pass,
            reason: None,
            score: 0.0,
            challenge_html: None,
        }
    }

    fn block(reason: ThreatReason, score: f64) -> Self {
        Self {
            action: ThreatAction::Block,
            reason: Some(reason),
            score,
            challenge_html: None,
        }
    }

    fn challenge(reason: ThreatReason, score: f64, html: String) -> Self {
        Self {
            action: ThreatAction::Challenge,
            reason: Some(reason),
            score,
            challenge_html: Some(html),
        }
    }
}

impl ProtectionPipeline {
    /
    ///
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    /
    pub fn process(&self, ctx: &mut RequestContext, settings: &Settings, service: Option<&ServiceConfig>) -> PipelineResult {
        let mut cumulative_score: f64 = 0.0;

        if Self::is_whitelisted(&ctx.client_ip, settings) {
            debug!(ip = %ctx.client_ip, "Whitelisted IP/subnet - bypassing pipeline");
            return PipelineResult::allow();
        }

        if self.blocklist.check_ip(&ctx.client_ip).is_some() {
            info!(ip = %ctx.client_ip, "Blocked by IP blocklist");
            return PipelineResult::block(ThreatReason::BlockedIp, 100.0);
        }

        if let Some(reason) = self.auto_ban.is_banned(&ctx.client_ip) {
            debug!(ip = %ctx.client_ip, reason = %reason, "Blocked by auto-ban");
            return PipelineResult::block(ThreatReason::AutoBanned, 100.0);
        }

        if let Some((action, reason_str)) = self.custom_rules.check(ctx) {
            match action {
                ThreatAction::Pass => {
                    debug!(ip = %ctx.client_ip, reason = %reason_str, "Custom rule: allowing");
                    return PipelineResult::allow();
                }
                ThreatAction::Block => {
                    info!(ip = %ctx.client_ip, reason = %reason_str, "Custom rule: blocking");
                    return PipelineResult::block(ThreatReason::CustomRule, 100.0);
                }
                ThreatAction::Challenge => {
                    cumulative_score += 80.0;
                    debug!(ip = %ctx.client_ip, reason = %reason_str, "Custom rule: challenge score added");
                }
                ThreatAction::Tarpit => {
                    info!(ip = %ctx.client_ip, reason = %reason_str, "Custom rule: tarpitting");
                    return PipelineResult {
                        action: ThreatAction::Tarpit,
                        reason: Some(ThreatReason::CustomRule),
                        score: 100.0,
                        challenge_html: None,
                    };
                }
            }
        }

        if let Some(rule_result) = self.managed_rules.check(ctx) {
            match rule_result.action {
                RuleAction::Block => {
                    info!(
                        ip = %ctx.client_ip,
                        rule = ?rule_result.matched_rule,
                        rule_id = rule_result.rule_id,
                        "Blocked by managed rule"
                    );
                    return PipelineResult::block(ThreatReason::ManagedRule, 100.0);
                }
                RuleAction::Challenge => {
                    cumulative_score += 80.0;
                    debug!(
                        ip = %ctx.client_ip,
                        rule = ?rule_result.matched_rule,
                        "Managed rule: challenge score added"
                    );
                }
                RuleAction::Score(s) => {
                    cumulative_score += s;
                    debug!(
                        ip = %ctx.client_ip,
                        rule = ?rule_result.matched_rule,
                        score = s,
                        "Managed rule: score added"
                    );
                }
            }
        }

        if ctx.country_code.is_none() {
            if let Some(country) = self.geoip.lookup_country(ctx.client_ip) {
                ctx.country_code = Some(country.clone());
            }
        }
        if let Some(ref country) = ctx.country_code {
            if let Some((action, _reason)) = self.blocklist.check_country(country) {
                match action {
                    crate::storage::blocklist::ThreatAction::Block => {
                        info!(ip = %ctx.client_ip, country = %country, "Blocked by country blocklist");
                        return PipelineResult::block(ThreatReason::BlockedCountry, 100.0);
                    }
                    crate::storage::blocklist::ThreatAction::Challenge => {
                        cumulative_score += settings.blocklist.country_challenge_score;
                        debug!(ip = %ctx.client_ip, country = %country,
                               score = settings.blocklist.country_challenge_score,
                               "Challenged country: adding score modifier");
                    }
                }
            }
        }

        if let Some((asn_number, asn_name)) = self.geoip.lookup_asn(ctx.client_ip) {
            ctx.asn = Some(asn_number);
            ctx.asn_name = Some(asn_name);

            if self.blocklist.check_asn(asn_number).is_some() {
                info!(ip = %ctx.client_ip, asn = asn_number, "Blocked by ASN blocklist");
                return PipelineResult::block(ThreatReason::BlockedAsn, 100.0);
            }
        }

        {
            let p = ctx.path.as_str();
            let is_static = p.starts_with("/_next/")
                || p.starts_with("/static/")
                || p.starts_with("/assets/")
                || p.starts_with("/providers/")
                || p.starts_with("/images/")
                || p.starts_with("/img/")
                || p.starts_with("/css/")
                || p.starts_with("/js/")
                || p.starts_with("/fonts/")
                || p.starts_with("/media/")
                || p.ends_with(".js")
                || p.ends_with(".css")
                || p.ends_with(".png")
                || p.ends_with(".jpg")
                || p.ends_with(".jpeg")
                || p.ends_with(".gif")
                || p.ends_with(".svg")
                || p.ends_with(".webp")
                || p.ends_with(".ico")
                || p.ends_with(".woff")
                || p.ends_with(".woff2")
                || p.ends_with(".ttf")
                || p.ends_with(".eot")
                || p.ends_with(".map");
            if is_static && (ctx.method == "GET" || ctx.method == "HEAD") {
                debug!(ip = %ctx.client_ip, path = %ctx.path, "Static asset - bypassing pipeline");
                return PipelineResult::allow();
            }
        }

        if let Some(bot_name) = self.bot_whitelist.check(
            ctx.user_agent.as_deref(),
            &ctx.client_ip,
        ) {
            debug!(ip = %ctx.client_ip, bot = %bot_name, "Whitelisted search engine bot - allowing");
            return PipelineResult::allow();
        }

        {
            let (rep_score, should_block) = self.ip_reputation.check(&ctx.client_ip);
            if should_block {
                info!(ip = %ctx.client_ip, score = rep_score, "Blocked by IP reputation");
                return PipelineResult::block(ThreatReason::BadReputation, rep_score);
            }
            if rep_score > 0.0 {
                cumulative_score += rep_score;
                debug!(ip = %ctx.client_ip, score = rep_score, "IP reputation score added");
            }
        }

        let protection_level = match service.and_then(|s| s.protection_level_override) {
            Some(0) => ProtectionLevel::L0,
            Some(1) => ProtectionLevel::L1,
            Some(2) => ProtectionLevel::L2,
            Some(3) => ProtectionLevel::L3,
            Some(4) => ProtectionLevel::L4,
            _ => self.escalation.current_level(),
        };
        let subnet = crate::storage::memory::ip_to_subnet(ctx.client_ip, settings.protection.ipv4_subnet_mask);
        let asn = ctx.asn.unwrap_or(0);
        let country = ctx.country_code.as_deref().unwrap_or("XX");

        self.memory.record_request(ctx.client_ip, subnet, asn, country);

        if let Some(reason) = self.rate_limiter.check(
            ctx.client_ip,
            subnet,
            asn,
            country,
            &protection_level,
            settings,
        ) {
            match protection_level {
                ProtectionLevel::L3 | ProtectionLevel::L4 => {
                    info!(ip = %ctx.client_ip, reason = ?reason, "Rate limit exceeded (emergency block)");
                    return PipelineResult::block(reason, 90.0);
                }
                _ => {
                    cumulative_score += 90.0;
                    info!(ip = %ctx.client_ip, reason = ?reason, "Rate limit exceeded (challenge mode)");
                }
            }
        }

        {
            let dist_result = self.distributed.check(
                ctx.client_ip,
                &ctx.path,
                ctx.user_agent.as_deref(),
            );
            if dist_result.score_modifier > 0.0 {
                cumulative_score += dist_result.score_modifier;
                debug!(
                    ip = %ctx.client_ip,
                    score = dist_result.score_modifier,
                    is_new = dist_result.is_new_ip,
                    "Distributed attack score added"
                );
            }
        }

        if let Some(asn_num) = ctx.asn {
            let asn_score = self.asn_classifier.suspicion_score(asn_num, &settings.asn_scoring);
            if asn_score > 0.0 {
                cumulative_score += asn_score;
                debug!(ip = %ctx.client_ip, asn = asn_num, score = asn_score, "ASN reputation score");
            }
        }

        if !ctx.is_behind_cloudflare {
            let (fp_score, fp_reason) = self.fingerprint.analyze(
                ctx.ja3_hash.as_deref(),
                ctx.user_agent.as_deref(),
            );
            cumulative_score += fp_score;

            if let Some(reason) = fp_reason {
                if fp_score >= 80.0 {
                    warn!(ip = %ctx.client_ip, score = fp_score, "Fingerprint analysis: high threat");
                    return PipelineResult::block(reason, cumulative_score);
                }
                debug!(ip = %ctx.client_ip, score = fp_score, reason = ?reason, "Fingerprint anomaly detected");
            }
        }

        let (header_score, header_reason) = self.header_analysis.analyze(ctx);
        cumulative_score += header_score;

        if let Some(reason) = header_reason {
            if header_score >= 80.0 {
                warn!(ip = %ctx.client_ip, score = header_score, "Header analysis: high threat");
                return PipelineResult::block(reason, cumulative_score);
            }
            debug!(ip = %ctx.client_ip, score = header_score, reason = ?reason, "Header anomaly detected");
        }

        let (mobile_score, is_mobile_proxy) = self.mobile_proxy.detect(ctx);
        cumulative_score += mobile_score;

        if is_mobile_proxy {
            debug!(ip = %ctx.client_ip, score = mobile_score, "Mobile proxy detected");
            if mobile_score >= 70.0 {
                return PipelineResult::block(ThreatReason::MobileProxy, cumulative_score);
            }
        }

        let behavioral_score = self.behavioral.analyze(ctx);
        cumulative_score += behavioral_score * 0.5;

        debug!(
            ip = %ctx.client_ip,
            behavioral_score = behavioral_score,
            cumulative_score = cumulative_score,
            "Behavioral analysis complete"
        );

        let force_challenge = service.map(|s| s.always_challenge).unwrap_or(false);
        if force_challenge || self.challenge.should_challenge(ctx, &protection_level, cumulative_score) {
            if self.challenge.is_exempt_path(&ctx.path) {
                debug!(ip = %ctx.client_ip, path = %ctx.path, "Path exempt from challenge");
            } else {
                let cookies = ctx.headers.get("cookie").map(|s| s.as_str());
                if self.challenge.has_valid_clearance(&ctx.client_ip, cookies) {
                    debug!(ip = %ctx.client_ip, "Valid clearance cookie found, allowing");
                    return PipelineResult {
                        action: ThreatAction::Pass,
                        reason: None,
                        score: cumulative_score,
                        challenge_html: None,
                    };
                }

                info!(
                    ip = %ctx.client_ip,
                    score = cumulative_score,
                    level = ?protection_level,
                    "Issuing challenge"
                );
                let html = self.challenge.generate_challenge_page(&protection_level);
                return PipelineResult::challenge(
                    ThreatReason::ChallengeRequired,
                    cumulative_score,
                    html,
                );
            }
        }

        PipelineResult {
            action: ThreatAction::Pass,
            reason: None,
            score: cumulative_score,
            challenge_html: None,
        }
    }

    /
    fn is_whitelisted(ip: &IpAddr, settings: &Settings) -> bool {
        let ip_str = ip.to_string();

        for whitelisted in &settings.protection.whitelisted_ips {
            if ip_str == *whitelisted {
                return true;
            }
        }

        if let IpAddr::V4(v4) = ip {
            let octets = v4.octets();
            for subnet_str in &settings.protection.whitelisted_subnets {
                if let Some(prefix) = subnet_str.strip_suffix("/24") {
                    let parts: Vec<&str> = prefix.split('.').collect();
                    if parts.len() >= 3 {
                        let subnet_prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
                        let ip_prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
                        if subnet_prefix == ip_prefix {
                            return true;
                        }
                    }
                } else if let Some(prefix) = subnet_str.strip_suffix("/16") {
                    let parts: Vec<&str> = prefix.split('.').collect();
                    if parts.len() >= 2 {
                        let subnet_prefix = format!("{}.{}", parts[0], parts[1]);
                        let ip_prefix = format!("{}.{}", octets[0], octets[1]);
                        if subnet_prefix == ip_prefix {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}
