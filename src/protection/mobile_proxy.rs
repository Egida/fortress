use std::sync::Arc;
use tracing::debug;

use crate::models::request::RequestContext;

use crate::config::settings::MobileProxyConfig;
use super::asn::{AsnClassifier, AsnType};

/// Mobile proxy detection heuristics.
///
/// Mobile proxies route traffic through real mobile carrier IP addresses,
/// making them appear as legitimate mobile users. This detector uses
/// multiple heuristics to identify inconsistencies that reveal proxy usage.
pub struct MobileProxyDetector {
    asn_classifier: Arc<AsnClassifier>,
    min_signals: u32,
    score_threshold: f64,
}

impl MobileProxyDetector {
    pub fn new(asn_classifier: Arc<AsnClassifier>, config: &MobileProxyConfig) -> Self {
        Self {
            asn_classifier,
            min_signals: config.min_signals,
            score_threshold: config.score_threshold,
        }
    }

    /// Detect if a request is likely coming through a mobile proxy.
    ///
    /// Returns (score, is_mobile_proxy):
    /// - score: 0-100 threat contribution
    /// - is_mobile_proxy: true if heuristics strongly indicate a mobile proxy
    pub fn detect(&self, ctx: &RequestContext) -> (f64, bool) {
        let mut total_score: f64 = 0.0;
        let mut signals: u32 = 0;

        // Heuristic 1: UA claims mobile but JA3 doesn't match mobile browsers
        let ua_is_mobile = self.ua_claims_mobile(ctx);
        let ja3_is_mobile = self.ja3_matches_mobile(ctx);

        if ua_is_mobile && !ja3_is_mobile && ctx.ja3_hash.is_some() {
            debug!(ip = %ctx.client_ip, "Mobile UA but non-mobile JA3 fingerprint");
            total_score += 30.0;
            signals += 1;
        }

        // Heuristic 2: Known residential proxy ASN
        if let Some(asn) = ctx.asn {
            let asn_type = self.asn_classifier.classify(asn);
            if asn_type == AsnType::ResidentialProxy {
                debug!(ip = %ctx.client_ip, asn = asn, "Residential proxy ASN detected");
                total_score += 40.0;
                signals += 1;
            }
        }

        // Heuristic 3: IP from mobile carrier but headers inconsistent
        if let Some(asn) = ctx.asn {
            let asn_type = self.asn_classifier.classify(asn);
            if asn_type == AsnType::MobileCarrier {
                if !ua_is_mobile {
                    debug!(
                        ip = %ctx.client_ip,
                        "Mobile carrier ASN but non-mobile User-Agent"
                    );
                    total_score += 10.0;
                    signals += 1;
                }

                // Mobile browsers typically send smaller Accept headers
                if let Some(accept) = ctx.headers.get("accept") {
                    if accept.len() > 200 {
                        debug!(
                            ip = %ctx.client_ip,
                            "Mobile carrier ASN but desktop-style Accept header"
                        );
                        total_score += 5.0;
                        signals += 1;
                    }
                }
            }
        }

        // Heuristic 4: Accept-Language doesn't match IP's country
        if let (Some(accept_lang), Some(ref country)) =
            (ctx.headers.get("accept-language"), &ctx.country_code)
        {
            if !self.language_matches_country(accept_lang, country) {
                debug!(
                    ip = %ctx.client_ip,
                    country = country.as_str(),
                    lang = accept_lang.as_str(),
                    "Accept-Language doesn't match IP country"
                );
                total_score += 15.0;
                signals += 1;
            }
        }

        // Heuristic 5: Missing mobile-specific headers (Sec-CH-UA-Mobile)
        if ua_is_mobile && !ctx.headers.contains_key("sec-ch-ua-mobile") {
            debug!(
                ip = %ctx.client_ip,
                "Mobile UA but missing Sec-CH-UA-Mobile header"
            );
            total_score += 5.0;
            signals += 1;
        }

        let is_mobile_proxy = signals >= self.min_signals || total_score >= self.score_threshold;
        let normalized_score = total_score.min(100.0);

        debug!(
            ip = %ctx.client_ip,
            score = normalized_score,
            signals = signals,
            is_mobile_proxy = is_mobile_proxy,
            "Mobile proxy detection complete"
        );

        (normalized_score, is_mobile_proxy)
    }

    /// Check if the User-Agent claims to be a mobile browser.
    fn ua_claims_mobile(&self, ctx: &RequestContext) -> bool {
        ctx.user_agent
            .as_ref()
            .map(|ua| {
                let lower = ua.to_lowercase();
                lower.contains("mobile")
                    || lower.contains("android")
                    || lower.contains("iphone")
                    || lower.contains("ipad")
                    || lower.contains("ipod")
                    || lower.contains("windows phone")
                    || lower.contains("opera mini")
                    || lower.contains("opera mobi")
            })
            .unwrap_or(false)
    }

    /// Check if the JA3 hash matches known mobile browser fingerprints.
    fn ja3_matches_mobile(&self, ctx: &RequestContext) -> bool {
        let ja3 = match &ctx.ja3_hash {
            Some(h) => h.as_str(),
            None => return false,
        };

        // Known mobile browser JA3 hashes
        let mobile_ja3_hashes: &[&str] = &[
            "e7d705a3286e19ea42f587b344ee6865", // Chrome Android
            "e92afb86ef1929e3e2d25d0c72539c49", // Safari iOS
            "b6e1f1a282c8e6b3b9e1d7c5f8a4e2d1", // Firefox Android
            "d3a4e8c1f2b5a6d7e9c0f3b8a1e4d7c2", // Samsung Internet
        ];

        mobile_ja3_hashes.contains(&ja3)
    }

    /// Check if the Accept-Language header is consistent with the IP's country.
    fn language_matches_country(&self, accept_lang: &str, country: &str) -> bool {
        let primary_lang = accept_lang
            .split(',')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();

        if primary_lang.is_empty() {
            return true;
        }

        let lang_prefix = if primary_lang.len() >= 2 {
            &primary_lang[..2]
        } else {
            &primary_lang
        };

        let expected = match country.to_uppercase().as_str() {
            "US" | "GB" | "AU" | "CA" | "NZ" | "IE" => &["en"][..],
            "TR" => &["tr"],
            "DE" | "AT" | "CH" => &["de", "en"],
            "FR" | "BE" => &["fr", "en"],
            "ES" | "MX" | "AR" | "CO" | "CL" => &["es", "en"],
            "PT" | "BR" => &["pt", "en"],
            "IT" => &["it", "en"],
            "NL" => &["nl", "en"],
            "RU" | "BY" => &["ru"],
            "UA" => &["uk", "ru"],
            "CN" => &["zh"],
            "JP" => &["ja"],
            "KR" => &["ko"],
            "IN" => &["hi", "en", "ta", "te", "bn"],
            _ => return true,
        };

        expected.iter().any(|e| lang_prefix.starts_with(e))
    }
}
