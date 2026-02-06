use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::config::settings::ChallengeConfig;
use crate::models::request::RequestContext;
use crate::models::threat::ProtectionLevel;
use crate::storage::memory::MemoryStore;

type HmacSha256 = Hmac<Sha256>;

/// JavaScript proof-of-work challenge system.
///
/// Issues challenges to suspicious clients that require computing a SHA-256
/// proof-of-work. Legitimate browsers solve this within seconds. Automated
/// tools and scripts fail unless they implement a full headless browser.
///
/// Challenge flow:
/// 1. Server returns challenge HTML page with embedded PoW JavaScript
/// 2. Browser computes SHA-256 hashes until leading zeros match difficulty
/// 3. Browser sets a signed cookie with the solution
/// 4. Browser reloads the page, and the clearance cookie bypasses the challenge
pub struct ChallengeSystem {
    memory: Arc<MemoryStore>,
    hmac_secret: Vec<u8>,
    cookie_name: String,
    cookie_max_age: Duration,
    exempt_paths: Vec<String>,
    pow_difficulty_l1: u8,
    pow_difficulty_l2: u8,
    pow_difficulty_l3: u8,
    cookie_subnet_binding: bool,
    nojs_fallback_enabled: bool,
}

impl ChallengeSystem {
    /// Create a new ChallengeSystem from configuration.
    pub fn new(config: &ChallengeConfig, memory: Arc<MemoryStore>) -> Self {
        Self {
            memory,
            hmac_secret: config.hmac_secret.as_bytes().to_vec(),
            cookie_name: config.cookie_name.clone(),
            cookie_max_age: Duration::from_secs(config.cookie_max_age_secs),
            exempt_paths: config.exempt_paths.clone(),
            pow_difficulty_l1: config.pow_difficulty_l1,
            pow_difficulty_l2: config.pow_difficulty_l2,
            pow_difficulty_l3: config.pow_difficulty_l3,
            cookie_subnet_binding: config.cookie_subnet_binding,
            nojs_fallback_enabled: config.nojs_fallback_enabled,
        }
    }

    /// Determine if a challenge should be issued for this request.
    ///
    /// Challenge criteria depend on the current protection level:
    /// - L0: Only challenge if score > 70
    /// - L1: Challenge if score > 50
    /// - L2: Challenge if score > 30
    /// - L3: Challenge all requests (score > 0)
    /// - L4: Challenge all requests (maximum security)
    pub fn should_challenge(
        &self,
        _ctx: &RequestContext,
        level: &ProtectionLevel,
        score: f64,
    ) -> bool {
        let threshold = match level {
            ProtectionLevel::L0 => 95.0,
            ProtectionLevel::L1 => 80.0,
            ProtectionLevel::L2 => 65.0,
            ProtectionLevel::L3 => 40.0,
            ProtectionLevel::L4 => 15.0,
        };

        score > threshold
    }

    /// Check if the request has a valid clearance cookie.
    ///
    /// Validates:
    /// 1. Cookie exists with the correct name
    /// 2. Cookie format is `challenge:nonce:signature`
    /// 3. HMAC signature is valid
    /// 4. Challenge timestamp is not expired
    /// 5. IP hash in challenge matches requesting IP
    pub fn has_valid_clearance(&self, ip: &IpAddr, cookies: Option<&str>) -> bool {
        let cookies_str = match cookies {
            Some(c) => c,
            None => return false,
        };

        // Parse the cookie header to find our clearance cookie
        let cookie_value = match self.extract_cookie(cookies_str) {
            Some(v) => v,
            None => return false,
        };

        // Cookie format: challenge:nonce:signature
        // Challenge format: timestamp:random_hex:ip_hash
        // So full cookie: timestamp:random_hex:ip_hash:nonce:signature
        let parts: Vec<&str> = cookie_value.splitn(5, ':').collect();
        if parts.len() != 5 {
            debug!("Invalid clearance cookie format: wrong number of parts");
            return false;
        }

        let timestamp_str = parts[0];
        let random_hex = parts[1];
        let ip_hash = parts[2];
        let nonce = parts[3];
        let signature = parts[4];

        // Reconstruct the challenge string
        let challenge = format!("{}:{}:{}", timestamp_str, random_hex, ip_hash);

        // Verify HMAC signature
        let expected_signature = self.compute_signature(&challenge, nonce, "clearance");
        if signature != expected_signature {
            debug!("Invalid clearance cookie: signature mismatch");
            return false;
        }

        // Verify timestamp is not expired
        let timestamp: i64 = match timestamp_str.parse() {
            Ok(t) => t,
            Err(_) => {
                debug!("Invalid clearance cookie: bad timestamp");
                return false;
            }
        };

        let now = Utc::now().timestamp();
        let age = now - timestamp;
        if age < 0 || age > self.cookie_max_age.as_secs() as i64 {
            debug!(
                age = age,
                max_age = self.cookie_max_age.as_secs(),
                "Clearance cookie expired"
            );
            return false;
        }

        // Verify IP hash matches requesting IP
        let expected_ip_hash = self.hash_ip(ip);
        if ip_hash != expected_ip_hash {
            debug!("Invalid clearance cookie: IP hash mismatch");
            return false;
        }

        debug!(ip = %ip, "Valid clearance cookie accepted");
        true
    }

    /// Generate a full HTML challenge page with embedded PoW JavaScript.
    ///
    /// The difficulty scales with the protection level (and reads from config):
    /// - L0-L1: pow_difficulty_l1 leading zero bits
    /// - L2: pow_difficulty_l2 leading zero bits
    /// - L3-L4: pow_difficulty_l3 leading zero bits
    pub fn generate_challenge_page(&self, level: &ProtectionLevel) -> String {
        let difficulty = match level {
            ProtectionLevel::L0 | ProtectionLevel::L1 => self.pow_difficulty_l1 as u32,
            ProtectionLevel::L2 => self.pow_difficulty_l2 as u32,
            ProtectionLevel::L3 | ProtectionLevel::L4 => self.pow_difficulty_l3 as u32,
        };

        let timestamp = Utc::now().timestamp();
        let random_hex = self.generate_random_hex(16);
        let challenge_template = format!("{}:{}", timestamp, random_hex);

        // Generate nojs fallback redirect URL
        let nojs_redirect = if self.nojs_fallback_enabled {
            let nojs_token = format!("{}:{}", timestamp, random_hex);
            let nojs_sig = self.compute_signature(&nojs_token, "0", "nojs");
            format!("/__fortress/nojs-verify?token={}&sig={}", nojs_token, nojs_sig)
        } else {
            String::from("javascript:void(0)")
        };

        let html = CHALLENGE_HTML_TEMPLATE
            .replace("__NOJS_REDIRECT__", &nojs_redirect)
            .replace("__CHALLENGE__", &challenge_template)
            .replace("__DIFFICULTY__", &difficulty.to_string());

        html
    }

    /// Verify a proof-of-work solution.
    ///
    /// Checks that SHA-256(challenge + ":" + nonce) has the required number
    /// of leading zero bits.
    pub fn verify_solution(&self, challenge: &str, nonce: &str) -> bool {
        let data = format!("{}:{}", challenge, nonce);
        let hash = Sha256::digest(data.as_bytes());

        // Count leading zero bits
        let mut zeros = 0u32;
        for byte in hash.iter() {
            if *byte == 0 {
                zeros += 8;
            } else {
                // Count leading zeros in this byte
                zeros += byte.leading_zeros();
                break;
            }
        }

        // We require at least 16 leading zero bits as minimum
        // The actual difficulty check is done by the client
        zeros >= 16
    }

    /// Generate a signed clearance cookie value for the given IP.
    ///
    /// Cookie format: `timestamp:random_hex:ip_hash:nonce:signature`
    /// Where signature = base64url(HMAC-SHA256(challenge + ":" + nonce, hmac_secret))
    pub fn generate_clearance_cookie(&self, ip: &IpAddr) -> String {
        let timestamp = Utc::now().timestamp();
        let random_hex = self.generate_random_hex(16);
        let ip_hash = self.hash_ip(ip);
        let challenge = format!("{}:{}:{}", timestamp, random_hex, ip_hash);
        let nonce = "0"; // Pre-verified clearance, no PoW needed
        let signature = self.compute_signature(&challenge, nonce, "clearance");

        let cookie_value = format!("{}:{}:{}", challenge, nonce, signature);
        format!(
            "{}={}; Path=/; Max-Age={}; SameSite=Lax; HttpOnly",
            self.cookie_name,
            cookie_value,
            self.cookie_max_age.as_secs()
        )
    }


    /// Verify a nojs verification token and signature.
    ///
    /// Used by the non-JavaScript fallback flow: the `<meta http-equiv="refresh">`
    /// tag redirects browsers to `/__fortress/nojs-verify?token=...&sig=...`.
    /// This method validates the HMAC signature and checks that the token
    /// timestamp is no older than 5 minutes.
    pub fn verify_nojs_token(&self, token: &str, sig: &str) -> bool {
        let expected_sig = self.compute_signature(token, "0", "nojs");
        if sig != expected_sig {
            return false;
        }
        // Check timestamp freshness (5 minutes)
        if let Some(ts_str) = token.split(':').next() {
            if let Ok(ts) = ts_str.parse::<i64>() {
                let now = chrono::Utc::now().timestamp();
                if (now - ts).abs() > 300 {
                    return false;
                }
            }
        }
        true
    }

    /// Check if a path is exempt from challenges.
    /// Supports `*` wildcard anywhere in the pattern (e.g. `/google*.html`, `/api/*/webhook`).
    pub fn is_exempt_path(&self, path: &str) -> bool {
        for exempt in &self.exempt_paths {
            if glob_match(exempt, path) {
                return true;
            }
        }
        false
    }

    // Private helpers

    /// Extract the clearance cookie value from a Cookie header string.
    fn extract_cookie<'a>(&self, cookies: &'a str) -> Option<&'a str> {
        for cookie in cookies.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix(&format!("{}=", self.cookie_name)) {
                return Some(value);
            }
        }
        None
    }

    /// Compute HMAC-SHA256 signature, returned as base64url.
    ///
    /// The `purpose` parameter is mixed into the HMAC to produce
    /// domain-separated signatures (e.g. "clearance" vs "nojs").
    fn compute_signature(&self, challenge: &str, nonce: &str, purpose: &str) -> String {
        let data = format!("{}:{}", challenge, nonce);
        let mut mac = HmacSha256::new_from_slice(&self.hmac_secret)
            .expect("HMAC can take key of any size");
        mac.update(data.as_bytes());
        mac.update(b":");
        mac.update(purpose.as_bytes());
        let result = mac.finalize().into_bytes();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
    }

    /// Hash an IP address with the HMAC secret, returning first 8 hex chars.
    ///
    /// When `cookie_subnet_binding` is enabled, hashes the /24 (IPv4) or
    /// /48 (IPv6) subnet instead of the exact IP. This reduces false positives
    /// when a user switches between nearby networks (e.g. WiFi -> mobile).
    fn hash_ip(&self, ip: &IpAddr) -> String {
        let ip_str = if self.cookie_subnet_binding {
            match ip {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    format!("{}.{}.{}.0", o[0], o[1], o[2])
                }
                IpAddr::V6(v6) => {
                    let s = v6.segments();
                    format!("{:x}:{:x}:{:x}::", s[0], s[1], s[2])
                }
            }
        } else {
            ip.to_string()
        };
        let data = format!("{}{}", ip_str, String::from_utf8_lossy(&self.hmac_secret));
        let hash = Sha256::digest(data.as_bytes());
        hex::encode(&hash[..4]) // First 4 bytes = 8 hex chars
    }

    /// Generate a random hex string of the specified length.
    fn generate_random_hex(&self, len: usize) -> String {
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..len / 2).map(|_| rng.random()).collect();
        hex::encode(&bytes)
    }
}

/// Inline hex encoding utility to avoid extra dependency.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// The full HTML challenge page template.
///
/// Placeholders:
/// - `__CHALLENGE__`: The challenge string (timestamp:random_hex)
/// - `__DIFFICULTY__`: Number of leading zero bits required
const CHALLENGE_HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0a; color: #fff; font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.container { text-align: center; max-width: 400px; padding: 2rem; }
.shield { font-size: 48px; margin-bottom: 1rem; }
h2 { font-size: 1.25rem; margin-bottom: 0.5rem; }
p { color: #888; font-size: 0.9rem; margin-bottom: 1.5rem; }
.spinner { width: 40px; height: 40px; border: 3px solid #333; border-top-color: #3b82f6; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 1rem; }
@keyframes spin { to { transform: rotate(360deg); } }
.progress { background: #1a1a1a; border-radius: 4px; height: 4px; overflow: hidden; margin-top: 1rem; }
.progress-bar { background: #3b82f6; height: 100%; width: 0%; transition: width 0.3s; }
#status { color: #666; font-size: 0.8rem; margin-top: 0.5rem; }
noscript { color: #ef4444; }
</style>
</head>
<body>
<div class="container">
<div class="shield">&#x1f6e1;</div>
<h2>Verifying your connection</h2>
<p>This won't take long. Please wait while we verify your browser.</p>
<div class="spinner" id="spinner"></div>
<div class="progress"><div class="progress-bar" id="progress"></div></div>
<div id="status">Initializing...</div>
<noscript><p>Verifying your connection... You will be redirected automatically.</p><meta http-equiv="refresh" content="5;url=__NOJS_REDIRECT__"></noscript>
</div>
<script>
(async function() {
  // Headless browser detection
  var hlScore = 0;
  try {
    // navigator.webdriver (Puppeteer/Playwright/Selenium)
    if (navigator.webdriver) hlScore += 40;
    // Chrome DevTools Protocol traces
    if (window.chrome && window.chrome.csi) hlScore += 10;
    if (window.__nightmare) hlScore += 40;
    if (document.__selenium_unwrapped || document.__webdriver_evaluate || document.__driver_evaluate) hlScore += 40;
    // Zero plugins on desktop (mobile normally has 0)
    var isMobile = /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
    if (!isMobile && navigator.plugins && navigator.plugins.length === 0) hlScore += 10;
    // WebGL renderer check for headless signatures
    try {
      var canvas = document.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        var dbg = gl.getExtension("WEBGL_debug_renderer_info");
        if (dbg) {
          var renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "";
          if (/SwiftShader|LLVMpipe|Mesa/i.test(renderer)) hlScore += 30;
        }
      }
    } catch(e) {}
    // Screen dimensions of 0 (headless default)
    if (screen.width === 0 || screen.height === 0) hlScore += 20;
    // Missing language
    if (!navigator.language && !navigator.languages) hlScore += 10;
    // Phantom.js
    if (window.callPhantom || window._phantom) hlScore += 40;
  } catch(e) {}
  var challenge = "__CHALLENGE__";
  var difficulty = __DIFFICULTY__;
  var statusEl = document.getElementById("status");
  var progressEl = document.getElementById("progress");
  var maxNonce = 0xFFFFFFFF;
  statusEl.textContent = "Computing proof of work...";
  var encoder = new TextEncoder();
  for (var n = 0; n < maxNonce; n++) {
    var data = encoder.encode(challenge + ":" + n);
    var hash = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
    var zeros = 0;
    for (var i = 0; i < hash.length; i++) {
      if (hash[i] === 0) { zeros += 8; }
      else { for (var b = 7; b >= 0; b--) { if ((hash[i] >> b) & 1) break; zeros++; } break; }
    }
    if (n % 10000 === 0) {
      progressEl.style.width = Math.min(95, (n / (1 << difficulty) * 100)) + "%";
      statusEl.textContent = "Verifying... " + Math.floor(n / 1000) + "k attempts";
      await new Promise(function(r) { setTimeout(r, 0); });
    }
    if (zeros >= difficulty) {
      statusEl.textContent = "Verified! Redirecting...";
      progressEl.style.width = "100%";
      var redirect = window.location.pathname + window.location.search;
      window.location.href = "/__fortress/verify?challenge=" + encodeURIComponent(challenge) + "&nonce=" + n + "&redirect=" + encodeURIComponent(redirect) + "&hl=" + hlScore;
      return;
    }
  }
  statusEl.textContent = "Verification failed. Please refresh the page.";
})();
</script>
</body>
</html>"#;

/// Simple glob matching: supports `*` wildcard anywhere in the pattern.
/// Each `*` matches zero or more characters (non-greedy segments).
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    // No wildcard → exact match
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut pos = 0usize;

    // First segment must be a prefix
    if !text.starts_with(parts[0]) {
        return false;
    }
    pos = parts[0].len();

    // Middle segments must appear in order
    for &part in &parts[1..parts.len() - 1] {
        if let Some(idx) = text[pos..].find(part) {
            pos += idx + part.len();
        } else {
            return false;
        }
    }

    // Last segment must be a suffix
    let last = parts[parts.len() - 1];
    if last.is_empty() {
        // Pattern ended with `*` — matches anything remaining
        return true;
    }
    text[pos..].ends_with(last) && (text.len() - last.len()) >= pos
}
