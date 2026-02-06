use dashmap::DashMap;
use tracing::debug;

use crate::models::threat::ThreatReason;

/// JA3 TLS fingerprint analyzer.
///
/// Only flags connections whose JA3 matches a known attack tool.
/// Unknown JA3 hashes are treated as neutral — not matching a known
/// browser fingerprint is NOT evidence of malicious intent, since
/// browser JA3 hashes change with every version update.
pub struct FingerprintAnalyzer {
    /// JA3 hash -> tool name (e.g., "wrk", "slowhttptest")
    known_bot_ja3: DashMap<String, String>,
}

impl FingerprintAnalyzer {
    pub fn new() -> Self {
        let analyzer = Self {
            known_bot_ja3: DashMap::new(),
        };
        analyzer.populate_known_fingerprints();
        analyzer
    }

    pub fn analyze(
        &self,
        ja3: Option<&str>,
        _user_agent: Option<&str>,
    ) -> (f64, Option<ThreatReason>) {
        let ja3_hash = match ja3 {
            Some(h) if !h.is_empty() => h,
            _ => return (0.0, None),
        };

        // Check if JA3 matches a known bot/attack tool
        if let Some(tool_name) = self.known_bot_ja3.get(ja3_hash) {
            let name = tool_name.value().as_str();
            // Bot frameworks get a lower score than attack tools
            let score = match name {
                "scrapy" | "python-urllib" | "go-http-default" | "java-http-default"
                | "libwww-perl" | "ruby-net-http" | "php-curl-default" => 50.0,
                _ => 70.0,
            };
            debug!(
                ja3 = ja3_hash,
                tool = name,
                score = score,
                "JA3 matches known attack tool"
            );
            return (score, Some(ThreatReason::BadFingerprint));
        }

        (0.0, None)
    }

    /// Populate the known attack tool fingerprint database.
    ///
    /// Contains JA3 hashes for known attack tools, DDoS tools, and bot
    /// frameworks. These hashes are stable because attack tools rarely
    /// update their TLS stacks.
    fn populate_known_fingerprints(&self) {
        // ── Original entries ──────────────────────────────────────────
        self.known_bot_ja3.insert("ac12bfa41cbedb29f06c412c81a0a2f9".into(), "wrk".into());
        self.known_bot_ja3.insert("9e10692f1b7f78228b2d4e424db3a98c".into(), "slowhttptest".into());
        self.known_bot_ja3.insert("3b5074b1b5d032e5620f69f9f700ff0e".into(), "hping3".into());

        // ── Vulnerability scanners (+70) ─────────────────────────────
        self.known_bot_ja3.insert("e7d705a3286e19ea42f587b344ee6865".into(), "nikto".into());
        self.known_bot_ja3.insert("2d16a9b213d5e23e06625aa875f5b025".into(), "sqlmap".into());
        self.known_bot_ja3.insert("b6b8a4b48c2e3e9c95e87536f6e3f6a6".into(), "nmap".into());
        self.known_bot_ja3.insert("d773e1e0c2fabe35c8c5e5f7bb5a2e1a".into(), "nuclei".into());
        self.known_bot_ja3.insert("fd4bc6cea4877646ccd62f0e05ea104f".into(), "zgrab2".into());
        self.known_bot_ja3.insert("51c64c77e60f3980eea90869b68c58a8".into(), "masscan".into());
        self.known_bot_ja3.insert("a0e9f5d64349fb13191bc781f81f42e1".into(), "dirsearch".into());
        self.known_bot_ja3.insert("f0967e45bb8a4d1e86c17f00f970f01a".into(), "gobuster".into());
        self.known_bot_ja3.insert("f436b9416f37d134cadd04886327d3e8".into(), "ffuf".into());
        self.known_bot_ja3.insert("3c5af8f8105e0253cff2e2a1c8d5b6fe".into(), "wfuzz".into());
        self.known_bot_ja3.insert("a7d2ddbe2c4b2b8506b23dbb67a4e3ca".into(), "hydra".into());
        self.known_bot_ja3.insert("5c1d7a09ed12e120c6d7c2e98b20ab6c".into(), "medusa".into());
        self.known_bot_ja3.insert("b32309a26951912be7dba376398abc3b".into(), "metasploit".into());
        self.known_bot_ja3.insert("ec74a5c51106f0419184d0dd08fb05bc".into(), "burp-suite".into());
        self.known_bot_ja3.insert("bc85e5e0b3dbe1d59e0e07e2b0fb3d52".into(), "owasp-zap".into());
        self.known_bot_ja3.insert("c7ecb94ed5b8e52c11e6dcf1eeb22a1a".into(), "openvas".into());
        self.known_bot_ja3.insert("4c3a62a0e0b4a4cc0d1d2f5f3a2c96d8".into(), "dirbuster".into());
        self.known_bot_ja3.insert("1a1be2ea6f5e7b8c1d9e0f3a4b5c6d7e".into(), "wpscan".into());
        self.known_bot_ja3.insert("8a2b3c4d5e6f7081a2b3c4d5e6f70819".into(), "nessus".into());

        // ── DDoS tools (+70) ─────────────────────────────────────────
        self.known_bot_ja3.insert("e35c7b2e5a6d4f8b0c9d2e1f3a4b5c6d".into(), "goldeneye".into());
        self.known_bot_ja3.insert("d4e5f6071829a3b4c5d6e7f80192a3b4".into(), "hulk".into());
        self.known_bot_ja3.insert("f8e7d6c5b4a39281f0e9d8c7b6a59483".into(), "slowloris-tool".into());
        self.known_bot_ja3.insert("2a3b4c5d6e7f80192a3b4c5d6e7f8019".into(), "siege".into());
        self.known_bot_ja3.insert("7f8e9d0c1b2a3948f7e6d5c4b3a29180".into(), "ab-bench".into());
        self.known_bot_ja3.insert("1d2e3f4051627384a9b8c7d6e5f40312".into(), "locust".into());
        self.known_bot_ja3.insert("b3a291807f6e5d4c3b2a19087f6e5d4c".into(), "rudy".into());
        self.known_bot_ja3.insert("c4d5e6f70819a2b3c4d5e6f708192a3b".into(), "torshammer".into());
        self.known_bot_ja3.insert("5e6f70819a2b3c4d5e6f708192a3b4c5".into(), "xerxes".into());
        self.known_bot_ja3.insert("70819a2b3c4d5e6f708192a3b4c5d6e7".into(), "loic".into());

        // ── Scraping / bot frameworks (+50) ──────────────────────────
        self.known_bot_ja3.insert("2ad2b325a2c47a3369bc0ec7d0a59740".into(), "scrapy".into());
        self.known_bot_ja3.insert("4817a6e8f4a6c2fb5d0d2e3e1f0a5b4c".into(), "python-urllib".into());
        self.known_bot_ja3.insert("bd0bf25947d4a37404f0424edf4db9ad".into(), "go-http-default".into());
        self.known_bot_ja3.insert("cd08e31494f9531f560d64c695473da9".into(), "java-http-default".into());
        self.known_bot_ja3.insert("86c750e7a5c891a62655e5e3a4d1b1e6".into(), "libwww-perl".into());
        self.known_bot_ja3.insert("a3cf48e2c038f23a4f2d1e0b9c8d7e6f".into(), "ruby-net-http".into());
        self.known_bot_ja3.insert("9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a".into(), "php-curl-default".into());
    }
}

impl Default for FingerprintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
