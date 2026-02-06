use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ThreatAction
// ---------------------------------------------------------------------------

/// The action to take against a request after threat evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatAction {
    /// Allow the request through to the upstream.
    Pass,
    /// Serve a proof-of-work / JS challenge page.
    Challenge,
    /// Immediately reject the request (403).
    Block,
    /// Accept the connection but respond extremely slowly.
    Tarpit,
}

impl fmt::Display for ThreatAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatAction::Pass => write!(f, "pass"),
            ThreatAction::Challenge => write!(f, "challenge"),
            ThreatAction::Block => write!(f, "block"),
            ThreatAction::Tarpit => write!(f, "tarpit"),
        }
    }
}

impl ThreatAction {
    /// Convert from a string representation.
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pass" => Some(Self::Pass),
            "challenge" => Some(Self::Challenge),
            "block" => Some(Self::Block),
            "tarpit" => Some(Self::Tarpit),
            _ => None,
        }
    }

    /// Whether this action prevents the request from reaching the upstream.
    pub fn is_blocking(&self) -> bool {
        matches!(self, ThreatAction::Block | ThreatAction::Tarpit)
    }
}

// ---------------------------------------------------------------------------
// ThreatReason
// ---------------------------------------------------------------------------

/// The reason a particular threat action was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatReason {
    /// Per-IP, per-subnet, per-ASN, or per-country rate limit exceeded.
    RateLimit,
    /// JA3 or TLS fingerprint matches a known bad actor profile.
    BadFingerprint,
    /// Behavioral analysis flagged the client as suspicious.
    SuspiciousBehavior,
    /// Traffic originates from a known mobile/residential proxy network.
    MobileProxy,
    /// Client IP is in a blocked country.
    BlockedCountry,
    /// Client IP belongs to a blocked ASN.
    BlockedAsn,
    /// Client IP is explicitly blocklisted.
    BlockedIp,
    /// Request headers exhibit anomalies (missing, contradictory, etc.).
    HeaderAnomaly,
    /// Slow-read / slow-POST attack pattern detected.
    Slowloris,
    /// Manually added to the blocklist via the admin API.
    ManualBlock,
    /// Client must complete a challenge before proceeding.
    ChallengeRequired,
    /// IP has bad reputation from past behavior.
    BadReputation,
    /// IP is automatically banned due to repeated offenses.
    AutoBanned,
    /// Request matched a managed security rule.
    ManagedRule,
    /// Distributed attack pattern detected.
    DistributedAttack,
    /// Request matched a user-defined custom rule.
    CustomRule,
}

impl fmt::Display for ThreatReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatReason::RateLimit => write!(f, "rate_limit"),
            ThreatReason::BadFingerprint => write!(f, "bad_fingerprint"),
            ThreatReason::SuspiciousBehavior => write!(f, "suspicious_behavior"),
            ThreatReason::MobileProxy => write!(f, "mobile_proxy"),
            ThreatReason::BlockedCountry => write!(f, "blocked_country"),
            ThreatReason::BlockedAsn => write!(f, "blocked_asn"),
            ThreatReason::BlockedIp => write!(f, "blocked_ip"),
            ThreatReason::HeaderAnomaly => write!(f, "header_anomaly"),
            ThreatReason::Slowloris => write!(f, "slowloris"),
            ThreatReason::ManualBlock => write!(f, "manual_block"),
            ThreatReason::ChallengeRequired => write!(f, "challenge_required"),
            ThreatReason::BadReputation => write!(f, "bad_reputation"),
            ThreatReason::AutoBanned => write!(f, "auto_banned"),
            ThreatReason::ManagedRule => write!(f, "managed_rule"),
            ThreatReason::DistributedAttack => write!(f, "distributed_attack"),
            ThreatReason::CustomRule => write!(f, "custom_rule"),
        }
    }
}

impl ThreatReason {
    /// Convert from a string representation.
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rate_limit" => Some(Self::RateLimit),
            "bad_fingerprint" => Some(Self::BadFingerprint),
            "suspicious_behavior" => Some(Self::SuspiciousBehavior),
            "mobile_proxy" => Some(Self::MobileProxy),
            "blocked_country" => Some(Self::BlockedCountry),
            "blocked_asn" => Some(Self::BlockedAsn),
            "blocked_ip" => Some(Self::BlockedIp),
            "header_anomaly" => Some(Self::HeaderAnomaly),
            "slowloris" => Some(Self::Slowloris),
            "manual_block" => Some(Self::ManualBlock),
            "challenge_required" => Some(Self::ChallengeRequired),
            "bad_reputation" => Some(Self::BadReputation),
            "auto_banned" => Some(Self::AutoBanned),
            "managed_rule" => Some(Self::ManagedRule),
            "distributed_attack" => Some(Self::DistributedAttack),
            "custom_rule" => Some(Self::CustomRule),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ProtectionLevel
// ---------------------------------------------------------------------------

/// System-wide protection posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// Level 0 -- normal traffic; minimal intervention.
    L0 = 0,
    /// Level 1 -- elevated traffic; lightweight challenges.
    L1 = 1,
    /// Level 2 -- active attack; aggressive challenges.
    L2 = 2,
    /// Level 3 -- severe attack; strict rate limits and challenges.
    L3 = 3,
    /// Level 4 -- emergency; near-total lockdown.
    L4 = 4,
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtectionLevel::L0 => write!(f, "normal (0)"),
            ProtectionLevel::L1 => write!(f, "elevated (1)"),
            ProtectionLevel::L2 => write!(f, "under_attack (2)"),
            ProtectionLevel::L3 => write!(f, "severe (3)"),
            ProtectionLevel::L4 => write!(f, "emergency (4)"),
        }
    }
}

impl ProtectionLevel {
    /// Convert a numeric level (0..=4) to a `ProtectionLevel`.
    pub fn from_u8(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::L0),
            1 => Some(Self::L1),
            2 => Some(Self::L2),
            3 => Some(Self::L3),
            4 => Some(Self::L4),
            _ => None,
        }
    }

    /// Return the numeric value of this protection level.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Escalate to the next level, capping at L4.
    pub fn escalate(&self) -> Self {
        match self {
            Self::L0 => Self::L1,
            Self::L1 => Self::L2,
            Self::L2 => Self::L3,
            Self::L3 => Self::L4,
            Self::L4 => Self::L4,
        }
    }

    /// De-escalate to the previous level, flooring at L0.
    pub fn deescalate(&self) -> Self {
        match self {
            Self::L0 => Self::L0,
            Self::L1 => Self::L0,
            Self::L2 => Self::L1,
            Self::L3 => Self::L2,
            Self::L4 => Self::L3,
        }
    }

    /// Convert from a string representation.
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "normal" | "l0" | "0" => Some(Self::L0),
            "elevated" | "high" | "l1" | "1" => Some(Self::L1),
            "under_attack" | "underattack" | "l2" | "2" => Some(Self::L2),
            "severe" | "l3" | "3" => Some(Self::L3),
            "emergency" | "l4" | "4" => Some(Self::L4),
            _ => None,
        }
    }
}

impl Default for ProtectionLevel {
    fn default() -> Self {
        Self::L0
    }
}
