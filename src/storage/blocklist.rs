use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::memory::MemoryStore;
use super::sqlite::SqliteStore;

// ---------------------------------------------------------------------------
// ThreatAction – what to do with a matched request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatAction {
    Block,
    Challenge,
}

impl ThreatAction {
    fn from_str_action(s: &str) -> Self {
        match s {
            "challenge" => ThreatAction::Challenge,
            _ => ThreatAction::Block,
        }
    }
}

// ---------------------------------------------------------------------------
// BlocklistManager
// ---------------------------------------------------------------------------

pub struct BlocklistManager {
    memory: Arc<MemoryStore>,
    sqlite: Arc<SqliteStore>,
    blocked_cidrs: DashMap<String, String>,    // CIDR string -> reason
    blocked_asns: DashMap<u32, String>,        // ASN -> action (block/challenge)
    blocked_countries: DashMap<String, String>, // Country code -> action
}

impl BlocklistManager {
    pub fn new(memory: Arc<MemoryStore>, sqlite: Arc<SqliteStore>) -> Self {
        Self {
            memory,
            sqlite,
            blocked_cidrs: DashMap::new(),
            blocked_asns: DashMap::new(),
            blocked_countries: DashMap::new(),
        }
    }

    /// Load all blocklist data from SQLite into the in-memory caches.
    pub fn load_from_db(&self) -> Result<(), Box<dyn std::error::Error>> {
        // --- Blocked IPs ---
        let ips = self.sqlite.get_blocked_ips()?;
        for row in &ips {
            // Skip entries that have already expired.
            if let Some(ref exp) = row.expires_at {
                if let Ok(exp_dt) = DateTime::parse_from_str(
                    &format!("{} +0000", exp),
                    "%Y-%m-%d %H:%M:%S %z",
                ) {
                    if exp_dt < Utc::now() {
                        continue;
                    }
                }
            }

            // If it is a CIDR entry, store in the CIDR map.
            if row.cidr.is_some() {
                self.blocked_cidrs
                    .insert(row.ip.clone(), row.reason.clone());
            } else if let Ok(ip) = IpAddr::from_str(&row.ip) {
                // Compute optional duration from expires_at.
                let duration = row.expires_at.as_ref().and_then(|exp| {
                    DateTime::parse_from_str(
                        &format!("{} +0000", exp),
                        "%Y-%m-%d %H:%M:%S %z",
                    )
                    .ok()
                    .and_then(|exp_dt| {
                        let diff = exp_dt.signed_duration_since(Utc::now());
                        if diff.num_seconds() > 0 {
                            Some(Duration::from_secs(diff.num_seconds() as u64))
                        } else {
                            None
                        }
                    })
                });

                self.memory
                    .block_ip(ip, row.reason.clone(), duration);
            }
        }

        // --- Blocked ASNs ---
        let asns = self.sqlite.get_blocked_asns()?;
        for row in &asns {
            self.blocked_asns.insert(row.asn, row.action.clone());
        }

        // --- Blocked countries ---
        let countries = self.sqlite.get_blocked_countries()?;
        for row in &countries {
            self.blocked_countries
                .insert(row.country_code.clone(), row.action.clone());
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Checks
    // -----------------------------------------------------------------------

    /// Check whether `ip` is blocked (exact match or CIDR match).
    /// Returns `(action, reason)` if the IP should be acted upon.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<(ThreatAction, String)> {
        // 1. Exact IP match via in-memory blocked_ips cache.
        if let Some(entry) = self.memory.is_blocked(ip) {
            return Some((ThreatAction::Block, entry.reason));
        }

        // 2. CIDR match.
        for entry in self.blocked_cidrs.iter() {
            let cidr_str = entry.key();
            if let Ok(network) = cidr_str.parse::<IpNet>() {
                if network.contains(ip) {
                    return Some((ThreatAction::Block, entry.value().clone()));
                }
            }
        }

        None
    }

    /// Check whether `asn` is blocked/challenged.
    pub fn check_asn(&self, asn: u32) -> Option<(ThreatAction, String)> {
        self.blocked_asns.get(&asn).map(|entry| {
            let action = ThreatAction::from_str_action(entry.value());
            let reason = format!("ASN {} is {}", asn, entry.value());
            (action, reason)
        })
    }

    /// Check whether `country` code is blocked/challenged.
    pub fn check_country(&self, country: &str) -> Option<(ThreatAction, String)> {
        self.blocked_countries.get(country).map(|entry| {
            let action = ThreatAction::from_str_action(entry.value());
            let reason = format!("Country {} is {}", country, entry.value());
            (action, reason)
        })
    }

    // -----------------------------------------------------------------------
    // Mutations
    // -----------------------------------------------------------------------

    /// Block an IP (or CIDR) persistently and in memory.
    pub fn add_ip(
        &self,
        ip: &str,
        reason: &str,
        source: &str,
        duration: Option<Duration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expires_at: Option<DateTime<Utc>> = duration.map(|d| {
            Utc::now() + chrono::Duration::seconds(d.as_secs() as i64)
        });

        // Determine if this is a CIDR or a single IP.
        let is_cidr = ip.contains('/');
        let cidr_param: Option<&str> = if is_cidr { Some(ip) } else { None };

        // Persist to SQLite.
        self.sqlite
            .add_blocked_ip(ip, cidr_param, reason, source, expires_at)?;

        // Update in-memory caches.
        if is_cidr {
            self.blocked_cidrs
                .insert(ip.to_string(), reason.to_string());
        } else if let Ok(parsed) = IpAddr::from_str(ip) {
            self.memory
                .block_ip(parsed, reason.to_string(), duration);
        }

        Ok(())
    }

    /// Remove a blocked-IP entry by its database row ID.
    pub fn remove_ip(&self, id: i64) -> Result<(), Box<dyn std::error::Error>> {
        // Look up the row first so we can evict the memory cache.
        let rows = self.sqlite.get_blocked_ips()?;
        if let Some(row) = rows.iter().find(|r| r.id == id) {
            if row.cidr.is_some() {
                self.blocked_cidrs.remove(&row.ip);
            } else if let Ok(ip) = std::net::IpAddr::from_str(&row.ip) {
                self.memory.unblock_ip(&ip);
            }
        }

        self.sqlite.remove_blocked_ip(id)?;
        Ok(())
    }

    /// Remove a blocked ASN entry by its database row ID.
    pub fn remove_asn(&self, id: i64) -> Result<(), Box<dyn std::error::Error>> {
        // Look up the row to get the ASN number for cache eviction
        let rows = self.sqlite.get_blocked_asns()?;
        if let Some(row) = rows.iter().find(|r| r.id == id) {
            self.blocked_asns.remove(&row.asn);
        }
        self.sqlite.remove_blocked_asn(id)?;
        Ok(())
    }

    /// Remove a blocked country entry by its database row ID.
    pub fn remove_country(&self, id: i64) -> Result<(), Box<dyn std::error::Error>> {
        // Look up the row to get the country code for cache eviction
        let rows = self.sqlite.get_blocked_countries()?;
        if let Some(row) = rows.iter().find(|r| r.id == id) {
            self.blocked_countries.remove(&row.country_code);
        }
        self.sqlite.remove_blocked_country(id)?;
        Ok(())
    }
}
