use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIpRow {
    pub id: i64,
    pub ip: String,
    pub cidr: Option<String>,
    pub reason: String,
    pub source: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedAsnRow {
    pub id: i64,
    pub asn: u32,
    pub name: Option<String>,
    pub action: String,
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedCountryRow {
    pub id: i64,
    pub country_code: String,
    pub country_name: Option<String>,
    pub action: String,
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRow {
    pub id: i64,
    pub name: String,
    pub priority: i32,
    pub conditions_json: String,
    pub action: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsRow {
    pub timestamp: String,
    pub total_requests: u64,
    pub passed_requests: u64,
    pub blocked_requests: u64,
    pub challenged_requests: u64,
    pub unique_ips: u64,
    pub avg_latency_ms: f64,
    pub protection_level: u8,
    pub top_countries_json: Option<String>,
    pub top_asns_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackRow {
    pub id: i64,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub peak_rps: u64,
    pub total_requests: u64,
    pub unique_ips: u64,
    pub max_level: u8,
    pub top_countries_json: Option<String>,
    pub top_ips_json: Option<String>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRow {
    pub id: String,
    pub name: String,
    pub domains: String,
    pub upstream_address: String,
    pub enabled: bool,
    pub protection_level_override: Option<i32>,
    pub always_challenge: bool,
    pub rate_limit_multiplier: f64,
    pub max_connections: i64,
    pub connect_timeout_ms: i64,
    pub response_timeout_ms: i64,
    pub exempt_paths: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4EventRow {
    pub id: i64,
    pub timestamp: String,
    pub client_ip: String,
    pub action: String,
    pub reason: Option<String>,
    pub concurrent_connections: Option<i64>,
    pub connection_rate: Option<i64>,
}


pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                cidr        TEXT,
                reason      TEXT NOT NULL,
                source      TEXT NOT NULL DEFAULT 'auto',
                created_at  TEXT DEFAULT (datetime('now')),
                expires_at  TEXT,
                UNIQUE(ip)
            );

            CREATE TABLE IF NOT EXISTS blocked_asns (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                asn         INTEGER NOT NULL UNIQUE,
                name        TEXT,
                action      TEXT NOT NULL DEFAULT 'block',
                reason      TEXT,
                created_at  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS blocked_countries (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                country_code  TEXT NOT NULL UNIQUE,
                country_name  TEXT,
                action        TEXT NOT NULL DEFAULT 'block',
                reason        TEXT,
                created_at    TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS protection_rules (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                priority        INTEGER NOT NULL DEFAULT 100,
                conditions_json TEXT NOT NULL,
                action          TEXT NOT NULL,
                enabled         INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT DEFAULT (datetime('now')),
                updated_at      TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS metrics_hourly (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT NOT NULL,
                total_requests      INTEGER DEFAULT 0,
                passed_requests     INTEGER DEFAULT 0,
                blocked_requests    INTEGER DEFAULT 0,
                challenged_requests INTEGER DEFAULT 0,
                unique_ips          INTEGER DEFAULT 0,
                avg_latency_ms      REAL    DEFAULT 0,
                protection_level    INTEGER DEFAULT 0,
                top_countries_json  TEXT,
                top_asns_json       TEXT,
                UNIQUE(timestamp)
            );

            CREATE TABLE IF NOT EXISTS attacks (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at          TEXT NOT NULL,
                ended_at            TEXT,
                peak_rps            INTEGER DEFAULT 0,
                total_requests      INTEGER DEFAULT 0,
                unique_ips          INTEGER DEFAULT 0,
                max_level           INTEGER DEFAULT 0,
                top_countries_json  TEXT,
                top_ips_json        TEXT,
                severity            TEXT DEFAULT 'low'
            );

            CREATE TABLE IF NOT EXISTS config (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS services (
                id                      TEXT PRIMARY KEY,
                name                    TEXT NOT NULL,
                domains                 TEXT NOT NULL,
                upstream_address        TEXT NOT NULL,
                enabled                 INTEGER NOT NULL DEFAULT 1,
                protection_level_override INTEGER,
                always_challenge        INTEGER NOT NULL DEFAULT 0,
                rate_limit_multiplier   REAL NOT NULL DEFAULT 1.0,
                max_connections         INTEGER NOT NULL DEFAULT 10000,
                connect_timeout_ms      INTEGER NOT NULL DEFAULT 5000,
                response_timeout_ms     INTEGER NOT NULL DEFAULT 60000,
                exempt_paths            TEXT,
                created_at              TEXT DEFAULT (datetime('now')),
                updated_at              TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS l4_events (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp               TEXT DEFAULT (datetime('now')),
                client_ip               TEXT NOT NULL,
                action                  TEXT NOT NULL,
                reason                  TEXT,
                concurrent_connections  INTEGER,
                connection_rate         INTEGER
            );
            ",
        )?;

        let _ = conn.execute_batch(
            "ALTER TABLE services ADD COLUMN always_challenge INTEGER NOT NULL DEFAULT 0;"
        );

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }


    pub fn add_blocked_ip(
        &self,
        ip: &str,
        cidr: Option<&str>,
        reason: &str,
        source: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let expires_str = expires_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, cidr, reason, source, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip, cidr, reason, source, expires_str],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn remove_blocked_ip(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute("DELETE FROM blocked_ips WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_blocked_ips(&self) -> Result<Vec<BlockedIpRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, ip, cidr, reason, source, created_at, expires_at FROM blocked_ips",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BlockedIpRow {
                id: row.get(0)?,
                ip: row.get(1)?,
                cidr: row.get(2)?,
                reason: row.get(3)?,
                source: row.get(4)?,
                created_at: row.get(5)?,
                expires_at: row.get(6)?,
            })
        })?;
        rows.collect()
    }


    pub fn add_blocked_asn(
        &self,
        asn: u32,
        name: Option<&str>,
        action: &str,
        reason: Option<&str>,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO blocked_asns (asn, name, action, reason)
             VALUES (?1, ?2, ?3, ?4)",
            params![asn, name, action, reason],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn remove_blocked_asn(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute("DELETE FROM blocked_asns WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_blocked_asns(&self) -> Result<Vec<BlockedAsnRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT id, asn, name, action, reason, created_at FROM blocked_asns")?;
        let rows = stmt.query_map([], |row| {
            Ok(BlockedAsnRow {
                id: row.get(0)?,
                asn: row.get::<_, u32>(1)?,
                name: row.get(2)?,
                action: row.get(3)?,
                reason: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        rows.collect()
    }


    pub fn add_blocked_country(
        &self,
        code: &str,
        name: Option<&str>,
        action: &str,
        reason: Option<&str>,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO blocked_countries (country_code, country_name, action, reason)
             VALUES (?1, ?2, ?3, ?4)",
            params![code, name, action, reason],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn remove_blocked_country(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute("DELETE FROM blocked_countries WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_blocked_countries(&self) -> Result<Vec<BlockedCountryRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, country_code, country_name, action, reason, created_at
             FROM blocked_countries",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BlockedCountryRow {
                id: row.get(0)?,
                country_code: row.get(1)?,
                country_name: row.get(2)?,
                action: row.get(3)?,
                reason: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        rows.collect()
    }


    pub fn add_rule(
        &self,
        name: &str,
        priority: i32,
        conditions: &str,
        action: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO protection_rules (name, priority, conditions_json, action)
             VALUES (?1, ?2, ?3, ?4)",
            params![name, priority, conditions, action],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_rule(
        &self,
        id: i64,
        name: &str,
        priority: i32,
        conditions: &str,
        action: &str,
        enabled: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "UPDATE protection_rules
             SET name = ?1, priority = ?2, conditions_json = ?3, action = ?4,
                 enabled = ?5, updated_at = datetime('now')
             WHERE id = ?6",
            params![name, priority, conditions, action, enabled as i32, id],
        )?;
        Ok(())
    }

    pub fn delete_rule(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute("DELETE FROM protection_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_rules(&self) -> Result<Vec<RuleRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, name, priority, conditions_json, action, enabled, created_at
             FROM protection_rules ORDER BY priority ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RuleRow {
                id: row.get(0)?,
                name: row.get(1)?,
                priority: row.get(2)?,
                conditions_json: row.get(3)?,
                action: row.get(4)?,
                enabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
            })
        })?;
        rows.collect()
    }


    pub fn insert_metrics_hourly(&self, snapshot: &MetricsRow) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO metrics_hourly
             (timestamp, total_requests, passed_requests, blocked_requests,
              challenged_requests, unique_ips, avg_latency_ms, protection_level,
              top_countries_json, top_asns_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                snapshot.timestamp,
                snapshot.total_requests as i64,
                snapshot.passed_requests as i64,
                snapshot.blocked_requests as i64,
                snapshot.challenged_requests as i64,
                snapshot.unique_ips as i64,
                snapshot.avg_latency_ms,
                snapshot.protection_level as i32,
                snapshot.top_countries_json,
                snapshot.top_asns_json,
            ],
        )?;
        Ok(())
    }

    pub fn get_metrics_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<MetricsRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let from_str = from.format("%Y-%m-%d %H:%M:%S").to_string();
        let to_str = to.format("%Y-%m-%d %H:%M:%S").to_string();
        let mut stmt = conn.prepare(
            "SELECT timestamp, total_requests, passed_requests, blocked_requests,
                    challenged_requests, unique_ips, avg_latency_ms, protection_level,
                    top_countries_json, top_asns_json
             FROM metrics_hourly
             WHERE timestamp >= ?1 AND timestamp <= ?2
             ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map(params![from_str, to_str], |row| {
            Ok(MetricsRow {
                timestamp: row.get(0)?,
                total_requests: row.get::<_, i64>(1)? as u64,
                passed_requests: row.get::<_, i64>(2)? as u64,
                blocked_requests: row.get::<_, i64>(3)? as u64,
                challenged_requests: row.get::<_, i64>(4)? as u64,
                unique_ips: row.get::<_, i64>(5)? as u64,
                avg_latency_ms: row.get(6)?,
                protection_level: row.get::<_, i32>(7)? as u8,
                top_countries_json: row.get(8)?,
                top_asns_json: row.get(9)?,
            })
        })?;
        rows.collect()
    }


    pub fn insert_attack(&self, attack: &AttackRow) -> Result<i64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO attacks
             (started_at, ended_at, peak_rps, total_requests, unique_ips,
              max_level, top_countries_json, top_ips_json, severity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                attack.started_at,
                attack.ended_at,
                attack.peak_rps as i64,
                attack.total_requests as i64,
                attack.unique_ips as i64,
                attack.max_level as i32,
                attack.top_countries_json,
                attack.top_ips_json,
                attack.severity,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_attack(&self, id: i64, attack: &AttackRow) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "UPDATE attacks
             SET started_at = ?1, ended_at = ?2, peak_rps = ?3, total_requests = ?4,
                 unique_ips = ?5, max_level = ?6, top_countries_json = ?7,
                 top_ips_json = ?8, severity = ?9
             WHERE id = ?10",
            params![
                attack.started_at,
                attack.ended_at,
                attack.peak_rps as i64,
                attack.total_requests as i64,
                attack.unique_ips as i64,
                attack.max_level as i32,
                attack.top_countries_json,
                attack.top_ips_json,
                attack.severity,
                id,
            ],
        )?;
        Ok(())
    }

    pub fn get_attacks(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<AttackRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let from_str = from.format("%Y-%m-%d %H:%M:%S").to_string();
        let to_str = to.format("%Y-%m-%d %H:%M:%S").to_string();
        let mut stmt = conn.prepare(
            "SELECT id, started_at, ended_at, peak_rps, total_requests, unique_ips,
                    max_level, top_countries_json, top_ips_json, severity
             FROM attacks
             WHERE started_at >= ?1 AND started_at <= ?2
             ORDER BY started_at DESC",
        )?;
        let rows = stmt.query_map(params![from_str, to_str], |row| {
            Ok(AttackRow {
                id: row.get(0)?,
                started_at: row.get(1)?,
                ended_at: row.get(2)?,
                peak_rps: row.get::<_, i64>(3)? as u64,
                total_requests: row.get::<_, i64>(4)? as u64,
                unique_ips: row.get::<_, i64>(5)? as u64,
                max_level: row.get::<_, i32>(6)? as u8,
                top_countries_json: row.get(7)?,
                top_ips_json: row.get(8)?,
                severity: row.get(9)?,
            })
        })?;
        rows.collect()
    }


    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare("SELECT value FROM config WHERE key = ?1")?;
        let mut rows = stmt.query_map(params![key], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(Ok(value)) => Ok(Some(value)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO config (key, value, updated_at)
             VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
            params![key, value],
        )?;
        Ok(())
    }


    pub fn add_service(&self, svc: &ServiceRow) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO services
             (id, name, domains, upstream_address, enabled, protection_level_override,
              always_challenge, rate_limit_multiplier, max_connections, connect_timeout_ms,
              response_timeout_ms, exempt_paths)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                svc.id, svc.name, svc.domains, svc.upstream_address,
                svc.enabled as i32, svc.protection_level_override,
                svc.always_challenge as i32, svc.rate_limit_multiplier,
                svc.max_connections, svc.connect_timeout_ms,
                svc.response_timeout_ms, svc.exempt_paths,
            ],
        )?;
        Ok(())
    }

    pub fn update_service(&self, svc: &ServiceRow) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "UPDATE services SET name=?1, domains=?2, upstream_address=?3, enabled=?4,
             protection_level_override=?5, always_challenge=?6, rate_limit_multiplier=?7,
             max_connections=?8, connect_timeout_ms=?9, response_timeout_ms=?10,
             exempt_paths=?11, updated_at=datetime('now')
             WHERE id=?12",
            params![
                svc.name, svc.domains, svc.upstream_address, svc.enabled as i32,
                svc.protection_level_override, svc.always_challenge as i32,
                svc.rate_limit_multiplier, svc.max_connections,
                svc.connect_timeout_ms, svc.response_timeout_ms,
                svc.exempt_paths, svc.id,
            ],
        )?;
        Ok(())
    }

    pub fn delete_service(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute("DELETE FROM services WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_services(&self) -> Result<Vec<ServiceRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, name, domains, upstream_address, enabled, protection_level_override,
                    always_challenge, rate_limit_multiplier, max_connections, connect_timeout_ms,
                    response_timeout_ms, exempt_paths, created_at, updated_at
             FROM services ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ServiceRow {
                id: row.get(0)?,
                name: row.get(1)?,
                domains: row.get(2)?,
                upstream_address: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
                protection_level_override: row.get(5)?,
                always_challenge: row.get::<_, i32>(6)? != 0,
                rate_limit_multiplier: row.get(7)?,
                max_connections: row.get(8)?,
                connect_timeout_ms: row.get(9)?,
                response_timeout_ms: row.get(10)?,
                exempt_paths: row.get(11)?,
                created_at: row.get(12)?,
                updated_at: row.get(13)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_service(&self, id: &str) -> Result<Option<ServiceRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, name, domains, upstream_address, enabled, protection_level_override,
                    always_challenge, rate_limit_multiplier, max_connections, connect_timeout_ms,
                    response_timeout_ms, exempt_paths, created_at, updated_at
             FROM services WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(ServiceRow {
                id: row.get(0)?,
                name: row.get(1)?,
                domains: row.get(2)?,
                upstream_address: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
                protection_level_override: row.get(5)?,
                always_challenge: row.get::<_, i32>(6)? != 0,
                rate_limit_multiplier: row.get(7)?,
                max_connections: row.get(8)?,
                connect_timeout_ms: row.get(9)?,
                response_timeout_ms: row.get(10)?,
                exempt_paths: row.get(11)?,
                created_at: row.get(12)?,
                updated_at: row.get(13)?,
            })
        })?;
        match rows.next() {
            Some(Ok(row)) => Ok(Some(row)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }


    pub fn insert_l4_event(
        &self,
        client_ip: &str,
        action: &str,
        reason: Option<&str>,
        concurrent: Option<i64>,
        rate: Option<i64>,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO l4_events (client_ip, action, reason, concurrent_connections, connection_rate)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![client_ip, action, reason, concurrent, rate],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_l4_events(&self, limit: usize) -> Result<Vec<L4EventRow>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, client_ip, action, reason, concurrent_connections, connection_rate
             FROM l4_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(L4EventRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                client_ip: row.get(2)?,
                action: row.get(3)?,
                reason: row.get(4)?,
                concurrent_connections: row.get(5)?,
                connection_rate: row.get(6)?,
            })
        })?;
        rows.collect()
    }
}
