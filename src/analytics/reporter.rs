use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};

use crate::analytics::alerting::AlertManager;
use crate::analytics::collector::MetricsCollector;
use crate::config::settings::Settings;
use crate::protection::escalation::EscalationEngine;
use crate::storage::sqlite::{AttackRow, MetricsRow, SqliteStore};

/// Periodic reporter that drives the collector tick and flushes aggregated
/// metrics to the SQLite backing store.
pub struct MetricsReporter {
    collector: Arc<MetricsCollector>,
    sqlite: Arc<SqliteStore>,
    escalation: Arc<EscalationEngine>,
    settings: Arc<Settings>,
    alerting: Option<Arc<AlertManager>>,

    // Attack tracking state
    previous_level: Mutex<u8>,
    current_attack_id: Mutex<Option<i64>>,
    attack_peak_rps: Mutex<u64>,
    attack_started_at: Mutex<Option<String>>,
}

impl MetricsReporter {
    pub fn new(
        collector: Arc<MetricsCollector>,
        sqlite: Arc<SqliteStore>,
        escalation: Arc<EscalationEngine>,
        settings: Arc<Settings>,
        alerting: Option<Arc<AlertManager>>,
    ) -> Self {
        let initial_level = escalation.level_as_u8();
        Self {
            collector,
            sqlite,
            escalation,
            settings,
            alerting,
            previous_level: Mutex::new(initial_level),
            current_attack_id: Mutex::new(None),
            attack_peak_rps: Mutex::new(0),
            attack_started_at: Mutex::new(None),
        }
    }

    /// Run the reporter loop forever.
    pub async fn run(&self) {
        let mut tick_interval = interval(Duration::from_secs(1));
        tick_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut escalation_interval = interval(Duration::from_secs(5));
        escalation_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut flush_interval = interval(Duration::from_secs(3600));
        flush_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = tick_interval.tick() => {
                    self.collector.tick();
                }

                _ = escalation_interval.tick() => {
                    self.evaluate_escalation();
                }

                _ = flush_interval.tick() => {
                    self.flush_to_sqlite();
                }
            }
        }
    }

    /// Feed live traffic stats into the escalation engine and track attacks.
    fn evaluate_escalation(&self) {
        let current_rps = self.collector.get_current_rps();
        let snapshot = self.collector.get_snapshot();

        // Run the escalation engine
        self.escalation.evaluate(current_rps, snapshot.total_blocked, snapshot.total_requests, &self.settings);

        let new_level = self.escalation.level_as_u8();
        let mut prev_level = self.previous_level.lock();
        let old_level = *prev_level;

        // Track peak RPS during ongoing attack
        if self.current_attack_id.lock().is_some() {
            let mut peak = self.attack_peak_rps.lock();
            let rps = current_rps as u64;
            if rps > *peak {
                *peak = rps;
            }
        }

        if new_level != old_level {
            *prev_level = new_level;

            // L0 -> L1+: attack started
            if old_level == 0 && new_level >= 1 {
                self.record_attack_start(new_level, current_rps as u64);
            }
            // L1+ -> L0: attack ended
            else if old_level >= 1 && new_level == 0 {
                self.record_attack_end();
            }
            // L1+ -> higher: update attack severity
            else if new_level > old_level {
                self.update_attack_severity(new_level);

                // Send alert on escalation
                if let Some(ref alerting) = self.alerting {
                    let msg = format!(
                        "Protection level escalated: L{} -> L{} (RPS: {:.0})",
                        old_level, new_level, current_rps
                    );
                    let alerting = alerting.clone();
                    tokio::spawn(async move {
                        alerting.send_alert("escalation", &msg).await;
                    });
                }
            }
        }
    }

    /// Record the start of a new attack.
    fn record_attack_start(&self, level: u8, rps: u64) {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let severity = Self::level_to_severity(level);
        let snapshot = self.collector.get_snapshot();

        let top_countries = self.collector.get_top_countries(10);
        let top_ips = self.collector.get_top_ips(10);
        let top_countries_json = serde_json::to_string(
            &top_countries.iter().map(|(c, n)| (c.as_str(), *n)).collect::<Vec<_>>()
        ).ok();
        let top_ips_json = serde_json::to_string(
            &top_ips.iter().map(|(ip, n)| (ip.to_string(), *n)).collect::<Vec<_>>()
        ).ok();

        let attack = AttackRow {
            id: 0,
            started_at: now.clone(),
            ended_at: None,
            peak_rps: rps,
            total_requests: snapshot.total_requests,
            unique_ips: snapshot.unique_ips,
            max_level: level,
            top_countries_json,
            top_ips_json,
            severity,
        };

        match self.sqlite.insert_attack(&attack) {
            Ok(id) => {
                info!(attack_id = id, level = level, rps = rps, "Attack recorded: started");
                *self.current_attack_id.lock() = Some(id);
                *self.attack_peak_rps.lock() = rps;
                *self.attack_started_at.lock() = Some(now);
            }
            Err(e) => {
                warn!("Failed to record attack start: {}", e);
            }
        }

        // Send alert
        if let Some(ref alerting) = self.alerting {
            let msg = format!("Attack detected! Level: L{}, RPS: {}", level, rps);
            let alerting = alerting.clone();
            tokio::spawn(async move {
                alerting.send_alert("attack_start", &msg).await;
            });
        }
    }

    /// Record the end of an ongoing attack.
    fn record_attack_end(&self) {
        let mut attack_id = self.current_attack_id.lock();
        let id = match *attack_id {
            Some(id) => id,
            None => return,
        };

        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let peak = *self.attack_peak_rps.lock();
        let started = self.attack_started_at.lock().clone().unwrap_or_default();
        let snapshot = self.collector.get_snapshot();

        let top_countries = self.collector.get_top_countries(10);
        let top_ips = self.collector.get_top_ips(10);
        let top_countries_json = serde_json::to_string(
            &top_countries.iter().map(|(c, n)| (c.as_str(), *n)).collect::<Vec<_>>()
        ).ok();
        let top_ips_json = serde_json::to_string(
            &top_ips.iter().map(|(ip, n)| (ip.to_string(), *n)).collect::<Vec<_>>()
        ).ok();

        let attack = AttackRow {
            id,
            started_at: started,
            ended_at: Some(now),
            peak_rps: peak,
            total_requests: snapshot.total_requests,
            unique_ips: snapshot.unique_ips,
            max_level: 0,
            top_countries_json,
            top_ips_json,
            severity: "low".to_string(),
        };

        if let Err(e) = self.sqlite.update_attack(id, &attack) {
            warn!(attack_id = id, "Failed to record attack end: {}", e);
        } else {
            info!(attack_id = id, peak_rps = peak, "Attack ended");
        }

        *attack_id = None;
        *self.attack_peak_rps.lock() = 0;
        *self.attack_started_at.lock() = None;

        // Send alert
        if let Some(ref alerting) = self.alerting {
            let msg = format!("Attack ended. Peak RPS: {}", peak);
            let alerting = alerting.clone();
            tokio::spawn(async move {
                alerting.send_alert("attack_end", &msg).await;
            });
        }
    }

    /// Update the severity of an ongoing attack when level increases.
    fn update_attack_severity(&self, new_level: u8) {
        let attack_id = self.current_attack_id.lock();
        let id = match *attack_id {
            Some(id) => id,
            None => return,
        };

        let peak = *self.attack_peak_rps.lock();
        let started = self.attack_started_at.lock().clone().unwrap_or_default();
        let severity = Self::level_to_severity(new_level);
        let snapshot = self.collector.get_snapshot();

        let top_countries = self.collector.get_top_countries(10);
        let top_ips = self.collector.get_top_ips(10);
        let top_countries_json = serde_json::to_string(
            &top_countries.iter().map(|(c, n)| (c.as_str(), *n)).collect::<Vec<_>>()
        ).ok();
        let top_ips_json = serde_json::to_string(
            &top_ips.iter().map(|(ip, n)| (ip.to_string(), *n)).collect::<Vec<_>>()
        ).ok();

        let attack = AttackRow {
            id,
            started_at: started,
            ended_at: None,
            peak_rps: peak,
            total_requests: snapshot.total_requests,
            unique_ips: snapshot.unique_ips,
            max_level: new_level,
            top_countries_json,
            top_ips_json,
            severity,
        };

        if let Err(e) = self.sqlite.update_attack(id, &attack) {
            warn!(attack_id = id, "Failed to update attack severity: {}", e);
        } else {
            info!(attack_id = id, new_level = new_level, "Attack severity updated");
        }
    }

    fn level_to_severity(level: u8) -> String {
        match level {
            1 => "low".to_string(),
            2 => "medium".to_string(),
            3 => "high".to_string(),
            4 => "critical".to_string(),
            _ => "low".to_string(),
        }
    }

    /// Persist accumulated metrics to SQLite and reset hourly aggregates.
    fn flush_to_sqlite(&self) {
        info!("Flushing hourly metrics to SQLite");

        let snapshot = self.collector.get_snapshot();
        let top_countries = self.collector.get_top_countries(50);
        let top_asns = self.collector.get_top_asns(50);

        let top_countries_json = serde_json::to_string(&top_countries).ok();
        let top_asns_json = serde_json::to_string(&top_asns).ok();

        let level = self.escalation.level_as_u8();

        let metrics_row = MetricsRow {
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            total_requests: snapshot.total_requests,
            passed_requests: snapshot.total_requests.saturating_sub(snapshot.total_blocked),
            blocked_requests: snapshot.total_blocked,
            challenged_requests: 0,
            unique_ips: snapshot.unique_ips,
            avg_latency_ms: snapshot.avg_latency_ms,
            protection_level: level,
            top_countries_json,
            top_asns_json,
        };

        if let Err(e) = self.sqlite.insert_metrics_hourly(&metrics_row) {
            warn!("Failed to store hourly metrics: {}", e);
        }

        self.collector.reset_hourly();
        info!("Hourly metrics flushed and counters reset");
    }
}
