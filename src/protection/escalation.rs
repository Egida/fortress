use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::config::settings::Settings;
use crate::models::threat::ProtectionLevel;

/
///
/
/
/
/
/
pub struct EscalationEngine {
    current_level: AtomicU8,
    last_escalation: Mutex<Instant>,
    last_deescalation: Mutex<Instant>,
    deescalation_counter: AtomicU8,
    escalation_counter: AtomicU8,
    sustained_checks_required: u8,
    block_ratio_threshold: f64,
    deescalation_cooldown: Duration,
}

/
const DEESCALATION_CONSECUTIVE_CHECKS: u8 = 3;
/
const ESCALATION_COOLDOWN_SECS: u64 = 10;

impl EscalationEngine {
    pub fn new() -> Self {
        Self {
            current_level: AtomicU8::new(0),
            last_escalation: Mutex::new(Instant::now()),
            last_deescalation: Mutex::new(Instant::now()),
            deescalation_counter: AtomicU8::new(0),
            escalation_counter: AtomicU8::new(0),
            sustained_checks_required: 3,
            block_ratio_threshold: 0.3,
            deescalation_cooldown: Duration::from_secs(60),
        }
    }

    /
    pub fn with_config(settings: &Settings) -> Self {
        Self {
            current_level: AtomicU8::new(0),
            last_escalation: Mutex::new(Instant::now()),
            last_deescalation: Mutex::new(Instant::now()),
            deescalation_counter: AtomicU8::new(0),
            escalation_counter: AtomicU8::new(0),
            sustained_checks_required: settings.escalation.sustained_checks_required,
            block_ratio_threshold: settings.escalation.block_ratio_threshold,
            deescalation_cooldown: Duration::from_secs(settings.escalation.deescalation_cooldown_secs),
        }
    }

    pub fn current_level(&self) -> ProtectionLevel {
        Self::u8_to_level(self.current_level.load(Ordering::Relaxed))
    }

    pub fn level_as_u8(&self) -> u8 {
        self.current_level.load(Ordering::Relaxed)
    }

    pub fn set_level(&self, level: ProtectionLevel) {
        let level_u8 = Self::level_to_u8(&level);
        let prev = self.current_level.swap(level_u8, Ordering::Relaxed);
        if prev != level_u8 {
            info!(from = prev, to = level_u8, "Protection level manually set");
            self.deescalation_counter.store(0, Ordering::Relaxed);
            self.escalation_counter.store(0, Ordering::Relaxed);
        }
    }

    /
    ///
    /
    /
    /
    /
    /
    pub fn evaluate(&self, rps: f64, blocked_per_min: u64, total_per_min: u64, settings: &Settings) {
        let current = self.current_level.load(Ordering::Relaxed);
        let thresholds = self.get_thresholds(settings);

        let block_ratio = if total_per_min > 0 {
            blocked_per_min as f64 / total_per_min as f64
        } else {
            0.0
        };

        if self.should_escalate(current, rps, blocked_per_min, &thresholds) {
            if block_ratio < self.block_ratio_threshold && current == 0 {
                debug!(
                    rps = rps,
                    block_ratio = block_ratio,
                    threshold = self.block_ratio_threshold,
                    "High RPS but low block ratio — skipping escalation (likely legitimate traffic)"
                );
                self.escalation_counter.store(0, Ordering::Relaxed);
                return;
            }

            let counter = self.escalation_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if counter >= self.sustained_checks_required {
                self.try_escalate(current);
                self.escalation_counter.store(0, Ordering::Relaxed);
            } else {
                debug!(
                    rps = rps,
                    counter = counter,
                    required = self.sustained_checks_required,
                    "Escalation condition met {}/{} consecutive checks",
                    counter,
                    self.sustained_checks_required,
                );
            }
            return;
        }

        self.escalation_counter.store(0, Ordering::Relaxed);

        if self.should_deescalate(current, rps, blocked_per_min, &thresholds) {
            let counter = self.deescalation_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if counter >= DEESCALATION_CONSECUTIVE_CHECKS {
                self.try_deescalate(current);
            }
        } else {
            self.deescalation_counter.store(0, Ordering::Relaxed);
        }
    }

    fn should_escalate(
        &self,
        current: u8,
        rps: f64,
        blocked_per_min: u64,
        thresholds: &EscalationThresholds,
    ) -> bool {
        match current {
            0 => rps > thresholds.l0_to_l1_rps || blocked_per_min > 50,
            1 => rps > thresholds.l1_to_l2_rps || blocked_per_min > 200,
            2 => rps > thresholds.l2_to_l3_rps || blocked_per_min > 500,
            3 => rps > thresholds.l3_to_l4_rps,
            _ => false,
        }
    }

    fn should_deescalate(
        &self,
        current: u8,
        rps: f64,
        blocked_per_min: u64,
        thresholds: &EscalationThresholds,
    ) -> bool {
        if current == 0 {
            return false;
        }

        let half_threshold = match current {
            1 => thresholds.l0_to_l1_rps * 0.5,
            2 => thresholds.l1_to_l2_rps * 0.5,
            3 => thresholds.l2_to_l3_rps * 0.5,
            4 => thresholds.l3_to_l4_rps * 0.5,
            _ => return false,
        };

        let block_threshold = match current {
            1 => 25,
            2 => 100,
            3 => 250,
            4 => 250,
            _ => return false,
        };

        rps < half_threshold && blocked_per_min < block_threshold
    }

    fn try_escalate(&self, current: u8) {
        if current >= 4 {
            return;
        }

        let mut last = self.last_escalation.lock();
        if last.elapsed() < Duration::from_secs(ESCALATION_COOLDOWN_SECS) {
            return;
        }

        let new_level = current + 1;
        match self.current_level.compare_exchange(
            current,
            new_level,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                *last = Instant::now();
                self.deescalation_counter.store(0, Ordering::Relaxed);
                warn!(from = current, to = new_level, "Protection level ESCALATED");
            }
            Err(actual) => {
                info!(
                    expected = current,
                    actual = actual,
                    "Escalation skipped: level changed concurrently"
                );
            }
        }
    }

    fn try_deescalate(&self, current: u8) {
        if current == 0 {
            return;
        }

        let mut last = self.last_deescalation.lock();
        if last.elapsed() < self.deescalation_cooldown {
            return;
        }

        let new_level = current - 1;
        match self.current_level.compare_exchange(
            current,
            new_level,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                *last = Instant::now();
                self.deescalation_counter.store(0, Ordering::Relaxed);
                info!(from = current, to = new_level, "Protection level de-escalated");
            }
            Err(actual) => {
                info!(
                    expected = current,
                    actual = actual,
                    "De-escalation skipped: level changed concurrently"
                );
            }
        }
    }

    fn get_thresholds(&self, settings: &Settings) -> EscalationThresholds {
        let esc = &settings.escalation;
        EscalationThresholds {
            l0_to_l1_rps: esc.l0_to_l1_rps as f64,
            l1_to_l2_rps: esc.l1_to_l2_rps as f64,
            l2_to_l3_rps: esc.l2_to_l3_rps as f64,
            l3_to_l4_rps: esc.l3_to_l4_rps as f64,
        }
    }

    fn u8_to_level(level: u8) -> ProtectionLevel {
        match level {
            0 => ProtectionLevel::L0,
            1 => ProtectionLevel::L1,
            2 => ProtectionLevel::L2,
            3 => ProtectionLevel::L3,
            _ => ProtectionLevel::L4,
        }
    }

    fn level_to_u8(level: &ProtectionLevel) -> u8 {
        match level {
            ProtectionLevel::L0 => 0,
            ProtectionLevel::L1 => 1,
            ProtectionLevel::L2 => 2,
            ProtectionLevel::L3 => 3,
            ProtectionLevel::L4 => 4,
        }
    }
}

impl Default for EscalationEngine {
    fn default() -> Self {
        Self::new()
    }
}

struct EscalationThresholds {
    l0_to_l1_rps: f64,
    l1_to_l2_rps: f64,
    l2_to_l3_rps: f64,
    l3_to_l4_rps: f64,
}
