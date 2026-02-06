use std::sync::Arc;
use tracing::debug;

use crate::models::request::RequestContext;
use crate::storage::memory::MemoryStore;

/// Behavioral analysis engine that scores IPs based on their request patterns.
///
/// Assigns a composite threat score (0-100) by analyzing request timing,
/// path diversity, and JA3/UA consistency. Header anomaly checks are
/// handled separately by HeaderAnalyzer to avoid double-counting.
pub struct BehavioralAnalyzer {
    memory: Arc<MemoryStore>,
}

impl BehavioralAnalyzer {
    pub fn new(memory: Arc<MemoryStore>) -> Self {
        Self { memory }
    }

    /// Analyze a request context and return a composite threat score (0-100).
    pub fn analyze(&self, ctx: &RequestContext) -> f64 {
        let raw_score = self.memory.update_behavior(
            ctx.client_ip,
            &ctx.path,
            &ctx.method,
            ctx.ja3_hash.as_deref(),
            ctx.user_agent.as_deref(),
        );

        // MemoryStore returns a score in [0.0, 1.0]; scale to [0, 100].
        let composite = (raw_score * 100.0).clamp(0.0, 100.0);

        debug!(
            ip = %ctx.client_ip,
            memory_score = raw_score,
            composite = composite,
            "Behavioral analysis complete"
        );

        composite
    }
}
