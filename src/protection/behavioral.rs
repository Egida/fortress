use std::sync::Arc;
use tracing::debug;

use crate::models::request::RequestContext;
use crate::storage::memory::MemoryStore;

/
///
/
/
/
pub struct BehavioralAnalyzer {
    memory: Arc<MemoryStore>,
}

impl BehavioralAnalyzer {
    pub fn new(memory: Arc<MemoryStore>) -> Self {
        Self { memory }
    }

    /
    pub fn analyze(&self, ctx: &RequestContext) -> f64 {
        let raw_score = self.memory.update_behavior(
            ctx.client_ip,
            &ctx.path,
            &ctx.method,
            ctx.ja3_hash.as_deref(),
            ctx.user_agent.as_deref(),
        );

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
