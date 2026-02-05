use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::proxy::service_router::ServiceRouter;

/
///
/
/
/
pub struct HealthChecker {
    service_router: Arc<ServiceRouter>,
    interval: Duration,
    timeout: Duration,
}

impl HealthChecker {
    pub fn new(service_router: Arc<ServiceRouter>, interval_secs: u64, timeout_ms: u64) -> Self {
        Self {
            service_router,
            interval: Duration::from_secs(interval_secs),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /
    pub async fn run(&self) {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            self.check_all().await;
        }
    }

    /
    async fn check_all(&self) {
        let services = self.service_router.list_services();

        for svc in &services {
            let addr = &svc.upstream_address;
            let healthy = match tokio::time::timeout(
                self.timeout,
                TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(_)) => true,
                Ok(Err(e)) => {
                    warn!(
                        service = %svc.name,
                        upstream = %addr,
                        error = %e,
                        "Health check failed"
                    );
                    false
                }
                Err(_) => {
                    warn!(
                        service = %svc.name,
                        upstream = %addr,
                        "Health check timed out"
                    );
                    false
                }
            };

            self.service_router.set_health(&svc.id, healthy);

            debug!(
                service = %svc.name,
                upstream = %addr,
                healthy = healthy,
                "Health check completed"
            );
        }
    }
}
