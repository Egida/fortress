use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use dashmap::DashMap;
use tracing::info;

use crate::config::service::ServiceConfig;
use crate::storage::sqlite::SqliteStore;

/// Per-service health state.
struct ServiceHealth {
    config: Arc<ServiceConfig>,
    healthy: AtomicBool,
}

/// Routes incoming requests to the correct backend service based on the Host header.
pub struct ServiceRouter {
    /// domain -> service_id
    domain_map: DashMap<String, String>,
    /// service_id -> ServiceHealth
    services: DashMap<String, Arc<ServiceHealth>>,
    /// Fallback upstream address if no service matches
    default_upstream: std::sync::RwLock<String>,
}

impl ServiceRouter {
    pub fn new(default_upstream: &str) -> Self {
        Self {
            domain_map: DashMap::new(),
            services: DashMap::new(),
            default_upstream: std::sync::RwLock::new(default_upstream.to_string()),
        }
    }

    /// Resolve which service handles the given host.
    /// Returns None if no service matches or if the service is unhealthy.
    pub fn resolve(&self, host: &str) -> Option<Arc<ServiceConfig>> {
        let clean_host = host.split(':').next().unwrap_or(host).to_lowercase();
        let service_id = self.domain_map.get(&clean_host)?;
        let health = self.services.get(service_id.value())?;
        Some(health.config.clone())
    }

    /// Check if a service is healthy.
    pub fn is_healthy(&self, service_id: &str) -> bool {
        self.services
            .get(service_id)
            .map(|h| h.healthy.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Set the health status of a service.
    pub fn set_health(&self, service_id: &str, healthy: bool) {
        if let Some(h) = self.services.get(service_id) {
            h.healthy.store(healthy, Ordering::Relaxed);
        }
    }

    /// Get the default upstream address (used when no service matches).
    pub fn default_upstream(&self) -> String {
        self.default_upstream.read().unwrap().clone()
    }

    /// Add a service and register all its domains.
    pub fn add_service(&self, config: ServiceConfig) {
        let arc = Arc::new(config.clone());
        let health = Arc::new(ServiceHealth {
            config: arc,
            healthy: AtomicBool::new(true), // assume healthy until proven otherwise
        });
        for domain in &config.domains {
            let clean = domain.to_lowercase();
            self.domain_map.insert(clean, config.id.clone());
        }
        info!(service_id = %config.id, name = %config.name, domains = ?config.domains, "Service registered");
        self.services.insert(config.id.clone(), health);
    }

    /// Remove a service and unregister all its domains.
    pub fn remove_service(&self, id: &str) {
        if let Some((_, health)) = self.services.remove(id) {
            for domain in &health.config.domains {
                let clean = domain.to_lowercase();
                self.domain_map.remove(&clean);
            }
            info!(service_id = %id, "Service removed");
        }
    }

    /// Update a service (remove old domain mappings, add new ones).
    pub fn update_service(&self, config: ServiceConfig) {
        self.remove_service(&config.id);
        self.add_service(config);
    }

    /// List all services.
    pub fn list_services(&self) -> Vec<Arc<ServiceConfig>> {
        self.services.iter().map(|r| r.value().config.clone()).collect()
    }

    /// Get a single service by ID.
    pub fn get_service(&self, id: &str) -> Option<Arc<ServiceConfig>> {
        self.services.get(id).map(|r| r.value().config.clone())
    }

    /// Load services from the SQLite database.
    pub fn load_from_db(&self, sqlite: &SqliteStore) -> anyhow::Result<()> {
        let rows = sqlite.get_services().map_err(|e| anyhow::anyhow!("Failed to load services: {}", e))?;
        for row in rows {
            let domains: Vec<String> = serde_json::from_str(&row.domains).unwrap_or_default();
            let exempt_paths: Vec<String> = row.exempt_paths
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let config = ServiceConfig {
                id: row.id,
                name: row.name,
                domains,
                upstream_address: row.upstream_address,
                enabled: row.enabled,
                protection_level_override: row.protection_level_override.map(|v| v as u8),
                always_challenge: row.always_challenge,
                rate_limit_multiplier: row.rate_limit_multiplier,
                max_connections: row.max_connections as usize,
                connect_timeout_ms: row.connect_timeout_ms as u64,
                response_timeout_ms: row.response_timeout_ms as u64,
                exempt_paths,
                created_at: Some(row.created_at),
                updated_at: Some(row.updated_at),
            };
            if config.enabled {
                self.add_service(config);
            }
        }
        Ok(())
    }

    /// Load services from the TOML config.
    pub fn load_from_config(&self, services: &[ServiceConfig]) {
        for svc in services {
            if svc.enabled {
                self.add_service(svc.clone());
            }
        }
    }

    /// Total number of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }
}
