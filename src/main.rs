mod admin_api;
mod analytics;
mod config;
mod models;
mod protection;
mod proxy;
mod storage;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::admin_api::routes::AppState;
use crate::admin_api::server::AdminApiServer;
use crate::analytics::alerting::AlertManager;
use crate::analytics::collector::MetricsCollector;
use crate::analytics::reporter::MetricsReporter;
use crate::config::settings::Settings;
use crate::protection::asn::AsnClassifier;
use crate::protection::auto_ban::AutoBanManager;
use crate::protection::distributed::DistributedDetector;
use crate::protection::custom_rules::CustomRulesEngine;
use crate::protection::managed_rules::ManagedRulesEngine;
use crate::protection::behavioral::BehavioralAnalyzer;
use crate::protection::bot_whitelist::BotWhitelist;
use crate::protection::challenge::ChallengeSystem;
use crate::protection::escalation::EscalationEngine;
use crate::protection::fingerprint::FingerprintAnalyzer;
use crate::protection::geoip::GeoIpLookup;
use crate::protection::header_analysis::HeaderAnalyzer;
use crate::protection::ip_reputation::IpReputationManager;
use crate::protection::l4_tracker::L4Tracker;
use crate::protection::mobile_proxy::MobileProxyDetector;
use crate::protection::pipeline::ProtectionPipeline;
use crate::protection::rate_limiter::RateLimiter;
use crate::protection::slowloris::SlowlorisDetector;
use crate::proxy::connection::ConnectionTracker;
use crate::proxy::health_check::HealthChecker;
use crate::proxy::http_handler::HttpHandler;
use crate::proxy::server::ProxyServer;
use crate::proxy::service_router::ServiceRouter;
use crate::proxy::tls::build_tls_config;
use crate::storage::blocklist::BlocklistManager;
use crate::storage::memory::MemoryStore;
use crate::storage::sqlite::SqliteStore;

/// Parse the `--config` CLI flag. Defaults to `/opt/fortress/config/fortress.toml`.
fn parse_config_path() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = String::from("/opt/fortress/config/fortress.toml");

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" {
            if let Some(path) = args.get(i + 1) {
                config_path = path.clone();
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    config_path
}

/// Initialise the `tracing` subscriber with both stdout and file output.
fn init_tracing(log_dir: &str) {
    let _ = std::fs::create_dir_all(log_dir);

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}/fortress.log", log_dir))
        .expect("Failed to open log file");

    let file_layer = fmt::layer()
        .with_writer(log_file)
        .with_ansi(false)
        .with_target(true);

    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(true);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,fortress=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
}

/// Background task that periodically evicts expired entries from the
/// in-memory store, L4 tracker, slowloris detector, auto-ban, and IP reputation.
async fn cleanup_loop(
    memory: Arc<MemoryStore>,
    l4_tracker: Option<Arc<L4Tracker>>,
    slowloris: Arc<SlowlorisDetector>,
    auto_ban: Arc<AutoBanManager>,
    ip_reputation: Arc<IpReputationManager>,
    distributed: Arc<DistributedDetector>,
    managed_rules: Arc<ManagedRulesEngine>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        memory.cleanup();
        if let Some(ref l4) = l4_tracker {
            l4.cleanup();
        }
        slowloris.cleanup();
        auto_ban.cleanup();
        ip_reputation.cleanup();
        distributed.cleanup();
        managed_rules.cleanup();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    // ---------------------------------------------------------------
    // 1. Configuration
    // ---------------------------------------------------------------
    let config_path = parse_config_path();
    let settings = Settings::load(&config_path)?;
    let settings = Arc::new(settings);

    // ---------------------------------------------------------------
    // 2. Logging
    // ---------------------------------------------------------------
    let log_dir = std::path::Path::new(&settings.logging.file)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("/opt/fortress/logs")
        .to_string();
    init_tracing(&log_dir);

    info!("Starting Fortress anti-DDoS reverse proxy");
    info!("Config loaded from {}", config_path);

    // ---------------------------------------------------------------
    // 3. Storage
    // ---------------------------------------------------------------
    let sqlite = Arc::new(
        SqliteStore::new(&settings.storage.sqlite_path)
            .expect("Failed to initialise SQLite store"),
    );

    let memory = Arc::new(MemoryStore::new());

    let blocklist = Arc::new(BlocklistManager::new(memory.clone(), sqlite.clone()));
    blocklist
        .load_from_db()
        .expect("Failed to load blocklist from database");

    // ---------------------------------------------------------------
    // 3.5 Load config blocklists into database
    // ---------------------------------------------------------------
    for country in &settings.blocklist.blocked_countries {
        if let Err(e) = sqlite.add_blocked_country(country, None, "block", Some("config")) {
            warn!("Failed to load blocked country {}: {}", country, e);
        }
    }
    for country in &settings.blocklist.challenged_countries {
        if let Err(e) = sqlite.add_blocked_country(country, None, "challenge", Some("config")) {
            warn!("Failed to load challenged country {}: {}", country, e);
        }
    }
    for asn in &settings.blocklist.blocked_asns {
        if let Err(e) = sqlite.add_blocked_asn(*asn, None, "block", Some("config")) {
            warn!("Failed to load blocked ASN {}: {}", asn, e);
        }
    }
    // Reload blocklist after config additions
    if let Err(e) = blocklist.load_from_db() {
        warn!("Failed to reload blocklist: {}", e);
    }

    info!("Storage layer initialised");

    // ---------------------------------------------------------------
    // Service Router
    // ---------------------------------------------------------------
    let service_router = Arc::new(ServiceRouter::new(&settings.upstream.address));
    service_router.load_from_db(&sqlite)?;
    service_router.load_from_config(&settings.services);
    info!("Loaded {} services", service_router.service_count());

    // ---------------------------------------------------------------
    // 4. Protection components
    // ---------------------------------------------------------------
    let geoip = Arc::new(
        GeoIpLookup::new(&settings.geoip.city_db, &settings.geoip.asn_db),
    );

    let asn_classifier = Arc::new(AsnClassifier::new());

    let rate_limiter = Arc::new(RateLimiter::new(memory.clone()));
    let fingerprint_analyzer = Arc::new(FingerprintAnalyzer::new());
    let challenge_system = Arc::new(ChallengeSystem::new(&settings.challenge, memory.clone()));
    let behavioral_analyzer = Arc::new(BehavioralAnalyzer::new(memory.clone()));
    let mobile_proxy_detector = Arc::new(MobileProxyDetector::new(asn_classifier.clone(), &settings.mobile_proxy));
    let header_analyzer = Arc::new(HeaderAnalyzer::new());
    let slowloris_detector = Arc::new(SlowlorisDetector::new());

    let escalation = Arc::new(EscalationEngine::with_config(&settings));
    let bot_whitelist = Arc::new(BotWhitelist::new(&settings.bot_whitelist));
    let ip_reputation = Arc::new(IpReputationManager::new(&settings.ip_reputation));
    let auto_ban = Arc::new(AutoBanManager::new(&settings.auto_ban));
    let distributed = Arc::new(DistributedDetector::new());
    let managed_rules = Arc::new(ManagedRulesEngine::new());
    let custom_rules = Arc::new(CustomRulesEngine::new(Arc::clone(&sqlite)));

    // Apply default protection level from config
    if settings.protection.default_level > 0 {
        if let Some(level) = crate::models::threat::ProtectionLevel::from_u8(settings.protection.default_level) {
            escalation.set_level(level);
            info!("Default protection level set to L{}", settings.protection.default_level);
        }
    }

    let pipeline = Arc::new(ProtectionPipeline {
        rate_limiter: rate_limiter.clone(),
        geoip: geoip.clone(),
        fingerprint: fingerprint_analyzer.clone(),
        challenge: challenge_system.clone(),
        behavioral: behavioral_analyzer.clone(),
        mobile_proxy: mobile_proxy_detector.clone(),
        header_analysis: header_analyzer.clone(),
        escalation: escalation.clone(),
        blocklist: blocklist.clone(),
        memory: memory.clone(),
        bot_whitelist: bot_whitelist.clone(),
        asn_classifier: asn_classifier.clone(),
        ip_reputation: ip_reputation.clone(),
        auto_ban: auto_ban.clone(),
        distributed: distributed.clone(),
        managed_rules: managed_rules.clone(),
        custom_rules: custom_rules.clone(),
    });

    info!("Protection pipeline initialised");

    // ---------------------------------------------------------------
    // L4 Protection
    // ---------------------------------------------------------------
    let l4_tracker = if settings.l4_protection.enabled {
        let tracker = Arc::new(L4Tracker::new(settings.l4_protection.clone()));
        info!("L4 TCP protection enabled");
        Some(tracker)
    } else {
        info!("L4 TCP protection disabled");
        None
    };

    // ---------------------------------------------------------------
    // 5. Proxy infrastructure
    // ---------------------------------------------------------------
    let connections = Arc::new(ConnectionTracker::new());
    let metrics = Arc::new(MetricsCollector::new());

    let http_handler = Arc::new(HttpHandler::new(
        pipeline.clone(),
        service_router.clone(),
        memory.clone(),
        connections.clone(),
        metrics.clone(),
        settings.clone(),
        challenge_system.clone(),
    ));

    let tls_config = build_tls_config(&settings.tls.cert_dir).ok();
    if tls_config.is_some() {
        info!("TLS configuration loaded");
    } else {
        info!("Running without TLS (plain HTTP mode)");
    }

    let tls_server_config = match tls_config {
        Some(config) => Arc::new(config),
        None => {
            info!("No valid TLS certificates found; HTTPS will not work until certs are configured.");
            Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(
                        crate::proxy::tls::FortressCertResolver::load_certs(&settings.tls.cert_dir),
                    )),
            )
        }
    };

    let proxy_server = ProxyServer::new(
        settings.clone(),
        tls_server_config,
        http_handler.clone(),
        connections.clone(),
        l4_tracker.clone(),
        sqlite.clone(),
        slowloris_detector.clone(),
    );

    info!("Proxy server configured");

    // ---------------------------------------------------------------
    // 6. Admin API
    // ---------------------------------------------------------------
    let admin_state = AppState {
        memory: memory.clone(),
        sqlite: sqlite.clone(),
        blocklist: blocklist.clone(),
        escalation: escalation.clone(),
        metrics: metrics.clone(),
        connections: connections.clone(),
        start_time: Instant::now(),
        api_key: settings.admin_api.api_key.clone(),
        service_router: service_router.clone(),
        l4_tracker: l4_tracker.clone(),
        settings: settings.clone(),
        ip_reputation: ip_reputation.clone(),
        auto_ban: auto_ban.clone(),
        distributed: distributed.clone(),
        managed_rules: managed_rules.clone(),
        geoip: geoip.clone(),
    };

    let admin_bind = settings.admin_api.bind.clone();

    let admin_server = AdminApiServer::new(admin_state, admin_bind.clone());

    info!("Admin API will listen on {}", admin_bind);

    // ---------------------------------------------------------------
    // 7. Alerting
    // ---------------------------------------------------------------
    let alerting = if settings.alerting.enabled {
        let manager = Arc::new(AlertManager::new(
            settings.alerting.webhook_url.clone(),
            true,
        ));
        info!("Alerting enabled");
        Some(manager)
    } else {
        info!("Alerting disabled");
        None
    };

    // ---------------------------------------------------------------
    // 8. Metrics reporter
    // ---------------------------------------------------------------
    let reporter = MetricsReporter::new(
        metrics.clone(),
        sqlite.clone(),
        escalation.clone(),
        settings.clone(),
        alerting.clone(),
    );

    // ---------------------------------------------------------------
    // 9. Health checker
    // ---------------------------------------------------------------
    let health_checker = Arc::new(HealthChecker::new(
        service_router.clone(),
        10, // check every 10 seconds
        5000, // 5 second timeout
    ));

    // ---------------------------------------------------------------
    // 10. Spawn everything
    // ---------------------------------------------------------------
    let memory_clone = memory.clone();
    let l4_tracker_cleanup = l4_tracker.clone();
    let slowloris_cleanup = slowloris_detector.clone();
    let auto_ban_cleanup = auto_ban.clone();
    let ip_reputation_cleanup = ip_reputation.clone();
    let distributed_cleanup = distributed.clone();
    let managed_rules_cleanup = managed_rules.clone();

    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy_server.run().await {
            error!("Proxy server error: {}", e);
        }
    });

    let admin_handle = tokio::spawn(async move {
        if let Err(e) = admin_server.run().await {
            error!("Admin API server error: {}", e);
        }
    });

    let reporter_handle = tokio::spawn(async move {
        reporter.run().await;
    });

    let cleanup_handle = tokio::spawn(cleanup_loop(
        memory_clone,
        l4_tracker_cleanup,
        slowloris_cleanup,
        auto_ban_cleanup,
        ip_reputation_cleanup,
        distributed_cleanup,
        managed_rules_cleanup,
    ));

    let health_handle = tokio::spawn(async move {
        health_checker.run().await;
    });

    info!("Fortress is running. Press Ctrl+C to shut down.");

    // ---------------------------------------------------------------
    // 11. Wait for shutdown signal
    // ---------------------------------------------------------------
    tokio::signal::ctrl_c().await?;
    info!("Shutting down Fortress...");

    // Cancel background tasks.
    proxy_handle.abort();
    admin_handle.abort();
    reporter_handle.abort();
    cleanup_handle.abort();
    health_handle.abort();

    info!("Fortress shut down gracefully");
    Ok(())
}
