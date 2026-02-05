use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::admin_api::{auth, routes, websocket};
use crate::admin_api::routes::AppState;

/
pub struct AdminApiServer {
    state: AppState,
    bind_addr: String,
}

impl AdminApiServer {
    pub fn new(state: AppState, bind_addr: String) -> Self {
        Self { state, bind_addr }
    }

    /
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = self.state.clone();
        let api_key = state.api_key.clone();

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/api/fortress/status", get(routes::get_status))
            .route("/api/fortress/metrics", get(routes::get_metrics))
            .route(
                "/api/fortress/metrics/history",
                get(routes::get_metrics_history),
            )
            .route("/api/fortress/live", get(websocket::live_traffic_handler))
            .route("/api/fortress/threats", get(routes::get_threats))
            .route(
                "/api/fortress/blocklist",
                get(routes::get_blocklist).post(routes::add_to_blocklist),
            )
            .route(
                "/api/fortress/blocklist/{id}",
                delete(routes::remove_from_blocklist),
            )
            .route(
                "/api/fortress/rules",
                get(routes::get_rules).post(routes::create_rule),
            )
            .route(
                "/api/fortress/rules/{id}",
                put(routes::update_rule).delete(routes::delete_rule),
            )
            .route(
                "/api/fortress/config",
                get(routes::get_config).put(routes::update_config),
            )
            .route("/api/fortress/settings", get(routes::get_settings))
            .route("/api/fortress/level", post(routes::set_level))
            .route("/api/fortress/analytics", get(routes::get_analytics))
            .route("/api/fortress/top-ips", get(routes::get_top_ips))
            .route(
                "/api/fortress/top-countries",
                get(routes::get_top_countries),
            )
            .route("/api/fortress/fingerprints", get(routes::get_fingerprints))
            .route("/api/fortress/services", get(routes::list_services).post(routes::create_service))
            .route("/api/fortress/services/{id}", get(routes::get_service).put(routes::update_service).delete(routes::delete_service))
            .route("/api/fortress/services/{id}/toggle", post(routes::toggle_service))
            .route("/api/fortress/l4/metrics", get(routes::get_l4_metrics))
            .route("/api/fortress/l4/events", get(routes::get_l4_events))
            .route("/api/fortress/ip-reputation", get(routes::get_ip_reputation))
            .route("/api/fortress/auto-bans", get(routes::get_auto_bans))
            .route("/api/fortress/auto-bans/{ip}", delete(routes::unban_ip))
            .route("/api/fortress/ip-lookup/{ip}", get(routes::get_ip_info))
            .route("/api/fortress/managed-rules", get(routes::get_managed_rules))
            .route("/api/fortress/managed-rules/{id}", put(routes::toggle_managed_rule))
            .route("/api/fortress/distributed-attacks", get(routes::get_distributed_attacks))
            .route("/api/fortress/threat-summary", get(routes::get_threat_summary))
            .layer(middleware::from_fn_with_state(
                api_key,
                auth::auth_middleware,
            ))
            .layer(cors)
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(&self.bind_addr).await?;
        info!("Admin API listening on {}", self.bind_addr);
        axum::serve(listener, app).await?;

        Ok(())
    }
}
