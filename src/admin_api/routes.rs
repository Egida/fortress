use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::analytics::collector::MetricsCollector;
use crate::models::threat::ProtectionLevel;
use crate::protection::escalation::EscalationEngine;
use crate::protection::l4_tracker::L4Tracker;
use crate::proxy::connection::ConnectionTracker;
use crate::proxy::service_router::ServiceRouter;
use crate::protection::geoip::GeoIpLookup;
use crate::storage::blocklist::BlocklistManager;
use crate::storage::memory::MemoryStore;
use crate::storage::sqlite::SqliteStore;


/
/
#[derive(Clone)]
pub struct AppState {
    pub memory: Arc<MemoryStore>,
    pub sqlite: Arc<SqliteStore>,
    pub blocklist: Arc<BlocklistManager>,
    pub escalation: Arc<EscalationEngine>,
    pub metrics: Arc<MetricsCollector>,
    pub connections: Arc<ConnectionTracker>,
    pub start_time: Instant,
    pub api_key: String,
    pub service_router: Arc<ServiceRouter>,
    pub l4_tracker: Option<Arc<L4Tracker>>,
    pub settings: Arc<crate::config::settings::Settings>,
    pub ip_reputation: Arc<crate::protection::ip_reputation::IpReputationManager>,
    pub auto_ban: Arc<crate::protection::auto_ban::AutoBanManager>,
    pub distributed: Arc<crate::protection::distributed::DistributedDetector>,
    pub managed_rules: Arc<crate::protection::managed_rules::ManagedRulesEngine>,
    pub geoip: Arc<GeoIpLookup>,
}


#[derive(Debug, Deserialize)]
pub struct HistoryParams {
    pub from: Option<String>,
    pub to: Option<String>,
    pub granularity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BlocklistParams {
    #[serde(rename = "type")]
    pub list_type: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct BlocklistTypeParam {
    #[serde(rename = "type")]
    pub list_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddBlocklistRequest {
    pub value: String,
    #[serde(rename = "type")]
    pub list_type: String,
    pub reason: Option<String>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub condition: Value,
    pub action: String,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub condition: Option<Value>,
    pub action: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SetLevelRequest {
    pub level: String,
}

#[derive(Debug, Deserialize)]
pub struct TopParams {
    pub limit: Option<usize>,
}


/
pub async fn get_status(State(state): State<AppState>) -> Json<Value> {
    let uptime = state.start_time.elapsed().as_secs();
    let snapshot = state.metrics.get_snapshot();
    let level = state.escalation.current_level();

    let level_name = match level {
        ProtectionLevel::L0 => "Normal",
        ProtectionLevel::L1 => "High",
        ProtectionLevel::L2 => "UnderAttack",
        ProtectionLevel::L3 => "Severe",
        ProtectionLevel::L4 => "Emergency",
    };

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime,
        "protection_level": level_name,
        "active_connections": state.connections.active_count(),
        "total_requests_today": snapshot.total_requests,
    }))
}

/
pub async fn get_metrics(State(state): State<AppState>) -> Json<Value> {
    let snapshot = state.metrics.get_snapshot();

    Json(json!({
        "rps": snapshot.rps,
        "blocked_per_sec": snapshot.blocked_per_sec,
        "challenged_per_sec": snapshot.challenged_per_sec,
        "passed_per_sec": snapshot.passed_per_sec,
        "unique_ips": snapshot.unique_ips,
        "avg_latency_ms": snapshot.avg_latency_ms,
        "total_requests": snapshot.total_requests,
        "total_blocked": snapshot.total_blocked,
        "uptime_secs": snapshot.uptime_secs,
    }))
}

/
pub async fn get_metrics_history(
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Json<Value> {
    let granularity = params.granularity.as_deref().unwrap_or("second");

    let seconds_to_fetch: usize = match granularity {
        "minute" => 3600,
        "hour" => 3600,
        _ => 300,
    };

    let history = state.metrics.get_second_history(seconds_to_fetch);

    let data: Vec<Value> = match granularity {
        "minute" => {
            aggregate_snapshots(&history, 60)
        }
        "hour" => {
            aggregate_snapshots(&history, 3600)
        }
        _ => {
            history
                .iter()
                .map(|s| {
                    json!({
                        "timestamp": s.timestamp,
                        "requests": s.requests,
                        "blocked": s.blocked,
                        "challenged": s.challenged,
                        "passed": s.passed,
                    })
                })
                .collect()
        }
    };

    Json(json!({
        "granularity": granularity,
        "from": params.from,
        "to": params.to,
        "data": data,
    }))
}

/
///
/
/
pub async fn get_threats(State(state): State<AppState>) -> Json<Value> {
    let now = Utc::now();
    let from = now - ChronoDuration::hours(24);
    match state.sqlite.get_attacks(from, now) {
        Ok(attacks) => Json(json!({ "threats": attacks })),
        Err(e) => Json(json!({ "error": format!("Failed to load threats: {}", e) })),
    }
}


/
///
/
pub async fn get_blocklist(
    State(state): State<AppState>,
    Query(params): Query<BlocklistParams>,
) -> Json<Value> {
    let list_type = params.list_type.as_deref().unwrap_or("ip");

    match list_type {
        "ip" => match state.sqlite.get_blocked_ips() {
            Ok(entries) => Json(json!({
                "type": list_type,
                "entries": entries,
            })),
            Err(e) => Json(json!({ "error": format!("{}", e) })),
        },
        "asn" => match state.sqlite.get_blocked_asns() {
            Ok(entries) => Json(json!({
                "type": list_type,
                "entries": entries,
            })),
            Err(e) => Json(json!({ "error": format!("{}", e) })),
        },
        "country" => match state.sqlite.get_blocked_countries() {
            Ok(entries) => Json(json!({
                "type": list_type,
                "entries": entries,
            })),
            Err(e) => Json(json!({ "error": format!("{}", e) })),
        },
        _ => Json(json!({ "error": format!("Unknown list type: {}", list_type) })),
    }
}

/
pub async fn add_to_blocklist(
    State(state): State<AppState>,
    Json(body): Json<AddBlocklistRequest>,
) -> Json<Value> {
    let reason = body.reason.as_deref().unwrap_or("manual");
    let duration = body.ttl_secs.map(std::time::Duration::from_secs);

    match body.list_type.as_str() {
        "ip" => {
            match state.blocklist.add_ip(&body.value, reason, "admin_api", duration) {
                Ok(()) => Json(json!({ "status": "added" })),
                Err(e) => Json(json!({ "error": format!("{}", e) })),
            }
        }
        "asn" => {
            let asn: u32 = match body.value.parse() {
                Ok(v) => v,
                Err(_) => return Json(json!({ "error": "Invalid ASN number" })),
            };
            match state.sqlite.add_blocked_asn(asn, None, "block", Some(reason)) {
                Ok(id) => {
                    let _ = state.blocklist.load_from_db();
                    Json(json!({ "id": id, "status": "added" }))
                }
                Err(e) => Json(json!({ "error": format!("{}", e) })),
            }
        }
        "country" => {
            match state.sqlite.add_blocked_country(&body.value, None, "block", Some(reason)) {
                Ok(id) => {
                    let _ = state.blocklist.load_from_db();
                    Json(json!({ "id": id, "status": "added" }))
                }
                Err(e) => Json(json!({ "error": format!("{}", e) })),
            }
        }
        _ => Json(json!({ "error": format!("Unknown list type: {}", body.list_type) })),
    }
}

/
pub async fn remove_from_blocklist(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<BlocklistTypeParam>,
) -> StatusCode {
    let list_type = params.list_type.as_deref().unwrap_or("ip");
    let result = match list_type {
        "ip" => state.blocklist.remove_ip(id),
        "asn" => state.blocklist.remove_asn(id),
        "country" => state.blocklist.remove_country(id),
        _ => return StatusCode::BAD_REQUEST,
    };
    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}


/
pub async fn get_rules(State(state): State<AppState>) -> Json<Value> {
    match state.sqlite.get_rules() {
        Ok(rules) => Json(json!({ "rules": rules })),
        Err(e) => Json(json!({ "error": format!("{}", e) })),
    }
}

/
pub async fn create_rule(
    State(state): State<AppState>,
    Json(body): Json<CreateRuleRequest>,
) -> Json<Value> {
    let priority = body.priority.unwrap_or(0);
    let conditions_str = serde_json::to_string(&body.condition).unwrap_or_default();

    match state
        .sqlite
        .add_rule(&body.name, priority, &conditions_str, &body.action)
    {
        Ok(id) => Json(json!({ "id": id, "status": "created" })),
        Err(e) => Json(json!({ "error": format!("{}", e) })),
    }
}

/
pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateRuleRequest>,
) -> Json<Value> {
    let name = body.name.as_deref().unwrap_or("");
    let priority = body.priority.unwrap_or(0);
    let conditions_str = body
        .condition
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default())
        .unwrap_or_default();
    let action = body.action.as_deref().unwrap_or("");
    let enabled = body.enabled.unwrap_or(true);

    match state.sqlite.update_rule(id, name, priority, &conditions_str, action, enabled) {
        Ok(_) => Json(json!({ "id": id, "status": "updated" })),
        Err(e) => Json(json!({ "error": format!("{}", e) })),
    }
}

/
pub async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> StatusCode {
    match state.sqlite.delete_rule(id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}


/
///
/
pub async fn get_config(State(state): State<AppState>) -> Json<Value> {
    let known_keys = [
        "protection_level",
        "auto_escalation",
        "rate_limit_multiplier",
        "challenge_difficulty",
    ];
    let mut config = serde_json::Map::new();
    for key in &known_keys {
        if let Ok(Some(value)) = state.sqlite.get_config(key) {
            config.insert(key.to_string(), Value::String(value));
        }
    }
    Json(Value::Object(config))
}

/
///
/
/
pub async fn get_settings(State(state): State<AppState>) -> Json<Value> {
    let s = &state.settings;
    Json(json!({
        "bot_whitelist": {
            "enabled": s.bot_whitelist.enabled,
            "verify_ip": s.bot_whitelist.verify_ip,
        },
        "mobile_proxy": {
            "min_signals": s.mobile_proxy.min_signals,
            "score_threshold": s.mobile_proxy.score_threshold,
        },
        "asn_scoring": {
            "datacenter_score": s.asn_scoring.datacenter_score,
            "vpn_score": s.asn_scoring.vpn_score,
            "residential_proxy_score": s.asn_scoring.residential_proxy_score,
        },
        "escalation": {
            "sustained_checks_required": s.escalation.sustained_checks_required,
            "block_ratio_threshold": s.escalation.block_ratio_threshold,
            "deescalation_cooldown_secs": s.escalation.deescalation_cooldown_secs,
            "l0_to_l1_rps": s.escalation.l0_to_l1_rps,
            "l1_to_l2_rps": s.escalation.l1_to_l2_rps,
            "l2_to_l3_rps": s.escalation.l2_to_l3_rps,
            "l3_to_l4_rps": s.escalation.l3_to_l4_rps,
        },
        "challenge": {
            "cookie_subnet_binding": s.challenge.cookie_subnet_binding,
            "nojs_fallback_enabled": s.challenge.nojs_fallback_enabled,
            "pow_difficulty_l1": s.challenge.pow_difficulty_l1,
            "pow_difficulty_l2": s.challenge.pow_difficulty_l2,
            "pow_difficulty_l3": s.challenge.pow_difficulty_l3,
            "cookie_max_age_secs": s.challenge.cookie_max_age_secs,
            "exempt_paths": s.challenge.exempt_paths,
        },
        "blocklist": {
            "country_challenge_score": s.blocklist.country_challenge_score,
            "challenged_countries": s.blocklist.challenged_countries,
            "blocked_countries": s.blocklist.blocked_countries,
        },
        "protection": {
            "default_level": s.protection.default_level,
            "auto_escalation": s.protection.auto_escalation,
            "ipv4_subnet_mask": s.protection.ipv4_subnet_mask,
        },
    }))
}

/
///
/
pub async fn update_config(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    if let Some(obj) = body.as_object() {
        for (key, value) in obj {
            let value_str = match value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if let Err(e) = state.sqlite.set_config(key, &value_str) {
                return Json(json!({ "error": format!("Failed to set {}: {}", key, e) }));
            }
        }
        Json(json!({ "status": "updated" }))
    } else {
        Json(json!({ "error": "Expected a JSON object" }))
    }
}


/
pub async fn set_level(
    State(state): State<AppState>,
    Json(body): Json<SetLevelRequest>,
) -> Json<Value> {
    match ProtectionLevel::from_str_name(&body.level) {
        Some(level) => {
            state.escalation.set_level(level);
            let level_name = match level {
                ProtectionLevel::L0 => "Normal",
                ProtectionLevel::L1 => "High",
                ProtectionLevel::L2 => "UnderAttack",
                ProtectionLevel::L3 => "Severe",
                ProtectionLevel::L4 => "Emergency",
            };
            Json(json!({
                "status": "ok",
                "level": level_name,
            }))
        }
        None => Json(json!({ "error": format!("Unknown protection level: {}", body.level) })),
    }
}


/
pub async fn get_analytics(State(state): State<AppState>) -> Json<Value> {
    let snapshot = state.metrics.get_snapshot();
    let top_ips = state.metrics.get_top_ips(10);
    let top_countries = state.metrics.get_top_countries(10);
    let top_asns = state.metrics.get_top_asns(10);
    let top_fingerprints = state.metrics.get_top_fingerprints(10);

    Json(json!({
        "snapshot": {
            "rps": snapshot.rps,
            "blocked_per_sec": snapshot.blocked_per_sec,
            "challenged_per_sec": snapshot.challenged_per_sec,
            "passed_per_sec": snapshot.passed_per_sec,
            "unique_ips": snapshot.unique_ips,
            "avg_latency_ms": snapshot.avg_latency_ms,
            "total_requests": snapshot.total_requests,
            "total_blocked": snapshot.total_blocked,
        },
        "top_ips": top_ips.iter().map(|(ip, count)| json!({
            "ip": ip.to_string(),
            "count": count,
        })).collect::<Vec<_>>(),
        "top_countries": top_countries.iter().map(|(cc, count)| json!({
            "country": cc,
            "count": count,
        })).collect::<Vec<_>>(),
        "top_asns": top_asns.iter().map(|(asn, count)| json!({
            "asn": asn,
            "count": count,
        })).collect::<Vec<_>>(),
        "top_fingerprints": top_fingerprints.iter().map(|(fp, count)| json!({
            "fingerprint": fp,
            "count": count,
        })).collect::<Vec<_>>(),
    }))
}

/
pub async fn get_top_ips(
    State(state): State<AppState>,
    Query(params): Query<TopParams>,
) -> Json<Value> {
    let limit = params.limit.unwrap_or(50);
    let top = state.metrics.get_top_ips(limit);

    Json(json!({
        "top_ips": top.iter().map(|(ip, count)| json!({
            "ip": ip.to_string(),
            "count": count,
        })).collect::<Vec<_>>(),
    }))
}

/
pub async fn get_top_countries(State(state): State<AppState>) -> Json<Value> {
    let top = state.metrics.get_top_countries(50);

    Json(json!({
        "top_countries": top.iter().map(|(cc, count)| json!({
            "country": cc,
            "count": count,
        })).collect::<Vec<_>>(),
    }))
}

/
pub async fn get_fingerprints(State(state): State<AppState>) -> Json<Value> {
    let top = state.metrics.get_top_fingerprints(50);

    Json(json!({
        "fingerprints": top.iter().map(|(fp, count)| json!({
            "fingerprint": fp,
            "count": count,
        })).collect::<Vec<_>>(),
    }))
}


pub async fn list_services(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let services = state.service_router.list_services();
    let result: Vec<serde_json::Value> = services.iter().map(|svc| {
        serde_json::json!({
            "id": svc.id,
            "name": svc.name,
            "domains": svc.domains,
            "upstream_address": svc.upstream_address,
            "enabled": svc.enabled,
            "protection_level_override": svc.protection_level_override,
            "always_challenge": svc.always_challenge,
            "rate_limit_multiplier": svc.rate_limit_multiplier,
            "max_connections": svc.max_connections,
            "connect_timeout_ms": svc.connect_timeout_ms,
            "response_timeout_ms": svc.response_timeout_ms,
        })
    }).collect();
    Json(result)
}

pub async fn get_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.service_router.get_service(&id) {
        Some(svc) => Json(serde_json::json!({
            "id": svc.id,
            "name": svc.name,
            "domains": svc.domains,
            "upstream_address": svc.upstream_address,
            "enabled": svc.enabled,
            "protection_level_override": svc.protection_level_override,
            "always_challenge": svc.always_challenge,
            "rate_limit_multiplier": svc.rate_limit_multiplier,
            "max_connections": svc.max_connections,
            "connect_timeout_ms": svc.connect_timeout_ms,
            "response_timeout_ms": svc.response_timeout_ms,
        })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateServiceRequest {
    pub id: Option<String>,
    pub name: String,
    pub domains: Vec<String>,
    pub upstream_address: String,
    pub enabled: Option<bool>,
    pub protection_level_override: Option<u8>,
    pub always_challenge: Option<bool>,
    pub rate_limit_multiplier: Option<f64>,
    pub max_connections: Option<usize>,
    pub connect_timeout_ms: Option<u64>,
    pub response_timeout_ms: Option<u64>,
}

pub async fn create_service(
    State(state): State<AppState>,
    Json(body): Json<CreateServiceRequest>,
) -> impl IntoResponse {
    use crate::config::service::ServiceConfig;
    use crate::storage::sqlite::ServiceRow;

    let id = body.id.unwrap_or_else(|| {
        format!("svc-{}", &uuid_simple())
    });

    let config = ServiceConfig {
        id: id.clone(),
        name: body.name.clone(),
        domains: body.domains.clone(),
        upstream_address: body.upstream_address.clone(),
        enabled: body.enabled.unwrap_or(true),
        protection_level_override: body.protection_level_override,
        always_challenge: body.always_challenge.unwrap_or(false),
        rate_limit_multiplier: body.rate_limit_multiplier.unwrap_or(1.0),
        max_connections: body.max_connections.unwrap_or(10_000),
        connect_timeout_ms: body.connect_timeout_ms.unwrap_or(5_000),
        response_timeout_ms: body.response_timeout_ms.unwrap_or(60_000),
        exempt_paths: Vec::new(),
        created_at: None,
        updated_at: None,
    };

    let row = ServiceRow {
        id: config.id.clone(),
        name: config.name.clone(),
        domains: serde_json::to_string(&config.domains).unwrap_or_default(),
        upstream_address: config.upstream_address.clone(),
        enabled: config.enabled,
        protection_level_override: config.protection_level_override.map(|v| v as i32),
        always_challenge: config.always_challenge,
        rate_limit_multiplier: config.rate_limit_multiplier,
        max_connections: config.max_connections as i64,
        connect_timeout_ms: config.connect_timeout_ms as i64,
        response_timeout_ms: config.response_timeout_ms as i64,
        exempt_paths: None,
        created_at: String::new(),
        updated_at: String::new(),
    };
    let _ = state.sqlite.add_service(&row);

    state.service_router.add_service(config);

    (StatusCode::CREATED, Json(serde_json::json!({"id": id, "status": "created"})))
}

pub async fn update_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CreateServiceRequest>,
) -> impl IntoResponse {
    use crate::config::service::ServiceConfig;
    use crate::storage::sqlite::ServiceRow;

    let config = ServiceConfig {
        id: id.clone(),
        name: body.name.clone(),
        domains: body.domains.clone(),
        upstream_address: body.upstream_address.clone(),
        enabled: body.enabled.unwrap_or(true),
        protection_level_override: body.protection_level_override,
        always_challenge: body.always_challenge.unwrap_or(false),
        rate_limit_multiplier: body.rate_limit_multiplier.unwrap_or(1.0),
        max_connections: body.max_connections.unwrap_or(10_000),
        connect_timeout_ms: body.connect_timeout_ms.unwrap_or(5_000),
        response_timeout_ms: body.response_timeout_ms.unwrap_or(60_000),
        exempt_paths: Vec::new(),
        created_at: None,
        updated_at: None,
    };

    let row = ServiceRow {
        id: config.id.clone(),
        name: config.name.clone(),
        domains: serde_json::to_string(&config.domains).unwrap_or_default(),
        upstream_address: config.upstream_address.clone(),
        enabled: config.enabled,
        protection_level_override: config.protection_level_override.map(|v| v as i32),
        always_challenge: config.always_challenge,
        rate_limit_multiplier: config.rate_limit_multiplier,
        max_connections: config.max_connections as i64,
        connect_timeout_ms: config.connect_timeout_ms as i64,
        response_timeout_ms: config.response_timeout_ms as i64,
        exempt_paths: None,
        created_at: String::new(),
        updated_at: String::new(),
    };
    let _ = state.sqlite.update_service(&row);
    state.service_router.update_service(config);

    Json(serde_json::json!({"status": "updated"}))
}

pub async fn delete_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.service_router.remove_service(&id);
    let _ = state.sqlite.delete_service(&id);
    Json(serde_json::json!({"status": "deleted"}))
}

pub async fn toggle_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(svc) = state.service_router.get_service(&id) {
        let mut updated = (*svc).clone();
        updated.enabled = !updated.enabled;
        let new_enabled = updated.enabled;

        state.service_router.update_service(updated);

        if let Ok(Some(row)) = state.sqlite.get_service(&id) {
            let mut row = row;
            row.enabled = new_enabled;
            let _ = state.sqlite.update_service(&row);
        }

        Json(serde_json::json!({"status": "toggled", "enabled": new_enabled}))
    } else {
        Json(serde_json::json!({"error": "not found"}))
    }
}


pub async fn get_l4_metrics(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match &state.l4_tracker {
        Some(l4) => Json(serde_json::json!(l4.get_metrics())).into_response(),
        None => Json(serde_json::json!({"error": "L4 protection not enabled"})).into_response(),
    }
}

pub async fn get_l4_events(
    State(state): State<AppState>,
    Query(params): Query<TopParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100) as usize;
    match state.sqlite.get_l4_events(limit) {
        Ok(events) => Json(serde_json::json!(events)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let rand_part: u64 = rand::random();
    format!("{:x}{:08x}", ts, rand_part as u32)
}



/
pub async fn get_ip_reputation(
    State(state): State<AppState>,
    Query(params): Query<TopParams>,
) -> Json<Value> {
    let limit = params.limit.unwrap_or(50);
    let top_ips = state.ip_reputation.get_top_ips(limit);

    let ips: Vec<Value> = top_ips.iter().map(|(ip, score, total, blocked, cats)| {
        let country = state.geoip.lookup_country(*ip);
        let city = state.geoip.lookup_city(*ip);
        let asn_info = state.geoip.lookup_asn(*ip);

        json!({
            "ip": ip.to_string(),
            "score": score,
            "total_requests": total,
            "blocked_count": blocked,
            "categories": cats,
            "country": country,
            "city": city,
            "asn": asn_info.as_ref().map(|(asn, _)| *asn),
            "asn_org": asn_info.as_ref().map(|(_, org)| org.clone()),
        })
    }).collect();

    Json(json!({
        "tracked_count": state.ip_reputation.tracked_count(),
        "ips": ips,
    }))
}


/
pub async fn get_auto_bans(State(state): State<AppState>) -> Json<Value> {
    let bans = state.auto_ban.get_active_bans();

    let bans_list: Vec<Value> = bans.iter().map(|(ip, reason, remaining, total)| {
        let country = state.geoip.lookup_country(*ip);
        let city = state.geoip.lookup_city(*ip);
        let asn_info = state.geoip.lookup_asn(*ip);

        json!({
            "ip": ip.to_string(),
            "reason": reason,
            "remaining_secs": remaining,
            "total_duration_secs": total,
            "country": country,
            "city": city,
            "asn": asn_info.as_ref().map(|(asn, _)| *asn),
            "asn_org": asn_info.as_ref().map(|(_, org)| org.clone()),
        })
    }).collect();

    Json(json!({
        "active_count": state.auto_ban.active_ban_count(),
        "bans": bans_list,
    }))
}

/
pub async fn get_ip_info(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => {
            let country = state.geoip.lookup_country(addr);
            let city = state.geoip.lookup_city(addr);
            let asn_info = state.geoip.lookup_asn(addr);
            let reputation = state.ip_reputation.get_score(&addr);
            let ban_reason = state.auto_ban.is_banned(&addr);

            (StatusCode::OK, Json(json!({
                "ip": ip,
                "country": country,
                "city": city,
                "asn": asn_info.as_ref().map(|(asn, _)| *asn),
                "asn_org": asn_info.as_ref().map(|(_, org)| org.clone()),
                "reputation_score": reputation,
                "is_banned": ban_reason.is_some(),
                "ban_reason": ban_reason,
            }))).into_response()
        }
        Err(_) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid IP address"}))).into_response()
        }
    }
}

/
pub async fn unban_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => {
            if state.auto_ban.unban(&addr) {
                (StatusCode::OK, Json(json!({"message": "IP unbanned"}))).into_response()
            } else {
                (StatusCode::NOT_FOUND, Json(json!({"error": "IP not found in ban list"}))).into_response()
            }
        }
        Err(_) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid IP address"}))).into_response()
        }
    }
}


/
pub async fn get_managed_rules(State(state): State<AppState>) -> Json<Value> {
    let rules = state.managed_rules.get_rules();

    let rules_list: Vec<Value> = rules.iter().map(|(id, name, desc, enabled)| {
        json!({
            "id": id,
            "name": name,
            "description": desc,
            "enabled": enabled,
        })
    }).collect();

    Json(json!({ "rules": rules_list }))
}

/
pub async fn toggle_managed_rule(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

    if state.managed_rules.set_rule_enabled(id, enabled) {
        (StatusCode::OK, Json(json!({"message": "Rule updated", "id": id, "enabled": enabled}))).into_response()
    } else {
        (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid rule ID"}))).into_response()
    }
}


/
pub async fn get_distributed_attacks(State(state): State<AppState>) -> Json<Value> {
    let (total, unique_ips, new_ips, active) = state.distributed.get_stats();
    let last_attack = state.distributed.get_last_attack();

    let attack_info = last_attack.map(|a| {
        json!({
            "signals": a.signals,
            "top_path": a.top_path,
            "request_count": a.request_count,
            "unique_ips": a.unique_ips,
            "new_ip_ratio": a.new_ip_ratio,
        })
    });

    Json(json!({
        "current_window": {
            "total_requests": total,
            "unique_ips": unique_ips,
            "new_ips": new_ips,
            "attack_active": active,
        },
        "last_attack": attack_info,
    }))
}


/
pub async fn get_threat_summary(State(state): State<AppState>) -> Json<Value> {
    let snapshot = state.metrics.get_snapshot();
    let level = state.escalation.current_level();
    let (dist_total, dist_ips, dist_new, dist_active) = state.distributed.get_stats();

    let level_str = match level {
        ProtectionLevel::L0 => "L0",
        ProtectionLevel::L1 => "L1",
        ProtectionLevel::L2 => "L2",
        ProtectionLevel::L3 => "L3",
        ProtectionLevel::L4 => "L4",
    };

    Json(json!({
        "protection_level": level_str,
        "rps": snapshot.rps,
        "block_rate": if snapshot.rps > 0.0 { snapshot.blocked_per_sec / snapshot.rps * 100.0 } else { 0.0 },
        "active_connections": state.connections.active_count(),
        "auto_ban_count": state.auto_ban.active_ban_count(),
        "ip_reputation_tracked": state.ip_reputation.tracked_count(),
        "distributed_attack_active": dist_active,
        "distributed_window_requests": dist_total,
        "distributed_unique_ips": dist_ips,
    }))
}


fn aggregate_snapshots(
    snapshots: &[crate::analytics::collector::SecondSnapshot],
    bucket_secs: u64,
) -> Vec<Value> {
    if snapshots.is_empty() {
        return Vec::new();
    }

    let mut buckets: Vec<Value> = Vec::new();
    let mut bucket_start = snapshots[0].timestamp / bucket_secs * bucket_secs;
    let mut acc_requests: u64 = 0;
    let mut acc_blocked: u64 = 0;
    let mut acc_challenged: u64 = 0;
    let mut acc_passed: u64 = 0;

    for snap in snapshots {
        let snap_bucket = snap.timestamp / bucket_secs * bucket_secs;
        if snap_bucket != bucket_start {
            buckets.push(json!({
                "timestamp": bucket_start,
                "requests": acc_requests,
                "blocked": acc_blocked,
                "challenged": acc_challenged,
                "passed": acc_passed,
            }));
            bucket_start = snap_bucket;
            acc_requests = 0;
            acc_blocked = 0;
            acc_challenged = 0;
            acc_passed = 0;
        }
        acc_requests += snap.requests;
        acc_blocked += snap.blocked;
        acc_challenged += snap.challenged;
        acc_passed += snap.passed;
    }

    buckets.push(json!({
        "timestamp": bucket_start,
        "requests": acc_requests,
        "blocked": acc_blocked,
        "challenged": acc_challenged,
        "passed": acc_passed,
    }));

    buckets
}
