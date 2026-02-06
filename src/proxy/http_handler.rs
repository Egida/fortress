use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use tracing::{debug, error, info, warn};

use crate::analytics::collector::MetricsCollector;
use crate::config::settings::Settings;
use crate::models::request::RequestContext;
use crate::models::threat::ThreatAction;
use crate::protection::challenge::ChallengeSystem;
use crate::protection::pipeline::ProtectionPipeline;
use crate::proxy::service_router::ServiceRouter;
use crate::storage::memory::MemoryStore;

use super::access_log::AccessLogger;
use super::connection::ConnectionTracker;

/// Core HTTP request handler for the Fortress reverse proxy.
///
/// For every incoming request the handler:
///
/// 1. Extracts metadata (IP, host, path, headers, JA3, ...).
/// 2. Constructs a [`RequestContext`].
/// 3. Runs the [`ProtectionPipeline`].
/// 4. Forwards legitimate traffic to the upstream backend or returns a
///    block / challenge response.
/// 5. Records the outcome in the [`MetricsCollector`].
pub struct HttpHandler {
    pipeline: Arc<ProtectionPipeline>,
    service_router: Arc<ServiceRouter>,
    #[allow(dead_code)]
    memory: Arc<MemoryStore>,
    connections: Arc<ConnectionTracker>,
    metrics: Arc<MetricsCollector>,
    settings: Arc<Settings>,
    challenge: Arc<ChallengeSystem>,
    upstream_client: HyperClient<HttpConnector, Full<Bytes>>,
    access_log: Option<Arc<AccessLogger>>,
}

impl HttpHandler {
    /// Create a new handler.
    pub fn new(
        pipeline: Arc<ProtectionPipeline>,
        service_router: Arc<ServiceRouter>,
        memory: Arc<MemoryStore>,
        connections: Arc<ConnectionTracker>,
        metrics: Arc<MetricsCollector>,
        settings: Arc<Settings>,
        challenge: Arc<ChallengeSystem>,
    ) -> Self {
        let upstream_client = HyperClient::builder(TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(128)
            .build_http();

        // Initialise the per-request access logger (best-effort).
        let access_log = if !settings.logging.access_log.is_empty() {
            match AccessLogger::new(&settings.logging.access_log) {
                Ok(logger) => {
                    info!("Access log enabled: {}", settings.logging.access_log);
                    Some(Arc::new(logger))
                }
                Err(e) => {
                    error!("Failed to open access log {}: {}", settings.logging.access_log, e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            pipeline,
            service_router,
            memory,
            connections,
            metrics,
            settings,
            challenge,
            upstream_client,
            access_log,
        }
    }

    /// Process a single inbound HTTP request end-to-end.
    pub async fn handle(
        &self,
        req: Request<Incoming>,
        client_ip: IpAddr,
        ja3_hash: Option<String>,
        conn_id: u64,
    ) -> Response<Full<Bytes>> {
        let start = std::time::Instant::now();

        // Track the request.
        self.connections.increment_requests(conn_id);

        // --- Extract request metadata ---
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let query_string = req.uri().query().map(|q| q.to_string());
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Associate host with the connection for observability.
        if !host.is_empty() {
            self.connections.set_host(conn_id, host.clone());
        }

        // Resolve service from Host header
        let resolved_service = self.service_router.resolve(&host);
        let upstream_addr = match &resolved_service {
            Some(svc) if svc.enabled => svc.upstream_address.clone(),
            Some(_) => {
                return Response::builder()
                    .status(503)
                    .body(Full::new(Bytes::from("Service Unavailable")))
                    .unwrap();
            }
            None => self.service_router.default_upstream(),
        };

        let real_ip = extract_client_ip(&req, client_ip, self.settings.cloudflare.enabled);
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        debug!(
            client_ip = %real_ip,
            method = %method,
            path = %path,
            host = %host,
            "Incoming request"
        );

        // --- Internal endpoints ---
        if path == "/__fortress/nojs-verify" {
            let query = req.uri().query().unwrap_or("").to_string();
            return self.handle_nojs_verification(&query, real_ip);
        }

        if path == "/__fortress/verify" {
            let query = req.uri().query().unwrap_or("").to_string();
            return self.handle_challenge_verification(&query, real_ip);
        }

        // --- Collect headers as HashMap ---
        let headers: HashMap<String, String> = req
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        // CORS preflight requests bypass protection
        if method == "OPTIONS" {
            debug!(client_ip = %real_ip, path = %path, "CORS preflight - bypassing protection");
            return self.forward_to_backend(
                &method,
                &path,
                query_string.as_deref(),
                &host,
                &headers,
                Bytes::new(),
                real_ip,
                &upstream_addr,
            ).await;
        }

        // --- Build RequestContext ---
        let mut ctx = RequestContext::new(real_ip, method.clone(), path.clone(), host.clone());
        ctx.is_behind_cloudflare = self.settings.cloudflare.enabled && crate::protection::cloudflare::is_cloudflare_ip(client_ip);
        ctx.ja3_hash = ja3_hash.clone();
        ctx.user_agent = if user_agent.is_empty() {
            None
        } else {
            Some(user_agent.clone())
        };
        ctx.headers = headers.clone();

        // Use Cloudflare's country header when available (more accurate than GeoIP for CF traffic)
        if ctx.is_behind_cloudflare {
            if let Some(cf_country) = headers.get("cf-ipcountry") {
                if cf_country.len() == 2 && cf_country != "XX" {
                    ctx.country_code = Some(cf_country.to_uppercase());
                }
            }
        }

        // --- Run protection pipeline (NOT async) ---
        let pipeline_result = self.pipeline.process(&mut ctx, &self.settings, resolved_service.as_deref());

        // --- Consume the request body ---
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                warn!("Failed to read request body: {}", err);
                Bytes::new()
            }
        };

        // Generate a unique ray ID for this request
        let ray_id = format!(
            "{:016x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
                ^ (conn_id << 32)
        );

        // --- Act on pipeline result ---
        let response = match pipeline_result.action {
            ThreatAction::Pass => {
                debug!(client_ip = %real_ip, "Request passed protection pipeline");
                self.forward_to_backend(
                    &method,
                    &path,
                    query_string.as_deref(),
                    &host,
                    &headers,
                    body_bytes.clone(),
                    real_ip,
                    &upstream_addr,
                )
                .await
            }
            ThreatAction::Challenge => {
                info!(client_ip = %real_ip, path = %path, "Challenge issued");
                // Detect API/webhook requests - return JSON instead of HTML challenge
                let is_api = is_api_request(&path, &headers);
                if is_api {
                    info!(client_ip = %real_ip, path = %path, "API request challenged - returning JSON 403");
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "application/json")
                        .header("Cache-Control", "no-store")
                        .header("X-Fortress-Protected", "true")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"blocked","message":"Request blocked by security policy","code":1020}"#
                        )))
                        .unwrap()
                } else if let Some(html) = pipeline_result.challenge_html {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/html; charset=utf-8")
                        .header("Cache-Control", "no-store")
                        .header("X-Fortress-Protected", "true")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap()
                } else {
                    forbidden()
                }
            }
            ThreatAction::Block => {
                info!(client_ip = %real_ip, path = %path, ray_id = %ray_id, "Request blocked");
                if is_api_request(&path, &headers) {
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "application/json")
                        .header("Cache-Control", "no-store")
                        .header("X-Fortress-Protected", "true")
                        .header("X-Fortress-Ray", ray_id.as_str())
                        .body(Full::new(Bytes::from(format!(
                            r#"{{"error":"blocked","message":"Request blocked by security policy","code":1020,"ray":"{}"}}"#,
                            ray_id
                        ))))
                        .unwrap()
                } else {
                    forbidden_with_details(real_ip, &ray_id)
                }
            }
            ThreatAction::Tarpit => {
                info!(client_ip = %real_ip, path = %path, ray_id = %ray_id, "Request tarpitted");
                // Sleep before responding to waste the attacker's resources
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                forbidden_with_details(real_ip, &ray_id)
            }
        };

        // --- Metrics ---
        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros() as u64;
        let action_str = match pipeline_result.action {
            ThreatAction::Pass => "passed",
            ThreatAction::Challenge => "challenged",
            ThreatAction::Block | ThreatAction::Tarpit => "blocked",
        };
        self.metrics.record_request(
            real_ip,
            ctx.country_code.as_deref(),
            ctx.asn,
            ctx.ja3_hash.as_deref(),
            action_str,
            elapsed_us,
        );

        // Track bytes (approximate).
        let resp_size = body_bytes.len() as u64;
        self.connections
            .update_bytes(conn_id, resp_size, body_bytes.len() as u64);

        // --- Access log ---
        if let Some(ref logger) = self.access_log {
            logger.log(
                real_ip,
                &method,
                &path,
                &host,
                response.status().as_u16(),
                action_str,
                elapsed_us,
                &user_agent,
                ctx.country_code.as_deref(),
                &ray_id,
            );
        }

        response
    }

    // -----------------------------------------------------------------------
    // Challenge verification
    // -----------------------------------------------------------------------

    fn handle_challenge_verification(
        &self,
        query: &str,
        client_ip: IpAddr,
    ) -> Response<Full<Bytes>> {
        let mut challenge = None;
        let mut nonce = None;
        let mut redirect = String::from("/");
        let mut hl_score: u32 = 0;

        for param in query.split('&') {
            if let Some(val) = param.strip_prefix("challenge=") {
                challenge = Some(url_decode(val));
            } else if let Some(val) = param.strip_prefix("nonce=") {
                nonce = Some(val.to_string());
            } else if let Some(val) = param.strip_prefix("redirect=") {
                redirect = url_decode(val);
            } else if let Some(val) = param.strip_prefix("hl=") {
                hl_score = val.parse::<u32>().unwrap_or(0);
            }
        }

        let challenge = match challenge {
            Some(c) if !c.is_empty() => c,
            _ => {
                warn!(client_ip = %client_ip, "Challenge verification: missing challenge param");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Missing challenge")))
                    .unwrap();
            }
        };

        let nonce = match nonce {
            Some(n) => n,
            None => {
                warn!(client_ip = %client_ip, "Challenge verification: missing nonce param");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Missing nonce")))
                    .unwrap();
            }
        };

        // Verify the PoW solution
        if !self.challenge.verify_solution(&challenge, &nonce) {
            warn!(client_ip = %client_ip, "Challenge verification: invalid PoW solution");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from("Verification failed")))
                .unwrap();
        }

        // Headless browser detection check
        if hl_score >= 40 {
            warn!(client_ip = %client_ip, hl_score = hl_score, "Challenge verification: headless browser detected");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from("Verification failed")))
                .unwrap();
        }

        // Generate signed clearance cookie
        let cookie = self.challenge.generate_clearance_cookie(&client_ip);

        info!(client_ip = %client_ip, "Challenge verified, clearance cookie issued");

        // Sanitize redirect path (must start with "/" and not contain "//")
        let safe_redirect = if redirect.starts_with('/') && !redirect.starts_with("//") {
            redirect
        } else {
            "/".to_string()
        };

        // 302 redirect with Set-Cookie
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", &safe_redirect)
            .header("Set-Cookie", cookie)
            .header("Cache-Control", "no-store")
            .header("X-Fortress-Protected", "true")
            .body(Full::new(Bytes::from("Redirecting...")))
            .unwrap()
    }


    // -----------------------------------------------------------------------
    // Non-JavaScript challenge verification (meta-refresh fallback)
    // -----------------------------------------------------------------------

    fn handle_nojs_verification(
        &self,
        query: &str,
        client_ip: IpAddr,
    ) -> Response<Full<Bytes>> {
        let mut token = None;
        let mut sig = None;

        for param in query.split('&') {
            if let Some(val) = param.strip_prefix("token=") {
                token = Some(url_decode(val));
            } else if let Some(val) = param.strip_prefix("sig=") {
                sig = Some(url_decode(val));
            }
        }

        let token = match token {
            Some(t) if !t.is_empty() => t,
            _ => {
                warn!(client_ip = %client_ip, "Nojs verification: missing token param");
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("Invalid token")))
                    .unwrap();
            }
        };
        let sig = match sig {
            Some(s) => s,
            None => {
                warn!(client_ip = %client_ip, "Nojs verification: missing sig param");
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("Missing signature")))
                    .unwrap();
            }
        };

        // Verify token and signature
        if !self.challenge.verify_nojs_token(&token, &sig) {
            warn!(client_ip = %client_ip, "Nojs verification: invalid token or signature");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Verification failed")))
                .unwrap();
        }

        // Issue clearance cookie and redirect to homepage
        let cookie = self.challenge.generate_clearance_cookie(&client_ip);

        info!(client_ip = %client_ip, "Nojs challenge verified, clearance cookie issued");

        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", "/")
            .header("Set-Cookie", cookie)
            .header("Cache-Control", "no-store")
            .header("X-Fortress-Protected", "true")
            .body(Full::new(Bytes::from("Redirecting...")))
            .unwrap()
    }

    // -----------------------------------------------------------------------
    // Backend forwarding (connection-pooled via hyper client)
    // -----------------------------------------------------------------------

    async fn forward_to_backend(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        host: &str,
        headers: &HashMap<String, String>,
        body: Bytes,
        client_ip: IpAddr,
        upstream_addr: &str,
    ) -> Response<Full<Bytes>> {
        let uri = match query {
            Some(q) => format!("http://{}{}?{}", upstream_addr, path, q),
            None => format!("http://{}{}", upstream_addr, path),
        };

        let parsed_method = match hyper::Method::from_bytes(method.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                warn!("Invalid HTTP method: {}", method);
                return bad_gateway();
            }
        };

        let mut builder = Request::builder().method(parsed_method).uri(&uri);

        // Set required headers
        builder = builder.header("Host", host);
        builder = builder.header("X-Forwarded-For", client_ip.to_string());
        builder = builder.header("X-Real-IP", client_ip.to_string());
        builder = builder.header("X-Fortress-Protected", "true");

        // Forward original headers, skipping hop-by-hop, headers we override,
        // and Cloudflare-injected headers that confuse backend apps.
        let skip_headers: &[&str] = &[
            "host",
            "x-forwarded-for",
            "x-real-ip",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
            "transfer-encoding",
            "connection",
            // Cloudflare-specific headers – already consumed by Fortress
            "cf-connecting-ip",
            "cf-ipcountry",
            "cf-ray",
            "cf-visitor",
            "cf-request-id",
            "cf-warp-tag-id",
            "cdn-loop",
            "true-client-ip",
        ];
        for (name, value) in headers {
            let lower = name.to_lowercase();
            if skip_headers.contains(&lower.as_str()) {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }

        let upstream_req = match builder.body(Full::new(body)) {
            Ok(r) => r,
            Err(err) => {
                error!("Failed to build upstream request: {}", err);
                return bad_gateway();
            }
        };

        let upstream_resp = match self.upstream_client.request(upstream_req).await {
            Ok(r) => r,
            Err(err) => {
                error!(upstream = %upstream_addr, error = %err, "Backend request failed");
                return bad_gateway();
            }
        };

        // Convert Response<Incoming> to Response<Full<Bytes>>
        let (parts, incoming_body) = upstream_resp.into_parts();
        let body_bytes = match incoming_body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                error!("Failed to read backend response body: {}", err);
                return bad_gateway();
            }
        };

        Response::from_parts(parts, Full::new(body_bytes))
    }
}

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

/// Return a `502 Bad Gateway` response.
pub fn bad_gateway() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("X-Fortress-Protected", "true")
        .body(Full::new(Bytes::from(
            "<!DOCTYPE html>\
            <html><head><title>502 Bad Gateway</title></head>\
            <body><h1>502 Bad Gateway</h1>\
            <p>The upstream server is not available. Please try again later.</p>\
            <hr><p>Fortress Anti-DDoS Proxy</p></body></html>",
        )))
        .unwrap()
}

/// Return a `403 Forbidden` response with a professional block page.
pub fn forbidden_with_details(client_ip: IpAddr, ray_id: &str) -> Response<Full<Bytes>> {
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Denied | Fortress</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0a;color:#e4e4e7;font-family:-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;flex-direction:column}}
.top-bar{{background:linear-gradient(135deg,#dc2626,#991b1b);padding:4px 0;text-align:center}}
.top-bar span{{color:#fecaca;font-size:12px;font-weight:600;letter-spacing:1px;text-transform:uppercase}}
.container{{flex:1;display:flex;align-items:center;justify-content:center;padding:2rem}}
.card{{background:#18181b;border:1px solid #27272a;border-radius:12px;max-width:560px;width:100%;overflow:hidden}}
.card-header{{background:#1c1917;padding:24px 32px;border-bottom:1px solid #27272a;display:flex;align-items:center;gap:16px}}
.shield{{width:48px;height:48px;background:linear-gradient(135deg,#dc2626,#b91c1c);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:24px}}
.card-header h1{{font-size:18px;color:#fafafa;font-weight:600}}
.card-header p{{font-size:13px;color:#a1a1aa;margin-top:2px}}
.card-body{{padding:28px 32px}}
.message{{font-size:14px;color:#a1a1aa;line-height:1.7;margin-bottom:24px}}
.message strong{{color:#f87171}}
.details{{background:#0f0f0f;border:1px solid #27272a;border-radius:8px;padding:16px 20px}}
.detail-row{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #1a1a1a}}
.detail-row:last-child{{border:none}}
.detail-label{{font-size:12px;color:#71717a;text-transform:uppercase;letter-spacing:0.5px}}
.detail-value{{font-size:13px;color:#d4d4d8;font-family:"SF Mono",Monaco,Consolas,monospace}}
.footer{{padding:16px 32px;border-top:1px solid #27272a;text-align:center}}
.footer span{{font-size:11px;color:#52525b}}
.footer a{{color:#3b82f6;text-decoration:none}}
</style>
</head>
<body>
<div class="top-bar"><span>Fortress DDoS Protection</span></div>
<div class="container">
<div class="card">
<div class="card-header">
<div class="shield">&#x1F6E1;</div>
<div><h1>Access Denied</h1><p>Error 1020 — Connection blocked</p></div>
</div>
<div class="card-body">
<div class="message">This request has been <strong>blocked</strong> by the website's security policy. If you believe this is an error, please contact the site administrator with the Ray ID shown below.</div>
<div class="details">
<div class="detail-row"><span class="detail-label">Your IP</span><span class="detail-value">{ip}</span></div>
<div class="detail-row"><span class="detail-label">Ray ID</span><span class="detail-value">{ray}</span></div>
<div class="detail-row"><span class="detail-label">Timestamp</span><span class="detail-value">{ts}</span></div>
</div>
</div>
<div class="footer"><span>Protected by <a href="#">Fortress</a> Anti-DDoS &middot; Performance &amp; Security</span></div>
</div>
</div>
</body>
</html>"##,
        ip = client_ip,
        ray = ray_id,
        ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    );

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("X-Fortress-Protected", "true")
        .header("X-Fortress-Ray", ray_id)
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::from(html)))
        .unwrap()
}

/// Simple 403 without details (for internal use).
pub fn forbidden() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("X-Fortress-Protected", "true")
        .body(Full::new(Bytes::from("Forbidden")))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Determine the true client IP from proxy headers, falling back to the
/// directly-connected peer address.
///
/// When Cloudflare mode is active, headers are only trusted if the peer IP
/// belongs to a known Cloudflare range. `CF-Connecting-IP` takes highest
/// priority in that case.
pub fn extract_client_ip(req: &Request<Incoming>, peer_addr: IpAddr, cf_enabled: bool) -> IpAddr {
    // When Cloudflare mode is enabled, only trust headers from CF IPs.
    let trusted_proxy = cf_enabled && crate::protection::cloudflare::is_cloudflare_ip(peer_addr);

    if trusted_proxy {
        // CF-Connecting-IP is the most reliable header from Cloudflare.
        if let Some(cf_ip) = req.headers().get("cf-connecting-ip") {
            if let Ok(val) = cf_ip.to_str() {
                if let Ok(ip) = val.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    if trusted_proxy {
        // X-Real-IP (trusted proxy scenario).
        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(val) = real_ip.to_str() {
                if let Ok(ip) = val.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }

        // X-Forwarded-For left-most entry.
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(val) = xff.to_str() {
                if let Some(first) = val.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }

    peer_addr
}

/// Simple percent-decoding for URL query parameters.
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let hex = [hi, lo];
            if let Ok(s) = std::str::from_utf8(&hex) {
                if let Ok(val) = u8::from_str_radix(s, 16) {
                    result.push(val as char);
                    continue;
                }
            }
            result.push('%');
            result.push(hi as char);
            result.push(lo as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Detect API, webhook, and non-browser requests that should receive JSON errors
/// instead of HTML challenge pages.
fn is_api_request(path: &str, headers: &HashMap<String, String>) -> bool {
    let p = path.to_lowercase();

    // Path-based detection
    if p.starts_with("/api/")
        || p.starts_with("/webhook")
        || p.starts_with("/graphql")
        || p.starts_with("/.well-known/")
        || p.starts_with("/wp-json/")
        || p.ends_with("/callback")
        || p.ends_with("/webhook")
    {
        return true;
    }

    // Accept header detection
    if let Some(accept) = headers.get("accept") {
        let a = accept.to_lowercase();
        if a.contains("application/json") && !a.contains("text/html") {
            return true;
        }
    }

    // Content-Type detection (POST with JSON body)
    if let Some(ct) = headers.get("content-type") {
        let c = ct.to_lowercase();
        if c.contains("application/json") || c.contains("application/graphql") {
            return true;
        }
    }

    // Common webhook/API user agents
    if let Some(ua) = headers.get("user-agent") {
        let u = ua.to_lowercase();
        if u.starts_with("stripe/")
            || u.starts_with("github-hookshot/")
            || u.starts_with("discord")
            || u.starts_with("paypal")
            || u.contains("webhook")
            || u.starts_with("axios/")
            || u.starts_with("node-fetch")
            || u.starts_with("python-requests")
            || u.starts_with("go-http-client")
            || u.starts_with("curl/")
            || u.starts_with("postman")
        {
            return true;
        }
    }

    false
}
