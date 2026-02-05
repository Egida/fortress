use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

/
///
/
/
pub struct AlertManager {
    webhook_url: Option<String>,
    enabled: bool,
}

impl AlertManager {
    pub fn new(webhook_url: Option<String>, enabled: bool) -> Self {
        Self {
            webhook_url,
            enabled,
        }
    }

    /
    pub async fn send_alert(&self, event_type: &str, message: &str) {
        if !self.enabled {
            return;
        }

        let url = match &self.webhook_url {
            Some(u) if !u.is_empty() => u.clone(),
            _ => {
                info!(event = event_type, msg = message, "Alert (no webhook configured)");
                return;
            }
        };

        let payload = serde_json::json!({
            "event": event_type,
            "message": message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "fortress"
        });

        let body = payload.to_string();

        use hyper_util::client::legacy::Client;
        use hyper_util::client::legacy::connect::HttpConnector;
        use hyper_util::rt::TokioExecutor;
        use http_body_util::Full;
        use bytes::Bytes;

        let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(5))
            .build_http();

        let req = match hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&url)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
        {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to build alert request: {}", e);
                return;
            }
        };

        match tokio::time::timeout(Duration::from_secs(10), client.request(req)).await {
            Ok(Ok(resp)) => {
                info!(
                    status = resp.status().as_u16(),
                    event = event_type,
                    "Alert sent to webhook"
                );
            }
            Ok(Err(e)) => {
                warn!(error = %e, "Failed to send alert to webhook");
            }
            Err(_) => {
                warn!("Alert webhook request timed out");
            }
        }
    }
}
