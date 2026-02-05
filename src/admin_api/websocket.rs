use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::time::interval;

use crate::admin_api::routes::AppState;

/
/
pub async fn live_traffic_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_live_traffic(socket, state))
}

/
///
/
/
/
async fn handle_live_traffic(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
        let _ = shutdown_tx.send(());
    });

    let mut tick = interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snapshot = state.metrics.get_snapshot();
                let history = state.metrics.get_second_history(1);
                let latest = history.last();

                let payload = json!({
                    "rps": snapshot.rps,
                    "blocked_per_sec": snapshot.blocked_per_sec,
                    "challenged_per_sec": snapshot.challenged_per_sec,
                    "passed_per_sec": snapshot.passed_per_sec,
                    "unique_ips": snapshot.unique_ips,
                    "avg_latency_ms": snapshot.avg_latency_ms,
                    "total_requests": snapshot.total_requests,
                    "total_blocked": snapshot.total_blocked,
                    "latest_second": latest.map(|s| json!({
                        "timestamp": s.timestamp,
                        "requests": s.requests,
                        "blocked": s.blocked,
                        "challenged": s.challenged,
                        "passed": s.passed,
                    })),
                });

                let text = serde_json::to_string(&payload).unwrap_or_default();
                if sender.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }

            _ = &mut shutdown_rx => {
                break;
            }
        }
    }

    recv_task.abort();
}
