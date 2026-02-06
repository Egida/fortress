use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Holds the expected API key for the admin interface.
pub struct ApiKeyAuth {
    pub api_key: String,
}

/// Axum middleware that validates requests carry a valid
/// `X-Fortress-Key` header before forwarding them to the inner handler.
///
/// The expected key is passed via Axum `State` so it can be shared across
/// all routes without capturing anything by value.
pub async fn auth_middleware(
    State(api_key): State<String>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let provided_key = req
        .headers()
        .get("X-Fortress-Key")
        .and_then(|v| v.to_str().ok());

    match provided_key {
        Some(key) if key == api_key.as_str() => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
