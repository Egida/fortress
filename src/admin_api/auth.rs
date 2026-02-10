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

/// Constant-time byte comparison to prevent timing attacks on API key validation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
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
        Some(key) if constant_time_eq(key.as_bytes(), api_key.as_bytes()) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
