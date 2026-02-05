use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/
pub struct ApiKeyAuth {
    pub api_key: String,
}

/
/
///
/
/
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
