use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_stream::stream;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use futures::StreamExt;
use tokio::net::TcpListener;

use crate::audit::AuditLog;
use crate::redact::Engine;
use crate::stream::ByteRestorer;

const MAX_BODY: usize = 32 * 1024 * 1024;

const HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
];

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Mutex<Engine>>,
    pub http: reqwest::Client,
    pub openai_base: String,
    pub anthropic_base: String,
    pub audit: Arc<Mutex<AuditLog>>,
}

impl AppState {
    pub fn new(
        engine: Engine,
        openai_base: String,
        anthropic_base: String,
        audit: AuditLog,
        timeout_secs: u64,
    ) -> Result<Self> {
        Ok(Self {
            engine: Arc::new(Mutex::new(engine)),
            http: build_client(timeout_secs)?,
            openai_base,
            anthropic_base,
            audit: Arc::new(Mutex::new(audit)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Health,
    OpenAi,
    Anthropic,
    Unknown,
}

pub fn classify(path: &str) -> Route {
    if path == "/health" {
        return Route::Health;
    }
    if path == "/v1/messages" || path.starts_with("/v1/messages/") {
        return Route::Anthropic;
    }
    if path == "/v1" || path.starts_with("/v1/") {
        return Route::OpenAi;
    }
    Route::Unknown
}

pub async fn serve(listener: TcpListener, state: AppState) -> Result<()> {
    let app = router(state);
    axum::serve(listener, app)
        .await
        .context("symveil proxy stopped")?;
    Ok(())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .fallback(proxy_request)
        .with_state(state)
}

pub fn build_client(timeout_secs: u64) -> Result<reqwest::Client> {
    let mut builder =
        reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(15));
    if timeout_secs > 0 {
        builder = builder.timeout(std::time::Duration::from_secs(timeout_secs));
    }
    builder.build().context("build HTTP client")
}

async fn health() -> Response {
    json_response(StatusCode::OK, r#"{"status":"ok"}"#)
}

async fn proxy_request(State(state): State<AppState>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();

    let base = match classify(&path) {
        Route::Health => return health().await,
        Route::Unknown => {
            return error_response(StatusCode::NOT_FOUND, "symveil proxies /v1/* only");
        }
        Route::OpenAi => state.openai_base.clone(),
        Route::Anthropic => state.anthropic_base.clone(),
    };

    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY).await {
        Ok(body) => body,
        Err(err) => {
            let message = err.to_string();
            let status = if message.to_ascii_lowercase().contains("length") {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            return error_response(status, &format!("read request body: {message}"));
        }
    };
    let wants_stream = request_wants_stream(&body);

    let (redacted, hits, map) = {
        let mut engine = state.engine.lock().unwrap_or_else(|err| err.into_inner());
        let redacted = match engine.redact_bytes(&body) {
            Ok(pair) => pair,
            Err(err) => return error_response(StatusCode::BAD_REQUEST, &format!("redact: {err}")),
        };
        if let Err(err) = engine.save_if_dirty() {
            tracing::warn!("vault save failed: {err}");
        }
        let map = engine.restore_map();
        (redacted.0, redacted.1, map)
    };

    if let Ok(mut audit) = state.audit.lock() {
        if let Err(err) = audit.record_request(&path, &hits) {
            tracing::warn!("audit log: {err}");
        }
    }

    let url = join_url(&base, &path_and_query);
    let upstream_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "unsupported method");
        }
    };
    let upstream_headers = forward_headers(&headers);

    let upstream = match state
        .http
        .request(upstream_method, &url)
        .headers(upstream_headers)
        .body(redacted)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {err}"),
            );
        }
    };

    if let Some(encoding) = upstream.headers().get(reqwest::header::CONTENT_ENCODING) {
        let encoding = encoding.to_str().unwrap_or("").to_ascii_lowercase();
        if !encoding.is_empty() && encoding != "identity" {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "upstream sent a compressed body; symveil refused to forward it unrestored",
            );
        }
    }

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase());
    let streaming = should_stream(content_type.as_deref(), wants_stream);
    let json_escape = should_json_escape(content_type.as_deref());
    tracing::info!(
        method = %method,
        path = %path,
        redactions = hits.len(),
        streaming,
        status = status.as_u16(),
        "proxied"
    );

    let mut builder = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        if is_hop(name.as_str()) || name.as_str().eq_ignore_ascii_case("x-symveil-redactions") {
            continue;
        }
        if let Ok(header_name) = HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(header_name, header_value);
            }
        }
    }
    if let Ok(count) = HeaderValue::from_str(&hits.len().to_string()) {
        builder = builder.header("x-symveil-redactions", count);
    }

    if streaming {
        let body = stream_body(
            upstream.bytes_stream(),
            map,
            json_escape,
            Arc::clone(&state.audit),
            path,
        );
        return builder.body(body).unwrap_or_else(|_| {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "build stream response")
        });
    }

    let bytes = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("read upstream body: {err}"),
            );
        }
    };
    let mut restorer = ByteRestorer::new(map, json_escape);
    let mut restored = restorer.push(&bytes);
    restored.push_str(&restorer.finish());
    let count = restorer.restored();
    if count > 0 {
        if let Ok(mut audit) = state.audit.lock() {
            if let Err(err) = audit.record_response(&path, count) {
                tracing::warn!("audit log: {err}");
            }
        }
    }
    builder
        .body(Body::from(restored))
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "build response"))
}

fn stream_body(
    upstream: impl futures::Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
    map: std::collections::HashMap<String, String>,
    json_escape: bool,
    audit: Arc<Mutex<AuditLog>>,
    path: String,
) -> Body {
    let body = stream! {
        let mut restorer = ByteRestorer::new(map, json_escape);
        tokio::pin!(upstream);
        while let Some(item) = upstream.next().await {
            match item {
                Ok(chunk) => {
                    let out = restorer.push(&chunk);
                    if !out.is_empty() {
                        yield Ok::<Bytes, std::io::Error>(Bytes::from(out));
                    }
                }
                Err(err) => {
                    log_restored(&audit, &path, restorer.restored());
                    yield Err(std::io::Error::other(err));
                    return;
                }
            }
        }
        let tail = restorer.finish();
        if !tail.is_empty() {
            yield Ok(Bytes::from(tail));
        }
        log_restored(&audit, &path, restorer.restored());
    };
    Body::from_stream(body)
}

fn log_restored(audit: &Mutex<AuditLog>, path: &str, restored: usize) {
    if restored == 0 {
        return;
    }
    match audit.lock() {
        Ok(mut log) => {
            if let Err(err) = log.record_response(path, restored) {
                tracing::warn!("audit log: {err}");
            }
        }
        Err(err) => {
            if let Err(write_err) = err.into_inner().record_response(path, restored) {
                tracing::warn!("audit log: {write_err}");
            }
        }
    }
}

fn request_wants_stream(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn should_stream(content_type: Option<&str>, wants_stream: bool) -> bool {
    if let Some(content_type) = content_type {
        if content_type.contains("text/event-stream") {
            return true;
        }
        if content_type.contains("json") {
            return false;
        }
    }
    wants_stream
}

fn should_json_escape(content_type: Option<&str>) -> bool {
    match content_type {
        None => true,
        Some(content_type) => {
            content_type.contains("json") || content_type.contains("event-stream")
        }
    }
}

fn join_url(base: &str, path_and_query: &str) -> String {
    format!("{}{path_and_query}", base.trim_end_matches('/'))
}

fn is_hop(name: &str) -> bool {
    HOP.iter().any(|hop| hop.eq_ignore_ascii_case(name))
}

fn forward_headers(headers: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        if is_hop(name.as_str()) {
            continue;
        }
        let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        let Ok(value) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        out.append(name, value);
    }
    out
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({
        "error": { "message": message, "type": "symveil_error" }
    });
    json_response(status, &body.to_string())
}

fn json_response(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from(body.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_agent_paths() {
        assert_eq!(classify("/health"), Route::Health);
        assert_eq!(classify("/v1/messages"), Route::Anthropic);
        assert_eq!(classify("/v1/messages/count_tokens"), Route::Anthropic);
        assert_eq!(classify("/v1/chat/completions"), Route::OpenAi);
        assert_eq!(classify("/v1/responses"), Route::OpenAi);
        assert_eq!(classify("/v1/models"), Route::OpenAi);
        assert_eq!(classify("/"), Route::Unknown);
    }

    #[test]
    fn stream_flag_follows_content_type() {
        assert!(should_stream(Some("text/event-stream"), false));
        assert!(!should_stream(Some("application/json"), true));
        assert!(should_stream(None, true));
        assert!(should_json_escape(Some("text/event-stream; charset=utf-8")));
        assert!(!should_json_escape(Some("text/plain")));
    }
}
