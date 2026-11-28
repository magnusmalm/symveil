//! Testing-only forwarder.
//!
//! `symveil-capture` listens on `127.0.0.1`, appends each request body to a
//! private file, and forwards the request. The proxy does not record bodies
//! and does not start this listener. Run it only for a manual check. It does
//! not sandbox the client.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use futures::StreamExt;
use regex::Regex;
use tokio::net::TcpListener;

use symveil_detect::dotenv::dotenv_assignment_hits;

use crate::perms;
use crate::proxy::{self, MAX_BODY};

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

/// Assignment values from a dotenv fixture.
///
/// All-digit values are omitted. A URL assignment contributes its password,
/// which is the part the proxy is supposed to mask, rather than the whole URL.
pub fn fixture_values(text: &str) -> Vec<String> {
    dotenv_assignment_hits(text)
        .into_iter()
        .filter_map(|hit| {
            let value = &text[hit.start..hit.end];
            if value.is_empty() {
                return None;
            }
            Some(url_password(value).unwrap_or_else(|| value.to_string()))
        })
        .collect()
}

/// `captured_requests`, then `value N: masked` or `value N: LEAKED`.
///
/// The strings from the fixture are not copied into the report.
pub fn report(fixture: &str, bodies: &[u8]) -> Result<String> {
    let values = fixture_values(fixture);
    if values.is_empty() {
        bail!("fixture has no values to scan");
    }
    let records = read_records(bodies)?;
    let mut out = format!("captured_requests={}\n", records.len());
    for (index, value) in values.iter().enumerate() {
        let leaked = records.iter().any(|body| contains(body, value.as_bytes()));
        let label = if leaked { "LEAKED" } else { "masked" };
        out.push_str(&format!("value {}: {label}\n", index + 1));
    }
    Ok(out)
}

/// Bind `127.0.0.1:PORT` and return the listener plus its `http` URL.
pub async fn bind(listen: &str) -> Result<(TcpListener, String)> {
    validate_listen(listen)?;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    let addr = listener.local_addr().context("capture address")?;
    if !addr.ip().is_loopback() {
        bail!("capture refused to listen on {addr}");
    }
    Ok((listener, format!("http://{addr}")))
}

/// Append every request body to `bodies` and forward it to `upstream`.
///
/// `upstream` must be `https`, or `http` on a loopback host. The bodies file
/// is created mode `0600`.
pub async fn serve(listener: TcpListener, upstream: &str, bodies: &Path) -> Result<()> {
    validate_upstream(upstream)?;
    if let Some(parent) = bodies.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            bail!(
                "capture bodies directory {} does not exist",
                parent.display()
            );
        }
    }
    let file = perms::open_append_private(bodies)
        .with_context(|| format!("create {}", bodies.display()))?;
    let state = FwdState {
        upstream: upstream.trim_end_matches('/').to_string(),
        http: proxy::build_client(0)?,
        bodies: Arc::new(Mutex::new(file)),
    };
    let app = Router::new().fallback(record_and_forward).with_state(state);
    axum::serve(listener, app)
        .await
        .context("capture forwarder stopped")?;
    Ok(())
}

#[derive(Clone)]
struct FwdState {
    upstream: String,
    http: reqwest::Client,
    bodies: Arc<Mutex<File>>,
}

async fn record_and_forward(State(state): State<FwdState>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY).await {
        Ok(body) => body,
        Err(_) => {
            return text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "capture could not read the request body",
            );
        }
    };
    if let Err(err) = append_record(&state.bodies, &body) {
        tracing::warn!("capture record failed: {err}");
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capture could not record the request body",
        );
    }

    let url = format!("{}{path_and_query}", state.upstream);
    let upstream_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            return text_response(StatusCode::BAD_REQUEST, "unsupported method");
        }
    };
    let upstream = match state
        .http
        .request(upstream_method, &url)
        .headers(forward_headers(&headers))
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            tracing::warn!("capture upstream failed: {err}");
            return text_response(StatusCode::BAD_GATEWAY, "capture upstream request failed");
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        if is_hop(name.as_str()) {
            continue;
        }
        if let Ok(header_name) = axum::http::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(header_value) = axum::http::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(header_name, header_value);
            }
        }
    }
    let stream = upstream
        .bytes_stream()
        .map(|chunk| chunk.map_err(io::Error::other));
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "capture response"))
}

fn append_record(slot: &Mutex<File>, body: &[u8]) -> Result<()> {
    let mut file = slot.lock().unwrap_or_else(|err| err.into_inner());
    let len = u64::try_from(body.len()).context("body length")?;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(body)?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

fn read_records(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.len() - index < 8 {
            bail!("captured bodies ended inside a length");
        }
        let mut len_bytes = [0_u8; 8];
        len_bytes.copy_from_slice(&bytes[index..index + 8]);
        let len = usize::try_from(u64::from_le_bytes(len_bytes)).context("captured body length")?;
        index += 8;
        if bytes.len() - index < len {
            bail!("captured bodies ended inside a request");
        }
        out.push(&bytes[index..index + len]);
        index += len;
    }
    Ok(out)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn url_password(value: &str) -> Option<String> {
    // Same shape as the `url-password` builtin: the password is the capture
    // group, and the user and host stay outside it.
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z][a-z0-9+.-]*://[^:\s/@]*:([^\s/@]{8,})@")
            .expect("url password pattern")
    });
    pattern
        .captures(value)
        .and_then(|caps| caps.get(1))
        .map(|matched| matched.as_str().to_string())
}

fn validate_listen(listen: &str) -> Result<()> {
    let Some((host, port)) = listen.rsplit_once(':') else {
        bail!("capture listen address must be 127.0.0.1:PORT");
    };
    if host != "127.0.0.1" {
        bail!("capture listens on 127.0.0.1 only");
    }
    if port.parse::<u16>().is_err() {
        bail!("capture listen port is not a number");
    }
    Ok(())
}

fn validate_upstream(url: &str) -> Result<()> {
    if url.chars().any(char::is_control) || url.contains('@') {
        bail!("capture upstream must not contain userinfo or control characters");
    }
    if let Some(rest) = url.strip_prefix("https://") {
        if rest.is_empty() || rest.starts_with('/') {
            bail!("capture upstream needs a host");
        }
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or("");
        if loopback_authority(authority) {
            return Ok(());
        }
    }
    bail!("capture upstream must be https, or http on a loopback address");
}

fn loopback_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        &rest[..end]
    } else {
        authority
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
    };
    host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost")
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

fn text_response(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(message.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from(message.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn fixture_file_yields_the_five_secret_values() {
        let text = include_str!("../../../tests/fixtures/dotenv-repo/.env");
        let values = fixture_values(text);
        assert_eq!(
            values,
            vec![
                "sk-Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1",
                "ghp_cD1cD1cD1cD1cD1cD1cD1cD1cD1cD1cD1cD1",
                "n0t-a-token-db-pass",
                "db-url-password",
                "s3ssion-value-9f3a",
            ]
        );
    }

    #[test]
    fn report_names_only_the_bodies_that_contain_a_value() {
        let text = include_str!("../../../tests/fixtures/dotenv-repo/.env");
        let values = fixture_values(text);
        let mut bodies = Vec::new();
        append_owned(&mut bodies, b"{\"text\":\"redacted\"}");
        append_owned(&mut bodies, values[2].as_bytes());
        let report = report(text, &bodies).unwrap();
        assert!(report.starts_with("captured_requests=2\n"), "{report}");
        assert!(report.contains("value 1: masked\n"), "{report}");
        assert!(report.contains("value 2: masked\n"), "{report}");
        assert!(report.contains("value 3: LEAKED\n"), "{report}");
        assert!(report.contains("value 4: masked\n"), "{report}");
        assert!(report.contains("value 5: masked\n"), "{report}");
        for value in &values {
            assert!(!report.contains(value), "report included a fixture value");
        }
    }

    #[test]
    fn a_short_file_is_not_a_record() {
        let err = read_records(&[1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("length"), "{err}");
    }

    #[test]
    fn upstream_must_be_https_or_loopback() {
        assert!(validate_upstream("https://api.anthropic.com").is_ok());
        assert!(validate_upstream("http://127.0.0.1:9").is_ok());
        assert!(validate_upstream("http://localhost:9").is_ok());
        assert!(validate_upstream("http://[::1]:9").is_ok());
        assert!(validate_upstream("http://example.com").is_err());
        assert!(validate_upstream("http://127.0.0.1:9/path").is_ok());
        assert!(validate_upstream("https://user:secret@example.com").is_err());
        assert!(validate_listen("127.0.0.1:0").is_ok());
        assert!(validate_listen("0.0.0.0:9").is_err());
    }

    #[tokio::test]
    async fn forwarder_records_the_body_and_returns_the_upstream_bytes() {
        let hits = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let stored = Arc::clone(&hits);
        let app = Router::new().fallback(move |req: Request<Body>| {
            let stored = Arc::clone(&stored);
            async move {
                let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY)
                    .await
                    .unwrap_or_default();
                stored
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .push(bytes.to_vec());
                Response::new(Body::from(bytes))
            }
        });
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(echo, app).await.unwrap();
        });

        let dir = std::env::temp_dir().join(format!(
            "symveil-capture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let bodies = dir.join("bodies");
        let (listener, url) = bind("127.0.0.1:0").await.unwrap();
        let bodies_path = bodies.clone();
        let upstream = format!("http://127.0.0.1:{echo_port}");
        let server = tokio::spawn(async move {
            serve(listener, &upstream, &bodies_path).await.unwrap();
        });

        let client = reqwest::Client::new();
        let payload = b"synthetic-body-not-a-fixture".to_vec();
        let response = client
            .post(format!("{url}/v1/messages"))
            .header("content-type", "application/json")
            .header("x-api-key", "synthetic-header")
            .body(payload.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let echoed = response.bytes().await.unwrap();
        assert_eq!(&echoed[..], payload.as_slice());

        let recorded = std::fs::read(&bodies).unwrap();
        let records = read_records(&recorded).unwrap();
        assert_eq!(records, vec![payload.as_slice()]);
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&bodies).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let seen = hits.lock().unwrap_or_else(|err| err.into_inner());
        assert_eq!(seen.as_slice(), &[payload]);

        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn append_owned(out: &mut Vec<u8>, body: &[u8]) {
        let len = u64::try_from(body.len()).unwrap();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(body);
    }
}
