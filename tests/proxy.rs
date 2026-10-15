use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use symveil::audit::AuditLog;
use symveil::build_engine;
use symveil::config::RedactSection;
use symveil::proxy::AppState;
use symveil::vault::Vault;
use tokio::net::TcpListener;

#[derive(Clone)]
struct MockState {
    hits: Arc<Mutex<Vec<Recorded>>>,
    sse: bool,
    body: Arc<Vec<u8>>,
}

struct Recorded {
    path: String,
    body: Vec<u8>,
    authorization: Option<String>,
    api_key: Option<String>,
    accept_encoding: Option<String>,
}

#[tokio::test]
async fn chat_stream_redacts_the_request_and_restores_split_placeholders() {
    let redact = RedactSection {
        internal_domains: Vec::new(),
        ..RedactSection::default()
    };
    let mut engine = build_engine(Vault::ephemeral(), &redact).unwrap();
    let sample = "call aurora_rcc_enable_pll key AKIAIOSFODNN7EXAMPLE";
    let (preview, hits) = engine.redact_str(sample).unwrap();
    assert!(preview.contains("aurora_rcc_enable_pll"));
    assert!(!preview.contains("AKIA"));
    assert_eq!(hits.len(), 1);
    let key = hits
        .iter()
        .find(|hit| hit.original == "AKIAIOSFODNN7EXAMPLE")
        .unwrap()
        .placeholder
        .clone();

    let sse = format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"call aurora_rcc_enable_pll key {key}\"}}}}]}}\n\ndata: [DONE]\n\n"
    );
    let (openai, openai_hits) = spawn_mock(sse.into_bytes(), true).await;
    let (anthropic, anthropic_hits) = spawn_mock(b"{}".to_vec(), false).await;

    let dir = temp_dir("audit-stream");
    let audit_path = dir.join("audit.jsonl");
    let state = AppState::new(
        engine,
        openai.clone(),
        anthropic,
        AuditLog::open(&audit_path).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;

    let client = reqwest::Client::new();
    let request = r#"{"model":"gpt-test","stream":true,"messages":[{"role":"user","content":"call aurora_rcc_enable_pll key AKIAIOSFODNN7EXAMPLE"}]}"#;
    let response = client
        .post(format!("{proxy}/v1/chat/completions"))
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .header("accept-encoding", "gzip")
        .body(request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-symveil-redactions")
            .map(|v| v.as_bytes()),
        Some(b"1".as_slice())
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("aurora_rcc_enable_pll"), "{body}");
    assert!(body.contains("AKIAIOSFODNN7EXAMPLE"), "{body}");
    assert!(!body.contains(&key), "{body}");
    assert!(body.contains("[DONE]"));

    let seen = openai_hits.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/v1/chat/completions");
    let forwarded = String::from_utf8_lossy(&seen[0].body);
    assert!(forwarded.contains("aurora_rcc_enable_pll"), "{forwarded}");
    assert!(!forwarded.contains("AKIA"), "{forwarded}");
    assert!(forwarded.contains(&key), "{forwarded}");
    assert_eq!(seen[0].authorization.as_deref(), Some("Bearer test-token"));
    assert!(seen[0].accept_encoding.is_none());
    assert!(anthropic_hits.lock().unwrap().is_empty());

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains("AKIA"));
    assert!(audit.contains("aws-access-key-id"));
    assert!(audit.contains("\"dir\":\"response\""));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn messages_and_responses_go_to_the_right_upstream() {
    let redact = RedactSection {
        internal_domains: Vec::new(),
        ..RedactSection::default()
    };
    let mut engine = build_engine(Vault::ephemeral(), &redact).unwrap();
    let placeholder = engine
        .redact_str("AKIAIOSFODNN7EXAMPLE")
        .unwrap()
        .1
        .pop()
        .unwrap()
        .placeholder;
    let message = format!(
        r#"{{"id":"msg_test","type":"message","role":"assistant","content":[{{"type":"text","text":"use {placeholder}"}}],"stop_reason":"end_turn"}}"#
    );
    let (openai, openai_hits) = spawn_mock(b"{}".to_vec(), false).await;
    let (anthropic, anthropic_hits) = spawn_mock(message.into_bytes(), false).await;
    let dir = temp_dir("audit-route");
    let state = AppState::new(
        engine,
        openai,
        anthropic.clone(),
        AuditLog::open(&dir.join("audit.jsonl")).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let client = reqwest::Client::new();

    let messages = client
        .post(format!("{proxy}/v1/messages"))
        .header("x-api-key", "sk-ant-test")
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-test","max_tokens":32,"messages":[{"role":"user","content":"use AKIAIOSFODNN7EXAMPLE"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(messages.status(), 200);
    let text = messages.text().await.unwrap();
    assert!(text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
    assert!(!text.contains(&placeholder), "{text}");
    {
        let anthropic_seen = anthropic_hits.lock().unwrap();
        assert_eq!(anthropic_seen.len(), 1);
        assert_eq!(anthropic_seen[0].path, "/v1/messages");
        assert_eq!(anthropic_seen[0].api_key.as_deref(), Some("sk-ant-test"));
        assert!(!String::from_utf8_lossy(&anthropic_seen[0].body).contains("AKIA"));
    }

    let responses = client
        .post(format!("{proxy}/v1/responses"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-test","input":"AKIAIOSFODNN7EXAMPLE"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(responses.status(), 200);
    let openai_seen = openai_hits.lock().unwrap();
    assert_eq!(openai_seen.len(), 1);
    assert_eq!(openai_seen[0].path, "/v1/responses");
    assert!(!String::from_utf8_lossy(&openai_seen[0].body).contains("AKIA"));
    let _ = std::fs::remove_dir_all(&dir);
}

async fn spawn_mock(body: Vec<u8>, sse: bool) -> (String, Arc<Mutex<Vec<Recorded>>>) {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        hits: Arc::clone(&hits),
        sse,
        body: Arc::new(body),
    };
    let app = Router::new().fallback(any(mock_handler)).with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), hits)
}

async fn mock_handler(State(state): State<MockState>, req: Request<Body>) -> Response {
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .unwrap();
    state.hits.lock().unwrap().push(Recorded {
        path,
        body: body.to_vec(),
        authorization: header_string(&headers, "authorization"),
        api_key: header_string(&headers, "x-api-key"),
        accept_encoding: header_string(&headers, "accept-encoding"),
    });
    if state.sse {
        let payload = (*state.body).clone();
        let chunks = stream_chunks(payload, 1);
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(chunks))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from((*state.body).clone()))
            .unwrap()
    }
}

fn stream_chunks(
    data: Vec<u8>,
    size: usize,
) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send {
    async_stream::stream! {
        let mut index = 0;
        while index < data.len() {
            let end = (index + size).min(data.len());
            yield Ok(Bytes::copy_from_slice(&data[index..end]));
            index = end;
        }
    }
}

fn header_string(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

async fn spawn_proxy(state: AppState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        symveil::proxy::serve(listener, state).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let url = format!("http://{addr}");
    for _ in 0..50 {
        if client.get(format!("{url}/health")).send().await.is_ok() {
            return url;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy did not start");
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "symveil-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
