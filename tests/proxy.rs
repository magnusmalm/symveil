use std::fmt::Write;
use std::sync::{Arc, Mutex, OnceLock};
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

#[tokio::test]
async fn rule_actions_on_messages_and_responses() {
    let _logs = install_logs();
    let secret = "widget_tok_abcd1234";
    let rule = "widget-token";
    let base = r#"
        [redact]
        internal_domains = []

        [[redact.secrets]]
        name = "widget-token"
        regex = '\bwidget_tok_[A-Za-z0-9]{8}\b'
    "#;

    run_case(Case {
        name: "default-redact",
        config: base,
        marker: secret,
        text: &format!("token {secret}"),
        rule,
        kind: Kind::Redact,
    })
    .await;

    run_case(Case {
        name: "explicit-warn",
        config: &format!("{base}\naction = \"warn\"\n"),
        marker: secret,
        text: &format!("token {secret}"),
        rule,
        kind: Kind::Warn,
    })
    .await;

    run_case(Case {
        name: "explicit-block",
        config: &format!("{base}\naction = \"block\"\n"),
        marker: secret,
        text: &format!("token {secret}"),
        rule,
        kind: Kind::Block,
    })
    .await;

    run_case(Case {
        name: "observe-overrides-block",
        config: r#"
            [redact]
            mode = "observe"
            internal_domains = []

            [redact.builtin]
            aws-access-key-id = "block"
        "#,
        marker: "AKIAIOSFODNN7EXAMPLE",
        text: "key AKIAIOSFODNN7EXAMPLE",
        rule: "aws-access-key-id",
        kind: Kind::Warn,
    })
    .await;

    let pem = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----";
    run_case(Case {
        name: "builtin-private-key-block",
        config: r#"
            [redact]
            internal_domains = []

            [redact.builtin]
            private-key = "block"
        "#,
        marker: "not-a-real-key",
        text: pem,
        rule: "private-key",
        kind: Kind::Block,
    })
    .await;
}

struct Case<'a> {
    name: &'a str,
    config: &'a str,
    marker: &'a str,
    text: &'a str,
    rule: &'a str,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Redact,
    Warn,
    Block,
}

async fn run_case(case: Case<'_>) {
    let redact = symveil::config::Config::parse(case.config)
        .unwrap_or_else(|err| panic!("{}: parse config: {err:#}", case.name))
        .redact;
    let placeholder = match case.kind {
        Kind::Redact => Some(placeholder_for(&redact, case.text, case.marker)),
        Kind::Warn | Kind::Block => None,
    };
    let echo = placeholder
        .clone()
        .unwrap_or_else(|| "upstream-ok".to_string());
    let (openai, openai_hits) =
        spawn_mock(format!(r#"{{"output_text":"{echo}"}}"#).into_bytes(), false).await;
    let (anthropic, anthropic_hits) = spawn_mock(
        format!(
            r#"{{"id":"msg_test","type":"message","role":"assistant","content":[{{"type":"text","text":"{echo}"}}]}}"#
        )
        .into_bytes(),
        false,
    )
    .await;
    let dir = temp_dir(&format!("actions-{}", case.name));
    let audit_path = dir.join("audit.jsonl");
    let state = AppState::new(
        build_engine(Vault::ephemeral(), &redact).unwrap(),
        openai,
        anthropic,
        AuditLog::open(&audit_path).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let client = reqwest::Client::new();
    let payload = serde_json::to_string(case.text).unwrap();

    check_endpoint(
        &case,
        &client,
        &proxy,
        "/v1/responses",
        &format!(r#"{{"model":"gpt-test","input":{payload}}}"#),
        &openai_hits,
        placeholder.as_deref(),
    )
    .await;
    check_endpoint(
        &case,
        &client,
        &proxy,
        "/v1/messages",
        &format!(
            r#"{{"model":"claude-test","max_tokens":16,"messages":[{{"role":"user","content":{payload}}}]}}"#
        ),
        &anthropic_hits,
        placeholder.as_deref(),
    )
    .await;

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        !audit.contains(case.marker),
        "{}: audit contains the matched value:\n{audit}",
        case.name
    );
    assert!(
        audit.contains(case.rule),
        "{}: audit missing rule {}:\n{audit}",
        case.name,
        case.rule
    );
    let action = match case.kind {
        Kind::Redact => "redact",
        Kind::Warn => "warn",
        Kind::Block => "block",
    };
    assert!(
        audit.contains(&format!("\"action\":\"{action}\"")),
        "{}: audit missing action {action}:\n{audit}",
        case.name
    );
    let logged = log_lines_containing(case.rule);
    match case.kind {
        Kind::Redact => {}
        Kind::Warn => {
            assert!(
                logged.contains("forwarded a match unchanged"),
                "{}: missing warn log:\n{logged}",
                case.name
            );
            assert!(!logged.contains(case.marker), "{}:\n{logged}", case.name);
        }
        Kind::Block => {
            assert!(
                logged.contains("blocked request"),
                "{}: missing block log:\n{logged}",
                case.name
            );
            assert!(!logged.contains(case.marker), "{}:\n{logged}", case.name);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

async fn check_endpoint(
    case: &Case<'_>,
    client: &reqwest::Client,
    proxy: &str,
    path: &str,
    body: &str,
    hits: &Arc<Mutex<Vec<Recorded>>>,
    placeholder: Option<&str>,
) {
    let anthropic = path == "/v1/messages";
    let response = client
        .post(format!("{proxy}{path}"))
        .header("content-type", "application/json")
        .header("authorization", "Bearer test-token")
        .header("x-api-key", "sk-ant-test")
        .body(body.to_string())
        .send()
        .await
        .unwrap_or_else(|err| panic!("{} {path}: {err}", case.name));
    let status = response.status();
    let retry = response
        .headers()
        .get("x-should-retry")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let text = response.text().await.unwrap();
    match case.kind {
        Kind::Block => {
            assert_eq!(status, 400, "{} {path}: {text}", case.name);
            assert_eq!(retry.as_deref(), Some("false"), "{} {path}", case.name);
            assert!(
                !text.contains(case.marker),
                "{} {path}: error body contains the matched value:\n{text}",
                case.name
            );
            assert!(hits.lock().unwrap().is_empty(), "{} {path}", case.name);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            let message = if anthropic {
                assert_eq!(value["type"].as_str(), Some("error"), "{text}");
                assert_eq!(
                    value["error"]["type"].as_str(),
                    Some("invalid_request_error"),
                    "{text}"
                );
                assert_eq!(
                    value["message"].as_str(),
                    value["error"]["message"].as_str(),
                    "{text}"
                );
                value["error"]["message"].as_str().unwrap().to_string()
            } else {
                assert_eq!(
                    value["error"]["type"].as_str(),
                    Some("invalid_request_error"),
                    "{text}"
                );
                assert_eq!(
                    value["error"]["code"].as_str(),
                    Some("symveil_blocked"),
                    "{text}"
                );
                assert!(value["error"]["param"].is_null(), "{text}");
                value["error"]["message"].as_str().unwrap().to_string()
            };
            assert!(
                message.contains(case.rule),
                "{} {path}: {message}",
                case.name
            );
            assert!(message.contains("SymVeil blocked"), "{message}");
            assert!(!message.contains(case.marker), "{message}");
        }
        Kind::Warn => {
            assert_eq!(status, 200, "{} {path}: {text}", case.name);
            let seen = hits.lock().unwrap();
            assert_eq!(seen.len(), 1, "{} {path}", case.name);
            assert_eq!(seen[0].path, path);
            let forwarded = String::from_utf8_lossy(&seen[0].body);
            assert!(
                forwarded.contains(case.marker),
                "{} {path}: upstream did not receive the original:\n{forwarded}",
                case.name
            );
        }
        Kind::Redact => {
            assert_eq!(status, 200, "{} {path}: {text}", case.name);
            let placeholder = placeholder.unwrap();
            assert!(
                text.contains(case.marker),
                "{} {path}: client response was not restored:\n{text}",
                case.name
            );
            assert!(!text.contains(placeholder), "{text}");
            let seen = hits.lock().unwrap();
            assert_eq!(seen.len(), 1, "{} {path}", case.name);
            assert_eq!(seen[0].path, path);
            let forwarded = String::from_utf8_lossy(&seen[0].body);
            assert!(
                !forwarded.contains(case.marker),
                "{} {path}: upstream saw the value:\n{forwarded}",
                case.name
            );
            assert!(
                forwarded.contains(placeholder),
                "{} {path}: upstream missing placeholder:\n{forwarded}",
                case.name
            );
        }
    }
}

fn placeholder_for(redact: &RedactSection, text: &str, marker: &str) -> String {
    let mut engine = build_engine(Vault::ephemeral(), redact).unwrap();
    let (redacted, hits) = engine.redact_str(text).unwrap();
    assert!(!redacted.contains(marker), "{redacted}");
    hits.into_iter()
        .find(|hit| hit.original.contains(marker))
        .unwrap()
        .placeholder
}

fn install_logs() -> Arc<Mutex<Vec<String>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let subscriber = LogCapture {
            lines: Arc::clone(&lines),
        };
        tracing::subscriber::set_global_default(subscriber).expect("install log capture");
        lines
    })
    .clone()
}

fn log_lines_containing(rule: &str) -> String {
    install_logs()
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.contains(rule))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

struct LogCapture {
    lines: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN && metadata.target().contains("symveil")
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = LineVisitor::default();
        event.record(&mut visitor);
        self.lines.lock().unwrap().push(format!(
            "{} {}{}",
            event.metadata().target(),
            event.metadata().name(),
            visitor.text
        ));
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[derive(Default)]
struct LineVisitor {
    text: String,
}

impl tracing::field::Visit for LineVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.text, " {}={value:?}", field.name());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let _ = write!(self.text, " {}={value}", field.name());
    }
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
