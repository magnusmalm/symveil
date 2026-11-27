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
use symveil::config::{NamesSection, PiiSection, RedactSection};
use symveil::proxy::AppState;
use symveil::vault::Vault;
use tokio::net::TcpListener;

#[derive(Clone)]
struct MockState {
    hits: Arc<Mutex<Vec<Recorded>>>,
    sse: bool,
    body: Arc<Vec<u8>>,
    echo: bool,
    chunk: usize,
    response_encoding: Option<String>,
}

struct Recorded {
    path: String,
    body: Vec<u8>,
    authorization: Option<String>,
    api_key: Option<String>,
    accept_encoding: Option<String>,
    content_encoding: Option<String>,
    content_length: Option<String>,
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

#[tokio::test]
async fn tool_results_mask_env_and_token_shapes_and_restore_them() {
    let legacy = format!("sk-{}", "A".repeat(48));
    let project = format!("sk-proj-{}", "C".repeat(32));
    let anthropic = format!("sk-ant-{}", "E".repeat(24));
    let header = "eyJhbGciOiJub25lIn0";
    let payload = "eyJzdWIiOiJmYWtlIn0";
    let signature = "ZmFrZXNpZ25hdHVyZQ";
    let jwt = format!("{header}.{payload}.{signature}");
    let db_password = "hunter2hunter2";
    let url_password = "notarealpassword";
    let service = "svc_fake_token_value";
    let env_file = format!(
        "\
# local
export OPENAI_API_KEY={legacy}
OPENAI_PROJECT_KEY={project}
ANTHROPIC_API_KEY={anthropic}
DATABASE_PASSWORD=\"{db_password}\"
export DATABASE_URL=postgres://app:{url_password}@db.example/app
AUTH_TOKEN={jwt}
SERVICE_TOKEN={service} # rotated
TOKEN_LIMIT=4096
MAX_TOKEN=12345678
API_KEY=changeme
API_KEY=${{OTHER_API_KEY}}
"
    );
    let secrets = [
        legacy.as_str(),
        project.as_str(),
        anthropic.as_str(),
        db_password,
        url_password,
        signature,
        service,
        "db.example",
    ];
    let keepers = [
        "OPENAI_API_KEY",
        "OPENAI_PROJECT_KEY",
        "ANTHROPIC_API_KEY",
        "DATABASE_PASSWORD",
        "DATABASE_URL",
        "AUTH_TOKEN",
        "SERVICE_TOKEN",
        "# rotated",
        "TOKEN_LIMIT=4096",
        "MAX_TOKEN=12345678",
        "API_KEY=changeme",
        "API_KEY=${OTHER_API_KEY}",
    ];

    let redact = RedactSection {
        internal_domains: Vec::new(),
        ..RedactSection::default()
    };
    let engine = build_engine(Vault::ephemeral(), &redact).unwrap();
    let (openai, openai_hits) = spawn_echo(true).await;
    let (anthropic_base, anthropic_hits) = spawn_echo(false).await;
    let dir = temp_dir("audit-env");
    let audit_path = dir.join("audit.jsonl");
    let state = AppState::new(
        engine,
        openai,
        anthropic_base,
        AuditLog::open(&audit_path).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let client = reqwest::Client::new();

    let messages = serde_json::json!({
        "model": "claude-test",
        "max_tokens": 64,
        "messages": [{
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "toolu_fake",
                "content": env_file,
            }]
        }]
    });
    let messages_response = client
        .post(format!("{proxy}/v1/messages"))
        .header("content-type", "application/json")
        .header("x-api-key", "sk-ant-test")
        .body(messages.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(messages_response.status(), 200);
    let messages_body = messages_response.text().await.unwrap();
    assert_restored(&messages_body, &secrets, &keepers);
    {
        let seen = anthropic_hits.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/v1/messages");
        let forwarded = String::from_utf8_lossy(&seen[0].body);
        assert_masked(&forwarded, &secrets, &keepers);
    }

    let responses = serde_json::json!({
        "model": "gpt-test",
        "stream": true,
        "input": [{
            "type": "function_call_output",
            "call_id": "call_fake",
            "output": env_file,
        }]
    });
    let responses_response = client
        .post(format!("{proxy}/v1/responses"))
        .header("content-type", "application/json")
        .body(responses.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(responses_response.status(), 200);
    let responses_body = responses_response.text().await.unwrap();
    assert_restored(&responses_body, &secrets, &keepers);
    {
        let seen = openai_hits.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/v1/responses");
        let forwarded = String::from_utf8_lossy(&seen[0].body);
        assert_masked(&forwarded, &secrets, &keepers);
    }

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    for secret in secrets {
        assert!(!audit.contains(secret), "{audit}");
    }
    for rule in [
        "openai-api-key",
        "anthropic-api-key",
        "jwt",
        "dotenv-assignment",
        "env-assignment",
        "env-quoted-assignment",
    ] {
        assert!(audit.contains(rule), "{audit}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn assert_masked(body: &str, secrets: &[&str], keepers: &[&str]) {
    for secret in secrets {
        assert!(!body.contains(secret), "leaked {secret} in {body}");
    }
    for keeper in keepers {
        assert!(body.contains(keeper), "missing {keeper} in {body}");
    }
}

fn assert_restored(body: &str, secrets: &[&str], keepers: &[&str]) {
    for secret in secrets {
        assert!(body.contains(secret), "unrestored {secret} in {body}");
    }
    for keeper in keepers {
        assert!(body.contains(keeper), "missing {keeper} in {body}");
    }
}

/// Five synthetic values from `tests/fixtures/dotenv-repo/.env`.
/// SymVeil does not stop the read. This counts how many of those values the
/// proxy still forwards.
struct DotenvFixture {
    raw: String,
    numbered: String,
    secrets: Vec<String>,
}

fn dotenv_fixture() -> DotenvFixture {
    let raw = include_str!("fixtures/dotenv-repo/.env").to_string();
    let numbered = raw
        .lines()
        .enumerate()
        .map(|(index, line)| format!("{:>6}|{line}", index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let secrets = [
        "sk-Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1",
        "ghp_cD1cD1cD1cD1cD1cD1cD1cD1cD1cD1cD1cD1",
        "n0t-a-token-db-pass",
        "db-url-password",
        "s3ssion-value-9f3a",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    DotenvFixture {
        raw,
        numbered,
        secrets,
    }
}

fn leaked_secrets(body: &str, secrets: &[String]) -> Vec<String> {
    secrets
        .iter()
        .filter(|secret| body.contains(secret.as_str()))
        .cloned()
        .collect()
}

#[tokio::test]
async fn dotenv_file_values_do_not_reach_upstream() {
    let fixture = dotenv_fixture();
    let quoted = format!("contents of /repo/.env:\n{}", fixture.raw);
    let redact = RedactSection {
        internal_domains: Vec::new(),
        ..RedactSection::default()
    };
    let engine = build_engine(Vault::ephemeral(), &redact).unwrap();
    let (openai, openai_hits) = spawn_echo(false).await;
    let (anthropic_base, anthropic_hits) = spawn_echo(false).await;
    let dir = temp_dir("dotenv-leak");
    let state = AppState::new(
        engine,
        openai,
        anthropic_base,
        AuditLog::open(&dir.join("audit.jsonl")).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let client = reqwest::Client::new();

    let shapes = [
        (
            "anthropic-messages",
            "/v1/messages",
            true,
            serde_json::json!({
                "model": "claude-test",
                "max_tokens": 16,
                "messages": [
                    {"role": "user", "content": "Read /repo/.env"},
                    {"role": "assistant", "content": [{
                        "type": "tool_use",
                        "id": "toolu_env",
                        "name": "Read",
                        "input": {"file_path": "/repo/.env"}
                    }]},
                    {"role": "user", "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_env",
                            "content": fixture.numbered
                        },
                        {"type": "text", "text": quoted}
                    ]}
                ]
            }),
        ),
        (
            "openai-chat",
            "/v1/chat/completions",
            false,
            serde_json::json!({
                "model": "gpt-test",
                "messages": [
                    {"role": "user", "content": quoted},
                    {"role": "assistant", "tool_calls": [{
                        "id": "call_env",
                        "type": "function",
                        "function": {
                            "name": "Read",
                            "arguments": "{\"file_path\":\"/repo/.env\"}"
                        }
                    }]},
                    {"role": "tool", "tool_call_id": "call_env", "content": fixture.numbered}
                ]
            }),
        ),
        (
            "openai-responses",
            "/v1/responses",
            false,
            serde_json::json!({
                "model": "gpt-test",
                "input": [
                    {"role": "user", "content": quoted},
                    {
                        "type": "function_call",
                        "name": "Read",
                        "call_id": "call_env",
                        "arguments": "{\"file_path\":\"/repo/.env\"}"
                    },
                    {
                        "type": "function_call_output",
                        "call_id": "call_env",
                        "output": fixture.numbered
                    }
                ]
            }),
        ),
    ];

    let mut leaks = Vec::new();
    for (name, path, anthropic, body) in shapes {
        let request = client
            .post(format!("{proxy}{path}"))
            .header("content-type", "application/json");
        let request = if anthropic {
            request.header("x-api-key", "sk-ant-test")
        } else {
            request.header("authorization", "Bearer test")
        };
        let response = request.body(body.to_string()).send().await.unwrap();
        assert_eq!(response.status(), 200, "{name}");
        let restored = response.text().await.unwrap();
        for secret in &fixture.secrets {
            assert!(restored.contains(secret), "{name} did not restore {secret}");
        }
        assert!(restored.contains("TOKEN_LIMIT=4096"), "{name}");
        let hits = if anthropic {
            anthropic_hits.lock().unwrap()
        } else {
            openai_hits.lock().unwrap()
        };
        let seen = hits
            .iter()
            .rev()
            .find(|hit| hit.path == path)
            .unwrap_or_else(|| panic!("{name} did not reach upstream"));
        let forwarded = String::from_utf8_lossy(&seen.body);
        let leaked = leaked_secrets(&forwarded, &fixture.secrets);
        let host_left = forwarded.contains("db.internal.example");
        leaks.push(format!(
            "{name}: {} of 5: {leaked:?}; host_left={host_left}",
            leaked.len()
        ));
        assert!(forwarded.contains("OPENAI_API_KEY"), "{name}");
        assert!(forwarded.contains("SESSION_COOKIE"), "{name}");
        assert!(forwarded.contains("PGPASSWORD"), "{name}");
        assert!(forwarded.contains("DATABASE_URL"), "{name}");
        assert!(forwarded.contains("GITHUB_PAT"), "{name}");
        assert!(forwarded.contains("TOKEN_LIMIT=4096"), "{name}");
        drop(hits);
    }
    assert!(
        leaks
            .iter()
            .all(|line| line.contains("0 of 5") && line.contains("host_left=false")),
        "secret values reached upstream:\n{}",
        leaks.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

async fn spawn_echo(sse: bool) -> (String, Arc<Mutex<Vec<Recorded>>>) {
    spawn_mock_inner(Vec::new(), sse, true, 7, None).await
}

async fn spawn_mock(body: Vec<u8>, sse: bool) -> (String, Arc<Mutex<Vec<Recorded>>>) {
    spawn_mock_inner(body, sse, false, 1, None).await
}

async fn spawn_encoded(body: Vec<u8>, encoding: &str) -> (String, Arc<Mutex<Vec<Recorded>>>) {
    spawn_mock_inner(body, false, false, 1, Some(encoding.to_string())).await
}

async fn spawn_mock_inner(
    body: Vec<u8>,
    sse: bool,
    echo: bool,
    chunk: usize,
    response_encoding: Option<String>,
) -> (String, Arc<Mutex<Vec<Recorded>>>) {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        hits: Arc::clone(&hits),
        sse,
        body: Arc::new(body),
        echo,
        chunk,
        response_encoding,
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
    // Record the arrival before reading the body so a forwarded bomb still
    // counts when the read fails.
    let slot = {
        let mut hits = state.hits.lock().unwrap();
        hits.push(Recorded {
            path,
            body: Vec::new(),
            authorization: header_string(&headers, "authorization"),
            api_key: header_string(&headers, "x-api-key"),
            accept_encoding: header_string(&headers, "accept-encoding"),
            content_encoding: header_string(&headers, "content-encoding"),
            content_length: header_string(&headers, "content-length"),
        });
        hits.len() - 1
    };
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap_or_default();
    if let Some(hit) = state.hits.lock().unwrap().get_mut(slot) {
        hit.body = body.to_vec();
    }
    let payload = if state.echo {
        body.to_vec()
    } else {
        (*state.body).clone()
    };
    let content_type = if state.sse {
        "text/event-stream"
    } else {
        "application/json"
    };
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type);
    if let Some(encoding) = &state.response_encoding {
        builder = builder.header("content-encoding", encoding.as_str());
    }
    if state.sse {
        let chunks = stream_chunks(payload, state.chunk.max(1));
        builder.body(Body::from_stream(chunks)).unwrap()
    } else {
        builder.body(Body::from(payload)).unwrap()
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

const PII_PROMPT: &str = "\
Reach ada@example.com or +46 70 000 00 00 about 20990101-9993 and 990161-9990. \
Keep ssh user@host, git@github.com:acme/widgets.git, date 2024-11-10, version 1.2.3, \
sha a1b2c3d4e5f6789012345678901234567890abcd, and bad 20990101-9994.";

const PII_VALUES: &[&str] = &[
    "ada@example.com",
    "+46 70 000 00 00",
    "20990101-9993",
    "990161-9990",
];

const PII_KEEPERS: &[&str] = &[
    "user@host",
    "git@github.com:acme/widgets.git",
    "2024-11-10",
    "1.2.3",
    "a1b2c3d4e5f6789012345678901234567890abcd",
    "20990101-9994",
];

#[tokio::test]
async fn pii_on_masks_each_type_and_restores_the_stream() {
    let mut engine = build_engine(Vault::ephemeral(), &pii_redact(true)).unwrap();
    let (preview, hits) = engine.redact_str(PII_PROMPT).unwrap();
    assert_eq!(hits.len(), PII_VALUES.len(), "{preview}");
    for value in PII_VALUES {
        assert!(
            !preview.contains(value),
            "{value} reached the preview: {preview}"
        );
        assert!(
            hits.iter()
                .any(|hit| hit.original == *value && hit.category.as_str() == "pii"),
            "missing {value}"
        );
    }
    for keeper in PII_KEEPERS {
        assert!(preview.contains(keeper), "{keeper} missing from {preview}");
    }
    let restored_bits: Vec<String> = hits.iter().map(|hit| hit.placeholder.clone()).collect();
    let spoken = hits
        .iter()
        .map(|hit| hit.placeholder.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let sse = format!(
        "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{spoken}\"}}}}]}}\n\ndata: [DONE]\n\n"
    );

    let (openai, openai_hits) = spawn_mock(sse.into_bytes(), true).await;
    let (anthropic, _) = spawn_mock(b"{}".to_vec(), false).await;
    let dir = temp_dir("audit-pii");
    let audit_path = dir.join("audit.jsonl");
    let state = AppState::new(
        engine,
        openai,
        anthropic,
        AuditLog::open(&audit_path).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let response = reqwest::Client::new()
        .post(format!("{proxy}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(pii_request())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-symveil-redactions")
            .and_then(|value| value.to_str().ok()),
        Some("4")
    );
    let body = response.text().await.unwrap();
    for value in PII_VALUES {
        assert!(
            body.contains(value),
            "response did not restore {value}: {body}"
        );
    }
    for placeholder in &restored_bits {
        assert!(!body.contains(placeholder), "placeholder leaked: {body}");
    }
    assert!(body.contains("[DONE]"));

    let seen = openai_hits.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let forwarded = content_of(&seen[0].body);
    for value in PII_VALUES {
        assert!(
            !forwarded.contains(value),
            "{value} reached upstream: {forwarded}"
        );
    }
    for keeper in PII_KEEPERS {
        assert!(
            forwarded.contains(keeper),
            "{keeper} was masked on the way out: {forwarded}"
        );
    }

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    for value in PII_VALUES {
        assert!(
            !audit.contains(value),
            "{value} written to the audit log: {audit}"
        );
    }
    let mut saw_request = false;
    for line in audit.lines() {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        if event["dir"] != "request" {
            continue;
        }
        saw_request = true;
        let replacements = event["replacements"].as_array().unwrap();
        assert_eq!(replacements.len(), PII_VALUES.len());
        for replacement in replacements {
            assert_eq!(replacement["category"], "pii");
            assert!(replacement.get("original").is_none(), "{replacement}");
            assert!(replacement["rule"].as_str().is_some());
            assert!(replacement["len"].as_u64().is_some());
        }
    }
    assert!(saw_request);
    assert!(audit.contains("\"dir\":\"response\""));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pii_off_leaves_personal_data_unchanged() {
    let engine = build_engine(Vault::ephemeral(), &pii_redact(false)).unwrap();
    let (openai, openai_hits) = spawn_mock(b"data: [DONE]\n\n".to_vec(), true).await;
    let (anthropic, _) = spawn_mock(b"{}".to_vec(), false).await;
    let dir = temp_dir("audit-pii-off");
    let state = AppState::new(
        engine,
        openai,
        anthropic,
        AuditLog::open(&dir.join("audit.jsonl")).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let response = reqwest::Client::new()
        .post(format!("{proxy}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(pii_request())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-symveil-redactions")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    let body = response.text().await.unwrap();
    assert_eq!(body, "data: [DONE]\n\n");
    let seen = openai_hits.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(content_of(&seen[0].body), PII_PROMPT);
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
    assert!(audit.is_empty(), "{audit}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn pii_redact(on: bool) -> RedactSection {
    RedactSection {
        internal_domains: Vec::new(),
        pii: PiiSection {
            email: on,
            phone: on,
            personnummer: on,
        },
        ..RedactSection::default()
    }
}

fn pii_request() -> String {
    format!(
        r#"{{"model":"gpt-test","stream":true,"messages":[{{"role":"user","content":"{}"}}]}}"#,
        PII_PROMPT
    )
}

fn content_of(body: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap();
    value["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string()
}

fn seed_value(id: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/leak/seed.json");
    let seed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let item = seed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("seed item {id} missing"));
    assert_eq!(
        item["expect"].as_str(),
        Some("masked"),
        "{id} is no longer a masked seed"
    );
    item["value"]
        .as_str()
        .unwrap_or_else(|| panic!("seed item {id} has no string value"))
        .to_string()
}

fn seeded_request() -> (Vec<u8>, String, String, String) {
    let exempla = seed_value("company-exempla");
    let tundrahorn = seed_value("company-tundrahorn");
    let aws = seed_value("aws-access-key");
    let payload = serde_json::json!({
        "model": "grok-test",
        "input": format!("{exempla} builds {tundrahorn} fläkt {aws}"),
    });
    (
        serde_json::to_vec(&payload).unwrap(),
        exempla,
        tundrahorn,
        aws,
    )
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn zstd_bytes(data: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(data, 3).unwrap()
}

fn gzip_zeros(len: usize) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let chunk = [0u8; 8192];
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len());
        enc.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    enc.finish().unwrap()
}

struct Upstream {
    proxy: String,
    hits: Arc<Mutex<Vec<Recorded>>>,
    audit_path: std::path::PathBuf,
    dir: std::path::PathBuf,
}

async fn seed_upstream() -> Upstream {
    let exempla = seed_value("company-exempla");
    let tundrahorn = seed_value("company-tundrahorn");
    let redact = RedactSection {
        internal_domains: Vec::new(),
        names: NamesSection {
            terms: vec![exempla, tundrahorn],
            ..NamesSection::default()
        },
        ..RedactSection::default()
    };
    let engine = build_engine(Vault::ephemeral(), &redact).unwrap();
    let (upstream, hits) = spawn_mock(b"{}".to_vec(), false).await;
    let dir = temp_dir("audit-encoding");
    let audit_path = dir.join("audit.jsonl");
    let state = AppState::new(
        engine,
        upstream.clone(),
        upstream,
        AuditLog::open(&audit_path).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    Upstream {
        proxy,
        hits,
        audit_path,
        dir,
    }
}

async fn post_encoded(proxy: &str, encoding: &str, body: Vec<u8>) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{proxy}/v1/responses"))
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .header("content-encoding", encoding)
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn assert_compressed_is_masked(encoding: &str, compress: fn(&[u8]) -> Vec<u8>) {
    let (plain, exempla, tundrahorn, aws) = seeded_request();
    let compressed = compress(&plain);
    assert_ne!(compressed, plain);
    let upstream = seed_upstream().await;
    let response = post_encoded(&upstream.proxy, encoding, compressed).await;
    assert_eq!(response.status(), 200);
    let count: usize = response
        .headers()
        .get("x-symveil-redactions")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(count >= 3, "redactions={count}");

    let seen = upstream.hits.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].content_encoding.is_none(),
        "{:?}",
        seen[0].content_encoding
    );
    let length: usize = seen[0]
        .content_length
        .as_deref()
        .unwrap_or_else(|| panic!("missing content-length"))
        .parse()
        .unwrap();
    assert_eq!(length, seen[0].body.len());
    assert_ne!(&seen[0].body[..2.min(seen[0].body.len())], b"\x1f\x8b");
    assert!(
        seen[0].body.len() < 4 || &seen[0].body[..4] != b"\x28\xb5\x2f\xfd",
        "forwarded body is still zstd"
    );
    let forwarded: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
    let input = forwarded["input"].as_str().unwrap();
    assert!(input.contains("fläkt"), "{input}");
    assert!(input.contains("builds"), "{input}");
    assert!(!input.contains(&exempla), "{input}");
    assert!(!input.contains(&tundrahorn), "{input}");
    assert!(!input.contains(&aws), "{input}");
    assert!(input.contains("@@sv:"), "{input}");
    let raw = String::from_utf8_lossy(&seen[0].body);
    assert!(!raw.contains(&exempla), "{raw}");
    assert!(!raw.contains(&tundrahorn), "{raw}");
    assert!(!raw.contains(&aws), "{raw}");
    assert_eq!(seen[0].authorization.as_deref(), Some("Bearer test-token"));

    let audit = std::fs::read_to_string(&upstream.audit_path).unwrap();
    assert!(audit.contains("aws-access-key-id"), "{audit}");
    assert!(audit.contains("name-term"), "{audit}");
    assert!(!audit.contains(&aws), "{audit}");
    assert!(!audit.contains("\"dir\":\"refuse\""), "{audit}");
    drop(seen);
    let _ = std::fs::remove_dir_all(&upstream.dir);
}

#[tokio::test]
async fn zstd_request_reaches_upstream_masked_and_valid() {
    assert_compressed_is_masked("zstd", zstd_bytes).await;
}

#[tokio::test]
async fn gzip_request_reaches_upstream_masked_and_valid() {
    assert_compressed_is_masked("gzip", gzip_bytes).await;
}

async fn assert_refused(encoding: &str, body: Vec<u8>, status: u16, reason: &str) {
    let aws = seed_value("aws-access-key");
    let exempla = seed_value("company-exempla");
    let upstream = seed_upstream().await;
    let response = post_encoded(&upstream.proxy, encoding, body).await;
    assert_eq!(response.status().as_u16(), status);
    let text = response.text().await.unwrap();
    assert!(text.contains("symveil_error"), "{text}");
    assert!(text.contains("symveil refused"), "{text}");
    assert!(!text.contains(&aws), "{text}");
    assert!(!text.contains(&exempla), "{text}");
    assert!(upstream.hits.lock().unwrap().is_empty());
    let audit = std::fs::read_to_string(&upstream.audit_path).unwrap();
    assert!(audit.contains("\"dir\":\"refuse\""), "{audit}");
    assert!(audit.contains(reason), "{audit}");
    assert!(audit.contains(&format!("\"status\":{status}")), "{audit}");
    assert!(!audit.contains(&aws), "{audit}");
    assert!(!audit.contains(&exempla), "{audit}");
    assert!(audit.len() < 4096, "audit line looks like it stored a body");
    let _ = std::fs::remove_dir_all(&upstream.dir);
}

#[tokio::test]
async fn corrupt_zstd_is_rejected_and_not_forwarded() {
    let aws = seed_value("aws-access-key");
    let mut body = aws.into_bytes();
    body.extend_from_slice(b" not-a-zstd-frame Exempla");
    assert_refused("zstd", body, 400, "content-encoding-decode").await;
}

#[tokio::test]
async fn unknown_encoding_is_rejected_and_not_forwarded() {
    let (plain, _, _, _) = seeded_request();
    assert_refused("xz", plain, 415, "unsupported-content-encoding").await;
}

#[tokio::test]
async fn stacked_encoding_is_rejected_and_not_forwarded() {
    let (plain, _, _, _) = seeded_request();
    assert_refused(
        "gzip, zstd",
        gzip_bytes(&plain),
        415,
        "stacked-content-encoding",
    )
    .await;
}

#[tokio::test]
async fn decompression_bomb_is_rejected_and_not_forwarded() {
    const {
        assert!(
            symveil::proxy::MAX_BODY >= 32 * 1024 * 1024,
            "decoded body cap dropped below 32 MiB"
        );
    };
    let bomb = gzip_zeros(symveil::proxy::MAX_BODY + 1);
    assert!(
        bomb.len() * 10 < symveil::proxy::MAX_BODY,
        "fixture is not a bomb: {} bytes on the wire",
        bomb.len()
    );
    assert!(bomb.len() < symveil::proxy::MAX_BODY);
    assert_refused("gzip", bomb, 413, "decompressed-body-too-large").await;
}

#[tokio::test]
async fn compressed_upstream_response_is_not_forwarded_unrestored() {
    let aws = seed_value("aws-access-key");
    let payload = serde_json::json!({ "text": format!("{aws} @@sv:0123abcd@@") });
    let compressed = gzip_bytes(&serde_json::to_vec(&payload).unwrap());
    let (upstream, hits) = spawn_encoded(compressed, "gzip").await;
    let redact = RedactSection {
        internal_domains: Vec::new(),
        ..RedactSection::default()
    };
    let dir = temp_dir("audit-compressed-response");
    let audit_path = dir.join("audit.jsonl");
    let state = AppState::new(
        build_engine(Vault::ephemeral(), &redact).unwrap(),
        upstream.clone(),
        upstream,
        AuditLog::open(&audit_path).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let response = reqwest::Client::new()
        .post(format!("{proxy}/v1/responses"))
        .header("content-type", "application/json")
        .body(r#"{"model":"grok-test","input":"hello"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    let bytes = response.bytes().await.unwrap();
    assert_ne!(&bytes[..2.min(bytes.len())], b"\x1f\x8b");
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("symveil_error"), "{text}");
    assert!(text.contains("compressed body"), "{text}");
    assert!(!text.contains(&aws), "{text}");
    assert!(!text.contains("@@sv:"), "{text}");
    assert_eq!(hits.lock().unwrap().len(), 1);
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(audit.contains("\"dir\":\"refuse\""), "{audit}");
    assert!(audit.contains("compressed-response"), "{audit}");
    assert!(audit.contains("\"encoding\":\"gzip\""), "{audit}");
    assert!(!audit.contains(&aws), "{audit}");
    let _ = std::fs::remove_dir_all(&dir);
}
