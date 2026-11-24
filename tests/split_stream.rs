//! The proxy restores placeholders that a fake upstream splits across SSE deltas.
//!
//! Each logical argument or text string is cut at every character boundary and
//! sent as two deltas. Parallel tool calls interleave those deltas. The mock
//! also emits the bytes one at a time, so a cut inside a token is not aligned
//! to an HTTP chunk.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use serde_json::Value;
use symveil::audit::AuditLog;
use symveil::build_engine;
use symveil::config::RedactSection;
use symveil::proxy::AppState;
use symveil::vault::Vault;
use tokio::net::TcpListener;

const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
const GITHUB: &str = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const DUMMY: &str = "@@sv:00000000@@";

#[derive(Clone)]
struct MockState {
    hits: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[tokio::test]
async fn proxy_restores_split_placeholders_for_every_stream_shape() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let mock = spawn_mock(Arc::clone(&hits)).await;
    let redact = RedactSection {
        internal_domains: Vec::new(),
        ..RedactSection::default()
    };
    let engine = build_engine(Vault::ephemeral(), &redact).unwrap();
    let dir = temp_dir("split-stream");
    let audit_path = dir.join("audit.jsonl");
    let state = AppState::new(
        engine,
        mock.clone(),
        mock,
        AuditLog::open(&audit_path).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let tool_len = tool_logical(DUMMY).chars().count();
    let text_len = text_logical(DUMMY).chars().count();
    let password = password_secret();

    for shape in ["chat_tools", "anthropic_tools", "responses_tools"] {
        for at in 0..=tool_len {
            drive(
                &client,
                &proxy,
                &Case {
                    shape,
                    split: at,
                    split_b: None,
                    secrets: vec![AWS.to_string()],
                },
            )
            .await;
            drive(
                &client,
                &proxy,
                &Case {
                    shape,
                    split: at,
                    split_b: Some(tool_len - at),
                    secrets: vec![AWS.to_string(), GITHUB.to_string()],
                },
            )
            .await;
            drive(
                &client,
                &proxy,
                &Case {
                    shape,
                    split: at,
                    split_b: None,
                    secrets: vec![password.clone()],
                },
            )
            .await;
        }
    }
    for shape in ["chat_text", "anthropic_text", "responses_text"] {
        for at in 0..=text_len {
            drive(
                &client,
                &proxy,
                &Case {
                    shape,
                    split: at,
                    split_b: None,
                    secrets: vec![AWS.to_string()],
                },
            )
            .await;
        }
    }

    let seen = hits.lock().unwrap();
    assert!(!seen.is_empty());
    for body in seen.iter() {
        let text = String::from_utf8_lossy(body);
        assert!(!text.contains("AKIA"), "{text}");
        assert!(!text.contains("ghp_"), "{text}");
        assert!(!text.contains("p@ss"), "{text}");
        assert!(text.contains("@@sv:"), "{text}");
    }
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains("AKIA"));
    assert!(!audit.contains("ghp_"));
    assert!(!audit.contains("p@ss"));
    let _ = std::fs::remove_dir_all(&dir);
}

struct Case {
    shape: &'static str,
    split: usize,
    split_b: Option<usize>,
    secrets: Vec<String>,
}

async fn drive(client: &reqwest::Client, proxy: &str, case: &Case) {
    let path = match case.shape {
        "anthropic_tools" | "anthropic_text" => "/v1/messages",
        "responses_tools" | "responses_text" => "/v1/responses",
        "chat_tools" | "chat_text" => "/v1/chat/completions",
        _ => unreachable!(),
    };
    let content = case.secrets.join(" ");
    let mut request = serde_json::json!({
        "stream": true,
        "shape": case.shape,
        "split": case.split,
        "messages": [{"role": "user", "content": content}],
    });
    if let Some(split_b) = case.split_b {
        request["split_b"] = serde_json::json!(split_b);
    }
    let response = client
        .post(format!("{proxy}{path}"))
        .header("content-type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .unwrap_or_else(|err| panic!("{} split {}: {err}", case.shape, case.split));
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(
        status, 200,
        "{} split {} body {body}",
        case.shape, case.split
    );
    assert_frames(&body, case);
    assert!(
        !body.contains("@@sv:"),
        "{} split {}: {body}",
        case.shape,
        case.split
    );
    match case.shape {
        "chat_tools" | "anthropic_tools" | "responses_tools" => {
            for (index, secret) in case.secrets.iter().enumerate() {
                let joined = joined_tool(&body, case.shape, index);
                let parsed: Value = serde_json::from_str(&joined).unwrap_or_else(|err| {
                    panic!(
                        "{} tool {index} split {} is not json: {err} joined {joined}",
                        case.shape, case.split
                    )
                });
                assert_eq!(
                    parsed["cmd"],
                    format!("echo {secret}"),
                    "{} tool {index} split {}",
                    case.shape,
                    case.split
                );
            }
            if case.shape == "responses_tools" {
                for (index, secret) in case.secrets.iter().enumerate() {
                    assert_eq!(
                        done_cmd(&body, index),
                        format!("echo {secret}"),
                        "done event tool {index} split {}",
                        case.split
                    );
                }
            }
        }
        "chat_text" | "anthropic_text" | "responses_text" => {
            let secret = &case.secrets[0];
            assert_eq!(
                joined_text(&body, case.shape),
                format!("café key {secret} end"),
                "{} split {}",
                case.shape,
                case.split
            );
            if case.shape == "responses_text" {
                assert_eq!(done_text(&body), format!("café key {secret} end"));
            }
        }
        _ => unreachable!(),
    }
}

fn password_secret() -> String {
    "password = \"p@ss\\word12\"".to_string()
}

fn tool_logical(placeholder: &str) -> String {
    format!(r#"{{"cmd":"echo {placeholder}"}}"#)
}

fn text_logical(placeholder: &str) -> String {
    format!("café key {placeholder} end")
}

fn assert_frames(body: &str, case: &Case) {
    assert!(
        body.ends_with("\n\n"),
        "{} split {} missing frame terminator: {body}",
        case.shape,
        case.split
    );
    let mut saw_event = false;
    for block in body.split("\n\n") {
        if block.is_empty() {
            continue;
        }
        saw_event = true;
        let data = event_data(block);
        if data.trim() == "[DONE]" {
            continue;
        }
        serde_json::from_str::<Value>(&data).unwrap_or_else(|err| {
            panic!(
                "{} split {} invalid json ({err}) in {block}",
                case.shape, case.split
            )
        });
    }
    assert!(saw_event, "{} split {} empty body", case.shape, case.split);
    if case.shape.starts_with("anthropic") {
        assert!(body.contains("event: "), "{body}");
    }
    if case.shape.starts_with("responses") {
        assert!(body.contains("event: response."), "{body}");
    }
}

fn event_data(block: &str) -> String {
    let mut lines = Vec::new();
    for line in block.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("data:") {
            lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    lines.join("\n")
}

fn frames(body: &str) -> Vec<Value> {
    body.split("\n\n")
        .filter(|block| !block.is_empty())
        .filter_map(|block| {
            let data = event_data(block);
            if data.trim() == "[DONE]" {
                None
            } else {
                Some(serde_json::from_str(&data).unwrap())
            }
        })
        .collect()
}

fn joined_tool(body: &str, shape: &str, index: usize) -> String {
    let mut out = String::new();
    for value in frames(body) {
        match shape {
            "chat_tools" => {
                let Some(calls) = value
                    .pointer("/choices/0/delta/tool_calls")
                    .and_then(Value::as_array)
                else {
                    continue;
                };
                for call in calls {
                    if call.get("index").and_then(Value::as_u64) != Some(index as u64) {
                        continue;
                    }
                    if let Some(args) = call.pointer("/function/arguments").and_then(Value::as_str)
                    {
                        out.push_str(args);
                    }
                }
            }
            "anthropic_tools" => {
                if value.get("index").and_then(Value::as_u64) != Some(index as u64) {
                    continue;
                }
                if value.pointer("/delta/type").and_then(Value::as_str) != Some("input_json_delta")
                {
                    continue;
                }
                if let Some(part) = value.pointer("/delta/partial_json").and_then(Value::as_str) {
                    out.push_str(part);
                }
            }
            "responses_tools" => {
                if value.get("type").and_then(Value::as_str)
                    != Some("response.function_call_arguments.delta")
                {
                    continue;
                }
                if value.get("output_index").and_then(Value::as_u64) != Some(index as u64) {
                    continue;
                }
                if let Some(part) = value.get("delta").and_then(Value::as_str) {
                    out.push_str(part);
                }
            }
            _ => unreachable!(),
        }
    }
    out
}

fn joined_text(body: &str, shape: &str) -> String {
    let mut out = String::new();
    for value in frames(body) {
        match shape {
            "chat_text" => {
                if let Some(text) = value
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                {
                    out.push_str(text);
                }
            }
            "anthropic_text" => {
                if value.pointer("/delta/type").and_then(Value::as_str) == Some("text_delta") {
                    if let Some(text) = value.pointer("/delta/text").and_then(Value::as_str) {
                        out.push_str(text);
                    }
                }
            }
            "responses_text" => {
                if value.get("type").and_then(Value::as_str) == Some("response.output_text.delta") {
                    if let Some(text) = value.get("delta").and_then(Value::as_str) {
                        out.push_str(text);
                    }
                }
            }
            _ => unreachable!(),
        }
    }
    out
}

fn done_cmd(body: &str, index: usize) -> String {
    for value in frames(body) {
        if value.get("type").and_then(Value::as_str)
            != Some("response.function_call_arguments.done")
        {
            continue;
        }
        if value.get("output_index").and_then(Value::as_u64) != Some(index as u64) {
            continue;
        }
        let args = value.get("arguments").and_then(Value::as_str).unwrap_or("");
        let parsed: Value = serde_json::from_str(args).unwrap();
        return parsed["cmd"].as_str().unwrap_or("").to_string();
    }
    String::new()
}

fn done_text(body: &str) -> String {
    for value in frames(body) {
        if value.get("type").and_then(Value::as_str) == Some("response.output_text.done") {
            return value
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
    }
    String::new()
}

async fn spawn_mock(hits: Arc<Mutex<Vec<Vec<u8>>>>) -> String {
    let app = Router::new()
        .fallback(any(mock_handler))
        .with_state(MockState { hits });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn mock_handler(State(state): State<MockState>, req: Request<Body>) -> Response {
    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .unwrap();
    state.hits.lock().unwrap().push(body.to_vec());
    let text = String::from_utf8_lossy(&body);
    let value: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(err) => return plain(StatusCode::BAD_REQUEST, &format!("request json: {err}")),
    };
    let shape = value.get("shape").and_then(Value::as_str).unwrap_or("");
    let split = value.get("split").and_then(Value::as_u64).unwrap_or(0) as usize;
    let split_b = value
        .get("split_b")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    let phs = placeholders(&text);
    let sse = match build_sse(shape, split, split_b, &phs) {
        Ok(sse) => sse,
        Err(err) => return plain(StatusCode::BAD_REQUEST, &err),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(byte_chunks(sse.into_bytes())))
        .unwrap()
}

fn plain(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Body::from(message.to_string()))
        .unwrap()
}

fn placeholders(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 15 <= bytes.len() {
        let token = &bytes[index..index + 15];
        let hex = token.len() >= 15
            && &token[..5] == b"@@sv:"
            && &token[13..15] == b"@@"
            && token[5..13].iter().all(|byte| byte.is_ascii_hexdigit());
        if hex {
            found.push(body[index..index + 15].to_string());
            index += 15;
        } else {
            index += 1;
        }
    }
    found
}

fn build_sse(
    shape: &str,
    split: usize,
    split_b: Option<usize>,
    phs: &[String],
) -> Result<String, String> {
    if phs.is_empty() {
        return Err("upstream request had no placeholder".to_string());
    }
    match shape {
        "chat_tools" | "anthropic_tools" | "responses_tools" => {
            let first = split_pair(&tool_logical(&phs[0]), split)?;
            let mut tools = vec![first];
            if let Some(split_b) = split_b {
                if phs.len() < 2 {
                    return Err("interleaved tools need two placeholders".to_string());
                }
                tools.push(split_pair(&tool_logical(&phs[1]), split_b)?);
            }
            let tools: Vec<(&str, &str)> = tools
                .iter()
                .map(|(left, right)| (left.as_str(), right.as_str()))
                .collect();
            Ok(match shape {
                "chat_tools" => chat_tool_sse(&tools),
                "anthropic_tools" => anthropic_tool_sse(&tools),
                "responses_tools" => responses_tool_sse(&tools),
                _ => unreachable!(),
            })
        }
        "chat_text" | "anthropic_text" | "responses_text" => {
            let (left, right) = split_pair(&text_logical(&phs[0]), split)?;
            Ok(match shape {
                "chat_text" => chat_text_sse(&left, &right),
                "anthropic_text" => anthropic_text_sse(&left, &right),
                "responses_text" => responses_text_sse(&left, &right),
                _ => unreachable!(),
            })
        }
        _ => Err(format!("unknown shape {shape}")),
    }
}

fn split_pair(text: &str, at: usize) -> Result<(String, String), String> {
    let count = text.chars().count();
    if at > count {
        return Err(format!("split {at} past end {count}"));
    }
    if at == count {
        return Ok((text.to_string(), String::new()));
    }
    let Some((idx, _)) = text.char_indices().nth(at) else {
        return Err(format!("split {at} is not a character boundary"));
    };
    Ok((text[..idx].to_string(), text[idx..].to_string()))
}

fn chat_tool_sse(tools: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (left, _)) in tools.iter().enumerate() {
        push_data(
            &mut out,
            &serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {
                        "tool_calls": [{
                            "index": index,
                            "id": format!("call_{index}"),
                            "type": "function",
                            "function": {"name": "run_terminal_command", "arguments": left}
                        }]
                    }
                }]
            }),
        );
    }
    for (index, (_, right)) in tools.iter().enumerate() {
        push_data(
            &mut out,
            &serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {
                        "tool_calls": [{
                            "index": index,
                            "function": {"arguments": right}
                        }]
                    }
                }]
            }),
        );
    }
    out.push_str(
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
    );
    out.push_str("data: [DONE]\n\n");
    out
}

fn chat_text_sse(left: &str, right: &str) -> String {
    let mut out = String::new();
    for part in [left, right] {
        push_data(
            &mut out,
            &serde_json::json!({"choices": [{"index": 0, "delta": {"content": part}}]}),
        );
    }
    out.push_str(
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
    );
    out
}

fn anthropic_tool_sse(tools: &[(&str, &str)]) -> String {
    let mut out = String::from(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\n",
    );
    out.push_str("event: ping\ndata: {\"type\":\"ping\"}\n\n");
    for (index, _) in tools.iter().enumerate() {
        push_event(
            &mut out,
            "content_block_start",
            &serde_json::json!({
                "type": "content_block_start",
                "index": index,
                "content_block": {
                    "type": "tool_use",
                    "id": format!("toolu_{index}"),
                    "name": "run_terminal_command",
                    "input": {}
                }
            }),
        );
    }
    for (index, (left, _)) in tools.iter().enumerate() {
        push_partial(&mut out, index, left);
    }
    for (index, (_, right)) in tools.iter().enumerate() {
        push_partial(&mut out, index, right);
    }
    for index in 0..tools.len() {
        push_event(
            &mut out,
            "content_block_stop",
            &serde_json::json!({"type": "content_block_stop", "index": index}),
        );
    }
    push_event(
        &mut out,
        "message_delta",
        &serde_json::json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
    );
    push_event(
        &mut out,
        "message_stop",
        &serde_json::json!({"type": "message_stop"}),
    );
    out
}

fn push_partial(out: &mut String, index: usize, text: &str) {
    push_event(
        out,
        "content_block_delta",
        &serde_json::json!({
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "input_json_delta", "partial_json": text}
        }),
    );
}

fn anthropic_text_sse(left: &str, right: &str) -> String {
    let mut out = String::new();
    push_event(
        &mut out,
        "content_block_start",
        &serde_json::json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""}
        }),
    );
    for part in [left, right] {
        push_event(
            &mut out,
            "content_block_delta",
            &serde_json::json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": part}
            }),
        );
    }
    push_event(
        &mut out,
        "content_block_stop",
        &serde_json::json!({"type": "content_block_stop", "index": 0}),
    );
    out
}

fn responses_tool_sse(tools: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, _) in tools.iter().enumerate() {
        push_event(
            &mut out,
            "response.output_item.added",
            &serde_json::json!({
                "type": "response.output_item.added",
                "output_index": index,
                "item": {
                    "type": "function_call",
                    "id": format!("fc_{index}"),
                    "call_id": format!("call_{index}"),
                    "name": "run_terminal_command",
                    "arguments": ""
                }
            }),
        );
    }
    for (index, (left, _)) in tools.iter().enumerate() {
        push_response_delta(&mut out, index, left);
    }
    for (index, (_, right)) in tools.iter().enumerate() {
        push_response_delta(&mut out, index, right);
    }
    let mut outputs = Vec::new();
    for (index, (left, right)) in tools.iter().enumerate() {
        let full = format!("{left}{right}");
        push_event(
            &mut out,
            "response.function_call_arguments.done",
            &serde_json::json!({
                "type": "response.function_call_arguments.done",
                "item_id": format!("fc_{index}"),
                "output_index": index,
                "arguments": full
            }),
        );
        let item = serde_json::json!({
            "type": "function_call",
            "id": format!("fc_{index}"),
            "call_id": format!("call_{index}"),
            "name": "run_terminal_command",
            "arguments": full
        });
        push_event(
            &mut out,
            "response.output_item.done",
            &serde_json::json!({
                "type": "response.output_item.done",
                "output_index": index,
                "item": item
            }),
        );
        outputs.push(item);
    }
    push_event(
        &mut out,
        "response.completed",
        &serde_json::json!({
            "type": "response.completed",
            "response": {"id": "resp_test", "output": outputs}
        }),
    );
    out
}

fn push_response_delta(out: &mut String, index: usize, text: &str) {
    push_event(
        out,
        "response.function_call_arguments.delta",
        &serde_json::json!({
            "type": "response.function_call_arguments.delta",
            "item_id": format!("fc_{index}"),
            "output_index": index,
            "delta": text
        }),
    );
}

fn responses_text_sse(left: &str, right: &str) -> String {
    let mut out = String::new();
    for part in [left, right] {
        push_event(
            &mut out,
            "response.output_text.delta",
            &serde_json::json!({
                "type": "response.output_text.delta",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "delta": part
            }),
        );
    }
    push_event(
        &mut out,
        "response.output_text.done",
        &serde_json::json!({
            "type": "response.output_text.done",
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "text": format!("{left}{right}")
        }),
    );
    out
}

fn push_data(out: &mut String, value: &Value) {
    out.push_str("data: ");
    out.push_str(&value.to_string());
    out.push_str("\n\n");
}

fn push_event(out: &mut String, event: &str, value: &Value) {
    out.push_str("event: ");
    out.push_str(event);
    out.push('\n');
    push_data(out, value);
}

fn byte_chunks(data: Vec<u8>) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send {
    async_stream::stream! {
        for byte in data {
            yield Ok(Bytes::copy_from_slice(&[byte]));
        }
    }
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
