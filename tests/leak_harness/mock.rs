//! Local recorder. It binds to 127.0.0.1 and stores every request body.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use serde_json::Value;
use tokio::net::TcpListener;

#[derive(Clone)]
struct MockState {
    hits: Arc<Mutex<Vec<Recorded>>>,
}

#[derive(Clone)]
pub struct Recorded {
    pub session: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub struct Mock {
    pub base: String,
    hits: Arc<Mutex<Vec<Recorded>>>,
}

impl Mock {
    pub async fn spawn() -> Self {
        let hits = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            hits: Arc::clone(&hits),
        };
        let app = Router::new().fallback(record).with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let port = listener.local_addr().expect("mock addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock serve");
        });
        Self {
            base: format!("http://127.0.0.1:{port}"),
            hits,
        }
    }

    pub fn recorded(&self) -> Vec<Recorded> {
        self.hits.lock().expect("mock lock").clone()
    }
}

async fn record(State(state): State<MockState>, req: Request<Body>) -> Response {
    let session = header(req.headers(), "x-leak-session").unwrap_or_else(|| "unknown".into());
    let echo = header(req.headers(), "x-leak-echo").unwrap_or_default();
    let path = req.uri().path().to_string();
    let bytes = axum::body::to_bytes(req.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap_or_default();
    state.hits.lock().expect("mock lock").push(Recorded {
        session,
        path,
        body: bytes.to_vec(),
    });
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let echo_me = value.get("echo_me").and_then(Value::as_str).unwrap_or("");
    match echo.as_str() {
        "" | "none" => json_response(r#"{"ok":true}"#),
        "messages-text" => json_response(&messages_text(echo_me)),
        "responses-text" => json_response(&responses_text(echo_me)),
        "messages-text-stream" => sse(messages_text_stream(echo_me)),
        "responses-text-stream" => sse(responses_text_stream(echo_me)),
        "messages-tool-stream" => sse(messages_tool_stream(echo_me)),
        "responses-tool-stream" => sse(responses_tool_stream(echo_me)),
        other => {
            let body = format!(r#"{{"error":"unknown echo mode {other}"}}"#);
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("mock response")
        }
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn json_response(body: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("json response")
}

fn sse(body: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(Body::from(body))
        .expect("sse response")
}

fn messages_text(echo: &str) -> String {
    serde_json::json!({
        "id": "msg_mock",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": echo}],
        "stop_reason": "end_turn"
    })
    .to_string()
}

fn responses_text(echo: &str) -> String {
    serde_json::json!({
        "id": "resp_mock",
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": echo}]
        }]
    })
    .to_string()
}

fn messages_text_stream(echo: &str) -> String {
    let (left, right) = split_token(echo);
    let mut out = String::new();
    out.push_str(&event(
        "content_block_start",
        &serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
    ));
    out.push_str(&event(
        "content_block_delta",
        &serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":left}}),
    ));
    out.push_str(&event(
        "content_block_delta",
        &serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":right}}),
    ));
    out.push_str(&event(
        "content_block_stop",
        &serde_json::json!({"type":"content_block_stop","index":0}),
    ));
    out.push_str(&event(
        "message_stop",
        &serde_json::json!({"type":"message_stop"}),
    ));
    out
}

fn messages_tool_stream(echo: &str) -> String {
    let (left, right) = split_token(echo);
    let mut out = String::new();
    out.push_str(&event(
        "content_block_start",
        &serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_mock","name":"bash","input":{}}}),
    ));
    out.push_str(&event(
        "content_block_delta",
        &serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":left}}),
    ));
    out.push_str(&event(
        "content_block_delta",
        &serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":right}}),
    ));
    out.push_str(&event(
        "content_block_stop",
        &serde_json::json!({"type":"content_block_stop","index":0}),
    ));
    out.push_str(&event(
        "message_stop",
        &serde_json::json!({"type":"message_stop"}),
    ));
    out
}

fn responses_text_stream(echo: &str) -> String {
    let (left, right) = split_token(echo);
    let mut out = String::new();
    out.push_str(&event(
        "response.output_text.delta",
        &serde_json::json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":left}),
    ));
    out.push_str(&event(
        "response.output_text.delta",
        &serde_json::json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":right}),
    ));
    out.push_str(&event(
        "response.output_text.done",
        &serde_json::json!({"type":"response.output_text.done","output_index":0,"content_index":0}),
    ));
    out
}

fn responses_tool_stream(echo: &str) -> String {
    let (left, right) = split_token(echo);
    let mut out = String::new();
    out.push_str(&event(
        "response.function_call_arguments.delta",
        &serde_json::json!({"type":"response.function_call_arguments.delta","output_index":0,"content_index":0,"delta":left}),
    ));
    out.push_str(&event(
        "response.function_call_arguments.delta",
        &serde_json::json!({"type":"response.function_call_arguments.delta","output_index":0,"content_index":0,"delta":right}),
    ));
    out.push_str(&event(
        "response.function_call_arguments.done",
        &serde_json::json!({"type":"response.function_call_arguments.done","output_index":0,"content_index":0}),
    ));
    out
}

fn event(name: &str, data: &Value) -> String {
    format!("event: {name}\ndata: {data}\n\n")
}

fn split_token(text: &str) -> (String, String) {
    if let Some(index) = text.find("@@sv:") {
        let mid = index + "@@sv:".len() + 2;
        if text.is_char_boundary(mid) && mid < text.len() {
            return (text[..mid].to_string(), text[mid..].to_string());
        }
    }
    let mid = text
        .char_indices()
        .nth(text.chars().count() / 2)
        .map(|(index, _)| index)
        .unwrap_or(0);
    (text[..mid].to_string(), text[mid..].to_string())
}
