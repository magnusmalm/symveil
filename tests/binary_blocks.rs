//! Inline image and document blocks must not carry seeded corpus terms upstream.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;
use symveil::audit::AuditLog;
use symveil::build_engine;
use symveil::config::Config;
use symveil::proxy::AppState;
use symveil::vault::Vault;
use tokio::net::TcpListener;

const SIBLING: &str = "describe the image";

#[derive(Clone)]
struct MockState {
    hits: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[tokio::test]
async fn seeded_png_and_pdf_blocks_do_not_reach_upstream() {
    let seed = load_seed();
    let png_needles = png_needles(&seed);
    let pdf_needles = pdf_needles(&seed);
    let png = png_with_text(&png_needles);
    let pdf = pdf_with_text(&pdf_needles);
    assert_embedded(&png, &png_needles);
    assert_embedded(&pdf, &pdf_needles);
    let png_b64 = STANDARD.encode(&png);
    let pdf_b64 = STANDARD.encode(&pdf);

    let cfg = Config::parse("[redact]\ninternal_domains = []\n").unwrap();
    assert_eq!(cfg.binary.mode, symveil::config::BinaryMode::Block);
    let mut engine = build_engine(Vault::ephemeral(), &cfg.redact).unwrap();
    engine.set_binary_mode(cfg.binary.mode);

    let (openai, openai_hits) = spawn_mock().await;
    let (anthropic, anthropic_hits) = spawn_mock().await;
    let dir = temp_dir("binary-block");
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
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let cases = uploads(
        &png_b64,
        &pdf_b64,
        png.len(),
        pdf.len(),
        &png_needles,
        &pdf_needles,
    );
    for case in &cases {
        let response = client
            .post(format!("{proxy}{}", case.path))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&case.request).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", case.name);
        let hits = if case.path == "/v1/messages" {
            &anthropic_hits
        } else {
            &openai_hits
        };
        let body = {
            let seen = hits.lock().unwrap();
            seen.last().expect(case.name).clone()
        };
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains(SIBLING),
            "{}: sibling text was dropped:\n{text}",
            case.name
        );
        assert!(
            text.contains(&case.notice),
            "{}: missing withheld notice:\n{text}",
            case.name
        );
        assert!(
            !text.contains("@@sv:"),
            "{}: block was turned into a placeholder instead of a text note:\n{text}",
            case.name
        );
        assert!(
            !text.contains(&case.payload),
            "{}: base64 payload was forwarded",
            case.name
        );
        assert_needles_absent(&body, &case.needles, case.name);
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            find_notice(&value, &case.notice)
                .unwrap_or_else(|| panic!("{}: notice is not a string field", case.name)),
            case.notice
        );
        if case.name.contains("tool_result") {
            assert!(text.contains("toolu_png"), "{text}");
        }
    }

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert_needles_absent(audit.as_bytes(), &png_needles, "audit");
    assert_needles_absent(audit.as_bytes(), &pdf_needles, "audit");
    assert_eq!(
        audit.matches("\"disposition\":\"withheld\"").count(),
        cases.len(),
        "{audit}"
    );
    assert!(audit.contains("\"kind\":\"image\""), "{audit}");
    assert!(audit.contains("\"kind\":\"document\""), "{audit}");
    assert!(audit.contains("\"kind\":\"file\""), "{audit}");
    assert!(
        audit.contains(&format!("\"bytes\":{}", png.len())),
        "{audit}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pass_mode_forwards_binary_blocks_unchanged() {
    let seed = load_seed();
    let png_needles = png_needles(&seed);
    let png = png_with_text(&png_needles);
    assert_embedded(&png, &png_needles);
    let png_b64 = STANDARD.encode(&png);
    let cfg =
        Config::parse("[binary]\nmode = \"pass\"\n[redact]\ninternal_domains = []\n").unwrap();
    let mut engine = build_engine(Vault::ephemeral(), &cfg.redact).unwrap();
    engine.set_binary_mode(cfg.binary.mode);

    let (openai, openai_hits) = spawn_mock().await;
    let (anthropic, anthropic_hits) = spawn_mock().await;
    let dir = temp_dir("binary-pass");
    let state = AppState::new(
        engine,
        openai,
        anthropic.clone(),
        AuditLog::open(&dir.join("audit.jsonl")).unwrap(),
        30,
    )
    .unwrap();
    let proxy = spawn_proxy(state).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let request = anthropic_image(&png_b64);
    let raw = serde_json::to_vec(&request).unwrap();
    let response = client
        .post(format!("{proxy}/v1/messages"))
        .header("content-type", "application/json")
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let forwarded = {
        let seen = anthropic_hits.lock().unwrap();
        assert_eq!(seen.len(), 1);
        seen[0].clone()
    };
    assert_eq!(forwarded, raw, "pass mode changed the image request");
    assert_needles_present_in_decoded(&forwarded, &png_needles);

    let data_url = format!("data:image/png;base64,{png_b64}");
    let chat = serde_json::json!({
        "model": "gpt-test",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "key AKIAIOSFODNN7EXAMPLE"},
                {"type": "image_url", "image_url": {"url": data_url}}
            ]
        }]
    });
    let response = client
        .post(format!("{proxy}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&chat).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let forwarded = {
        let seen = openai_hits.lock().unwrap();
        seen.last().expect("openai request").clone()
    };
    let text = String::from_utf8_lossy(&forwarded);
    assert!(
        text.contains(&png_b64),
        "image data URL was rewritten:\n{text}"
    );
    assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
    assert!(!text.contains("[symveil:"), "{text}");
    assert_needles_present_in_decoded(&forwarded, &png_needles);
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(!audit.contains("AKIA"), "{audit}");
    assert!(!audit.contains("withheld"), "{audit}");
    assert_needles_absent(audit.as_bytes(), &png_needles, "pass audit");
    let _ = std::fs::remove_dir_all(&dir);
}

struct Upload {
    name: &'static str,
    path: &'static str,
    request: Value,
    notice: String,
    payload: String,
    needles: Vec<String>,
}

fn uploads(
    png_b64: &str,
    pdf_b64: &str,
    png_len: usize,
    pdf_len: usize,
    png_needles: &[String],
    pdf_needles: &[String],
) -> Vec<Upload> {
    let image_notice = format!("[symveil: image withheld, {png_len} bytes]");
    let document_notice = format!("[symveil: document withheld, {pdf_len} bytes]");
    let file_notice = format!("[symveil: file withheld, {pdf_len} bytes]");
    let png_data_url = format!("data:image/png;base64,{png_b64}");
    let pdf_data_url = format!("data:application/pdf;base64,{pdf_b64}");
    vec![
        Upload {
            name: "anthropic-image",
            path: "/v1/messages",
            request: anthropic_content(vec![
                text_block(SIBLING),
                serde_json::json!({
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": png_b64}
                }),
            ]),
            notice: image_notice.clone(),
            payload: png_b64.to_string(),
            needles: png_needles.to_vec(),
        },
        Upload {
            name: "anthropic-tool-result",
            path: "/v1/messages",
            request: anthropic_content(vec![serde_json::json!({
                "type": "tool_result",
                "tool_use_id": "toolu_png",
                "content": [
                    text_block(SIBLING),
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": png_b64}}
                ]
            })]),
            notice: image_notice.clone(),
            payload: png_b64.to_string(),
            needles: png_needles.to_vec(),
        },
        Upload {
            name: "anthropic-document",
            path: "/v1/messages",
            request: anthropic_content(vec![
                text_block(SIBLING),
                serde_json::json!({
                    "type": "document",
                    "source": {"type": "base64", "media_type": "application/pdf", "data": pdf_b64}
                }),
            ]),
            notice: document_notice,
            payload: pdf_b64.to_string(),
            needles: pdf_needles.to_vec(),
        },
        Upload {
            name: "openai-image-url",
            path: "/v1/chat/completions",
            request: serde_json::json!({
                "model": "gpt-test",
                "messages": [{
                    "role": "user",
                    "content": [
                        text_block(SIBLING),
                        {"type": "image_url", "image_url": {"url": png_data_url.clone()}}
                    ]
                }]
            }),
            notice: image_notice.clone(),
            payload: png_b64.to_string(),
            needles: png_needles.to_vec(),
        },
        Upload {
            name: "openai-tool-image",
            path: "/v1/chat/completions",
            request: serde_json::json!({
                "model": "gpt-test",
                "messages": [
                    {"role": "user", "content": SIBLING},
                    {
                        "role": "tool",
                        "tool_call_id": "call_png",
                        "content": [
                            {"type": "image_url", "image_url": png_data_url.clone()}
                        ]
                    }
                ]
            }),
            notice: image_notice.clone(),
            payload: png_b64.to_string(),
            needles: png_needles.to_vec(),
        },
        Upload {
            name: "openai-input-image",
            path: "/v1/responses",
            request: serde_json::json!({
                "model": "gpt-test",
                "input": [{
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": SIBLING},
                        {"type": "input_image", "image_url": png_data_url}
                    ]
                }]
            }),
            notice: image_notice,
            payload: png_b64.to_string(),
            needles: png_needles.to_vec(),
        },
        Upload {
            name: "openai-input-file",
            path: "/v1/responses",
            request: serde_json::json!({
                "model": "gpt-test",
                "input": [{
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": SIBLING},
                        {"type": "input_file", "filename": "notes.pdf", "file_data": pdf_data_url.clone()}
                    ]
                }]
            }),
            notice: file_notice.clone(),
            payload: pdf_b64.to_string(),
            needles: pdf_needles.to_vec(),
        },
        Upload {
            name: "openai-file-part",
            path: "/v1/chat/completions",
            request: serde_json::json!({
                "model": "gpt-test",
                "messages": [{
                    "role": "user",
                    "content": [
                        text_block(SIBLING),
                        {"type": "file", "file": {"filename": "notes.pdf", "file_data": pdf_data_url}}
                    ]
                }]
            }),
            notice: file_notice,
            payload: pdf_b64.to_string(),
            needles: pdf_needles.to_vec(),
        },
    ]
}

fn anthropic_image(png_b64: &str) -> Value {
    anthropic_content(vec![
        text_block(SIBLING),
        serde_json::json!({
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": png_b64}
        }),
    ])
}

fn anthropic_content(content: Vec<Value>) -> Value {
    serde_json::json!({
        "model": "claude-test",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": content}]
    })
}

fn text_block(text: &str) -> Value {
    serde_json::json!({"type": "text", "text": text})
}

fn find_notice(value: &Value, notice: &str) -> Option<String> {
    match value {
        Value::String(text) if text == notice => Some(text.clone()),
        Value::Array(items) => items.iter().find_map(|item| find_notice(item, notice)),
        Value::Object(map) => map.values().find_map(|item| find_notice(item, notice)),
        _ => None,
    }
}

fn assert_needles_absent(body: &[u8], needles: &[String], label: &str) {
    let blobs = decoded_blobs(body);
    for needle in needles {
        let raw = needle.as_bytes();
        assert!(
            body.len() < raw.len() || !body.windows(raw.len()).any(|window| window == raw),
            "{label}: raw body contains {needle}"
        );
        let utf16 = utf16_le(needle);
        assert!(
            body.len() < utf16.len() || !body.windows(utf16.len()).any(|window| window == utf16),
            "{label}: raw body contains utf-16 {needle}"
        );
        for blob in &blobs {
            assert!(
                blob.len() < raw.len() || !blob.windows(raw.len()).any(|window| window == raw),
                "{label}: decoded body contains {needle}"
            );
            assert!(
                blob.len() < utf16.len()
                    || !blob.windows(utf16.len()).any(|window| window == utf16),
                "{label}: decoded body contains utf-16 {needle}"
            );
        }
    }
}

fn assert_needles_present_in_decoded(body: &[u8], needles: &[String]) {
    let blobs = decoded_blobs(body);
    for needle in needles {
        let raw = needle.as_bytes();
        assert!(
            blobs
                .iter()
                .any(|blob| blob.windows(raw.len()).any(|window| window == raw)),
            "pass mode dropped {needle} from the decoded image"
        );
    }
}

fn decoded_blobs(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < body.len() {
        if is_b64_body(body[index]) {
            let start = index;
            while index < body.len() && is_b64_body(body[index]) {
                index += 1;
            }
            let mut end = index;
            while end < body.len() && body[end] == b'=' && end - index < 2 {
                end += 1;
            }
            if end - start >= 16 {
                if let Some(decoded) = decode_b64(&body[start..end]) {
                    out.push(decoded);
                }
            }
            index = end;
        } else {
            index += 1;
        }
    }
    out
}

fn is_b64_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

fn decode_b64(data: &[u8]) -> Option<Vec<u8>> {
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(data) {
            return Some(bytes);
        }
    }
    None
}

fn utf16_le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend(unit.to_le_bytes());
    }
    out
}

fn assert_embedded(bytes: &[u8], needles: &[String]) {
    for needle in needles {
        let raw = needle.as_bytes();
        assert!(
            bytes.windows(raw.len()).any(|window| window == raw),
            "generated file is missing {needle}"
        );
    }
}

fn load_seed() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/leak/seed.json");
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn item_value(seed: &Value, id: &str) -> String {
    seed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing seed item {id}"))["value"]
        .as_str()
        .unwrap()
        .to_string()
}

fn file_spec<'a>(seed: &'a Value, path: &str) -> &'a Value {
    seed["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|spec| spec["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("missing seed file {path}"))
}

fn png_needles(seed: &Value) -> Vec<String> {
    let mut needles = Vec::new();
    for chunk in file_spec(seed, "assets/badge.png")["chunks"]
        .as_array()
        .unwrap()
    {
        needles.push(chunk["text"].as_str().unwrap().to_string());
    }
    for id in [
        "aws-access-key",
        "github-pat",
        "host-git",
        "company-exempla",
        "company-tundrahorn",
        "person-ren",
    ] {
        let value = item_value(seed, id);
        if !needles.contains(&value) {
            needles.push(value);
        }
    }
    needles
}

fn pdf_needles(seed: &Value) -> Vec<String> {
    let spec = file_spec(seed, "docs/manual.pdf");
    vec![
        spec["author"].as_str().unwrap().to_string(),
        spec["title"].as_str().unwrap().to_string(),
    ]
}

fn png_with_text(needles: &[String]) -> Vec<u8> {
    let chunks: Vec<(String, String)> = needles
        .iter()
        .enumerate()
        .map(|(index, text)| (format!("Note{index}"), text.clone()))
        .collect();
    png(&chunks)
}

fn pdf_with_text(needles: &[String]) -> Vec<u8> {
    assert_eq!(needles.len(), 2);
    format!(
        "%PDF-1.4\n1 0 obj\n<< /Title ({}) /Author ({}) >>\nendobj\n%%EOF\n",
        needles[1], needles[0]
    )
    .into_bytes()
}

fn png(chunks: &[(String, String)]) -> Vec<u8> {
    let mut ihdr = Vec::new();
    ihdr.extend(1u32.to_be_bytes());
    ihdr.extend(1u32.to_be_bytes());
    ihdr.extend([8, 2, 0, 0, 0]);
    let scanline = [0, 0, 0, 0];
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &ihdr));
    for (keyword, text) in chunks {
        let mut data = keyword.as_bytes().to_vec();
        data.push(0);
        data.extend(text.as_bytes());
        out.extend(chunk(b"tEXt", &data));
    }
    out.extend(chunk(b"IDAT", &zlib_store(&scanline)));
    out.extend(chunk(b"IEND", &[]));
    out
}

fn chunk(tag: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + data.len());
    body.extend(tag);
    body.extend(data);
    let crc = crc32(&body);
    let mut out = Vec::new();
    out.extend((data.len() as u32).to_be_bytes());
    out.extend(body);
    out.extend(crc.to_be_bytes());
    out
}

fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01, 0x01];
    let len = u16::try_from(data.len()).expect("stored block");
    out.extend(len.to_le_bytes());
    out.extend((!len).to_le_bytes());
    out.extend(data);
    out.extend(adler32(data).to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = if crc & 1 == 1 { 0xEDB8_8320 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}

async fn spawn_mock() -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        hits: Arc::clone(&hits),
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
    let body = axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    state.hits.lock().unwrap().push(body.to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"ok":true}"#))
        .unwrap()
}

async fn spawn_proxy(state: AppState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        symveil::proxy::serve(listener, state).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .no_proxy()
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
