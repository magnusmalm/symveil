//! End-to-end bench: `symveil proxy` in front of a local mock upstream.
//!
//! The mock speaks OpenAI Chat Completions, OpenAI Responses, and Anthropic
//! Messages, including server-sent events. It binds to 127.0.0.1 and never
//! dials a real host. Payloads come from `bench_corpus` (synthetic terms,
//! people, hosts, and secrets).
//!
//! ```text
//! SYMVEIL_BIN=target/release/symveil SYMVEIL_BENCH_PROFILE=full \
//!   cargo bench --bench proxy_e2e
//! ```
//!
//! `MB/s` is decimal megabytes per second (bytes / 1e6 / seconds). Added
//! latency is the proxy round trip minus the same request sent straight at
//! the mock. Startup is process spawn until `GET /health` returns.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use bytes::Bytes;
use futures::stream;
use serde_json::{json, Value};
use symveil_core::bench_corpus::{
    payloads, planted_secrets, redact_section, write_proxy_config, Profile,
};
use symveil_core::redact::Engine;
use symveil_core::vault::Vault;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let profile = Profile::from_env();
    println!("symveil e2e bench");
    println!(
        "profile={} terms={} people={} domains={} secret_rules={} filler_bytes={}",
        profile.name,
        profile.terms,
        profile.people,
        profile.domains,
        profile.secret_rules,
        profile.filler_bytes
    );
    println!("machine: {}", machine());
    println!("data: synthetic terms, people, hosts, and secrets only");
    println!();

    throughput(&profile)?;
    let mock = Mock::spawn().await?;
    let workspace = Workspace::new(&profile)?;
    let startup = startup_samples(&workspace, &mock.base, 3).await?;
    print_startup(&startup);

    let proxy = spawn_proxy(&workspace, &mock.base)?;
    wait_healthy(&proxy.url).await?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()?;
    let samples = if profile.name == "full" { 11 } else { 5 };

    let chat = payloads(&profile)
        .into_iter()
        .find(|item| item.name == "openai-chat")
        .expect("chat");
    let messages = payloads(&profile)
        .into_iter()
        .find(|item| item.name == "anthropic-messages")
        .expect("messages");
    let responses = chat.bytes.clone();

    println!("## added latency (ms)");
    println!("| shape | cold proxy | p50 added | p99 added | p50 proxy | p50 direct |");
    println!("| --- | ---: | ---: | ---: | ---: | ---: |");
    measure_latency(
        &client,
        &proxy.url,
        &mock.base,
        "/v1/chat/completions",
        chat.bytes.clone(),
        samples,
    )
    .await?;
    measure_latency(
        &client,
        &proxy.url,
        &mock.base,
        "/v1/messages",
        messages.bytes,
        samples,
    )
    .await?;
    measure_latency(
        &client,
        &proxy.url,
        &mock.base,
        "/v1/responses",
        responses,
        samples.max(3) / 2 + 1,
    )
    .await?;

    println!();
    println!("## time to first response byte (ms)");
    println!("| shape | p50 overhead | p99 overhead | p50 proxy | p50 direct |");
    println!("| --- | ---: | ---: | ---: | ---: |");
    let stream_samples = samples.clamp(3, 7);
    for (label, path, body) in [
        (
            "openai-chat-sse",
            "/v1/chat/completions",
            stream_body(&chat.bytes),
        ),
        (
            "anthropic-messages-sse",
            "/v1/messages",
            stream_body(&messages_body(&profile)),
        ),
        (
            "openai-responses-sse",
            "/v1/responses",
            stream_body(&chat.bytes),
        ),
    ] {
        measure_ttft(
            &client,
            &proxy.url,
            &mock.base,
            label,
            path,
            body,
            stream_samples,
        )
        .await?;
    }

    let seen = mock.seen.lock().expect("mock lock");
    let checked = seen.iter().find(|body| body.len() > 32);
    if let Some(body) = checked {
        let text = String::from_utf8_lossy(body);
        for planted in planted_secrets() {
            if text.contains(&planted) {
                anyhow::bail!("mock upstream saw planted value {planted}");
            }
        }
        println!();
        println!(
            "upstream check: {} recorded bodies, planted values absent",
            seen.len()
        );
    }
    drop(seen);
    drop(proxy);
    Ok(())
}

fn messages_body(profile: &Profile) -> Vec<u8> {
    payloads(profile)
        .into_iter()
        .find(|item| item.name == "anthropic-messages")
        .expect("messages")
        .bytes
}

fn stream_body(bytes: &[u8]) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("stream".to_string(), json!(true));
    }
    serde_json::to_vec(&value).unwrap_or_else(|_| bytes.to_vec())
}

fn throughput(profile: &Profile) -> anyhow::Result<()> {
    println!("## in-process redact and restore");
    println!("| bytes | redact ms | redact MB/s | restore ms | restore MB/s | hits |");
    println!("| ---: | ---: | ---: | ---: | ---: | ---: |");
    let redact = redact_section(profile);
    let mut engine = Engine::new(Vault::ephemeral(), &redact)?;
    let mut sizes = vec![profile.filler_bytes.max(16 * 1024)];
    if profile.name == "full" {
        sizes = vec![100 * 1024, 1024 * 1024, 5 * 1024 * 1024];
    } else if profile.name == "quick" {
        sizes = vec![16 * 1024, 64 * 1024];
    }
    let mut previous_ms = 0.0;
    for (index, size) in sizes.into_iter().enumerate() {
        if index > 0 && previous_ms > 20_000.0 {
            println!("| {size} | skipped |  |  |  | previous shot was {previous_ms:.0} ms |");
            continue;
        }
        let payload = payloads(&profile.with_filler(size))
            .into_iter()
            .find(|item| item.name == "plain")
            .expect("plain");
        let bytes = payload.bytes.len();
        let _ = engine.redact_bytes(&payload.bytes)?;
        let started = Instant::now();
        let (redacted, hits) = engine.redact_bytes(&payload.bytes)?;
        let redact_ms = elapsed_ms(started);
        let started = Instant::now();
        let (restored, _) = engine.restore_bytes(&redacted, false);
        let restore_ms = elapsed_ms(started);
        assert_eq!(restored, payload.bytes, "restore round trip");
        println!(
            "| {bytes} | {redact_ms:.1} | {:.2} | {restore_ms:.1} | {:.2} | {} |",
            mb_per_s(bytes, redact_ms),
            mb_per_s(redacted.len(), restore_ms),
            hits.len()
        );
        let _ = std::io::stdout().flush();
        previous_ms = redact_ms;
        std::hint::black_box(redacted.len());
    }
    println!();
    Ok(())
}

fn mb_per_s(bytes: usize, millis: f64) -> f64 {
    if millis <= 0.0 {
        return 0.0;
    }
    (bytes as f64 / 1_000_000.0) / (millis / 1_000.0)
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

struct Mock {
    base: String,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Mock {
    async fn spawn() -> anyhow::Result<Self> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            seen: Arc::clone(&seen),
        };
        let app = Router::new()
            .route("/v1/chat/completions", post(handle))
            .route("/v1/messages", post(handle))
            .route("/v1/responses", post(handle))
            .fallback(handle)
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock serve");
        });
        Ok(Self {
            base: format!("http://127.0.0.1:{port}"),
            seen,
        })
    }
}

#[derive(Clone)]
struct MockState {
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn handle(State(state): State<MockState>, req: axum::extract::Request) -> Response {
    let path = req.uri().path().to_string();
    let bytes = axum::body::to_bytes(req.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap_or_default();
    state.seen.lock().expect("mock lock").push(bytes.to_vec());
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let stream = value
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let echo = String::from_utf8_lossy(&bytes).into_owned();
    if stream {
        let frames = match path.as_str() {
            "/v1/messages" => anthropic_frames(&echo),
            "/v1/responses" => response_frames(&echo),
            _ => chat_frames(&echo),
        };
        let body = Body::from_stream(stream::iter(
            frames
                .into_iter()
                .map(|frame| Ok::<Bytes, std::io::Error>(Bytes::from(frame))),
        ));
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(body)
            .expect("sse response");
    }
    let body = match path.as_str() {
        "/v1/messages" => json!({
            "id": "msg_bench",
            "type": "message",
            "role": "assistant",
            "model": "bench-local",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": echo}],
        }),
        "/v1/responses" => json!({
            "id": "resp_bench",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": echo}],
            }],
        }),
        _ => json!({
            "id": "chat_bench",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": echo},
            }],
        }),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("response json"),
        ))
        .expect("json response")
}

fn chat_frames(echo: &str) -> Vec<String> {
    let mut frames = Vec::new();
    for piece in pieces(echo, 24) {
        let payload = json!({
            "choices": [{"index": 0, "delta": {"content": piece}}]
        });
        frames.push(format!("data: {payload}\n\n"));
    }
    frames.push(
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
            .to_string(),
    );
    frames
}

fn anthropic_frames(echo: &str) -> Vec<String> {
    let mut frames = vec![
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
            .to_string(),
    ];
    for piece in pieces(echo, 24) {
        let payload = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": piece},
        });
        frames.push(format!("event: content_block_delta\ndata: {payload}\n\n"));
    }
    frames.push(
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
            .to_string(),
    );
    frames
}

fn response_frames(echo: &str) -> Vec<String> {
    let mut frames = Vec::new();
    for piece in pieces(echo, 24) {
        let payload = json!({
            "type": "response.output_text.delta",
            "item_id": "msg_bench",
            "output_index": 0,
            "content_index": 0,
            "delta": piece,
        });
        frames.push(format!(
            "event: response.output_text.delta\ndata: {payload}\n\n"
        ));
    }
    frames.push(
        "event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"output_index\":0,\"content_index\":0}\n\n"
            .to_string(),
    );
    frames
}

fn pieces(text: &str, chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for ch in text.chars().take(4_096) {
        buf.push(ch);
        if buf.chars().count() >= chars {
            out.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

struct Workspace {
    root: PathBuf,
    config: PathBuf,
    home: PathBuf,
    bin: PathBuf,
}

impl Workspace {
    fn new(profile: &Profile) -> anyhow::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "symveil-bench-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let home = root.join("home");
        std::fs::create_dir_all(&home)?;
        let config = root.join(".symveil.toml");
        let redact = redact_section(profile);
        write_proxy_config(&config, &redact)?;
        Ok(Self {
            root,
            config,
            home,
            bin: symveil_bin(),
        })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn symveil_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("SYMVEIL_BIN") {
        return PathBuf::from(path);
    }
    let mut exe = std::env::current_exe().expect("current exe");
    exe.pop();
    exe.pop();
    exe.push("symveil");
    exe
}

struct ProxyChild {
    child: Child,
    url: String,
}

impl Drop for ProxyChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_proxy(workspace: &Workspace, upstream: &str) -> anyhow::Result<ProxyChild> {
    if !workspace.bin.is_file() {
        anyhow::bail!(
            "symveil binary not found at {}. Build it with `cargo build --release --bin symveil` and set SYMVEIL_BIN.",
            workspace.bin.display()
        );
    }
    let mut command = Command::new(&workspace.bin);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("HOME", &workspace.home)
        .env("SYMVEIL_TEST_FILE_KEY", "1")
        .env("RUST_LOG", "symveil=error")
        .args([
            "proxy",
            "--port",
            "0",
            "--repo",
            workspace.root.to_str().expect("utf-8 temp path"),
            "--config",
            workspace.config.to_str().expect("utf-8 config path"),
            "--openai-base",
            upstream,
            "--anthropic-base",
            upstream,
        ]);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if let Some(rest) = line.strip_prefix("symveil listening on ") {
                let _ = tx.send(rest.to_string());
            }
        }
    });
    let url = rx
        .recv_timeout(Duration::from_secs(120))
        .map_err(|_| anyhow::anyhow!("proxy did not listen within 120s"))?;
    if !url.starts_with("http://127.0.0.1:") {
        anyhow::bail!("proxy listened on {url}");
    }
    Ok(ProxyChild { child, url })
}

async fn startup_samples(
    workspace: &Workspace,
    upstream: &str,
    count: usize,
) -> anyhow::Result<Vec<f64>> {
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let started = Instant::now();
        let proxy = spawn_proxy(workspace, upstream)?;
        wait_healthy(&proxy.url).await?;
        samples.push(elapsed_ms(started));
    }
    Ok(samples)
}

fn print_startup(samples: &[f64]) {
    println!("## startup (ms, spawn until /health)");
    println!("| sample | ms |");
    println!("| ---: | ---: |");
    for (index, sample) in samples.iter().enumerate() {
        println!("| {} | {sample:.1} |", index + 1);
    }
    println!();
}

async fn wait_healthy(proxy: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    for _ in 0..100 {
        if let Ok(response) = client.get(format!("{proxy}/health")).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("proxy at {proxy} never answered /health");
}

async fn measure_latency(
    client: &reqwest::Client,
    proxy: &str,
    mock: &str,
    path: &str,
    body: Vec<u8>,
    samples: usize,
) -> anyhow::Result<()> {
    let cold = round_trip(client, &format!("{proxy}{path}"), body.clone()).await?;
    let _ = round_trip(client, &format!("{mock}{path}"), body.clone()).await?;
    let mut added = Vec::with_capacity(samples);
    let mut via = Vec::with_capacity(samples);
    let mut direct = Vec::with_capacity(samples);
    for _ in 0..samples {
        let proxy_ms = round_trip(client, &format!("{proxy}{path}"), body.clone()).await?;
        let direct_ms = round_trip(client, &format!("{mock}{path}"), body.clone()).await?;
        via.push(proxy_ms);
        direct.push(direct_ms);
        added.push(proxy_ms - direct_ms);
    }
    println!(
        "| {path} | {cold:.1} | {:.1} | {:.1} | {:.1} | {:.1} |",
        percentile(&added, 0.50),
        percentile(&added, 0.99),
        percentile(&via, 0.50),
        percentile(&direct, 0.50),
    );
    let _ = std::io::stdout().flush();
    Ok(())
}

async fn measure_ttft(
    client: &reqwest::Client,
    proxy: &str,
    mock: &str,
    label: &str,
    path: &str,
    body: Vec<u8>,
    samples: usize,
) -> anyhow::Result<()> {
    let _ = first_byte(client, &format!("{proxy}{path}"), body.clone()).await?;
    let mut added = Vec::with_capacity(samples);
    let mut via = Vec::with_capacity(samples);
    let mut direct = Vec::with_capacity(samples);
    for _ in 0..samples {
        let proxy_ms = first_byte(client, &format!("{proxy}{path}"), body.clone()).await?;
        let direct_ms = first_byte(client, &format!("{mock}{path}"), body.clone()).await?;
        via.push(proxy_ms);
        direct.push(direct_ms);
        added.push(proxy_ms - direct_ms);
    }
    println!(
        "| {label} {path} | {:.1} | {:.1} | {:.1} | {:.1} |",
        percentile(&added, 0.50),
        percentile(&added, 0.99),
        percentile(&via, 0.50),
        percentile(&direct, 0.50),
    );
    let _ = std::io::stdout().flush();
    Ok(())
}

async fn round_trip(client: &reqwest::Client, url: &str, body: Vec<u8>) -> anyhow::Result<f64> {
    let started = Instant::now();
    let response = client
        .post(url)
        .header(header::CONTENT_TYPE.as_str(), "application/json")
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    let elapsed = elapsed_ms(started);
    if !status.is_success() {
        anyhow::bail!("POST {url} returned {status}");
    }
    std::hint::black_box(bytes.len());
    Ok(elapsed)
}

async fn first_byte(client: &reqwest::Client, url: &str, body: Vec<u8>) -> anyhow::Result<f64> {
    let started = Instant::now();
    let mut response = client
        .post(url)
        .header(header::CONTENT_TYPE.as_str(), "application/json")
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let first = response.chunk().await?;
    let elapsed = elapsed_ms(started);
    if !status.is_success() {
        anyhow::bail!("POST {url} returned {status}");
    }
    std::hint::black_box(first.map(|chunk| chunk.len()));
    while response.chunk().await?.is_some() {}
    Ok(elapsed)
}

fn percentile(samples: &[f64], p: f64) -> f64 {
    let mut samples = samples.to_vec();
    samples.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    if samples.is_empty() {
        return 0.0;
    }
    let rank = (p * (samples.len() - 1) as f64).round() as usize;
    samples[rank.min(samples.len() - 1)]
}

fn machine() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    format!("{os} {arch}, {cpus} threads")
}
