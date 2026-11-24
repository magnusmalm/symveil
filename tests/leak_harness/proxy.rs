//! Spawn `symveil` with a scrubbed environment and talk to it on 127.0.0.1.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

#[derive(Clone, Copy)]
pub enum EchoMode {
    None,
    MessagesText,
    ResponsesText,
    MessagesTextStream,
    ResponsesTextStream,
    MessagesToolStream,
    ResponsesToolStream,
}

impl EchoMode {
    pub fn header(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MessagesText => "messages-text",
            Self::ResponsesText => "responses-text",
            Self::MessagesTextStream => "messages-text-stream",
            Self::ResponsesTextStream => "responses-text-stream",
            Self::MessagesToolStream => "messages-tool-stream",
            Self::ResponsesToolStream => "responses-tool-stream",
        }
    }
}

pub struct Proxy {
    child: Child,
    pub url: String,
    stderr: Arc<Mutex<String>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proxy {
    pub fn stderr(&self) -> String {
        self.stderr.lock().expect("proxy stderr").clone()
    }
}

pub struct RedactOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

pub struct HttpReply {
    pub status: u16,
    pub body: String,
    pub retry: Option<String>,
}

pub fn write_config(dir: &Path, text: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(".symveil.toml");
    std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

pub fn spawn_proxy(
    bin: &Path,
    repo: &Path,
    config: &Path,
    openai_base: &str,
    anthropic_base: &str,
    home: &Path,
) -> Result<Proxy> {
    std::fs::create_dir_all(home)?;
    let mut command = Command::new(bin);
    scrub(&mut command, home);
    let mut child = command
        .args([
            "proxy",
            "--port",
            "0",
            "--repo",
            &repo.display().to_string(),
            "--config",
            &config.display().to_string(),
            "--openai-base",
            openai_base,
            "--anthropic-base",
            anthropic_base,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn symveil proxy")?;
    let stderr = child.stderr.take().context("proxy stderr")?;
    let log = Arc::new(Mutex::new(String::new()));
    let log_thread = Arc::clone(&log);
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        for line in std::io::BufRead::lines(reader) {
            let Ok(line) = line else { break };
            if let Some(rest) = line.strip_prefix("symveil listening on ") {
                let _ = tx.send(rest.to_string());
            }
            let mut guard = log_thread.lock().expect("proxy stderr");
            guard.push_str(&line);
            guard.push('\n');
        }
    });
    let url = match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(url) => url,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "proxy did not listen within 20s\n{}",
                log.lock().expect("proxy stderr")
            );
        }
    };
    if !url.starts_with("http://127.0.0.1:") {
        let _ = child.kill();
        let _ = child.wait();
        bail!("proxy listened on {url}, expected 127.0.0.1");
    }
    Ok(Proxy {
        child,
        url,
        stderr: log,
    })
}

pub fn redact_stdin(
    bin: &Path,
    repo: &Path,
    config: &Path,
    home: &Path,
    input: &[u8],
) -> Result<RedactOutput> {
    std::fs::create_dir_all(home)?;
    let mut command = Command::new(bin);
    scrub(&mut command, home);
    let mut child = command
        .args([
            "redact",
            "--repo",
            &repo.display().to_string(),
            "--config",
            &config.display().to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn symveil redact")?;
    let mut stdin = child.stdin.take().context("redact stdin")?;
    let mut stdout = child.stdout.take().context("redact stdout")?;
    let mut stderr = child.stderr.take().context("redact stderr")?;
    let payload = input.to_vec();
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(&payload);
    });
    let out_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_thread = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });
    writer.join().expect("redact writer");
    let status = child.wait().context("wait symveil redact")?;
    let stdout = out_thread.join().expect("redact stdout thread");
    let stderr = err_thread.join().expect("redact stderr thread");
    Ok(RedactOutput {
        code: status.code().unwrap_or(1),
        stdout,
        stderr,
    })
}

pub async fn post_json(
    client: &reqwest::Client,
    proxy: &str,
    path: &str,
    session: &str,
    echo: EchoMode,
    body: &Value,
) -> Result<HttpReply> {
    let response = client
        .post(format!("{proxy}{path}"))
        .header("content-type", "application/json")
        .header("x-leak-session", session)
        .header("x-leak-echo", echo.header())
        .body(body.to_string())
        .send()
        .await
        .with_context(|| format!("POST {path} session {session}"))?;
    let status = response.status().as_u16();
    let retry = response
        .headers()
        .get("x-should-retry")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response.text().await.context("read proxy response")?;
    Ok(HttpReply {
        status,
        body,
        retry,
    })
}

pub async fn wait_healthy(client: &reqwest::Client, proxy: &str) -> Result<()> {
    for _ in 0..40 {
        if let Ok(response) = client.get(format!("{proxy}/health")).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("proxy at {proxy} never answered /health");
}

pub fn restored_text(body: &str, mode: EchoMode) -> Result<String> {
    match mode {
        EchoMode::None => bail!("no echo to restore"),
        EchoMode::MessagesText => messages_text(body),
        EchoMode::ResponsesText => responses_text(body),
        EchoMode::MessagesTextStream
        | EchoMode::ResponsesTextStream
        | EchoMode::MessagesToolStream
        | EchoMode::ResponsesToolStream => Ok(sse_text(body)),
    }
}

fn messages_text(body: &str) -> Result<String> {
    let value: Value = serde_json::from_str(body).context("messages response")?;
    value
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .context("messages response has no content text")
}

fn responses_text(body: &str) -> Result<String> {
    let value: Value = serde_json::from_str(body).context("responses response")?;
    value
        .get("output")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("content"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .context("responses response has no output text")
}

fn sse_text(body: &str) -> String {
    let mut out = String::new();
    for block in body.split("\n\n") {
        let mut data = String::new();
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(rest.trim_start());
            }
        }
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        let Some(delta) = value.get("delta") else {
            continue;
        };
        match delta {
            Value::String(text) => out.push_str(text),
            Value::Object(map) => {
                if let Some(text) = map.get("text").and_then(Value::as_str) {
                    out.push_str(text);
                }
                if let Some(text) = map.get("partial_json").and_then(Value::as_str) {
                    out.push_str(text);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) => {}
        }
    }
    out
}

fn scrub(cmd: &mut Command, home: &Path) {
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("HOME", home);
    cmd.env("SYMVEIL_TEST_FILE_KEY", "1");
}
