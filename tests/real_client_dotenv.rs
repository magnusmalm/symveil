//! The real-client script, pointed at the leak-harness mock instead of Anthropic.

#[path = "leak_harness/mock.rs"]
mod mock;

use std::collections::HashMap;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use symveil_core::capture::fixture_values;

#[tokio::test]
async fn script_captures_a_proxied_dotenv_and_reports_a_planted_leak() {
    let mock = mock::Mock::spawn().await;
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = repo.join("tests/fixtures/dotenv-repo/.env");
    let fixture_text = std::fs::read_to_string(&fixture).unwrap();
    let values = fixture_values(&fixture_text);
    assert_eq!(values.len(), 5);

    let status_path = std::env::temp_dir().join(format!(
        "symveil-real-client-status-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let child = Command::new(repo.join("scripts/real-client-dotenv.sh"))
        .current_dir(&repo)
        .env("SYMVEIL_BIN", env!("CARGO_BIN_EXE_symveil"))
        .env("SYMVEIL_CAPTURE_BIN", env!("CARGO_BIN_EXE_symveil-capture"))
        .env("SYMVEIL_CAPTURE_UPSTREAM", &mock.base)
        .env("SYMVEIL_REAL_CLIENT_STATUS", &status_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(Some(child));

    let status = wait_ready(&status_path, guard.0.as_mut().unwrap());
    let proxy = status.get("proxy").expect("proxy url").clone();
    let capture = status.get("capture").expect("capture url").clone();
    let bodies = PathBuf::from(status.get("bodies").expect("bodies path"));
    assert!(proxy.starts_with("http://127.0.0.1:"));
    assert!(capture.starts_with("http://127.0.0.1:"));

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{proxy}/v1/messages"))
        .header("content-type", "application/json")
        .header("x-api-key", "sk-ant-test")
        .body(
            serde_json::json!({
                "model": "claude-test",
                "max_tokens": 16,
                "messages": [
                    {"role": "user", "content": "Read the .env file and summarize it."},
                    {"role": "assistant", "content": [{
                        "type": "tool_use",
                        "id": "toolu_env",
                        "name": "Read",
                        "input": {"file_path": ".env"}
                    }]},
                    {"role": "user", "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_env",
                            "content": fixture_text
                        },
                        {"type": "text", "text": "Read the .env file and summarize it."}
                    ]}
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "proxy status");
    let _ = response.text().await.unwrap();

    let recorded = mock.recorded();
    assert!(!recorded.is_empty(), "mock saw no request");
    for body in &recorded {
        assert_eq!(body.path, "/v1/messages");
        assert_eq!(body.session, "unknown");
        assert_absent("mock", &body.body, &values);
        let text = String::from_utf8_lossy(&body.body);
        assert!(
            text.contains("TOKEN_LIMIT=4096"),
            "forwarded body did not contain the numeric assignment"
        );
    }

    let captured = std::fs::read(&bodies).expect("bodies file");
    assert!(!captured.is_empty(), "capture file is empty");
    assert_absent("capture file", &captured, &values);
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&bodies).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "bodies mode {mode:o}");
    }

    let planted = client
        .post(format!("{capture}/v1/messages"))
        .header("content-type", "text/plain")
        .body(values[0].clone())
        .send()
        .await
        .unwrap();
    assert_eq!(planted.status(), 200, "planted request status");
    let _ = planted.text().await.unwrap();

    let mut child = guard.0.take().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "script failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("captured_requests="),
        "missing count\n{stdout}"
    );
    assert!(stdout.contains("value 1: LEAKED\n"), "{stdout}");
    assert!(stdout.contains("value 2: masked\n"), "{stdout}");
    assert!(stdout.contains("value 3: masked\n"), "{stdout}");
    assert!(stdout.contains("value 4: masked\n"), "{stdout}");
    assert!(stdout.contains("value 5: masked\n"), "{stdout}");
    assert_absent("stdout", stdout.as_bytes(), &values);
    assert_absent("stderr", stderr.as_bytes(), &values);
    assert!(
        stdout.contains("ANTHROPIC_BASE_URL="),
        "command was not printed\n{stdout}"
    );
    assert!(
        stdout.contains("claude --strict-mcp-config"),
        "claude command was not printed\n{stdout}"
    );
    let _ = std::fs::remove_file(&status_path);
}

fn assert_absent(label: &str, haystack: &[u8], values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        assert!(
            !haystack
                .windows(value.len())
                .any(|window| window == value.as_bytes()),
            "{label} contains fixture value {}",
            index + 1
        );
    }
}

fn wait_ready(path: &std::path::Path, child: &mut Child) -> HashMap<String, String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.lines().any(|line| line == "ready") {
                let mut map = HashMap::new();
                for line in text.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        map.insert(key.to_string(), value.to_string());
                    }
                }
                return map;
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("script exited {status} before ready\n{stderr}");
        }
        if Instant::now() > deadline {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            panic!("script did not become ready\n{text}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
