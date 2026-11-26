//! The launch scripts must fail closed and must not print tokens.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const TOKEN: &str = "synthetic-token-not-a-secret";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn write_exe(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

fn temp_dir(label: &str) -> PathBuf {
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

struct Health {
    port: u16,
}

fn spawn_health(body: &'static str) -> Health {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else {
                continue;
            };
            read_headers(&mut conn);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes());
            let _ = conn.shutdown(Shutdown::Both);
        }
    });
    let health = Health { port };
    wait_health(&health);
    health
}

fn read_headers(conn: &mut TcpStream) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        match conn.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn wait_health(health: &Health) {
    let url = format!("http://127.0.0.1:{}/health", health.port);
    for _ in 0..50 {
        let ok = Command::new("curl")
            .args(["-fsS", "--max-time", "1", &url])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if ok {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("health server did not start on port {}", health.port);
}

struct Captured {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_script(script: &str, args: &[&str], envs: &[(&str, &str)], capture: &Path) -> Captured {
    let mut cmd = Command::new(repo().join("scripts").join(script));
    cmd.args(args)
        .current_dir(repo())
        .env("CAPTURE", capture)
        .env("ANTHROPIC_API_KEY", TOKEN)
        .env("XAI_API_KEY", TOKEN)
        .env(
            "PATH",
            format!(
                "{}:{}",
                capture.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let output = cmd.output().unwrap();
    Captured {
        status: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn assert_no_token(captured: &Captured) {
    assert!(
        !captured.stdout.contains(TOKEN),
        "stdout printed a token:\n{}",
        captured.stdout
    );
    assert!(
        !captured.stderr.contains(TOKEN),
        "stderr printed a token:\n{}",
        captured.stderr
    );
}

fn install_fakes(dir: &Path) {
    write_exe(
        &dir.join("claude"),
        "#!/bin/sh\nset -eu\nout=${CAPTURE:?}\nmkdir -p \"${out}\"\nprintf '%s\\n' \"$@\" > \"${out}/args\"\nprintf '%s\\n' \"${ANTHROPIC_BASE_URL:-}\" > \"${out}/anthropic_base\"\nprintf '%s\\n' \"${CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:-}\" > \"${out}/traffic\"\nprintf '%s\\n' \"${ENABLE_CLAUDEAI_MCP_SERVERS:-}\" > \"${out}/mcp\"\n",
    );
    write_exe(
        &dir.join("grok"),
        "#!/bin/sh\nset -eu\nout=${CAPTURE:?}\nmkdir -p \"${out}\"\nprintf '%s\\n' \"$@\" > \"${out}/args\"\nprintf '%s\\n' \"${GROK_CLI_CHAT_PROXY_BASE_URL:-}\" > \"${out}/chat_base\"\nprintf '%s\\n' \"${GROK_MODELS_LIST_URL:-}\" > \"${out}/models_url\"\nprintf '%s\\n' \"${GROK_REQUEST_COMPRESSION:-}\" > \"${out}/compression\"\n",
    );
}

#[test]
fn shellcheck_launch_scripts() {
    let status = Command::new("shellcheck")
        .args([
            "-s",
            "sh",
            "-x",
            "scripts/symveil-claude",
            "scripts/symveil-grok",
            "scripts/symveil-common.sh",
        ])
        .current_dir(repo())
        .status()
        .expect("shellcheck is installed");
    assert!(status.success());
}

#[test]
fn claude_script_points_at_the_proxy_and_forwards_args() {
    let dir = temp_dir("launch-claude");
    install_fakes(&dir);
    let health = spawn_health(r#"{"status":"ok"}"#);
    let origin = format!("http://127.0.0.1:{}", health.port);
    let captured = run_script(
        "symveil-claude",
        &["--print", "hello world"],
        &[
            ("SYMVEIL_HOST", "127.0.0.1"),
            ("SYMVEIL_PORT", &health.port.to_string()),
            ("SYMVEIL_PROXY", ""),
        ],
        &dir,
    );
    assert_eq!(captured.status, 0, "stderr:\n{}", captured.stderr);
    assert!(captured.stdout.is_empty(), "{}", captured.stdout);
    assert_no_token(&captured);
    assert_eq!(
        std::fs::read_to_string(dir.join("anthropic_base")).unwrap(),
        format!("{origin}\n")
    );
    assert_eq!(std::fs::read_to_string(dir.join("traffic")).unwrap(), "1\n");
    assert_eq!(std::fs::read_to_string(dir.join("mcp")).unwrap(), "false\n");
    assert_eq!(
        std::fs::read_to_string(dir.join("args")).unwrap(),
        "--strict-mcp-config\n--print\nhello world\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn grok_script_disables_compression_and_uses_symveil_proxy() {
    let dir = temp_dir("launch-grok");
    install_fakes(&dir);
    let health = spawn_health(r#"{"status":"ok"}"#);
    let origin = format!("http://127.0.0.1:{}", health.port);
    let captured = run_script(
        "symveil-grok",
        &["-p", "Explain this repo."],
        &[
            ("SYMVEIL_PROXY", &origin),
            ("SYMVEIL_PORT", "1"),
            ("SYMVEIL_HOST", "127.0.0.1"),
        ],
        &dir,
    );
    assert_eq!(captured.status, 0, "stderr:\n{}", captured.stderr);
    assert!(captured.stdout.is_empty(), "{}", captured.stdout);
    assert_no_token(&captured);
    assert_eq!(
        std::fs::read_to_string(dir.join("chat_base")).unwrap(),
        format!("{origin}/v1\n")
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("models_url")).unwrap(),
        format!("{origin}/v1/models\n")
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("compression")).unwrap(),
        "0\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("args")).unwrap(),
        "-p\nExplain this repo.\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripts_refuse_to_start_when_the_proxy_is_down() {
    let dir = temp_dir("launch-down");
    install_fakes(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    drop(listener);
    for script in ["symveil-claude", "symveil-grok"] {
        let captured = run_script(
            script,
            &["should-not-run"],
            &[
                ("SYMVEIL_HOST", "127.0.0.1"),
                ("SYMVEIL_PORT", &port),
                ("SYMVEIL_PROXY", ""),
            ],
            &dir,
        );
        assert_ne!(captured.status, 0, "{script} started without a proxy");
        assert_no_token(&captured);
        assert!(
            captured.stderr.contains("not starting the client"),
            "{script} stderr:\n{}",
            captured.stderr
        );
        assert!(!dir.join("args").exists(), "{script} launched the client");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripts_refuse_a_health_body_that_is_not_ok_and_hide_userinfo() {
    let dir = temp_dir("launch-bad-health");
    install_fakes(&dir);
    let health = spawn_health(r#"{"status":"no"}"#);
    let port = health.port.to_string();
    let proxy = format!("http://user:{TOKEN}@127.0.0.1:{port}");
    let captured = run_script(
        "symveil-claude",
        &["should-not-run"],
        &[("SYMVEIL_PROXY", &proxy)],
        &dir,
    );
    assert_ne!(captured.status, 0);
    assert_no_token(&captured);
    assert!(
        captured.stderr.contains("did not report status ok"),
        "{}",
        captured.stderr
    );
    assert!(!dir.join("args").exists());

    let huge = format!("{{\"status\":\"ok\"{}}}", "x".repeat(300));
    // The health thread serves a static body. A second server covers the size cap.
    let dir2 = temp_dir("launch-huge-health");
    install_fakes(&dir2);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let huge_port = listener.local_addr().unwrap().port();
    let huge_body = huge.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else {
                continue;
            };
            read_headers(&mut conn);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{huge_body}",
                huge_body.len()
            );
            let _ = conn.write_all(resp.as_bytes());
            let _ = conn.shutdown(Shutdown::Both);
        }
    });
    let huge_url = format!("http://127.0.0.1:{huge_port}/health");
    let mut ready = false;
    for _ in 0..50 {
        let ok = Command::new("curl")
            .args(["-fsS", "--max-time", "1", &huge_url])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if ok {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(ready, "oversized health server did not start");
    let captured = run_script(
        "symveil-grok",
        &["should-not-run"],
        &[("SYMVEIL_PROXY", &format!("http://127.0.0.1:{huge_port}"))],
        &dir2,
    );
    assert_ne!(captured.status, 0, "stderr:\n{}", captured.stderr);
    assert_no_token(&captured);
    assert!(
        captured.stderr.contains("unexpected body"),
        "{}",
        captured.stderr
    );
    assert!(!dir2.join("args").exists());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}
