//! Vault file on disk: encryption, migration, and a proxy that refuses a bad key.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use symveil::vault::{placeholder_token, vault_key_path, Vault, TOKEN_LEN};
use tokio::net::TcpListener;

const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

#[derive(Clone)]
struct Mock {
    hits: Arc<Mutex<Vec<Vec<u8>>>>,
    body: Arc<Vec<u8>>,
}

struct RunningProxy {
    child: Option<Child>,
    url: String,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl RunningProxy {
    fn logs(&self) -> String {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            self.stdout.lock().unwrap(),
            self.stderr.lock().unwrap()
        )
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

#[tokio::test]
async fn proxy_masks_a_secret_and_restores_it_after_restart() {
    let root = temp_dir("e2e-vault");
    let symveil_dir = root.join(".symveil");
    let vault_path = symveil_dir.join("vault.json");
    let (mock_url, hits) = spawn_mock(b"{}".to_vec()).await;
    let proxy = spawn_cli(&root, &mock_url, &mock_url).await;
    wait_health(&proxy.url).await;
    assert!(
        !vault_path.exists(),
        "a new vault is written when a value is masked"
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let response = client
        .post(format!("{}/v1/chat/completions", proxy.url))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"model":"gpt-test","messages":[{{"role":"user","content":"token {SECRET}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", proxy.logs());
    let forwarded = String::from_utf8(hits.lock().unwrap()[0].clone()).unwrap();
    assert!(!forwarded.contains(SECRET), "{forwarded}");
    let placeholder = placeholder_in(&forwarded);
    assert_eq!(placeholder.len(), TOKEN_LEN);

    assert_no_secret(&symveil_dir);
    assert!(!proxy.logs().contains(SECRET), "{}", proxy.logs());
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vault_path).unwrap()).unwrap();
    assert_eq!(on_disk["version"].as_u64(), Some(2));
    assert_eq!(on_disk["cipher"].as_str(), Some("aes-256-gcm"));
    assert_eq!(
        names_in(&symveil_dir),
        vec![
            "audit.jsonl".to_string(),
            "vault.json".to_string(),
            "vault.key".to_string()
        ]
    );
    #[cfg(unix)]
    {
        assert_eq!(mode_bits(&symveil_dir), 0o700);
        assert_eq!(mode_bits(&vault_path), 0o600);
        assert_eq!(mode_bits(&vault_key_path(&vault_path)), 0o600);
        assert_eq!(mode_bits(&symveil_dir.join("audit.jsonl")), 0o600);
    }
    drop(proxy);

    let (mock_url, _) = spawn_mock(
        format!(r#"{{"choices":[{{"message":{{"content":"was {placeholder}"}}}}]}}"#).into_bytes(),
    )
    .await;
    let restarted = spawn_cli(&root, &mock_url, &mock_url).await;
    wait_health(&restarted.url).await;
    let response = client
        .post(format!("{}/v1/chat/completions", restarted.url))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-test","messages":[{"role":"user","content":"again"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", restarted.logs());
    let text = response.text().await.unwrap();
    assert!(text.contains(SECRET), "{text}");
    assert!(!text.contains(&placeholder), "{text}");
    assert_no_secret(&symveil_dir);
    assert!(!restarted.logs().contains(SECRET), "{}", restarted.logs());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn proxy_migrates_a_plaintext_vault_and_restores_the_old_placeholder() {
    let root = temp_dir("e2e-migrate");
    let symveil_dir = root.join(".symveil");
    std::fs::create_dir(&symveil_dir).unwrap();
    #[cfg(unix)]
    let dir_mode = mode_bits(&symveil_dir);
    let vault_path = symveil_dir.join("vault.json");
    let natural = placeholder_token(SECRET, 0);
    let placeholder = if natural == "@@sv:89abcdef@@" {
        "@@sv:0123abcd@@"
    } else {
        "@@sv:89abcdef@@"
    };
    assert_ne!(placeholder, natural);
    let plain = format!(
        r#"{{"version":1,"entries":[{{"original":"{SECRET}","placeholder":"{placeholder}","category":"secret","rule":"aws-access-key-id"}}]}}"#
    );
    std::fs::write(&vault_path, &plain).unwrap();
    assert!(std::fs::read(&vault_path)
        .unwrap()
        .windows(SECRET.len())
        .any(|w| w == SECRET.as_bytes()));

    let (mock_url, hits) = spawn_mock(
        format!(r#"{{"choices":[{{"message":{{"content":"was {placeholder}"}}}}]}}"#).into_bytes(),
    )
    .await;
    let proxy = spawn_cli(&root, &mock_url, &mock_url).await;
    wait_health(&proxy.url).await;
    assert_no_secret(&symveil_dir);
    let sealed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vault_path).unwrap()).unwrap();
    assert_eq!(sealed["version"].as_u64(), Some(2));
    #[cfg(unix)]
    {
        assert_eq!(mode_bits(&symveil_dir), dir_mode);
        assert_eq!(mode_bits(&vault_path), 0o600);
        assert_eq!(mode_bits(&vault_key_path(&vault_path)), 0o600);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let response = client
        .post(format!("{}/v1/chat/completions", proxy.url))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"model":"gpt-test","messages":[{{"role":"user","content":"token {SECRET}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", proxy.logs());
    let forwarded = String::from_utf8(hits.lock().unwrap()[0].clone()).unwrap();
    assert!(
        forwarded.contains(placeholder),
        "migration kept the old placeholder, got {forwarded}"
    );
    assert!(!forwarded.contains(&natural), "{forwarded}");
    let text = response.text().await.unwrap();
    assert!(text.contains(SECRET), "{text}");
    assert!(!text.contains(placeholder), "{text}");
    assert_no_secret(&symveil_dir);
    assert!(!proxy.logs().contains(SECRET), "{}", proxy.logs());
    drop(proxy);

    let (mock_url, _) = spawn_mock(
        format!(r#"{{"choices":[{{"message":{{"content":"still {placeholder}"}}}}]}}"#)
            .into_bytes(),
    )
    .await;
    let restarted = spawn_cli(&root, &mock_url, &mock_url).await;
    wait_health(&restarted.url).await;
    let response = client
        .post(format!("{}/v1/chat/completions", restarted.url))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-test","messages":[{"role":"user","content":"again"}]}"#)
        .send()
        .await
        .unwrap();
    let text = response.text().await.unwrap();
    assert!(text.contains(SECRET), "{text}");
    assert_no_secret(&symveil_dir);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn proxy_exits_when_the_key_is_missing() {
    let root = temp_dir("cli-missing-key");
    let vault_path = root.join(".symveil").join("vault.json");
    std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();
    let mut vault = Vault::create(vault_path.clone());
    vault
        .assign(SECRET, symveil::Category::Secret, None)
        .unwrap();
    vault.save().unwrap();
    let sealed = std::fs::read(&vault_path).unwrap();
    std::fs::remove_file(vault_key_path(&vault_path)).unwrap();

    let err = proxy_fails(&root);
    assert!(err.contains("missing"), "{err}");
    assert!(err.contains("unchanged"), "{err}");
    assert!(err.contains("empty vault"), "{err}");
    assert_eq!(std::fs::read(&vault_path).unwrap(), sealed);
    assert!(!vault_key_path(&vault_path).exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn proxy_exits_when_the_key_is_wrong() {
    let root = temp_dir("cli-wrong-key");
    let vault_path = root.join(".symveil").join("vault.json");
    std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();
    let mut vault = Vault::create(vault_path.clone());
    vault
        .assign(SECRET, symveil::Category::Secret, None)
        .unwrap();
    vault.save().unwrap();
    let sealed = std::fs::read(&vault_path).unwrap();

    let other_dir = temp_dir("cli-other-key");
    let other_path = other_dir.join("vault.json");
    let mut other = Vault::create(other_path.clone());
    other
        .assign("other-secret-value", symveil::Category::Secret, None)
        .unwrap();
    other.save().unwrap();
    let wrong = std::fs::read(vault_key_path(&other_path)).unwrap();
    std::fs::copy(vault_key_path(&other_path), vault_key_path(&vault_path)).unwrap();

    let err = proxy_fails(&root);
    assert!(err.contains("unchanged"), "{err}");
    assert!(err.contains("empty vault"), "{err}");
    assert!(
        err.contains("does not match") || err.contains("decrypt"),
        "{err}"
    );
    assert_eq!(std::fs::read(&vault_path).unwrap(), sealed);
    assert_eq!(std::fs::read(vault_key_path(&vault_path)).unwrap(), wrong);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&other_dir);
}

fn proxy_fails(repo: &Path) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_symveil"))
        .current_dir(repo)
        .args(["proxy", "--repo", ".", "--port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdout_handle = thread::spawn(move || {
        let mut buf = String::new();
        let _ = std::io::Read::read_to_string(&mut stdout, &mut buf);
        buf
    });
    let stderr_handle = thread::spawn(move || {
        let mut buf = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr, &mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let out = stdout_handle.join().unwrap();
            let err = stderr_handle.join().unwrap();
            panic!("proxy stayed up\nstdout:\n{out}\nstderr:\n{err}");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let out = stdout_handle.join().unwrap();
    let err = stderr_handle.join().unwrap();
    assert!(
        !status.success(),
        "proxy exited 0\nstdout:\n{out}\nstderr:\n{err}"
    );
    err
}

async fn spawn_cli(repo: &Path, openai: &str, anthropic: &str) -> RunningProxy {
    let repo = repo.to_path_buf();
    let openai = openai.to_string();
    let anthropic = anthropic.to_string();
    tokio::task::spawn_blocking(move || spawn_cli_blocking(&repo, &openai, &anthropic))
        .await
        .unwrap()
}

fn spawn_cli_blocking(repo: &Path, openai: &str, anthropic: &str) -> RunningProxy {
    let child = Command::new(env!("CARGO_BIN_EXE_symveil"))
        .current_dir(repo)
        .args([
            "proxy",
            "--repo",
            ".",
            "--port",
            "0",
            "--openai-base",
            openai,
            "--anthropic-base",
            anthropic,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(Some(child));
    let child = guard.0.as_mut().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdout_buf = Arc::new(Mutex::new(String::new()));
    let stderr_buf = Arc::new(Mutex::new(String::new()));
    let stdout_copy = Arc::clone(&stdout_buf);
    let stderr_copy = Arc::clone(&stderr_buf);
    thread::spawn(move || {
        let mut reader = BufReader::new(&mut stdout);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            stdout_copy.lock().unwrap().push_str(&line);
            line.clear();
        }
    });
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(&mut stderr);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            stderr_copy.lock().unwrap().push_str(&line);
            if line.contains("listening on") {
                let _ = tx.send(line.trim().to_string());
            }
            line.clear();
        }
    });
    let line = match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(line) => line,
        Err(_) => {
            panic!(
                "proxy did not listen\nstdout:\n{}\nstderr:\n{}",
                stdout_buf.lock().unwrap(),
                stderr_buf.lock().unwrap()
            );
        }
    };
    let url = line
        .split_whitespace()
        .find(|part| part.starts_with("http://"))
        .unwrap_or_else(|| panic!("no listen url in {line}"))
        .to_string();
    RunningProxy {
        child: guard.0.take(),
        url,
        stdout: stdout_buf,
        stderr: stderr_buf,
    }
}

async fn spawn_mock(body: Vec<u8>) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = Mock {
        hits: Arc::clone(&hits),
        body: Arc::new(body),
    };
    let app = Router::new().fallback(any(record)).with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), hits)
}

async fn record(State(state): State<Mock>, req: Request<Body>) -> Response {
    let bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .unwrap();
    state.hits.lock().unwrap().push(bytes.to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from((*state.body).clone()))
        .unwrap()
}

async fn wait_health(url: &str) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    for _ in 0..50 {
        if client.get(format!("{url}/health")).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("health check failed for {url}");
}

fn placeholder_in(body: &str) -> String {
    let start = body.find("@@sv:").expect("placeholder");
    body[start..start + TOKEN_LEN].to_string()
}

fn assert_no_secret(dir: &Path) {
    let hits = files_containing(dir, SECRET.as_bytes());
    assert!(hits.is_empty(), "plaintext of the secret is in {hits:?}");
}

fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            if bytes.len() >= needle.len()
                && bytes.windows(needle.len()).any(|window| window == needle)
            {
                found.push(path);
            }
        }
    }
    found
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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

#[cfg(unix)]
fn mode_bits(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}
