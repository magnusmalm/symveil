//! `symveil check` and `proxy --check` / `--dry-run`.
//!
//! The child environment is cleared so a learned file or `SYMVEIL_LEARNED`
//! in this process cannot change the report. Every assertion that a secret or
//! a term stays hidden uses the sentinels in `HIDDEN`.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;

const HIDDEN: &[&str] = &[
    "Exempla",
    "Testdotter",
    "Tundrahorn",
    "AKIA",
    "HiddenTermZZZ",
    "zebrafinch",
    "ada@example.com",
    "db.box.example",
    "VAULTBODYZZZ",
];

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "symveil-check-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn home(&self) -> PathBuf {
        let home = self.path.join("home");
        fs::create_dir_all(home.join(".config")).unwrap();
        home
    }

    fn repo(&self) -> PathBuf {
        let repo = self.path.join("repo");
        fs::create_dir_all(&repo).unwrap();
        repo
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Out {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn run(home: &Path, args: &[&str]) -> Out {
    let output = command(home).args(args).output().unwrap();
    Out {
        status: output.status,
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn command(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_symveil"));
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("HOME", home);
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn clean_body(port: u16) -> String {
    format!(
        r#"[proxy]
listen = "127.0.0.1"
port = {port}
openai_base = "https://api.openai.invalid"
anthropic_base = "https://api.anthropic.invalid"
timeout_secs = 30
audit_log = ".symveil/audit.jsonl"
vault = ".symveil/vault.json"

[binary]
mode = "block"

[redact]
mode = "enforce"
internal_domains = ["example"]
high_entropy = false

[redact.pii]
email = true
phone = true
personnummer = true

[redact.names]
terms = ["Exempla"]
people = ["Ren Testdotter"]
"#
    )
}

fn write_config(repo: &Path, body: &str) {
    fs::write(repo.join(".symveil.toml"), body).unwrap();
}

fn with_learned(body: &str, path: &Path) -> String {
    let line = format!("learned = \"{}\"\n", path.display());
    body.replace(
        "high_entropy = false\n",
        &format!("high_entropy = false\n{line}"),
    )
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

fn assert_hidden(text: &str) {
    assert_hidden_except(text, &[]);
}

fn assert_hidden_except(text: &str, allowed: &[&str]) {
    for secret in HIDDEN {
        if allowed.contains(secret) {
            continue;
        }
        assert!(!text.contains(secret), "output contains {secret}:\n{text}");
    }
}

fn assert_both_hidden(out: &Out) {
    assert_hidden(&out.stdout);
    assert_hidden(&out.stderr);
}

fn codes(value: &Value) -> Vec<String> {
    value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|warning| warning["code"].as_str().unwrap().to_string())
        .collect()
}

fn assert_shape(value: &Value) {
    for key in [
        "config",
        "repo",
        "vault",
        "audit_log",
        "binary_mode",
        "pii",
        "internal_domains",
        "names",
        "learned",
        "upstream",
        "listen",
        "port",
        "port_free",
        "proxy",
        "warnings",
        "sample",
    ] {
        assert!(value.get(key).is_some(), "missing {key}");
    }
    assert!(value["names"].get("terms").is_some());
    assert!(value["names"].get("people").is_some());
    assert!(value["names"].get("values").is_none());
    assert!(value["learned"].get("terms").is_some());
    assert!(value["learned"].get("people").is_some());
    assert!(value["learned"].get("secrets").is_some());
    assert!(value["learned"].get("hosts").is_some());
    assert!(value["learned"].get("symbols").is_some());
    assert!(value["learned"].get("skips").is_some());
    assert!(value["vault"].get("exists").is_some());
    assert!(value["vault"].get("writable").is_some());
    assert!(value["proxy"].get("timeout_secs").is_some());
    assert!(value["proxy"].get("high_entropy").is_some());
    assert!(value["proxy"].get("dotenv").is_some());
    assert!(value["proxy"].get("home_paths").is_some());
}

#[test]
fn clean_config_is_quiet_and_hides_terms() {
    let tmp = Temp::new("clean");
    let repo = tmp.repo();
    let port = free_port();
    write_config(&repo, &clean_body(port));
    let out = run(
        &tmp.home(),
        &[
            "check",
            "--strict",
            "--repo",
            repo.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(out.status.success(), "{}\n{}", out.stderr, out.stdout);
    assert!(out.stderr.is_empty(), "{}", out.stderr);
    assert_both_hidden(&out);
    let value: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_shape(&value);
    assert!(value["warnings"].as_array().unwrap().is_empty(), "{value}");
    assert_eq!(value["names"]["terms"], 1);
    assert_eq!(value["names"]["people"], 1);
    assert_eq!(value["binary_mode"], "block");
    assert_eq!(value["pii"]["email"], true);
    assert_eq!(value["port_free"], true);
    assert_eq!(value["vault"]["exists"], false);
    assert_eq!(value["vault"]["writable"], true);
    assert_eq!(value["config"]["found"], true);
    assert!(value["config"]["path"]
        .as_str()
        .unwrap()
        .ends_with(".symveil.toml"));
    assert!(value["learned"]["path"].is_string());
    assert_eq!(value["learned"]["loaded"], false);
    assert_eq!(
        value["upstream"]["openai_base"],
        "https://api.openai.invalid"
    );
    assert_eq!(value["proxy"]["timeout_secs"], 30);
    assert_eq!(value["proxy"]["mode"], "enforce");
    assert!(!repo.join(".symveil").exists());
    assert!(repo.read_dir().unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".symveil-check-probe-")));
}

#[test]
fn buffered_audit_check_names_the_crash_tradeoff() {
    let tmp = Temp::new("audit-buffer");
    let repo = tmp.repo();
    let port = free_port();
    let mut body = clean_body(port);
    write_config(&repo, &body);
    let off = run(
        &tmp.home(),
        &["check", "--json", "--repo", repo.to_str().unwrap()],
    );
    assert!(off.status.success(), "{}\n{}", off.stderr, off.stdout);
    assert!(!off.stdout.contains("a crash can lose"));
    let off_json: Value = serde_json::from_str(&off.stdout).unwrap();
    assert_eq!(off_json["audit_buffered"], false);
    assert_eq!(off_json["proxy"]["audit_buffered"], false);

    body = body.replace(
        "audit_log = \".symveil/audit.jsonl\"\n",
        "audit_log = \".symveil/audit.jsonl\"\naudit_buffered = true\n",
    );
    write_config(&repo, &body);
    let on = run(&tmp.home(), &["check", "--repo", repo.to_str().unwrap()]);
    assert!(on.status.success(), "{}\n{}", on.stderr, on.stdout);
    assert!(on.stdout.contains("audit_flush"), "{}", on.stdout);
    assert!(
        on.stdout
            .contains("buffered; a crash can lose the last lines still in the buffer"),
        "{}",
        on.stdout
    );
    assert_both_hidden(&on);
    let json = run(
        &tmp.home(),
        &["check", "--json", "--repo", repo.to_str().unwrap()],
    );
    assert!(json.status.success(), "{}\n{}", json.stderr, json.stdout);
    let value: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(value["audit_buffered"], true);
    assert_eq!(value["proxy"]["audit_buffered"], true);
}

#[test]
fn human_report_lists_the_effective_settings() {
    let tmp = Temp::new("human");
    let repo = tmp.repo();
    let port = free_port();
    write_config(&repo, &clean_body(port));
    let out = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}\n{}", out.stderr, out.stdout);
    assert_both_hidden(&out);
    for label in [
        "symveil check",
        "config",
        "repo",
        "vault",
        "audit",
        "binaries",
        "block",
        "pii",
        "email=on",
        "phone=on",
        "personnummer=on",
        "domains",
        "example",
        "names",
        "terms=1",
        "people=1",
        "learned",
        "openai",
        "anthropic",
        "port",
        "free=yes",
        "timeout",
        "mode",
        "enforce",
        "entropy",
        "dotenv",
        "home_paths",
        "warnings",
        "none",
    ] {
        assert!(
            out.stdout.contains(label),
            "missing {label}:\n{}",
            out.stdout
        );
    }
}

#[test]
fn warnings_exit_zero_unless_strict() {
    let tmp = Temp::new("strict");
    let repo = tmp.repo();
    let loose = run(&tmp.home(), &["check", "--repo", repo.to_str().unwrap()]);
    assert!(loose.status.success(), "{}", loose.stderr);
    assert!(loose.stdout.contains("[no_config]"));
    assert!(loose.stdout.contains("[pii_off]"));
    assert!(loose.stdout.contains("[terms_empty]"));
    assert_both_hidden(&loose);
    let strict = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(strict.status.code(), Some(2), "{}", strict.stderr);
    assert!(strict.stdout.contains("[no_config]"));
    assert_both_hidden(&strict);
}

#[test]
fn binary_pass_is_a_warning_and_scan_is_not() {
    let tmp = Temp::new("binary");
    let repo = tmp.repo();
    let port = free_port();
    let mut body = clean_body(port);
    body = body.replace("mode = \"block\"", "mode = \"pass\"");
    write_config(&repo, &body);
    let out = run(
        &tmp.home(),
        &[
            "check",
            "--strict",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}\n{}", out.stderr, out.stdout);
    assert_both_hidden(&out);
    let value: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(value["binary_mode"], "pass");
    assert_eq!(codes(&value), vec!["binary_pass".to_string()]);

    body = body.replace("mode = \"pass\"", "mode = \"scan\"");
    write_config(&repo, &body);
    let scan = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert!(scan.status.success(), "{}\n{}", scan.stderr, scan.stdout);
    assert!(!scan.stdout.contains("[binary_pass]"));
    assert!(scan.stdout.contains("scan"));
    assert_both_hidden(&scan);
}

#[test]
fn no_config_warns_about_defaults() {
    let tmp = Temp::new("noconfig");
    let repo = tmp.repo();
    let out = run(
        &tmp.home(),
        &[
            "check",
            "--strict",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let value: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(value["config"]["found"], false);
    assert!(value["config"]["path"].is_null());
    let found = codes(&value);
    assert!(found.contains(&"no_config".to_string()), "{found:?}");
    assert!(found.contains(&"pii_off".to_string()), "{found:?}");
    assert!(found.contains(&"terms_empty".to_string()), "{found:?}");
    assert_both_hidden(&out);
}

#[test]
fn pii_off_warns_and_one_detector_is_enough() {
    let tmp = Temp::new("pii");
    let repo = tmp.repo();
    let port = free_port();
    let mut body = clean_body(port);
    body = body.replace(
        "email = true\nphone = true\npersonnummer = true\n",
        "email = false\nphone = false\npersonnummer = false\n",
    );
    write_config(&repo, &body);
    let out = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2), "{}", out.stdout);
    assert!(out.stdout.contains("[pii_off]"));
    assert!(out.stdout.contains("email=off"));
    assert!(!out.stdout.contains("[terms_empty]"));
    assert_both_hidden(&out);

    body = body.replace("email = false", "email = true");
    write_config(&repo, &body);
    let one = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert!(one.status.success(), "{}\n{}", one.stderr, one.stdout);
    assert!(!one.stdout.contains("[pii_off]"));
    assert!(one.stdout.contains("email=on phone=off personnummer=off"));
    assert_both_hidden(&one);
}

#[test]
fn empty_term_list_warns_without_printing_people() {
    let tmp = Temp::new("terms");
    let repo = tmp.repo();
    let port = free_port();
    let body = clean_body(port).replace("terms = [\"Exempla\"]\n", "terms = []\n");
    write_config(&repo, &body);
    let out = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2), "{}", out.stdout);
    assert!(out.stdout.contains("[terms_empty]"));
    assert!(out.stdout.contains("terms=0"));
    assert!(out.stdout.contains("people=1"));
    assert_both_hidden(&out);
}

#[test]
fn upstream_must_be_https_or_loopback() {
    let tmp = Temp::new("upstream");
    let repo = tmp.repo();
    let port = free_port();
    let bad = clean_body(port)
        .replace("https://api.openai.invalid", "http://upstream.invalid")
        .replace("https://api.anthropic.invalid", "http://files.invalid/v1");
    write_config(&repo, &bad);
    let out = run(
        &tmp.home(),
        &[
            "check",
            "--strict",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}", out.stdout);
    let value: Value = serde_json::from_str(&out.stdout).unwrap();
    let found = codes(&value);
    assert!(found.contains(&"upstream_openai".to_string()), "{found:?}");
    assert!(
        found.contains(&"upstream_anthropic".to_string()),
        "{found:?}"
    );
    assert!(out.stdout.contains("upstream.invalid"));
    assert!(out.stdout.contains("files.invalid"));
    assert_both_hidden(&out);

    let local = clean_body(port)
        .replace("https://api.openai.invalid", "http://127.0.0.1:9")
        .replace("https://api.anthropic.invalid", "http://localhost:9");
    write_config(&repo, &local);
    let ok = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert!(ok.status.success(), "{}\n{}", ok.stderr, ok.stdout);
    assert!(!ok.stdout.contains("[upstream_"));
    assert_both_hidden(&ok);

    let v6 = clean_body(port).replace("https://api.openai.invalid", "http://[::1]:9");
    write_config(&repo, &v6);
    let v6_out = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert!(
        v6_out.status.success(),
        "{}\n{}",
        v6_out.stderr,
        v6_out.stdout
    );
    assert!(!v6_out.stdout.contains("[upstream_openai]"));
    assert_both_hidden(&v6_out);
}

#[test]
fn unknown_keys_are_warnings_and_invalid_values_still_fail() {
    let tmp = Temp::new("unknown");
    let repo = tmp.repo();
    let port = free_port();
    let mut body = clean_body(port);
    body = body.replace(
        "port = ",
        "prot = 1\nunused_note = \"HiddenTermZZZ\"\nport = ",
    );
    body = body.replace("email = true", "emial = true\nemail = true");
    write_config(&repo, &body);
    let out = run(
        &tmp.home(),
        &[
            "check",
            "--strict",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}\n{}", out.stderr, out.stdout);
    assert_both_hidden(&out);
    let value: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(value["pii"]["email"], true);
    assert_eq!(value["port"], port);
    let messages: Vec<_> = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|warning| warning["message"].as_str().unwrap())
        .collect();
    let joined = messages.join("\n");
    assert!(joined.contains("proxy.prot"), "{joined}");
    assert!(joined.contains("proxy.unused_note"), "{joined}");
    assert!(joined.contains("redact.pii.emial"), "{joined}");
    assert!(!joined.contains("HiddenTermZZZ"), "{joined}");

    write_config(&repo, "[redact]\nmode = \"nope\"\n");
    let bad = run(&tmp.home(), &["check", "--repo", repo.to_str().unwrap()]);
    assert_eq!(bad.status.code(), Some(1), "{}", bad.stdout);
    assert!(bad.stderr.contains("unknown redact mode"), "{}", bad.stderr);
    assert_both_hidden(&bad);
}

#[test]
fn learned_file_missing_unreadable_invalid_and_private() {
    let tmp = Temp::new("learned");
    let repo = tmp.repo();
    let home = tmp.home();
    let port = free_port();
    let missing = repo.join("missing-learned.toml");
    write_config(&repo, &with_learned(&clean_body(port), &missing));
    let out = run(
        &home,
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2), "{}", out.stdout);
    assert!(out.stdout.contains("[learned_missing]"));
    assert_both_hidden(&out);

    let dir = repo.join("learned-dir");
    fs::create_dir(&dir).unwrap();
    write_config(&repo, &with_learned(&clean_body(port), &dir));
    let unread = run(
        &home,
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(unread.status.code(), Some(2), "{}", unread.stdout);
    assert!(unread.stdout.contains("[learned_unreadable]"));
    assert_both_hidden(&unread);

    let broken = repo.join("broken-learned.toml");
    fs::write(&broken, "terms = [\"HiddenTermZZZ\"\n").unwrap();
    set_mode(&broken, 0o600);
    write_config(&repo, &with_learned(&clean_body(port), &broken));
    let invalid = run(
        &home,
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(invalid.status.code(), Some(2), "{}", invalid.stdout);
    assert!(invalid.stdout.contains("[learned_invalid]"));
    assert_both_hidden(&invalid);

    let good = home.join("learned.toml");
    fs::write(&good, "[names]\nterms = [\"Tundrahorn\"]\n").unwrap();
    set_mode(&good, 0o600);
    write_config(&repo, &with_learned(&clean_body(port), &good));
    let loaded = run(
        &home,
        &[
            "check",
            "--strict",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert!(
        loaded.status.success(),
        "{}\n{}",
        loaded.stderr,
        loaded.stdout
    );
    assert_both_hidden(&loaded);
    let value: Value = serde_json::from_str(&loaded.stdout).unwrap();
    assert_eq!(value["learned"]["loaded"], true);
    assert_eq!(value["learned"]["terms"], 1);
    assert_eq!(value["names"]["terms"], 2);
    assert!(value["warnings"].as_array().unwrap().is_empty(), "{value}");
}

#[cfg(unix)]
#[test]
fn loose_learned_and_vault_modes_warn() {
    let tmp = Temp::new("mode");
    let repo = tmp.repo();
    let port = free_port();
    let learned = repo.join("loose-learned.toml");
    fs::write(&learned, "[names]\nterms = [\"Tundrahorn\"]\n").unwrap();
    set_mode(&learned, 0o644);
    write_config(&repo, &with_learned(&clean_body(port), &learned));
    let out = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2), "{}", out.stdout);
    assert!(out.stdout.contains("[learned_mode]"));
    assert!(out.stdout.contains("0644"));
    assert_both_hidden(&out);

    set_mode(&learned, 0o600);
    fs::create_dir_all(repo.join(".symveil")).unwrap();
    let vault = repo.join(".symveil/vault.json");
    fs::write(&vault, "VAULTBODYZZZ").unwrap();
    set_mode(&vault, 0o640);
    let vault_out = run(
        &tmp.home(),
        &["check", "--strict", "--repo", repo.to_str().unwrap()],
    );
    assert_eq!(vault_out.status.code(), Some(2), "{}", vault_out.stdout);
    assert!(vault_out.stdout.contains("[vault_mode]"));
    assert!(!vault_out.stdout.contains("[learned_mode]"));
    assert_both_hidden(&vault_out);
}

#[test]
fn git_warns_when_a_path_would_be_committed_and_ignores_symveil_dir() {
    let tmp = Temp::new("git");
    let repo = tmp.repo();
    let port = free_port();
    git(&repo, &["init", "-q"]);
    fs::write(repo.join(".gitignore"), ".symveil/\n").unwrap();
    fs::create_dir_all(repo.join(".symveil")).unwrap();
    let vault = repo.join(".symveil/vault.json");
    fs::write(&vault, "VAULTBODYZZZ").unwrap();
    set_mode(&vault, 0o600);
    let learned = repo.join("learned.toml");
    fs::write(&learned, "[names]\nterms = [\"Tundrahorn\"]\n").unwrap();
    set_mode(&learned, 0o600);
    write_config(
        &repo,
        &with_learned(&clean_body(port), &repo.join("learned.toml")),
    );
    let out = run(
        &tmp.home(),
        &[
            "check",
            "--strict",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}\n{}", out.stderr, out.stdout);
    assert_both_hidden(&out);
    let value: Value = serde_json::from_str(&out.stdout).unwrap();
    let found = codes(&value);
    assert!(found.contains(&"config_git".to_string()), "{found:?}");
    assert!(found.contains(&"learned_git".to_string()), "{found:?}");
    assert!(!found.contains(&"vault_git".to_string()), "{found:?}");
    assert!(out.stdout.contains("would be committed"));

    git(&repo, &["add", ".symveil.toml"]);
    let tracked = run(&tmp.home(), &["check", "--repo", repo.to_str().unwrap()]);
    assert!(tracked.stdout.contains("tracked by git"));
    assert!(tracked.stdout.contains("[config_git]"));
    assert_both_hidden(&tracked);
}

#[test]
fn env_learned_path_counts_as_configured() {
    let tmp = Temp::new("envlearned");
    let repo = tmp.repo();
    let port = free_port();
    write_config(&repo, &clean_body(port));
    let missing = repo.join("from-env.toml");
    let output = command(&tmp.home())
        .env("SYMVEIL_LEARNED", &missing)
        .args(["check", "--strict", "--repo", repo.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2), "{stderr}\n{stdout}");
    assert!(stdout.contains("[learned_missing]"), "{stdout}");
    assert_hidden(&stdout);
    assert_hidden(&stderr);
}

#[test]
fn sample_counts_categories_and_reveal_is_local_only() {
    let tmp = Temp::new("sample");
    let repo = tmp.repo();
    let home = tmp.home();
    let port = free_port();
    let learned = home.join("learned.toml");
    fs::write(&learned, "[names]\nterms = [\"Tundrahorn\"]\n").unwrap();
    set_mode(&learned, 0o600);
    write_config(&repo, &with_learned(&clean_body(port), &learned));
    let sample = repo.join("sample.txt");
    fs::write(
        &sample,
        "zebrafinch AKIAIOSFODNN7EXAMPLE\nExempla\nRen Testdotter\nada@example.com\ndb.box.example\n",
    )
    .unwrap();
    let hidden = run(
        &home,
        &[
            "check",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
            "--sample",
            sample.to_str().unwrap(),
        ],
    );
    assert!(
        hidden.status.success(),
        "{}\n{}",
        hidden.stderr,
        hidden.stdout
    );
    assert_both_hidden(&hidden);
    assert!(!hidden.stdout.contains("@@sv:"));
    let value: Value = serde_json::from_str(&hidden.stdout).unwrap();
    assert_eq!(value["sample"]["reveal"], false);
    assert_eq!(value["sample"]["local_only"], false);
    assert!(value["sample"].get("values").is_none(), "{value}");
    assert!(value["sample"]["replacements"]["secret"].as_u64().unwrap() >= 1);
    assert!(
        value["sample"]["replacements"]["codename"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(value["sample"]["replacements"]["pii"].as_u64().unwrap() >= 1);
    assert!(
        value["sample"]["replacements"]["hostname"]
            .as_u64()
            .unwrap()
            >= 1
    );

    let shown = run(
        &home,
        &[
            "check",
            "--json",
            "--reveal",
            "--repo",
            repo.to_str().unwrap(),
            "--sample",
            sample.to_str().unwrap(),
        ],
    );
    assert!(shown.status.success(), "{}\n{}", shown.stderr, shown.stdout);
    assert!(shown.stdout.contains("LOCAL ONLY"));
    assert!(shown.stdout.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(shown.stdout.contains("Exempla"));
    assert!(shown.stdout.contains("@@sv:"));
    assert_hidden_except(
        &shown.stdout,
        &[
            "Exempla",
            "Testdotter",
            "AKIA",
            "ada@example.com",
            "db.box.example",
        ],
    );
    assert!(!shown.stdout.contains("zebrafinch"), "{}", shown.stdout);
    assert!(!shown.stdout.contains("Tundrahorn"), "{}", shown.stdout);
    assert_hidden(&shown.stderr);
    let revealed: Value = serde_json::from_str(&shown.stdout).unwrap();
    assert_eq!(revealed["sample"]["local_only"], true);
    assert!(revealed["sample"]["notice"]
        .as_str()
        .unwrap()
        .contains("LOCAL ONLY"));
}

#[test]
fn sample_stdin_counts_without_printing_the_input() {
    let tmp = Temp::new("stdin");
    let repo = tmp.repo();
    let port = free_port();
    write_config(&repo, &clean_body(port));
    let mut child = command(&tmp.home())
        .args(["check", "--repo", repo.to_str().unwrap(), "--sample", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"zebrafinch AKIAIOSFODNN7EXAMPLE Exempla\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(stdout.contains("secret="), "{stdout}");
    assert_hidden(&stdout);
    assert_hidden(&stderr);
    assert!(!stdout.contains("@@sv:"));
}

#[test]
fn busy_port_is_reported_and_not_a_warning() {
    let tmp = Temp::new("port");
    let repo = tmp.repo();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    write_config(&repo, &clean_body(port));
    let out = run(
        &tmp.home(),
        &[
            "check",
            "--strict",
            "--json",
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}\n{}", out.stderr, out.stdout);
    let value: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(value["port_free"], false);
    assert!(value["warnings"].as_array().unwrap().is_empty(), "{value}");
    drop(listener);
}

#[test]
fn missing_repo_and_bad_toml_exit_one() {
    let tmp = Temp::new("bad");
    let missing = tmp.path.join("nope");
    let gone = run(&tmp.home(), &["check", "--repo", missing.to_str().unwrap()]);
    assert_eq!(gone.status.code(), Some(1));
    assert!(gone.stderr.contains("symveil:"), "{}", gone.stderr);

    let repo = tmp.repo();
    write_config(&repo, "this is not [ toml");
    let bad = run(&tmp.home(), &["check", "--repo", repo.to_str().unwrap()]);
    assert_eq!(bad.status.code(), Some(1), "{}", bad.stdout);
    assert!(bad.stderr.contains("symveil:"), "{}", bad.stderr);
    assert_both_hidden(&bad);
}

#[test]
fn proxy_check_and_dry_run_print_the_summary_and_do_not_listen() {
    let tmp = Temp::new("dry");
    let repo = tmp.repo();
    let port = free_port();
    write_config(&repo, &clean_body(port));
    for flag in ["--check", "--dry-run"] {
        let out = run(
            &tmp.home(),
            &[
                "proxy",
                flag,
                "--repo",
                repo.to_str().unwrap(),
                "--port",
                "9",
                "--openai-base",
                "http://upstream.invalid",
            ],
        );
        assert!(
            out.status.success(),
            "{flag} {}\n{}",
            out.stderr,
            out.stdout
        );
        assert!(
            out.stdout.contains("symveil check"),
            "{flag}\n{}",
            out.stdout
        );
        assert!(out.stdout.contains("terms=1"), "{flag}\n{}", out.stdout);
        assert!(
            out.stdout.contains("[upstream_openai]"),
            "{flag}\n{}",
            out.stdout
        );
        assert!(out.stdout.contains(":9 "), "{flag}\n{}", out.stdout);
        assert_both_hidden(&out);
        assert!(!repo.join(".symveil/vault.json").exists());
    }
}

#[test]
fn proxy_startup_prints_a_short_summary_without_terms() {
    let tmp = Temp::new("start");
    let repo = tmp.repo();
    let port = free_port();
    let learned = tmp.home().join("learned.toml");
    fs::write(&learned, "[names]\nterms = [\"Tundrahorn\"]\n").unwrap();
    set_mode(&learned, 0o600);
    write_config(&repo, &with_learned(&clean_body(port), &learned));

    let mut child = command(&tmp.home())
        .env("SYMVEIL_TEST_FILE_KEY", "1")
        .args(["proxy", "--repo", repo.to_str().unwrap(), "--port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    let log_thread = Arc::clone(&log);
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            log_thread.lock().unwrap().push_str(&line);
            log_thread.lock().unwrap().push('\n');
        }
    });
    thread::spawn(move || {
        let _ = std::io::read_to_string(stdout);
    });
    let guard = ChildGuard(Some(child));
    let deadline = Instant::now() + Duration::from_secs(20);
    let text = loop {
        let current = log.lock().unwrap().clone();
        if current.contains("listening on") && current.contains("terms=2") {
            break current;
        }
        if Instant::now() >= deadline {
            panic!("proxy did not print the summary\n{current}");
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(guard);
    assert!(text.contains("binaries    block"), "{text}");
    assert!(text.contains("email=on"), "{text}");
    assert!(text.contains("loaded=yes"), "{text}");
    assert!(text.contains(".symveil.toml"), "{text}");
    assert_hidden(&text);
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

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-c")
        .arg("safe.directory=*")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", dir)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} in {}", dir.display());
}
