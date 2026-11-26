//! Drives the `symveil learn` binary. The child environment is cleared so a
//! proxy variable in this process cannot fail the offline gate.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use symveil::config::Config;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "symveil-learn-cli-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn command(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_symveil"));
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("HOME", home);
    cmd
}

#[test]
fn report_is_offline_and_masks_secret_values() {
    let root = temp_dir("report");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/fan.rs"),
        "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\nfn tundrahorn_fan_init() {}\n",
    )
    .unwrap();
    let output = command(&root.join("home"))
        .args(["learn", "--report", root.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(stdout.contains("offline"), "{stdout}");
    assert!(
        !stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "report printed a full secret: {stdout}"
    );
    assert!(
        stdout.contains("len=20"),
        "report should show a masked length: {stdout}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn refuses_when_a_model_base_url_is_set() {
    let root = temp_dir("refuse");
    let output = command(&root)
        .env("OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
        .args(["learn", "--report", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("refuses"), "{stderr}");
    assert!(stderr.contains("OPENAI_BASE_URL"), "{stderr}");
    assert!(!stderr.contains("127.0.0.1"), "{stderr}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn interactive_stdin_writes_a_private_file_the_proxy_loads() {
    let root = temp_dir("flow");
    let home = root.join("home");
    fs::create_dir_all(root.join("tree/src")).unwrap();
    fs::write(
        root.join("tree/src/fan.rs"),
        "fn tundrahorn_fan_init() {}\nconst KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\n",
    )
    .unwrap();
    let out = root.join("learned.toml");
    let mut child = command(&home)
        .args([
            "learn",
            "--out",
            out.to_str().unwrap(),
            root.join("tree").to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"Exempla\nRen Testdotter\n\nquit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(stdout.contains("added Exempla as name"), "{stdout}");
    assert!(
        !stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "interactive prompt printed a full secret: {stdout}"
    );
    let text = fs::read_to_string(&out).unwrap();
    assert!(text.contains("Exempla"), "{text}");
    assert!(text.contains("Ren Testdotter"), "{text}");
    assert!(!text.contains("[proxy]"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }
    let mut cfg = Config::parse("[redact]\ninternal_domains = []\n").unwrap();
    cfg.apply_learned_toml(&text).unwrap();
    assert!(cfg.redact.names.terms.iter().any(|term| term == "Exempla"));
    assert!(cfg
        .redact
        .names
        .people
        .iter()
        .any(|person| person == "Ren Testdotter"));
    let _ = fs::remove_dir_all(&root);
}
