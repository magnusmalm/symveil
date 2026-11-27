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
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("src")).unwrap();
    fs::write(
        tree.join("src/fan.rs"),
        "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\nfn tundrahorn_fan_init() {}\n",
    )
    .unwrap();
    let output = command(&root.join("home"))
        .args(["learn", "--report", "--full", tree.to_str().unwrap()])
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
        .write_all(b"Exempla\nperson Ren Testdotter\n\nquit\n")
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

#[test]
fn quiet_suppresses_progress_and_a_pipe_does_not_print_secrets() {
    let root = temp_dir("progress");
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("src")).unwrap();
    fs::write(
        tree.join("src/fan.rs"),
        "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\nfn tundrahorn_fan_init() {}\n",
    )
    .unwrap();
    let quiet = command(&root.join("home"))
        .args(["learn", "--quiet", "--report", tree.to_str().unwrap()])
        .output()
        .unwrap();
    let quiet_err = String::from_utf8(quiet.stderr).unwrap();
    assert!(quiet.status.success(), "{quiet_err}");
    assert!(
        !quiet_err.contains("symveil learn:"),
        "quiet printed progress: {quiet_err}"
    );
    let shown = command(&root.join("home"))
        .args(["learn", "--report", tree.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(shown.stderr).unwrap();
    assert!(shown.status.success(), "{stderr}");
    assert!(
        stderr.contains("symveil learn:"),
        "expected a progress line: {stderr}"
    );
    assert!(
        !stderr.contains("AKIAIOSFODNN7EXAMPLE"),
        "progress printed a secret: {stderr}"
    );
    let both = command(&root.join("home"))
        .args([
            "learn",
            "--quiet",
            "--progress",
            "--report",
            tree.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!both.status.success());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn exclude_glob_skips_a_bsp_directory() {
    let root = temp_dir("exclude");
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("bsp/kernel")).unwrap();
    fs::write(
        tree.join("bsp/kernel/board.c"),
        "int tundrahorn_board_init(void) { return 0; }\n",
    )
    .unwrap();
    fs::write(tree.join("keep.rs"), "fn exempla_keep() {}\n").unwrap();
    let output = command(&root.join("home"))
        .args([
            "learn",
            "--quiet",
            "--report",
            "--exclude",
            "bsp/**",
            "--full",
            tree.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(stdout.contains("exempla_keep"), "{stdout}");
    assert!(!stdout.contains("tundrahorn_board_init"), "{stdout}");
    assert!(stdout.contains("skipped by --exclude"), "{stdout}");
    let _ = fs::remove_dir_all(&root);
}

fn secret_tree(root: &std::path::Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/fan.rs"),
        "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\nfn tundrahorn_fan_init() {}\n",
    )
    .unwrap();
}

#[test]
fn report_summary_writes_a_private_file_and_masks_values() {
    let root = temp_dir("summary");
    let tree = root.join("tree");
    let home = root.join("home");
    secret_tree(&tree);
    let output = command(&home)
        .args(["learn", "--quiet", "--report", tree.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    let report = home.join(".config/symveil/learn-report.txt");
    assert!(stdout.contains("candidates "), "{stdout}");
    assert!(stdout.contains("\nsecret "), "{stdout}");
    assert!(stdout.contains("files "), "{stdout}");
    assert!(stdout.contains("skipped_dir "), "{stdout}");
    assert!(
        stdout.contains(&format!("full report: {}", report.display())),
        "{stdout}"
    );
    assert!(
        !stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "summary printed a secret: {stdout}"
    );
    assert!(
        !stdout.contains("len=20"),
        "summary listed a masked value: {stdout}"
    );
    assert!(
        !stdout.contains("offline, read-only"),
        "summary printed the full report: {stdout}"
    );
    let file = fs::read_to_string(&report).unwrap();
    assert!(file.contains("offline, read-only"), "{file}");
    assert!(file.contains("len=20"), "{file}");
    assert!(
        !file.contains("AKIAIOSFODNN7EXAMPLE"),
        "report file printed a full secret: {file}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&report).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn report_file_sits_beside_out() {
    let base = temp_dir("beside");
    let tree = base.join("tree");
    let home = base.join("home");
    secret_tree(&tree);
    let out = base.join("learned.toml");
    let report = base.join("learn-report.txt");
    let output = command(&home)
        .args([
            "learn",
            "--quiet",
            "--report",
            "--out",
            out.to_str().unwrap(),
            tree.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(report.is_file(), "missing {}", report.display());
    assert!(!out.exists(), "report mode wrote learned.toml");
    assert!(
        stdout.contains(&format!("full report: {}", report.display())),
        "{stdout}"
    );
    assert!(!stdout.contains("AKIAIOSFODNN7EXAMPLE"), "{stdout}");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn full_report_on_stdout_matches_the_file() {
    let root = temp_dir("full");
    let tree = root.join("tree");
    let home = root.join("home");
    secret_tree(&tree);
    let report = home.join("learn-report.txt");
    let output = command(&home)
        .args([
            "learn",
            "--quiet",
            "--report",
            "--full",
            "--report-file",
            report.to_str().unwrap(),
            tree.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    let file = fs::read_to_string(&report).unwrap();
    assert_eq!(stdout, file);
    assert!(stdout.starts_with("symveil learn report\n"), "{stdout}");
    assert!(
        stdout.contains(
            "offline, read-only. no model, no network. secrets are masked unless --reveal."
        ),
        "{stdout}"
    );
    assert!(stdout.contains("len=20"), "{stdout}");
    assert!(!stdout.contains("AKIAIOSFODNN7EXAMPLE"), "{stdout}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&report).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }
    let alias = command(&home)
        .args([
            "learn",
            "--quiet",
            "--report",
            "--report-full",
            "--report-file",
            report.to_str().unwrap(),
            tree.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let alias_out = String::from_utf8(alias.stdout).unwrap();
    assert!(
        alias.status.success(),
        "{}",
        String::from_utf8_lossy(&alias.stderr)
    );
    assert_eq!(alias_out, file);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn reveal_writes_the_secret_only_in_the_report_file() {
    let root = temp_dir("reveal");
    let tree = root.join("tree");
    let home = root.join("home");
    secret_tree(&tree);
    let report = home.join("learn-report.txt");
    let output = command(&home)
        .args([
            "learn",
            "--quiet",
            "--report",
            "--reveal",
            "--report-file",
            report.to_str().unwrap(),
            tree.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(
        !stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "summary printed a secret: {stdout}"
    );
    let file = fs::read_to_string(&report).unwrap();
    assert!(
        file.contains("AKIAIOSFODNN7EXAMPLE"),
        "reveal did not write the secret into the report file"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn report_file_inside_the_tree_is_refused() {
    let root = temp_dir("inside");
    let home = root.join("home");
    secret_tree(&root);
    let inside = root.join("learn-report.txt");
    let output = command(&home)
        .args([
            "learn",
            "--quiet",
            "--report",
            "--report-file",
            inside.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("inside the scanned tree"), "{stderr}");
    assert!(!inside.exists());
    let _ = fs::remove_dir_all(&root);
}
