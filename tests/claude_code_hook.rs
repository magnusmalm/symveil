use std::process::Command;

/// Runs the hook script the way a command hook would: JSON on stdin, JSON on stdout.
#[test]
fn claude_code_hook_demo() {
    let bin = env!("CARGO_BIN_EXE_symveil");
    let demo =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("integrations/claude-code/demo.py");
    let status = Command::new("python3")
        .arg(&demo)
        .env("SYMVEIL_BIN", bin)
        .status()
        .expect("run claude-code hook demo");
    assert!(status.success(), "claude-code hook demo failed");
}
