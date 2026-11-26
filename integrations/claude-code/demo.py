#!/usr/bin/env python3
"""Scripted demo for the Claude Code hook prototype.

Runs `symveil detect` and the hook script against sample prompts. Exits
non-zero when a matched value appears in output or a decision is wrong.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOOK = ROOT / "hooks" / "symveil_hook.py"
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"
EXAMPLE_PASSWORD = "example-secret-value"
EXAMPLE_HOST = "cache.internal"
EXAMPLE_IP = "192.0.2.1"
LEAKS = (EXAMPLE_KEY, EXAMPLE_PASSWORD, EXAMPLE_HOST, EXAMPLE_IP)


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path != "/health":
            self.send_response(404)
            self.end_headers()
            return
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    binary = os.environ.get("SYMVEIL_BIN", "").strip()
    if not binary:
        raise SystemExit("SYMVEIL_BIN is not set")
    if not Path(binary).is_file():
        raise SystemExit(f"SYMVEIL_BIN is not a file: {binary}")

    server = HTTPServer(("127.0.0.1", 0), HealthHandler)
    host, port = server.server_address
    proxy = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="symveil-hook-") as repo:
            run_demo(binary, repo, proxy)
    finally:
        server.shutdown()
    print("claude-code hook demo ok")


def run_demo(binary: str, repo: str, proxy: str) -> None:
    check_static_files()
    check_detect(binary, repo)
    check_hook(binary, repo, proxy)


def check_static_files() -> None:
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
    settings = json.loads((ROOT / "project.settings.json").read_text())
    if plugin.get("name") != "symveil":
        raise SystemExit("plugin name")
    if market.get("name") != "symveil-local":
        raise SystemExit("marketplace name")
    if market["plugins"][0]["source"] != "./":
        raise SystemExit("marketplace source")
    events = hooks["hooks"]
    if "SessionStart" not in events or "UserPromptSubmit" not in events:
        raise SystemExit("hook events")
    env = settings["env"]
    if env.get("ANTHROPIC_BASE_URL") != "http://127.0.0.1:8787":
        raise SystemExit("project settings base url")
    if env.get("SYMVEIL_HOOK_MODE") != "warn":
        raise SystemExit("project settings mode")
    if "env" in plugin:
        raise SystemExit("plugin manifest must not set env")


def check_detect(binary: str, repo: str) -> None:
    vault = Path(repo) / ".symveil" / "vault.json"
    vault.parent.mkdir()
    original = b'{"version":1,"entries":[]}\n'
    vault.write_bytes(original)

    clean = run_detect(binary, repo, "Explain the example module.\n")
    if clean["report"]["hits"] != []:
        raise SystemExit(f"clean prompt reported hits: {clean['report']}")

    sample = sample_prompt()
    found = run_detect(binary, repo, sample)
    rules = {(hit["rule"], hit["category"]) for hit in found["report"]["hits"]}
    expected = {
        ("aws-access-key-id", "secret"),
        ("generic-api-key", "secret"),
        ("internal-hostname", "hostname"),
        ("ipv4", "ip"),
    }
    if rules != expected:
        raise SystemExit(f"detect rules {rules} != {expected}")
    assert_clean(found["stdout"])
    assert_clean(found["stderr"])
    if vault.read_bytes() != original:
        raise SystemExit("detect wrote the vault")
    if any(path.name != "vault.json" for path in vault.parent.iterdir()):
        raise SystemExit("detect created extra vault files")

    as_json = json.dumps({"note": EXAMPLE_KEY})
    parsed = run_detect(binary, repo, as_json)
    parsed_rules = {hit["rule"] for hit in parsed["report"]["hits"]}
    if "aws-access-key-id" not in parsed_rules:
        raise SystemExit(f"json detect missed the key: {parsed['report']}")
    assert_clean(parsed["stdout"])


def check_hook(binary: str, repo: str, proxy: str) -> None:
    prompt = sample_prompt()
    event = {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "demo",
        "cwd": repo,
        "prompt": prompt,
    }
    clean_event = {**event, "prompt": "Explain the example module."}

    off = run_hook(event, env_for(binary, proxy, mode="off"))
    if off is not None:
        raise SystemExit(f"off mode printed {off}")

    warned = require_object(run_hook(event, env_for(binary, proxy, mode="warn")))
    if "decision" in warned:
        raise SystemExit("warn mode blocked")
    message = warned.get("systemMessage", "")
    for rule in ("aws-access-key-id", "generic-api-key", "internal-hostname", "ipv4"):
        if rule not in message:
            raise SystemExit(f"warn mode missed {rule}: {message}")
    if "did not change the prompt" not in message:
        raise SystemExit(message)

    quiet = run_hook(clean_event, env_for(binary, proxy, mode="warn"))
    if quiet is not None:
        raise SystemExit(f"clean warn printed {quiet}")

    blocked = require_object(run_hook(event, env_for(binary, proxy, mode="block")))
    if blocked.get("decision") != "block":
        raise SystemExit(blocked)
    if blocked["hookSpecificOutput"].get("suppressOriginalPrompt") is not True:
        raise SystemExit(blocked)
    if EXAMPLE_KEY in blocked["reason"]:
        raise SystemExit("block reason contained matched text")

    asked = require_object(run_hook(event, env_for(binary, proxy, mode="ask")))
    if asked.get("decision") != "block" or "SYMVEIL_HOOK_CONFIRM" not in asked["reason"]:
        raise SystemExit(asked)

    allowed = require_object(
        run_hook(event, env_for(binary, proxy, mode="ask", confirm="1"))
    )
    if "decision" in allowed:
        raise SystemExit(allowed)
    if "allowing the prompt" not in allowed["systemMessage"]:
        raise SystemExit(allowed)

    unknown = require_object(run_hook(event, env_for(binary, proxy, mode="sometimes")))
    if "decision" in unknown or "unrecognized" not in unknown["systemMessage"]:
        raise SystemExit(unknown)

    missing = require_object(
        run_hook(event, env_for(binary, proxy, mode="block", binary_path=""))
    )
    if missing.get("decision") != "block" or "could not run" not in missing["reason"]:
        raise SystemExit(missing)

    down = require_object(
        run_hook(
            session_event(repo),
            env_for(binary, "http://127.0.0.1:9", mode="warn"),
        )
    )
    if "not responding" not in down["systemMessage"] or "ANTHROPIC_BASE_URL is unset" not in down["systemMessage"]:
        raise SystemExit(down)

    ready = run_hook(
        session_event(repo),
        env_for(binary, proxy, mode="warn", base=proxy),
    )
    if ready is not None:
        raise SystemExit(f"healthy session printed {ready}")

    suffix = require_object(
        run_hook(
            session_event(repo),
            env_for(binary, proxy, mode="warn", base=proxy + "/v1"),
        )
    )
    if "/v1" not in suffix["systemMessage"]:
        raise SystemExit(suffix)

    vault = Path(repo) / ".symveil" / "vault.json"
    before = vault.read_bytes()
    run_hook(event, env_for(binary, proxy, mode="warn"))
    if vault.read_bytes() != before:
        raise SystemExit("hook rewrote the vault")


def sample_prompt() -> str:
    return (
        f"export AWS_ACCESS_KEY_ID={EXAMPLE_KEY}\n"
        f'password = "{EXAMPLE_PASSWORD}"\n'
        f"connect to {EXAMPLE_HOST} at {EXAMPLE_IP}\n"
    )


def session_event(repo: str) -> dict[str, str]:
    return {
        "hook_event_name": "SessionStart",
        "session_id": "demo",
        "cwd": repo,
        "source": "startup",
    }


def env_for(
    binary: str,
    proxy: str,
    mode: str,
    base: str | None = None,
    confirm: str | None = None,
    binary_path: str | None = None,
) -> dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/tmp"),
        "SYMVEIL_PROXY_URL": proxy,
        "SYMVEIL_HOOK_MODE": mode,
    }
    chosen = binary if binary_path is None else binary_path
    if chosen:
        env["SYMVEIL_BIN"] = chosen
    if base is not None:
        env["ANTHROPIC_BASE_URL"] = base
    if confirm is not None:
        env["SYMVEIL_HOOK_CONFIRM"] = confirm
    return env


def run_detect(binary: str, repo: str, text: str) -> dict[str, object]:
    completed = subprocess.run(
        [binary, "detect", "--repo", repo],
        input=text,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"detect failed: {completed.stderr}")
    assert_clean(completed.stdout)
    assert_clean(completed.stderr)
    return {
        "report": json.loads(completed.stdout),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run_hook(event: dict[str, str], env: dict[str, str]) -> dict[str, object] | None:
    completed = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(event),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert_clean(completed.stdout)
    assert_clean(completed.stderr)
    if completed.returncode != 0:
        raise SystemExit(f"hook exit {completed.returncode}: {completed.stderr}")
    if not completed.stdout.strip():
        return None
    body = json.loads(completed.stdout)
    if not isinstance(body, dict):
        raise SystemExit(body)
    blob = json.dumps(body)
    assert_clean(blob)
    return body


def require_object(body: dict[str, object] | None) -> dict[str, object]:
    if body is None:
        raise SystemExit("hook printed nothing")
    return body


def assert_clean(text: str) -> None:
    for leak in LEAKS:
        if leak in text:
            raise SystemExit("output contained matched text")


if __name__ == "__main__":
    main()
