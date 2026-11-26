#!/usr/bin/env python3
"""Claude Code command hook for the SymVeil prototype.

SessionStart reports when the local proxy is down or ANTHROPIC_BASE_URL in
this process does not name it. UserPromptSubmit runs `symveil detect` and
warns or blocks. The hook never rewrites the prompt and never prints matched
text.

SYMVEIL_HOOK_MODE: off (default), warn, ask, or block.
SYMVEIL_HOOK_CONFIRM=1 lets ask mode allow the prompt for this process.
"""

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

DEFAULT_PROXY = "http://127.0.0.1:8787"
MODES = ("off", "warn", "ask", "block")
CONFIRM_VALUES = {"1", "true", "yes", "on"}


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        emit(warn_body("SymVeil ignored a hook event it could not parse."))
        return 0
    if not isinstance(event, dict):
        emit(warn_body("SymVeil ignored a hook event that was not a JSON object."))
        return 0

    name = event.get("hook_event_name")
    if name == "SessionStart":
        emit_session()
        return 0
    if name == "UserPromptSubmit":
        prompt = event.get("prompt") if isinstance(event.get("prompt"), str) else ""
        cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else ""
        emit_prompt(prompt, cwd)
        return 0
    return 0


def emit_session() -> None:
    notes = session_notes()
    if notes:
        emit(warn_body(" ".join(notes)))


def emit_prompt(prompt: str, cwd: str) -> None:
    mode = hook_mode()
    if mode is None:
        emit(warn_body("SymVeil ignored an unrecognized SYMVEIL_HOOK_MODE and left the prompt unchanged."))
        return
    if mode == "off" or prompt == "":
        return

    try:
        report = detect(prompt, cwd)
    except DetectError:
        message = "SymVeil could not run local detection, so this prompt was not scanned."
        if mode in ("ask", "block"):
            emit(block_body(message))
        else:
            emit(warn_body(message))
        return

    hits = report.get("hits")
    if not isinstance(hits, list) or not hits:
        return

    summary = hit_summary(hits)
    if summary is None:
        message = "SymVeil could not read the detection report, so this prompt was not described."
        if mode in ("ask", "block"):
            emit(block_body(message))
        else:
            emit(warn_body(message))
        return

    routing = routing_note()
    if mode == "warn":
        emit(
            warn_body(
                f"SymVeil matched {summary}. The hook did not change the prompt. {routing}"
            )
        )
        return
    if mode == "ask" and confirmed():
        emit(
            warn_body(
                f"SymVeil matched {summary}. SYMVEIL_HOOK_CONFIRM is set for this process, "
                f"so ask mode is allowing the prompt. The hook did not change it. {routing}"
            )
        )
        return

    reason = (
        f"SymVeil matched {summary}. The prompt was not sent. {routing} "
        "UserPromptSubmit cannot rewrite the prompt or show a yes/no dialog."
    )
    if mode == "ask":
        reason += " Set SYMVEIL_HOOK_CONFIRM=1 and submit again to allow prompts while that variable stays set."
    emit(block_body(reason))


def session_notes() -> list[str]:
    proxy = proxy_url()
    notes: list[str] = []
    health = proxy_health(proxy)
    if health != "ok":
        notes.append(f"SymVeil proxy at {display_url(proxy)} is not responding on /health ({health}).")
    base = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    if not base:
        notes.append(
            "ANTHROPIC_BASE_URL is unset in this process. A plugin manifest cannot set it. "
            "Copy integrations/claude-code/project.settings.json into the project's "
            ".claude/settings.local.json env block, then restart Claude Code."
        )
    elif not same_origin(base, proxy):
        notes.append(
            f"ANTHROPIC_BASE_URL is {display_url(base)}, which is not the SymVeil proxy at {display_url(proxy)}."
        )
    elif not root_path(base):
        notes.append(
            f"ANTHROPIC_BASE_URL is {display_url(base)}. Use {display_url(proxy)} with no /v1 suffix; "
            "the Anthropic client appends /v1/messages itself."
        )
    return notes


def routing_note() -> str:
    proxy = proxy_url()
    base = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    if base and same_origin(base, proxy) and root_path(base):
        return (
            "This process has ANTHROPIC_BASE_URL pointed at the local proxy. "
            "The hook cannot see whether the next API call will use it."
        )
    return (
        "This process is not pointed at the local proxy, so a sent prompt can leave with the matched text. "
        "Set ANTHROPIC_BASE_URL in .claude/settings.local.json; the plugin cannot set it."
    )


def hook_mode() -> str | None:
    raw = os.environ.get("SYMVEIL_HOOK_MODE", "off").strip().lower()
    if raw in MODES:
        return raw
    return None


def confirmed() -> bool:
    return os.environ.get("SYMVEIL_HOOK_CONFIRM", "").strip().lower() in CONFIRM_VALUES


def proxy_url() -> str:
    raw = os.environ.get("SYMVEIL_PROXY_URL", DEFAULT_PROXY).strip()
    return raw or DEFAULT_PROXY


def hit_summary(hits: list[object]) -> str | None:
    parts: list[str] = []
    for hit in hits:
        if not isinstance(hit, dict):
            return None
        rule = hit.get("rule")
        category = hit.get("category")
        count = hit.get("count")
        if not isinstance(rule, str) or not isinstance(category, str) or not isinstance(count, int):
            return None
        if not rule or not category or count < 1:
            return None
        parts.append(f"{rule} ({category}) x{count}")
    if not parts:
        return None
    return ", ".join(parts)


class DetectError(Exception):
    pass


def detect(prompt: str, cwd: str) -> dict[str, object]:
    binary = os.environ.get("SYMVEIL_BIN", "").strip() or shutil.which("symveil")
    if not binary:
        raise DetectError
    repo = (
        os.environ.get("SYMVEIL_REPO", "").strip()
        or cwd.strip()
        or os.environ.get("CLAUDE_PROJECT_DIR", "").strip()
        or "."
    )
    try:
        completed = subprocess.run(
            [binary, "detect", "--repo", repo],
            input=prompt,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        raise DetectError from err
    if completed.returncode != 0:
        raise DetectError
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as err:
        raise DetectError from err
    if not isinstance(report, dict):
        raise DetectError
    return report


def proxy_health(proxy: str) -> str:
    url = proxy.rstrip("/") + "/health"
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            body = response.read(4096)
            status = response.status
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return "unreachable"
    if status != 200:
        return f"HTTP {status}"
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unexpected body"
    if isinstance(payload, dict) and payload.get("status") == "ok":
        return "ok"
    return "unexpected body"


def same_origin(left: str, right: str) -> bool:
    return origin(left) != "" and origin(left) == origin(right)


def root_path(url: str) -> bool:
    path = urlsplit(url.strip()).path
    return path in ("", "/")


def origin(url: str) -> str:
    parts = urlsplit(url.strip())
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        return ""
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{host.lower()}:{port}"


def display_url(url: str) -> str:
    parts = urlsplit(url.strip())
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        return "(unparsed)"
    netloc = host.lower()
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "", "", ""))


def warn_body(message: str) -> dict[str, object]:
    return {"systemMessage": message}


def block_body(message: str) -> dict[str, object]:
    return {
        "decision": "block",
        "reason": message,
        "systemMessage": message,
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "suppressOriginalPrompt": True,
        },
    }


def emit(body: dict[str, object]) -> None:
    json.dump(body, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    sys.exit(main())
