# Real-client check (Magnus's host only)

This harness does not run Claude Code or Grok Build. Those checks happen on a machine you control, against the **synthetic** corpus only. Do not point either client at a proprietary tree for this check. SymVeil is not a sandbox: the agent can still read files locally, and anything that does not go through the proxy is not redacted.

Generate the corpus with `make leak-test` (output under `target/leak-report/corpus-a`) or by running the harness's generator. The files are fake: company Exempla, product Tundrahorn. Open that directory as the workspace.

## 1. Mock upstream first

Start a recorder that stores every request body. The leak harness's mock is one implementation; any local HTTP server that writes the raw body to disk is enough. Bind it to `127.0.0.1`.

```bash
cargo build --release
./target/release/symveil proxy --port 8787 --repo /path/to/synthetic \
  --openai-base http://127.0.0.1:MOCK \
  --anthropic-base http://127.0.0.1:MOCK
```

Use a `.symveil.toml` in the synthetic repo with personal-data rules on if that is the configuration under test:

```toml
[redact]
mode = "enforce"
internal_domains = ["corp", "internal", "lan"]

[redact.pii]
email = true
phone = true
personnummer = true
```

Confirm the mock received the request and that planted secrets are `@@sv:…@@` placeholders. If the mock records **nothing**, the client bypassed SymVeil. That is a failed check, not a pass.

## 2. Claude Code

Set the base URL at the proxy and leave the Anthropic SDK path without a `/v1` suffix:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

Run Claude Code in the synthetic directory on your subscription. Ask it to read `configs/fan.env`, `firmware/tundrahorn_fan.c`, and `logs/boot.log`.

This repository was not run against Claude Code. Subscription traffic may ignore `ANTHROPIC_BASE_URL` and talk to another host. The mock is how you see that. Only after the mock shows redacted bodies should you restart the proxy with `--anthropic-base https://api.anthropic.com`, still on the synthetic repo, and repeat the same prompts. Do not switch the workspace to real source.

## 3. Grok Build

Grok Build can send a session-title request straight to `https://cli-chat-proxy.grok.com`, ignoring the custom base URL. Point `session_summary` at the SymVeil model or that call never hits the proxy. The README in this repo has the fuller note from the 1.0.52 check.

`~/.grok/config.toml`:

```toml
[models]
default = "symveil-grok"
session_summary = "symveil-grok"

[model.symveil-grok]
model = "grok-4.7"
base_url = "http://127.0.0.1:8787/v1"
name = "Grok 4.7 via SymVeil"
env_key = "XAI_API_KEY"
api_backend = "responses"
context_window = 128000
supports_backend_search = false
```

With the proxy still aimed at the mock:

```bash
export XAI_API_KEY=stand-in
grok -p "Read configs/fan.env and firmware/tundrahorn_fan.c" -m symveil-grok
```

Confirm the mock saw `POST /v1/responses`, the secret values were placeholders, and nothing in the capture went to `cli-chat-proxy.grok.com`. Then restart the proxy with `--openai-base https://api.x.ai` and `--anthropic-base https://api.x.ai` and repeat on the synthetic repo only.

Server-side tools (web search, code interpreter) run at the provider when a real API is used. They were not part of this harness.

## 4. What counts as a pass

A real-client pass is: the mock (and then the real upstream, if you capture it) shows no gated canary, placeholders restore in the tool output you see locally, and the title-bypass check above is clean. Company and code names will still be visible on this free build. That alone keeps the safe-for-work-code verdict at NOT SAFE until a build that actually masks them has three clean runs and this real-client pass.
