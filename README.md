# SymVeil

Local redaction proxy so cloud coding agents never see your secrets.

![demo](assets/demo.gif)

SymVeil is a local proxy that sits between a coding agent and a cloud model. This tree is the free tier: it masks secrets before a request leaves the machine and restores them in the response, including streamed server-sent events.

The vault and the audit log stay on the machine. Upstream sees placeholders of the form `@@sv:0123abcd@@` instead of the secret.

The free tier masks secrets. Pro identifier and code-name masking is at [symveil.dev](https://symveil.dev).

## What it masks

Builtin rules, always on:

- AWS access key ids
- GitHub PATs (classic and fine-grained)
- Slack tokens
- Google API keys
- Stripe live secrets
- PEM private keys
- `api_key`, `secret`, `token`, and `password` assignments

It also masks IPv4 and IPv6 addresses (keeping `127.0.0.1`, `0.0.0.0`, `255.255.255.255`, and `::1`) and hostnames under the configured internal domains. Add your own secret rules under `[[redact.secrets]]`.

An allow entry does not exempt a secret.

## Quickstart

```bash
cargo build --release
```

The binary is `target/release/symveil`.

Mask a secret on stdin:

```bash
printf '%s\n' 'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' \
  | ./target/release/symveil redact --repo .
```

`redact` writes the masked text to stdout and a count to stderr. `restore` reverses a placeholder stream. The proxy is what an agent should use.

Run the proxy:

```bash
./target/release/symveil proxy --port 8787 --openai-base https://api.openai.com
```

This listens on `127.0.0.1` only. Point a client at it:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

`ANTHROPIC_BASE_URL` has no `/v1` suffix; the Anthropic SDK appends `/v1/messages` itself. OpenAI-compatible clients, including Chat Completions and the Responses API, use the `/v1` base. The `Authorization` and `x-api-key` headers are forwarded and are not logged.

| Client path | Upstream |
| --- | --- |
| `POST /v1/messages` | `https://api.anthropic.com` |
| `POST /v1/chat/completions`, `POST /v1/responses`, other `/v1/*` | `https://api.openai.com` |

Override the upstream origin with `--openai-base` or `--anthropic-base` (no trailing `/v1`). `GET /health` returns `{"status":"ok"}`.

## Grok Build

Checked with Grok Build 1.0.52 (`grok`) and a local mock upstream that recorded every request and returned a streaming reply, including a `run_terminal_command` tool call. Testing was against that mock. It was not run against `https://api.x.ai`.

> **Session titles call xAI directly unless you reroute them.** Grok Build's session-title generation calls `https://cli-chat-proxy.grok.com` directly (observed with `grok-4.6` on `POST /v1/responses`). That request ignores the custom `base_url` and bypasses SymVeil, so the start of the prompt may reach xAI unredacted. With a stand-in key the call returned 401 and still left the machine.
>
> No setting was found that disables this first title call. `features.title_refresh` and `GROK_TITLE_REFRESH` control a later refresh of an existing title. The docs and the 1.0.52 source (`models.session_summary`, env `GROK_SESSION_SUMMARY_MODEL`) select the model used for the title. Point that at the SymVeil custom model, as in the `config.toml` example. With `session_summary` set to that model, the mock recorded the title `POST /v1/responses` on the SymVeil base as `grok-4.7`, the secret in that body was already an `@@sv:…@@` placeholder, and grok made no request to `cli-chat-proxy.grok.com`.

**Known limitation.** When a tool-argument stream splits one `@@sv:…@@` placeholder across two JSON fragments, Grok may concatenate it unrestored. A placeholder split only by HTTP chunk boundaries, inside one JSON value, was restored. On the Responses path the completed event carried the arguments in one piece, and those were restored.

`responses` and `chat_completions` follow `--openai-base`. `messages` follows `--anthropic-base`. `GET /v1/models` follows `--openai-base`. Origins have no trailing `/v1`. The check pointed the two flags at two different mocks so the routes stayed distinct. Grok 4.7 used the Responses API.

```bash
./target/release/symveil proxy --port 8787 \
  --openai-base https://api.x.ai \
  --anthropic-base https://api.x.ai
```

`https://api.x.ai` is the origin for the real Responses API. The `messages` route was checked against the mock only.

`~/.grok/config.toml` for the three backends that completed a turn through the proxy:

```toml
[models]
default = "symveil-grok"
# Reroute session-title generation through this model. Without it, grok calls
# https://cli-chat-proxy.grok.com directly and the start of the prompt is not redacted.
session_summary = "symveil-grok"

[model.symveil-grok]
model = "grok-4.7"
base_url = "http://127.0.0.1:8787/v1"
name = "Grok 4.7 via SymVeil"
env_key = "XAI_API_KEY"
api_backend = "responses"
context_window = 128000
supports_backend_search = false

[model.symveil-chat]
model = "grok-4.7-chat"
base_url = "http://127.0.0.1:8787/v1"
env_key = "XAI_API_KEY"
api_backend = "chat_completions"
context_window = 128000

[model.symveil-messages]
model = "messages-via-symveil"
base_url = "http://127.0.0.1:8787/v1"
env_key = "XAI_API_KEY"
api_backend = "messages"
context_window = 128000
extra_headers = { "anthropic-version" = "2023-06-01" }
```

```bash
export XAI_API_KEY=...
grok -p "Explain this repo." -m symveil-grok
```

Grok requires `XAI_API_KEY` for that model list and for API-key inference. The check used a stand-in key. The mock received `Authorization: Bearer` on all three backends, and `anthropic-version: 2023-06-01` on `messages`.

Two environment variables were checked on their own, without relying on the custom `base_url`:

```bash
export GROK_XAI_API_BASE_URL=http://127.0.0.1:8787/v1
grok -p "Explain this repo." -m grok-4.7
```

That sent `POST /v1/responses` for `grok-4.7` through SymVeil, and fetched `GET /v1/models` from the same base. `GROK_MODELS_BASE_URL=http://127.0.0.1:8787/v1` made `grok models` read `{base}/models` through SymVeil. The command listed the mock entries (`grok-4.7`, `mock-chat`) and the custom models from `config.toml`. The list body is the upstream JSON.

On the recorded requests, the AWS example key, a `password = "…"` assignment, `db.payments.corp`, and `10.8.8.8` arrived as `@@sv:…@@` placeholders. After Grok ran the restored tool and read a file, the GitHub PAT in that file was a placeholder on the next request. The code identifier `aurora_rcc_enable_pll` was still in the body. This build masks secrets, addresses, and internal hostnames. The local audit log omits secret values and stores the original IP and hostname. It does not store the API key.

Streamed text and tool-call arguments came back with the AWS key restored. Grok ran `run_terminal_command`, and the shell printed that key.

Server-side tools (web search, code interpreter, and the other hosted Responses tools) were not part of the run: web search was disabled, and `supports_backend_search` was false. Those tools run on xAI when the real API is used.

## Configuration

`.symveil.toml` is read from the working repository, or the nearest file above it.

```toml
[proxy]
listen = "127.0.0.1"
port = 8787
openai_base = "https://api.openai.com"
anthropic_base = "https://api.anthropic.com"
timeout_secs = 900
audit_log = ".symveil/audit.jsonl"
vault = ".symveil/vault.json"

[redact]
internal_domains = ["corp", "internal", "lan"]

[[redact.secrets]]
name = "acme-factory-token"
regex = '\bacme_live_[A-Za-z0-9]{16,}\b'
```

`.symveil/` is gitignored. The vault is the reverse map, including secrets. Do not copy it off the machine.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

Apache-2.0. See [LICENSE](LICENSE).
