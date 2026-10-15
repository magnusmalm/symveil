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
