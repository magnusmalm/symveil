# SymVeil

Local redaction proxy so cloud coding agents never see your secrets.

![demo](assets/demo.gif)

SymVeil is a local proxy that sits between a coding agent and a cloud model. This tree is the free tier: it masks secrets before a request leaves the machine and restores them in the response, including streamed server-sent events.

The vault and the audit log stay on the machine. The vault file is encrypted; the key sits next to it. Upstream sees placeholders of the form `@@sv:0123abcd@@` instead of the secret.

The free tier masks secrets, and company, product, project, and person names listed in `[redact.names]`. The identifier index is the Pro plugin at [symveil.dev](https://symveil.dev).

## What it masks

Builtin rules, always on:

- AWS access key ids
- GitHub PATs (classic and fine-grained)
- Slack tokens (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-`) with a body of 10 to 256 characters
- Google API keys
- Stripe live secrets
- PEM private keys
- GitLab personal access tokens (`glpat-` plus 16 or more characters)
- Azure `AccountKey=` values
- Quoted `api_key`, `apikey`, `secret`, `token`, and `password` assignments (the value only), including a JSON object whose key is one of those words. The same walk scans JSON object keys and the decimal text of JSON numbers.
- `.env` assignments whose names are uppercase and end in `_KEY`, `_SECRET`, `_TOKEN`, `_PASSWORD`, or `_PASS`. A leading `export`, spaces around `=`, an optional quote before the name (a docker inspect `Env` entry), single or double quotes around the value, and a trailing `#` comment are recognized. An unquoted value may contain spaces and runs until that comment. Only the value is masked. A pytest `environ({...})` or Python dict with the same kind of name is masked the same way.
- A password glued to `-p` when it contains a digit, and a password after `--password` or `--pass`
- Two adjacent double-quoted string literals whose concatenation is a builtin secret (both literals are masked). A split that does not form a real token is left as written.
- OpenAI keys: `sk-` plus 48 alphanumeric characters, and `sk-proj-`, `sk-admin-`, and `sk-svcacct-` keys with a body of at least 32 characters
- Anthropic keys that start with `sk-ant-`
- JWTs with three base64url segments, with or without `=` padding, and a header starting with `eyJ`
- Standard and URL-safe base64 (16 characters or longer, padding optional) when the decoded text contains a builtin secret. Decoding stops after two layers and 64 KiB. A base64 blob of at least 32 characters is also masked when its plaintext is a single credential-like word, so an opaque secret that is not itself a token shape does not have to be sent through. `high_entropy` stays off and still does not mask a raw token that does not decode to text.
- The password in a URL with userinfo (`scheme://user:password@host`), including a password that contains `:`. The user and host stay.

Assignment and URL-password values shorter than 8 characters, all-numeric assignment values, and whole-value placeholders such as `changeme`, `password`, and `${VAR}` are left in place. A longer secret that merely contains one of those words is masked. `TOKEN_LIMIT=4096` is not treated as a secret name. A secret-shaped name mentioned mid-line is not an assignment. `sk-ant-` stays on the Anthropic rule.

It also masks IPv4 and IPv6 addresses (keeping `127.0.0.1`, `0.0.0.0`, `255.255.255.255`, and `::1`) and hostnames under the configured internal domains, including a label that contains `_`. An address has to stand on its own, so a Rust path such as `std::env` is left alone. Add your own secret rules under `[[redact.secrets]]`. The name has to be one you choose: a name that matches a builtin detector is rejected at startup.

`[redact.names]` masks a list of terms, person names, and project-code regexes. A term is matched case-insensitively, with `-`, `_`, or `.` between letters, and with a Swedish genitive `-s` or a common suffix (`-en`, `-et`, `-ar`, `-or`, `-er`, and the definite plurals). `Exempla` matches `EXEMPLA`, `exempla_`, `Exem-pla`, and `Exemplas`. It does not match `exempel`. A term needs at least three letters or digits, so `TDH` matches `TDH_FAN_MAX` and does not match inside an unrelated word. A regex such as `TDH-\d+` is used as written. `people = ["Ren Testdotter"]` matches `Ren Testdotter`, `REN TESTDOTTER`, `Testdotter, Ren`, and each of those tokens on a word boundary (`Hello Ren.`). It does not match `render`, `rental`, or `parent`. A person token shorter than three letters or digits is rejected. The placeholder restores to the exact matched text. Usernames and whole paths are not a separate rule: a path is masked only where a configured term or person token appears. The `deny` list and `patterns` list are still the identifier plugin's inputs and do nothing in this build.

Each rule has an action. `redact` is the default: the proxy replaces the match and restores it in the response. `warn` forwards the original, writes an audit entry, and logs a warning. `block` returns HTTP 400 and does not call upstream. A config that omits `action` keeps the `redact` behavior.

Set `high_entropy = true` under `[redact]` to also mask tokens of 32 to 4096 characters whose Shannon entropy is at least 4.5 bits per character. It is off by default. Hex strings, UUIDs, and tokens that start with `sha1-`, `sha256-`, `sha384-`, or `sha512-` are skipped. Other long base64 blobs are still masked, which is why the switch stays off.

An allow entry does not exempt a secret or a personal-data match.

## Optional personal data

Emails, phone numbers, and Swedish identity numbers are off unless you opt in. Person names are masked only when listed under `[redact.names]` `people`. There is no built-in list of people.

```toml
[redact.pii]
email = true
phone = true
personnummer = true
```

Each flag defaults to `false`. Leave the section out and those values are sent through unchanged.

`email` matches an address with a dotted domain, such as `ada@example.com`. `user@host` and `user@localhost` stay, because there is no dot. `git@github.com:org/repo.git` stays too: a colon followed by a path is an ssh/scp remote. `git@github.com` with no colon is masked, and so is `user@box.local`, because those shapes are also mailboxes. `user@10.1.2.3` is not an email; a public address there is still masked by the IP rule.

`phone` matches E.164 numbers that start with `+`, and common Swedish numbers: `070-123 45 67`, `0701234567`, `08-123 456 78`, `08-12345678`, `+46 70 123 45 67`, `+46 (0) 70 …`. Spaces, hyphens, and parentheses are separators. A leading `00` is accepted when the rest is grouped (`0046 70 …`). Dotted numbers (`+1.2.3`, `+1.202.555.0143`, `+46.70…`) are not phones, so version strings stay. A compact landline with no separator (`0812345678`) stays; write it with a hyphen or as `+46…`. A compact `0046…` with no separator stays for the same reason. A 10-digit mobile with no separator is masked, so an order number with that exact shape is too. Groups are short (at most four digits, or eight in the last group), which keeps a following personnummer or order number intact. A later group that would make the number the wrong length is left outside the match, so `070-123 45 67 2024` still masks the phone.

`personnummer` matches Swedish personnummer and samordningsnummer. Both the 10-digit and 12-digit forms are accepted, with or without one `-` or `+`. A samordningsnummer is the same shape with the day in 61–91 (the real day plus 60). The 10-digit payload has to pass the Luhn check, and the day has to be possible. A 12-digit year has to fall in 1800–2099, and February 29 only when that year is a leap year. A 10-digit number has no century, so February 29 is accepted when some year 1800–2099 with those two digits is a leap year (`00` can be 2000; `99` cannot). `2024-11-10`, a git SHA, and `123456789012` stay. So does `ORD-20990101-9993` and `v209901019993`, because a hyphen or a letter glued to the digits is an order number or a version tag, not an identity number written on its own. A bare number that is both a valid identity number and an order number cannot be told apart, so it is masked. Spaces, as in `20990101 - 9993`, are not a supported form.

Matches use the `pii` category. The audit log stores the category, the rule (`email`, `phone-e164`, `phone-se`, `personnummer`, or `samordningsnummer`), and the length. It does not store the original value. The vault on this machine still stores it, so the reply can be restored.

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
# enforce (default) honors each action. observe treats every match as warn.
mode = "enforce"
internal_domains = ["corp", "internal", "lan"]

# Optional default for a whole category. Omitted categories use redact.
[redact.category]
secret = "redact"
ip = "redact"
hostname = "redact"

# Optional action for one builtin detector. This overrides [redact.category].
[redact.builtin]
private-key = "block"

[[redact.secrets]]
name = "acme-factory-token"
regex = '\bacme_live_[A-Za-z0-9]{16,}\b'
action = "warn"

[redact.names]
terms = ["Exempla", "Tundrahorn", "TDH"]
people = ["Ren Testdotter"]
```

`action` is `redact`, `warn`, or `block`. Leave it out to redact. An explicit action on a `[[redact.secrets]]` rule applies to that rule. It does not change a builtin detector. Startup fails if a custom rule's name matches a builtin detector name, and the error names the rule and tells you to rename it. Change a builtin's action in `[redact.builtin]`. A `block` match blocks the request even when a wider `warn` or `redact` span covers the same bytes. `mode = "observe"` forces warn for every match, including rules set to block, so a repo can be tried before anything is masked or refused.

Builtin detector names: `aws-access-key-id`, `github-pat`, `github-fine-grained-pat`, `slack-token`, `google-api-key`, `stripe-live-secret`, `openai-api-key`, `anthropic-api-key`, `jwt`, `url-password`, `private-key`, `generic-api-key`, `env-assignment`, `env-quoted-assignment`, `gitlab-pat`, `azure-account-key`, `repr-env-assignment`, `shell-password`, `split-string-literal`, `base64-secret`, `ipv4`, `ipv6`, `internal-hostname`. Category names: `secret`, `ip`, `hostname`. An unknown action, mode, category, or builtin name fails at startup and names the values that are accepted.

`block` responds with HTTP 400 and does not contact upstream. The response sets `x-should-retry: false`. `POST /v1/messages` returns an Anthropic error object: `type` is `error`, `error.type` is `invalid_request_error`, and the same sentence is repeated in the top-level `message` and in `error.message`. Other `/v1/*` routes return an OpenAI error object: `error.type` is `invalid_request_error` and `error.code` is `symveil_blocked`. The sentence names the rule and the length. It does not include the matched secret.

The official OpenAI and Anthropic Python SDKs, and the Anthropic TypeScript SDK, retry 408, 409, 429, and 5xx. They do not retry 400 unless `x-should-retry` is `true`. The OpenAI Node SDK reads `error.message`. The Anthropic TypeScript SDK uses the top-level `message` as the exception text and `error.message` as `apiMessage`. This repository was not run against Claude Code or those SDK processes.

`warn` leaves the match in the upstream body. The proxy logs `forwarded a match unchanged` with the rule, category, and length. The audit line uses `"action":"warn"` and, for a secret or a personal-data value, omits both the value and a placeholder. Addresses and hostnames are still stored, as they were for redaction. `redact` still writes the placeholder and restores it on the way back.

Personal data stays off until `[redact.pii]` sets `email`, `phone`, or `personnummer`. See [Optional personal data](#optional-personal-data).

`.symveil/` is gitignored. The vault is the reverse map, including secrets and, when those rules are on, personal-data values. SymVeil encrypts it with AES-256-GCM. The key is stored in the OS keychain (macOS Keychain, Linux Secret Service, or Windows Credential Manager), under the service name `symveil` and an account named from a random id in the vault header, so moving the file does not lose the key. A vault whose account was still a hash of the path is migrated the next time it is opened at that path. An existing `.symveil/vault.key` is moved into that keychain on open and then removed. When no keychain can be opened, SymVeil falls back to `.symveil/vault.key` (mode `0600`; the directory is `0700` when SymVeil creates it) and prints a warning that a copy of the directory can decrypt the vault. A locked keychain is not that fallback: startup fails and leaves the vault unchanged. The audit log does not contain secret values or personal-data values. It is mode `0600` and is not encrypted. Encryption does not hide the vault from a process running as the same user, or from root. Do not copy `.symveil/` off the machine. Details: [docs/design/vault-at-rest.md](docs/design/vault-at-rest.md).

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

Apache-2.0. See [LICENSE](LICENSE).
