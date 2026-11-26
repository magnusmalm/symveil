# Real-client check (Magnus's host only)

`make leak-streak` runs the full leak measurement three times back to back. Each run starts from a clean `target/leak-report`. The makefile prints SAFE when all three `cargo test` invocations exit 0, and NOT SAFE with the failing run number otherwise. Exit 0 means zero gated leaks. It does not mean the report verdict flipped to SAFE.

A passing `leak_measurement` still prints `NOT SAFE`, then `gated leaks: 0`. NOT SAFE is the work-use verdict. The harness sets the real-client pass to false, so the streak in the report stays 0 and the verdict stays NOT SAFE even when no covered canary reached the mock. That print is the same on main. The test fails if a gated canary reaches a covered channel. Read `Gated leaks this run` in `target/leak-report/report.md` for the count. Uncovered findings, such as the split string literals, are listed separately and are not gated leaks.

SAFE for work use also requires the real-client pass: Claude Code and Grok Build on starbase, synthetic repo only, mock upstream first. The streak alone does not satisfy that.

This harness does not run Claude Code or Grok Build. Those checks happen on a machine you control, against the **synthetic** corpus only. Do not point either client at a proprietary tree for this check. SymVeil is not a sandbox: the agent can still read files locally, and anything that does not go through the proxy is not redacted.

Generate the corpus with `make leak-corpus`. It writes `target/leak-corpus` and leaves it there. `make leak-test` also writes a copy at `target/leak-report/corpus`, and the next measurement deletes that whole directory. There is no `corpus-a` directory. The files are fake: company Exempla, product Tundrahorn. Open `target/leak-corpus` as the workspace.

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

[redact.names]
terms = ["Exempla", "Tundrahorn", "TDH"]
people = ["Ren Testdotter"]
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

A real-client pass is: the mock (and then the real upstream, if you capture it) shows no gated canary, placeholders restore in the tool output you see locally, and the title-bypass check above is clean. Configured company, project, and person names in `[redact.names]` are masked on this free build. Usernames are not. A path is masked only where a configured term or person token appears. Safe for work use still needs three consecutive clean runs and this real-client pass.

## 5. `symveil learn` is not part of this check

`symveil learn <path>` only reads a local tree and writes `learned.toml`. It does not call a model, does not open a socket, and does not read `[proxy]` to contact an upstream. If `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `HTTP_PROXY`, `HTTPS_PROXY`, or the other endpoint variables named in its error are set, it exits instead of scanning. CI checks that the learn crate's dependency closure does not include HTTP clients (`cargo tree -p symveil-learn`).

The file it writes is a list: names, extra literal rules, and allow entries. The proxy merges it on startup. That list is incomplete whenever the scan did not see a value or you skipped it. A keep does not stop a builtin secret rule, and it does not stop personal-data rules when those are on. Learn does not sandbox the tree. It is not a leak measurement. `make leak-test` and `make leak-streak` do not run it, and a clean learn report is not a SAFE result. Use the synthetic corpus only if you try the command while doing the real-client pass. Do not point it at a proprietary tree for this check.

```bash
make leak-corpus
./target/release/symveil learn target/leak-corpus --report
./target/release/symveil learn target/leak-corpus
```

The interactive prompt asks for names, then a triage of counts. `[r]edact`, `[k]eep`, `[s]kip`, and `[a]ll-in-group` decide the selected category. On other identifiers, `[a]` skips; `a redact` redacts the rows that are shown. `[?]` explains each key. `[q]` prints undecided secrets and what `learned.toml` will contain, then saves. Secrets stay masked in the source line unless you pass `--reveal`. `--include-skipped` also reads build directories other than `.git`, and text inside files such as `.pdf` and `.png`.

Unset `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, and `HTTP_PROXY` / `HTTPS_PROXY` in that process first. Learn exits if those are set. It still does not connect.
