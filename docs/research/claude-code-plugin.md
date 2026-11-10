# Claude Code plugin spike

Research for [issue #8](https://github.com/magnusmalm/symveil/issues/8). This is not a release, and the prototype is not registered with a plugin directory.

Every page below was fetched on **10 Nov 2026**. A claim is **verified-by-test** only when this checkout ran it. The Claude Code CLI check used the npm package `@anthropic-ai/claude-code` 2.1.321 (`claude --version` printed `2.1.321 (Claude Code)`). The VS Code extension, the JetBrains plugin, the Claude Desktop app, Cursor, and the ChatGPT/Codex apps were not run.

SymVeil does not isolate an agent or contain its tool calls. A proxy only sees bytes that are sent to it.

## Verified by test

The scripted demo is `integrations/claude-code/demo.sh`. `cargo test --workspace` runs it as `claude_code_hook_demo`.

| Check | Result |
| --- | --- |
| `symveil detect` reports `aws-access-key-id`, `generic-api-key`, `internal-hostname`, and `ipv4` for a sample prompt, and reports the same key inside a JSON string | Passed locally |
| Detect stdout and stderr do not contain the matched text | Passed locally |
| Detect does not change an existing `.symveil/vault.json` | Passed locally |
| Hook mode `off` prints nothing | Passed locally |
| Hook mode `warn` prints a `systemMessage` that names those rules and does not set `decision` | Passed locally |
| Hook mode `ask` prints `decision: "block"` unless `SYMVEIL_HOOK_CONFIRM=1` | Passed locally |
| Hook mode `block` prints `decision: "block"` and `suppressOriginalPrompt: true` | Passed locally |
| Hook stdout does not contain the matched text, and the hook does not rewrite the vault | Passed locally |
| `SessionStart` JSON says the proxy is not responding when `/health` is down, and prints nothing when `/health` returns `{"status":"ok"}` and `ANTHROPIC_BASE_URL` is that same origin | Passed locally, against a loopback HTTP stub |

The demo pipes hook JSON into `integrations/claude-code/hooks/symveil_hook.py` and sample text into `symveil detect`. It does not start Claude Code.

### Claude Code CLI 2.1.321

`claude plugin validate integrations/claude-code` printed `Validation passed`. It also printed a plugin-directory warning that the folder has no icon. That check runs because the folder contains `marketplace.json`. Nothing was submitted.

A print-mode session was then pointed at a loopback HTTP stub. The shell did not have `ANTHROPIC_BASE_URL`. A `--settings` file set it to the stub, along with a dummy `ANTHROPIC_AUTH_TOKEN`. The plugin was loaded with `--plugin-dir` for that process only. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` was set. The stub answered `GET /health` and a minimal `POST /v1/messages` event stream.

| Check | Result |
| --- | --- |
| `SessionStart` runs under `claude -p` | The stream recorded `hook_event: SessionStart` and the hook exited 0 |
| Proxy down | With `SYMVEIL_PROXY_URL` on a closed port, the hook's stdout was a `systemMessage` naming that port and saying `ANTHROPIC_BASE_URL` was the stub instead. In `--output-format stream-json --verbose` that text was on the `hook_response` event. It was not a separate informational line, and plain `claude -p` printed only the stub's reply |
| `ANTHROPIC_BASE_URL` from `--settings` | The stub recorded `POST /v1/messages`, and the printed reply was the stub's `ok`. This was the CLI only |
| Mode `block` and a prompt containing the AWS documentation example key | Informational line `UserPromptSubmit operation blocked by hook`, zero turns, `duration_api_ms` 0, and no `POST /v1/messages`. The example key was not in that stdout. `suppressOriginalPrompt` was set |
| Mode `warn` and the same prompt | Informational line `UserPromptSubmit says:` naming `aws-access-key-id`, then one turn. The stub's `POST /v1/messages` body contained the example key and did not contain an `@@sv:` placeholder. Plain `claude -p` printed `ok` and did not print the warning |

So, on this CLI build, a `UserPromptSubmit` command hook can block or annotate, and it does not rewrite the prompt. A `SessionStart` `systemMessage` came back in the verbose hook record and was not shown in the plain printed answer. No IDE or desktop session was opened.

## 1. Hook events, and what they can do to a prompt

Source: [Hooks reference](https://code.claude.com/docs/en/hooks), fetched 10 Nov 2026. The CLI test above confirms the `UserPromptSubmit` part on 2.1.321: block, annotate, and no rewrite. Which events exist, and where other surfaces fire them, is **docs-only**.

The page lists these events:

`SessionStart`, `Setup`, `UserPromptSubmit`, `UserPromptExpansion`, `PreToolUse`, `PermissionRequest`, `PermissionDenied`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `Notification`, `MessageDisplay`, `SubagentStart`, `SubagentStop`, `TaskCreated`, `TaskCompleted`, `Stop`, `StopFailure`, `TeammateIdle`, `InstructionsLoaded`, `ConfigChange`, `CwdChanged`, `DirectoryAdded`, `FileChanged`, `WorktreeCreate`, `WorktreeRemove`, `PreCompact`, `PostCompact`, `PreModelSwitch`, `PostModelSwitch`, `Elicitation`, `ElicitationResult`, `SessionEnd`.

A command hook reads JSON on stdin. Exit code 2 blocks on events that can block. Exit 0 with a JSON object is the structured form. For `UserPromptSubmit`, the only `decision` value is `"block"`. Omitting `decision` lets the prompt through.

What a `UserPromptSubmit` command hook can do:

- **Block.** `decision: "block"` with `reason`, or exit 2 with the message on stderr. The prompt does not reach Claude. `suppressOriginalPrompt: true` leaves the prompt text out of the block message. The same page says the text can still land in the session transcript and prompt history, so a block is not a way to keep a secret off disk.
- **Annotate.** Plain stdout, or `hookSpecificOutput.additionalContext`, is added beside the prompt as context Claude can read. It is not a visible chat line. `systemMessage` is the universal field for a warning shown to the user. The `UserPromptSubmit` section says all JSON output fields are available, and it does not say this event discards `systemMessage`. This spike did not watch a Claude Code UI render one.
- **Not rewrite.** The decision-control section says, in so many words: `UserPromptSubmit` can't replace the prompt; it only injects `additionalContext` alongside it. There is no `updatedPrompt` field.

`PreToolUse` is different. It can `allow`, `deny`, `ask`, or `defer`, and `updatedInput` replaces the tool's arguments before the tool runs. `ask` shows the tool call to the user. That `ask` value is not accepted on `UserPromptSubmit`.

`PostToolUse` can set `updatedToolOutput`, which replaces what Claude sees of a tool result. The tool has already run. `MessageDisplay` can replace text on screen only; the transcript and what Claude sees stay the original.

The same opening paragraph says Claude Code fires the same hook events in the terminal, the IDE extensions, the Desktop app, and cloud sessions. The [VS Code page](https://code.claude.com/docs/en/vs-code) says the extension's Customize view lists hooks, including plugin hooks as read-only, on Claude Code v2.1.269 or later. The [JetBrains page](https://code.claude.com/docs/en/jetbrains) says that plugin runs the `claude` CLI in the IDE terminal rather than bundling its own copy, so those sessions are CLI sessions. None of that was run here.

A separate mechanism, a plugin **mod**, can rewrite a prompt. [React to events with a mod](https://code.claude.com/docs/en/plugins/mods/events) says a `prompt.submit` handler may return `next({ ...e, text: newText })`, and that the transcript and prompt history then show the new text. `{ drop: 'the reason' }` stops the send, with the exceptions on that page (a throw or a timeout still sends the prompt). The mods page fetched the same day does not say whether mods run in the IDE extensions or the Desktop app. This prototype does not ship a mod. Rewriting the prompt would still leave later tool output, such as a file read, unmasked unless the API call itself goes through the proxy.

## 2. Can a plugin set or require `ANTHROPIC_BASE_URL`?

A plugin cannot set it, and nothing in the manifest can require it. The CLI half of the settings `env` block was **verified-by-test** on 2.1.321, as the table above records. The rest of this section is **docs-only**.

[Plugin manifest reference](https://code.claude.com/docs/en/plugins/manifest-reference) and [Add components to a plugin](https://code.claude.com/docs/en/plugins/components), both fetched 10 Nov 2026: a plugin `settings.json`, or the manifest `settings` object, applies only `agent` and `subagentStatusLine`. Every other key is dropped. There is no `env` field that survives load, and no field that refuses to start unless a variable is set.

`CLAUDE_ENV_FILE` is not a substitute. The hooks page says `SessionStart`, `Setup`, `CwdChanged`, and `FileChanged` may append `export` lines to that file, and that those variables apply to later Bash (and, on v2.1.296 or later, PowerShell) commands. The [environment variables page](https://code.claude.com/docs/en/env-vars) describes `CLAUDE_ENV_FILE` the same way: a script run before each Bash command. It does not say Claude Code's own model requests read it.

What does set `ANTHROPIC_BASE_URL` for Claude Code's own client is the `env` object in a Claude Code settings file. [All settings](https://code.claude.com/docs/en/settings-reference) (`env`, fetched 10 Nov 2026) shows that object with `ANTHROPIC_BASE_URL` as the example of routing through a proxy. The same section's ignore list for project and local settings covers config directories, telemetry exporters, OAuth tokens, and a few startup switches. `ANTHROPIC_BASE_URL` is not in that list. [Settings files](https://code.claude.com/docs/en/settings) say a project's `.claude/settings.json` is the shared place for environment variables the project needs, and `.claude/settings.local.json` is the per-user unshared file. Project and local `env` values apply after the workspace is trusted, or at startup in `-p` mode, which skips the trust dialog. A settings value overrides the same variable from the shell. If the Claude Desktop app, or a self-hosted runner, already put the variable in the launch environment, settings cannot override that copy.

[Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect), fetched 10 Nov 2026, is the surface-by-surface page:

- **CLI.** Shell export or a settings `env` block. The settings block is what background sessions see reliably.
- **VS Code extension.** Put `ANTHROPIC_BASE_URL` in VS Code user settings under `claudeCode.environmentVariables`. The page says values in `~/.claude/settings.json` reach the process the extension spawns, but not the extension's own login check, which reads `claudeCode.environmentVariables` before launch. This spike did not install the extension, so that split is docs-only.
- **Desktop app.** The app does not take gateway routing from `ANTHROPIC_BASE_URL` or `settings.json`. It uses third-party inference configuration, from an administrator or from Developer → Configure Third-Party Inference. See question 3.
- **Slack and Claude Code cloud sessions.** Gateway variables in a cloud session's environment configuration are not applied.

`CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST`, on the environment variables page, makes an embedding host ignore `ANTHROPIC_BASE_URL` in settings files. The page does not say which apps set that variable.

The prototype's `project.settings.json` is the project `env` block a person copies into `.claude/settings.local.json`. The plugin does not write that file. `SessionStart` only reports whether this process already has the variable.

## 3. Cursor, Claude Desktop, and ChatGPT/Codex

### Cursor

**No. Cursor's agent cannot be routed through a local proxy.**

[Bring your own API key](https://cursor.com/docs/settings/api-keys), fetched 10 Nov 2026, says a custom key is sent to Cursor's backend with every request because prompt building happens on Cursor's servers. The key is not stored there. Custom keys do not apply to Tab completion. The page documents OpenAI, Anthropic, Google, Azure OpenAI, and AWS Bedrock keys. It does not document a base URL, and it does not document a localhost model endpoint.

That is the official description of the product path. This spike did not run Cursor.

### Claude Desktop

**The chat app can send Chat, Cowork, and Code inference to a Messages API gateway. It cannot be switched with `ANTHROPIC_BASE_URL`. A loopback SymVeil URL was not tested.**

[Deploy Claude Desktop on 3P with an LLM gateway](https://claude.com/docs/third-party/claude-desktop/gateway), fetched 10 Nov 2026: set `inferenceProvider` to `gateway` and `inferenceGatewayBaseUrl` (since desktop 1.2581.0) to a gateway that implements `POST /v1/messages` with streaming and tool use. The page says Chat, Cowork, and Code sessions send those requests. The examples are `https://` hosts. The page does not say the local app rejects `http://127.0.0.1`.

[Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect) says SSH sessions in the desktop app cannot use a gateway that is `localhost` on the client computer, because the remote machine dials the gateway itself. That sentence is about SSH sessions, not about a Code tab running on the same machine.

[Network proxy](https://claude.com/docs/third-party/claude-desktop/network-proxy) is a different knob. `egressProxyUrl` can be `http://127.0.0.1:<port>` and is an HTTP proxy in front of whatever the inference endpoint already is. SymVeil speaks `/v1/messages`. It is not an HTTP CONNECT proxy, so `egressProxyUrl` does not point the app at SymVeil.

### ChatGPT and Codex desktop

**Codex can. Ordinary ChatGPT chat is not documented as a custom base URL.**

Codex local clients read `~/.codex/config.toml`. [Advanced Configuration](https://learn.chatgpt.com/docs/config-file/config-advanced), fetched 10 Nov 2026, says `openai_base_url` points the built-in OpenAI provider at a proxy, and shows a custom provider with `base_url = "http://localhost:11434/v1"` for Ollama. [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) says a project `.codex/config.toml` cannot set `openai_base_url`, `model_provider`, or `model_providers`. Those keys belong in the user file. [Codex Manual](https://learn.chatgpt.com/docs/codex-manual) says the CLI, the IDE extension, and the ChatGPT desktop app share that configuration, and that the desktop app opens the user file from Settings → Configuration → Open config.toml.

[Network recommendations for ChatGPT](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps) tells networks which OpenAI domains to allow. It does not document a custom inference base for the ChatGPT chat product. This spike did not run either app, and it did not confirm that Chat (as opposed to Codex) follows `model_provider`.

## What the prototype does

Layout:

- `integrations/claude-code/.claude-plugin/plugin.json` names the plugin `symveil` at version `0.0.0`.
- `integrations/claude-code/.claude-plugin/marketplace.json` exists so a local checkout can be added with `claude plugin marketplace add ./integrations/claude-code` and installed with `claude plugin install symveil@symveil-local`. Do not add the GitHub repository as a marketplace, and do not submit this to a plugin directory. `claude plugin validate` was not run.
- `hooks/hooks.json` registers `SessionStart` and `UserPromptSubmit`.
- `hooks/symveil_hook.py` is the command hook.
- `project.settings.json` is the `env` block to copy by hand into `.claude/settings.local.json`. It sets `ANTHROPIC_BASE_URL` to `http://127.0.0.1:8787` and `SYMVEIL_HOOK_MODE` to `warn`.

`symveil detect` reads stdin, runs the same secret and network matchers as `redact`, and writes JSON rule names, categories, and counts. It uses an in-memory vault and does not save one. `redact` was the wrong call for a warning: it writes the vault and does not print rule names.

On `SessionStart` the hook GETs `{SYMVEIL_PROXY_URL}/health` (default `http://127.0.0.1:8787`) and compares `ANTHROPIC_BASE_URL` in its own environment with that origin. It prints a `systemMessage` only when the proxy is down, the variable is missing, or the variable points somewhere else. A `/v1` suffix is called out because the Anthropic client appends `/v1/messages`. On CLI 2.1.321 that message was visible in the verbose stream's hook record, not in the plain printed answer.

On `UserPromptSubmit` the mode comes from `SYMVEIL_HOOK_MODE`:

| Mode | Behavior |
| --- | --- |
| `off` (default) | Do not scan. |
| `warn` | `systemMessage` naming the rules. The prompt is unchanged and is not blocked. |
| `ask` | `decision: "block"` until `SYMVEIL_HOOK_CONFIRM=1`. That variable then allows later prompts for the life of the process. Claude Code has no yes/no field on this event. |
| `block` | `decision: "block"`, including when confirm is set. |

Messages name rules only. `suppressOriginalPrompt` is set on a block so the block text does not repeat the prompt. The docs still say Claude Code can store the prompt in the transcript.

## Out of scope

The proxy never sees Claude Code's local files. In particular:

- Session transcripts under `~/.claude/`, including tool output such as a file the agent read.
- A permission rule saved in `.claude/settings.local.json` after a "don't ask again" answer. That file can contain the command text.

The plugin does not read or edit those files. A block does not remove a prompt from disk.

## Still unverified

- The VS Code extension, including `claudeCode.environmentVariables`, and the JetBrains plugin. `/hooks` was not opened in either UI.
- The Claude Desktop app, including `inferenceGatewayBaseUrl` set to `http://127.0.0.1:8787`.
- Whether an interactive terminal shows a `SessionStart` `systemMessage`. The print-mode checks above did not.
- `claude plugin marketplace add` was not run, and the plugin was not submitted anywhere.
- Cursor and the ChatGPT/Codex apps were not run.
- Whether a mod's `prompt.submit` rewrite runs in the IDE extensions and the Desktop app.
