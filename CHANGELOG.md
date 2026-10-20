# Changelog

## [0.1.0] - Unreleased

First free-tier release of the local proxy. The notes below are the behavior landed in git on 2026-10-15. Replace `Unreleased` with the release date before tagging; the GitHub Release notes are taken from this section.

### Added

- Apache-2.0 proxy that masks secrets before a request leaves the machine and restores them in the response, including streamed server-sent events (`69df81a`).
- Builtin secret rules for AWS access key ids, GitHub PATs (classic and fine-grained), Slack tokens, Google API keys, Stripe live secrets, PEM private keys, and `api_key`, `secret`, `token`, and `password` assignments.
- IPv4 and IPv6 masking. `127.0.0.1`, `0.0.0.0`, `255.255.255.255`, and `::1` are left in place. Hostnames under the configured internal domains are masked. The defaults are `corp`, `internal`, and `lan`.
- User secret rules under `[[redact.secrets]]`. An allow entry does not exempt a secret.
- `proxy`, `redact`, and `restore`. The proxy listens on `127.0.0.1` and forwards OpenAI-compatible `/v1/*` and Anthropic `/v1/messages`. `Authorization` and `x-api-key` are forwarded and are not written to the audit log.
- Local vault (`.symveil/vault.json`) and audit log (`.symveil/audit.jsonl`). The audit log records the rule, the length, and the placeholder. It omits secret values.
- CI running `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked`.

### Fixed

- Sentence-final IPv4 addresses (`b3d46c7`). A period after a complete address was treated as another octet, so a prompt ending in `10.8.8.8.` left the address in the upstream body.

### Documented

- Grok Build 1.0.52 through a local mock (`b3d46c7`). Session-title generation calls `https://cli-chat-proxy.grok.com` directly unless `models.session_summary` points at the SymVeil model. A placeholder split across two JSON fragments may come back unrestored. The check was not run against `https://api.x.ai`.

### Not in this build

- Identifier and code-name masking. That behavior is not part of this Apache-2.0 tree. The published crates do not declare an `identifiers` feature and do not depend on a proprietary masker.
