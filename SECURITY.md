# Security

SymVeil masks secrets on the machine that runs the agent. The vault file is the reverse map. Anyone who can read it can undo every placeholder, including secrets.

## Reporting

If you find a way for a secret to reach the upstream model, or for the proxy to log a secret value, report it privately. Open a GitHub security advisory on this repository. Do not attach a live vault, a real token, or a request body that still contains a secret. A redacted `.symveil/audit.jsonl` line and a description of the rule that should have matched are enough.

## What stays local

- `.symveil/vault.json` holds original secrets and their placeholders.
- `.symveil/audit.jsonl` records category, rule, length, and placeholder. It omits the secret text.
- `Authorization`, `x-api-key`, and other client headers are forwarded upstream and are not written to the audit log.

## Expectations

Builtin rules are a small set, not a complete secret scanner. They do not replace scanning in CI. The proxy only sees traffic from clients that opt in by changing their base URL. It is not a TLS intercept.
