# Security

SymVeil masks secrets in traffic from clients that opt in by using the proxy. It does not sandbox the agent, and it is not a TLS intercept.

The vault file is the reverse map. On disk it is encrypted with AES-256-GCM. The key lives beside it (`.symveil/vault.key`). Anyone who can read both files can undo every placeholder. That includes other programs running as the same user, and anyone with a copy of the directory. See [docs/design/vault-at-rest.md](docs/design/vault-at-rest.md).

## Reporting

If you find a way for a secret to reach the upstream model, or for the proxy to log a secret value, report it privately. Open a GitHub security advisory on this repository. Do not attach a live vault, a real token, or a request body that still contains a secret. A redacted `.symveil/audit.jsonl` line and a description of the rule that should have matched are enough.

## What stays local

- `.symveil/vault.json` is the encrypted reverse map (placeholders and original values).
- `.symveil/vault.key` is the AES-256-GCM key for that vault. Losing it makes the vault undecryptable. SymVeil will not replace an undecryptable vault with an empty one.
- `.symveil/audit.jsonl` records category, rule, length, and placeholder. It omits secret text. It is not encrypted. Non-secret categories still store their original string.
- Files SymVeil creates under `.symveil/` are owner-only on Unix (`0700` directory, `0600` files). An existing directory or audit log that is more open is warned about and left as it is.
- `Authorization`, `x-api-key`, and other client headers are forwarded upstream and are not written to the audit log.

## Expectations

Builtin rules are a small set, not a complete secret scanner. They do not replace scanning in CI. The proxy only sees traffic from clients that opt in by changing their base URL. It is not a TLS intercept.
