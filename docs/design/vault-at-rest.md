# Vault encryption at rest

SymVeil's `.symveil/vault.json` is the reverse map: every original value and its
placeholder. This note is the threat model for encrypting that file, and the
choice implemented in this tree. It does not claim the proxy sandboxes an
agent, intercepts TLS, or hides secrets from the user who runs it.

## What is protected

On Unix, a vault SymVeil creates is ciphertext unless the reader also has the
key file. That holds for:

- Another local account that is not root and cannot read mode `0600` files in
  a mode `0700` directory.
- A copy, attachment, or partial backup of `vault.json` that does not include
  the sibling key file.
- Someone opening the vault in an editor. The file does not show the original
  values.
- A modified ciphertext. AES-GCM authentication fails, SymVeil refuses to
  load the file, and it does not replace the file.

The audit log is not encrypted. It still omits secret values. It still stores
originals for non-secret categories (including hostnames and IP addresses),
which is unchanged.

## What is not protected

Encryption here is a file format plus owner-only permissions. It does not
raise the bar against a caller who is already the vault's owner.

- Any process running as the same user can read the key file and the
  plaintext in memory. That includes malware, a debugger, and a shell as that
  user. A mode `0600` file does not stop the owner.
- Root, and anyone who can impersonate the user, can read the key.
- A backup, sync, or disk image of the whole `.symveil/` directory includes
  the key. Encryption does not help that copy.
- An older plaintext copy of the vault, from before it was encrypted, is
  still plaintext.
- Secrets that already left the machine, and placeholders already sent
  upstream, are unaffected.
- Process memory, swap, hibernation, and core dumps can contain the original
  values. The running proxy has to hold them to restore a response.
- Losing the key does not delete those upstream placeholders. It only makes
  this vault unable to turn them back into the original values.

## Key storage

Three places to keep the 32-byte AES key:

| Option | Fit |
| --- | --- |
| OS keychain (`keyring` or similar) | The key is outside `.symveil/`, so a copy of the directory is not enough to decrypt. Headless agents, SSH sessions, CI, and containers often have no Secret Service or login keychain. The same user can still read a keychain entry. Not the default. |
| Key file, mode `0600` | Works without a desktop session. The mode is testable. This is the implementation. The file is the sibling of the vault: `.symveil/vault.json` uses `.symveil/vault.key`. |
| Environment variable | Same owner can read it, and it also shows up in process listings and service definitions. Worse than a `0600` file for the same boundary. Not used. |

An age identity file (mentioned on issue #7) is another on-disk key. The vault
does not need public-key wrapping. Not used.

There is no passphrase and no KDF. The key file is the raw key. Moving that
file into the OS keychain later does not require a new vault payload format.

## Cipher

AES-256-GCM from the RustCrypto `aes-gcm` crate. SymVeil does not implement a
cipher, a mode, or a random-number generator.

- Key: 32 bytes from `OsRng`.
- Nonce: 12 random bytes from `OsRng`, new on every write. The nonce is stored
  next to the ciphertext. It is not secret.
- Tag: 16 bytes, appended by the crate and stored as part of the ciphertext.
- Associated data: the UTF-8 bytes `symveil-vault-v2 aes-256-gcm`, so a
  swapped cipher name does not verify under this key.

A 96-bit random nonce is enough for this file. Each save is one message, not
a stream, and the write rate is "when a new value is masked." XChaCha20-Poly1305
would be the alternative if one key ever encrypted a very large number of
messages. It is not required here.

## On-disk format

Version 2 envelope, pretty-printed JSON:

```json
{
  "version": 2,
  "cipher": "aes-256-gcm",
  "nonce": "<standard base64>",
  "ciphertext": "<standard base64 of ciphertext and tag>"
}
```

The decrypted payload is the historical version 1 document: `version` and
`entries` (original, placeholder, category, rule). Placeholders are unchanged
across encryption.

Key file, mode `0600`:

```text
symveil-vault-key-v1
<standard base64 of 32 bytes>
```

A file that does not have that header is not overwritten.

## Migration

A version 1 JSON object that has no `cipher`, `nonce`, or `ciphertext` field
is a plaintext vault. `Vault::load` reads it, writes the key if there is not
one yet, and replaces the file with a version 2 envelope. The key file is
synced before that replace. A crash before the replace leaves the plaintext
file in place; the next open retries with the same key.

If the version 1 file cannot be parsed, or a key file is already there and is
not a valid SymVeil key, the plaintext file is left as it is and the open
fails.

A file that is version 1 and also has encryption fields is refused. It is not
loaded as an empty map and then saved over the original.

The proxy, `redact`, and `restore` all open the vault through `Vault::load`,
so an old file is migrated at startup, before the proxy accepts a connection.

## Lost, missing, or wrong key

There is no escrow and no recovery.

- Sealed vault, key file missing: open fails. SymVeil does not create a
  replacement key and does not start with an empty vault. A new key cannot
  decrypt the existing file. Placeholders already issued from this vault
  cannot be restored unless the original key file is put back.
- Key file present but not the header-plus-32-byte format: open fails. The
  key file and the vault are both left as they are. If the vault is still
  plaintext, move that key file aside and open again. If the vault is sealed,
  put the original key back.
- Key file is a valid key for a different vault, or the ciphertext was
  modified: AES-GCM verification fails. The vault is left as it is.
- Deleting both the vault and the key starts a new map. Old placeholders in
  transcripts stay unrestorable. That is a manual choice; SymVeil does not do
  it on error.

The error text says the vault was left unchanged and that it will not be
replaced with an empty vault. `symveil proxy` exits before it listens.

## File permissions (Unix)

SymVeil forces these modes after create, so a loose umask cannot widen them:

| Path | Mode | When |
| --- | --- | --- |
| Directory it creates for the vault (`.symveil/`) | `0700` | The directory did not exist |
| `vault.json`, `vault.key`, the `*.tmp` write, `audit.jsonl` | `0600` | SymVeil creates the file |

Missing parents that SymVeil has to create are also `0700`. An existing
directory is not chmod'd. An existing audit log is not chmod'd. If group or
other permission bits are set on an existing directory, vault, key, or audit
log, startup prints a warning and continues.

Replacing the vault (every save, including migration) uses a new file created
at `0600`, then renames it into place. A previous `0644` vault inode does not
stay in place across that save.

These modes are Unix permissions. They are not applied on other platforms.
They do not stop the owner, and they do not stop root.

## Left open

- Issue #7 step 3: `symveil vault clear`, and a max age so old values do not
  accumulate. Not in this change.
- Putting the key in the OS keychain, or a path outside the repository, so a
  directory backup does not include it.
- An explicit opt-out that keeps writing version 1 plaintext.
- Whether a loose existing key or audit log should be chmod'd to `0600`
  instead of only warned about.
- The proxy still logs a warning and forwards the request if a vault save
  fails mid-request. A crash before a later successful save can leave a
  placeholder that this process had in memory and did not commit. Startup
  with a bad key does not have that hole: the process exits and does not
  listen.
