# Vault encryption at rest

SymVeil's `.symveil/vault.json` is the reverse map: every original value and its
placeholder. This note is the threat model for encrypting that file, and the
choice implemented in this tree. It does not claim the proxy sandboxes an
agent, intercepts TLS, or hides secrets from the user who runs it.

## What is protected

On Unix, a vault SymVeil creates is ciphertext unless the reader also has the
key. That holds for:

- Another local account that is not root and cannot read the owner's keychain
  or, when the file fallback is in use, mode `0600` files in a mode `0700`
  directory.
- A copy, attachment, or partial backup of `vault.json` that does not include
  the keychain entry or the fallback key file.
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

- Any process running as the same user can read the keychain entry and the
  plaintext in memory. That includes malware, a debugger, and a shell as that
  user. A keychain does not stop the owner.
- Root, and anyone who can impersonate the user, can read the key.
- A backup of the whole `.symveil/` directory does not include the keychain
  entry. It does include `.symveil/vault.key` when the file fallback is in
  use. Encryption does not help that copy.
- An older plaintext copy of the vault, from before it was encrypted, is
  still plaintext.
- Secrets that already left the machine, and placeholders already sent
  upstream, are unaffected.
- Process memory, swap, hibernation, and core dumps can contain the original
  values. The running proxy has to hold them to restore a response.
- Losing the key does not delete those upstream placeholders. It only makes
  this vault unable to turn them back into the original values.

## Key storage

The 32-byte AES key is stored in the OS keychain through the `keyring` crate:

| Platform | Store |
| --- | --- |
| macOS | Keychain |
| Linux | Secret Service |
| Windows | Credential Manager |

The service name is `symveil`. The account is `vault-key-` plus a random
128-bit id stored in the cleartext vault header, so two vaults do not share a
key and moving the file does not lose it. The keychain holds the raw 32 bytes.
There is no passphrase and no KDF.

A vault sealed before that id existed used `vault-key-` plus the SHA-256 hex
of the path. The next open at that same path copies the key to a new id
account, writes the id into the header, and deletes the path-based entry.
Opening it only after the path has already changed cannot find that old entry.

A file is the fallback, and only then. When the keychain cannot be opened at
all (no Secret Service, no login keychain, a headless session), SymVeil writes
`.symveil/vault.key` at mode `0600` and prints `no OS keychain is available`
on stderr, with the path. A copy of the directory then includes the key. A
keychain that exists but is locked or returns an error is not this case:
startup fails, and SymVeil does not write a second key beside the vault.

An environment variable is not a key store. It would show up in process
listings. Not used.

An age identity file (mentioned on issue #7) is another on-disk key. The vault
does not need public-key wrapping. Not used.

The vault payload format does not change when the key moves between the
keychain and the file.

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
  "id": "<32 lowercase hex chars>",
  "cipher": "aes-256-gcm",
  "nonce": "<standard base64>",
  "ciphertext": "<standard base64 of ciphertext and tag>"
}
```

`id` is not part of the GCM associated data. Changing it makes the file look
up a different keychain account, and decryption with the wrong key fails. An
envelope with no `id` is the path-hash format and is migrated as described
above. The ciphertext is not rewritten for that migration.

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
is a plaintext vault. `Vault::load` reads it, stores the key (keychain, or the
file when no keychain can be opened), and replaces the file with a version 2
envelope. The key is stored before that replace. A crash before the replace
leaves the plaintext file in place; the next open retries with the same key.

If the version 1 file cannot be parsed, or a key file is already there and is
not a valid SymVeil key, the plaintext file is left as it is and the open
fails.

An existing `.symveil/vault.key` is copied into the keychain on open and the
file is removed. If the keychain already has a different key for that vault,
the open fails and both copies are left as they are. If the keychain cannot
be opened, the file stays and the warning is printed.

A file that is version 1 and also has encryption fields is refused. It is not
loaded as an empty map and then saved over the original.

The proxy, `redact`, and `restore` all open the vault through `Vault::load`,
so an old file is migrated at startup, before the proxy accepts a connection.

## Lost, missing, or wrong key

There is no escrow and no recovery.

- Sealed vault, key missing from the keychain and from the file: open fails.
  SymVeil does not create a replacement key and does not start with an empty
  vault. A new key cannot decrypt the existing file. Placeholders already
  issued from this vault cannot be restored unless the original key is put
  back.
- Key file present but not the header-plus-32-byte format: open fails. The
  key file and the vault are both left as they are. If the vault is still
  plaintext, move that key file aside and open again. If the vault is sealed,
  put the original key back.
- Keychain entry and key file both exist and differ: open fails. Neither is
  overwritten.
- The key is a valid key for a different vault, or the ciphertext was
  modified: AES-GCM verification fails. The vault is left as it is.
- Deleting the vault and its key starts a new map. Old placeholders in
  transcripts stay unrestorable. That is a manual choice; SymVeil does not do
  it on error. Moving a vault that already has an `id` keeps the same
  keychain account. A vault that still uses the path hash has to be opened
  once at the old path so the key can be copied onto an id.

The error text says the vault was left unchanged and that it will not be
replaced with an empty vault. `symveil proxy` exits before it listens.

## File permissions (Unix)

SymVeil forces these modes after create, so a loose umask cannot widen them:

| Path | Mode | When |
| --- | --- | --- |
| Directory it creates for the vault (`.symveil/`) | `0700` | The directory did not exist |
| `vault.json`, `vault.key` (only if there is no keychain), the `*.tmp` write, `audit.jsonl` | `0600` | SymVeil creates the file |

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
- An explicit opt-out that keeps writing version 1 plaintext.
- Tests do not open a real keychain. The keychain path uses an in-memory
  backend. The binary reads `SYMVEIL_TEST_FILE_KEY`. When it is `1`, that
  process uses the file fallback and prints the same warning, even if a
  keychain exists. The proxy integration test sets it so a developer keychain
  is never written. It is not a second supported configuration.
- Whether a loose existing key or audit log should be chmod'd to `0600`
  instead of only warned about.
- The proxy still logs a warning and forwards the request if a vault save
  fails mid-request. A crash before a later successful save can leave a
  placeholder that this process had in memory and did not commit. Startup
  with a bad key does not have that hole: the process exits and does not
  listen.
