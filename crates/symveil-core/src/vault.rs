//! Reverse map from original values to placeholders.
//!
//! On disk the map is an AES-256-GCM payload (version 2). The key is a sibling
//! file, not part of the ciphertext. See `docs/design/vault-at-rest.md`.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::category::Category;
use crate::perms;
use crate::seal;

pub const VAULT_VERSION: u32 = 1;
pub const TOKEN_LEN: usize = 15;

const REFUSED: &str =
    "SymVeil left the vault unchanged and will not replace it with an empty vault.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub original: String,
    pub placeholder: String,
    pub category: Category,
    #[serde(default)]
    pub rule: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    entries: Vec<Entry>,
}

pub struct Vault {
    path: Option<PathBuf>,
    key: Option<Zeroizing<[u8; 32]>>,
    entries: BTreeMap<String, Entry>,
    reverse: HashMap<String, String>,
    dirty: bool,
}

/// Path of the AES-256-GCM key for `vault`.
///
/// `.symveil/vault.json` uses `.symveil/vault.key`.
pub fn vault_key_path(vault: &Path) -> PathBuf {
    vault.with_extension("key")
}

impl Vault {
    pub fn ephemeral() -> Self {
        Self {
            path: None,
            key: None,
            entries: BTreeMap::new(),
            reverse: HashMap::new(),
            dirty: false,
        }
    }

    pub fn create(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            key: None,
            entries: BTreeMap::new(),
            reverse: HashMap::new(),
            dirty: false,
        }
    }

    /// Load a vault from `path`.
    ///
    /// A version 1 plaintext file is encrypted in place before this returns.
    /// A version 2 file is decrypted with the sibling key from [`vault_key_path`].
    /// If that key is missing or wrong, or the file cannot be authenticated, this
    /// returns an error and does not modify the vault file.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read vault {}", path.display()))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && parent.exists() {
                perms::warn_if_loose_dir(parent);
            }
        }
        perms::warn_if_loose_file(path);
        match seal::inspect(&bytes) {
            Ok(seal::Inspected::Plaintext) => load_plaintext(path, &bytes),
            Ok(seal::Inspected::Sealed(envelope)) => load_sealed(path, &envelope),
            Err(err) => Err(refused_error(path, &seal_reason(&err))),
        }
    }

    pub fn save(&mut self) -> Result<()> {
        let Some(path) = self.path.clone() else {
            self.dirty = false;
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                perms::ensure_private_dir(parent)?;
            }
        }
        // The key file is synced before a plaintext vault is replaced. A crash
        // in between leaves the old file and a key that can finish the migration.
        self.ensure_key()?;
        let payload = Zeroizing::new(serialize_payload(self)?);
        let key = self
            .key
            .as_deref()
            .ok_or_else(|| anyhow!("internal: vault key missing after ensure"))?;
        let sealed = seal::seal(key, payload.as_slice())
            .map_err(|err| refused_error(&path, &seal_reason(&err)))?;
        perms::write_atomic_private(&path, &sealed)?;
        self.dirty = false;
        Ok(())
    }

    pub fn assign(
        &mut self,
        original: &str,
        category: Category,
        rule: Option<String>,
    ) -> Result<String> {
        if original.is_empty() {
            bail!("refusing to assign a placeholder to an empty string");
        }
        if let Some(entry) = self.entries.get(original) {
            return Ok(entry.placeholder.clone());
        }
        let placeholder = self.fresh_placeholder(original)?;
        let entry = Entry {
            original: original.to_string(),
            placeholder: placeholder.clone(),
            category,
            rule,
        };
        self.reverse
            .insert(placeholder.clone(), original.to_string());
        self.entries.insert(original.to_string(), entry);
        self.dirty = true;
        Ok(placeholder)
    }

    pub fn placeholder(&self, original: &str) -> Option<&str> {
        self.entries
            .get(original)
            .map(|entry| entry.placeholder.as_str())
    }

    pub fn contains(&self, original: &str) -> bool {
        self.entries.contains_key(original)
    }

    pub fn category_of(&self, original: &str) -> Option<Category> {
        self.entries.get(original).map(|entry| entry.category)
    }

    pub fn rule_of(&self, original: &str) -> Option<&str> {
        self.entries
            .get(original)
            .and_then(|entry| entry.rule.as_deref())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn counts(&self) -> BTreeMap<Category, usize> {
        let mut counts = BTreeMap::new();
        for entry in self.entries.values() {
            *counts.entry(entry.category).or_insert(0) += 1;
        }
        counts
    }

    pub fn restore_map(&self) -> HashMap<String, String> {
        self.reverse.clone()
    }

    fn fresh_placeholder(&self, original: &str) -> Result<String> {
        for salt in 0..32u32 {
            let placeholder = placeholder_token(original, salt);
            match self.reverse.get(&placeholder) {
                Some(existing) if existing == original => return Ok(placeholder),
                Some(_) => continue,
                None => return Ok(placeholder),
            }
        }
        bail!(
            "could not mint a unique placeholder for a value of length {}",
            original.len()
        )
    }

    fn ensure_key(&mut self) -> Result<()> {
        let path = self
            .path
            .clone()
            .ok_or_else(|| anyhow!("vault has no path"))?;
        let key_path = vault_key_path(&path);
        if key_path.exists() {
            perms::warn_if_loose_file(&key_path);
            let disk = match seal::read_key(&key_path) {
                Ok(key) => Zeroizing::new(key),
                Err(err) => return Err(key_error(&path, &key_path, &err)),
            };
            if let Some(memory) = &self.key {
                if disk.as_ref() != memory.as_ref() {
                    return Err(refused_error(
                        &path,
                        &format!(
                            "key file {} does not match the key already used for this vault",
                            key_path.display()
                        ),
                    ));
                }
            } else {
                self.key = Some(disk);
            }
            return Ok(());
        }
        if let Some(memory) = &self.key {
            return match seal::write_new_key(&key_path, memory) {
                Ok(()) => Ok(()),
                Err(err) => Err(key_error(&path, &key_path, &err)),
            };
        }
        let created = match seal::read_or_create_key(&key_path) {
            Ok(key) => key,
            Err(err) => return Err(key_error(&path, &key_path, &err)),
        };
        self.key = Some(Zeroizing::new(created));
        Ok(())
    }
}

fn load_plaintext(path: &Path, bytes: &[u8]) -> Result<Vault> {
    let entries = parse_entries(bytes).map_err(|err| {
        refused_error(path, &format!("plaintext vault could not be read: {err:#}"))
    })?;
    let mut vault = from_entries(path.to_path_buf(), entries).map_err(|err| {
        refused_error(path, &format!("plaintext vault could not be read: {err:#}"))
    })?;
    vault.dirty = true;
    vault.save().with_context(|| {
        format!(
            "encrypt plaintext vault {} (the plaintext file was left in place)",
            path.display()
        )
    })?;
    eprintln!(
        "symveil: encrypted the plaintext vault at {}",
        path.display()
    );
    Ok(vault)
}

fn load_sealed(path: &Path, envelope: &seal::Envelope) -> Result<Vault> {
    let key_path = vault_key_path(path);
    if key_path.exists() {
        perms::warn_if_loose_file(&key_path);
    }
    let key = match seal::read_key(&key_path) {
        Ok(key) => key,
        Err(err) => return Err(key_error(path, &key_path, &err)),
    };
    let plain = match seal::open_envelope(&key, envelope) {
        Ok(plain) => Zeroizing::new(plain),
        Err(seal::SealError::DecryptFailed) => {
            return Err(refused_error(
                path,
                &format!(
                    "could not decrypt the vault with the key in {}. The key does not match this vault, or the vault file was modified",
                    key_path.display()
                ),
            ));
        }
        Err(err) => return Err(refused_error(path, &seal_reason(&err))),
    };
    let entries = parse_entries(&plain).map_err(|err| {
        refused_error(
            path,
            &format!("decrypted vault payload is not a version {VAULT_VERSION} vault: {err:#}"),
        )
    })?;
    let mut vault = from_entries(path.to_path_buf(), entries).map_err(|err| {
        refused_error(path, &format!("decrypted vault could not be read: {err:#}"))
    })?;
    vault.key = Some(Zeroizing::new(key));
    Ok(vault)
}

fn parse_entries(bytes: &[u8]) -> Result<Vec<Entry>> {
    let file: VaultFile = serde_json::from_slice(bytes)?;
    if file.version != VAULT_VERSION {
        bail!(
            "unsupported vault payload version {} (this build reads version {VAULT_VERSION})",
            file.version
        );
    }
    Ok(file.entries)
}

fn from_entries(path: PathBuf, entries: Vec<Entry>) -> Result<Vault> {
    let mut vault = Vault::create(path.clone());
    for entry in entries {
        if let Some(other) = vault.reverse.get(&entry.placeholder) {
            if other != &entry.original {
                bail!("vault {} has a placeholder collision", path.display());
            }
        }
        vault
            .reverse
            .insert(entry.placeholder.clone(), entry.original.clone());
        vault.entries.insert(entry.original.clone(), entry);
    }
    vault.dirty = false;
    Ok(vault)
}

fn serialize_payload(vault: &Vault) -> Result<Vec<u8>> {
    let file = VaultFile {
        version: VAULT_VERSION,
        entries: vault.entries.values().cloned().collect(),
    };
    Ok(serde_json::to_vec(&file)?)
}

fn refused_error(path: &Path, reason: &str) -> anyhow::Error {
    anyhow!("{} ({}). {}", reason, path.display(), REFUSED)
}

fn key_error(vault: &Path, key: &Path, err: &seal::KeyError) -> anyhow::Error {
    let reason = match err {
        seal::KeyError::Missing => format!(
            "encrypted vault needs key file {}, which is missing. Without that key, placeholders from this vault cannot be restored, and a new key will not decrypt it",
            key.display()
        ),
        seal::KeyError::Invalid(why) => format!(
            "key file {} is not a SymVeil vault key ({why}). If the vault is still plaintext, move the key file aside and retry. If the vault is already encrypted, restore the original key; a new key will not decrypt it",
            key.display()
        ),
        seal::KeyError::Io(err) => format!("could not read key file {} ({err})", key.display()),
    };
    refused_error(vault, &reason)
}

fn seal_reason(err: &seal::SealError) -> String {
    match err {
        seal::SealError::NotJson => "vault is not valid JSON".to_string(),
        seal::SealError::NotObject => "vault is not a JSON object".to_string(),
        seal::SealError::MissingVersion => "vault has no numeric version".to_string(),
        seal::SealError::UnsupportedVersion(version) => {
            format!("unsupported vault version {version}")
        }
        seal::SealError::MixedPlaintext => {
            "vault version 1 also has encryption fields; refusing to treat it as plaintext"
                .to_string()
        }
        seal::SealError::UnknownCipher(name) => format!("unsupported vault cipher {name}"),
        seal::SealError::Malformed(what) => format!("encrypted vault has a bad {what}"),
        seal::SealError::DecryptFailed => "could not decrypt the vault".to_string(),
        seal::SealError::Crypto => "failed to encrypt the vault".to_string(),
    }
}

pub fn placeholder_token(original: &str, salt: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"symveil-v1\0");
    hasher.update(salt.to_le_bytes());
    hasher.update(original.as_bytes());
    let digest = hasher.finalize();
    format!(
        "@@sv:{:02x}{:02x}{:02x}{:02x}@@",
        digest[0], digest[1], digest[2], digest[3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "symveil-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack.len() >= needle.len()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn expect_err(result: Result<Vault>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("expected the vault open to fail"),
            Err(err) => err,
        }
    }

    fn err_text(err: &anyhow::Error) -> String {
        format!("{err:#}")
    }

    fn assert_refused(err: &anyhow::Error) {
        let text = err_text(err);
        assert!(text.contains("unchanged"), "{text}");
        assert!(text.contains("empty vault"), "{text}");
    }

    #[cfg(unix)]
    fn mode_bits(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn placeholder_is_fixed_width_and_stable() {
        let mut vault = Vault::ephemeral();
        let first = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let second = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), TOKEN_LEN);
        assert!(first.starts_with("@@sv:"));
        assert!(first.ends_with("@@"));
        let other = vault
            .assign("AURORA_RCC_CTRL_REG", Category::Register, None)
            .unwrap();
        assert_ne!(first, other);
    }

    #[test]
    fn reload_keeps_the_same_token() {
        let dir = temp_dir("vault-reload");
        let path = dir.join("vault.json");
        let mut vault = Vault::create(path.clone());
        let token = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        vault.save().unwrap();
        assert!(!vault.is_dirty());
        let on_disk = fs::read(&path).unwrap();
        assert!(
            !contains(&on_disk, b"aurora_rcc_enable_pll"),
            "vault file contains the original value"
        );
        let loaded = Vault::load(&path).unwrap();
        assert_eq!(
            loaded.placeholder("aurora_rcc_enable_pll"),
            Some(token.as_str())
        );
        assert!(!loaded.is_dirty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_path_replaces_only_the_file_extension() {
        assert_eq!(
            vault_key_path(Path::new("/repo/.symveil/vault.json")),
            PathBuf::from("/repo/.symveil/vault.key")
        );
    }

    #[test]
    fn saved_vault_has_no_plaintext_and_a_fresh_nonce_each_save() {
        let dir = temp_dir("vault-sealed");
        let path = dir.join("vault.json");
        let secret = "sealed-secret-value-91af";
        let mut vault = Vault::create(path.clone());
        let token = vault
            .assign(secret, Category::Secret, Some("aws-access-key-id".into()))
            .unwrap();
        vault.save().unwrap();
        let first = fs::read(&path).unwrap();
        let first_key = fs::read(vault_key_path(&path)).unwrap();
        assert!(!contains(&first, secret.as_bytes()));
        let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(value["version"].as_u64(), Some(2));
        assert_eq!(value["cipher"].as_str(), Some(seal::CIPHER_NAME));
        let nonce = value["nonce"].as_str().unwrap().to_string();
        vault
            .assign("second-secret-value-91af", Category::Secret, None)
            .unwrap();
        vault.save().unwrap();
        let second: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_ne!(second["nonce"].as_str(), Some(nonce.as_str()));
        assert_eq!(fs::read(vault_key_path(&path)).unwrap(), first_key);
        assert!(fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .all(|name| !name.to_string_lossy().contains(".tmp")));
        let loaded = Vault::load(&path).unwrap();
        assert_eq!(loaded.placeholder(secret), Some(token.as_str()));
        assert_eq!(loaded.rule_of(secret), Some("aws-access-key-id"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plaintext_vault_migrates_and_keeps_the_placeholder() {
        let dir = temp_dir("vault-migrate");
        let path = dir.join("vault.json");
        let secret = "migrate-me-secret-77ab";
        let placeholder = "@@sv:89abcdef@@";
        assert_ne!(placeholder_token(secret, 0), placeholder);
        let plain = format!(
            r#"{{
  "version": 1,
  "entries": [
    {{
      "original": "{secret}",
      "placeholder": "{placeholder}",
      "category": "secret",
      "rule": "aws-access-key-id"
    }}
  ]
}}"#
        );
        let plain_bytes = plain.into_bytes();
        fs::write(&path, &plain_bytes).unwrap();
        assert!(contains(&fs::read(&path).unwrap(), secret.as_bytes()));
        let loaded = Vault::load(&path).unwrap();
        assert_eq!(loaded.placeholder(secret), Some(placeholder));
        assert_eq!(loaded.category_of(secret), Some(Category::Secret));
        assert_eq!(loaded.rule_of(secret), Some("aws-access-key-id"));
        assert!(!loaded.is_dirty());
        let sealed = fs::read(&path).unwrap();
        assert!(!contains(&sealed, secret.as_bytes()));
        let value: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        assert_eq!(value["version"].as_u64(), Some(2));
        let again = Vault::load(&path).unwrap();
        assert_eq!(again.placeholder(secret), Some(placeholder));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_key_does_not_migrate_plaintext() {
        let dir = temp_dir("vault-bad-key");
        let path = dir.join("vault.json");
        let plain = br#"{"version":1,"entries":[{"original":"keep-me-secret","placeholder":"@@sv:0123abcd@@","category":"secret"}]}"#;
        fs::write(&path, plain).unwrap();
        fs::write(vault_key_path(&path), b"not a key\n").unwrap();
        let err = expect_err(Vault::load(&path));
        assert_refused(&err);
        assert!(
            err_text(&err).contains("not a SymVeil vault key"),
            "{}",
            err_text(&err)
        );
        assert_eq!(fs::read(&path).unwrap(), plain);
        assert_eq!(fs::read(vault_key_path(&path)).unwrap(), b"not a key\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_key_does_not_replace_a_sealed_vault() {
        let dir = temp_dir("vault-missing-key");
        let path = saved_secret(&dir, "vault.json", "missing-key-secret-55c0");
        let sealed = fs::read(&path).unwrap();
        fs::remove_file(vault_key_path(&path)).unwrap();
        let err = expect_err(Vault::load(&path));
        let text = err_text(&err);
        assert_refused(&err);
        assert!(text.contains("missing"), "{text}");
        assert_eq!(fs::read(&path).unwrap(), sealed);
        assert!(!vault_key_path(&path).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_does_not_replace_the_vault() {
        let dir = temp_dir("vault-wrong-key");
        let path = saved_secret(&dir, "vault.json", "wrong-key-secret-9c1e");
        let other = saved_secret(&dir, "other.json", "different-value");
        let sealed = fs::read(&path).unwrap();
        let wrong = fs::read(vault_key_path(&other)).unwrap();
        fs::copy(vault_key_path(&other), vault_key_path(&path)).unwrap();
        let err = expect_err(Vault::load(&path));
        let text = err_text(&err);
        assert_refused(&err);
        assert!(
            text.contains("does not match") || text.contains("decrypt"),
            "{text}"
        );
        assert_eq!(fs::read(&path).unwrap(), sealed);
        assert_eq!(fs::read(vault_key_path(&path)).unwrap(), wrong);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_ciphertext_is_left_in_place() {
        let dir = temp_dir("vault-tamper");
        let path = saved_secret(&dir, "vault.json", "tamper-secret-18de");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut chars = value["ciphertext"]
            .as_str()
            .unwrap()
            .to_string()
            .into_bytes();
        let index = chars.len() / 2;
        chars[index] = if chars[index] == b'A' { b'B' } else { b'A' };
        value["ciphertext"] = serde_json::Value::String(String::from_utf8(chars).unwrap());
        let tampered = serde_json::to_vec_pretty(&value).unwrap();
        fs::write(&path, &tampered).unwrap();
        let err = expect_err(Vault::load(&path));
        assert_refused(&err);
        assert_eq!(fs::read(&path).unwrap(), tampered);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_vaults_are_not_replaced() {
        let cases: &[(&str, &[u8])] = &[
            ("empty", b""),
            ("junk", b"{not-json"),
            ("array", b"[]"),
            ("version", br#"{"version":9,"entries":[]}"#),
            (
                "mixed",
                br#"{"version":1,"cipher":"aes-256-gcm","entries":[]}"#,
            ),
            (
                "cipher",
                br#"{"version":2,"cipher":"rot13","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}"#,
            ),
        ];
        for (label, body) in cases {
            let dir = temp_dir(&format!("vault-bad-{label}"));
            let path = dir.join("vault.json");
            fs::write(&path, body).unwrap();
            let err = expect_err(Vault::load(&path));
            assert_refused(&err);
            assert_eq!(fs::read(&path).unwrap(), *body, "{label}");
            assert!(!vault_key_path(&path).exists(), "{label}");
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn new_vault_directory_and_files_are_owner_only() {
        let root = temp_dir("vault-mode-new");
        let root_mode = mode_bits(&root);
        let path = root.join(".symveil").join("vault.json");
        let mut vault = Vault::create(path.clone());
        vault.assign("mode-secret", Category::Secret, None).unwrap();
        vault.save().unwrap();
        assert_eq!(mode_bits(&root), root_mode);
        assert_eq!(mode_bits(&root.join(".symveil")), 0o700);
        assert_eq!(mode_bits(&path), 0o600);
        assert_eq!(mode_bits(&vault_key_path(&path)), 0o600);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn existing_directory_mode_is_not_changed() {
        let dir = temp_dir("vault-mode-keep");
        let before = mode_bits(&dir);
        let path = dir.join("vault.json");
        fs::write(&path, b"placeholder").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        let plain = br#"{"version":1,"entries":[{"original":"mode-secret","placeholder":"@@sv:89abcdef@@","category":"secret"}]}"#;
        fs::write(&path, plain).unwrap();
        assert_eq!(mode_bits(&path), 0o644);
        Vault::load(&path).unwrap();
        assert_eq!(mode_bits(&dir), before);
        assert_eq!(mode_bits(&path), 0o600);
        assert_eq!(mode_bits(&vault_key_path(&path)), 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    fn saved_secret(dir: &Path, name: &str, secret: &str) -> PathBuf {
        let path = dir.join(name);
        let mut vault = Vault::create(path.clone());
        vault
            .assign(secret, Category::Secret, Some("rule".into()))
            .unwrap();
        vault.save().unwrap();
        path
    }
}
