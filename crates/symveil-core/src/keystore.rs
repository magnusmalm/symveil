//! Where the AES-256-GCM vault key is stored.
//!
//! The default is the OS keychain: macOS Keychain, Linux Secret Service, or
//! Windows Credential Manager, via the `keyring` crate. The account name is
//! `vault-key-` plus a random id stored in the vault file, so moving the file
//! does not lose the key. Older entries used a hash of the path and are
//! migrated on open. A file at `.symveil/vault.key` is used only when no
//! keychain can be opened. A locked keychain is not that case: startup fails
//! instead of writing a second key beside the vault.

#[cfg(test)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const SERVICE: &str = "symveil";

#[derive(Clone)]
pub(crate) enum Backend {
    /// The process keychain.
    #[cfg(not(test))]
    System,
    /// In-memory stand-in. Tests use it so they never need a real keychain.
    #[cfg(test)]
    Memory(std::sync::Arc<Mutex<HashMap<String, Zeroizing<[u8; 32]>>>>),
    /// No keychain. Forces the file fallback, including its warning.
    Unavailable,
}

impl Backend {
    #[cfg(test)]
    pub(crate) fn memory() -> Self {
        Self::Memory(std::sync::Arc::new(Mutex::new(HashMap::new())))
    }

    pub(crate) fn get(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, KeyFailure> {
        match self {
            Self::Unavailable => Err(KeyFailure::Unavailable(
                "this process has no OS keychain".to_string(),
            )),
            #[cfg(test)]
            Self::Memory(map) => {
                let guard = map.lock().unwrap_or_else(|err| err.into_inner());
                Ok(guard.get(account).cloned())
            }
            #[cfg(not(test))]
            Self::System => os_get(account),
        }
    }

    pub(crate) fn put(&self, account: &str, key: &[u8; 32]) -> Result<(), KeyFailure> {
        match self {
            Self::Unavailable => Err(KeyFailure::Unavailable(
                "this process has no OS keychain".to_string(),
            )),
            #[cfg(test)]
            Self::Memory(map) => {
                let mut guard = map.lock().unwrap_or_else(|err| err.into_inner());
                guard.insert(account.to_string(), Zeroizing::new(*key));
                Ok(())
            }
            #[cfg(not(test))]
            Self::System => os_put(account, key),
        }
    }

    pub(crate) fn delete(&self, account: &str) -> Result<(), KeyFailure> {
        match self {
            Self::Unavailable => Err(KeyFailure::Unavailable(
                "this process has no OS keychain".to_string(),
            )),
            #[cfg(test)]
            Self::Memory(map) => {
                let mut guard = map.lock().unwrap_or_else(|err| err.into_inner());
                guard.remove(account);
                Ok(())
            }
            #[cfg(not(test))]
            Self::System => os_delete(account),
        }
    }
}

pub(crate) enum KeyFailure {
    /// Nothing to store a key in. The caller may use `.symveil/vault.key`.
    Unavailable(String),
    /// A keychain is there and the call failed. Do not write a second key.
    /// The OS backend is the only constructor, and unit tests do not build it.
    #[cfg_attr(test, allow(dead_code))]
    Failed(String),
}

#[derive(Clone)]
pub(crate) enum KeyHome {
    Keychain { account: String },
    File(PathBuf),
}

impl KeyHome {
    pub(crate) fn line(&self) -> String {
        match self {
            Self::Keychain { account } => {
                format!("OS keychain (service {SERVICE}, account {account})")
            }
            Self::File(path) => path.display().to_string(),
        }
    }
}

pub(crate) fn key_account_for_id(id: &str) -> String {
    format!("vault-key-{id}")
}

/// Account used before the vault file carried its own id. Opening that vault
/// at the same path copies the key onto [`key_account_for_id`] and deletes this
/// entry.
pub(crate) fn legacy_key_account(vault: &Path) -> String {
    let canonical = std::fs::canonicalize(vault).unwrap_or_else(|_| vault.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("vault-key-{hex}")
}

pub(crate) fn warn_file_fallback(path: &Path, reason: &str) {
    static WARNED: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(Vec::new()));
    let mut seen = warned.lock().unwrap_or_else(|err| err.into_inner());
    if seen.iter().any(|item| item == path) {
        return;
    }
    seen.push(path.to_path_buf());
    drop(seen);
    eprintln!(
        "symveil: warning: no OS keychain is available ({reason}). The vault key is stored in {}. Anyone who copies this directory can decrypt the vault. macOS Keychain, Linux Secret Service, or Windows Credential Manager keeps the key out of the directory.",
        path.display()
    );
    let _ = std::io::Write::flush(&mut std::io::stderr());
}

#[cfg(not(test))]
fn os_get(account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, KeyFailure> {
    if let Err(err) = keyring::Entry::store_status() {
        return Err(KeyFailure::Unavailable(err.to_string()));
    }
    let entry = keyring::Entry::new(SERVICE, account).map_err(classify)?;
    match entry.get_secret() {
        Ok(bytes) => match bytes.as_slice().try_into() {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(_) => Err(KeyFailure::Failed(format!(
                "OS keychain entry {SERVICE}/{account} is not a 32-byte vault key"
            ))),
        },
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(classify(err)),
    }
}

#[cfg(not(test))]
fn os_put(account: &str, key: &[u8; 32]) -> Result<(), KeyFailure> {
    if let Err(err) = keyring::Entry::store_status() {
        return Err(KeyFailure::Unavailable(err.to_string()));
    }
    let entry = keyring::Entry::new(SERVICE, account).map_err(classify)?;
    entry.set_secret(key).map_err(classify)
}

#[cfg(not(test))]
fn os_delete(account: &str) -> Result<(), KeyFailure> {
    if let Err(err) = keyring::Entry::store_status() {
        return Err(KeyFailure::Unavailable(err.to_string()));
    }
    let entry = keyring::Entry::new(SERVICE, account).map_err(classify)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(classify(err)),
    }
}

#[cfg(not(test))]
fn classify(err: keyring::Error) -> KeyFailure {
    match err {
        keyring::Error::NoDefaultStore => KeyFailure::Unavailable(err.to_string()),
        other => KeyFailure::Failed(other.to_string()),
    }
}
