use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::category::Category;

pub const VAULT_VERSION: u32 = 1;
pub const TOKEN_LEN: usize = 15;

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

#[derive(Debug, Clone)]
pub struct Vault {
    path: Option<PathBuf>,
    entries: BTreeMap<String, Entry>,
    reverse: HashMap<String, String>,
    dirty: bool,
}

impl Vault {
    pub fn ephemeral() -> Self {
        Self {
            path: None,
            entries: BTreeMap::new(),
            reverse: HashMap::new(),
            dirty: false,
        }
    }

    pub fn create(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            entries: BTreeMap::new(),
            reverse: HashMap::new(),
            dirty: false,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("read vault {}", path.display()))?;
        let file: VaultFile = serde_json::from_slice(&data)
            .with_context(|| format!("parse vault {}", path.display()))?;
        if file.version != VAULT_VERSION {
            anyhow::bail!(
                "unsupported vault version {} in {} (this build reads version {VAULT_VERSION})",
                file.version,
                path.display()
            );
        }
        let mut vault = Self::create(path.to_path_buf());
        for entry in file.entries {
            if let Some(other) = vault.reverse.get(&entry.placeholder) {
                if other != &entry.original {
                    anyhow::bail!("vault {} has a placeholder collision", path.display());
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

    pub fn save(&mut self) -> Result<()> {
        let Some(path) = self.path.clone() else {
            self.dirty = false;
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
        }
        let entries: Vec<Entry> = self.entries.values().cloned().collect();
        let file = VaultFile {
            version: VAULT_VERSION,
            entries,
        };
        let data = serde_json::to_vec_pretty(&file)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &data).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("replace vault {}", path.display()))?;
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
            anyhow::bail!("refusing to assign a placeholder to an empty string");
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
        anyhow::bail!(
            "could not mint a unique placeholder for a value of length {}",
            original.len()
        )
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
        let dir = std::env::temp_dir().join(format!(
            "symveil-vault-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.json");
        let mut vault = Vault::create(path.clone());
        let token = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        vault.save().unwrap();
        assert!(!vault.is_dirty());
        let loaded = Vault::load(&path).unwrap();
        assert_eq!(
            loaded.placeholder("aurora_rcc_enable_pll"),
            Some(token.as_str())
        );
        assert!(!loaded.is_dirty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
