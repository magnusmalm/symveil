use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

fn default_listen() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8787
}

fn default_openai() -> String {
    "https://api.openai.com".to_string()
}

fn default_anthropic() -> String {
    "https://api.anthropic.com".to_string()
}

fn default_timeout() -> u64 {
    900
}

fn default_audit() -> String {
    ".symveil/audit.jsonl".to_string()
}

fn default_vault() -> String {
    ".symveil/vault.json".to_string()
}

fn default_min_len() -> usize {
    4
}

fn default_extensions() -> Vec<String> {
    [
        "c", "h", "cc", "cpp", "cxx", "hh", "hpp", "hxx", "dts", "dtsi",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_domains() -> Vec<String> {
    vec![
        "corp".to_string(),
        "internal".to_string(),
        "lan".to_string(),
    ]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProxySection {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_openai")]
    pub openai_base: String,
    #[serde(default = "default_anthropic")]
    pub anthropic_base: String,
    /// Overall upstream timeout. Zero waits without a deadline.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_audit")]
    pub audit_log: String,
    #[serde(default = "default_vault")]
    pub vault: String,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            port: default_port(),
            openai_base: default_openai(),
            anthropic_base: default_anthropic(),
            timeout_secs: default_timeout(),
            audit_log: default_audit(),
            vault: default_vault(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IndexSection {
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,
}

impl Default for IndexSection {
    fn default() -> Self {
        Self {
            min_len: default_min_len(),
            extensions: default_extensions(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPattern {
    pub name: String,
    pub regex: String,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RedactSection {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default = "default_domains")]
    pub internal_domains: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<UserPattern>,
    #[serde(default)]
    pub secrets: Vec<UserPattern>,
}

impl Default for RedactSection {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            internal_domains: default_domains(),
            patterns: Vec::new(),
            secrets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub index: IndexSection,
    #[serde(default)]
    pub redact: RedactSection,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))
    }

    /// Load `explicit` when given, otherwise the nearest `.symveil.toml` at or above `root`.
    pub fn load_for(root: &Path, explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            return Self::load(path);
        }
        if let Some(path) = discover(root) {
            return Self::load(&path);
        }
        Ok(Self::default())
    }
}

pub fn discover(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent()?.to_path_buf()
    };
    loop {
        let candidate = dir.join(".symveil.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn resolve_path(root: &Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_proxy_section_keeps_defaults() {
        let cfg: Config = toml::from_str("[proxy]\nport = 9\n").unwrap();
        assert_eq!(cfg.proxy.port, 9);
        assert_eq!(cfg.proxy.listen, "127.0.0.1");
        assert_eq!(cfg.proxy.openai_base, "https://api.openai.com");
        assert_eq!(cfg.redact.internal_domains, vec!["corp", "internal", "lan"]);
    }

    #[test]
    fn discover_walks_to_parent() {
        let dir = std::env::temp_dir().join(format!(
            "symveil-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let nested = dir.join("src");
        std::fs::create_dir_all(&nested).unwrap();
        let cfg_path = dir.join(".symveil.toml");
        std::fs::write(&cfg_path, "[proxy]\nport = 4242\n").unwrap();
        let found = discover(&nested).unwrap();
        assert_eq!(found, cfg_path);
        let loaded = Config::load_for(&nested, None).unwrap();
        assert_eq!(loaded.proxy.port, 4242);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
