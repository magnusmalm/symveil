use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

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

/// What a rule does when it matches.
///
/// A missing action means [`Action::Redact`], which is the behavior of configs
/// written before actions existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Replace the match with a placeholder and restore it in the response.
    #[default]
    Redact,
    /// Forward the match unchanged, record an audit entry, and log a warning.
    Warn,
    /// Refuse the request before contacting upstream.
    Block,
}

impl Action {
    fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "redact" => Ok(Self::Redact),
            "warn" => Ok(Self::Warn),
            "block" => Ok(Self::Block),
            other => Err(format!(
                "unknown action `{other}`; expected \"redact\", \"warn\", or \"block\""
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Redact => "redact",
            Self::Warn => "warn",
            Self::Block => "block",
        })
    }
}

/// Whether configured actions are honored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Honor each rule action. With no actions set, every match is redacted.
    #[default]
    Enforce,
    /// Treat every match as [`Action::Warn`], including rules set to block.
    Observe,
}

impl Mode {
    fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "enforce" => Ok(Self::Enforce),
            "observe" => Ok(Self::Observe),
            other => Err(format!(
                "unknown redact mode `{other}`; expected \"enforce\" or \"observe\""
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Enforce => "enforce",
            Self::Observe => "observe",
        })
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

/// A user secret rule from `[[redact.secrets]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRule {
    pub name: String,
    pub regex: String,
    /// `None` inherits `[redact.builtin]`, then `[redact.category] secret`,
    /// then [`Action::Redact`].
    #[serde(default)]
    pub action: Option<Action>,
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
    /// `enforce` honors each action. `observe` turns every match into a warning.
    #[serde(default)]
    pub mode: Mode,
    /// Default action for the `secret`, `ip`, and `hostname` categories.
    #[serde(default, rename = "category")]
    pub category_actions: HashMap<String, Action>,
    /// Action for one builtin detector, by rule name.
    #[serde(default, rename = "builtin")]
    pub builtin_actions: HashMap<String, Action>,
    #[serde(default)]
    pub patterns: Vec<UserPattern>,
    #[serde(default)]
    pub secrets: Vec<SecretRule>,
}

impl Default for RedactSection {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            internal_domains: default_domains(),
            mode: Mode::Enforce,
            category_actions: HashMap::new(),
            builtin_actions: HashMap::new(),
            patterns: Vec::new(),
            secrets: Vec::new(),
        }
    }
}

impl RedactSection {
    pub fn validate(&self) -> Result<()> {
        for name in self.category_actions.keys() {
            if !matches!(name.as_str(), "secret" | "ip" | "hostname") {
                anyhow::bail!(
                    "unknown category `{name}` in [redact.category]; expected \"secret\", \"ip\", or \"hostname\". Builtin detectors such as \"private-key\" and \"ipv4\" belong in [redact.builtin]"
                );
            }
        }
        let known = known_builtin_rules();
        for name in self.builtin_actions.keys() {
            if !known.iter().any(|rule| *rule == name) {
                anyhow::bail!(
                    "unknown builtin rule `{name}` in [redact.builtin]; expected one of: {}",
                    known.join(", ")
                );
            }
        }
        Ok(())
    }
}

fn known_builtin_rules() -> Vec<&'static str> {
    let mut names = crate::secrets::builtin_rule_names();
    names.extend_from_slice(crate::scan::NETWORK_RULES);
    names.sort_unstable();
    names.dedup();
    names
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
        Self::parse(&text).with_context(|| format!("parse config {}", path.display()))
    }

    /// Parse and validate a config document.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        self.redact.validate()
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
        assert_eq!(cfg.redact.mode, Mode::Enforce);
        assert!(cfg.redact.secrets.is_empty());
        assert!(cfg.redact.builtin_actions.is_empty());
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

    #[test]
    fn legacy_config_keeps_enforce_and_omits_action() {
        let cfg = Config::parse(
            r#"
            [redact]
            internal_domains = ["corp", "internal", "lan"]

            [[redact.secrets]]
            name = "acme-factory-token"
            regex = '\bacme_live_[A-Za-z0-9]{16,}\b'
            "#,
        )
        .unwrap();
        assert_eq!(cfg.redact.mode, Mode::Enforce);
        assert!(cfg.redact.secrets[0].action.is_none());
        assert!(cfg.redact.builtin_actions.is_empty());
        assert!(cfg.redact.category_actions.is_empty());
        assert_eq!(cfg.redact.internal_domains, vec!["corp", "internal", "lan"]);
    }

    #[test]
    fn documented_actions_parse() {
        let cfg = Config::parse(
            r#"
            [redact]
            mode = "Observe"

            [redact.category]
            secret = "block"
            ip = "warn"
            hostname = "redact"

            [redact.builtin]
            private-key = "block"
            aws-access-key-id = "redact"

            [[redact.secrets]]
            name = "acme-factory-token"
            regex = '\bacme_live_[A-Za-z0-9]{16,}\b'
            action = "WARN"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.redact.mode, Mode::Observe);
        assert_eq!(
            cfg.redact.category_actions.get("secret").copied(),
            Some(Action::Block)
        );
        assert_eq!(
            cfg.redact.category_actions.get("ip").copied(),
            Some(Action::Warn)
        );
        assert_eq!(
            cfg.redact.builtin_actions.get("private-key").copied(),
            Some(Action::Block)
        );
        assert_eq!(cfg.redact.secrets[0].action, Some(Action::Warn));
    }

    #[test]
    fn unknown_action_names_the_expected_values() {
        let err = Config::parse(
            r#"
            [[redact.secrets]]
            name = "acme"
            regex = "acme_live"
            action = "drop"
            "#,
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("unknown action `drop`"), "{message}");
        assert!(message.contains("\"redact\""), "{message}");
        assert!(message.contains("\"warn\""), "{message}");
        assert!(message.contains("\"block\""), "{message}");
    }

    #[test]
    fn unknown_builtin_category_and_mode_are_rejected() {
        let builtin = Config::parse(
            r#"
            [redact.builtin]
            nope = "block"
            "#,
        )
        .unwrap_err();
        let message = format!("{builtin:#}");
        assert!(message.contains("unknown builtin rule `nope`"), "{message}");
        assert!(message.contains("private-key"), "{message}");
        assert!(message.contains("aws-access-key-id"), "{message}");
        assert!(message.contains("ipv4"), "{message}");

        let category = Config::parse(
            r#"
            [redact.category]
            function = "warn"
            "#,
        )
        .unwrap_err();
        let message = format!("{category:#}");
        assert!(message.contains("unknown category `function`"), "{message}");
        assert!(message.contains("[redact.builtin]"), "{message}");

        let mode = Config::parse(
            r#"
            [redact]
            mode = "strict"
            "#,
        )
        .unwrap_err();
        let message = format!("{mode:#}");
        assert!(
            message.contains("unknown redact mode `strict`"),
            "{message}"
        );
        assert!(message.contains("enforce"), "{message}");
        assert!(message.contains("observe"), "{message}");
    }

    #[test]
    fn load_reports_an_unknown_action_with_the_config_path() {
        let dir = std::env::temp_dir().join(format!(
            "symveil-action-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".symveil.toml");
        std::fs::write(
            &path,
            "[[redact.secrets]]\nname = \"acme\"\nregex = \"x\"\naction = \"drop\"\n",
        )
        .unwrap();
        let err = Config::load(&path).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("unknown action `drop`"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
