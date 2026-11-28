use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use symveil_detect::learned::LearnedFile;
use symveil_detect::literals::literal_pattern;

#[path = "config_lenient.rs"]
mod lenient;

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

fn default_audit_buffered() -> bool {
    false
}

fn default_dotenv() -> bool {
    true
}

fn default_home_paths() -> bool {
    true
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
    /// When false, each audit line is flushed before the proxy continues.
    /// When true, lines stay in the process buffer until the proxy exits.
    /// A crash can lose the last lines still in that buffer.
    #[serde(default = "default_audit_buffered")]
    pub audit_buffered: bool,
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
            audit_buffered: default_audit_buffered(),
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

/// What to do with an inline image, document, or file content block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryMode {
    /// Replace the block with a short text note. This is the default.
    #[default]
    Block,
    /// Forward the block unchanged.
    Pass,
    /// Decode the payload and withhold the block when a term or detector matches.
    Scan,
}

impl BinaryMode {
    fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "pass" => Ok(Self::Pass),
            "scan" => Ok(Self::Scan),
            other => Err(format!(
                "unknown binary mode `{other}`; expected \"block\", \"pass\", or \"scan\""
            )),
        }
    }
}

impl<'de> Deserialize<'de> for BinaryMode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for BinaryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Block => "block",
            Self::Pass => "pass",
            Self::Scan => "scan",
        })
    }
}

/// `[binary]`. Missing means [`BinaryMode::Block`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BinarySection {
    pub mode: BinaryMode,
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

/// Opt-in personal-data rules. Every flag defaults to off.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PiiSection {
    pub email: bool,
    pub phone: bool,
    pub personnummer: bool,
}

impl PiiSection {
    pub fn enabled(&self) -> bool {
        self.email || self.phone || self.personnummer
    }
}

/// Company, product, project, and person names for the free-core masker.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NamesSection {
    pub terms: Vec<String>,
    /// Project-code regexes, used as written. `TDH-\d+` is a typical entry.
    pub patterns: Vec<UserPattern>,
    /// Person names. Each entry is `First Last` (more tokens are allowed).
    /// Matched case-insensitively as the full sequence, as `Last, First`, and
    /// as each token on a word boundary.
    pub people: Vec<String>,
}

impl NamesSection {
    pub fn enabled(&self) -> bool {
        !self.terms.is_empty() || !self.patterns.is_empty() || !self.people.is_empty()
    }
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
    /// Scan long high-entropy tokens that no builtin names. Off by default:
    /// mixed base64 blobs that are not credentials still match.
    #[serde(default)]
    pub high_entropy: bool,
    /// Redact every assignment value in dotenv-shaped text. On by default.
    /// Set false to keep only the suffix rules and the known token shapes.
    #[serde(default = "default_dotenv")]
    pub dotenv: bool,
    /// Mask the username in `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`,
    /// and `~user`, and mask the local username as a bare word. On by default.
    #[serde(default = "default_home_paths")]
    pub home_paths: bool,
    /// Bare-word username. When omitted, the process `USER` or `USERNAME` is
    /// used. A common account name is not masked as a bare word unless it is
    /// set here. Path forms still mask that name.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub pii: PiiSection,
    /// Company, product, project, and person names. Empty leaves names untouched.
    #[serde(default)]
    pub names: NamesSection,
    /// `learned.toml` from `symveil learn`. Relative to the repository root.
    /// When omitted, the proxy reads the user config path if that file exists.
    #[serde(default)]
    pub learned: Option<String>,
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
            high_entropy: false,
            dotenv: true,
            home_paths: true,
            username: None,
            pii: PiiSection::default(),
            names: NamesSection::default(),
            learned: None,
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
        crate::names::validate(&self.names)?;
        for rule in &self.secrets {
            if known.iter().any(|builtin| *builtin == rule.name) {
                anyhow::bail!(
                    "secret rule `{}` reuses the builtin rule name `{}`. Rename it. A custom rule cannot use a builtin detector name; set that detector's action in [redact.builtin].",
                    rule.name,
                    rule.name
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

/// How long [`Config::apply_learned_toml`] spent reading and merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LearnedLoadTiming {
    pub parse: std::time::Duration,
    pub merge: std::time::Duration,
}

/// Where a `learned.toml` would be read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnedOrigin {
    pub path: PathBuf,
    /// True when `[redact] learned` or `SYMVEIL_LEARNED` selected the path.
    /// A default user-config path is not configured.
    pub configured: bool,
}

/// Counts from a learned file. The strings are not returned.
///
/// `terms` and `people` are the name matcher. `secrets`, `emails`, `ips`,
/// `hosts`, `domains`, and `symbols` are rules the secret scanner enforces.
/// `keeps` is the allow list. `skips` are resume rows and are not matched.
/// `decisions` is every resume row, including redact and keep. It is not the
/// term count: a redact decision is a term, a person, or one scanner rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LearnedCounts {
    pub terms: usize,
    pub people: usize,
    pub secrets: usize,
    pub emails: usize,
    pub ips: usize,
    pub hosts: usize,
    pub domains: usize,
    pub symbols: usize,
    pub skips: usize,
    pub keeps: usize,
    /// Resume rows in the file. This is the decision count, not `terms`.
    pub decisions: usize,
}

impl LearnedCounts {
    /// Parse `learned.toml` and return counts only.
    ///
    /// The error does not include the file body. Callers must not format a
    /// raw `learned.toml` parse error: it can quote terms and secrets.
    pub fn parse(text: &str) -> Result<Self> {
        let file =
            LearnedFile::parse(text).map_err(|_| anyhow!("learned file could not be parsed"))?;
        Ok(Self::from_file(&file))
    }

    pub fn from_file(file: &LearnedFile) -> Self {
        let mut counts = Self {
            terms: file.names.terms.len(),
            people: file.names.people.len(),
            symbols: file.symbols.len(),
            keeps: file.allow.entries.len(),
            skips: file
                .decisions
                .iter()
                .filter(|decision| decision.action == "skip")
                .count(),
            decisions: file.decisions.len(),
            ..Self::default()
        };
        for rule in &file.secrets {
            match learned_rule_category(&rule.name) {
                Some("email") => counts.emails += 1,
                Some("ip") => counts.ips += 1,
                Some("host") => counts.hosts += 1,
                Some("domain") => counts.domains += 1,
                Some("symbol") => counts.symbols += 1,
                Some(_) | None => counts.secrets += 1,
            }
        }
        counts
    }
}

fn learned_rule_category(name: &str) -> Option<&str> {
    let (head, hash) = name.rsplit_once('-')?;
    if hash.len() != 16 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    head.strip_prefix("learned-")
}

/// A config plus keys the strict parser would reject.
#[derive(Debug, Clone)]
pub struct LenientConfig {
    pub config: Config,
    pub unknown_keys: Vec<String>,
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
    /// Inline image, document, and file blocks. The default withholds them.
    #[serde(default)]
    pub binary: BinarySection,
    /// Set when a learned file was merged. Not part of `.symveil.toml`.
    #[serde(skip)]
    pub learned_loaded: bool,
    /// Counts from that file. Empty until a file loads.
    #[serde(skip)]
    pub learned_counts: LearnedCounts,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut cfg = Self::load_file(path)?;
        let root = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        cfg.merge_discovered_learned(root)?;
        Ok(cfg)
    }

    fn load_file(path: &Path) -> Result<Self> {
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

    /// Parse a document, drop unknown keys, and list them.
    ///
    /// Known fields keep their values. [`Config::parse`] still rejects the
    /// same document, which is what `proxy` uses at startup.
    pub fn parse_lenient(text: &str) -> Result<LenientConfig> {
        lenient::parse(text)
    }

    /// Path of the learned file this config would merge, if any source exists.
    pub fn learned_origin(&self, root: &Path) -> Option<LearnedOrigin> {
        if let Some(configured) = &self.redact.learned {
            return Some(LearnedOrigin {
                path: resolve_path(root, configured),
                configured: true,
            });
        }
        if let Some(path) = learned_env_path() {
            return Some(LearnedOrigin {
                path,
                configured: true,
            });
        }
        symveil_detect::learned::default_path().map(|path| LearnedOrigin {
            path,
            configured: false,
        })
    }

    fn validate(&self) -> Result<()> {
        self.redact.validate()
    }

    /// Load `explicit` when given, otherwise the nearest `.symveil.toml` at or above `root`.
    ///
    /// A `learned.toml` is merged afterwards: `[redact] learned` if set, else
    /// `SYMVEIL_LEARNED`, else the user config file when it exists. Missing
    /// default path is not an error. Learn does not call this function.
    pub fn load_for(root: &Path, explicit: Option<&Path>) -> Result<Self> {
        let mut cfg = if let Some(path) = explicit {
            Self::load_file(path)?
        } else if let Some(path) = discover(root) {
            Self::load_file(&path)?
        } else {
            Self::default()
        };
        cfg.merge_discovered_learned(root)?;
        Ok(cfg)
    }

    /// Merge a `learned.toml` document into this config.
    pub fn apply_learned_toml(&mut self, text: &str) -> Result<()> {
        self.apply_learned_toml_timed(text)?;
        Ok(())
    }

    /// Merge a learned document and report parse time separately from the
    /// merge. Parse is the toml read. Merge copies rules into this config and
    /// checks ones that are not literals. Neither duration includes engine
    /// startup.
    pub fn apply_learned_toml_timed(&mut self, text: &str) -> Result<LearnedLoadTiming> {
        let started = std::time::Instant::now();
        let file = LearnedFile::parse(text)?;
        let parse = started.elapsed();
        let started = std::time::Instant::now();
        self.apply_learned_file(&file)?;
        Ok(LearnedLoadTiming {
            parse,
            merge: started.elapsed(),
        })
    }

    /// Merge an already-parsed learned file. Literals are not compiled here;
    /// the secret scanner builds one automaton for them.
    pub fn apply_learned_file(&mut self, file: &LearnedFile) -> Result<()> {
        self.merge_learned(file)
    }

    fn merge_learned(&mut self, file: &LearnedFile) -> Result<()> {
        let mut terms: HashSet<String> = self.redact.names.terms.iter().cloned().collect();
        let mut people: HashSet<String> = self.redact.names.people.iter().cloned().collect();
        let mut allow: HashSet<String> = self.redact.allow.iter().cloned().collect();
        for term in &file.names.terms {
            push_unique(&mut self.redact.names.terms, &mut terms, term);
        }
        for person in &file.names.people {
            push_unique(&mut self.redact.names.people, &mut people, person);
        }
        for entry in &file.allow.entries {
            push_unique(&mut self.redact.allow, &mut allow, entry);
        }
        let mut names: HashSet<String> = self
            .redact
            .secrets
            .iter()
            .map(|rule| rule.name.clone())
            .collect();
        for rule in file.secrets.iter().chain(file.symbols.iter()) {
            if !names.insert(rule.name.clone()) {
                anyhow::bail!(
                    "learned rule `{}` uses the same name as a secret rule already in the config",
                    rule.name
                );
            }
            if literal_pattern(&rule.regex).is_none() {
                Regex::new(&rule.regex).with_context(|| format!("learned rule `{}`", rule.name))?;
            }
            self.redact.secrets.push(SecretRule {
                name: rule.name.clone(),
                regex: rule.regex.clone(),
                action: None,
            });
        }
        self.learned_counts = LearnedCounts::from_file(file);
        self.learned_loaded = true;
        self.validate()
    }

    fn merge_discovered_learned(&mut self, root: &Path) -> Result<()> {
        let Some(path) = self.learned_source(root) else {
            return Ok(());
        };
        if !path.is_file() {
            if self.redact.learned.is_some() || learned_env_is_set() {
                anyhow::bail!("learned file {} does not exist", path.display());
            }
            return Ok(());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read learned rules {}", path.display()))?;
        self.apply_learned_toml(&text)
            .with_context(|| format!("parse learned rules {}", path.display()))
    }

    fn learned_source(&self, root: &Path) -> Option<PathBuf> {
        self.learned_origin(root).map(|origin| origin.path)
    }
}

fn push_unique(list: &mut Vec<String>, seen: &mut HashSet<String>, value: &str) {
    if value.is_empty() || !seen.insert(value.to_string()) {
        return;
    }
    list.push(value.to_string());
}

fn learned_env_path() -> Option<PathBuf> {
    let value = std::env::var_os("SYMVEIL_LEARNED")?;
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn learned_env_is_set() -> bool {
    learned_env_path().is_some()
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
        assert!(!cfg.proxy.audit_buffered);
        assert_eq!(cfg.proxy.listen, "127.0.0.1");
        assert_eq!(cfg.proxy.openai_base, "https://api.openai.com");
        assert_eq!(cfg.redact.internal_domains, vec!["corp", "internal", "lan"]);
        assert_eq!(cfg.redact.mode, Mode::Enforce);
        assert_eq!(cfg.binary.mode, BinaryMode::Block);
        assert!(cfg.redact.secrets.is_empty());
        assert!(cfg.redact.builtin_actions.is_empty());
        assert!(!cfg.redact.high_entropy);
        assert!(!cfg.redact.pii.enabled());
    }

    #[test]
    fn audit_buffer_is_off_unless_set() {
        assert!(!Config::default().proxy.audit_buffered);
        let buffered: Config = toml::from_str("[proxy]\naudit_buffered = true\n").unwrap();
        assert!(buffered.proxy.audit_buffered);
        let line: Config = toml::from_str("[proxy]\naudit_buffered = false\n").unwrap();
        assert!(!line.proxy.audit_buffered);
    }

    #[test]
    fn pii_section_is_off_unless_a_flag_is_set() {
        let cfg = Config::default();
        assert!(!cfg.redact.pii.email);
        assert!(!cfg.redact.pii.phone);
        assert!(!cfg.redact.pii.personnummer);

        let cfg: Config = toml::from_str("[redact]\n").unwrap();
        assert!(!cfg.redact.pii.enabled());

        let cfg: Config =
            toml::from_str("[redact.pii]\nemail = true\npersonnummer = true\n").unwrap();
        assert!(cfg.redact.pii.email);
        assert!(!cfg.redact.pii.phone);
        assert!(cfg.redact.pii.personnummer);

        let names: Config = toml::from_str(
            "[redact.names]\nterms = [\"Exempla\"]\npeople = [\"Ren Testdotter\"]\n",
        )
        .unwrap();
        assert_eq!(names.redact.names.terms, vec!["Exempla".to_string()]);
        assert_eq!(
            names.redact.names.people,
            vec!["Ren Testdotter".to_string()]
        );
        assert!(names.redact.names.patterns.is_empty());
        let legacy: Config = toml::from_str("[redact.names]\nterms = [\"Exempla\"]\n").unwrap();
        assert!(legacy.redact.names.people.is_empty());

        let err = toml::from_str::<Config>("[redact.pii]\nnames = true\n").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("names"),
            "unknown pii field should be named in the error: {message}"
        );
    }

    #[test]
    fn high_entropy_can_be_enabled() {
        let cfg: Config = toml::from_str("[redact]\nhigh_entropy = true\n").unwrap();
        assert!(cfg.redact.high_entropy);
    }

    #[test]
    fn dotenv_is_on_unless_the_config_turns_it_off() {
        assert!(RedactSection::default().dotenv);
        assert!(RedactSection::default().home_paths);
        assert!(RedactSection::default().username.is_none());
        let omitted: Config = toml::from_str("[redact]\nhigh_entropy = false\n").unwrap();
        assert!(omitted.redact.dotenv);
        assert!(omitted.redact.home_paths);
        let off: Config =
            toml::from_str("[redact]\ndotenv = false\nhome_paths = false\nusername = \"jdoe\"\n")
                .unwrap();
        assert!(!off.redact.dotenv);
        assert!(!off.redact.home_paths);
        assert_eq!(off.redact.username.as_deref(), Some("jdoe"));
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

    #[test]
    fn a_custom_rule_cannot_reuse_a_builtin_name() {
        let dir = std::env::temp_dir().join(format!(
            "symveil-builtin-name-{}-{}",
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
            "[[redact.secrets]]\nname = \"aws-access-key-id\"\nregex = 'AKIA[0-9A-Z]{16}'\naction = \"warn\"\n",
        )
        .unwrap();
        let err = Config::load(&path).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("aws-access-key-id"), "{message}");
        assert!(message.contains("Rename"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");

        std::fs::write(
            &path,
            "[[redact.secrets]]\nname = \"acme-factory-token\"\nregex = '\\bacme_live_[A-Za-z0-9]{16,}\\b'\naction = \"warn\"\n",
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.redact.secrets.len(), 1);
        assert_eq!(cfg.redact.secrets[0].name, "acme-factory-token");
        assert_eq!(cfg.redact.secrets[0].action, Some(Action::Warn));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn binary_mode_defaults_to_block_and_rejects_unknown_values() {
        let cfg = Config::parse("[redact]\n").unwrap();
        assert_eq!(cfg.binary.mode, BinaryMode::Block);
        let pass = Config::parse("[binary]\nmode = \"PASS\"\n").unwrap();
        assert_eq!(pass.binary.mode, BinaryMode::Pass);
        let scan = Config::parse("[binary]\nmode = \"scan\"\n").unwrap();
        assert_eq!(scan.binary.mode, BinaryMode::Scan);
        let err = Config::parse("[binary]\nmode = \"drop\"\n").unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("unknown binary mode `drop`"), "{message}");
        assert!(message.contains("\"block\""), "{message}");
        assert!(message.contains("\"pass\""), "{message}");
        assert!(message.contains("\"scan\""), "{message}");
    }

    #[test]
    fn learned_file_merges_names_symbols_and_allow_into_the_engine() {
        let mut cfg = Config::parse("[redact]\ninternal_domains = []\n").unwrap();
        cfg.apply_learned_toml(
            r#"
            version = 1

            [names]
            terms = ["Exempla"]
            people = ["Ren Testdotter"]

            [[symbols]]
            name = "learned-symbol-fan"
            regex = '\baurora_rcc_enable_pll\b'

            [allow]
            entries = ["Tundrahorn", "AKIAIOSFODNN7EXAMPLE"]
            "#,
        )
        .unwrap();
        cfg.redact.names.terms.push("Tundrahorn".to_string());
        let mut engine =
            crate::redact::Engine::new(crate::vault::Vault::ephemeral(), &cfg.redact).unwrap();
        let input = "Exempla aurora_rcc_enable_pll Tundrahorn Ren Testdotter AKIAIOSFODNN7EXAMPLE";
        let (out, _) = engine.redact_str(input).unwrap();
        assert!(!out.contains("Exempla"), "{out}");
        assert!(!out.contains("aurora_rcc_enable_pll"), "{out}");
        assert!(!out.contains("Testdotter"), "{out}");
        assert!(out.contains("Tundrahorn"), "{out}");
        assert!(!out.contains("AKIA"), "{out}");
        assert_eq!(engine.restore_str(&out), input);
    }

    #[test]
    fn load_for_reads_an_explicit_learned_path() {
        let dir = std::env::temp_dir().join(format!(
            "symveil-learned-load-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("learned.toml"), "[names]\nterms = [\"Exempla\"]\n").unwrap();
        std::fs::write(
            dir.join(".symveil.toml"),
            "[redact]\nlearned = \"learned.toml\"\ninternal_domains = []\n",
        )
        .unwrap();
        let cfg = Config::load_for(&dir, None).unwrap();
        assert!(cfg.redact.names.terms.iter().any(|term| term == "Exempla"));

        std::fs::write(
            dir.join(".symveil.toml"),
            "[redact]\nlearned = \"missing.toml\"\n",
        )
        .unwrap();
        let err = Config::load_for(&dir, None).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("does not exist"), "{message}");
        assert!(message.contains("missing.toml"), "{message}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lenient_parse_keeps_known_fields_and_names_unknown_keys() {
        let loaded = Config::parse_lenient(
            r#"
            [proxy]
            port = 9
            prot = 1

            [redact]
            high_entropy = true

            [redact.pii]
            email = true
            emial = true

            [redact.category]
            secret = "block"
            function = "warn"

            [redact.builtin]
            private-key = "block"
            not-a-rule = "warn"

            [[redact.secrets]]
            name = "acme-factory-token"
            regex = '\bacme_live_[A-Za-z0-9]{16,}\b'
            action = "warn"
            typo = "HiddenTermZZZ"

            [redact.names]
            terms = ["Exempla"]
            "#,
        )
        .unwrap();
        assert_eq!(loaded.config.proxy.port, 9);
        assert!(loaded.config.redact.high_entropy);
        assert!(loaded.config.redact.pii.email);
        assert_eq!(
            loaded.config.redact.secrets[0].regex,
            r"\bacme_live_[A-Za-z0-9]{16,}\b"
        );
        assert_eq!(
            loaded.config.redact.names.terms,
            vec!["Exempla".to_string()]
        );
        assert!(loaded
            .config
            .redact
            .builtin_actions
            .contains_key("private-key"));
        assert!(!loaded
            .config
            .redact
            .builtin_actions
            .contains_key("not-a-rule"));
        assert!(!loaded
            .config
            .redact
            .category_actions
            .contains_key("function"));
        for key in [
            "proxy.prot",
            "redact.pii.emial",
            "redact.category.function",
            "redact.builtin.not-a-rule",
            "redact.secrets[0].typo",
        ] {
            assert!(
                loaded.unknown_keys.iter().any(|found| found == key),
                "missing {key} in {:?}",
                loaded.unknown_keys
            );
        }
        let rendered = loaded.unknown_keys.join(" ");
        assert!(!rendered.contains("HiddenTermZZZ"), "{rendered}");
        assert!(!rendered.contains("Exempla"), "{rendered}");
        assert!(Config::parse("[proxy]\nprot = 1\n").is_err());
    }

    #[test]
    fn documented_config_has_no_unknown_keys() {
        let loaded = Config::parse_lenient(
            r#"
            [proxy]
            listen = "127.0.0.1"
            port = 8787
            openai_base = "https://api.openai.invalid"
            anthropic_base = "https://api.anthropic.invalid"
            timeout_secs = 900
            audit_log = ".symveil/audit.jsonl"
            audit_buffered = false
            vault = ".symveil/vault.json"

            [binary]
            mode = "block"

            [redact]
            mode = "enforce"
            internal_domains = ["example"]
            high_entropy = false
            dotenv = true
            home_paths = true

            [redact.category]
            secret = "redact"
            ip = "redact"
            hostname = "redact"

            [redact.builtin]
            private-key = "block"

            [[redact.secrets]]
            name = "acme-factory-token"
            regex = '\bacme_live_[A-Za-z0-9]{16,}\b'
            action = "warn"

            [redact.pii]
            email = true
            phone = false
            personnummer = true

            [redact.names]
            terms = ["Exempla"]
            people = ["Ren Testdotter"]

            [index]
            min_len = 4
            extensions = ["c", "h"]
            "#,
        )
        .unwrap();
        assert!(loaded.unknown_keys.is_empty(), "{:?}", loaded.unknown_keys);
        assert_eq!(loaded.config.proxy.port, 8787);
        assert_eq!(loaded.config.proxy.listen, "127.0.0.1");
        assert_eq!(loaded.config.binary.mode, BinaryMode::Block);
        assert_eq!(loaded.config.redact.mode, Mode::Enforce);
        assert!(loaded.config.redact.dotenv);
        assert!(loaded.config.redact.home_paths);
        assert!(loaded.config.redact.pii.email);
        assert!(!loaded.config.redact.pii.phone);
        assert!(loaded.config.redact.pii.personnummer);
        assert_eq!(
            loaded.config.redact.names.terms,
            vec!["Exempla".to_string()]
        );
        assert_eq!(
            loaded.config.redact.names.people,
            vec!["Ren Testdotter".to_string()]
        );
        assert_eq!(loaded.config.index.min_len, 4);
        assert_eq!(loaded.config.redact.secrets[0].name, "acme-factory-token");
        assert_eq!(
            loaded
                .config
                .redact
                .builtin_actions
                .get("private-key")
                .copied(),
            Some(Action::Block)
        );
        assert_eq!(
            loaded.config.redact.internal_domains,
            vec!["example".to_string()]
        );
    }

    #[test]
    fn learned_counts_hide_the_term_list() {
        let counts =
            LearnedCounts::parse("[names]\nterms = [\"Exempla\"]\npeople = [\"Ren Testdotter\"]\n")
                .unwrap();
        assert_eq!(counts.terms, 1);
        assert_eq!(counts.people, 1);
        assert_eq!(counts.secrets, 0);
        assert_eq!(counts.hosts, 0);
        assert_eq!(counts.symbols, 0);
        assert_eq!(counts.skips, 0);
        let err = LearnedCounts::parse("terms = [\"HiddenTermZZZ\"\n").unwrap_err();
        let message = format!("{err:#}");
        assert!(!message.contains("HiddenTermZZZ"), "{message}");
    }

    #[test]
    fn a_learned_rule_cannot_reuse_a_builtin_name() {
        let mut cfg = Config::default();
        let err = cfg
            .apply_learned_toml(
                "[[secrets]]\nname = \"aws-access-key-id\"\nregex = 'AKIA[0-9A-Z]{16}'\n",
            )
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("aws-access-key-id"), "{message}");
        assert!(message.contains("Rename"), "{message}");
    }
}
