//! `learned.toml`, the file `symveil learn` writes and the proxy merges.
//!
//! The document has no proxy or upstream fields. A `[proxy]` table is rejected.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// `$XDG_CONFIG_HOME/symveil/learned.toml`, or `~/.config/symveil/learned.toml`.
/// `None` when no home directory is set. This does not read proxy settings.
pub fn default_path() -> Option<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if xdg.is_empty() {
            home_config_dir()?
        } else {
            PathBuf::from(xdg)
        }
    } else {
        home_config_dir()?
    };
    Some(base.join("symveil").join("learned.toml"))
}

fn home_config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let value = std::env::var_os("APPDATA")?;
        if value.is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        }
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")?;
        if home.is_empty() {
            None
        } else {
            Some(PathBuf::from(home).join(".config"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub names: LearnedNames,
    #[serde(default)]
    pub secrets: Vec<LearnedRule>,
    #[serde(default)]
    pub symbols: Vec<LearnedRule>,
    #[serde(default)]
    pub allow: LearnedAllow,
    /// Resume state for a later `symveil learn`. The proxy does not match on
    /// these rows. It enforces `names.terms`, `names.people`, `secrets`
    /// (secrets, emails, ips, hosts, and domains), `symbols`, and `allow`.
    /// A `skip` row is remembered and is not a rule.
    #[serde(default)]
    pub decisions: Vec<DecisionRecord>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LearnedNames {
    pub terms: Vec<String>,
    pub people: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedRule {
    pub name: String,
    pub regex: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LearnedAllow {
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub key: String,
    pub action: String,
    pub category: String,
    pub text: String,
}

impl LearnedFile {
    pub fn parse(text: &str) -> Result<Self> {
        // The writer emits one regular shape. toml's parser builds a document
        // tree first, and that tree is most of a 200k-decision load. Anything
        // the direct reader does not recognize is still read here.
        let file = match crate::learned_fast::try_parse(text) {
            Ok(file) => file,
            Err(crate::learned_fast::Reject::Unsupported) => {
                toml::from_str(text).context("parse learned.toml")?
            }
            Err(crate::learned_fast::Reject::Invalid(err)) => return Err(err),
        };
        check_learned(file)
    }

    pub fn to_toml(&self) -> Result<String> {
        if self.version != 1 {
            bail!("refusing to write learned.toml version {}", self.version);
        }
        // serde's pretty writer spends most of a 200k-decision save on
        // per-field reflection. This writes the same document.
        let mut body = String::with_capacity(
            HEADER.len()
                + 160 * (self.decisions.len() + self.secrets.len() + self.symbols.len() + 8),
        );
        body.push_str(HEADER);
        body.push_str("version = 1\n\n[names]\n");
        push_string_list(&mut body, "terms", &self.names.terms);
        push_string_list(&mut body, "people", &self.names.people);
        body.push('\n');
        for rule in &self.secrets {
            push_rule(&mut body, "secrets", rule);
        }
        for rule in &self.symbols {
            push_rule(&mut body, "symbols", rule);
        }
        body.push_str("[allow]\n");
        push_string_list(&mut body, "entries", &self.allow.entries);
        body.push('\n');
        for decision in &self.decisions {
            body.push_str("[[decisions]]\n");
            push_pair(&mut body, "key", &decision.key);
            push_pair(&mut body, "action", &decision.action);
            push_pair(&mut body, "category", &decision.category);
            push_pair(&mut body, "text", &decision.text);
            body.push('\n');
        }
        Ok(body)
    }
}

fn check_learned(file: LearnedFile) -> Result<LearnedFile> {
    if file.version != 1 {
        bail!(
            "learned.toml version {} is not supported (this build reads version 1)",
            file.version
        );
    }
    for rule in file.secrets.iter().chain(file.symbols.iter()) {
        if rule.name.is_empty() {
            bail!("a learned rule needs a name");
        }
        if rule.regex.is_empty() {
            bail!("learned rule `{}` has an empty regex", rule.name);
        }
    }
    for decision in &file.decisions {
        if decision.action != "redact" && decision.action != "keep" && decision.action != "skip" {
            bail!(
                "learned decision `{}` has action `{}`; expected \"redact\", \"keep\", or \"skip\"",
                decision.key,
                decision.action
            );
        }
        if decision.text.is_empty() {
            bail!("learned decision `{}` has empty text", decision.key);
        }
    }
    Ok(file)
}

fn push_string_list(out: &mut String, key: &str, values: &[String]) {
    out.push_str(key);
    out.push_str(" = [");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_basic_string(out, value);
    }
    out.push_str("]\n");
}

fn push_rule(out: &mut String, table: &str, rule: &LearnedRule) {
    out.push_str("[[");
    out.push_str(table);
    out.push_str("]]\n");
    push_pair(out, "name", &rule.name);
    push_pair(out, "regex", &rule.regex);
    out.push('\n');
}

fn push_pair(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    push_basic_string(out, value);
    out.push('\n');
}

fn push_basic_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => {
                out.push_str(&format!("\\u{:04X}", u32::from(other)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

const HEADER: &str = "\
# Written by `symveil learn`. The proxy merges names, secrets, symbols, and allow.
# This file is not a guarantee that every secret or name was found.
# It has no upstream URL. The scan that produced it does not open a network connection.
# Mode 0600. `decisions` is how a later `symveil learn` skips choices you already made.
# Editing `decisions` and the lists by hand can make them diverge; the next learn run
# rewrites the lists from `decisions`.

";

#[cfg(test)]
mod tests {
    use super::LearnedFile;

    #[test]
    fn proxy_table_is_rejected() {
        let err = LearnedFile::parse("[proxy]\nlisten = \"127.0.0.1\"\n").unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("proxy"),
            "error should name the rejected table: {message}"
        );
    }

    #[test]
    fn round_trip_keeps_rules_and_decisions() {
        let text = r#"
version = 1

[names]
terms = ["Exempla"]
people = ["Ren Testdotter"]

[[secrets]]
name = "learned-secret-example"
regex = "svcn_learn_token_0001"

[[symbols]]
name = "learned-symbol-example"
regex = "\\btundrahorn_fan_init\\b"

[allow]
entries = ["threshold"]

[[decisions]]
key = "term:exempla"
action = "redact"
category = "name"
text = "Exempla"
"#;
        let file = LearnedFile::parse(text).unwrap();
        assert_eq!(file.names.terms, vec!["Exempla".to_string()]);
        assert_eq!(file.names.people, vec!["Ren Testdotter".to_string()]);
        assert_eq!(file.secrets[0].name, "learned-secret-example");
        assert_eq!(file.symbols[0].regex, r"\btundrahorn_fan_init\b");
        assert_eq!(file.allow.entries, vec!["threshold".to_string()]);
        assert_eq!(file.decisions[0].action, "redact");
        let again = LearnedFile::parse(&file.to_toml().unwrap()).unwrap();
        assert_eq!(again, file);
    }

    #[test]
    fn quotes_and_backslashes_round_trip() {
        let text = "say \"hi\" and \\path and line\nbreak";
        let mut file = LearnedFile::parse("version = 1\n").unwrap();
        file.names.terms.push(text.to_string());
        let parsed = LearnedFile::parse(&file.to_toml().unwrap()).unwrap();
        assert_eq!(parsed.names.terms, vec![text.to_string()]);
    }

    #[test]
    fn unknown_version_is_rejected() {
        let err = LearnedFile::parse("version = 2\n").unwrap_err();
        assert!(err.to_string().contains("version 2"));
    }
}
