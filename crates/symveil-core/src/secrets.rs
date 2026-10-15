use anyhow::{Context, Result};
use regex::Regex;

use crate::category::Category;
use crate::config::UserPattern;
use crate::masker::{Boundary, Candidate, Masker, PRI_SECRET};
use crate::vault::Vault;

const SECRET_CAP: usize = 16_384;

const BUILTINS: &[(&str, &str)] = &[
    ("aws-access-key-id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github-pat", r"\bghp_[A-Za-z0-9]{36}\b"),
    (
        "github-fine-grained-pat",
        r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
    ),
    ("slack-token", r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("stripe-live-secret", r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    (
        "private-key",
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    ),
    (
        "generic-api-key",
        r#"(?i)\b(?:api[_-]?key|apikey|secret|token|password)\b\s*[=:]\s*(?:'[^'\n]{8,200}'|"[^"\n]{8,200}")"#,
    ),
];

#[derive(Debug)]
pub struct SecretHit {
    pub start: usize,
    pub end: usize,
    pub rule: String,
}

pub struct SecretSet {
    rules: Vec<(String, Regex)>,
}

impl SecretSet {
    pub fn compile(user: &[UserPattern]) -> Result<Self> {
        let mut rules = Vec::with_capacity(BUILTINS.len() + user.len());
        for (name, pattern) in BUILTINS {
            let regex =
                Regex::new(pattern).with_context(|| format!("builtin secret rule {name}"))?;
            rules.push(((*name).to_string(), regex));
        }
        for pattern in user {
            if pattern.regex.is_empty() {
                anyhow::bail!("secret rule '{}' has an empty regex", pattern.name);
            }
            let regex = Regex::new(&pattern.regex)
                .with_context(|| format!("secret rule '{}'", pattern.name))?;
            rules.push((pattern.name.clone(), regex));
        }
        Ok(Self { rules })
    }

    pub fn find(&self, text: &str) -> Vec<SecretHit> {
        let mut hits = Vec::new();
        for (name, regex) in &self.rules {
            for matched in regex.find_iter(text) {
                if matched.start() == matched.end() {
                    continue;
                }
                if matched.end() - matched.start() > SECRET_CAP {
                    continue;
                }
                hits.push(SecretHit {
                    start: matched.start(),
                    end: matched.end(),
                    rule: name.clone(),
                });
            }
        }
        hits
    }
}

struct SecretLiteral {
    original: String,
    rule: Option<String>,
}

/// Builtin and user secret rules, plus secrets already stored in the vault.
pub struct SecretMasker {
    rules: SecretSet,
    literals: Vec<SecretLiteral>,
}

impl SecretMasker {
    pub(crate) fn compile(user: &[UserPattern], vault: &Vault) -> Result<Self> {
        let mut literals = Vec::new();
        for entry in vault.iter() {
            if entry.original.is_empty() || entry.category != Category::Secret {
                continue;
            }
            literals.push(SecretLiteral {
                original: entry.original.clone(),
                rule: entry.rule.clone(),
            });
        }
        Ok(Self {
            rules: SecretSet::compile(user)?,
            literals,
        })
    }
}

impl Masker for SecretMasker {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn collect(&self, text: &str) -> Vec<Candidate> {
        let mut out = Vec::new();
        for literal in &self.literals {
            let mut start = 0;
            while let Some(pos) = text[start..].find(&literal.original) {
                let abs = start + pos;
                let end = abs + literal.original.len();
                out.push(Candidate {
                    start: abs,
                    end,
                    category: Category::Secret,
                    rule: literal.rule.clone(),
                    priority: PRI_SECRET,
                    boundary: Boundary::None,
                });
                let step = text[abs..].chars().next().map(char::len_utf8).unwrap_or(1);
                start = abs + step;
            }
        }
        for hit in self.rules.find(text) {
            out.push(Candidate {
                start: hit.start,
                end: hit.end,
                category: Category::Secret,
                rule: Some(hit.rule),
                priority: PRI_SECRET,
                boundary: Boundary::None,
            });
        }
        out
    }
}
