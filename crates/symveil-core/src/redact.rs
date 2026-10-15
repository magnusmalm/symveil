use std::collections::HashSet;

use anyhow::Result;
use serde_json::Value;

use crate::category::Category;
use crate::config::RedactSection;
use crate::masker::{Boundary, Candidate, Masker};
use crate::scan::NetworkMasker;
use crate::secrets::SecretMasker;
use crate::stream::{self, placeholder_ranges};
use crate::vault::Vault;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub original: String,
    pub placeholder: String,
    pub category: Category,
    pub rule: Option<String>,
}

struct Span {
    start: usize,
    end: usize,
    priority: u8,
    category: Category,
    rule: Option<String>,
}

pub struct Engine {
    vault: Vault,
    maskers: Vec<Box<dyn Masker>>,
    allow: HashSet<String>,
    deny: HashSet<String>,
}

impl Engine {
    /// Secret and network maskers only. Identifier plugins are added with
    /// [`Engine::with_maskers`].
    pub fn new(vault: Vault, redact: &RedactSection) -> Result<Self> {
        Self::with_maskers(vault, redact, Vec::new())
    }

    /// `extra` plugins run after the built-in secret and network maskers.
    /// Built-ins are always installed, including when `extra` is empty.
    pub fn with_maskers(
        vault: Vault,
        redact: &RedactSection,
        extra: Vec<Box<dyn Masker>>,
    ) -> Result<Self> {
        let allow: HashSet<String> = redact.allow.iter().cloned().collect();
        let deny: HashSet<String> = redact.deny.iter().cloned().collect();
        let mut maskers: Vec<Box<dyn Masker>> = Vec::with_capacity(2 + extra.len());
        maskers.push(Box::new(SecretMasker::compile(&redact.secrets, &vault)?));
        maskers.push(Box::new(NetworkMasker::compile(&redact.internal_domains)?));
        maskers.extend(extra);
        Ok(Self {
            vault,
            maskers,
            allow,
            deny,
        })
    }

    pub fn placeholder(&self, original: &str) -> Option<&str> {
        self.vault.placeholder(original)
    }

    pub fn save_if_dirty(&mut self) -> Result<()> {
        if self.vault.is_dirty() {
            self.vault.save()?;
        }
        Ok(())
    }

    pub fn restore_map(&self) -> std::collections::HashMap<String, String> {
        self.vault.restore_map()
    }

    pub fn redact_str(&mut self, text: &str) -> Result<(String, Vec<Hit>)> {
        let blocked = placeholder_ranges(text);
        let mut spans = Vec::new();
        for masker in &self.maskers {
            for candidate in masker.collect(text) {
                self.consider(text, candidate, &blocked, &mut spans);
            }
        }
        let selected = select_spans(spans);
        self.apply(text, &selected)
    }

    pub fn redact_bytes(&mut self, body: &[u8]) -> Result<(Vec<u8>, Vec<Hit>)> {
        if body.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if let Ok(mut value) = serde_json::from_slice::<Value>(body) {
            let mut hits = Vec::new();
            self.redact_value(&mut value, &mut hits)?;
            let out = serde_json::to_vec(&value)?;
            return Ok((out, hits));
        }
        let text = String::from_utf8_lossy(body);
        let (redacted, hits) = self.redact_str(&text)?;
        Ok((redacted.into_bytes(), hits))
    }

    pub fn restore_str(&self, text: &str) -> String {
        let (bytes, _) = stream::restore_all(text.as_bytes(), &self.vault.restore_map(), false);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn restore_bytes(&self, body: &[u8], json_escape: bool) -> (Vec<u8>, usize) {
        stream::restore_all(body, &self.vault.restore_map(), json_escape)
    }

    fn redact_value(&mut self, value: &mut Value, hits: &mut Vec<Hit>) -> Result<()> {
        match value {
            Value::String(text) => {
                let (redacted, found) = self.redact_str(text)?;
                *text = redacted;
                hits.extend(found);
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_value(item, hits)?;
                }
            }
            Value::Object(map) => {
                for child in map.values_mut() {
                    self.redact_value(child, hits)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }

    fn consider(
        &self,
        text: &str,
        candidate: Candidate,
        blocked: &[(usize, usize)],
        spans: &mut Vec<Span>,
    ) {
        let Candidate {
            start,
            end,
            category,
            rule,
            priority,
            boundary,
        } = candidate;
        if start >= end || end > text.len() {
            return;
        }
        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            return;
        }
        if overlaps(start, end, blocked) {
            return;
        }
        if !boundary_ok(boundary, text, start, end) {
            return;
        }
        let matched = &text[start..end];
        if self.skipped(matched, category) {
            return;
        }
        spans.push(Span {
            start,
            end,
            priority,
            category,
            rule,
        });
    }

    fn skipped(&self, matched: &str, category: Category) -> bool {
        if category == Category::Secret {
            return false;
        }
        self.allow.contains(matched) && !self.deny.contains(matched)
    }

    fn apply(&mut self, text: &str, spans: &[Span]) -> Result<(String, Vec<Hit>)> {
        let mut out = String::with_capacity(text.len());
        let mut hits = Vec::with_capacity(spans.len());
        let mut cursor = 0;
        for span in spans {
            out.push_str(&text[cursor..span.start]);
            let original = &text[span.start..span.end];
            let placeholder = self
                .vault
                .assign(original, span.category, span.rule.clone())?;
            hits.push(Hit {
                original: original.to_string(),
                placeholder: placeholder.clone(),
                category: span.category,
                rule: span.rule.clone(),
            });
            out.push_str(&placeholder);
            cursor = span.end;
        }
        out.push_str(&text[cursor..]);
        Ok((out, hits))
    }
}

fn boundary_ok(boundary: Boundary, text: &str, start: usize, end: usize) -> bool {
    match boundary {
        Boundary::None => true,
        Boundary::Ident => ident_boundary(text, start, end),
        Boundary::Ip => ip_boundary(text, start, end),
    }
}

fn ident_boundary(text: &str, start: usize, end: usize) -> bool {
    let left_ok = start == 0
        || text[..start]
            .chars()
            .next_back()
            .is_some_and(|ch| !is_ident_continue(ch));
    let right_ok = end == text.len()
        || text[end..]
            .chars()
            .next()
            .is_some_and(|ch| !is_ident_continue(ch));
    left_ok && right_ok
}

fn ip_boundary(text: &str, start: usize, end: usize) -> bool {
    let bad = |ch: char| ch.is_ascii_digit() || ch == '.';
    let left_bad = start > 0 && text[..start].chars().next_back().is_some_and(bad);
    let right_bad = end < text.len() && text[end..].chars().next().is_some_and(bad);
    !left_bad && !right_bad
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn overlaps(start: usize, end: usize, blocked: &[(usize, usize)]) -> bool {
    blocked
        .iter()
        .any(|&(left, right)| start < right && end > left)
}

fn select_spans(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(b.priority.cmp(&a.priority))
    });
    let mut selected = Vec::with_capacity(spans.len());
    let mut cursor = 0;
    for span in spans {
        if span.start < cursor {
            continue;
        }
        cursor = span.end;
        selected.push(span);
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RedactSection, UserPattern};

    fn engine(redact: RedactSection) -> Engine {
        Engine::new(Vault::ephemeral(), &redact).unwrap()
    }

    #[test]
    fn vault_identifiers_are_not_masked_by_the_free_engine() {
        let mut vault = Vault::ephemeral();
        vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let mut engine = Engine::new(
            vault,
            &RedactSection {
                internal_domains: Vec::new(),
                ..RedactSection::default()
            },
        )
        .unwrap();
        let input = "call aurora_rcc_enable_pll()";
        let (redacted, hits) = engine.redact_str(input).unwrap();
        assert!(hits.is_empty());
        assert_eq!(redacted, input);
    }

    #[test]
    fn deny_list_and_code_name_patterns_are_not_free_tier_masks() {
        let mut engine = Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                deny: vec!["aurora_rcc_enable_pll".into()],
                patterns: vec![UserPattern {
                    name: "code".into(),
                    regex: r"(?i)\baurora(?:-[a-z0-9]+)?\b".into(),
                    category: Some("codename".into()),
                }],
                internal_domains: Vec::new(),
                ..RedactSection::default()
            },
        )
        .unwrap();
        let input = "call aurora_rcc_enable_pll() chip AURORA-7F";
        let (redacted, hits) = engine.redact_str(input).unwrap();
        assert!(hits.is_empty(), "{redacted}");
        assert_eq!(redacted, input);
    }

    #[test]
    fn secrets_ips_and_hosts_round_trip() {
        let mut engine = engine(RedactSection {
            internal_domains: vec!["corp".into()],
            ..RedactSection::default()
        });
        let input = "host fw.aurora.corp tftp 10.8.0.14 keep 127.0.0.1 key AKIAIOSFODNN7EXAMPLE and 2001:db8::1 see: also at 12:34:56";
        let (redacted, hits) = engine.redact_str(input).unwrap();
        assert!(!redacted.contains("fw.aurora.corp"));
        assert!(!redacted.contains("10.8.0.14"));
        assert!(redacted.contains("127.0.0.1"));
        assert!(!redacted.contains("AKIA"));
        assert!(!redacted.contains("2001:db8"));
        assert!(hits
            .iter()
            .any(|hit| hit.rule.as_deref() == Some("aws-access-key-id")));
        assert!(redacted.contains("see: also"));
        assert!(redacted.contains("12:34:56"));
        assert_eq!(engine.restore_str(&redacted), input);
        let (plain, _) = engine
            .redact_str("example.com and the password is written out")
            .unwrap();
        assert_eq!(plain, "example.com and the password is written out");
    }

    #[test]
    fn generic_assignment_and_private_key() {
        let mut engine = engine(RedactSection {
            internal_domains: Vec::new(),
            ..RedactSection::default()
        });
        let input = "api_key = \"supersecretvalue\"\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n";
        let (redacted, hits) = engine.redact_str(input).unwrap();
        assert!(!redacted.contains("supersecretvalue"));
        assert!(!redacted.contains("BEGIN PRIVATE KEY"));
        assert!(hits.iter().any(|hit| hit.category == Category::Secret));
        assert_eq!(engine.restore_str(&redacted), input);
    }

    #[test]
    fn json_values_are_redacted_and_keys_are_not() {
        let mut engine = engine(RedactSection {
            internal_domains: Vec::new(),
            ..RedactSection::default()
        });
        let input = br#"{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}"#;
        let (out, hits) = engine.redact_bytes(input).unwrap();
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value.get("role").and_then(Value::as_str), Some("user"));
        assert_eq!(value.get("content").map(|v| v.is_string()), Some(true));
        let redacted_content = value.get("content").and_then(Value::as_str).unwrap();
        assert!(!redacted_content.contains("AKIA"));
        assert!(value.get("content").is_some());
        assert!(!hits.is_empty());
        let (restored, _) = engine.restore_bytes(&out, true);
        let restored_value: Value = serde_json::from_slice(&restored).unwrap();
        assert_eq!(
            restored_value.get("content").and_then(Value::as_str),
            Some("key AKIAIOSFODNN7EXAMPLE")
        );
    }

    #[test]
    fn vault_secret_with_quote_round_trips_inside_json() {
        let mut vault = Vault::ephemeral();
        vault
            .assign("p@ss\"word12", Category::Secret, Some("literal".into()))
            .unwrap();
        let mut engine = Engine::new(
            vault,
            &RedactSection {
                internal_domains: Vec::new(),
                ..RedactSection::default()
            },
        )
        .unwrap();
        let input = br#"{"role":"user","content":"see p@ss\"word12"}"#;
        let (out, hits) = engine.redact_bytes(input).unwrap();
        let value: Value = serde_json::from_slice(&out).unwrap();
        let redacted_content = value.get("content").and_then(Value::as_str).unwrap();
        assert!(!redacted_content.contains("p@ss"));
        assert!(hits.iter().any(|hit| hit.category == Category::Secret));
        let (restored, _) = engine.restore_bytes(&out, true);
        let restored_value: Value = serde_json::from_slice(&restored).unwrap();
        assert_eq!(
            restored_value.get("content").and_then(Value::as_str),
            Some("see p@ss\"word12")
        );
    }

    #[test]
    fn prose_password_is_not_a_secret() {
        let mut engine = engine(RedactSection {
            internal_domains: Vec::new(),
            ..RedactSection::default()
        });
        let input = "the password is not an assignment";
        let (redacted, hits) = engine.redact_str(input).unwrap();
        assert!(hits.is_empty());
        assert_eq!(redacted, input);
    }
}
