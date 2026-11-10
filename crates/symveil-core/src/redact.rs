use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde_json::Value;

use crate::category::Category;
use crate::config::{Action, Mode, RedactSection};
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
    pub action: Action,
}

struct Span {
    start: usize,
    end: usize,
    priority: u8,
    category: Category,
    rule: Option<String>,
    action: Action,
}

pub struct Engine {
    vault: Vault,
    maskers: Vec<Box<dyn Masker>>,
    allow: HashSet<String>,
    deny: HashSet<String>,
    mode: Mode,
    rule_actions: HashMap<String, Action>,
    category_actions: HashMap<Category, Action>,
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
        redact.validate()?;
        let allow: HashSet<String> = redact.allow.iter().cloned().collect();
        let deny: HashSet<String> = redact.deny.iter().cloned().collect();
        let (rule_actions, category_actions) = policy_maps(redact)?;
        let mut maskers: Vec<Box<dyn Masker>> = Vec::with_capacity(2 + extra.len());
        maskers.push(Box::new(SecretMasker::compile(&redact.secrets, &vault)?));
        maskers.push(Box::new(NetworkMasker::compile(&redact.internal_domains)?));
        maskers.extend(extra);
        Ok(Self {
            vault,
            maskers,
            allow,
            deny,
            mode: redact.mode,
            rule_actions,
            category_actions,
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
        let selected = self.plan(text);
        if selected.iter().any(|span| span.action == Action::Block) {
            let hits = selected
                .iter()
                .filter(|span| span.action == Action::Block)
                .map(|span| hit_from_span(text, span))
                .collect();
            return Ok((text.to_string(), hits));
        }
        self.apply(text, &selected)
    }

    pub fn redact_bytes(&mut self, body: &[u8]) -> Result<(Vec<u8>, Vec<Hit>)> {
        if body.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if let Ok(mut value) = serde_json::from_slice::<Value>(body) {
            let mut blocks = Vec::new();
            self.collect_blocks(&value, &mut blocks);
            if !blocks.is_empty() {
                return Ok((body.to_vec(), blocks));
            }
            let mut hits = Vec::new();
            self.redact_value(&mut value, &mut hits)?;
            let out = serde_json::to_vec(&value)?;
            return Ok((out, hits));
        }
        let text = String::from_utf8_lossy(body);
        let (redacted, hits) = self.redact_str(&text)?;
        if hits.iter().any(|hit| hit.action == Action::Block) {
            return Ok((body.to_vec(), hits));
        }
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
        let action = self.resolve(category, rule.as_deref());
        spans.push(Span {
            start,
            end,
            priority,
            category,
            rule,
            action,
        });
    }

    fn skipped(&self, matched: &str, category: Category) -> bool {
        if category == Category::Secret {
            return false;
        }
        self.allow.contains(matched) && !self.deny.contains(matched)
    }

    fn plan(&self, text: &str) -> Vec<Span> {
        let blocked = placeholder_ranges(text);
        let mut spans = Vec::new();
        for masker in &self.maskers {
            for candidate in masker.collect(text) {
                self.consider(text, candidate, &blocked, &mut spans);
            }
        }
        select_spans(spans)
    }

    fn resolve(&self, category: Category, rule: Option<&str>) -> Action {
        if self.mode == Mode::Observe {
            return Action::Warn;
        }
        if let Some(name) = rule {
            if let Some(action) = self.rule_actions.get(name) {
                return *action;
            }
        }
        self.category_actions
            .get(&category)
            .copied()
            .unwrap_or(Action::Redact)
    }

    fn collect_blocks(&self, value: &Value, hits: &mut Vec<Hit>) {
        match value {
            Value::String(text) => {
                for span in self.plan(text) {
                    if span.action == Action::Block {
                        hits.push(hit_from_span(text, &span));
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.collect_blocks(item, hits);
                }
            }
            Value::Object(map) => {
                for child in map.values() {
                    self.collect_blocks(child, hits);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn apply(&mut self, text: &str, spans: &[Span]) -> Result<(String, Vec<Hit>)> {
        let mut out = String::with_capacity(text.len());
        let mut hits = Vec::with_capacity(spans.len());
        let mut cursor = 0;
        for span in spans {
            out.push_str(&text[cursor..span.start]);
            let original = &text[span.start..span.end];
            let (replacement, placeholder) = match span.action {
                Action::Redact => {
                    let placeholder =
                        self.vault
                            .assign(original, span.category, span.rule.clone())?;
                    (placeholder.clone(), placeholder)
                }
                Action::Warn | Action::Block => (original.to_string(), String::new()),
            };
            hits.push(Hit {
                original: original.to_string(),
                placeholder,
                category: span.category,
                rule: span.rule.clone(),
                action: span.action,
            });
            out.push_str(&replacement);
            cursor = span.end;
        }
        out.push_str(&text[cursor..]);
        Ok((out, hits))
    }
}

fn policy_maps(
    redact: &RedactSection,
) -> Result<(HashMap<String, Action>, HashMap<Category, Action>)> {
    let mut rule_actions = HashMap::new();
    for (name, action) in &redact.builtin_actions {
        rule_actions.insert(name.clone(), *action);
    }
    for secret in &redact.secrets {
        if let Some(action) = secret.action {
            rule_actions.insert(secret.name.clone(), action);
        }
    }
    let mut category_actions = HashMap::new();
    for (name, action) in &redact.category_actions {
        let category = match name.as_str() {
            "secret" => Category::Secret,
            "ip" => Category::Ip,
            "hostname" => Category::Hostname,
            other => anyhow::bail!(
                "unknown category `{other}` in [redact.category]; expected \"secret\", \"ip\", or \"hostname\""
            ),
        };
        category_actions.insert(category, *action);
    }
    Ok((rule_actions, category_actions))
}

fn hit_from_span(text: &str, span: &Span) -> Hit {
    Hit {
        original: text[span.start..span.end].to_string(),
        placeholder: String::new(),
        category: span.category,
        rule: span.rule.clone(),
        action: span.action,
    }
}

pub fn contains_block(hits: &[Hit]) -> bool {
    hits.iter().any(|hit| hit.action == Action::Block)
}

pub fn redact_count(hits: &[Hit]) -> usize {
    hits.iter()
        .filter(|hit| hit.action == Action::Redact)
        .count()
}

/// Rule, category, and length. The matched text is not included.
pub fn match_label(hit: &Hit) -> String {
    let rule = hit.rule.as_deref().unwrap_or(hit.category.as_str());
    format!("{rule} ({}, {} bytes)", hit.category, hit.original.len())
}

pub fn block_message(hits: &[Hit]) -> String {
    let mut parts: Vec<String> = hits
        .iter()
        .filter(|hit| hit.action == Action::Block)
        .map(match_label)
        .collect();
    parts.sort();
    parts.dedup();
    let list = if parts.is_empty() {
        "a configured rule".to_string()
    } else {
        parts.join(", ")
    };
    format!(
        "SymVeil blocked this request before sending it upstream. Matched {list}. Remove the secret or change its action in .symveil.toml."
    )
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
    crate::scan::ip_boundary_ok(text, start, end)
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
    use std::collections::HashMap;

    use super::*;
    use crate::config::{Action, Config, Mode, RedactSection, SecretRule, UserPattern};

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
        let sentence = "at 10.8.8.8. and 10.8.8.8.9 stays";
        let (punctuated, _) = engine.redact_str(sentence).unwrap();
        assert!(!punctuated.contains("at 10.8.8.8"));
        assert!(punctuated.contains("10.8.8.8.9 stays"), "{punctuated}");
        assert_eq!(engine.restore_str(&punctuated), sentence);
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

    #[test]
    fn config_without_action_redacts_like_the_historical_default() {
        let legacy = RedactSection {
            internal_domains: vec!["corp".into()],
            secrets: vec![SecretRule {
                name: "acme".into(),
                regex: r"\bacme_live_[A-Za-z0-9]{8,}\b".into(),
                action: None,
            }],
            ..RedactSection::default()
        };
        let parsed = Config::parse(
            r#"
            [redact]
            internal_domains = ["corp"]

            [[redact.secrets]]
            name = "acme"
            regex = '\bacme_live_[A-Za-z0-9]{8,}\b'
            "#,
        )
        .unwrap()
        .redact;
        assert_eq!(parsed.mode, Mode::Enforce);
        assert!(parsed.secrets[0].action.is_none());
        assert!(parsed.builtin_actions.is_empty());
        assert!(parsed.category_actions.is_empty());

        let mut left = engine(legacy);
        let mut right = engine(parsed);
        let input = "host fw.aurora.corp tftp 10.8.0.14 keep 127.0.0.1 key AKIAIOSFODNN7EXAMPLE token acme_live_abcdefghij";
        let (left_text, left_hits) = left.redact_str(input).unwrap();
        let (right_text, right_hits) = right.redact_str(input).unwrap();
        assert_eq!(left_text, right_text);
        assert_eq!(left_hits.len(), right_hits.len());
        for (left_hit, right_hit) in left_hits.iter().zip(&right_hits) {
            assert_eq!(left_hit.action, Action::Redact);
            assert_eq!(right_hit.action, Action::Redact);
            assert_eq!(left_hit.original, right_hit.original);
            assert_eq!(left_hit.placeholder, right_hit.placeholder);
            assert_eq!(left_hit.rule, right_hit.rule);
            assert_eq!(left_hit.category, right_hit.category);
        }
        assert_eq!(left.restore_str(&left_text), input);
        assert_eq!(right.restore_str(&right_text), input);
        assert!(!left_text.contains("AKIA"));
        assert!(!left_text.contains("acme_live_abcdefghij"));
        assert!(!left_text.contains("fw.aurora.corp"));
        assert!(!left_text.contains("10.8.0.14"));
        assert!(left_text.contains("127.0.0.1"));
    }

    #[test]
    fn warn_forwards_the_value_and_does_not_vault_it() {
        let secret = "widget_tok_abcd1234";
        let mut engine = engine(widget_rule(Some(Action::Warn)));
        let input = format!("token {secret}");
        let (out, hits) = engine.redact_str(&input).unwrap();
        assert_eq!(out, input);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].action, Action::Warn);
        assert_eq!(hits[0].rule.as_deref(), Some("widget-token"));
        assert!(hits[0].placeholder.is_empty());
        assert!(engine.placeholder(secret).is_none());
        assert!(!match_label(&hits[0]).contains(secret));
    }

    #[test]
    fn block_keeps_the_text_and_the_message_omits_the_secret() {
        let secret = "widget_tok_abcd1234";
        let mut engine = engine(widget_rule(Some(Action::Block)));
        let input = format!("token {secret} and AKIAIOSFODNN7EXAMPLE");
        let (out, hits) = engine.redact_str(&input).unwrap();
        assert_eq!(out, input);
        assert!(hits.iter().all(|hit| hit.action == Action::Block));
        assert!(hits
            .iter()
            .any(|hit| hit.rule.as_deref() == Some("widget-token")));
        assert!(engine.placeholder(secret).is_none());
        assert!(engine.placeholder("AKIAIOSFODNN7EXAMPLE").is_none());
        let message = block_message(&hits);
        assert!(!message.contains(secret));
        assert!(!message.contains("AKIA"));
        assert!(message.contains("widget-token"));
    }

    #[test]
    fn warn_and_redact_apply_to_the_same_text() {
        let mut engine = engine(widget_rule(Some(Action::Warn)));
        let input = "key AKIAIOSFODNN7EXAMPLE token widget_tok_abcd1234";
        let (out, hits) = engine.redact_str(input).unwrap();
        assert!(out.contains("widget_tok_abcd1234"), "{out}");
        assert!(!out.contains("AKIA"), "{out}");
        assert!(hits.iter().any(|hit| hit.action == Action::Warn));
        assert!(hits.iter().any(|hit| hit.action == Action::Redact));
        assert_eq!(engine.restore_str(&out), input);
    }

    #[test]
    fn category_defaults_and_explicit_rule_actions() {
        let mut engine = engine(RedactSection {
            internal_domains: vec!["corp".into()],
            category_actions: HashMap::from([
                ("ip".into(), Action::Warn),
                ("hostname".into(), Action::Block),
                ("secret".into(), Action::Block),
            ]),
            secrets: vec![SecretRule {
                name: "widget-token".into(),
                regex: r"\bwidget_tok_[A-Za-z0-9]{8}\b".into(),
                action: Some(Action::Redact),
            }],
            ..RedactSection::default()
        });
        let (out, hits) = engine
            .redact_str("see 10.1.2.3 token widget_tok_abcd1234")
            .unwrap();
        assert!(out.contains("10.1.2.3"), "{out}");
        assert!(!out.contains("widget_tok_abcd1234"), "{out}");
        assert!(hits
            .iter()
            .any(|hit| hit.action == Action::Warn && hit.category == Category::Ip));
        assert!(hits.iter().any(|hit| {
            hit.action == Action::Redact && hit.rule.as_deref() == Some("widget-token")
        }));
        assert_eq!(
            engine.restore_str(&out),
            "see 10.1.2.3 token widget_tok_abcd1234"
        );

        let blocked = "key AKIAIOSFODNN7EXAMPLE";
        let (out, hits) = engine.redact_str(blocked).unwrap();
        assert_eq!(out, blocked);
        assert!(hits.iter().all(|hit| hit.action == Action::Block));

        let host = "db.payments.corp";
        let (out, hits) = engine.redact_str(host).unwrap();
        assert_eq!(out, host);
        assert!(hits
            .iter()
            .any(|hit| hit.rule.as_deref() == Some("internal-hostname")));
        assert!(hits.iter().all(|hit| hit.action == Action::Block));
    }

    #[test]
    fn observe_mode_warns_even_when_the_rule_blocks() {
        let mut engine = engine(RedactSection {
            mode: Mode::Observe,
            internal_domains: Vec::new(),
            builtin_actions: HashMap::from([("aws-access-key-id".into(), Action::Block)]),
            ..RedactSection::default()
        });
        let input = "key AKIAIOSFODNN7EXAMPLE";
        let (out, hits) = engine.redact_str(input).unwrap();
        assert_eq!(out, input);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].action, Action::Warn);
        assert_eq!(hits[0].rule.as_deref(), Some("aws-access-key-id"));
        assert!(engine.placeholder("AKIAIOSFODNN7EXAMPLE").is_none());
    }

    #[test]
    fn builtin_private_key_can_block_while_another_builtin_redacts() {
        let mut engine = engine(RedactSection {
            internal_domains: Vec::new(),
            builtin_actions: HashMap::from([("private-key".into(), Action::Block)]),
            ..RedactSection::default()
        });
        let pem = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----";
        let (out, hits) = engine.redact_str(pem).unwrap();
        assert_eq!(out, pem);
        assert!(hits.iter().any(|hit| {
            hit.rule.as_deref() == Some("private-key") && hit.action == Action::Block
        }));
        assert!(!block_message(&hits).contains("not-a-real-key"));

        let (redacted, hits) = engine.redact_str("key AKIAIOSFODNN7EXAMPLE").unwrap();
        assert!(!redacted.contains("AKIA"));
        assert!(hits.iter().all(|hit| hit.action == Action::Redact));
        assert_eq!(engine.restore_str(&redacted), "key AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn a_block_anywhere_in_json_leaves_the_body_unchanged() {
        let mut engine = engine(RedactSection {
            internal_domains: Vec::new(),
            builtin_actions: HashMap::from([("private-key".into(), Action::Block)]),
            ..RedactSection::default()
        });
        let body = br#"{"a":"key AKIAIOSFODNN7EXAMPLE","b":"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----"}"#;
        let (out, hits) = engine.redact_bytes(body).unwrap();
        assert_eq!(out, body);
        assert!(hits.iter().all(|hit| hit.action == Action::Block));
        assert!(hits
            .iter()
            .any(|hit| hit.rule.as_deref() == Some("private-key")));
        let rendered = String::from_utf8_lossy(&out);
        assert!(rendered.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rendered.contains("@@sv:"));
    }

    fn widget_rule(action: Option<Action>) -> RedactSection {
        RedactSection {
            internal_domains: Vec::new(),
            secrets: vec![SecretRule {
                name: "widget-token".into(),
                regex: r"\bwidget_tok_[A-Za-z0-9]{8}\b".into(),
                action,
            }],
            ..RedactSection::default()
        }
    }
}
