//! Synthetic redaction workloads.
//!
//! Every name, host, address, and secret in here is invented for measurement.
//! Nothing is copied from a real environment. The same generator feeds the
//! criterion benches, the proxy bench, and the byte-stability test, so a
//! matcher change can be checked against recorded output.

use std::io::Write;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::config::{NamesSection, RedactSection, SecretRule, UserPattern};
use crate::redact::Engine;
use crate::vault::Vault;

/// How large a generated workload is. `ci` is what `cargo test` redacts.
/// `quick` is the short bench. `full` is the ~100k-term measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub name: &'static str,
    pub terms: usize,
    pub people: usize,
    pub domains: usize,
    pub secret_rules: usize,
    pub filler_bytes: usize,
    pub messages: usize,
}

impl Profile {
    /// Small enough to redact in a debug `cargo test` run.
    pub fn ci() -> Self {
        Self {
            name: "ci",
            terms: 200,
            people: 20,
            domains: 4,
            secret_rules: 4,
            filler_bytes: 8 * 1024,
            messages: 4,
        }
    }

    /// Non-gating CI bench and a local smoke measurement.
    pub fn quick() -> Self {
        Self {
            name: "quick",
            terms: 1_000,
            people: 50,
            domains: 8,
            secret_rules: 8,
            filler_bytes: 16 * 1024,
            messages: 8,
        }
    }

    /// The measurement workload: a large term set and multi-megabyte tool text.
    pub fn full() -> Self {
        Self {
            name: "full",
            terms: 100_000,
            people: 2_000,
            domains: 32,
            secret_rules: 24,
            filler_bytes: 100 * 1024,
            messages: 24,
        }
    }

    pub fn from_env() -> Self {
        match std::env::var("SYMVEIL_BENCH_PROFILE").as_deref() {
            Ok("full") => Self::full(),
            Ok("ci") => Self::ci(),
            _ => Self::quick(),
        }
    }

    pub fn with_filler(self, filler_bytes: usize) -> Self {
        Self {
            filler_bytes,
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Corpus {
    pub profile: Profile,
    pub redact: RedactSection,
    pub payloads: Vec<Payload>,
}

impl Corpus {
    pub fn build(profile: Profile) -> Self {
        let redact = redact_section(&profile);
        let payloads = payloads(&profile);
        Self {
            profile,
            redact,
            payloads,
        }
    }

    pub fn engine(&self) -> Engine {
        Engine::new(Vault::ephemeral(), &self.redact).expect("bench corpus is valid")
    }

    pub fn payload(&self, name: &str) -> &Payload {
        self.payloads
            .iter()
            .find(|payload| payload.name == name)
            .expect("payload")
    }
}

/// Invented terms. The first three are fixed so every profile has separator,
/// suffix, and case variants. The rest are `svterm` plus a zero-padded index.
pub fn term_name(index: usize) -> String {
    match index {
        0 => "qxvlig".to_string(),
        1 => "blomqxt".to_string(),
        2 => "norrqxv".to_string(),
        _ => format!("svterm{index:06}"),
    }
}

/// Invented two-token person. Tokens are at least three letters.
pub fn person_name(index: usize) -> String {
    format!("Zyxwaver{index:04} Qorlan{index:04}")
}

pub fn domain_name(index: usize) -> String {
    format!("zone{index:04}.test")
}

pub fn redact_section(profile: &Profile) -> RedactSection {
    let mut terms = Vec::with_capacity(profile.terms + 3);
    terms.push(term_name(0));
    terms.push(term_name(1));
    terms.push(term_name(2));
    // Index 0..terms, skipping nothing: `svterm000000` is term 0 in the
    // numeric series and is distinct from the three fixed terms.
    for index in 0..profile.terms {
        terms.push(term_name(index + 3));
    }
    let people = (0..profile.people).map(person_name).collect();
    let internal_domains = (0..profile.domains).map(domain_name).collect();
    let mut secrets = vec![SecretRule {
        name: "bench-token".into(),
        regex: r"svcn_[a-z0-9]{16}".into(),
        action: None,
    }];
    for index in 0..profile.secret_rules {
        secrets.push(SecretRule {
            name: format!("bench-rule-{index:04}"),
            regex: format!("benchrule{index:04}_[a-z]{{8}}"),
            action: None,
        });
    }
    RedactSection {
        allow: Vec::new(),
        deny: Vec::new(),
        internal_domains,
        mode: crate::config::Mode::Enforce,
        category_actions: std::collections::HashMap::new(),
        builtin_actions: std::collections::HashMap::new(),
        patterns: Vec::new(),
        secrets,
        high_entropy: false,
        pii: crate::config::PiiSection::default(),
        names: NamesSection {
            terms,
            patterns: vec![UserPattern {
                name: "bench-code".into(),
                regex: r"SVCODE-\d{4}".into(),
                category: None,
            }],
            people,
        },
        learned: None,
    }
}

pub fn payloads(profile: &Profile) -> Vec<Payload> {
    let filler = filler(profile);
    let canary = canaries();
    let plain = {
        let mut text = String::with_capacity(canary.len() + filler.len() + 1);
        text.push_str(&canary);
        text.push('\n');
        text.push_str(&filler);
        text.into_bytes()
    };
    let tool = json!({
        "model": "bench-local",
        "stream": false,
        "messages": message_list(&canary, &filler, profile.messages),
    });
    let anthropic = json!({
        "model": "bench-local",
        "max_tokens": 32,
        "stream": false,
        "messages": [{
            "role": "user",
            "content": format!("{canary}\n{filler}"),
        }],
    });
    vec![
        Payload {
            name: "plain",
            bytes: plain,
        },
        Payload {
            name: "openai-chat",
            bytes: serde_json::to_vec(&tool).expect("openai payload"),
        },
        Payload {
            name: "anthropic-messages",
            bytes: serde_json::to_vec(&anthropic).expect("anthropic payload"),
        },
    ]
}

fn message_list(canary: &str, filler: &str, messages: usize) -> Vec<Value> {
    let mut out = Vec::with_capacity(messages + 2);
    out.push(json!({
        "role": "system",
        "content": "Local bench fixture. No live service is contacted.",
    }));
    out.push(json!({
        "role": "user",
        "content": canary,
    }));
    let messages = messages.max(1);
    let chunk = (filler.len() / messages).max(1);
    for index in 0..messages {
        let start = (index * chunk).min(filler.len());
        let end = if index + 1 == messages {
            filler.len()
        } else {
            ((index + 1) * chunk).min(filler.len())
        };
        out.push(json!({
            "role": "tool",
            "tool_call_id": format!("call_bench_{index:04}"),
            "content": &filler[start..end],
        }));
    }
    out
}

/// Fixed canaries, present in every profile, plus one base64 block.
pub fn canaries() -> String {
    let term = term_name(3);
    let person = person_name(0);
    let host = format!("cache-01.{}", domain_name(0));
    let aws = "AKIAN0TREALKEY0000X1";
    let github = github_pat();
    let custom = "svcn_notarealtoken001";
    let encoded = STANDARD.encode(custom);
    format!(
        "project QXVLIG qxvlig_ Qxv-lig qxvligs blomqxten norrqxv_extra {term} {term}_ \
SVTERM{term_tail} person {person} and Qorlan0000, Zyxwaver0000 and Hello Zyxwaver0000. \
host {host} address 203.0.113.10 key {aws} pat {github}\n\
export SERVICE_TOKEN=svcn-not-a-real-token\n\
custom {custom} code SVCODE-0042 blob {encoded}\n\
path std::env stays",
        term_tail = &term[6..],
    )
}

const FILLER_WORDS: &[&str] = &[
    "lumen", "quartz", "pebble", "orbit", "nimbus", "kelvin", "vector", "module", "buffer",
    "socket", "cedar", "ribbon", "maple", "drift", "cinder", "harbor", "pixel", "lattice", "ember",
    "willow",
];

/// Deterministic tool-result text. A configured term or host is planted about
/// once per kibibyte so most of the scan is a miss, which is the common case.
pub fn filler(profile: &Profile) -> String {
    let target = profile.filler_bytes.max(64);
    let mut out = String::with_capacity(target + 64);
    let mut word = 0usize;
    let mut step = 0usize;
    while out.len() < target {
        if step > 0 && step.is_multiple_of(80) {
            let term = term_name(3 + (step % profile.terms.max(1)));
            out.push_str(&term);
            out.push(' ');
        } else if step > 0 && step.is_multiple_of(120) {
            let domain = domain_name(step % profile.domains.max(1));
            out.push_str(&format!("node{step}.{domain} "));
        } else {
            out.push_str(FILLER_WORDS[word % FILLER_WORDS.len()]);
            out.push(' ');
            word += 1;
        }
        step += 1;
    }
    out.truncate(target);
    // Keep the cut on a char boundary. The filler is ASCII, so any index is safe.
    out
}

/// Proxy config whose redact policy matches [`redact_section`].
pub fn write_proxy_config(path: &Path, redact: &RedactSection) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = std::fs::File::create(path)?;
    writeln!(
        file,
        "\
[proxy]
listen = \"127.0.0.1\"
port = 9
openai_base = \"http://127.0.0.1:9\"
anthropic_base = \"http://127.0.0.1:9\"
timeout_secs = 0
vault = \".symveil/vault.json\"
audit_log = \".symveil/audit.jsonl\"

[redact]
high_entropy = false
internal_domains = ["
    )?;
    for domain in &redact.internal_domains {
        writeln!(file, "  \"{}\",", toml_basic(domain))?;
    }
    writeln!(file, "]")?;
    writeln!(file)?;
    writeln!(file, "[redact.names]")?;
    writeln!(file, "terms = [")?;
    for term in &redact.names.terms {
        writeln!(file, "  \"{}\",", toml_basic(term))?;
    }
    writeln!(file, "]")?;
    writeln!(file, "people = [")?;
    for person in &redact.names.people {
        writeln!(file, "  \"{}\",", toml_basic(person))?;
    }
    writeln!(file, "]")?;
    for pattern in &redact.names.patterns {
        writeln!(file)?;
        writeln!(file, "[[redact.names.patterns]]")?;
        writeln!(file, "name = \"{}\"", toml_basic(&pattern.name))?;
        writeln!(file, "regex = '{}'", pattern.regex.replace('\'', "''"))?;
    }
    for rule in &redact.secrets {
        writeln!(file)?;
        writeln!(file, "[[redact.secrets]]")?;
        writeln!(file, "name = \"{}\"", toml_basic(&rule.name))?;
        writeln!(file, "regex = '{}'", rule.regex.replace('\'', "''"))?;
    }
    Ok(())
}

fn toml_basic(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn github_pat() -> String {
    format!("ghp_{}", "b".repeat(36))
}

/// Planted values the stability test expects to be gone after redaction.
pub fn planted_secrets() -> Vec<String> {
    let mut planted = vec![
        "qxvlig".to_string(),
        "QXVLIG".to_string(),
        "blomqxt".to_string(),
        "norrqxv".to_string(),
        "Zyxwaver0000".to_string(),
        "Qorlan0000".to_string(),
        "cache-01.zone0000.test".to_string(),
        "203.0.113.10".to_string(),
        "AKIAN0TREALKEY0000X1".to_string(),
        "svcn_notarealtoken001".to_string(),
        "SVCODE-0042".to_string(),
        "svcn-not-a-real-token".to_string(),
        term_name(3),
    ];
    planted.push(github_pat());
    planted
}
