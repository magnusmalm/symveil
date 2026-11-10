use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::{Captures, Regex};

use crate::category::Category;
use crate::config::UserPattern;
use crate::masker::{Boundary, Candidate, Masker, PRI_PATTERN, PRI_SECRET};
use crate::vault::Vault;

const SECRET_CAP: usize = 16_384;
const VALUE_MIN: usize = 8;
const VALUE_MAX: usize = 200;

struct Builtin {
    name: &'static str,
    pattern: &'static str,
    /// Capture groups that hold the secret. Empty means the whole match.
    /// The first group that participated wins.
    groups: &'static [usize],
    /// Drop placeholders, all-digit values, and other low-signal matches.
    filter_low_signal: bool,
}

const BUILTINS: &[Builtin] = &[
    Builtin {
        name: "aws-access-key-id",
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "github-pat",
        pattern: r"\bghp_[A-Za-z0-9]{36}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "github-fine-grained-pat",
        pattern: r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "slack-token",
        pattern: r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "google-api-key",
        pattern: r"\bAIza[0-9A-Za-z\-_]{35}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "stripe-live-secret",
        pattern: r"\bsk_live_[0-9a-zA-Z]{24,}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "openai-api-key",
        // Legacy keys are `sk-` plus 48 alphanumeric characters. Project keys
        // are `sk-proj-` plus a long base64url body. `sk-ant-` does not fit
        // either shape. `sk-admin-` and `sk-svcacct-` are not this rule.
        pattern: r"\bsk-(?:proj-[A-Za-z0-9_-]{32,2000}|[A-Za-z0-9]{48})\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "anthropic-api-key",
        pattern: r"\bsk-ant-[A-Za-z0-9_-]{24,2000}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "jwt",
        pattern: r"\beyJ[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,4000}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "url-password",
        // Password only. User and host stay so the model can still see the URL.
        pattern: r"(?i)\b[a-z][a-z0-9+.-]*://[^:\s/@]*:([^:\s/@]{8,200})@",
        groups: &[1],
        filter_low_signal: true,
    },
    Builtin {
        name: "private-key",
        pattern: r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "generic-api-key",
        pattern: r#"(?i)\b(?:api[_-]?key|apikey|secret|token|password)\b\s*[=:]\s*(?:'([^'\n]{8,200})'|"([^"\n]{8,200})")"#,
        groups: &[1, 2],
        filter_low_signal: true,
    },
    // Uppercase names only, and the suffix must end the name, so `TOKEN_LIMIT`
    // and a lowercase `api_key = load()` stay visible. The value is group 1.
    Builtin {
        name: "env-assignment",
        pattern: concat!(
            r"(?m)^[ \t]*(?:export[ \t]+)?",
            r"[A-Z_][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS)",
            r#"[ \t]*=[ \t]*([^\s#'"]{8,200})"#
        ),
        groups: &[1],
        filter_low_signal: true,
    },
    Builtin {
        name: "env-quoted-assignment",
        pattern: concat!(
            r"(?m)^[ \t]*(?:export[ \t]+)?",
            r"[A-Z_][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS)",
            r#"[ \t]*=[ \t]*(?:"([^"\r\n]{8,200})"|'([^'\r\n]{8,200})')"#
        ),
        groups: &[1, 2],
        filter_low_signal: true,
    },
];

#[derive(Debug)]
pub struct SecretHit {
    pub start: usize,
    pub end: usize,
    pub rule: String,
}

struct CompiledRule {
    name: String,
    regex: Regex,
    groups: Vec<usize>,
    filter_low_signal: bool,
}

pub struct SecretSet {
    rules: Vec<CompiledRule>,
}

impl SecretSet {
    pub fn compile(user: &[UserPattern]) -> Result<Self> {
        let mut rules = Vec::with_capacity(BUILTINS.len() + user.len());
        for builtin in BUILTINS {
            let regex = Regex::new(builtin.pattern)
                .with_context(|| format!("builtin secret rule {}", builtin.name))?;
            rules.push(CompiledRule {
                name: builtin.name.to_string(),
                regex,
                groups: builtin.groups.to_vec(),
                filter_low_signal: builtin.filter_low_signal,
            });
        }
        for pattern in user {
            if pattern.regex.is_empty() {
                anyhow::bail!("secret rule '{}' has an empty regex", pattern.name);
            }
            let regex = Regex::new(&pattern.regex)
                .with_context(|| format!("secret rule '{}'", pattern.name))?;
            rules.push(CompiledRule {
                name: pattern.name.clone(),
                regex,
                groups: Vec::new(),
                filter_low_signal: false,
            });
        }
        Ok(Self { rules })
    }

    pub fn find(&self, text: &str) -> Vec<SecretHit> {
        let mut hits = Vec::new();
        for rule in &self.rules {
            for caps in rule.regex.captures_iter(text) {
                let Some((start, end, value)) = secret_span(&caps, &rule.groups) else {
                    continue;
                };
                if start == end || end - start > SECRET_CAP {
                    continue;
                }
                if rule.filter_low_signal && is_low_signal(&rule.name, value) {
                    continue;
                }
                hits.push(SecretHit {
                    start,
                    end,
                    rule: rule.name.clone(),
                });
            }
        }
        hits
    }
}

fn secret_span<'a>(caps: &Captures<'a>, groups: &[usize]) -> Option<(usize, usize, &'a str)> {
    if groups.is_empty() {
        let matched = caps.get(0)?;
        return Some((matched.start(), matched.end(), matched.as_str()));
    }
    for &index in groups {
        if let Some(matched) = caps.get(index) {
            if matched.start() != matched.end() {
                return Some((matched.start(), matched.end(), matched.as_str()));
            }
        }
    }
    None
}

/// Assignment and URL-password hits that are usually placeholders.
/// All-digit URL passwords are kept: `user:12345678@host` is a credential,
/// while `MAX_TOKEN=12345678` is a limit.
fn is_low_signal(rule: &str, value: &str) -> bool {
    if !(VALUE_MIN..=VALUE_MAX).contains(&value.len()) {
        return true;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    if chars.all(|ch| ch == first) {
        return true;
    }
    if value.chars().all(|ch| ch.is_ascii_digit()) && rule != "url-password" {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with('$') || (lower.starts_with('<') && lower.ends_with('>')) {
        return true;
    }
    const EXACT: &[&str] = &[
        "changeme",
        "change-me",
        "change_me",
        "password",
        "password1",
        "password123",
        "secret",
        "secret123",
        "token",
        "token123",
        "apikey",
        "api_key",
        "api-key",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "redacted",
        "localhost",
    ];
    if EXACT.contains(&lower.as_str()) {
        return true;
    }
    const FRAGMENTS: &[&str] = &[
        "changeme",
        "placeholder",
        "replace-me",
        "replace_me",
        "insert-key",
        "insert_key",
        "your-api",
        "your_api",
        "your-key",
        "your_key",
        "redacted",
    ];
    FRAGMENTS.iter().any(|fragment| lower.contains(fragment))
}

const HIGH_ENTROPY_MIN: usize = 32;
const HIGH_ENTROPY_MAX: usize = 4_096;
const HIGH_ENTROPY_BITS: f64 = 4.5;

static HIGH_ENTROPY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_=-]{32,4096}").expect("high entropy token"));

fn high_entropy_hits(text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for matched in HIGH_ENTROPY.find_iter(text) {
        let token = matched.as_str();
        if token.len() < HIGH_ENTROPY_MIN
            || token.len() > HIGH_ENTROPY_MAX
            || token.len() > SECRET_CAP
        {
            continue;
        }
        if is_hex_token(token) || is_digest_token(token) || is_uuid(token) {
            continue;
        }
        if shannon_entropy(token) < HIGH_ENTROPY_BITS {
            continue;
        }
        hits.push(SecretHit {
            start: matched.start(),
            end: matched.end(),
            rule: "high-entropy".to_string(),
        });
    }
    hits
}

fn is_hex_token(token: &str) -> bool {
    token.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_digest_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    ["sha512-", "sha384-", "sha256-", "sha1-"]
        .into_iter()
        .any(|prefix| lower.starts_with(prefix) && lower.len() > prefix.len())
}

fn is_uuid(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let hex_at =
        |range: std::ops::Range<usize>| bytes[range].iter().all(|byte| byte.is_ascii_hexdigit());
    bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && hex_at(0..8)
        && hex_at(9..13)
        && hex_at(14..18)
        && hex_at(19..23)
        && hex_at(24..36)
}

fn shannon_entropy(token: &str) -> f64 {
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = f64::from(count) / len;
        entropy -= p * p.log2();
    }
    entropy
}

struct SecretLiteral {
    original: String,
    rule: Option<String>,
}

/// Builtin and user secret rules, plus secrets already stored in the vault.
pub struct SecretMasker {
    rules: SecretSet,
    literals: Vec<SecretLiteral>,
    high_entropy: bool,
}

impl SecretMasker {
    pub(crate) fn compile(user: &[UserPattern], vault: &Vault, high_entropy: bool) -> Result<Self> {
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
            high_entropy,
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
        if self.high_entropy {
            for hit in high_entropy_hits(text) {
                out.push(Candidate {
                    start: hit.start,
                    end: hit.end,
                    category: Category::Secret,
                    rule: Some(hit.rule),
                    // Named rules win when they cover the same span.
                    priority: PRI_PATTERN,
                    boundary: Boundary::None,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactSection;
    use crate::redact::Engine;

    fn engine(high_entropy: bool) -> Engine {
        Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                internal_domains: Vec::new(),
                high_entropy,
                ..RedactSection::default()
            },
        )
        .unwrap()
    }

    fn masked(input: &str) -> (String, Vec<String>) {
        let mut engine = engine(false);
        let (out, hits) = engine.redact_str(input).unwrap();
        let rules = hits.iter().filter_map(|hit| hit.rule.clone()).collect();
        assert_eq!(engine.restore_str(&out), input, "{out}");
        (out, rules)
    }

    fn assert_value_only(input: &str, secret: &str, name: &str, rule: &str) {
        let (out, rules) = masked(input);
        assert!(!out.contains(secret), "{out}");
        assert!(out.contains(name), "{out}");
        assert!(rules.iter().any(|item| item == rule), "{rules:?}");
    }

    fn legacy_openai() -> String {
        format!("sk-{}", "A".repeat(48))
    }

    fn project_openai() -> String {
        format!("sk-proj-{}", "C".repeat(16) + &"d".repeat(16))
    }

    fn anthropic() -> String {
        format!("sk-ant-{}", "E".repeat(24))
    }

    fn jwt() -> String {
        let header = "eyJhbGciOiJub25lIn0";
        let payload = "eyJzdWIiOiJmYWtlIn0";
        let signature = "ZmFrZXNpZ25hdHVyZQ";
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn env_assignment_masks_the_value_and_keeps_the_name() {
        let input = "export DATABASE_PASSWORD=hunter2hunter2 # keep\n";
        let (out, rules) = masked(input);
        assert!(!out.contains("hunter2hunter2"), "{out}");
        assert!(out.contains("export DATABASE_PASSWORD="), "{out}");
        assert!(out.contains("# keep"), "{out}");
        assert_eq!(rules, vec!["env-assignment".to_string()]);
    }

    #[test]
    fn env_assignment_allows_spaces_crlf_and_a_tight_export() {
        let (spaced, _) = masked("SERVICE_TOKEN = svc_fake_token_value\n");
        assert!(!spaced.contains("svc_fake_token_value"), "{spaced}");
        assert!(spaced.contains("SERVICE_TOKEN"), "{spaced}");
        let (crlf, _) = masked("export  FOO_API_KEY=abc123xyz\r\n");
        assert!(!crlf.contains("abc123xyz"), "{crlf}");
        assert!(crlf.contains("FOO_API_KEY"), "{crlf}");
    }

    #[test]
    fn env_quoted_assignment_masks_the_value_only() {
        assert_value_only(
            "DATABASE_PASSWORD=\"hunter2hunter2\"\n",
            "hunter2hunter2",
            "DATABASE_PASSWORD",
            "env-quoted-assignment",
        );
        let (single, rules) = masked("export DB_PASS='hunter2hunter2'\n");
        assert!(!single.contains("hunter2hunter2"), "{single}");
        assert!(single.contains("DB_PASS"), "{single}");
        assert_eq!(rules, vec!["env-quoted-assignment".to_string()]);
    }

    #[test]
    fn env_near_misses_stay_unmasked() {
        let input = "\
TOKEN_LIMIT=4096
MAX_TOKEN=12345678
MAX_TOKENS=abcdefghij
API_KEY=changeme
API_KEY=${OTHER_API_KEY}
API_KEY=abc123
FOO_PASSWORD=short
DATABASE_PASSPHRASE=hunter2hunter2
see FOO_API_KEY=abcdefghijklmnop in prose
api_key = os.environ.get(\"OPENAI_API_KEY\")
";
        let (out, rules) = masked(input);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, input);
    }

    #[test]
    fn quoted_placeholder_assignment_is_not_a_secret() {
        let input = "password = \"changeme\"\napi_key: \"your_api_key_here\"\n";
        let (out, rules) = masked(input);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, input);
    }

    #[test]
    fn quoted_generic_assignment_keeps_the_label() {
        assert_value_only(
            "api_key = \"supersecretvalue\"\n",
            "supersecretvalue",
            "api_key",
            "generic-api-key",
        );
    }

    #[test]
    fn openai_legacy_and_project_keys_are_masked() {
        let legacy = legacy_openai();
        let (out, rules) = masked(&format!("key {legacy} done"));
        assert!(!out.contains(&legacy), "{out}");
        assert_eq!(rules, vec!["openai-api-key".to_string()]);

        let project = project_openai();
        let (out, rules) = masked(&project);
        assert!(!out.contains(&project), "{out}");
        assert_eq!(rules, vec!["openai-api-key".to_string()]);
    }

    #[test]
    fn openai_near_misses_stay_unmasked() {
        let short_legacy = format!("sk-{}", "A".repeat(47));
        let short_project = format!("sk-proj-{}", "C".repeat(31));
        let input = format!("{short_legacy} {short_project} skill-not-a-key");
        let (out, rules) = masked(&input);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, input);
    }

    #[test]
    fn anthropic_key_is_masked_and_a_short_one_is_not() {
        let key = anthropic();
        let (out, rules) = masked(&format!("use {key}"));
        assert!(!out.contains(&key), "{out}");
        assert_eq!(rules, vec!["anthropic-api-key".to_string()]);

        let miss = format!("sk-ant-{}", "E".repeat(23));
        let (out, rules) = masked(&miss);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, miss);
    }

    #[test]
    fn jwt_is_masked_and_two_segments_are_not() {
        let token = jwt();
        let (out, rules) = masked(&format!("bearer {token}"));
        assert!(!out.contains("ZmFrZXNpZ25hdHVyZQ"), "{out}");
        assert_eq!(rules, vec!["jwt".to_string()]);

        let miss = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0";
        let (out, rules) = masked(miss);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, miss);
    }

    #[test]
    fn url_password_masks_only_the_password() {
        let input = "postgres://app:notarealpassword@db.example:5432/app";
        let (out, rules) = masked(input);
        assert!(!out.contains("notarealpassword"), "{out}");
        assert!(out.contains("postgres://app:"), "{out}");
        assert!(out.contains("@db.example:5432/app"), "{out}");
        assert_eq!(rules, vec!["url-password".to_string()]);

        let numeric = "postgres://app:12345678@db.example/app";
        let (out, rules) = masked(numeric);
        assert!(!out.contains("12345678"), "{out}");
        assert!(out.contains("postgres://app:"), "{out}");
        assert!(out.contains("@db.example/app"), "{out}");
        assert_eq!(rules, vec!["url-password".to_string()]);
    }

    #[test]
    fn url_near_misses_stay_unmasked() {
        let input = "\
postgres://app@db.example/app
https://example.com/docs
postgres://app:changeme@db.example/app
http://builder:1234@db.example/app
mailto:dev@example.com
";
        let (out, rules) = masked(input);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, input);
    }

    #[test]
    fn ordinary_code_and_config_is_not_masked() {
        let input = r#"
fn load_api_key() -> String {
    let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
    let token_limit = 4096;
    let max_token = token_limit;
    let password = "changeme";
    api_key
}

api_key = os.environ.get("API_KEY")
max_token = 4096
password = "changeme"
token = None
cache_key = "primary"

{"cache_key": "primary", "password": "changeme", "token": "placeholder"}

TOKEN_LIMIT=4096
MAX_TOKEN=12345678
API_KEY=changeme
API_KEY=${OTHER_API_KEY}
API_KEY=xxxxxxxx
FOO_API_KEY=abc123
# OPENAI_API_KEY=
see FOO_API_KEY=abcdefghijklmnop in the docs

checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
integrity = "sha512-qW7zL2nR9xT4mK8pY1cF6vB3hJ5sD0aGqW7zL2nR9xT4mK8pY1cF6vB3hJ5sD0aG"

postgres://app@db.example/app
https://example.com/docs
http://127.0.0.1:8080/health

let request_id = "123e4567-e89b-12d3-a456-426614174000";
"#;
        let (out, rules) = masked(input);
        assert!(rules.is_empty(), "{rules:?}\n{out}");
        assert_eq!(out, input);

        let mut engine = engine(false);
        let body = serde_json::to_vec(&serde_json::json!({"content": input})).unwrap();
        let (redacted, hits) = engine.redact_bytes(&body).unwrap();
        assert!(hits.is_empty(), "{redacted:?}");
        let value: serde_json::Value = serde_json::from_slice(&redacted).unwrap();
        assert_eq!(value["content"].as_str(), Some(input));
    }

    #[test]
    fn cargo_lock_checksums_are_not_secrets() {
        let lockfile = include_str!("../../../Cargo.lock");
        let (out, rules) = masked(lockfile);
        assert!(rules.is_empty(), "{rules:?}");
        assert_eq!(out, lockfile);
    }

    #[test]
    fn high_entropy_is_off_by_default_and_skips_digests_when_enabled() {
        let token = "qW7zL2nR9xT4mK8pY1cF6vB3hJ5sD0aG";
        let (out, rules) = masked(token);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, token);

        let mut enabled = engine(true);
        let (out, hits) = enabled.redact_str(token).unwrap();
        assert!(!out.contains(token), "{out}");
        assert_eq!(
            hits.iter().map(|hit| hit.rule.clone()).collect::<Vec<_>>(),
            vec![Some("high-entropy".to_string())]
        );
        assert_eq!(enabled.restore_str(&out), token);

        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let digest = format!("sha512-{token}{token}");
        for sample in [hex, uuid, digest.as_str()] {
            let (kept, hits) = enabled.redact_str(sample).unwrap();
            assert!(hits.is_empty(), "{sample} -> {kept}");
            assert_eq!(kept, sample);
        }

        let project = format!("sk-proj-{token}");
        let (out, hits) = enabled.redact_str(&project).unwrap();
        assert!(!out.contains(&project), "{out}");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.as_deref(), Some("openai-api-key"));
        assert_eq!(enabled.restore_str(&out), project);
    }
}
