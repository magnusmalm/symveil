use std::sync::LazyLock;

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::{Captures, Regex};

use crate::category::Category;
use crate::config::SecretRule;
use crate::masker::{Boundary, Candidate, Masker, PRI_PATTERN, PRI_SECRET};
use crate::vault::Vault;

const VALUE_MIN: usize = 8;

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
        // Optional `=` padding. The regex crate has no lookahead, and `\b` does
        // not hold between `=` and the next non-word byte.
        pattern: r"\beyJ[A-Za-z0-9_-]{10,4000}={0,2}\.[A-Za-z0-9_-]{10,4000}={0,2}\.[A-Za-z0-9_-]{10,4000}={0,2}",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "url-password",
        // Password only. User and host stay so the model can still see the URL.
        // `:` may appear inside the password (`user:pass:word@host`). The
        // required `@` keeps `http://localhost:8080` from matching.
        pattern: r"(?i)\b[a-z][a-z0-9+.-]*://[^:\s/@]*:([^\s/@]{8,})@",
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
        // The optional quote covers `"password": "…"` inside a string of JSON.
        pattern: r#"(?i)\b(?:api[_-]?key|apikey|secret|token|password)\b["']?\s*[=:]\s*(?:'([^'\n]{8,})'|"([^"\n]{8,})")"#,
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
            // Words may contain spaces. A `#` comment and quotes stay outside
            // the value, so a quoted assignment is left to the quoted rule.
            r#"[ \t]*=[ \t]*([^\r\n#'"]+(?:[ \t]+[^\r\n#'"]+)*)"#
        ),
        groups: &[1],
        filter_low_signal: true,
    },
    Builtin {
        name: "env-quoted-assignment",
        pattern: concat!(
            r"(?m)^[ \t]*(?:export[ \t]+)?",
            r"[A-Z_][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS)",
            r#"[ \t]*=[ \t]*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})')"#
        ),
        groups: &[1, 2],
        filter_low_signal: true,
    },
];

pub fn builtin_rule_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = BUILTINS.iter().map(|builtin| builtin.name).collect();
    names.push("base64-secret");
    names
}

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
    pub fn compile(user: &[SecretRule]) -> Result<Self> {
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
            if BUILTINS.iter().any(|builtin| builtin.name == pattern.name) {
                anyhow::bail!(
                    "secret rule `{}` reuses the builtin rule name `{}`. Rename it. A custom rule cannot use a builtin detector name; set that detector's action in [redact.builtin].",
                    pattern.name,
                    pattern.name
                );
            }
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
                if start == end {
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
    if value.chars().count() < VALUE_MIN {
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
    if lower.starts_with('<') && lower.ends_with('>') {
        return true;
    }
    if is_env_reference(&lower) {
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
        "your_api_key_here",
        "your-api-key-here",
        "your_key_here",
        "your-key-here",
        "insert_key_here",
        "insert-key-here",
        "replace_me",
        "replace-me",
    ];
    EXACT.contains(&lower.as_str())
}

/// `${VAR}` and `$NAME` are references. `$upers3cret` is a password.
fn is_env_reference(lower: &str) -> bool {
    let Some(rest) = lower.strip_prefix('$') else {
        return false;
    };
    if rest.starts_with('{') && lower.ends_with('}') && lower.len() > 3 {
        return true;
    }
    let mut chars = rest.chars();
    match chars.next() {
        Some(ch) if ch.is_ascii_uppercase() || ch == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

const HIGH_ENTROPY_MIN: usize = 32;
const HIGH_ENTROPY_MAX: usize = 4_096;
const HIGH_ENTROPY_BITS: f64 = 4.5;

/// Shortest base64 blob worth decoding. An AWS key encodes to 28 characters,
/// so this stays under that.
const BASE64_MIN_LEN: usize = 16;
const BASE64_MAX_LEN: usize = 8 * 1024;
/// `base64(base64(secret))` is decoded twice. A third layer is left alone.
const BASE64_MAX_DEPTH: usize = 2;
const BASE64_BUDGET: usize = 64 * 1024;

static HIGH_ENTROPY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_=-]{32,4096}").expect("high entropy token"));

static BASE64_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").expect("base64 candidate"));

fn high_entropy_hits(text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for matched in HIGH_ENTROPY.find_iter(text) {
        let token = matched.as_str();
        if token.len() < HIGH_ENTROPY_MIN || token.len() > HIGH_ENTROPY_MAX {
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

fn decode_base64_span(token: &str) -> Option<Vec<u8>> {
    if token.len() < BASE64_MIN_LEN || token.len() > BASE64_MAX_LEN {
        return None;
    }
    for engine in [STANDARD, URL_SAFE, STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(token) {
            if !bytes.is_empty() {
                return Some(bytes);
            }
        }
    }
    None
}

/// A decoded blob hides a secret when a builtin rule matches it, or when a
/// further base64 layer (bounded by depth and byte budget) does.
fn decoded_hides_secret(
    rules: &SecretSet,
    decoded: &[u8],
    depth: usize,
    budget: &mut usize,
) -> bool {
    let Ok(text) = std::str::from_utf8(decoded) else {
        return false;
    };
    if !rules.find(text).is_empty() {
        return true;
    }
    if depth >= BASE64_MAX_DEPTH {
        return false;
    }
    for matched in BASE64_CANDIDATE.find_iter(text) {
        let token = matched.as_str();
        if token.len() > BASE64_MAX_LEN {
            continue;
        }
        let Some(inner) = decode_base64_span(token) else {
            continue;
        };
        if *budget < inner.len() {
            return false;
        }
        *budget -= inner.len();
        if decoded_hides_secret(rules, &inner, depth + 1, budget) {
            return true;
        }
    }
    false
}

/// Opaque canaries such as `SVCN-base64-plaintext-secret-0001` are not a
/// builtin shape. Mask the encoding when it is a long high-entropy base64
/// blob whose plaintext is one credential-like word (no spaces, not a hex
/// digest). `high_entropy` itself stays off, so a raw token that does not
/// decode to text is unchanged.
fn opaque_base64_secret(token: &str, decoded: &[u8]) -> bool {
    if token.len() < HIGH_ENTROPY_MIN
        || is_hex_token(token)
        || is_digest_token(token)
        || is_uuid(token)
    {
        return false;
    }
    if shannon_entropy(token) < HIGH_ENTROPY_BITS {
        return false;
    }
    let Ok(text) = std::str::from_utf8(decoded) else {
        return false;
    };
    if text.chars().count() < 16 || text.chars().any(char::is_whitespace) {
        return false;
    }
    if !text
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return false;
    }
    if text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return false;
    }
    text.chars().any(|ch| ch.is_ascii_alphabetic()) && text.chars().any(|ch| ch.is_ascii_digit())
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
    pub(crate) fn compile(user: &[SecretRule], vault: &Vault, high_entropy: bool) -> Result<Self> {
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
        let mut budget = BASE64_BUDGET;
        for matched in BASE64_CANDIDATE.find_iter(text) {
            let token = matched.as_str();
            if token.len() > BASE64_MAX_LEN {
                continue;
            }
            let Some(decoded) = decode_base64_span(token) else {
                continue;
            };
            if budget < decoded.len() {
                break;
            }
            budget -= decoded.len();
            if !decoded_hides_secret(&self.rules, &decoded, 1, &mut budget)
                && !opaque_base64_secret(token, &decoded)
            {
                continue;
            }
            out.push(Candidate {
                start: matched.start(),
                end: matched.end(),
                category: Category::Secret,
                rule: Some("base64-secret".to_string()),
                priority: PRI_SECRET,
                boundary: Boundary::None,
            });
        }
        if self.high_entropy {
            let named: Vec<(usize, usize)> = out.iter().map(|hit| (hit.start, hit.end)).collect();
            for hit in high_entropy_hits(text) {
                // A named rule that overlaps this token already masks the
                // secret. Keeping the earlier high-entropy span would drop
                // that rule and leave the tail visible.
                let overlaps = named
                    .iter()
                    .any(|&(start, end)| hit.start < end && start < hit.end);
                if overlaps {
                    continue;
                }
                out.push(Candidate {
                    start: hit.start,
                    end: hit.end,
                    category: Category::Secret,
                    rule: Some(hit.rule),
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

    #[test]
    fn long_passphrases_and_real_secrets_are_not_treated_as_placeholders() {
        let long = format!("{}Zz", "Ab3xK9mQ".repeat(30));
        assert!(long.chars().count() > 200, "{}", long.chars().count());
        let quoted = format!("API_KEY=\"{long}\"\n");
        let (out, _) = masked(&quoted);
        assert!(!out.contains(&long), "{out}");
        assert!(out.contains("API_KEY"), "{out}");

        let unquoted = format!("DATABASE_PASSWORD={long}\n");
        let (out, _) = masked(&unquoted);
        assert!(!out.contains(&long), "{out}");
        assert!(out.contains("DATABASE_PASSWORD="), "{out}");

        let cjk: String = "密".repeat(40) + &"钥".repeat(40);
        let input = format!("API_KEY=\"{cjk}\"\n");
        let (out, _) = masked(&input);
        assert!(!out.contains(&cjk), "{out}");

        let phrase = "DATABASE_PASSWORD=correct horse battery staple\n";
        let (out, _) = masked(phrase);
        assert!(!out.contains("correct horse"), "{out}");
        assert!(out.contains("DATABASE_PASSWORD="), "{out}");

        for leaked in [
            "API_KEY=changeme123",
            "API_KEY=prod-changeme-rotated",
            "DATABASE_PASSWORD=$upers3cret",
        ] {
            let (out, _) = masked(leaked);
            assert!(!out.contains("changeme123"), "{leaked} -> {out}");
            assert!(!out.contains("prod-changeme-rotated"), "{leaked} -> {out}");
            assert!(!out.contains("$upers3cret"), "{leaked} -> {out}");
        }

        let (kept, rules) = masked("API_KEY=${OTHER_API_KEY}\nAPI_KEY=your_api_key_here\n");
        assert!(rules.is_empty(), "{kept}");
    }

    #[test]
    fn url_password_with_a_colon_and_padded_jwt_are_masked() {
        let input = "postgres://app:notareal:password@db.example/app";
        let (out, rules) = masked(input);
        assert!(!out.contains("notareal:password"), "{out}");
        assert!(out.contains("postgres://app:"), "{out}");
        assert!(out.contains("@db.example/app"), "{out}");
        assert_eq!(rules, vec!["url-password".to_string()]);

        let padded = "eyJhbGciOiJub25lIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIn0=.ZmFrZXNpZ25hdHVyZQ";
        let (out, rules) = masked(padded);
        assert!(!out.contains("eyJzdWIiOiIxMjM0NTY3ODkwIn0"), "{out}");
        assert_eq!(rules, vec!["jwt".to_string()]);
    }

    #[test]
    fn stringified_json_assignment_masks_the_value() {
        let input = r#"{"password": "hunter2hunter2", "note": "keep"}"#;
        let (out, rules) = masked(input);
        assert!(!out.contains("hunter2hunter2"), "{out}");
        assert!(out.contains("password"), "{out}");
        assert!(out.contains("keep"), "{out}");
        assert!(
            rules.iter().any(|rule| rule == "generic-api-key"),
            "{rules:?}"
        );
    }

    #[test]
    fn high_entropy_does_not_unmask_the_tail_of_a_named_secret() {
        let mut enabled = engine(true);
        let jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.ZmFrZXNpZ25hdHVyZQ";
        let input = format!("AUTH_TOKEN={jwt}");
        let (out, hits) = enabled.redact_str(&input).unwrap();
        assert!(!out.contains("eyJzdWIiOiIxIn0"), "{out}");
        assert!(out.contains("AUTH_TOKEN="), "{out}");
        assert!(!hits.is_empty());
        assert_eq!(enabled.restore_str(&out), input);

        let mixed = "DATABASE_PASSWORD=Ab3xK9mQ2pL7vN4sT8wY1zC6dE0fGh:hunter2hunter2";
        let (out, _) = enabled.redact_str(mixed).unwrap();
        assert!(!out.contains("hunter2hunter2"), "{out}");
        assert!(!out.contains("Ab3xK9mQ2pL7vN4sT8wY1zC6dE0fGh"), "{out}");
        assert!(out.contains("DATABASE_PASSWORD="), "{out}");
        assert_eq!(enabled.restore_str(&out), mixed);
    }

    #[test]
    fn base64_decode_and_rescan_masks_encoded_secrets_without_high_entropy() {
        let aws = "QUtJQVNWQ05FTkNPREVES0VZMDE=";
        let short = "U1ZDTi1iYXNlNjQtcGxhaW50ZXh0LXNlY3JldC0wMDAx";
        let long = "U1ZDTi1sb25nLWJhc2U2NC1zZWNyZXQtUTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4UTdtWnhRN21aeFE3bVp4";
        let url_safe = "QUtJQUlPU0ZPRE5ON0VYQU1QTEV-";
        let nested = "UVV0SlFVbFBVMFpQUkU1T04wVllRVTFRVEVVPQ==";
        for token in [aws, short, long, url_safe, nested] {
            let (out, rules) = masked(token);
            assert!(!out.contains(token), "{token} -> {out}");
            assert_eq!(rules, vec!["base64-secret".to_string()], "{token}");
        }

        let raw = "qW7zL2nR9xT4mK8pY1cF6vB3hJ5sD0aG";
        let (kept, rules) = masked(raw);
        assert!(rules.is_empty(), "{kept}");
        assert_eq!(kept, raw);

        let sentence = "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==";
        let (kept, rules) = masked(sentence);
        assert!(rules.is_empty(), "{kept}");
        assert_eq!(kept, sentence);

        let hyphenated = "aGVsbG8td29ybGQtdGhpcy1pcy1ub3QtYS1zZWNyZXQ=";
        let (kept, rules) = masked(hyphenated);
        assert!(rules.is_empty(), "{kept}");
        assert_eq!(kept, hyphenated);
    }
}
