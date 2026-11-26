//! Builtin secret shapes shared by the proxy and `symveil learn`.
//!
//! This crate has no HTTP client and does not open sockets. Callers decide
//! what to do with a span. Nothing here contacts a network.

use std::sync::LazyLock;

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::{Captures, Regex};

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
        pattern: r"\bxox[baprs]-[0-9A-Za-z-]{10,256}\b",
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
        // Legacy keys are `sk-` plus 48 alphanumeric characters. Project,
        // admin, and service-account keys share a longer body. `sk-ant-`
        // does not fit any of these shapes.
        pattern: r"\bsk-(?:(?:proj|admin|svcacct)-[A-Za-z0-9_-]{32,2000}|[A-Za-z0-9]{48})\b",
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
            // One quote covers a docker inspect Env entry, which is a JSON
            // string and therefore has a quote before the name in the raw file.
            r#"["']?"#,
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
            r#"["']?"#,
            r"[A-Z_][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS)",
            r#"[ \t]*=[ \t]*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})')"#
        ),
        groups: &[1, 2],
        filter_low_signal: true,
    },
    Builtin {
        name: "gitlab-pat",
        pattern: r"\bglpat-[A-Za-z0-9_-]{16,}\b",
        groups: &[],
        filter_low_signal: false,
    },
    Builtin {
        name: "azure-account-key",
        pattern: r#"(?i)\bAccountKey=([^\s&;"']{8,})"#,
        groups: &[1],
        filter_low_signal: true,
    },
    Builtin {
        name: "repr-env-assignment",
        // pytest's environ({...}) and a Python dict. The name stays.
        pattern: r#"['"]([A-Z][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS))['"]\s*:\s*(?:'([^'\n]{8,})'|"([^"\n]{8,})")"#,
        groups: &[2, 3],
        filter_low_signal: true,
    },
    Builtin {
        name: "shell-password",
        // A password glued to `-p`, or following `--password` / `--pass`.
        // The glued form has to contain a digit, so `-parameter` stays a flag.
        // A spaced `-p file` is left alone: `-p` is also a filename flag.
        pattern: r#"(?i)(?:--password|--pass)(?:=|\s+)([^\s'"]{8,})|(?:^|[\s;|&])-p([^\s'"]*\d[^\s'"]*)"#,
        groups: &[1, 2],
        filter_low_signal: true,
    },
];

pub fn builtin_rule_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = BUILTINS.iter().map(|builtin| builtin.name).collect();
    names.push("base64-secret");
    names.push("split-string-literal");
    names
}

/// A user-supplied rule. The proxy passes `[redact.secrets]` entries here.
#[derive(Debug, Clone)]
pub struct UserRule {
    pub name: String,
    pub regex: String,
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
    pub fn compile(user: &[UserRule]) -> Result<Self> {
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

static ADJACENT_STRINGS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"\\]*)"\s+"([^"\\]*)""#).expect("adjacent string literals"));

pub fn high_entropy_hits(text: &str) -> Vec<SecretHit> {
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

/// Base64 blobs whose decoded text hides a builtin secret, or a long opaque
/// credential-like word. Same spans the proxy masks as `base64-secret`.
pub fn base64_hits(rules: &SecretSet, text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
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
        if !decoded_hides_secret(rules, &decoded, 1, &mut budget)
            && !opaque_base64_secret(token, &decoded)
        {
            continue;
        }
        hits.push(SecretHit {
            start: matched.start(),
            end: matched.end(),
            rule: "base64-secret".to_string(),
        });
    }
    hits
}

/// Two adjacent double-quoted literals whose concatenation is a builtin secret.
pub fn split_literal_hits(rules: &SecretSet, text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for caps in ADJACENT_STRINGS.captures_iter(text) {
        let Some(left) = caps.get(1) else {
            continue;
        };
        let Some(right) = caps.get(2) else {
            continue;
        };
        let joined = format!("{}{}", left.as_str(), right.as_str());
        let boundary = left.as_str().len();
        let crosses = rules
            .find(&joined)
            .into_iter()
            .any(|hit| hit.start < boundary && hit.end > boundary);
        if !crosses {
            continue;
        }
        for part in [left, right] {
            if part.as_str().is_empty() {
                continue;
            }
            hits.push(SecretHit {
                start: part.start(),
                end: part.end(),
                rule: "split-string-literal".to_string(),
            });
        }
    }
    hits
}

static BUILTIN_SET: LazyLock<SecretSet> =
    LazyLock::new(|| SecretSet::compile(&[]).expect("builtin secret rules compile"));

/// Builtin rules, base64 secrets, and split string literals. High-entropy
/// tokens are [`high_entropy_hits`] and stay separate, matching the proxy
/// default (`high_entropy` off).
pub fn scan_secrets(text: &str) -> Vec<SecretHit> {
    let rules = &*BUILTIN_SET;
    let mut hits = rules.find(text);
    hits.extend(base64_hits(rules, text));
    hits.extend(split_literal_hits(rules, text));
    hits
}

#[cfg(test)]
mod tests {
    use super::{high_entropy_hits, scan_secrets};

    #[test]
    fn aws_example_key_is_a_builtin_secret() {
        let hits = scan_secrets("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(hits.iter().any(|hit| hit.rule == "aws-access-key-id"));
    }

    #[test]
    fn repeated_character_is_not_high_entropy() {
        let token = "a".repeat(40);
        assert!(high_entropy_hits(&token).is_empty());
    }

    #[test]
    fn uuid_is_not_high_entropy() {
        let token = "123e4567-e89b-12d3-a456-426614174000";
        assert!(high_entropy_hits(token).is_empty());
    }
}
