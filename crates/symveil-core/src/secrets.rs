//! Builtin and user secret rules. Detection lives in `symveil-detect` so
//! `symveil learn` can reuse it without linking the proxy's HTTP stack.

use anyhow::Result;

use symveil_detect::aws::{gap_hits, labeled_secret_hits};
use symveil_detect::dotenv::dotenv_assignment_hits;
use symveil_detect::secrets::{
    base64_hits, high_entropy_hits, split_literal_hits, SecretSet, UserRule,
};

pub use symveil_detect::secrets::{builtin_rule_names, SecretHit};

use crate::category::Category;
use crate::config::SecretRule;
use crate::masker::{Boundary, Candidate, Masker, PRI_PATTERN, PRI_SECRET};
use crate::vault::Vault;

struct SecretLiteral {
    original: String,
    rule: Option<String>,
}

/// Builtin and user secret rules, plus secrets already stored in the vault.
pub struct SecretMasker {
    rules: SecretSet,
    literals: Vec<SecretLiteral>,
    high_entropy: bool,
    dotenv: bool,
}

impl SecretMasker {
    pub(crate) fn compile(
        user: &[SecretRule],
        vault: &Vault,
        high_entropy: bool,
        dotenv: bool,
    ) -> Result<Self> {
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
        let user_rules = user
            .iter()
            .map(|rule| UserRule {
                name: rule.name.clone(),
                regex: rule.regex.clone(),
            })
            .collect::<Vec<_>>();
        Ok(Self {
            rules: SecretSet::compile(&user_rules)?,
            literals,
            high_entropy,
            dotenv,
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
            out.push(secret_candidate(hit));
        }
        for hit in base64_hits(&self.rules, text) {
            out.push(secret_candidate(hit));
        }
        for hit in split_literal_hits(&self.rules, text) {
            out.push(secret_candidate(hit));
        }
        for hit in gap_hits(text) {
            out.push(secret_candidate(hit));
        }
        for hit in labeled_secret_hits(text) {
            out.push(secret_candidate(hit));
        }
        if self.dotenv {
            for hit in dotenv_assignment_hits(text) {
                out.push(secret_candidate(hit));
            }
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

fn secret_candidate(hit: SecretHit) -> Candidate {
    Candidate {
        start: hit.start,
        end: hit.end,
        category: Category::Secret,
        rule: Some(hit.rule),
        priority: PRI_SECRET,
        boundary: Boundary::None,
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
    fn dotenv_file_redacts_values_the_suffix_rules_miss() {
        let input = "\
# synthetic
export OPENAI_API_KEY=sk-Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1
PGPASSWORD=\"n0t-a-token-db-pass\"
DATABASE_URL=postgres://app:db-url-password@db.internal.example/app
SESSION_COOKIE='s3ssion-value-9f3a'
TOKEN_LIMIT=4096
API_KEY=changeme
";
        let (out, rules) = masked(input);
        for secret in [
            "sk-Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1",
            "n0t-a-token-db-pass",
            "db-url-password",
            "db.internal.example",
            "s3ssion-value-9f3a",
        ] {
            assert!(!out.contains(secret), "{secret} in {out}");
        }
        assert!(out.contains("PGPASSWORD="), "{out}");
        assert!(out.contains("SESSION_COOKIE="), "{out}");
        assert!(out.contains("DATABASE_URL="), "{out}");
        assert!(out.contains("TOKEN_LIMIT=4096"), "{out}");
        assert!(out.contains("API_KEY=changeme"), "{out}");
        assert!(out.contains("# synthetic"), "{out}");
        assert!(
            rules.iter().any(|rule| rule == "dotenv-assignment"),
            "{rules:?}"
        );

        let mut off = Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                internal_domains: Vec::new(),
                dotenv: false,
                ..RedactSection::default()
            },
        )
        .unwrap();
        let (kept, _) = off.redact_str(input).unwrap();
        assert!(kept.contains("n0t-a-token-db-pass"), "{kept}");
        assert!(kept.contains("s3ssion-value-9f3a"), "{kept}");
        assert!(!kept.contains("db-url-password"), "{kept}");
        assert!(kept.contains("db.internal.example"), "{kept}");
        assert_eq!(off.restore_str(&kept), input);
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

    #[test]
    fn missing_token_shapes_are_masked_and_near_misses_stay() {
        let cases = [
            (
                "glpat-SVCNGITLABTOKEN0001",
                "glpat-SVCNGITLABTOKEN0001",
                "gitlab-pat",
            ),
            (
                "AccountKey=svcn-azure-bare-0001",
                "svcn-azure-bare-0001",
                "azure-account-key",
            ),
            (
                "xoxb-SVCNSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                "xoxb-SVCNSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                "slack-token",
            ),
            (
                "sk-admin-SVCNadminKey00000000000000000000",
                "sk-admin-SVCNadminKey00000000000000000000",
                "openai-api-key",
            ),
            (
                "sk-svcacct-SVCNsvcacctKey000000000000000000",
                "sk-svcacct-SVCNsvcacctKey000000000000000000",
                "openai-api-key",
            ),
            (
                "mysql -h db.example -pSVCNAgentPassw0rd",
                "SVCNAgentPassw0rd",
                "shell-password",
            ),
            (
                "tool --password SVCNAgentPassw0rd",
                "SVCNAgentPassw0rd",
                "shell-password",
            ),
            (
                "      \"TDH_API_TOKEN=svcn-docker-opaque-0001\",",
                "svcn-docker-opaque-0001",
                "env-assignment",
            ),
            (
                "environ({'TDH_DB_PASSWORD': 'svcn-pytest-opaque-0001'})",
                "svcn-pytest-opaque-0001",
                "repr-env-assignment",
            ),
        ];
        for (input, secret, rule) in cases {
            let (out, rules) = masked(input);
            assert!(!out.contains(secret), "{input} -> {out}");
            assert!(rules.iter().any(|item| item == rule), "{input} {rules:?}");
        }

        let joined = "\"AKIAIOSFODNN7EXA\"\n    \"MPLE\"";
        let (out, rules) = masked(joined);
        assert!(!out.contains("AKIAIOSFODNN7EXA"), "{out}");
        assert!(!out.contains("MPLE"), "{out}");
        assert!(
            rules.iter().any(|rule| rule == "split-string-literal"),
            "{rules:?}"
        );

        let short_split = "\"AKIASVCNSPLIT\"\n    \"KEY001\"";
        let (out, rules) = masked(short_split);
        assert!(rules.is_empty(), "{out}");
        assert_eq!(out, short_split);

        let misses = "\
gcc -pthread
gcc -parameter
mysql -pshort
mysql -p changeme
TOKEN_LIMIT=4096
password = \"changeme\"
glpat-short
AccountKey=short
sk-admin-tooshort
";
        let (out, rules) = masked(misses);
        assert!(rules.is_empty(), "{rules:?}\n{out}");
        assert_eq!(out, misses);
    }
}
