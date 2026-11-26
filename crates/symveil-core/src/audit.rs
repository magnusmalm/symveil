use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::binary::BinaryNote;
use crate::category::Category;
use crate::config::Action;
use crate::redact::Hit;

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub dir: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacements: Option<Vec<AuditReplacement>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restored: Option<usize>,
    /// Image, document, and file blocks replaced before the request was forwarded.
    /// Kind and length only. The bytes are not stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binaries: Option<Vec<BinaryAudit>>,
    /// Set when the proxy refused to decode or forward a body. The body is not stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// Short content-coding token for a refusal. Never the body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// HTTP status returned with a refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct BinaryAudit {
    pub kind: &'static str,
    pub bytes: usize,
    pub disposition: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AuditReplacement {
    pub category: Category,
    pub action: Action,
    /// Present when the match was replaced. Warn and block do not mint a placeholder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub len: usize,
    /// Present for identifiers, addresses, and hostnames. Omitted for secrets and
    /// personal data so the log is not a second copy of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}

pub fn replacement_from_hit(hit: &Hit) -> AuditReplacement {
    let original = match hit.category {
        // Secrets and personal data stay out of the log. The vault still has them.
        Category::Secret | Category::Pii => None,
        Category::Function
        | Category::Type
        | Category::Macro
        | Category::Register
        | Category::Field
        | Category::Enumerator
        | Category::Codename
        | Category::Hostname
        | Category::Ip
        | Category::Identifier => Some(hit.original.clone()),
    };
    let placeholder = match hit.action {
        Action::Redact => Some(hit.placeholder.clone()),
        Action::Warn | Action::Block => None,
    };
    AuditReplacement {
        category: hit.category,
        action: hit.action,
        placeholder,
        rule: hit.rule.clone(),
        len: hit.original.len(),
        original,
    }
}

pub struct AuditLog {
    writer: Option<std::io::BufWriter<std::fs::File>>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::perms::ensure_private_dir(parent)?;
            }
        }
        let file = crate::perms::open_append_private(path)
            .with_context(|| format!("open audit log {}", path.display()))?;
        Ok(Self {
            writer: Some(std::io::BufWriter::new(file)),
        })
    }

    pub fn record_request(
        &mut self,
        path: &str,
        hits: &[Hit],
        binaries: &[BinaryNote],
    ) -> Result<()> {
        if hits.is_empty() && binaries.is_empty() {
            return Ok(());
        }
        let event = AuditEvent {
            ts: timestamp_now(),
            dir: "request",
            path: path.to_string(),
            replacements: if hits.is_empty() {
                None
            } else {
                Some(hits.iter().map(replacement_from_hit).collect())
            },
            restored: None,
            binaries: if binaries.is_empty() {
                None
            } else {
                Some(
                    binaries
                        .iter()
                        .map(|note| BinaryAudit {
                            kind: note.kind,
                            bytes: note.bytes,
                            disposition: "withheld",
                        })
                        .collect(),
                )
            },
            refusal: None,
            encoding: None,
            status: None,
        };
        self.write(&event)
    }

    pub fn record_response(&mut self, path: &str, restored: usize) -> Result<()> {
        if restored == 0 {
            return Ok(());
        }
        let event = AuditEvent {
            ts: timestamp_now(),
            dir: "response",
            path: path.to_string(),
            replacements: None,
            restored: Some(restored),
            binaries: None,
            refusal: None,
            encoding: None,
            status: None,
        };
        self.write(&event)
    }

    /// A body the proxy refused to forward. `refusal` is a short reason code.
    /// `encoding` is a short coding token. The body is not written.
    pub fn record_refusal(
        &mut self,
        path: &str,
        refusal: &str,
        encoding: Option<&str>,
        status: u16,
    ) -> Result<()> {
        let event = AuditEvent {
            ts: timestamp_now(),
            dir: "refuse",
            path: path.to_string(),
            replacements: None,
            restored: None,
            binaries: None,
            refusal: Some(refusal.to_string()),
            encoding: encoding.map(str::to_string),
            status: Some(status),
        };
        self.write(&event)
    }

    fn write(&mut self, event: &AuditEvent) -> Result<()> {
        let Some(writer) = self.writer.as_mut() else {
            return Ok(());
        };
        serde_json::to_writer(&mut *writer, event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }
}

pub fn timestamp_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    format_unix(secs)
}

pub fn format_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's civil_from_days, days relative to Unix epoch.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epochs_format() {
        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(format_unix(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn secret_original_is_omitted() {
        let secret = Hit {
            original: "AKIAIOSFODNN7EXAMPLE".to_string(),
            placeholder: "@@sv:0123abcd@@".to_string(),
            category: Category::Secret,
            rule: Some("aws-access-key-id".to_string()),
            action: Action::Redact,
        };
        let ident = Hit {
            original: "aurora_rcc_enable_pll".to_string(),
            placeholder: "@@sv:abcdef01@@".to_string(),
            category: Category::Function,
            rule: None,
            action: Action::Redact,
        };
        let secret_json = serde_json::to_string(&replacement_from_hit(&secret)).unwrap();
        assert!(!secret_json.contains("AKIA"));
        assert!(secret_json.contains("aws-access-key-id"));
        assert!(secret_json.contains("\"action\":\"redact\""));
        assert!(secret_json.contains("@@sv:0123abcd@@"));
        let ident_json = serde_json::to_string(&replacement_from_hit(&ident)).unwrap();
        assert!(ident_json.contains("aurora_rcc_enable_pll"));
    }

    #[test]
    fn pii_original_is_omitted() {
        let hit = Hit {
            original: "ada@example.com".to_string(),
            placeholder: "@@sv:0123abcd@@".to_string(),
            category: Category::Pii,
            rule: Some("email".to_string()),
            action: Action::Redact,
        };
        let value = serde_json::to_value(replacement_from_hit(&hit)).unwrap();
        assert_eq!(value["category"], "pii");
        assert_eq!(value["rule"], "email");
        assert_eq!(value["len"], 15);
        assert!(value.get("original").is_none());
        let json = value.to_string();
        assert!(!json.contains("ada@example.com"));
        assert!(json.contains("@@sv:0123abcd@@"));
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "symveil-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode_bits(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn new_audit_log_is_owner_rw() {
        let root = temp_dir("audit-mode");
        let path = root.join(".symveil").join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        drop(log);
        assert_eq!(mode_bits(&root.join(".symveil")), 0o700);
        assert_eq!(mode_bits(&path), 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn existing_loose_audit_log_is_not_chmodded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("audit-loose");
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, b"").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        let log = AuditLog::open(&path).unwrap();
        drop(log);
        assert_eq!(mode_bits(&path), 0o644);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn warn_and_block_omit_the_secret_and_any_placeholder() {
        let secret = "widget_tok_abcd1234";
        for action in [Action::Warn, Action::Block] {
            let hit = Hit {
                original: secret.to_string(),
                placeholder: String::new(),
                category: Category::Secret,
                rule: Some("widget-token".to_string()),
                action,
            };
            let json = serde_json::to_string(&replacement_from_hit(&hit)).unwrap();
            assert!(!json.contains(secret), "{json}");
            assert!(!json.contains("widget_tok"), "{json}");
            assert!(!json.contains("placeholder"), "{json}");
            assert!(json.contains("widget-token"), "{json}");
            assert!(json.contains(&format!("\"action\":\"{action}\"")), "{json}");
            assert!(
                json.contains(&format!("\"len\":{}", secret.len())),
                "{json}"
            );
        }
    }

    #[test]
    fn warn_still_records_an_address() {
        let hit = Hit {
            original: "10.1.2.3".to_string(),
            placeholder: String::new(),
            category: Category::Ip,
            rule: Some("ipv4".to_string()),
            action: Action::Warn,
        };
        let json = serde_json::to_string(&replacement_from_hit(&hit)).unwrap();
        assert!(json.contains("10.1.2.3"), "{json}");
        assert!(json.contains("\"action\":\"warn\""));
        assert!(!json.contains("placeholder"), "{json}");
    }

    #[test]
    fn binary_withholding_is_logged_without_the_payload() {
        let dir = temp_dir("audit-binary");
        let path = dir.join("audit.jsonl");
        let mut log = AuditLog::open(&path).unwrap();
        log.record_request(
            "/v1/messages",
            &[],
            &[BinaryNote {
                kind: "image",
                bytes: 128,
            }],
        )
        .unwrap();
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"kind\":\"image\""), "{text}");
        assert!(text.contains("\"bytes\":128"), "{text}");
        assert!(text.contains("\"disposition\":\"withheld\""), "{text}");
        assert!(!text.contains("iVBOR"), "{text}");
        assert!(!text.contains("png.author"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refusal_records_the_reason_and_not_a_body() {
        let dir = temp_dir("audit-refuse");
        let path = dir.join("audit.jsonl");
        let mut log = AuditLog::open(&path).unwrap();
        log.record_refusal(
            "/v1/responses",
            "unsupported-content-encoding",
            Some("xz"),
            415,
        )
        .unwrap();
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"dir\":\"refuse\""), "{text}");
        assert!(
            text.contains("\"refusal\":\"unsupported-content-encoding\""),
            "{text}"
        );
        assert!(text.contains("\"encoding\":\"xz\""), "{text}");
        assert!(text.contains("\"status\":415"), "{text}");
        assert!(!text.contains("replacements"), "{text}");
        assert!(!text.contains("AKIA"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
