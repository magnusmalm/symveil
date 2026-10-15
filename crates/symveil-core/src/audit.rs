use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::category::Category;
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
}

#[derive(Debug, Serialize)]
pub struct AuditReplacement {
    pub category: Category,
    pub placeholder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub len: usize,
    /// Present for identifiers. Omitted for secrets so the log is not a second copy of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}

pub fn replacement_from_hit(hit: &Hit) -> AuditReplacement {
    let original = match hit.category {
        Category::Secret => None,
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
    AuditReplacement {
        category: hit.category,
        placeholder: hit.placeholder.clone(),
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
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open audit log {}", path.display()))?;
        Ok(Self {
            writer: Some(std::io::BufWriter::new(file)),
        })
    }

    pub fn record_request(&mut self, path: &str, hits: &[Hit]) -> Result<()> {
        if hits.is_empty() {
            return Ok(());
        }
        let event = AuditEvent {
            ts: timestamp_now(),
            dir: "request",
            path: path.to_string(),
            replacements: Some(hits.iter().map(replacement_from_hit).collect()),
            restored: None,
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
        };
        let ident = Hit {
            original: "aurora_rcc_enable_pll".to_string(),
            placeholder: "@@sv:abcdef01@@".to_string(),
            category: Category::Function,
            rule: None,
        };
        let secret_json = serde_json::to_string(&replacement_from_hit(&secret)).unwrap();
        assert!(!secret_json.contains("AKIA"));
        assert!(secret_json.contains("aws-access-key-id"));
        let ident_json = serde_json::to_string(&replacement_from_hit(&ident)).unwrap();
        assert!(ident_json.contains("aurora_rcc_enable_pll"));
    }
}
