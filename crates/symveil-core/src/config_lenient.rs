//! Load a config while remembering keys this build does not know.
//!
//! `Config::parse` still rejects those keys. `check` reports them and
//! continues, so one typo does not hide the rest of the report. The proxy
//! keeps failing closed on the strict parser.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{Action, Config, LenientConfig};

pub(super) fn parse(text: &str) -> Result<LenientConfig> {
    let mut value: toml::Value = toml::from_str(text).context("parse config")?;
    let mut unknown = Vec::new();
    strip(&mut value, &schema(), "", &mut unknown);
    let mut cfg = Config::deserialize(value).context("parse config")?;
    take_unknown_actions(
        &mut cfg.redact.category_actions,
        &["secret", "ip", "hostname"],
        "redact.category",
        &mut unknown,
    );
    let builtins = super::known_builtin_rules();
    take_unknown_actions(
        &mut cfg.redact.builtin_actions,
        &builtins,
        "redact.builtin",
        &mut unknown,
    );
    cfg.validate()?;
    unknown.sort();
    unknown.dedup();
    Ok(LenientConfig {
        config: cfg,
        unknown_keys: unknown,
    })
}

fn take_unknown_actions(
    map: &mut HashMap<String, Action>,
    known: &[&str],
    prefix: &str,
    unknown: &mut Vec<String>,
) {
    let bad: Vec<String> = map
        .keys()
        .filter(|key| !known.iter().any(|name| name == *key))
        .cloned()
        .collect();
    for key in bad {
        map.remove(&key);
        unknown.push(format!("{prefix}.{key}"));
    }
}

enum Schema {
    Any,
    Table(Vec<(&'static str, Schema)>),
    Array(Box<Schema>),
    /// Every key is accepted here. Callers check names such as builtin rules.
    Map(Box<Schema>),
}

fn schema() -> Schema {
    Schema::Table(vec![
        ("proxy", proxy_schema()),
        ("index", index_schema()),
        ("redact", redact_schema()),
        ("binary", Schema::Table(vec![("mode", Schema::Any)])),
    ])
}

fn proxy_schema() -> Schema {
    Schema::Table(vec![
        ("listen", Schema::Any),
        ("port", Schema::Any),
        ("openai_base", Schema::Any),
        ("anthropic_base", Schema::Any),
        ("timeout_secs", Schema::Any),
        ("audit_log", Schema::Any),
        ("audit_buffered", Schema::Any),
        ("vault", Schema::Any),
    ])
}

fn index_schema() -> Schema {
    Schema::Table(vec![("min_len", Schema::Any), ("extensions", Schema::Any)])
}

fn redact_schema() -> Schema {
    Schema::Table(vec![
        ("allow", Schema::Any),
        ("deny", Schema::Any),
        ("internal_domains", Schema::Any),
        ("mode", Schema::Any),
        ("category", Schema::Map(Box::new(Schema::Any))),
        ("builtin", Schema::Map(Box::new(Schema::Any))),
        ("patterns", Schema::Array(Box::new(pattern_schema()))),
        ("secrets", Schema::Array(Box::new(secret_schema()))),
        ("high_entropy", Schema::Any),
        ("dotenv", Schema::Any),
        ("home_paths", Schema::Any),
        ("username", Schema::Any),
        ("pii", pii_schema()),
        ("names", names_schema()),
        ("learned", Schema::Any),
    ])
}

fn pii_schema() -> Schema {
    Schema::Table(vec![
        ("email", Schema::Any),
        ("phone", Schema::Any),
        ("personnummer", Schema::Any),
    ])
}

fn names_schema() -> Schema {
    Schema::Table(vec![
        ("terms", Schema::Any),
        ("patterns", Schema::Array(Box::new(pattern_schema()))),
        ("people", Schema::Any),
    ])
}

fn pattern_schema() -> Schema {
    Schema::Table(vec![
        ("name", Schema::Any),
        ("regex", Schema::Any),
        ("category", Schema::Any),
    ])
}

fn secret_schema() -> Schema {
    Schema::Table(vec![
        ("name", Schema::Any),
        ("regex", Schema::Any),
        ("action", Schema::Any),
    ])
}

fn strip(value: &mut toml::Value, schema: &Schema, path: &str, unknown: &mut Vec<String>) {
    match schema {
        Schema::Any => {}
        Schema::Map(inner) => {
            let Some(table) = value.as_table_mut() else {
                return;
            };
            let keys: Vec<String> = table.keys().cloned().collect();
            for key in keys {
                let child = child_path(path, &key);
                if let Some(entry) = table.get_mut(&key) {
                    strip(entry, inner, &child, unknown);
                }
            }
        }
        Schema::Array(inner) => {
            let Some(items) = value.as_array_mut() else {
                return;
            };
            for (index, item) in items.iter_mut().enumerate() {
                strip(item, inner, &format!("{path}[{index}]"), unknown);
            }
        }
        Schema::Table(fields) => {
            let Some(table) = value.as_table_mut() else {
                return;
            };
            let present: Vec<String> = table.keys().cloned().collect();
            for key in present {
                let child = child_path(path, &key);
                if let Some((_, sub)) = fields.iter().find(|(name, _)| *name == key) {
                    if let Some(entry) = table.get_mut(&key) {
                        strip(entry, sub, &child, unknown);
                    }
                } else {
                    unknown.push(child);
                    table.remove(&key);
                }
            }
        }
    }
}

fn child_path(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}
