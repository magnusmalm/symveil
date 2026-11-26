//! `learned.toml` on disk, mode 0600, outside the scanned tree.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use symveil_detect::learned::{
    DecisionRecord, LearnedAllow, LearnedFile, LearnedNames, LearnedRule,
};

use crate::model::{Decision, DecisionAction, LearnCategory};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub fn load_decisions(path: &Path) -> Result<Vec<Decision>> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let file = LearnedFile::parse(&text).with_context(|| format!("parse {}", path.display()))?;
    if !file.decisions.is_empty() {
        let mut decisions = Vec::with_capacity(file.decisions.len());
        for record in &file.decisions {
            let Some(decision) = Decision::from_record(record) else {
                bail!(
                    "learned decision `{}` has an unknown action or category",
                    record.key
                );
            };
            decisions.push(decision);
        }
        return Ok(decisions);
    }
    Ok(synthesize(&file))
}

fn synthesize(file: &LearnedFile) -> Vec<Decision> {
    let mut decisions = Vec::new();
    for term in &file.names.terms {
        decisions.push(Decision::new(
            DecisionAction::Redact,
            LearnCategory::Name,
            term,
        ));
    }
    for person in &file.names.people {
        decisions.push(Decision::new(
            DecisionAction::Redact,
            LearnCategory::Person,
            person,
        ));
    }
    for entry in &file.allow.entries {
        decisions.push(Decision::new(
            DecisionAction::Keep,
            LearnCategory::Symbol,
            entry,
        ));
    }
    decisions
}

pub fn file_from_decisions(decisions: &[Decision]) -> Result<LearnedFile> {
    let mut by_key: HashMap<String, Decision> = HashMap::new();
    for decision in decisions {
        by_key.insert(decision.key.clone(), decision.clone());
    }
    let mut ordered: Vec<Decision> = by_key.into_values().collect();
    ordered.sort_by(|left, right| left.key.cmp(&right.key).then(left.text.cmp(&right.text)));

    let mut names = LearnedNames::default();
    let mut secrets = Vec::new();
    let mut symbols = Vec::new();
    let mut allow = Vec::new();
    let mut records = Vec::new();
    for decision in &ordered {
        records.push(DecisionRecord {
            key: decision.key.clone(),
            action: decision.action.as_str().to_string(),
            category: decision.category.as_str().to_string(),
            text: decision.text.clone(),
        });
        match decision.action {
            DecisionAction::Keep => push_unique(&mut allow, &decision.text),
            DecisionAction::Redact => match decision.category {
                LearnCategory::Name => {
                    check_term(&decision.text)?;
                    push_unique(&mut names.terms, &decision.text);
                }
                LearnCategory::Person => {
                    check_person(&decision.text)?;
                    push_unique(&mut names.people, &decision.text);
                }
                LearnCategory::Symbol => symbols.push(rule(decision)?),
                LearnCategory::Secret
                | LearnCategory::Email
                | LearnCategory::Ip
                | LearnCategory::Host
                | LearnCategory::Domain => secrets.push(rule(decision)?),
            },
        }
    }
    names.terms.sort();
    names.people.sort();
    allow.sort();
    secrets.sort_by(|left, right| left.name.cmp(&right.name));
    symbols.sort_by(|left, right| left.name.cmp(&right.name));
    records.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(LearnedFile {
        version: 1,
        names,
        secrets,
        symbols,
        allow: LearnedAllow { entries: allow },
        decisions: records,
    })
}

fn rule(decision: &Decision) -> Result<LearnedRule> {
    let regex = literal_regex(&decision.text);
    regex::Regex::new(&regex).with_context(|| {
        format!(
            "learned {} rule for a {}-character value",
            decision.category,
            decision.text.chars().count()
        )
    })?;
    Ok(LearnedRule {
        name: format!(
            "learned-{}-{:016x}",
            decision.category.as_str(),
            fnv(&decision.text)
        ),
        regex,
    })
}

fn literal_regex(text: &str) -> String {
    let escaped = regex::escape(text);
    let word = !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    if word {
        format!(r"\b{escaped}\b")
    } else {
        escaped
    }
}

fn fnv(text: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn check_term(text: &str) -> Result<()> {
    if text.chars().filter(|ch| ch.is_alphanumeric()).count() < 3 {
        bail!("name `{text}` needs at least 3 letters or digits");
    }
    Ok(())
}

fn check_person(text: &str) -> Result<()> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.is_empty() {
        bail!("person name is empty");
    }
    for token in tokens {
        if token.chars().filter(|ch| ch.is_alphanumeric()).count() < 3 {
            bail!("person name `{text}` has a token shorter than 3 letters or digits");
        }
    }
    Ok(())
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !value.is_empty() && !list.iter().any(|existing| existing == value) {
        list.push(value.to_string());
    }
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            create_private_dir(parent)?;
        }
    }
    if path.exists() {
        let meta =
            fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if meta.file_type().is_symlink() {
            bail!("refusing to write {} through a symlink", path.display());
        }
    }
    let tmp = temp_sibling(path);
    let write_result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", tmp.display()))?;
        #[cfg(unix)]
        set_mode(&tmp, 0o600)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("replace {}", path.display()));
    }
    #[cfg(unix)]
    set_mode(path, 0o600)?;
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        if !dir.is_dir() {
            bail!("{} exists and is not a directory", dir.display());
        }
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            create_private_dir(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
        set_mode(dir, 0o700)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

fn temp_sibling(path: &Path) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("learned.toml"),
        std::process::id(),
        seq
    );
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_lists_names_symbols_secrets_and_allow_without_a_proxy_table() {
        let decisions = vec![
            Decision::new(DecisionAction::Redact, LearnCategory::Name, "Exempla"),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Person,
                "Ren Testdotter",
            ),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Symbol,
                "tundrahorn_fan_init",
            ),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Secret,
                "AKIAIOSFODNN7EXAMPLE",
            ),
            Decision::new(DecisionAction::Keep, LearnCategory::Symbol, "threshold"),
        ];
        let file = file_from_decisions(&decisions).unwrap();
        let text = file.to_toml().unwrap();
        assert!(text.contains("Exempla"));
        assert!(text.contains("Ren Testdotter"));
        assert!(text.contains("tundrahorn_fan_init"));
        assert!(text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(text.contains("threshold"));
        assert!(!text.contains("[proxy]"));
        assert!(!text.contains("openai_base"));
        let parsed = LearnedFile::parse(&text).unwrap();
        assert_eq!(parsed.names.terms, vec!["Exempla".to_string()]);
        assert_eq!(parsed.names.people, vec!["Ren Testdotter".to_string()]);
        assert_eq!(parsed.allow.entries, vec!["threshold".to_string()]);
        assert!(parsed
            .symbols
            .iter()
            .any(|rule| rule.regex.contains("tundrahorn_fan_init")));
        assert!(parsed
            .secrets
            .iter()
            .any(|rule| rule.regex.contains("AKIAIOSFODNN7EXAMPLE")));
        let again = load_round_trip(&text);
        assert!(again.iter().any(|decision| decision.text == "Exempla"));
    }

    fn load_round_trip(text: &str) -> Vec<Decision> {
        let dir = std::env::temp_dir().join(format!(
            "symveil-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let nested = dir.join("nested");
        let path = nested.join("learned.toml");
        write_private(&path, text.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "learned.toml mode is {mode:o}");
            let dir_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "config dir mode is {dir_mode:o}");
        }
        let decisions = load_decisions(&path).unwrap();
        let _ = fs::remove_dir_all(&dir);
        decisions
    }

    #[test]
    fn resume_hides_decided_keys() {
        let first = vec![Decision::new(
            DecisionAction::Keep,
            LearnCategory::Symbol,
            "threshold",
        )];
        let file = file_from_decisions(&first).unwrap();
        let loaded = {
            let parsed = LearnedFile::parse(&file.to_toml().unwrap()).unwrap();
            parsed
                .decisions
                .iter()
                .map(|record| Decision::from_record(record).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(loaded[0].key, first[0].key);
        assert_eq!(loaded[0].action, DecisionAction::Keep);
    }
}
