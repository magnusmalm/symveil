//! `learned.toml` on disk, mode 0600, outside the scanned tree.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use anyhow::{bail, Context, Result};
use regex::Regex;
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
    let mut expanded = decisions.to_vec();
    refile_org_phrases(&mut expanded);
    expand_spaced_names(&mut expanded);
    add_person_term_tokens(&mut expanded);
    let mut by_key: HashMap<String, Decision> = HashMap::new();
    for decision in expanded {
        by_key.insert(decision.key.clone(), decision);
    }
    let mut ordered: Vec<Decision> = by_key.into_values().collect();
    ordered.sort_by(|left, right| left.key.cmp(&right.key).then(left.text.cmp(&right.text)));
    collapse_redundant(&mut ordered);

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
            DecisionAction::Skip => {}
            DecisionAction::Redact => match filed_category(decision) {
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

/// `Exempla Tundrahorn` is a company and a product, not a person. Each word
/// becomes a term so `Exemplas`, `Exem-pla`, and `tundrahorn_fan` match.
fn refile_org_phrases(decisions: &mut Vec<Decision>) {
    let mut extra = Vec::new();
    decisions.retain(|decision| {
        if decision.action != DecisionAction::Redact
            || decision.category != LearnCategory::Person
            || !is_org_phrase(&decision.text)
        {
            return true;
        }
        for word in decision.text.split_whitespace() {
            extra.push(named_term(decision, word));
        }
        false
    });
    decisions.extend(extra);
}

/// A person token of at least four letters is also a term, so `Testdotter`
/// takes the same suffix and separator rules as a company name. `Ren` stays
/// only on the person entry.
fn add_person_term_tokens(decisions: &mut Vec<Decision>) {
    let mut extra = Vec::new();
    for decision in decisions.iter() {
        if decision.action != DecisionAction::Redact
            || decision.category != LearnCategory::Person
            || looks_like_credential(&decision.text)
        {
            continue;
        }
        for token in decision.text.split_whitespace() {
            if token.chars().filter(|ch| ch.is_alphanumeric()).count() >= 4 {
                extra.push(named_term(decision, token));
            }
        }
    }
    decisions.extend(extra);
}

fn expand_spaced_names(decisions: &mut Vec<Decision>) {
    let mut extra = Vec::new();
    decisions.retain(|decision| {
        if decision.action != DecisionAction::Redact || decision.category != LearnCategory::Name {
            return true;
        }
        let words: Vec<&str> = decision.text.split_whitespace().collect();
        if words.len() < 2 {
            return true;
        }
        for word in words {
            extra.push(named_term(decision, word));
        }
        false
    });
    decisions.extend(extra);
}

fn named_term(decision: &Decision, word: &str) -> Decision {
    let mut one = Decision::new(DecisionAction::Redact, LearnCategory::Name, word);
    one.sources = decision.sources.clone();
    one.left_glued = decision.left_glued;
    one.right_glued = decision.right_glued;
    one
}

/// Two or more capitalised words of at least four letters. `Ren Testdotter`
/// stays a person because the first name is shorter.
fn is_org_phrase(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    words.len() >= 2
        && words.iter().all(|word| {
            let mut chars = word.chars();
            let Some(first) = chars.next() else {
                return false;
            };
            first.is_uppercase()
                && chars.all(|ch| !ch.is_uppercase())
                && word.chars().count() >= 4
                && !crate::stoplist::is_calendar(word)
        })
}

fn filed_category(decision: &Decision) -> LearnCategory {
    if decision.category == LearnCategory::Person && looks_like_credential(&decision.text) {
        LearnCategory::Secret
    } else {
        decision.category
    }
}

/// A hyphenated opaque token is a secret, not a person name.
fn looks_like_credential(text: &str) -> bool {
    if text.contains(char::is_whitespace) {
        return false;
    }
    let n = text.chars().count();
    n >= 12
        && text.chars().any(|ch| ch.is_ascii_digit())
        && text.chars().any(|ch| ch.is_ascii_alphabetic())
}

fn rule(decision: &Decision) -> Result<LearnedRule> {
    let regex = matching_regex(
        &decision.text,
        &decision.sources,
        decision.left_glued,
        decision.right_glued,
    )?;
    Ok(LearnedRule {
        name: format!(
            "learned-{}-{:016x}",
            filed_category(decision).as_str(),
            fnv(&decision.text)
        ),
        regex,
    })
}

/// A literal the proxy can match on every stored source line.
///
/// `\b` is added on a side only when that side is a word boundary in every
/// source line. A password glued to `-p` has no leading boundary, so a wrapped
/// `\b...\b` would never fire. A product code becomes a prefix-and-tail
/// pattern (`TDH-4471` → `TDH-\d+`) when that pattern still matches the line.
pub fn matching_regex(
    text: &str,
    sources: &[String],
    left_glued: bool,
    right_glued: bool,
) -> Result<String> {
    if let Some(pattern) = product_code_regex(text) {
        if covers(&pattern, text, sources)? {
            return Ok(pattern);
        }
    }
    let escaped = escape_literal(text);
    let wordish = !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    if !wordish {
        return covered_or_bail(text, sources, escaped);
    }
    let left = if left_glued || side_glued(text, sources, true) {
        ""
    } else {
        r"\b"
    };
    let right = if right_glued || side_glued(text, sources, false) {
        ""
    } else {
        r"\b"
    };
    let wrapped = format!("{left}{escaped}{right}");
    if covers(&wrapped, text, sources)? {
        return Ok(wrapped);
    }
    covered_or_bail(text, sources, escaped)
}

fn covered_or_bail(text: &str, sources: &[String], regex: String) -> Result<String> {
    if covers(&regex, text, sources)? {
        Ok(regex)
    } else {
        bail!(
            "refusing a learned rule for a {}-character value because it does not match its source line",
            text.chars().count()
        )
    }
}

fn covers(pattern: &str, text: &str, sources: &[String]) -> Result<bool> {
    let re = Regex::new(pattern).with_context(|| "learned rule regex")?;
    let lines: Vec<&str> = sources
        .iter()
        .map(String::as_str)
        .filter(|line| line.contains(text))
        .collect();
    if lines.is_empty() {
        return Ok(re.is_match(text));
    }
    Ok(lines.iter().all(|line| re.is_match(line)))
}

fn side_glued(text: &str, sources: &[String], left: bool) -> bool {
    sources.iter().any(|line| {
        let Some(pos) = line.find(text) else {
            return false;
        };
        if left {
            line[..pos].chars().next_back().is_some_and(is_regex_word)
        } else {
            line[pos + text.len()..]
                .chars()
                .next()
                .is_some_and(is_regex_word)
        }
    })
}

fn is_regex_word(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

/// `regex::escape` leaves raw newlines in the pattern. Spell controls as
/// escapes so a learned rule stays printable and still matches the source.
fn escape_literal(text: &str) -> String {
    regex::escape(text)
        .replace('\n', r"\n")
        .replace('\r', r"\r")
        .replace('\t', r"\t")
}

static CODE_NUM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Z]{2,8})-(\d{2,8})$").expect("numeric product code"));
static CODE_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([A-Z]{2,8})-([A-Z]{2,16})-(\d{1,6})$").expect("word product code")
});

fn product_code_regex(text: &str) -> Option<String> {
    if let Some(caps) = CODE_NUM.captures(text) {
        return Some(format!(r"{}\-\d+", regex::escape(&caps[1])));
    }
    if let Some(caps) = CODE_WORD.captures(text) {
        return Some(format!(r"{}\-[A-Z]+-\d+", regex::escape(&caps[1])));
    }
    None
}

const NAME_SUFFIXES: &[&str] = &[
    "arna", "erna", "orna", "en", "et", "na", "ar", "or", "er", "s",
];

/// Drop a decision the proxy already covers with a broader term, person, or email.
fn collapse_redundant(decisions: &mut Vec<Decision>) {
    let terms: Vec<String> = decisions
        .iter()
        .filter(|decision| {
            decision.action == DecisionAction::Redact && decision.category == LearnCategory::Name
        })
        .map(|decision| decision.text.clone())
        .collect();
    let emails: Vec<String> = decisions
        .iter()
        .filter(|decision| {
            decision.action == DecisionAction::Redact && decision.category == LearnCategory::Email
        })
        .map(|decision| decision.text.to_lowercase())
        .collect();
    decisions.retain(|decision| {
        decision.action != DecisionAction::Redact || !redundant(decision, &terms, &emails)
    });
}

fn redundant(decision: &Decision, terms: &[String], emails: &[String]) -> bool {
    if decision.category == LearnCategory::Name {
        if terms
            .iter()
            .any(|term| term != &decision.text && same_or_suffix(&decision.text, term))
        {
            return true;
        }
        let words: Vec<&str> = decision.text.split_whitespace().collect();
        if words.len() >= 2
            && words
                .iter()
                .all(|word| terms.iter().any(|term| letters(term) == letters(word)))
        {
            return true;
        }
    }
    if matches!(
        decision.category,
        LearnCategory::Symbol | LearnCategory::Host | LearnCategory::Domain
    ) {
        if product_code_regex(&decision.text).is_some() {
            return false;
        }
        // A suffix (`Exemplas`) or a trailing separator (`exempla_`) is already
        // covered. A longer identifier (`tundrahorn_fan_init`) is not: the tail
        // would stay visible.
        if terms
            .iter()
            .any(|term| same_or_suffix(&decision.text, term))
        {
            return true;
        }
        let lower = decision.text.to_lowercase();
        if emails
            .iter()
            .any(|email| email.contains(&lower) && email != &lower)
        {
            return true;
        }
    }
    false
}

fn same_or_suffix(text: &str, broader: &str) -> bool {
    let own = letters(text);
    let base = letters(broader);
    if own == base {
        return text != broader
            && (text.chars().count() > broader.chars().count()
                || (text.chars().count() == broader.chars().count() && text > broader));
    }
    own.starts_with(&base)
        && NAME_SUFFIXES
            .iter()
            .any(|suffix| own == format!("{base}{suffix}"))
}

fn letters(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
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
        assert_eq!(
            parsed.names.terms,
            vec!["Exempla".to_string(), "Testdotter".to_string()]
        );
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

    #[test]
    fn glued_password_rule_matches_its_source_line() {
        let line = "\"mysql -h db.tundrahorn.corp -pSVCNAgentPassw0rd\"";
        let mut decision = Decision::new(
            DecisionAction::Redact,
            LearnCategory::Secret,
            "SVCNAgentPassw0rd",
        );
        decision.sources = vec![line.to_string()];
        decision.left_glued = true;
        let file = file_from_decisions(&[decision]).unwrap();
        let regex = &file.secrets[0].regex;
        assert!(
            !regex.starts_with(r"\b"),
            "a boundary before the password cannot match `-p`: {regex}"
        );
        let re = regex::Regex::new(regex).unwrap();
        assert!(re.is_match(line), "{regex} did not match {line}");
    }

    #[test]
    fn word_fragment_inside_an_identifier_is_not_a_dead_boundary() {
        let line = "#define TDH_FAN_MAX 2400";
        let regex = super::matching_regex("MAX", &[line.to_string()], true, false).unwrap();
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match(line), "{regex} did not match {line}");
        assert!(
            !regex.starts_with(r"\b"),
            "a leading boundary cannot match inside TDH_FAN_MAX: {regex}"
        );
    }

    #[test]
    fn product_code_becomes_a_prefix_and_tail_pattern() {
        let line = "code: TDH-4471";
        let regex = super::matching_regex("TDH-4471", &[line.to_string()], false, false).unwrap();
        assert_eq!(regex, r"TDH\-\d+");
        assert!(regex::Regex::new(&regex).unwrap().is_match(line));
        let fan = super::matching_regex("FAN-ALPHA-2", &["/* FAN-ALPHA-2 */".into()], false, false)
            .unwrap();
        assert!(regex::Regex::new(&fan).unwrap().is_match("see FAN-BETA-9"));
    }

    #[test]
    fn broader_terms_absorb_suffixes_and_keep_full_identifiers() {
        let decisions = vec![
            Decision::new(DecisionAction::Redact, LearnCategory::Name, "Exempla"),
            Decision::new(DecisionAction::Redact, LearnCategory::Name, "Exemplas"),
            Decision::new(DecisionAction::Redact, LearnCategory::Name, "exempla_"),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Name,
                "Exempla Tundrahorn",
            ),
            Decision::new(DecisionAction::Redact, LearnCategory::Name, "Tundrahorn"),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Symbol,
                "tundrahorn_fan_init",
            ),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Email,
                "fan.operator@exempla.test",
            ),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Domain,
                "exempla.test",
            ),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Person,
                "svcn-pytest-opaque-0001",
            ),
        ];
        let file = file_from_decisions(&decisions).unwrap();
        assert_eq!(
            file.names.terms,
            vec!["Exempla".to_string(), "Tundrahorn".to_string()]
        );
        assert!(
            file.symbols
                .iter()
                .any(|rule| rule.regex.contains("tundrahorn_fan_init")),
            "the full identifier should stay when the term only covers its prefix: {:?}",
            file.symbols
        );
        assert_eq!(file.symbols.len(), 1, "{:?}", file.symbols);
        assert!(file.names.people.is_empty(), "{:?}", file.names.people);
        assert!(file.secrets.iter().any(|rule| {
            regex::Regex::new(&rule.regex)
                .unwrap()
                .is_match("svcn-pytest-opaque-0001")
        }));
        assert!(file
            .secrets
            .iter()
            .all(|rule| !rule.regex.contains("exempla.test") || rule.regex.contains('@')));
    }

    #[test]
    fn a_company_phrase_becomes_terms_and_a_skip_writes_no_rule() {
        let decisions = vec![
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Person,
                "Exempla Tundrahorn",
            ),
            Decision::new(
                DecisionAction::Redact,
                LearnCategory::Person,
                "Ren Testdotter",
            ),
            Decision::new(DecisionAction::Skip, LearnCategory::Symbol, "zephyr_marker"),
        ];
        let file = file_from_decisions(&decisions).unwrap();
        assert_eq!(file.names.people, vec!["Ren Testdotter".to_string()]);
        assert!(file.names.terms.iter().any(|term| term == "Exempla"));
        assert!(file.names.terms.iter().any(|term| term == "Tundrahorn"));
        assert!(file.names.terms.iter().any(|term| term == "Testdotter"));
        assert!(file.symbols.is_empty(), "{:?}", file.symbols);
        assert!(file.secrets.is_empty(), "{:?}", file.secrets);
        assert!(file
            .decisions
            .iter()
            .any(|decision| decision.action == "skip" && decision.text == "zephyr_marker"));
        assert!(file
            .decisions
            .iter()
            .all(|decision| decision.text != "Exempla Tundrahorn"));
        let parsed = LearnedFile::parse(&file.to_toml().unwrap()).unwrap();
        assert_eq!(parsed.names.people, file.names.people);
        assert!(parsed
            .decisions
            .iter()
            .any(|decision| decision.action == "skip"));
    }
}
