//! Deterministic candidate extraction. No model calls.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

#[cfg(test)]
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use symveil_detect::secrets::{high_entropy_hits, scan_secrets};

use crate::model::{key_for, Candidate, LearnCategory};
use crate::stoplist::{is_calendar, is_common, is_stopped};
use crate::walk::WalkedFile;

static IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]{2,}").expect("identifier"));
static CAP_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z][a-z]{2,}\b").expect("capitalised word"));
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,24}\b").expect("email")
});
static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z][a-z0-9+.-]*://(?:[^/\s@]+@)?([A-Za-z0-9._\-]+)").expect("url")
});
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\.)+(?:[a-z]{2,24})\b")
        .expect("host")
});
static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])",
    )
    .expect("ipv4")
});
static PRODUCT_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z]{2,8}-\d{2,8}\b|\b[A-Z]{2,8}-[A-Z]{2,16}-\d{1,6}\b").expect("product code")
});
static FLAG_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:--password(?:=|\s+)|-p)([A-Za-z][A-Za-z0-9!@#$%^&*._-]{7,80})")
        .expect("flag secret")
});
static PERSON_PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\p{Lu}\p{Ll}{1,30})\s+(\p{Lu}\p{Ll}{2,40})\b").expect("person pair")
});

struct RawHit {
    start: usize,
    end: usize,
    text: String,
    category: LearnCategory,
    rule: Option<String>,
    in_comment: bool,
}

struct Acc {
    text: String,
    category: LearnCategory,
    rule: Option<String>,
    occurrences: u64,
    files: std::collections::BTreeSet<String>,
    first_file: String,
    first_line: u32,
    context: String,
    sources: Vec<String>,
    left_glued: bool,
    right_glued: bool,
    code_hits: u64,
    comment_hits: u64,
}

#[cfg(test)]
pub(crate) fn extract(files: &[WalkedFile]) -> Vec<Candidate> {
    let parts: Vec<Vec<RawHit>> = files
        .par_iter()
        .map(|file| extract_file(&file.text))
        .collect();
    assemble(files, parts)
}

#[cfg(test)]
pub(crate) fn extract_sequential(files: &[WalkedFile]) -> Vec<Candidate> {
    let parts: Vec<Vec<RawHit>> = files.iter().map(|file| extract_file(&file.text)).collect();
    assemble(files, parts)
}

pub(crate) struct Prepared {
    hits: Vec<RawHit>,
}

pub(crate) fn prepare(text: &str) -> Prepared {
    Prepared {
        hits: extract_file(text),
    }
}

pub(crate) fn candidates_from(files: &[WalkedFile], parts: Vec<Prepared>) -> Vec<Candidate> {
    assemble(files, parts.into_iter().map(|part| part.hits).collect())
}

fn assemble(files: &[WalkedFile], parts: Vec<Vec<RawHit>>) -> Vec<Candidate> {
    let mut acc: HashMap<String, Acc> = HashMap::new();
    for (file, hits) in files.iter().zip(parts) {
        let lines = LineMap::build(&file.text);
        for hit in hits {
            merge(&mut acc, file, hit, &lines);
        }
    }
    add_product_prefix_hits(files, &mut acc);
    let mut candidates: Vec<Candidate> = acc
        .into_iter()
        .filter_map(|(key, item)| finish(key, item))
        .collect();
    drop_company_people(&mut candidates);
    sort_candidates(&mut candidates);
    candidates
}

/// A product prefix longer than three letters can be a term. `TDH` and `FAN`
/// cannot: a case-insensitive term with inflection suffixes also matches
/// `firmware/fan.git` and `TDH_API_KEY`. File the full identifier
/// (`TDH_FAN_MAX`, `tundrahorn_fan_init`) instead, and skip names that are
/// assigned (`TDH_API_KEY=...`).
fn add_product_prefix_hits(files: &[WalkedFile], acc: &mut HashMap<String, Acc>) {
    let mut short_prefixes = Vec::new();
    let mut long_prefixes = Vec::new();
    for item in acc.values() {
        if item.rule.as_deref() != Some("product-code") {
            continue;
        }
        let Some(prefix) = item.text.split('-').next() else {
            continue;
        };
        let len = prefix.chars().count();
        if !(3..=8).contains(&len) || !prefix.bytes().all(|byte| byte.is_ascii_uppercase()) {
            continue;
        }
        let bucket = if len <= 3 {
            &mut short_prefixes
        } else {
            &mut long_prefixes
        };
        if !bucket.iter().any(|existing: &String| existing == prefix) {
            bucket.push(prefix.to_string());
        }
    }
    for file in files {
        let mut lines = None;
        for prefix in &long_prefixes {
            let marker = format!("{prefix}_");
            let Some(pos) = file.text.find(&marker) else {
                continue;
            };
            let lines = lines.get_or_insert_with(|| LineMap::build(&file.text));
            merge(
                acc,
                file,
                RawHit {
                    start: pos,
                    end: pos + prefix.len(),
                    text: prefix.clone(),
                    category: LearnCategory::Name,
                    rule: Some("product-prefix".to_string()),
                    in_comment: false,
                },
                lines,
            );
        }
    }
    promote_full_identifiers(files, acc, &short_prefixes);
}

fn promote_full_identifiers(
    files: &[WalkedFile],
    acc: &mut HashMap<String, Acc>,
    short_prefixes: &[String],
) {
    let names: HashSet<String> = acc
        .values()
        .filter(|item| {
            item.category == LearnCategory::Name
                && item.rule.as_deref() != Some("product-prefix")
                && item.text.chars().all(|ch| ch.is_alphanumeric())
                && item.text.chars().count() >= 4
                && !is_common(&item.text)
                && !is_stopped(&item.text)
        })
        .map(|item| item.text.to_lowercase())
        .collect();
    let short: HashSet<&str> = short_prefixes.iter().map(String::as_str).collect();
    let mut assignments = HashSet::new();
    let mut found = HashSet::new();
    for file in files {
        for matched in IDENT.find_iter(&file.text) {
            let ident = matched.as_str();
            if !ident.contains('_') {
                continue;
            }
            if is_assignment(&file.text, matched.end()) {
                assignments.insert(ident.to_string());
            }
            if full_form(ident, &short, &names) {
                found.insert(ident.to_string());
            }
        }
    }
    let mut sorted: Vec<String> = found.into_iter().collect();
    sorted.sort();
    for ident in &sorted {
        if assignments.contains(ident) || has_longer_extension(&sorted, ident) {
            continue;
        }
        let key = key_for(LearnCategory::Symbol, ident);
        if let Some(entry) = acc.get_mut(&key) {
            if entry.category == LearnCategory::Symbol && entry.rule.is_none() {
                entry.rule = Some("macro".to_string());
            }
        }
    }
}

fn has_longer_extension(sorted: &[String], ident: &str) -> bool {
    let mut prefix = String::with_capacity(ident.len() + 1);
    prefix.push_str(ident);
    prefix.push('_');
    let index = sorted.partition_point(|other| other.as_str() < prefix.as_str());
    sorted
        .get(index)
        .is_some_and(|other| other.starts_with(&prefix))
}

fn full_form(ident: &str, short_prefixes: &HashSet<&str>, names: &HashSet<String>) -> bool {
    let mut count = 0;
    let mut matched = false;
    for token in ident.split('_') {
        if token.is_empty() {
            continue;
        }
        count += 1;
        if short_prefixes.contains(token) || name_has(names, token) {
            matched = true;
        }
    }
    count >= 2 && matched
}

fn name_has(names: &HashSet<String>, token: &str) -> bool {
    const MAX: usize = 64;
    if token.len() <= MAX && token.is_ascii() {
        let mut buf = [0u8; MAX];
        for (index, byte) in token.bytes().enumerate() {
            buf[index] = byte.to_ascii_lowercase();
        }
        let lower = std::str::from_utf8(&buf[..token.len()]).unwrap_or("");
        return names.contains(lower);
    }
    names.contains(&token.to_lowercase())
}

fn is_assignment(text: &str, end: usize) -> bool {
    let rest = text[end..].trim_start_matches([' ', '\t']);
    rest.starts_with('=') && !rest.starts_with("==")
}

/// A capitalised pair whose words already stand alone is a company or product
/// phrase (`Exempla Tundrahorn`), not a person. People stay for a short first
/// name such as `Ren Testdotter`.
fn drop_company_people(candidates: &mut Vec<Candidate>) {
    let names: std::collections::HashSet<String> = candidates
        .iter()
        .filter(|candidate| candidate.category == LearnCategory::Name)
        .map(|candidate| candidate.text.to_lowercase())
        .collect();
    candidates.retain(|candidate| {
        if candidate.category != LearnCategory::Person {
            return true;
        }
        let words: Vec<String> = candidate
            .text
            .split_whitespace()
            .map(|word| word.to_lowercase())
            .collect();
        if words.iter().any(|word| is_calendar(word)) {
            return false;
        }
        !(words.len() >= 2 && words.iter().all(|word| names.contains(word)))
    });
}

/// Pull identifiers that contain a term the user typed, including ones the
/// first pass kept only as a shorter token.
pub fn surface_terms(files: &[WalkedFile], terms: &[String], candidates: &mut Vec<Candidate>) {
    if terms.is_empty() {
        return;
    }
    let mut acc: HashMap<String, Acc> = HashMap::new();
    for file in files {
        let lines = LineMap::build(&file.text);
        let lower = file.text.to_lowercase();
        for term in terms {
            if term.chars().count() < 3 {
                continue;
            }
            let mut from = 0;
            while let Some(pos) = lower[from..].find(term) {
                let abs = from + pos;
                if let Some(word) = expand_ident(&file.text, abs, abs + term.len()) {
                    if !is_stopped(word) {
                        let start = file.text.find(word).unwrap_or(abs);
                        merge(
                            &mut acc,
                            file,
                            RawHit {
                                start,
                                end: start + word.len(),
                                text: word.to_string(),
                                category: if word.contains('_') || word.contains('-') {
                                    LearnCategory::Symbol
                                } else if word.chars().next().is_some_and(|ch| ch.is_uppercase()) {
                                    LearnCategory::Name
                                } else {
                                    LearnCategory::Symbol
                                },
                                rule: None,
                                in_comment: false,
                            },
                            &lines,
                        );
                    }
                }
                from = abs + term.len();
            }
        }
    }
    for (key, item) in acc {
        if candidates.iter().any(|candidate| candidate.key == key) {
            continue;
        }
        if let Some(candidate) = finish(key, item) {
            candidates.push(candidate);
        }
    }
    sort_candidates(candidates);
}

fn expand_ident(text: &str, start: usize, end: usize) -> Option<&str> {
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut left = start;
    while left > 0 && is_ident_byte(bytes[left - 1]) && text.is_char_boundary(left - 1) {
        left -= 1;
    }
    let mut right = end;
    while right < bytes.len() && is_ident_byte(bytes[right]) && text.is_char_boundary(right) {
        right += 1;
    }
    if !text.is_char_boundary(left) || !text.is_char_boundary(right) || left >= right {
        return None;
    }
    Some(&text[left..right])
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn finish(key: String, item: Acc) -> Option<Candidate> {
    if item.category == LearnCategory::Name && item.code_hits == 0 && item.occurrences < 2 {
        return None;
    }
    if item.text.chars().count() < 3 && item.category != LearnCategory::Secret {
        return None;
    }
    Some(Candidate {
        key,
        text: item.text,
        category: item.category,
        rule: item.rule,
        occurrences: item.occurrences,
        files: item.files.len(),
        first_file: item.first_file,
        first_line: item.first_line,
        context: item.context,
        sources: item.sources,
        left_glued: item.left_glued,
        right_glued: item.right_glued,
        related: false,
        secretish: item.category.secretish(),
    })
}

fn merge(acc: &mut HashMap<String, Acc>, file: &WalkedFile, hit: RawHit, lines: &LineMap) {
    if hit.text.is_empty() || hit.start >= hit.end {
        return;
    }
    let key = key_for(hit.category, &hit.text);
    let line = lines.line_no(hit.start);
    let context = source_line(&file.text, lines, hit.start, hit.end);
    let (left_glued, right_glued) = glued(&file.text, hit.start, hit.end);
    let entry = acc.entry(key).or_insert_with(|| Acc {
        text: hit.text.clone(),
        category: hit.category,
        rule: hit.rule.clone(),
        occurrences: 0,
        files: std::collections::BTreeSet::new(),
        first_file: file.relative.clone(),
        first_line: line,
        context: context.clone(),
        sources: Vec::new(),
        left_glued: false,
        right_glued: false,
        code_hits: 0,
        comment_hits: 0,
    });
    entry.occurrences += 1;
    entry.files.insert(file.relative.clone());
    entry.left_glued |= left_glued;
    entry.right_glued |= right_glued;
    if entry.sources.len() < 6
        && !context.is_empty()
        && !entry.sources.iter().any(|line| line == &context)
    {
        entry.sources.push(context.clone());
    }
    if hit.in_comment {
        entry.comment_hits += 1;
    } else {
        entry.code_hits += 1;
    }
    if hit.category.strength() > entry.category.strength() {
        entry.category = hit.category;
        entry.rule = hit.rule;
        entry.text = hit.text;
        entry.context = context;
        entry.first_file = file.relative.clone();
        entry.first_line = line;
    }
}

fn glued(text: &str, start: usize, end: usize) -> (bool, bool) {
    if start > text.len()
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return (false, false);
    }
    let left = text[..start].chars().next_back().is_some_and(is_regex_word);
    let right = text[end..].chars().next().is_some_and(is_regex_word);
    (left, right)
}

fn is_regex_word(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

fn sort_candidates(candidates: &mut [Candidate]) {
    candidates.sort_by(|left, right| {
        right
            .related
            .cmp(&left.related)
            .then(left.category.rank().cmp(&right.category.rank()))
            .then(right.occurrences.cmp(&left.occurrences))
            .then(right.files.cmp(&left.files))
            .then(left.text.to_lowercase().cmp(&right.text.to_lowercase()))
            .then(left.text.cmp(&right.text))
    });
}

fn extract_file(text: &str) -> Vec<RawHit> {
    let lines = LineMap::build(text);
    let (comments, strings) = lex(text);
    let mut hits = Vec::new();
    let mut blocked: Vec<(usize, usize)> = Vec::new();
    for hit in scan_secrets(text) {
        let value = text_slice(text, hit.start, hit.end);
        blocked.push((hit.start, hit.end));
        hits.push(RawHit {
            start: hit.start,
            end: hit.end,
            text: value.to_string(),
            category: LearnCategory::Secret,
            rule: Some(hit.rule),
            in_comment: in_ranges(&comments, hit.start, hit.end),
        });
    }
    for hit in high_entropy_hits(text) {
        if overlaps_linear(&blocked, hit.start, hit.end) {
            continue;
        }
        let value = text_slice(text, hit.start, hit.end);
        blocked.push((hit.start, hit.end));
        hits.push(RawHit {
            start: hit.start,
            end: hit.end,
            text: value.to_string(),
            category: LearnCategory::Secret,
            rule: Some(hit.rule),
            in_comment: in_ranges(&comments, hit.start, hit.end),
        });
    }
    merge_spans(&mut blocked);
    push_emails(text, &comments, &blocked, &mut hits);
    push_ips(text, &comments, &blocked, &mut hits);
    push_hosts(text, &comments, &blocked, &mut hits);
    push_product_codes(text, &comments, &mut blocked, &mut hits);
    push_flag_secrets(text, &comments, &mut blocked, &mut hits);
    merge_spans(&mut blocked);
    push_people(text, &lines, &comments, &blocked, &mut hits);
    push_identifiers(text, &lines, &comments, &blocked, &mut hits);
    push_strings(text, &lines, &strings, &comments, &blocked, &mut hits);
    push_capitalised(text, &lines, &comments, &blocked, &mut hits);
    dedup_hits(hits)
}

fn dedup_hits(hits: Vec<RawHit>) -> Vec<RawHit> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for hit in hits {
        let key = (hit.start, hit.end, key_for(hit.category, &hit.text));
        if seen.insert(key) {
            out.push(hit);
        }
    }
    out
}

fn push_emails(
    text: &str,
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for matched in EMAIL.find_iter(text) {
        if overlaps(blocked, matched.start(), matched.end()) {
            continue;
        }
        if text[matched.end()..].starts_with(':') {
            continue;
        }
        hits.push(raw(
            text,
            matched.start(),
            matched.end(),
            LearnCategory::Email,
            Some("email".to_string()),
            in_ranges(comments, matched.start(), matched.end()),
        ));
    }
}

fn push_ips(
    text: &str,
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for matched in IPV4.find_iter(text) {
        if overlaps(blocked, matched.start(), matched.end()) {
            continue;
        }
        if !ipv4_edge_ok(text, matched.start(), matched.end()) {
            continue;
        }
        let value = matched.as_str();
        if matches!(value, "0.0.0.0" | "127.0.0.1" | "255.255.255.255") {
            continue;
        }
        hits.push(raw(
            text,
            matched.start(),
            matched.end(),
            LearnCategory::Ip,
            Some("ipv4".to_string()),
            in_ranges(comments, matched.start(), matched.end()),
        ));
    }
}

fn ipv4_edge_ok(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    if before.is_some_and(|ch| ch.is_ascii_digit() || ch == '.') {
        return false;
    }
    let mut rest = text[end..].chars();
    match rest.next() {
        Some(ch) if ch.is_ascii_digit() => false,
        Some('.') => !rest.next().is_some_and(|ch| ch.is_ascii_digit()),
        _ => true,
    }
}

fn push_hosts(
    text: &str,
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for caps in URL.captures_iter(text) {
        let Some(host) = caps.get(1) else {
            continue;
        };
        if overlaps(blocked, host.start(), host.end()) || skip_host(host.as_str()) {
            continue;
        }
        let category = if is_ipv4(host.as_str()) {
            LearnCategory::Ip
        } else {
            LearnCategory::Host
        };
        hits.push(raw(
            text,
            host.start(),
            host.end(),
            category,
            Some("url-host".to_string()),
            in_ranges(comments, host.start(), host.end()),
        ));
    }
    for matched in HOST.find_iter(text) {
        if overlaps(blocked, matched.start(), matched.end()) {
            continue;
        }
        if skip_host(matched.as_str()) {
            continue;
        }
        hits.push(raw(
            text,
            matched.start(),
            matched.end(),
            LearnCategory::Host,
            Some("hostname".to_string()),
            in_ranges(comments, matched.start(), matched.end()),
        ));
        if let Some(domain) = registrable(matched.as_str()) {
            if domain != matched.as_str() && !skip_host(&domain) {
                let offset = matched.as_str().len() - domain.len();
                let start = matched.start() + offset;
                hits.push(raw(
                    text,
                    start,
                    matched.end(),
                    LearnCategory::Domain,
                    Some("domain".to_string()),
                    in_ranges(comments, start, matched.end()),
                ));
            }
        }
    }
}

fn skip_host(host: &str) -> bool {
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() || lower == "localhost" {
        return true;
    }
    if is_ipv4(&lower) {
        return matches!(lower.as_str(), "0.0.0.0" | "127.0.0.1" | "255.255.255.255");
    }
    if !hostname_labels_valid(&lower) {
        return true;
    }
    let tld = lower.rsplit('.').next().unwrap_or("");
    if SOURCE_EXT.contains(&tld) {
        return true;
    }
    if lower == "example.com"
        || lower == "example.org"
        || lower == "example.net"
        || lower.ends_with(".example")
        || lower.ends_with(".invalid")
        || lower.ends_with(".localhost")
        || lower.ends_with(".test")
    {
        return true;
    }
    let labels: Vec<&str> = lower.split('.').filter(|label| !label.is_empty()).collect();
    let Some(tld) = labels.last() else {
        return true;
    };
    CODE_TLDS.contains(tld)
        || labels.iter().any(|label| {
            matches!(
                *label,
                "environ" | "getenv" | "os" | "fake" | "getattr" | "setattr"
            )
        })
}

const CODE_TLDS: &[&str] = &[
    "append", "args", "argv", "bool", "clone", "close", "cls", "copy", "decode", "encode", "env",
    "environ", "err", "expect", "extend", "fake", "false", "float", "format", "func", "get",
    "getenv", "getattr", "hasattr", "init", "insert", "int", "items", "join", "json", "keys",
    "len", "loads", "lower", "main", "new", "none", "open", "path", "pop", "read", "remove",
    "replace", "self", "setattr", "split", "str", "strip", "this", "true", "type", "unwrap",
    "update", "upper", "values", "write",
];

/// Letters, digits, hyphens, and underscores. Internal names such as
/// `db_backup.fan_line.internal` are hosts. NUL, other controls, and a label
/// glued out of a filename (`txtfl`, `txtpk`) are not.
pub(crate) fn hostname_labels_valid(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    labels.len() >= 2 && labels.iter().copied().all(hostname_label_valid)
}

fn hostname_label_valid(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
    {
        return false;
    }
    const GLUED_EXT: &[&str] = &["txt", "pdf", "png", "zip"];
    !GLUED_EXT.iter().any(|ext| {
        label.len() > ext.len()
            && label.starts_with(ext)
            && label.as_bytes()[ext.len()].is_ascii_alphanumeric()
    })
}

fn is_ipv4(value: &str) -> bool {
    let mut parts = value.split('.');
    for _ in 0..4 {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.is_empty() || part.parse::<u8>().is_err() {
            return false;
        }
    }
    parts.next().is_none()
}

fn registrable(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').filter(|part| !part.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    Some(format!(
        "{}.{}",
        parts[parts.len() - 2],
        parts[parts.len() - 1]
    ))
}

/// File and VCS suffixes. `fan.git` is a repository path, not a hostname.
const SOURCE_EXT: &[&str] = &[
    "c", "cc", "cfg", "cpp", "cs", "css", "csv", "cxx", "env", "git", "go", "h", "hh", "hpp",
    "html", "hxx", "ini", "java", "js", "json", "jsx", "kt", "lock", "md", "php", "py", "rb", "rs",
    "scss", "sh", "sql", "toml", "ts", "tsx", "txt", "vue", "xml", "yaml", "yml",
];

fn push_product_codes(
    text: &str,
    comments: &[(usize, usize)],
    blocked: &mut Vec<(usize, usize)>,
    hits: &mut Vec<RawHit>,
) {
    for matched in PRODUCT_CODE.find_iter(text) {
        if overlaps_linear(blocked, matched.start(), matched.end()) {
            continue;
        }
        blocked.push((matched.start(), matched.end()));
        hits.push(raw(
            text,
            matched.start(),
            matched.end(),
            LearnCategory::Symbol,
            Some("product-code".to_string()),
            in_ranges(comments, matched.start(), matched.end()),
        ));
    }
}

fn push_flag_secrets(
    text: &str,
    comments: &[(usize, usize)],
    blocked: &mut Vec<(usize, usize)>,
    hits: &mut Vec<RawHit>,
) {
    for caps in FLAG_SECRET.captures_iter(text) {
        let Some(value) = caps.get(1) else {
            continue;
        };
        if !value.as_str().chars().any(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if overlaps_linear(blocked, value.start(), value.end()) {
            continue;
        }
        blocked.push((value.start(), value.end()));
        hits.push(raw(
            text,
            value.start(),
            value.end(),
            LearnCategory::Secret,
            Some("command-flag".to_string()),
            in_ranges(comments, value.start(), value.end()),
        ));
    }
}

fn push_people(
    text: &str,
    lines: &LineMap,
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for caps in PERSON_PAIR.captures_iter(text) {
        let Some(whole) = caps.get(0) else {
            continue;
        };
        if overlaps(blocked, whole.start(), whole.end()) || lines.is_pem(whole.start()) {
            continue;
        }
        let Some(first) = caps.get(1) else {
            continue;
        };
        let Some(last) = caps.get(2) else {
            continue;
        };
        if is_common(first.as_str())
            || is_common(last.as_str())
            || is_stopped(first.as_str())
            || is_stopped(last.as_str())
            || is_calendar(first.as_str())
            || is_calendar(last.as_str())
        {
            continue;
        }
        if first.as_str().chars().count() < 3 || last.as_str().chars().count() < 3 {
            continue;
        }
        if date_context(text, lines, whole.start()) {
            continue;
        }
        hits.push(raw(
            text,
            whole.start(),
            whole.end(),
            LearnCategory::Person,
            None,
            in_ranges(comments, whole.start(), whole.end()),
        ));
    }
}

fn date_context(text: &str, lines: &LineMap, start: usize) -> bool {
    let (line_start, line_end) = lines.bounds(start);
    let line = text[line_start..line_end].trim_start();
    let mut buf = [0u8; 6];
    let mut count = 0;
    for byte in line.bytes().take(6) {
        buf[count] = byte.to_ascii_lowercase();
        count += 1;
    }
    let head = &buf[..count];
    head.starts_with(b"date:") || head.starts_with(b"datum:")
}

struct LineMap {
    /// Byte index of each `\n`.
    breaks: Vec<usize>,
    len: usize,
    pem: Vec<bool>,
}

impl LineMap {
    fn build(text: &str) -> Self {
        let breaks: Vec<usize> = text
            .bytes()
            .enumerate()
            .filter(|(_, byte)| *byte == b'\n')
            .map(|(index, _)| index)
            .collect();
        let mut pem = Vec::with_capacity(breaks.len() + 1);
        let mut start = 0;
        for &newline in &breaks {
            pem.push(pem_marker(&text[start..newline]));
            start = newline + 1;
        }
        pem.push(pem_marker(&text[start..]));
        Self {
            breaks,
            len: text.len(),
            pem,
        }
    }

    fn line_no(&self, start: usize) -> u32 {
        self.line_index(start) as u32 + 1
    }

    fn bounds(&self, start: usize) -> (usize, usize) {
        let start = start.min(self.len);
        let index = self.line_index(start);
        let line_start = if index == 0 {
            0
        } else {
            self.breaks[index - 1] + 1
        };
        let line_end = if index < self.breaks.len() {
            self.breaks[index]
        } else {
            self.len
        };
        (line_start, line_end)
    }

    fn is_pem(&self, start: usize) -> bool {
        let index = self.line_index(start.min(self.len));
        self.pem.get(index).copied().unwrap_or(false)
    }

    fn line_index(&self, start: usize) -> usize {
        self.breaks.partition_point(|newline| *newline < start)
    }
}

fn pem_marker(line: &str) -> bool {
    line.contains("PRIVATE KEY") || line.contains("OPENSSH") || line.contains("-----BEGIN")
}

fn push_identifiers(
    text: &str,
    lines: &LineMap,
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for matched in IDENT.find_iter(text) {
        if overlaps(blocked, matched.start(), matched.end()) {
            continue;
        }
        let ident = matched.as_str();
        if is_hex_token(ident)
            || is_uuid(ident)
            || !ident_edges(text, matched.start(), matched.end())
        {
            continue;
        }
        if lines.is_pem(matched.start()) {
            continue;
        }
        let in_comment = in_ranges(comments, matched.start(), matched.end());
        if opaque_token(ident) {
            hits.push(raw(
                text,
                matched.start(),
                matched.end(),
                LearnCategory::Secret,
                Some("token-literal".to_string()),
                in_comment,
            ));
            continue;
        }
        let tokens = split_ident(ident);
        let interesting = tokens.iter().any(|token| token_ok(token));
        // A single token is classified below. Pushing it again as a symbol
        // would hide the name category and keep a one-off comment word.
        if interesting && ident_ok(ident) && tokens.len() != 1 {
            hits.push(raw(
                text,
                matched.start(),
                matched.end(),
                LearnCategory::Symbol,
                None,
                in_comment,
            ));
        }
        for token in tokens {
            if !token_ok(&token) {
                continue;
            }
            let Some(offset) = ident.find(&token) else {
                continue;
            };
            let start = matched.start() + offset;
            let end = start + token.len();
            if token.chars().all(|ch| ch.is_ascii_uppercase()) && token.chars().count() <= 6 {
                continue;
            }
            let category = if looks_like_name(&token) {
                LearnCategory::Name
            } else {
                LearnCategory::Symbol
            };
            hits.push(raw(text, start, end, category, None, in_comment));
        }
    }
}

fn push_strings(
    text: &str,
    lines: &LineMap,
    strings: &[(usize, usize)],
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for &(start, end) in strings {
        if overlaps(blocked, start, end) {
            continue;
        }
        let value = text_slice(text, start, end).trim();
        if value.chars().count() < 3 || value.chars().count() > 80 || value.contains('\n') {
            continue;
        }
        if value.contains("://") || is_stopped(value) || lines.is_pem(start) {
            continue;
        }
        if opaque_token(value) {
            let trim_start = text[start..end].find(value).unwrap_or(0);
            hits.push(raw(
                text,
                start + trim_start,
                start + trim_start + value.len(),
                LearnCategory::Secret,
                Some("token-literal".to_string()),
                in_ranges(comments, start, end),
            ));
            continue;
        }
        let words: Vec<&str> = value.split_whitespace().collect();
        if words.len() > 4 || words.is_empty() {
            continue;
        }
        let in_comment = in_ranges(comments, start, end);
        if words.len() >= 2 && words.iter().all(|word| looks_like_name(word)) {
            // The words are collected on their own. One concatenated term would
            // not match `Exemplas` or `tundrahorn_fan`.
            continue;
        }
        if words.len() == 1 && ident_ok(value) && !is_hex_token(value) {
            let trim_start = text[start..end].find(value).unwrap_or(0);
            hits.push(raw(
                text,
                start + trim_start,
                start + trim_start + value.len(),
                LearnCategory::Symbol,
                None,
                in_comment,
            ));
        }
    }
}

fn push_capitalised(
    text: &str,
    lines: &LineMap,
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for matched in CAP_WORD.find_iter(text) {
        if overlaps(blocked, matched.start(), matched.end()) {
            continue;
        }
        let word = matched.as_str();
        if is_stopped(word) || is_calendar(word) || word.chars().count() < 4 {
            continue;
        }
        if date_context(text, lines, matched.start()) {
            continue;
        }
        hits.push(raw(
            text,
            matched.start(),
            matched.end(),
            LearnCategory::Name,
            None,
            in_ranges(comments, matched.start(), matched.end()),
        ));
    }
}

fn raw(
    text: &str,
    start: usize,
    end: usize,
    category: LearnCategory,
    rule: Option<String>,
    in_comment: bool,
) -> RawHit {
    RawHit {
        start,
        end,
        text: text_slice(text, start, end).to_string(),
        category,
        rule,
        in_comment,
    }
}

fn ident_edges(text: &str, start: usize, end: usize) -> bool {
    let left = text[..start]
        .chars()
        .next_back()
        .is_none_or(|ch| !ch.is_alphabetic());
    let right = text[end..]
        .chars()
        .next()
        .is_none_or(|ch| !ch.is_alphabetic());
    left && right
}

fn opaque_token(value: &str) -> bool {
    let n = value.chars().count();
    (12..=80).contains(&n)
        && !value.contains(' ')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        && value.chars().any(|ch| ch.is_ascii_digit())
        && value.chars().any(|ch| ch.is_ascii_alphabetic())
        && (value.contains('_') || value.contains('-') || n >= 16)
}

fn token_ok(token: &str) -> bool {
    if is_stopped(token) || is_hex_token(token) || is_uuid(token) {
        return false;
    }
    let len = token.chars().count();
    if token.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    if len >= 4 {
        return true;
    }
    len == 3 && token.chars().all(|ch| ch.is_ascii_uppercase())
}

fn ident_ok(ident: &str) -> bool {
    ident.chars().count() >= 3 && !is_stopped(ident) && !ident.chars().all(|ch| ch.is_ascii_digit())
}

fn looks_like_name(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_uppercase()
        && chars.clone().any(|ch| ch.is_lowercase())
        && chars.all(|ch| ch.is_alphanumeric())
        && token.chars().count() >= 4
        && !is_stopped(token)
}

fn is_hex_token(token: &str) -> bool {
    token.len() >= 8 && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_uuid(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
}

fn split_ident(ident: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for piece in ident.split(['_', '-']) {
        if piece.is_empty() {
            continue;
        }
        tokens.extend(split_camel(piece));
    }
    tokens
}

fn split_camel(piece: &str) -> Vec<String> {
    let chars: Vec<char> = piece.chars().collect();
    if chars.is_empty() {
        return Vec::new();
    }
    let mut parts = Vec::new();
    let mut start = 0;
    let mut index = 1;
    while index < chars.len() {
        let prev = chars[index - 1];
        let current = chars[index];
        let next = chars.get(index + 1).copied();
        let boundary = (prev.is_lowercase() && current.is_uppercase())
            || (prev.is_uppercase()
                && current.is_uppercase()
                && next.is_some_and(|ch| ch.is_lowercase()));
        if boundary {
            parts.push(chars[start..index].iter().collect());
            start = index;
        }
        index += 1;
    }
    parts.push(chars[start..].iter().collect());
    parts
}

fn overlaps_linear(spans: &[(usize, usize)], start: usize, end: usize) -> bool {
    spans
        .iter()
        .any(|&(left, right)| start < right && left < end)
}

fn merge_spans(spans: &mut Vec<(usize, usize)>) {
    if spans.len() < 2 {
        return;
    }
    spans.sort_unstable();
    let mut merged = Vec::with_capacity(spans.len());
    let mut current = spans[0];
    for &(left, right) in spans.iter().skip(1) {
        if left <= current.1 {
            current.1 = current.1.max(right);
        } else {
            merged.push(current);
            current = (left, right);
        }
    }
    merged.push(current);
    *spans = merged;
}

/// `spans` is sorted and disjoint.
fn overlaps(spans: &[(usize, usize)], start: usize, end: usize) -> bool {
    let index = spans.partition_point(|&(left, _)| left < end);
    index > 0 && start < spans[index - 1].1
}

fn in_ranges(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    let index = ranges.partition_point(|&(left, _)| left <= start);
    index > 0 && start >= ranges[index - 1].0 && end <= ranges[index - 1].1
}

fn text_slice(text: &str, start: usize, end: usize) -> &str {
    if start <= end
        && end <= text.len()
        && text.is_char_boundary(start)
        && text.is_char_boundary(end)
    {
        &text[start..end]
    } else {
        ""
    }
}

fn source_line(text: &str, lines: &LineMap, start: usize, end: usize) -> String {
    if text.is_empty() || start > text.len() {
        return String::new();
    }
    if start <= end
        && end <= text.len()
        && text.is_char_boundary(start)
        && text.is_char_boundary(end)
        && text[start..end].contains('\n')
    {
        return text[start..end].to_string();
    }
    let start = floor_boundary(text, start);
    let (line_start, line_end) = lines.bounds(start);
    let line = &text[line_start..line_end];
    if line.len() <= 240 || (line.len() <= 960 && line.chars().take(241).count() <= 240) {
        return line.to_string();
    }
    let value = text.get(start..end.min(text.len())).unwrap_or("");
    let Some(pos) = line.find(value) else {
        return line.chars().take(240).collect();
    };
    let from = floor_boundary(line, pos.saturating_sub(60));
    let to = ceil_boundary(line, (pos + value.len() + 60).min(line.len()));
    line[from..to].to_string()
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    if index > text.len() {
        index = text.len();
    }
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_boundary(text: &str, mut index: usize) -> usize {
    if index > text.len() {
        return text.len();
    }
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

type Span = (usize, usize);

fn lex(text: &str) -> (Vec<Span>, Vec<Span>) {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut comments = Vec::new();
    let mut strings = Vec::new();
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let start = index + 2;
            index = start;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            if index > start {
                comments.push((start, index));
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let start = index + 2;
            index = start;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            if index > start {
                comments.push((start, index));
            }
            if index + 1 < bytes.len() {
                index += 2;
            }
            continue;
        }
        if byte == b'#' {
            let start = index + 1;
            index = start;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            if index > start {
                comments.push((start, index));
            }
            continue;
        }
        if byte == b'"' || byte == b'\'' || byte == b'`' {
            let quote = byte;
            index += 1;
            let start = index;
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    index += 1 + utf8_width(bytes[index + 1]);
                    continue;
                }
                if bytes[index] == b'\n' && quote != b'`' {
                    break;
                }
                index += 1;
            }
            let end = index;
            if index < bytes.len() && bytes[index] == quote && end >= start {
                strings.push((start, end));
                index += 1;
            }
            continue;
        }
        index += utf8_width(byte);
    }
    (comments, strings)
}

fn utf8_width(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte < 0xE0 {
        2
    } else if byte < 0xF0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
#[path = "profile_extract.rs"]
mod profile_extract;

#[cfg(test)]
mod tests {
    use super::*;

    fn only(text: &str) -> Vec<Candidate> {
        extract(&[WalkedFile {
            relative: "src/fan.rs".to_string(),
            text: text.to_string(),
        }])
    }

    fn has(candidates: &[Candidate], category: LearnCategory, text: &str) -> bool {
        candidates
            .iter()
            .any(|candidate| candidate.category == category && candidate.text == text)
    }

    #[test]
    fn extracts_secret_symbol_host_ip_email_and_drops_keywords() {
        let text = r#"
// Exempla ships Tundrahorn.
// Exempla internal note.
fn tundrahorn_fan_init() {}
const KEY: &str = "AKIAIOSFODNN7EXAMPLE";
let host = "db.tundrahorn.internal";
let ip = "10.9.8.7";
let mail = "ren.testdotter@tundrahorn.example";
fn return_value() {}
"#;
        let found = only(text);
        assert!(
            has(&found, LearnCategory::Secret, "AKIAIOSFODNN7EXAMPLE"),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|candidate| candidate.text == "tundrahorn_fan_init"),
            "{found:?}"
        );
        assert!(
            has(&found, LearnCategory::Host, "db.tundrahorn.internal")
                || found.iter().any(|c| c.text.contains("tundrahorn.internal")),
            "{found:?}"
        );
        assert!(has(&found, LearnCategory::Ip, "10.9.8.7"), "{found:?}");
        assert!(
            found
                .iter()
                .any(|candidate| candidate.text.contains("testdotter@")),
            "{found:?}"
        );
        assert!(found.iter().all(|candidate| candidate.text != "return"));
        assert!(found.iter().all(|candidate| candidate.text != "fn"));
        let secret = found
            .iter()
            .find(|candidate| candidate.text == "AKIAIOSFODNN7EXAMPLE")
            .unwrap();
        assert!(secret.occurrences >= 1);
        assert_eq!(secret.files, 1);
        assert_eq!(secret.first_file, "src/fan.rs");
    }

    #[test]
    fn comment_only_name_needs_a_repeat() {
        let once = only("// Exempla appears once.\nfn main() {}\n");
        assert!(once.iter().all(|candidate| candidate.text != "Exempla"));
        let twice = only("// Exempla one.\n// Exempla two.\n");
        assert!(twice.iter().any(|candidate| candidate.text == "Exempla"));
    }

    #[test]
    fn camel_and_snake_tokens_split() {
        assert_eq!(
            split_camel("HTTPServer"),
            vec!["HTTP".to_string(), "Server".to_string()]
        );
        assert_eq!(
            split_ident("tundrahorn_fan_init"),
            vec![
                "tundrahorn".to_string(),
                "fan".to_string(),
                "init".to_string()
            ]
        );
    }

    #[test]
    fn full_person_name_and_product_codes_are_kept_whole() {
        let found = only(
            "Author: Ren Testdotter <fan@exempla.test>\ncode: TDH-4471\n/* FAN-ALPHA-2 */\n#define TDH_FAN_MAX 2400\n",
        );
        assert!(
            has(&found, LearnCategory::Person, "Ren Testdotter"),
            "{found:?}"
        );
        assert!(has(&found, LearnCategory::Symbol, "TDH-4471"), "{found:?}");
        assert!(
            has(&found, LearnCategory::Symbol, "FAN-ALPHA-2"),
            "{found:?}"
        );
        assert!(
            found.iter().all(|candidate| candidate.text != "MAX"),
            "a fragment of TDH_FAN_MAX was learned: {found:?}"
        );
        let code = found
            .iter()
            .find(|candidate| candidate.text == "TDH-4471")
            .unwrap();
        let regex = crate::store::matching_regex(
            &code.text,
            &code.sources,
            code.left_glued,
            code.right_glued,
        )
        .unwrap();
        assert!(regex::Regex::new(&regex).unwrap().is_match("TDH-4471"));
        assert!(regex::Regex::new(&regex)
            .unwrap()
            .is_match(&code.sources[0]));
    }

    #[test]
    fn agent_password_glued_to_a_flag_is_a_secret_that_matches() {
        let line = "\"mysql -h db.tundrahorn.corp -pSVCNAgentPassw0rd\"";
        let found = only(line);
        let secret = found
            .iter()
            .find(|candidate| candidate.text == "SVCNAgentPassw0rd")
            .unwrap_or_else(|| panic!("{found:?}"));
        assert_eq!(secret.category, LearnCategory::Secret);
        assert!(secret.left_glued, "password is glued to -p");
        let regex = crate::store::matching_regex(
            &secret.text,
            &secret.sources,
            secret.left_glued,
            secret.right_glued,
        )
        .unwrap();
        assert!(regex::Regex::new(&regex).unwrap().is_match(line), "{regex}");
    }

    #[test]
    fn unicode_words_and_code_hosts_are_not_split_into_junk() {
        let found = only(
            "fläkt fönster tröskel\nos.environ.get('X')\norg.fake.Example\nprint(os.environ)\n",
        );
        assert!(found.iter().all(|candidate| candidate.text != "nster"));
        assert!(found.iter().all(|candidate| candidate.text != "skel"));
        assert!(found
            .iter()
            .all(|candidate| candidate.category != LearnCategory::Host
                || !candidate.text.contains("environ")));
        assert!(found.iter().all(|candidate| candidate.text != "org.fake"));
    }

    #[test]
    fn openssh_block_is_not_filed_as_symbols() {
        let found = only(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nSVCNOPENSSHKEYLINE0001\n-----END OPENSSH PRIVATE KEY-----\n",
        );
        assert!(found.iter().all(|candidate| {
            candidate.category != LearnCategory::Symbol
                || (!candidate.text.contains("OPENSSH") && !candidate.text.contains("PRIVATE"))
        }));
        assert!(found.iter().any(|candidate| {
            candidate.category == LearnCategory::Secret
                && candidate.text.contains("OPENSSH PRIVATE KEY")
        }));
    }

    #[test]
    fn company_phrase_and_date_line_are_not_people() {
        let found = only(
            "company Exempla, product Tundrahorn.\nLABEL x=\"Exempla Tundrahorn\"\nDate:   Thu Jan 1 00:00:00 2099 +0000\nAuthor: Ren Testdotter <fan.operator@exempla.test>\n#define TDH_FAN_MAX 2400\ncode TDH-4471\n",
        );
        assert!(
            found
                .iter()
                .all(|candidate| candidate.text != "Exempla Tundrahorn"),
            "{found:?}"
        );
        assert!(
            found.iter().all(|candidate| candidate.text != "Thu Jan"),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .all(|candidate| candidate.text != "Thu" && candidate.text != "Jan"),
            "{found:?}"
        );
        assert!(
            has(&found, LearnCategory::Person, "Ren Testdotter"),
            "{found:?}"
        );
        assert!(has(&found, LearnCategory::Name, "Exempla"), "{found:?}");
        assert!(has(&found, LearnCategory::Name, "Tundrahorn"), "{found:?}");
        assert!(
            found
                .iter()
                .all(|candidate| candidate.text != "TDH" && candidate.text != "FAN"),
            "a three-letter product prefix was filed as a term: {found:?}"
        );
        assert!(
            found.iter().any(|candidate| {
                candidate.text == "TDH_FAN_MAX" && candidate.rule.as_deref() == Some("macro")
            }),
            "TDH_FAN_MAX should be the learned literal: {found:?}"
        );
        let author = found.iter().find(|candidate| candidate.text == "Author");
        assert!(
            author.is_none_or(crate::session::is_low_signal),
            "Author should stay low-signal: {found:?}"
        );
    }

    #[test]
    fn glued_filename_bytes_are_not_a_host() {
        let found = only("README.txtfl\u{0}README.txtPK\u{3}see artifacts.tdh.corp later\n");
        assert!(
            found
                .iter()
                .all(|candidate| !candidate.text.to_ascii_lowercase().contains("readme.txt")),
            "{found:?}"
        );
        assert!(
            has(&found, LearnCategory::Host, "artifacts.tdh.corp"),
            "{found:?}"
        );
        assert!(found
            .iter()
            .filter(|candidate| candidate.category == LearnCategory::Host)
            .all(|candidate| hostname_labels_valid(&candidate.text)));
    }

    #[test]
    fn underscore_internal_host_is_kept_and_binary_glue_is_not() {
        assert!(hostname_labels_valid("db_backup.fan_line.internal"));
        assert!(!hostname_labels_valid("readme.txtfl"));
        assert!(!hostname_labels_valid("readme.txtpk"));
        assert!(!hostname_labels_valid("db_backup.fan\u{0}line.internal"));
        assert!(!hostname_labels_valid("db_backup.fan\u{1}line.internal"));
        let found = only(
            "/* db_backup.fan_line.internal */\ncode: TDH-4471\n#define TDH_FAN_MAX 2400\nTDH_API_KEY=12345678\n",
        );
        assert!(
            has(&found, LearnCategory::Host, "db_backup.fan_line.internal"),
            "{found:?}"
        );
        assert!(
            found.iter().all(|candidate| {
                candidate.text != "TDH_API_KEY" || candidate.rule.as_deref() != Some("macro")
            }),
            "an assignment name was filed as a literal: {found:?}"
        );
        assert!(found.iter().any(|candidate| {
            candidate.text == "TDH_FAN_MAX" && candidate.rule.as_deref() == Some("macro")
        }));
    }

    #[test]
    fn a_git_suffix_is_not_a_host() {
        let found = only("git@git.tdh.corp:firmware/fan.git\n");
        assert!(
            found.iter().all(|candidate| candidate.text != "fan.git"),
            "{found:?}"
        );
        assert!(
            has(&found, LearnCategory::Host, "git.tdh.corp"),
            "{found:?}"
        );
    }

    #[test]
    fn parallel_extract_matches_sequential_order() {
        let files = vec![
            WalkedFile {
                relative: "src/a.rs".to_string(),
                text: "/* Ren Testdotter */\n#define TDH_FAN_MAX 1\ncode TDH-4471\n".to_string(),
            },
            WalkedFile {
                relative: "src/b.rs".to_string(),
                text: "fn tundrahorn_fan_init() {}\nconst KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\n"
                    .to_string(),
            },
        ];
        let parallel = extract(&files);
        let sequential = extract_sequential(&files);
        assert_eq!(parallel.len(), sequential.len());
        for (left, right) in parallel.iter().zip(sequential.iter()) {
            assert_eq!(left.key, right.key);
            assert_eq!(left.text, right.text);
            assert_eq!(left.category, right.category);
            assert_eq!(left.rule, right.rule);
            assert_eq!(left.occurrences, right.occurrences);
            assert_eq!(left.files, right.files);
            assert_eq!(left.first_file, right.first_file);
            assert_eq!(left.first_line, right.first_line);
            assert_eq!(left.context, right.context);
            assert_eq!(left.sources, right.sources);
            assert_eq!(left.left_glued, right.left_glued);
            assert_eq!(left.right_glued, right.right_glued);
        }
    }
}
