//! Deterministic candidate extraction. No model calls.

use std::collections::HashMap;
use std::sync::LazyLock;

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

pub fn extract(files: &[WalkedFile]) -> Vec<Candidate> {
    let mut acc: HashMap<String, Acc> = HashMap::new();
    for file in files {
        for hit in extract_file(&file.text) {
            merge(&mut acc, file, hit);
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

/// `TDH-4471` and `TDH_FAN_MAX` share a prefix. File that prefix as a name term
/// so the macro is covered with the same separator rules as other terms.
fn add_product_prefix_hits(files: &[WalkedFile], acc: &mut HashMap<String, Acc>) {
    let mut prefixes = Vec::new();
    for item in acc.values() {
        if item.rule.as_deref() != Some("product-code") {
            continue;
        }
        let Some(prefix) = item.text.split('-').next() else {
            continue;
        };
        let len = prefix.chars().count();
        if (3..=8).contains(&len)
            && prefix.bytes().all(|byte| byte.is_ascii_uppercase())
            && !prefixes.iter().any(|existing: &String| existing == prefix)
        {
            prefixes.push(prefix.to_string());
        }
    }
    for file in files {
        for prefix in &prefixes {
            let marker = format!("{prefix}_");
            let Some(pos) = file.text.find(&marker) else {
                continue;
            };
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
            );
        }
    }
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

fn merge(acc: &mut HashMap<String, Acc>, file: &WalkedFile, hit: RawHit) {
    if hit.text.is_empty() || hit.start >= hit.end {
        return;
    }
    let key = key_for(hit.category, &hit.text);
    let line = line_of(&file.text, hit.start);
    let context = source_line(&file.text, hit.start, hit.end);
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
        if overlaps(&blocked, hit.start, hit.end) {
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
    push_emails(text, &comments, &blocked, &mut hits);
    push_ips(text, &comments, &blocked, &mut hits);
    push_hosts(text, &comments, &blocked, &mut hits);
    push_product_codes(text, &comments, &mut blocked, &mut hits);
    push_flag_secrets(text, &comments, &mut blocked, &mut hits);
    push_people(text, &comments, &blocked, &mut hits);
    push_identifiers(text, &comments, &blocked, &mut hits);
    push_strings(text, &strings, &comments, &blocked, &mut hits);
    push_capitalised(text, &comments, &blocked, &mut hits);
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

/// Letters, digits, and hyphens only. A label glued out of a filename
/// (`txtfl`, `txtpk`) is not a hostname.
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
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
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

const SOURCE_EXT: &[&str] = &[
    "c", "cc", "cfg", "cpp", "cs", "css", "csv", "cxx", "env", "go", "h", "hh", "hpp", "html",
    "hxx", "ini", "java", "js", "json", "jsx", "kt", "lock", "md", "php", "py", "rb", "rs", "scss",
    "sh", "sql", "toml", "ts", "tsx", "txt", "vue", "xml", "yaml", "yml",
];

fn push_product_codes(
    text: &str,
    comments: &[(usize, usize)],
    blocked: &mut Vec<(usize, usize)>,
    hits: &mut Vec<RawHit>,
) {
    for matched in PRODUCT_CODE.find_iter(text) {
        if overlaps(blocked, matched.start(), matched.end()) {
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
        if overlaps(blocked, value.start(), value.end()) {
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
    comments: &[(usize, usize)],
    blocked: &[(usize, usize)],
    hits: &mut Vec<RawHit>,
) {
    for caps in PERSON_PAIR.captures_iter(text) {
        let Some(whole) = caps.get(0) else {
            continue;
        };
        if overlaps(blocked, whole.start(), whole.end()) || pem_line(text, whole.start()) {
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
        if date_context(text, whole.start()) {
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

fn date_context(text: &str, start: usize) -> bool {
    let (line_start, line_end) = line_bounds(text, start);
    let line = text[line_start..line_end].trim_start().to_ascii_lowercase();
    line.starts_with("date:") || line.starts_with("datum:")
}

fn pem_line(text: &str, start: usize) -> bool {
    let (line_start, line_end) = line_bounds(text, start);
    let line = &text[line_start..line_end];
    line.contains("PRIVATE KEY") || line.contains("OPENSSH") || line.contains("-----BEGIN")
}

fn line_bounds(text: &str, start: usize) -> (usize, usize) {
    let start = start.min(text.len());
    let line_start = text[..start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = text[start..]
        .find('\n')
        .map(|index| start + index)
        .unwrap_or(text.len());
    (line_start, line_end)
}

fn push_identifiers(
    text: &str,
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
        if pem_line(text, matched.start()) {
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
        if value.contains("://") || is_stopped(value) || pem_line(text, start) {
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
        if date_context(text, matched.start()) {
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

fn overlaps(spans: &[(usize, usize)], start: usize, end: usize) -> bool {
    spans
        .iter()
        .any(|&(left, right)| start < right && left < end)
}

fn in_ranges(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges
        .iter()
        .any(|&(left, right)| start >= left && end <= right)
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

fn source_line(text: &str, start: usize, end: usize) -> String {
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
    let line_start = text[..start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = text[start..]
        .find('\n')
        .map(|index| start + index)
        .unwrap_or(text.len());
    let line = &text[line_start..line_end];
    if line.chars().count() <= 240 {
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

fn line_of(text: &str, start: usize) -> u32 {
    text[..start.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1
}

type Span = (usize, usize);

fn lex(text: &str) -> (Vec<Span>, Vec<Span>) {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut index = 0;
    let mut comments = Vec::new();
    let mut strings = Vec::new();
    while index < chars.len() {
        let ch = chars[index].1;
        let next = chars.get(index + 1).map(|item| item.1);
        if ch == '/' && next == Some('/') {
            let start = chars
                .get(index + 2)
                .map(|item| item.0)
                .unwrap_or(text.len());
            index += 2;
            while index < chars.len() && chars[index].1 != '\n' {
                index += 1;
            }
            let end = chars.get(index).map(|item| item.0).unwrap_or(text.len());
            if end > start {
                comments.push((start, end));
            }
            continue;
        }
        if ch == '/' && next == Some('*') {
            let start = chars
                .get(index + 2)
                .map(|item| item.0)
                .unwrap_or(text.len());
            index += 2;
            while index + 1 < chars.len() && !(chars[index].1 == '*' && chars[index + 1].1 == '/') {
                index += 1;
            }
            let end = chars.get(index).map(|item| item.0).unwrap_or(text.len());
            if end > start {
                comments.push((start, end));
            }
            if index + 1 < chars.len() {
                index += 2;
            }
            continue;
        }
        if ch == '#' {
            let start = chars
                .get(index + 1)
                .map(|item| item.0)
                .unwrap_or(text.len());
            index += 1;
            while index < chars.len() && chars[index].1 != '\n' {
                index += 1;
            }
            let end = chars.get(index).map(|item| item.0).unwrap_or(text.len());
            if end > start {
                comments.push((start, end));
            }
            continue;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            let quote = ch;
            index += 1;
            let Some(start_item) = chars.get(index) else {
                break;
            };
            let start = start_item.0;
            while index < chars.len() && chars[index].1 != quote {
                if chars[index].1 == '\\' && index + 1 < chars.len() {
                    index += 2;
                    continue;
                }
                if chars[index].1 == '\n' && quote != '`' {
                    break;
                }
                index += 1;
            }
            let end = chars.get(index).map(|item| item.0).unwrap_or(text.len());
            if index < chars.len() && chars[index].1 == quote && end >= start {
                strings.push((start, end));
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    (comments, strings)
}

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
            found.iter().any(|candidate| {
                candidate.text == "TDH" && candidate.rule.as_deref() == Some("product-prefix")
            }),
            "{found:?}"
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
}
