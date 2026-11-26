//! Scores a realistic triage of the synthetic leak corpus.
//!
//! The text set is the 64 `expect = masked` items that appear in a text file.
//! The planted set is those masked items plus `agent-pass`, `docker-opaque`,
//! and `pytest-opaque` (73). Phone numbers, Swedish personnummer, and IPv6
//! stay in both denominators: this pass does not learn them.
//!
//! A full hit consumes the whole planted value. A partial hit masks a proper
//! substring and leaves the rest of the value in place. Benign words and
//! `expect = keep` items are precision failures. The floors are the measured
//! baseline of the triage below; a lower result is a regression.

use std::fs;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::extract::{self, hostname_labels_valid};
use crate::model::{Decision, DecisionAction, LearnCategory};
use crate::session::is_low_signal;
use crate::stoplist::is_calendar;
use crate::store::{file_from_decisions, matching_regex};
use crate::walk::{self, WalkOptions};

use symveil_detect::learned::LearnedFile;

/// Masked items with a text-file location.
const TEXT_SET: usize = 64;
/// Masked items, plus the three whole secrets the harness leaves visible.
const PLANTED_SET: usize = 73;

// Measured triage on this corpus. A partial that becomes full still passes.
// 54/58 useful is 93%. Keep hits and benign hits are precision failures.
const TEXT_FULL_FLOOR: usize = 53;
const TEXT_COVERED_FLOOR: usize = 53;
const PLANTED_FULL_FLOOR: usize = 56;
const PLANTED_COVERED_FLOOR: usize = 60;
const USEFUL_FLOOR: usize = 54;
const PRECISION_PERCENT_FLOOR: usize = 93;
const KEEP_HIT_CEILING: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Hit {
    Miss,
    Partial,
    Full,
}

#[derive(Deserialize)]
struct Seed {
    items: Vec<Item>,
    files: Vec<SeedFile>,
}

#[derive(Deserialize)]
struct Item {
    id: String,
    expect: String,
    family: String,
    value: String,
    locations: Vec<String>,
}

#[derive(Deserialize)]
struct SeedFile {
    path: String,
    kind: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    entry_name: Option<String>,
    #[serde(default)]
    entry_text: Option<String>,
}

#[test]
fn corpus_rules_match_their_source_and_leave_benign_words() {
    let seed = load_seed();
    let root = temp_root("text");
    write_text_files(&seed, &root);
    let walked = walk::walk(&root, &options(false)).unwrap();
    let candidates = extract::extract(&walked.files);
    let decisions = triage(&candidates);

    for decision in decisions.iter().filter(|decision| {
        decision.action == DecisionAction::Redact
            && matches!(
                decision.category,
                LearnCategory::Secret
                    | LearnCategory::Symbol
                    | LearnCategory::Email
                    | LearnCategory::Host
                    | LearnCategory::Domain
                    | LearnCategory::Ip
            )
    }) {
        let regex = matching_regex(
            &decision.text,
            &decision.sources,
            decision.left_glued,
            decision.right_glued,
        )
        .unwrap_or_else(|err| panic!("{err:#} for {}", decision.text));
        let re = Regex::new(&regex).unwrap();
        let lines: Vec<&str> = decision
            .sources
            .iter()
            .map(String::as_str)
            .filter(|line| line.contains(&decision.text))
            .collect();
        assert!(
            !lines.is_empty() && lines.iter().all(|line| re.is_match(line)),
            "rule {regex} missed a source for {}",
            decision.text
        );
    }

    let learned = file_from_decisions(&decisions).unwrap();
    let benign: Vec<&Item> = seed
        .items
        .iter()
        .filter(|item| item.family == "benign")
        .collect();
    assert_eq!(benign.len(), 14);
    for item in &benign {
        assert_eq!(
            cover_value(&learned, &item.value),
            Hit::Miss,
            "benign `{}` was learned",
            item.value
        );
    }

    let agent = seed
        .items
        .iter()
        .find(|item| item.id == "agent-pass")
        .unwrap();
    assert_eq!(
        cover_value(&learned, &agent.value),
        Hit::Full,
        "agent password was not learned in full"
    );
    assert!(learned
        .names
        .people
        .iter()
        .any(|person| person == "Ren Testdotter"));
    assert!(learned
        .names
        .people
        .iter()
        .all(|person| person.split_whitespace().all(|token| !is_calendar(token))));
    assert!(
        learned
            .names
            .people
            .iter()
            .all(|person| person != "Exempla Tundrahorn"),
        "company phrase was filed as a person: {:?}",
        learned.names.people
    );
    assert!(learned.names.terms.iter().any(|term| term == "Exempla"));
    assert!(learned.names.terms.iter().any(|term| term == "Tundrahorn"));
    assert!(
        learned
            .names
            .terms
            .iter()
            .all(|term| term != "TDH" && term != "FAN"),
        "a three-letter prefix was filed as a term: {:?}",
        learned.names.terms
    );
    for value in ["Exemplas", "Exem-pla"] {
        assert_ne!(
            cover_value(&learned, value),
            Hit::Miss,
            "{value} is not covered when the company name is accepted"
        );
    }
    assert_eq!(
        cover_value(&learned, "TDH_FAN_MAX"),
        Hit::Full,
        "TDH_FAN_MAX should be a learned literal, not a short term"
    );
    assert_eq!(
        cover_value(&learned, "tundrahorn_fan_init"),
        Hit::Full,
        "tundrahorn_fan_init should be a learned literal"
    );
    assert_eq!(
        cover_value(&learned, "db_backup.fan_line.internal"),
        Hit::Full,
        "underscore host was not learned in full"
    );
    assert_eq!(
        cover_value(&learned, "exempla_"),
        Hit::Full,
        "exempla_ was only partially covered"
    );
    assert_eq!(
        cover_value(&learned, "TDH-4471"),
        Hit::Full,
        "product code was not learned in full"
    );
    assert_eq!(cover_value(&learned, "FAN-ALPHA-2"), Hit::Full);
    assert_eq!(cover_value(&learned, "FAN-BETA-9"), Hit::Full);

    let text_items: Vec<&Item> = seed
        .items
        .iter()
        .filter(|item| text_item(item, &seed))
        .collect();
    let planted: Vec<&Item> = seed
        .items
        .iter()
        .filter(|item| planted_item(item))
        .collect();
    assert_eq!(text_items.len(), TEXT_SET, "text set changed");
    assert_eq!(planted.len(), PLANTED_SET, "planted set changed");

    let (text_full, text_partial) = tally(&learned, &text_items);
    let (planted_full, planted_partial) = tally(&learned, &planted);
    let (useful, entries, benign_hits, keep_hits) = precision(&learned, &seed);
    eprintln!(
        "learn corpus score: text {text_full} full + {text_partial} partial / {TEXT_SET}; planted {planted_full} full + {planted_partial} partial / {PLANTED_SET}; useful {useful}/{entries}; benign hits {benign_hits}; keep hits {keep_hits}"
    );
    assert_eq!(benign_hits, 0, "a learned entry matches a benign word");
    assert!(
        text_full >= TEXT_FULL_FLOOR && text_full + text_partial >= TEXT_COVERED_FLOOR,
        "text recall regressed: {text_full} full + {text_partial} partial"
    );
    assert!(
        planted_full >= PLANTED_FULL_FLOOR
            && planted_full + planted_partial >= PLANTED_COVERED_FLOOR,
        "planted recall regressed: {planted_full} full + {planted_partial} partial"
    );
    assert!(
        useful >= USEFUL_FLOOR && entries > 0 && useful * 100 / entries >= PRECISION_PERCENT_FLOOR,
        "precision regressed: {useful}/{entries}"
    );
    assert_eq!(
        keep_hits, KEEP_HIT_CEILING,
        "a learned entry matches an expect=keep item"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn include_skipped_rules_are_printable_and_hosts_are_legal() {
    let seed = load_seed();
    let root = temp_root("bin");
    write_text_files(&seed, &root);
    write_binary_files(&seed, &root);
    let walked = walk::walk(&root, &options(true)).unwrap();
    let joined = walked
        .files
        .iter()
        .map(|file| file.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !joined
            .chars()
            .any(|ch| ch == '\0' || (ch.is_control() && ch != '\n')),
        "binary extraction kept a NUL or a control character"
    );
    assert!(joined.contains("pdf.author@exempla.test"), "{joined}");
    assert!(joined.contains("zip.comment@exempla.test"), "{joined}");
    assert!(joined.contains("artifacts.tdh.corp"), "{joined}");

    let candidates = extract::extract(&walked.files);
    assert!(
        candidates.iter().all(|candidate| {
            candidate.category != LearnCategory::Host || hostname_labels_valid(&candidate.text)
        }),
        "invalid host label: {:?}",
        candidates
            .iter()
            .filter(|candidate| candidate.category == LearnCategory::Host)
            .map(|candidate| candidate.text.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        candidates
            .iter()
            .all(|candidate| !candidate.text.to_ascii_lowercase().contains("readme.txt")),
        "zip filename was learned as a host: {:?}",
        candidates
            .iter()
            .map(|candidate| candidate.text.as_str())
            .filter(|text| text.to_ascii_lowercase().contains("readme"))
            .collect::<Vec<_>>()
    );

    let learned = file_from_decisions(&triage(&candidates)).unwrap();
    for rule in learned.secrets.iter().chain(learned.symbols.iter()) {
        assert!(
            rule.regex.chars().all(|ch| ch != '\0' && !ch.is_control()),
            "rule `{}` is not printable: {:?}",
            rule.name,
            rule.regex
        );
    }
    for rule in &learned.secrets {
        if !rule.name.contains("-host-") && !rule.name.contains("-domain-") {
            continue;
        }
        let host = rule
            .regex
            .trim_start_matches(r"\b")
            .trim_end_matches(r"\b")
            .replace(r"\.", ".");
        assert!(
            hostname_labels_valid(&host),
            "host rule `{}` has an invalid label",
            rule.regex
        );
    }
    let _ = fs::remove_dir_all(&root);
}

fn triage(candidates: &[crate::model::Candidate]) -> Vec<Decision> {
    let mut decisions = Vec::new();
    for candidate in candidates {
        let action = if is_low_signal(candidate)
            || (candidate.category == LearnCategory::Symbol
                && !matches!(
                    candidate.rule.as_deref(),
                    Some("product-code") | Some("macro")
                )) {
            DecisionAction::Skip
        } else {
            DecisionAction::Redact
        };
        let mut decision = Decision::new(action, candidate.category, candidate.text.clone());
        decision.sources = if candidate.sources.is_empty() {
            vec![candidate.context.clone()]
        } else {
            candidate.sources.clone()
        };
        decision.left_glued = candidate.left_glued;
        decision.right_glued = candidate.right_glued;
        decisions.push(decision);
    }
    decisions
}

fn text_item(item: &Item, seed: &Seed) -> bool {
    item.expect == "masked"
        && item.locations.iter().any(|location| {
            seed.files
                .iter()
                .any(|file| file.kind == "text" && file.path == *location && file.body.is_some())
        })
}

fn planted_item(item: &Item) -> bool {
    item.expect == "masked"
        || matches!(
            item.id.as_str(),
            "agent-pass" | "docker-opaque" | "pytest-opaque"
        )
}

fn tally(learned: &LearnedFile, items: &[&Item]) -> (usize, usize) {
    let mut full = 0usize;
    let mut partial = 0usize;
    for item in items {
        match cover_value(learned, &item.value) {
            Hit::Full => full += 1,
            Hit::Partial => partial += 1,
            Hit::Miss => {}
        }
    }
    (full, partial)
}

fn precision(learned: &LearnedFile, seed: &Seed) -> (usize, usize, usize, usize) {
    let mut useful = 0usize;
    let mut benign_hits = 0usize;
    let mut keep_hits = 0usize;
    let entries = learned.names.terms.len()
        + learned.names.people.len()
        + learned.secrets.len()
        + learned.symbols.len();
    for term in learned
        .names
        .terms
        .iter()
        .chain(learned.names.people.iter())
    {
        judge_entry(
            seed,
            &mut useful,
            &mut benign_hits,
            &mut keep_hits,
            |value| cover_term(term, value),
        );
    }
    for rule in learned.secrets.iter().chain(learned.symbols.iter()) {
        let re = Regex::new(&rule.regex).unwrap();
        judge_entry(
            seed,
            &mut useful,
            &mut benign_hits,
            &mut keep_hits,
            |value| cover_regex(&re, value),
        );
    }
    (useful, entries, benign_hits, keep_hits)
}

fn judge_entry(
    seed: &Seed,
    useful: &mut usize,
    benign_hits: &mut usize,
    keep_hits: &mut usize,
    mut hit: impl FnMut(&str) -> Hit,
) {
    let mut planted = false;
    let mut benign = false;
    let mut keep = false;
    for item in &seed.items {
        if hit(&item.value) == Hit::Miss {
            continue;
        }
        if item.family == "benign" {
            benign = true;
        }
        if item.expect == "keep" {
            keep = true;
        }
        if planted_item(item) {
            planted = true;
        }
    }
    if benign {
        *benign_hits += 1;
    }
    if keep {
        *keep_hits += 1;
    }
    if planted && !benign && !keep {
        *useful += 1;
    }
}

fn cover_value(learned: &LearnedFile, value: &str) -> Hit {
    let mut best = Hit::Miss;
    for term in learned
        .names
        .terms
        .iter()
        .chain(learned.names.people.iter())
    {
        best = best.max(
            if learned.names.people.iter().any(|person| person == term) {
                cover_person(term, value)
            } else {
                cover_term(term, value)
            },
        );
    }
    for term in &learned.names.terms {
        best = best.max(cover_term(term, value));
    }
    for rule in learned.secrets.iter().chain(learned.symbols.iter()) {
        best = best.max(cover_regex(&Regex::new(&rule.regex).unwrap(), value));
    }
    best
}

fn cover_regex(re: &Regex, value: &str) -> Hit {
    let mut best = Hit::Miss;
    for matched in re.find_iter(value) {
        if matched.start() == matched.end() {
            continue;
        }
        best = best.max(if matched.start() == 0 && matched.end() == value.len() {
            Hit::Full
        } else {
            Hit::Partial
        });
    }
    best
}

fn cover_term(term: &str, value: &str) -> Hit {
    let letters = term_letters(term);
    if letters.len() < 3 {
        return Hit::Miss;
    }
    let chars: Vec<(usize, char)> = value.char_indices().collect();
    let mut best = Hit::Miss;
    for index in 0..chars.len() {
        if !start_boundary(&chars, index) {
            continue;
        }
        let Some(end) = match_term(value, &chars, index, &letters) else {
            continue;
        };
        best = best.max(span_hit(chars[index].0, end, value.len()));
    }
    best
}

fn cover_person(person: &str, value: &str) -> Hit {
    let tokens: Vec<Vec<char>> = person
        .split_whitespace()
        .map(term_letters)
        .filter(|letters| !letters.is_empty())
        .collect();
    let chars: Vec<(usize, char)> = value.char_indices().collect();
    let mut best = Hit::Miss;
    for index in 0..chars.len() {
        if !start_boundary(&chars, index) {
            continue;
        }
        if let Some(end) = match_sequence(&chars, index, &tokens) {
            best = best.max(span_hit(chars[index].0, end, value.len()));
        }
        for token in &tokens {
            if let Some(end) = match_token(&chars, index, token) {
                best = best.max(span_hit(chars[index].0, end, value.len()));
            }
        }
    }
    best
}

fn span_hit(start: usize, end: usize, len: usize) -> Hit {
    if start == 0 && end == len {
        Hit::Full
    } else {
        Hit::Partial
    }
}

const SUFFIXES: &[&str] = &[
    "arna", "erna", "orna", "en", "et", "na", "ar", "or", "er", "s",
];

fn term_letters(term: &str) -> Vec<char> {
    term.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn start_boundary(chars: &[(usize, char)], index: usize) -> bool {
    index == 0 || !chars[index - 1].1.is_alphanumeric()
}

fn is_separator(ch: char) -> bool {
    matches!(ch, '-' | '_' | '.')
}

fn match_term(
    text: &str,
    chars: &[(usize, char)],
    start: usize,
    letters: &[char],
) -> Option<usize> {
    if letters.is_empty() {
        return None;
    }
    let mut pos = start;
    for (offset, &letter) in letters.iter().enumerate() {
        if offset > 0 && pos < chars.len() && is_separator(chars[pos].1) {
            pos += 1;
        }
        if pos >= chars.len() || !same_letter(chars[pos].1, letter) {
            return None;
        }
        pos += 1;
    }
    let after = char_end(chars, pos - 1);
    let end = trailing_separator(text, after + suffix_bytes(&text[after..]));
    if !end_boundary(text, end) {
        return None;
    }
    Some(end)
}

/// `exempla_` is the whole token. A separator followed by more letters stays
/// outside the match.
fn trailing_separator(text: &str, end: usize) -> usize {
    let Some(ch) = text[end..].chars().next() else {
        return end;
    };
    if !is_separator(ch) {
        return end;
    }
    let next = end + ch.len_utf8();
    if end_boundary(text, next) {
        next
    } else {
        end
    }
}

fn char_end(chars: &[(usize, char)], index: usize) -> usize {
    let (start, ch) = chars[index];
    start + ch.len_utf8()
}

fn same_letter(ch: char, letter: char) -> bool {
    let mut lower = ch.to_lowercase();
    lower.next() == Some(letter) && lower.next().is_none()
}

fn suffix_bytes(rest: &str) -> usize {
    for suffix in SUFFIXES {
        let Some(prefix) = rest.get(..suffix.len()) else {
            continue;
        };
        if prefix.eq_ignore_ascii_case(suffix) && end_boundary(rest, suffix.len()) {
            return suffix.len();
        }
    }
    0
}

fn end_boundary(text: &str, end: usize) -> bool {
    match text[end..].chars().next() {
        None => true,
        Some(ch) => !ch.is_alphanumeric(),
    }
}

fn match_token(chars: &[(usize, char)], start: usize, letters: &[char]) -> Option<usize> {
    if letters.is_empty() {
        return None;
    }
    let mut pos = start;
    for &letter in letters {
        if pos >= chars.len() || !same_letter(chars[pos].1, letter) {
            return None;
        }
        pos += 1;
    }
    if pos < chars.len() && chars[pos].1.is_alphanumeric() {
        return None;
    }
    Some(char_end(chars, pos - 1))
}

fn match_sequence(chars: &[(usize, char)], start: usize, tokens: &[Vec<char>]) -> Option<usize> {
    if tokens.is_empty() {
        return None;
    }
    let mut pos = start;
    let mut end = 0;
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 {
            if pos >= chars.len() || !chars[pos].1.is_whitespace() {
                return None;
            }
            while pos < chars.len() && chars[pos].1.is_whitespace() {
                pos += 1;
            }
        }
        end = match_token(chars, pos, token)?;
        while pos < chars.len() && chars[pos].0 < end {
            pos += 1;
        }
    }
    Some(end)
}

fn load_seed() -> Seed {
    let seed_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/leak/seed.json");
    serde_json::from_str(&fs::read_to_string(&seed_path).unwrap()).unwrap()
}

fn temp_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "symveil-learn-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn options(include_skipped: bool) -> WalkOptions {
    WalkOptions {
        max_bytes: 1024 * 1024,
        gitignore: true,
        follow_symlinks: false,
        include_skipped,
    }
}

fn write_text_files(seed: &Seed, root: &Path) {
    for file in &seed.files {
        if file.kind != "text" {
            continue;
        }
        let Some(body) = &file.body else {
            continue;
        };
        let path = root.join(&file.path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
    }
}

fn write_binary_files(seed: &Seed, root: &Path) {
    for file in &seed.files {
        let path = root.join(&file.path);
        let bytes = match file.kind.as_str() {
            "pdf" => {
                let author = file.author.clone().unwrap_or_default();
                let mut bytes = b"\0".to_vec();
                bytes.extend(author.as_bytes());
                bytes.push(0);
                bytes
            }
            "png" => {
                let mut bytes = b"\x89PNG\r\n".to_vec();
                bytes.extend(b"png.author@exempla.test");
                bytes.push(0);
                bytes
            }
            "zip" => glue_zip(
                file.entry_name.as_deref().unwrap_or("README.txt"),
                file.entry_text.as_deref().unwrap_or(""),
                file.comment.as_deref().unwrap_or(""),
            ),
            _ => continue,
        };
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
    }
}

/// Filename, then the entry text, then a central-directory signature, so a
/// careless scan glues `README.txt` to `fl` and to `PK`.
fn glue_zip(name: &str, entry_text: &str, comment: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(entry_text.as_bytes());
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(name.as_bytes());
    out.push(0x05);
    out.extend_from_slice(comment.as_bytes());
    out
}
