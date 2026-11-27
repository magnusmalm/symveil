//! Configurable company, product, project, and person names.
//!
//! Terms are matched case-insensitively. `-`, `_`, or `.` may sit between
//! letters (`Exem-pla`). A trailing Swedish suffix (`-s`, `-en`, `-et`, and
//! the common plural forms) is part of the match. A project-code regex is
//! used as written.
//!
//! A person entry such as `Ren Testdotter` matches that sequence with any
//! whitespace between tokens, the `Last, First` form, and each token on its
//! own when the token is bounded by a non-alphanumeric character. A token
//! does not match inside a longer word (`Ren` does not match `render`).

use anyhow::{bail, Context, Result};
use regex::Regex;

use crate::category::Category;
use crate::config::{NamesSection, UserPattern};
use crate::masker::{Boundary, Candidate, Masker, PRI_PATTERN};

const MIN_TERM_CHARS: usize = 3;
const SUFFIXES: &[&str] = &[
    "arna", "erna", "orna", "en", "et", "na", "ar", "or", "er", "s",
];

pub fn validate(names: &NamesSection) -> Result<()> {
    for term in &names.terms {
        if term_letters(term).len() < MIN_TERM_CHARS {
            bail!("name term `{term}` needs at least {MIN_TERM_CHARS} letters or digits");
        }
    }
    for person in &names.people {
        person_tokens(person)?;
    }
    for pattern in &names.patterns {
        check_pattern(pattern)?;
    }
    Ok(())
}

fn check_pattern(pattern: &UserPattern) -> Result<()> {
    if pattern.name.is_empty() {
        bail!("a [redact.names] pattern needs a name");
    }
    if pattern.regex.is_empty() {
        bail!("name pattern `{}` has an empty regex", pattern.name);
    }
    Regex::new(&pattern.regex).with_context(|| format!("name pattern `{}`", pattern.name))?;
    Ok(())
}

struct Person {
    tokens: Vec<Vec<char>>,
}

pub struct NameMasker {
    terms: Trie,
    people: PersonTrie,
    patterns: Vec<(String, Regex)>,
}

impl NameMasker {
    pub fn compile(names: &NamesSection) -> Result<Self> {
        validate(names)?;
        let letters: Vec<Vec<char>> = names.terms.iter().map(|term| term_letters(term)).collect();
        let people = names
            .people
            .iter()
            .map(|person| {
                Ok(Person {
                    tokens: person_tokens(person)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut patterns = Vec::with_capacity(names.patterns.len());
        for pattern in &names.patterns {
            patterns.push((pattern.name.clone(), Regex::new(&pattern.regex)?));
        }
        Ok(Self {
            terms: Trie::from_terms(&letters),
            people: PersonTrie::build(people),
            patterns,
        })
    }
}

impl Masker for NameMasker {
    fn name(&self) -> &'static str {
        "names"
    }

    fn collect(&self, text: &str) -> Vec<Candidate> {
        let mut out = Vec::new();
        let chars: Vec<(usize, char)> = text.char_indices().collect();
        // Term candidates, then people, then patterns. `select_spans` is a
        // stable sort, so this order keeps an equal-length tie on the same
        // bytes as the earlier per-term scan.
        self.collect_terms(text, &chars, &mut out);
        self.collect_people(&chars, &mut out);
        for (name, regex) in &self.patterns {
            for matched in regex.find_iter(text) {
                if matched.start() == matched.end() {
                    continue;
                }
                out.push(candidate(matched.start(), matched.end(), name));
            }
        }
        out
    }
}

impl NameMasker {
    fn collect_terms(&self, text: &str, chars: &[(usize, char)], out: &mut Vec<Candidate>) {
        if !self.terms.has_terminal {
            return;
        }
        for index in 0..chars.len() {
            if !start_boundary(chars, index) {
                continue;
            }
            let start_byte = chars[index].0;
            let mut node = 0u32;
            let mut pos = index;
            let mut depth = 0usize;
            loop {
                let mut next = pos;
                if depth > 0 && next < chars.len() && is_separator(chars[next].1) {
                    next += 1;
                }
                if next >= chars.len() {
                    break;
                }
                let Some(letter) = fold_letter(chars[next].1) else {
                    break;
                };
                let Some(child) = self.terms.child(node, letter) else {
                    break;
                };
                node = child;
                depth += 1;
                let after = char_end(chars, next);
                pos = next + 1;
                if self.terms.nodes[node as usize].terminal {
                    let end = trailing_separator(text, after + suffix_bytes(&text[after..]));
                    if end_boundary(text, end) {
                        out.push(candidate(start_byte, end, "name-term"));
                    }
                }
            }
        }
    }

    fn collect_people(&self, chars: &[(usize, char)], out: &mut Vec<Candidate>) {
        if !self.people.trie.has_terminal {
            return;
        }
        for index in 0..chars.len() {
            if !start_boundary(chars, index) {
                continue;
            }
            let Some((node, next_pos)) = self.people.whole_token(chars, index) else {
                continue;
            };
            let start_byte = chars[index].0;
            let token_end = char_end(chars, next_pos - 1);
            out.push(candidate(start_byte, token_end, "person-name"));
            for &person in &self.people.first_of[node as usize] {
                let tokens = &self.people.tokens[person as usize];
                if let Some(end) = match_sequence(chars, index, tokens) {
                    out.push(candidate(start_byte, end, "person-name"));
                }
            }
            for &person in &self.people.last_of[node as usize] {
                let tokens = &self.people.tokens[person as usize];
                if let Some(end) = match_last_comma_first(chars, index, tokens) {
                    out.push(candidate(start_byte, end, "person-name"));
                }
            }
        }
    }
}

/// One lowercase letter. A character whose lowercase form is more than one
/// scalar matches no stored letter, which is the same rule as `same_letter`.
fn fold_letter(ch: char) -> Option<char> {
    let mut lower = ch.to_lowercase();
    let letter = lower.next()?;
    if lower.next().is_some() {
        None
    } else {
        Some(letter)
    }
}

struct TrieNode {
    head_char: char,
    head_child: u32,
    has_head: bool,
    terminal: bool,
    rest: Box<[(char, u32)]>,
}

impl TrieNode {
    fn empty() -> Self {
        Self {
            head_char: '\0',
            head_child: 0,
            has_head: false,
            terminal: false,
            rest: Box::from([]),
        }
    }
}

/// Terms share one walk. A chain of unique letters keeps its first edge on the
/// node so a 100k-term set does not allocate a vector per letter.
struct Trie {
    nodes: Vec<TrieNode>,
    has_terminal: bool,
}

impl Trie {
    fn new() -> Self {
        Self {
            nodes: vec![TrieNode::empty()],
            has_terminal: false,
        }
    }

    fn from_terms(terms: &[Vec<char>]) -> Self {
        let mut trie = Self::new();
        for letters in terms {
            if letters.is_empty() {
                continue;
            }
            trie.insert_terminal(letters);
        }
        trie
    }

    fn insert_terminal(&mut self, letters: &[char]) -> u32 {
        let mut node = 0u32;
        for &letter in letters {
            node = self.ensure_edge(node, letter);
        }
        self.nodes[node as usize].terminal = true;
        self.has_terminal = true;
        node
    }

    fn ensure_edge(&mut self, node: u32, letter: char) -> u32 {
        if let Some(child) = self.child(node, letter) {
            return child;
        }
        let child = self.nodes.len() as u32;
        self.nodes.push(TrieNode::empty());
        self.attach(node, letter, child);
        child
    }

    fn attach(&mut self, node: u32, letter: char, child: u32) {
        let current = &mut self.nodes[node as usize];
        if !current.has_head {
            current.has_head = true;
            current.head_char = letter;
            current.head_child = child;
            return;
        }
        let mut edges = Vec::with_capacity(current.rest.len() + 1);
        edges.extend(current.rest.iter().copied());
        let index = edges.partition_point(|edge| edge.0 < letter);
        edges.insert(index, (letter, child));
        current.rest = edges.into_boxed_slice();
    }

    fn child(&self, node: u32, letter: char) -> Option<u32> {
        let current = &self.nodes[node as usize];
        if current.has_head && current.head_char == letter {
            return Some(current.head_child);
        }
        current
            .rest
            .binary_search_by_key(&letter, |edge| edge.0)
            .ok()
            .map(|index| current.rest[index].1)
    }
}

struct PersonTrie {
    trie: Trie,
    tokens: Vec<Vec<Vec<char>>>,
    first_of: Vec<Box<[u32]>>,
    last_of: Vec<Box<[u32]>>,
}

impl PersonTrie {
    fn build(people: Vec<Person>) -> Self {
        let mut trie = Trie::new();
        let mut first_hits = Vec::new();
        let mut last_hits = Vec::new();
        for (id, person) in people.iter().enumerate() {
            for token in &person.tokens {
                trie.insert_terminal(token);
            }
            if person.tokens.len() > 1 {
                let id = id as u32;
                let first = trie.insert_terminal(&person.tokens[0]);
                let last = trie.insert_terminal(person.tokens.last().expect("len > 1"));
                first_hits.push((first, id));
                last_hits.push((last, id));
            }
        }
        let mut first_buckets = vec![Vec::new(); trie.nodes.len()];
        let mut last_buckets = vec![Vec::new(); trie.nodes.len()];
        for (node, id) in first_hits {
            first_buckets[node as usize].push(id);
        }
        for (node, id) in last_hits {
            last_buckets[node as usize].push(id);
        }
        Self {
            trie,
            tokens: people.into_iter().map(|person| person.tokens).collect(),
            first_of: first_buckets
                .into_iter()
                .map(|ids| ids.into_boxed_slice())
                .collect(),
            last_of: last_buckets
                .into_iter()
                .map(|ids| ids.into_boxed_slice())
                .collect(),
        }
    }

    /// The alphanumeric run starting at `start`, when that whole run is a
    /// configured token. A shorter token inside a longer word is not a match.
    fn whole_token(&self, chars: &[(usize, char)], start: usize) -> Option<(u32, usize)> {
        if start >= chars.len() || !chars[start].1.is_alphanumeric() {
            return None;
        }
        let mut node = 0u32;
        let mut pos = start;
        while pos < chars.len() && chars[pos].1.is_alphanumeric() {
            let letter = fold_letter(chars[pos].1)?;
            node = self.trie.child(node, letter)?;
            pos += 1;
        }
        if self.trie.nodes[node as usize].terminal {
            Some((node, pos))
        } else {
            None
        }
    }
}

fn candidate(start: usize, end: usize, rule: &str) -> Candidate {
    Candidate {
        start,
        end,
        category: Category::Codename,
        rule: Some(rule.to_string()),
        priority: PRI_PATTERN,
        boundary: Boundary::None,
    }
}

fn person_tokens(person: &str) -> Result<Vec<Vec<char>>> {
    let tokens: Vec<Vec<char>> = person
        .split_whitespace()
        .map(term_letters)
        .filter(|letters| !letters.is_empty())
        .collect();
    if tokens.is_empty() {
        bail!("person name `{person}` has no letters or digits");
    }
    for token in &tokens {
        if token.len() < MIN_TERM_CHARS {
            bail!(
                "person name `{person}` has a token shorter than {MIN_TERM_CHARS} letters or digits"
            );
        }
    }
    Ok(tokens)
}

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

#[cfg(test)]
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
    let after_letters = char_end(chars, pos - 1);
    let end = trailing_separator(text, after_letters + suffix_bytes(&text[after_letters..]));
    if !end_boundary(text, end) {
        return None;
    }
    Some(end)
}

/// `exempla_` is the whole token. A separator followed by more letters, as in
/// `tundrahorn_fan_init`, stays outside the match.
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

/// One token, with no separator inside it. The caller has already checked the
/// start boundary.
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

/// `Last, First` for a two-token name, and `Last, First Middle` when more
/// tokens were configured. Whitespace around the comma is optional.
fn match_last_comma_first(
    chars: &[(usize, char)],
    start: usize,
    tokens: &[Vec<char>],
) -> Option<usize> {
    let (last, rest) = tokens.split_last()?;
    if rest.is_empty() {
        return None;
    }
    let mut pos = start;
    let last_end = match_token(chars, pos, last)?;
    while pos < chars.len() && chars[pos].0 < last_end {
        pos += 1;
    }
    while pos < chars.len() && chars[pos].1.is_whitespace() {
        pos += 1;
    }
    if pos >= chars.len() || chars[pos].1 != ',' {
        return None;
    }
    pos += 1;
    while pos < chars.len() && chars[pos].1.is_whitespace() {
        pos += 1;
    }
    let rest_end = match_sequence(chars, pos, rest)?;
    Some(rest_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactSection;
    use crate::redact::Engine;
    use crate::vault::Vault;

    fn engine(names: NamesSection) -> Engine {
        Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                internal_domains: Vec::new(),
                names,
                ..RedactSection::default()
            },
        )
        .unwrap()
    }

    fn masked(names: NamesSection, input: &str) -> String {
        let mut engine = engine(names);
        let (out, _) = engine.redact_str(input).unwrap();
        assert_eq!(engine.restore_str(&out), input, "{out}");
        out
    }

    fn terms() -> NamesSection {
        NamesSection {
            terms: vec!["Exempla".into(), "Tundrahorn".into(), "TDH".into()],
            patterns: vec![
                UserPattern {
                    name: "tdh-code".into(),
                    regex: r"TDH-\d+".into(),
                    category: None,
                },
                UserPattern {
                    name: "fan-code".into(),
                    regex: r"FAN-[A-Z]+-\d+".into(),
                    category: None,
                },
            ],
            people: Vec::new(),
        }
    }

    fn people() -> NamesSection {
        NamesSection {
            people: vec!["Ren Testdotter".into()],
            ..NamesSection::default()
        }
    }

    #[test]
    fn names_match_case_separators_inflection_and_codes() {
        let names = terms();
        let samples = [
            "EXEMPLA",
            "exempla_",
            "Exem-pla",
            "Exemplas",
            "tundrahornen",
            "tundrahorn_fan_init",
            "TDH_FAN_MAX",
            "TDH-4471",
            "FAN-ALPHA-2",
        ];
        for sample in samples {
            let out = masked(names.clone(), sample);
            assert!(!out.contains(sample), "{sample} -> {out}");
            assert!(out.contains("@@sv:"), "{sample} -> {out}");
        }
        let underscore = masked(names.clone(), "exempla_");
        assert!(
            !underscore.contains('_'),
            "trailing underscore leaked: {underscore}"
        );
        let longer = masked(names, "tundrahorn_fan_init");
        assert!(
            longer.contains("_fan_init"),
            "a following identifier was swallowed: {longer}"
        );
    }

    #[test]
    fn benign_words_and_short_collisions_stay() {
        let input = "exempel fläkt threshold compile method";
        let out = masked(terms(), input);
        assert_eq!(out, input);
    }

    #[test]
    fn a_secret_that_starts_with_a_term_stays_one_secret() {
        let mut engine = Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                internal_domains: Vec::new(),
                names: NamesSection {
                    terms: vec!["TDH".into()],
                    ..NamesSection::default()
                },
                secrets: vec![crate::config::SecretRule {
                    name: "tdh-factory-token".into(),
                    regex: r"\btdh_live_[A-Za-z0-9]{16,}\b".into(),
                    action: None,
                }],
                ..RedactSection::default()
            },
        )
        .unwrap();
        let input = "token tdh_live_SVCNFACTORYTOKEN1";
        let (out, hits) = engine.redact_str(input).unwrap();
        assert!(!out.contains("tdh_live_SVCNFACTORYTOKEN1"), "{out}");
        assert!(
            hits.iter()
                .any(|hit| hit.rule.as_deref() == Some("tdh-factory-token")),
            "{hits:?}"
        );
        assert_eq!(engine.restore_str(&out), input);
    }

    #[test]
    fn a_term_shorter_than_three_characters_is_rejected() {
        let built = Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                names: NamesSection {
                    terms: vec!["ab".into()],
                    ..NamesSection::default()
                },
                ..RedactSection::default()
            },
        );
        let Err(error) = built else {
            panic!("a two-character term was accepted");
        };
        assert!(error.to_string().contains("ab"), "{error}");
    }

    #[test]
    fn empty_names_leave_text_unchanged() {
        let out = masked(
            NamesSection::default(),
            "Exempla stays until it is configured",
        );
        assert_eq!(out, "Exempla stays until it is configured");
    }

    #[test]
    fn people_match_case_order_and_a_single_token() {
        let names = people();
        let wholes = [
            "Ren Testdotter",
            "REN TESTDOTTER",
            "ren   testdotter",
            "Testdotter, Ren",
            "testdotter,  ren",
            "TESTDOTTER,REN",
        ];
        for sample in wholes {
            let out = masked(names.clone(), sample);
            assert!(
                out.starts_with("@@sv:") && out.ends_with("@@") && out.matches("@@").count() == 2,
                "{sample} -> {out}"
            );
        }

        let hello = masked(names.clone(), "Hello Ren.");
        assert!(hello.starts_with("Hello "), "{hello}");
        assert!(hello.ends_with('.'), "{hello}");
        assert!(!hello.contains("Ren"), "{hello}");

        let file = masked(names.clone(), "the Testdotter file");
        assert!(file.starts_with("the "), "{file}");
        assert!(file.ends_with(" file"), "{file}");
        assert!(!file.contains("Testdotter"), "{file}");

        let hyphen = masked(names, "Ren-Testdotter");
        assert!(
            !hyphen.contains("Ren") && !hyphen.contains("Testdotter"),
            "{hyphen}"
        );
        assert_eq!(hyphen.matches("@@sv:").count(), 2, "{hyphen}");
    }

    #[test]
    fn person_tokens_do_not_match_inside_a_word() {
        let input = "render rental parent pre-render testdottery or the rent";
        let out = masked(people(), input);
        assert_eq!(out, input);
    }

    #[test]
    fn a_short_person_token_is_rejected() {
        let built = Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                names: NamesSection {
                    people: vec!["Al Smith".into()],
                    ..NamesSection::default()
                },
                ..RedactSection::default()
            },
        );
        let Err(error) = built else {
            panic!("a two-character person token was accepted");
        };
        assert!(error.to_string().contains("Al Smith"), "{error}");
    }

    #[test]
    fn trie_spans_match_the_per_term_scan() {
        let samples = [
            (
                terms(),
                "EXEMPLA exempla_ Exem-pla Exemplas tundrahornen tundrahorn_fan_init TDH_FAN_MAX TDH-4471",
            ),
            (
                people(),
                "Ren Testdotter, REN   TESTDOTTER, Testdotter, Ren, Hello Ren. Ren-Testdotter render",
            ),
            (
                NamesSection {
                    terms: vec!["abc".into(), "abcd".into(), "abcde".into(), "xyz".into()],
                    people: vec!["Abc Defg".into(), "Xyz Abcd".into()],
                    patterns: vec![UserPattern {
                        name: "zz-code".into(),
                        regex: r"ZZ-\d+".into(),
                        category: None,
                    }],
                },
                "abc ab-cd abcden abcde Abc Defg Defg, Abc xyz ZZ-9 abcs abc_def a-b-c-d",
            ),
        ];
        for (names, text) in samples {
            assert_same_spans(&names, text);
        }

        let mut state = 0x5eed_u64;
        let mut mixed = terms();
        mixed.people = people().people;
        for _ in 0..40 {
            let mut text = String::new();
            for _ in 0..240 {
                let roll = xorshift(&mut state);
                let piece: &str = match roll % 17 {
                    0 => "Exempla",
                    1 => "exem-pla",
                    2 => "Tundrahornen",
                    3 => "Ren Testdotter",
                    4 => "Testdotter, Ren",
                    5 => " ",
                    6 => "-",
                    7 => "_",
                    8 => ".",
                    9 => "TDH",
                    10 => "render",
                    11 => "s",
                    12 => "en",
                    13 => "ZZ",
                    14 => "9",
                    15 => "abc",
                    _ => "word",
                };
                text.push_str(piece);
            }
            assert_same_spans(&mixed, &text);
        }

        let corpus = crate::bench_corpus::Corpus::build(crate::bench_corpus::Profile::ci());
        for payload in &corpus.payloads {
            let text = std::str::from_utf8(&payload.bytes).expect("bench payload is utf-8");
            assert_same_spans(&corpus.redact.names, text);
        }
    }

    fn assert_same_spans(names: &NamesSection, text: &str) {
        let legacy = legacy_collect(names, text);
        let masker = NameMasker::compile(names).expect("names");
        let got: Vec<(usize, usize, String)> = masker
            .collect(text)
            .into_iter()
            .map(|item| (item.start, item.end, item.rule.expect("rule")))
            .collect();
        let mut legacy_set = legacy.clone();
        legacy_set.sort();
        legacy_set.dedup();
        let mut got_set = got.clone();
        got_set.sort();
        got_set.dedup();
        for span in &legacy_set {
            assert!(got_set.contains(span), "missing {span:?}\ntext: {text}");
        }
        assert_eq!(
            greedy(&got),
            greedy(&legacy),
            "selected spans differ\ntext: {text}"
        );
    }

    fn greedy(spans: &[(usize, usize, String)]) -> Vec<(usize, usize, String)> {
        let mut ordered = spans.to_vec();
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then(right.1.cmp(&left.1)));
        let mut selected = Vec::new();
        let mut cursor = 0usize;
        for span in ordered {
            if span.0 < cursor {
                continue;
            }
            cursor = span.1;
            selected.push(span);
        }
        selected
    }

    fn legacy_collect(names: &NamesSection, text: &str) -> Vec<(usize, usize, String)> {
        let terms: Vec<Vec<char>> = names.terms.iter().map(|term| term_letters(term)).collect();
        let people: Vec<Vec<Vec<char>>> = names
            .people
            .iter()
            .map(|person| person_tokens(person).expect("person"))
            .collect();
        let mut out = Vec::new();
        let chars: Vec<(usize, char)> = text.char_indices().collect();
        for letters in &terms {
            let mut index = 0;
            while index < chars.len() {
                if !start_boundary(&chars, index) {
                    index += 1;
                    continue;
                }
                let Some(end) = match_term(text, &chars, index, letters) else {
                    index += 1;
                    continue;
                };
                out.push((chars[index].0, end, "name-term".to_string()));
                while index < chars.len() && chars[index].0 < end {
                    index += 1;
                }
            }
        }
        for person in &people {
            let mut index = 0;
            while index < chars.len() {
                if !start_boundary(&chars, index) {
                    index += 1;
                    continue;
                }
                let end = match_sequence(&chars, index, person)
                    .or_else(|| match_last_comma_first(&chars, index, person));
                let Some(end) = end else {
                    index += 1;
                    continue;
                };
                out.push((chars[index].0, end, "person-name".to_string()));
                while index < chars.len() && chars[index].0 < end {
                    index += 1;
                }
            }
            for token in person {
                let mut index = 0;
                while index < chars.len() {
                    if !start_boundary(&chars, index) {
                        index += 1;
                        continue;
                    }
                    let Some(end) = match_token(&chars, index, token) else {
                        index += 1;
                        continue;
                    };
                    out.push((chars[index].0, end, "person-name".to_string()));
                    while index < chars.len() && chars[index].0 < end {
                        index += 1;
                    }
                }
            }
        }
        for pattern in &names.patterns {
            let regex = regex::Regex::new(&pattern.regex).expect("pattern");
            for matched in regex.find_iter(text) {
                if matched.start() == matched.end() {
                    continue;
                }
                out.push((matched.start(), matched.end(), pattern.name.clone()));
            }
        }
        out
    }

    fn xorshift(state: &mut u64) -> u64 {
        let mut value = *state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        *state = value;
        value
    }
}
