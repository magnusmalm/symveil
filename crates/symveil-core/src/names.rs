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

struct Term {
    letters: Vec<char>,
}

struct Person {
    tokens: Vec<Vec<char>>,
}

pub struct NameMasker {
    terms: Vec<Term>,
    people: Vec<Person>,
    patterns: Vec<(String, Regex)>,
}

impl NameMasker {
    pub fn compile(names: &NamesSection) -> Result<Self> {
        validate(names)?;
        let terms = names
            .terms
            .iter()
            .map(|term| Term {
                letters: term_letters(term),
            })
            .collect();
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
            terms,
            people,
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
        for term in &self.terms {
            let mut index = 0;
            while index < chars.len() {
                if !start_boundary(&chars, index) {
                    index += 1;
                    continue;
                }
                let Some(end) = match_term(text, &chars, index, &term.letters) else {
                    index += 1;
                    continue;
                };
                let start = chars[index].0;
                out.push(candidate(start, end, "name-term"));
                while index < chars.len() && chars[index].0 < end {
                    index += 1;
                }
            }
        }
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
    fn collect_people(&self, chars: &[(usize, char)], out: &mut Vec<Candidate>) {
        for person in &self.people {
            let mut index = 0;
            while index < chars.len() {
                if !start_boundary(chars, index) {
                    index += 1;
                    continue;
                }
                let end = match_sequence(chars, index, &person.tokens)
                    .or_else(|| match_last_comma_first(chars, index, &person.tokens));
                let Some(end) = end else {
                    index += 1;
                    continue;
                };
                out.push(candidate(chars[index].0, end, "person-name"));
                while index < chars.len() && chars[index].0 < end {
                    index += 1;
                }
            }
            for token in &person.tokens {
                let mut index = 0;
                while index < chars.len() {
                    if !start_boundary(chars, index) {
                        index += 1;
                        continue;
                    }
                    let Some(end) = match_token(chars, index, token) else {
                        index += 1;
                        continue;
                    };
                    out.push(candidate(chars[index].0, end, "person-name"));
                    while index < chars.len() && chars[index].0 < end {
                        index += 1;
                    }
                }
            }
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
    let suffix = suffix_bytes(&text[after_letters..]);
    let end = after_letters + suffix;
    if !end_boundary(text, end) {
        return None;
    }
    Some(end)
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
}
