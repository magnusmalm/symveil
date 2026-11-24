//! Configurable company, product, and project names.
//!
//! Terms are matched case-insensitively. `-`, `_`, or `.` may sit between
//! letters (`Exem-pla`). A trailing Swedish suffix (`-s`, `-en`, `-et`, and
//! the common plural forms) is part of the match. A project-code regex is
//! used as written.

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

pub struct NameMasker {
    terms: Vec<Term>,
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
        let mut patterns = Vec::with_capacity(names.patterns.len());
        for pattern in &names.patterns {
            patterns.push((pattern.name.clone(), Regex::new(&pattern.regex)?));
        }
        Ok(Self { terms, patterns })
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
}
