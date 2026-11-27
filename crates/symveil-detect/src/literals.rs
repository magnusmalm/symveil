//! Literal learned rules.
//!
//! A learned secret, host, or symbol is usually an escaped literal with
//! optional word boundaries, not an open-ended expression. Those rules share
//! one automaton. A pattern that is not a literal stays a regex.

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralPattern {
    pub text: String,
    pub left_boundary: bool,
    pub right_boundary: bool,
}

/// `regex::escape` leaves raw newlines in the pattern. Spell controls as
/// escapes so a learned rule stays printable and still matches the source.
pub fn escape_literal(text: &str) -> String {
    regex::escape(text)
        .replace('\n', r"\n")
        .replace('\r', r"\r")
        .replace('\t', r"\t")
}

/// Parse a pattern learn would emit for a literal, or `None` when the
/// pattern is a real expression such as `TDH\-\d+`.
pub fn literal_pattern(pattern: &str) -> Option<LiteralPattern> {
    if pattern.is_empty() {
        return None;
    }
    let (left_boundary, rest) = strip_leading_boundary(pattern);
    let (body, right_boundary) = strip_trailing_boundary(rest);
    let text = unescape_literal(body)?;
    if text.is_empty() || escape_literal(&text) != body {
        return None;
    }
    Some(LiteralPattern {
        text,
        left_boundary,
        right_boundary,
    })
}

pub fn literal_is_match(haystack: &str, needle: &str, left: bool, right: bool) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(pos) = haystack[from..].find(needle) {
        let start = from + pos;
        let end = start + needle.len();
        if boundaries_ok(haystack, start, end, left, right) {
            return true;
        }
        let step = haystack[start..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(1);
        from = start + step;
    }
    false
}

pub fn boundaries_ok(text: &str, start: usize, end: usize, left: bool, right: bool) -> bool {
    if start > end || end > text.len() {
        return false;
    }
    if left && !word_boundary_at(text, start) {
        return false;
    }
    if right && !word_boundary_at(text, end) {
        return false;
    }
    true
}

fn strip_leading_boundary(pattern: &str) -> (bool, &str) {
    match pattern.strip_prefix(r"\b") {
        Some(rest) => (true, rest),
        None => (false, pattern),
    }
}

fn strip_trailing_boundary(pattern: &str) -> (&str, bool) {
    let bytes = pattern.as_bytes();
    if bytes.len() < 2 || bytes[bytes.len() - 1] != b'b' {
        return (pattern, false);
    }
    let mut index = bytes.len() - 1;
    let mut slashes = 0;
    while index > 0 && bytes[index - 1] == b'\\' {
        slashes += 1;
        index -= 1;
    }
    if slashes % 2 == 1 {
        (&pattern[..pattern.len() - 2], true)
    } else {
        (pattern, false)
    }
}

fn unescape_literal(pattern: &str) -> Option<String> {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => return None,
        }
    }
    Some(out)
}

/// Same edge the regex crate uses for `\b` on ASCII and letters.
/// Connector punctuation other than `_` is not treated as a word character.
fn word_boundary_at(text: &str, index: usize) -> bool {
    if !text.is_char_boundary(index) {
        return false;
    }
    let prev = text[..index].chars().next_back();
    let next = text[index..].chars().next();
    match (prev, next) {
        (None, None) => false,
        (None, Some(ch)) | (Some(ch), None) => is_word(ch),
        (Some(before), Some(after)) => is_word(before) != is_word(after),
    }
}

fn is_word(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

/// A literal rule and the regex crate agree on these spans.
pub fn literal_spans_match_regex(pattern: &str, text: &str) -> bool {
    let Some(lit) = literal_pattern(pattern) else {
        return false;
    };
    let re = Regex::new(pattern).expect("literal pattern");
    let mut from = 0;
    let mut ours = Vec::new();
    while let Some(pos) = text[from..].find(&lit.text) {
        let start = from + pos;
        let end = start + lit.text.len();
        if boundaries_ok(text, start, end, lit.left_boundary, lit.right_boundary) {
            ours.push((start, end));
            from = end;
        } else {
            let step = text[start..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            from = start + step;
        }
    }
    let theirs: Vec<_> = re.find_iter(text).map(|m| (m.start(), m.end())).collect();
    ours == theirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_round_trip_and_expressions_do_not() {
        for text in ["foo", "a.b", "x\\y", "a\nb", "host1.example"] {
            let escaped = escape_literal(text);
            let lit = literal_pattern(&escaped).unwrap();
            assert_eq!(lit.text, text);
            assert!(!lit.left_boundary);
            assert!(!lit.right_boundary);
        }
        let wrapped = format!(r"\b{}\b", escape_literal("foo_bar"));
        let lit = literal_pattern(&wrapped).unwrap();
        assert!(lit.left_boundary && lit.right_boundary);
        assert_eq!(lit.text, "foo_bar");
        assert!(literal_pattern(r"TDH\-\d+").is_none());
        assert!(literal_pattern(r"\bTDH\-\d+\b").is_none());
    }

    #[test]
    fn boundaries_match_the_regex_engine() {
        let samples = [
            (r"\bfoo\b", "foo xfoo foo foox"),
            (r"bar\b", "bar xbar barx"),
            (r"\bbar", "bar xbar"),
            (r"a\.b", "a.b xa.b"),
            (r"\bcafe\b", "café cafe"),
        ];
        for (pattern, text) in samples {
            assert!(
                literal_spans_match_regex(pattern, text),
                "{pattern} in {text}"
            );
        }
    }
}
