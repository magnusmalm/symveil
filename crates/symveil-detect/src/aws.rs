//! AWS keys that are split across a gap.
//!
//! A whole `AKIA` + 16 key is a builtin. This module masks the two pieces
//! when a newline, a `"…" + "…"` join, or two JSON string values form one
//! access key id or one 40-character secret access key. An unlabeled
//! 40-character string is not a secret: SHA-1 is that long.

use crate::secrets::SecretHit;

const SPLIT_RULE: &str = "split-aws-key";
const SECRET_RULE: &str = "aws-secret-access-key";

pub struct BoundaryPart {
    pub left: bool,
    pub start: usize,
    pub end: usize,
    pub rule: &'static str,
}

/// Pieces of one key that meet at the boundary between `left` and `right`.
pub fn boundary_parts(left: &str, right: &str) -> Vec<BoundaryPart> {
    let mut out = Vec::new();
    if let Some((start, end, right_start, right_end)) = access_key_boundary(left, right) {
        push_pair(&mut out, start, end, right_start, right_end);
    }
    if let Some((start, end, right_start, right_end)) = secret_boundary(left, right) {
        push_pair(&mut out, start, end, right_start, right_end);
    }
    out
}

/// A 40-character secret sitting next to a secret-access-key label.
/// An unlabeled 40-character string stays, including SHA-1.
pub fn labeled_secret_hits(text: &str) -> Vec<SecretHit> {
    // Real labels contain `secret`, `Secret`, or `SECRET`. A mixed spelling
    // such as `sEcret` is left alone.
    if !text.contains("secret") && !text.contains("Secret") && !text.contains("SECRET") {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let mut hits = Vec::new();
    let mut index = 0;
    while index + 6 <= bytes.len() {
        let Some(rel) = bytes[index..]
            .iter()
            .position(|byte| *byte == b's' || *byte == b'S')
        else {
            break;
        };
        index += rel;
        if index + 6 <= bytes.len() && starts_with_ignore_ascii(&bytes[index..], b"secret") {
            if let Some((start, end)) = secret_value_at(bytes, index) {
                hits.push(SecretHit {
                    start,
                    end,
                    rule: SECRET_RULE.to_string(),
                });
                index = end;
                continue;
            }
        }
        index += 1;
    }
    hits
}

/// Splits that sit inside one string: a newline, `"left" + "right"`, or
/// `"left","key":"right"`.
pub fn gap_hits(text: &str) -> Vec<SecretHit> {
    if !text.contains("AKIA") && !text.contains('/') && !text.contains('+') {
        return Vec::new();
    }
    let mut hits = Vec::new();
    if text.contains('\n') {
        let bytes = text.as_bytes();
        let mut offset = 0;
        while let Some(rel) = text[offset..].find('\n') {
            let at = offset + rel;
            let left_end = if at > 0 && bytes[at - 1] == b'\r' {
                at - 1
            } else {
                at
            };
            consider(&mut hits, &text[..left_end], &text[at + 1..], at + 1);
            offset = at + 1;
        }
    }
    if text.contains('+') {
        let bytes = text.as_bytes();
        let mut offset = 0;
        while let Some(rel) = text[offset..].find('+') {
            let at = offset + rel;
            if let Some((left_end, right_start)) = plus_gap(bytes, at) {
                consider(
                    &mut hits,
                    &text[..left_end],
                    &text[right_start..],
                    right_start,
                );
            }
            offset = at + 1;
        }
    }
    if text.contains('"') {
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'"' {
                if let Some(right_start) = json_next_value(bytes, index) {
                    consider(&mut hits, &text[..index], &text[right_start..], right_start);
                    index = right_start;
                    continue;
                }
            }
            index += 1;
        }
    }
    hits
}

fn push_pair(
    out: &mut Vec<BoundaryPart>,
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) {
    out.push(BoundaryPart {
        left: true,
        start: left_start,
        end: left_end,
        rule: SPLIT_RULE,
    });
    out.push(BoundaryPart {
        left: false,
        start: right_start,
        end: right_end,
        rule: SPLIT_RULE,
    });
}

fn consider(hits: &mut Vec<SecretHit>, left: &str, right: &str, right_base: usize) {
    for part in boundary_parts(left, right) {
        let (start, end) = if part.left {
            (part.start, part.end)
        } else {
            (right_base + part.start, right_base + part.end)
        };
        if hits.iter().any(|hit| hit.start == start && hit.end == end) {
            continue;
        }
        hits.push(SecretHit {
            start,
            end,
            rule: part.rule.to_string(),
        });
    }
}

fn access_key_boundary(left: &str, right: &str) -> Option<(usize, usize, usize, usize)> {
    let (left, right, right_off) = trimmed_sides(left, right);
    let (start, end) = ascii_suffix(left, is_akia)?;
    let (right_start, right_end) = ascii_prefix(right, is_akia)?;
    let left_len = end - start;
    let right_len = right_end - right_start;
    if left_len < 4 || right_len < 4 || left_len + right_len != 20 {
        return None;
    }
    if !left[start..end].starts_with("AKIA") {
        return None;
    }
    Some((start, end, right_off + right_start, right_off + right_end))
}

fn secret_boundary(left: &str, right: &str) -> Option<(usize, usize, usize, usize)> {
    let (left, right, right_off) = trimmed_sides(left, right);
    let (start, end) = ascii_suffix(left, is_secret_char)?;
    let (right_start, right_end) = ascii_prefix(right, is_secret_char)?;
    let left_len = end - start;
    let right_len = right_end - right_start;
    if left_len < 8 || right_len < 8 || left_len + right_len != 40 {
        return None;
    }
    let joined = format!("{}{}", &left[start..end], &right[right_start..right_end]);
    if !joined.contains('/') && !joined.contains('+') {
        return None;
    }
    if !joined.bytes().any(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !joined.bytes().any(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    Some((start, end, right_off + right_start, right_off + right_end))
}

fn trimmed_sides<'a>(left: &'a str, right: &'a str) -> (&'a str, &'a str, usize) {
    let left = left.trim_end_matches(|ch: char| ch.is_ascii_whitespace());
    let trimmed = right.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
    let right_off = right.len() - trimmed.len();
    (left, trimmed, right_off)
}

fn ascii_suffix(text: &str, class: fn(u8) -> bool) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut start = bytes.len();
    while start > 0 && class(bytes[start - 1]) {
        start -= 1;
    }
    if start == bytes.len() {
        None
    } else {
        Some((start, bytes.len()))
    }
}

fn ascii_prefix(text: &str, class: fn(u8) -> bool) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut end = 0;
    while end < bytes.len() && class(bytes[end]) {
        end += 1;
    }
    if end == 0 {
        None
    } else {
        Some((0, end))
    }
}

fn is_akia(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

fn is_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'=')
}

/// `"left" + "right"` or `'left' + 'right'`, with whitespace around `+`.
fn plus_gap(bytes: &[u8], plus: usize) -> Option<(usize, usize)> {
    let mut left_quote = plus;
    while left_quote > 0 && bytes[left_quote - 1].is_ascii_whitespace() {
        left_quote -= 1;
    }
    if left_quote == 0 {
        return None;
    }
    let quote = bytes[left_quote - 1];
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let mut right_quote = plus + 1;
    while right_quote < bytes.len() && bytes[right_quote].is_ascii_whitespace() {
        right_quote += 1;
    }
    if right_quote >= bytes.len() || bytes[right_quote] != quote {
        return None;
    }
    Some((left_quote - 1, right_quote + 1))
}

/// The next JSON string value after a closing quote: `"…","key":"…"`.
fn json_next_value(bytes: &[u8], closing_quote: usize) -> Option<usize> {
    let mut index = skip_ws(bytes, closing_quote + 1);
    if index >= bytes.len() || bytes[index] != b',' {
        return None;
    }
    index = skip_ws(bytes, index + 1);
    if index >= bytes.len() || bytes[index] != b'"' {
        return None;
    }
    index += 1;
    let key_start = index;
    while index < bytes.len() && is_key_char(bytes[index]) {
        index += 1;
    }
    if index == key_start || index >= bytes.len() || bytes[index] != b'"' {
        return None;
    }
    index = skip_ws(bytes, index + 1);
    if index >= bytes.len() || bytes[index] != b':' {
        return None;
    }
    index = skip_ws(bytes, index + 1);
    if index >= bytes.len() || bytes[index] != b'"' {
        return None;
    }
    Some(index + 1)
}

fn skip_ws(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn secret_value_at(bytes: &[u8], secret_at: usize) -> Option<(usize, usize)> {
    if secret_at > 0 && bytes[secret_at - 1].is_ascii_alphanumeric() {
        return None;
    }
    if let Some(end) = phrase_end(bytes, secret_at, &["secret", "access", "key"]) {
        if let Some(span) = value_after_label(bytes, end) {
            return Some(span);
        }
    }
    let aws = b"aws";
    let mut cursor = secret_at;
    while cursor > 0 && matches!(bytes[cursor - 1], b'_' | b'-' | b' ') {
        cursor -= 1;
    }
    if cursor >= aws.len()
        && starts_with_ignore_ascii(&bytes[cursor - aws.len()..], aws)
        && (cursor == aws.len() || !bytes[cursor - aws.len() - 1].is_ascii_alphanumeric())
    {
        return value_after_label(bytes, secret_at + "secret".len());
    }
    None
}

fn phrase_end(bytes: &[u8], mut index: usize, words: &[&str]) -> Option<usize> {
    for (place, word) in words.iter().enumerate() {
        if !starts_with_ignore_ascii(&bytes[index..], word.as_bytes()) {
            return None;
        }
        index += word.len();
        if place + 1 == words.len() {
            break;
        }
        while index < bytes.len() && matches!(bytes[index], b'_' | b'-' | b' ') {
            index += 1;
        }
    }
    Some(index)
}

fn starts_with_ignore_ascii(bytes: &[u8], word: &[u8]) -> bool {
    bytes.len() >= word.len()
        && bytes
            .iter()
            .zip(word)
            .all(|(byte, expected)| byte.to_ascii_lowercase() == *expected)
}

fn value_after_label(bytes: &[u8], mut index: usize) -> Option<(usize, usize)> {
    if index < bytes.len() && matches!(bytes[index], b'"' | b'\'') {
        index += 1;
    }
    index = skip_ws(bytes, index);
    if index >= bytes.len() || !matches!(bytes[index], b'=' | b':') {
        return None;
    }
    index += 1;
    index = skip_ws(bytes, index);
    if index < bytes.len() && matches!(bytes[index], b'"' | b'\'') {
        index += 1;
    }
    let start = index;
    let mut end = start;
    while end < bytes.len() && end - start < 40 && is_secret_char(bytes[end]) {
        end += 1;
    }
    if end - start != 40 {
        return None;
    }
    if end < bytes.len() && is_secret_char(bytes[end]) {
        return None;
    }
    Some((start, end))
}

fn is_key_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newline_and_plus_joins_are_hits_and_near_misses_stay() {
        let line = gap_hits("AKIALINEKEY0\nLINE9Q2W");
        assert_eq!(line.len(), 2, "{line:?}");
        let plus = gap_hits("code \"AKIAPLUSKEY0\" + \"PLUS9Q2W\" tail");
        assert_eq!(plus.len(), 2, "{plus:?}");
        let secret = gap_hits("wJalrXUtnFEMI/K7MDENG/xY\nbPxRfiCYLINE0001");
        assert_eq!(secret.len(), 2, "{secret:?}");
        let quoted = gap_hits("\"wJalrXUtnFEMI/K7MDENG/xY\" + \"bPxRfiCYPLUS0001\"");
        assert_eq!(quoted.len(), 2, "{quoted:?}");
        let fields = gap_hits(
            "{\"access_part_a\":\"AKIAJSONKEY0\",\"access_part_b\":\"JSON9Q2W\",\"secret_part_a\":\"wJalrXUtnFEMI/K7MDENG/xY\",\"secret_part_b\":\"bPxRfiCYJSON0001\"}",
        );
        assert_eq!(fields.len(), 4, "{fields:?}");

        assert!(gap_hits("\"AKIASVCNSPLIT\" + \"KEY001\"").is_empty());
        assert!(gap_hits("\"hello\" + \"world\"").is_empty());
        assert!(gap_hits("PLEASE\nNOTE").is_empty());
        assert!(
            gap_hits("da39a3ee5e6b4b0d3255bfef95601890afd80709\n0123456789abcdef0123").is_empty()
        );
        assert!(gap_hits("TOKEN_LIMIT=4096").is_empty());
        let labeled = labeled_secret_hits(
            "\"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/xYbPxRfiCYlabel001\"",
        );
        assert_eq!(labeled.len(), 1, "{labeled:?}");
        assert_eq!(
            &"\"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/xYbPxRfiCYlabel001\""
                [labeled[0].start..labeled[0].end],
            "wJalrXUtnFEMI/K7MDENG/xYbPxRfiCYlabel001"
        );
        assert!(labeled_secret_hits("sha da39a3ee5e6b4b0d3255bfef95601890afd80709").is_empty());
        assert_eq!(
            labeled_secret_hits("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/xYbPxRfiCYlabel001")
                .len(),
            1
        );
    }
}
