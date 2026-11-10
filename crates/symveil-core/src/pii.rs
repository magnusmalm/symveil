//! Opt-in detectors for email addresses, phone numbers, and Swedish
//! personnummer / samordningsnummer.
//!
//! Nothing here runs unless [`PiiSection`](crate::config::PiiSection) enables a
//! rule. Person names are out of scope: they need a model, not a regex.
//!
//! Lookalikes are rejected by shape:
//! - an identity number must be a possible calendar day (day 61–91 is a
//!   samordningsnummer) and pass Luhn on its 10-digit payload
//! - a phone is E.164 (`+…`) or a Swedish national number; a `.` ends the
//!   match, so version strings are not phones
//! - an email needs a dotted domain whose last label is letters, and
//!   `user@host:path` is kept as an ssh/scp remote

use std::sync::LazyLock;

use regex::Regex;

use crate::category::Category;
use crate::config::PiiSection;
use crate::masker::{Boundary, Candidate, Masker, PRI_PATTERN, PRI_SECRET};

pub struct PiiMasker {
    email: bool,
    phone: bool,
    personnummer: bool,
}

impl PiiMasker {
    pub(crate) fn compile(pii: &PiiSection) -> Self {
        Self {
            email: pii.email,
            phone: pii.phone,
            personnummer: pii.personnummer,
        }
    }
}

impl Masker for PiiMasker {
    fn name(&self) -> &'static str {
        "pii"
    }

    fn collect(&self, text: &str) -> Vec<Candidate> {
        let mut out = Vec::new();
        if self.personnummer {
            collect_personnummer(text, &mut out);
        }
        if self.phone {
            collect_phones(text, &mut out);
        }
        if self.email {
            collect_emails(text, &mut out);
        }
        out
    }
}

fn candidate(start: usize, end: usize, rule: &str, priority: u8) -> Candidate {
    Candidate {
        start,
        end,
        category: Category::Pii,
        rule: Some(rule.to_string()),
        priority,
        boundary: Boundary::Ident,
    }
}

// Longer forms are listed first. `regex` is leftmost-first, so a 12-digit run
// must win over the 10-digit alternative at the same index.
const PERSONNUMMER_PATTERN: &str = r"\d{12}|\d{8}[+\-]\d{4}|\d{10}|\d{6}[+\-]\d{4}";

static PERSONNUMMER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(PERSONNUMMER_PATTERN).expect("personnummer regex"));

fn collect_personnummer(text: &str, out: &mut Vec<Candidate>) {
    for matched in PERSONNUMMER.find_iter(text) {
        if !separated_edge(text, matched.start(), matched.end()) {
            continue;
        }
        let Some(rule) = personnummer_rule(matched.as_str()) else {
            continue;
        };
        // Higher than a phone so a 10-digit mobile that also passes Luhn is
        // recorded as an identity number.
        out.push(candidate(matched.start(), matched.end(), rule, PRI_SECRET));
    }
}

fn personnummer_rule(raw: &str) -> Option<&'static str> {
    let digits = digit_values(raw);
    let (year, ten) = match digits.len() {
        12 => {
            let year = u32::from(digits[0]) * 1000
                + u32::from(digits[1]) * 100
                + u32::from(digits[2]) * 10
                + u32::from(digits[3]);
            if !(1800..=2099).contains(&year) {
                return None;
            }
            (Some(year), digits[2..].to_vec())
        }
        10 => (None, digits),
        _ => return None,
    };
    if !luhn_ok(&ten) {
        return None;
    }
    let month = ten[2] * 10 + ten[3];
    let day_field = ten[4] * 10 + ten[5];
    let day = if (1..=31).contains(&day_field) {
        day_field
    } else if (61..=91).contains(&day_field) {
        day_field - 60
    } else {
        return None;
    };
    if !valid_day(year, ten[0] * 10 + ten[1], month, day) {
        return None;
    }
    Some(if day_field >= 61 {
        "samordningsnummer"
    } else {
        "personnummer"
    })
}

fn valid_day(year: Option<u32>, yy: u8, month: u8, day: u8) -> bool {
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if day == 0 || day > 29 {
                return false;
            }
            if day <= 28 {
                return true;
            }
            return feb29_ok(year, yy);
        }
        _ => return false,
    };
    (1..=max).contains(&day)
}

/// February 29 is accepted for a 12-digit year only when that year is a leap
/// year. A 10-digit year has no century, so it is accepted when any year
/// 1800–2099 with that `YY` is a leap year.
fn feb29_ok(year: Option<u32>, yy: u8) -> bool {
    match year {
        Some(year) => is_leap(year),
        None => [1800, 1900, 2000]
            .into_iter()
            .any(|base| is_leap(base + u32::from(yy))),
    }
}

fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn luhn_ok(digits: &[u8]) -> bool {
    if digits.len() != 10 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(index, &digit)| luhn_addend(index, digit))
        .sum();
    sum.is_multiple_of(10)
}

fn luhn_addend(index: usize, digit: u8) -> u32 {
    let mut value = u32::from(digit);
    if index.is_multiple_of(2) {
        value *= 2;
        if value > 9 {
            value -= 9;
        }
    }
    value
}

fn digit_values(raw: &str) -> Vec<u8> {
    raw.bytes()
        .filter(|byte| byte.is_ascii_digit())
        .map(|byte| byte - b'0')
        .collect()
}

fn collect_phones(text: &str, out: &mut Vec<Candidate>) {
    let mut index = 0;
    while index < text.len() {
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        let len = ch.len_utf8();
        if matches!(ch, '+' | '0' | '(') {
            if let Some((end, rule)) = phone_at(text, index) {
                if separated_edge(text, index, end) {
                    out.push(candidate(index, end, rule, PRI_PATTERN));
                }
                index = end;
                continue;
            }
        }
        index += len;
    }
}

fn phone_at(text: &str, start: usize) -> Option<(usize, &'static str)> {
    // Only the character before the number is a lead-in. The number's own
    // `+`, `0`, or `(` sits at `start` and is part of the match.
    if !left_separated(text, start) {
        return None;
    }
    let bytes = text.as_bytes();
    let taken = take_number(text, start)?;
    if bytes.get(start) == Some(&b'+') {
        return e164_ok(&taken).then_some((taken.end, "phone-e164"));
    }
    if bytes.get(start) == Some(&b'0') && bytes.get(start + 1) == Some(&b'0') {
        return idd_ok(&taken).then_some((taken.end, "phone-e164"));
    }
    if starts_swedish(bytes, start) {
        return swedish_ok(text, &taken).then_some((taken.end, "phone-se"));
    }
    None
}

fn starts_swedish(bytes: &[u8], start: usize) -> bool {
    if bytes.get(start) == Some(&b'0') {
        return matches!(bytes.get(start + 1), Some(b'1'..=b'9'));
    }
    // `(070) …`
    if bytes.get(start) != Some(&b'(') {
        return false;
    }
    matches!(bytes.get(start + 1), Some(b'0'))
}

struct Taken {
    start: usize,
    end: usize,
    digits: Vec<u8>,
    seps: u32,
}

struct Group {
    values: Vec<u8>,
    end: usize,
    /// Another phone group follows this one.
    continues: bool,
}

fn take_number(text: &str, start: usize) -> Option<Taken> {
    let bytes = text.as_bytes();
    let mut index = start;
    if bytes.get(index) == Some(&b'+') {
        index += 1;
    }
    let first = read_group(bytes, index)?;
    // No separator: one run, as in `+46700000000` or `0700000000`. A longer
    // run that is itself a valid length and is followed by another number
    // keeps only the compact run.
    if !first.continues || first.values.len() > 4 {
        let len = first.values.len();
        let compact = if first.continues {
            (8..=15).contains(&len)
        } else {
            (1..=15).contains(&len)
        };
        if !compact {
            return None;
        }
        return Some(Taken {
            start,
            end: first.end,
            digits: first.values,
            seps: 0,
        });
    }
    let mut digits = first.values;
    index = first.end;
    let mut seps = 0u32;
    while let Some((counted_sep, group)) = next_group(bytes, index) {
        if !grouped_len_ok(group.values.len(), group.continues)
            || digits.len() + group.values.len() > 18
        {
            break;
        }
        if counted_sep {
            seps += 1;
        }
        index = group.end;
        digits.extend(group.values);
    }
    if digits.is_empty() {
        return None;
    }
    Some(Taken {
        start,
        end: index,
        digits,
        seps,
    })
}

/// Grouped numbers use chunks of at most 4 digits (`+46 70 000 00 00`).
/// The last chunk may be up to 8 (`08-12345678`, `070-0000000`). A following
/// personnummer (`00 20990101-9993`) is not a phone chunk, so the match stops
/// before it.
fn grouped_len_ok(len: usize, continues: bool) -> bool {
    let max = if continues { 4 } else { 8 };
    (1..=max).contains(&len)
}

fn next_group(bytes: &[u8], index: usize) -> Option<(bool, Group)> {
    match bytes.get(index).copied() {
        Some(b' ' | b'-') => {
            let group = read_group(bytes, index + 1)?;
            Some((true, group))
        }
        Some(b'(') | Some(b'0'..=b'9') => read_group(bytes, index).map(|group| (false, group)),
        _ => None,
    }
}

fn read_group(bytes: &[u8], start: usize) -> Option<Group> {
    if bytes.get(start) == Some(&b'(') {
        let (end, values) = paren_group(bytes, start)?;
        return Some(Group {
            values,
            end,
            continues: group_continues(bytes, end),
        });
    }
    let mut end = start;
    let mut values = Vec::new();
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        values.push(bytes[end] - b'0');
        end += 1;
    }
    if values.is_empty() {
        return None;
    }
    Some(Group {
        values,
        end,
        continues: group_continues(bytes, end),
    })
}

fn group_continues(bytes: &[u8], end: usize) -> bool {
    match bytes.get(end).copied() {
        Some(b'0'..=b'9' | b'(') => true,
        Some(b' ' | b'-') => matches!(bytes.get(end + 1), Some(b'0'..=b'9' | b'(')),
        _ => false,
    }
}

fn paren_group(bytes: &[u8], open: usize) -> Option<(usize, Vec<u8>)> {
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut index = open + 1;
    let mut group = Vec::new();
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        group.push(bytes[index] - b'0');
        index += 1;
        if group.len() > 4 {
            return None;
        }
    }
    if group.is_empty() || bytes.get(index) != Some(&b')') {
        return None;
    }
    Some((index + 1, group))
}

fn e164_ok(taken: &Taken) -> bool {
    (8..=15).contains(&taken.digits.len()) && taken.digits.first().is_some_and(|digit| *digit != 0)
}

fn idd_ok(taken: &Taken) -> bool {
    // Compact `0046…` collides with order numbers. Require a separator.
    if taken.seps == 0 || taken.digits.len() < 10 {
        return false;
    }
    if taken.digits[0] != 0 || taken.digits[1] != 0 || taken.digits[2] == 0 {
        return false;
    }
    let national = taken.digits.len() - 2;
    (8..=15).contains(&national)
}

fn swedish_ok(text: &str, taken: &Taken) -> bool {
    let digits = &taken.digits;
    if digits.len() < 2 || digits[0] != 0 || digits[1] == 0 {
        return false;
    }
    let raw = &text[taken.start..taken.end];
    if date_like(raw) {
        return false;
    }
    if digits[1] == 7 {
        return digits.len() == 10;
    }
    taken.seps > 0 && (8..=10).contains(&digits.len())
}

fn date_like(raw: &str) -> bool {
    if raw
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || ch == '(' || ch == ')')
    {
        return false;
    }
    let parts: Vec<&str> = raw.split(['-', '/']).collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let (left, mid, right) = (parts[0].len(), parts[1].len(), parts[2].len());
    matches!(
        (left, mid, right),
        (4, 1 | 2, 1 | 2) | (1 | 2, 1 | 2, 4) | (2, 2, 2)
    )
}

// Local part at most 64 chars, domain labels cannot start or end with `-`,
// and the final label is letters so `user@10.1.2.3` is not an email.
const EMAIL_PATTERN: &str = r"(?i-u)[a-z0-9](?:[a-z0-9._%+\-]{0,62}[a-z0-9])?@[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}";

static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(EMAIL_PATTERN).expect("email regex"));

fn collect_emails(text: &str, out: &mut Vec<Candidate>) {
    for matched in EMAIL.find_iter(text) {
        let raw = matched.as_str();
        if raw.len() > 254 || raw.contains("..") {
            continue;
        }
        let start = matched.start();
        let end = matched.end();
        if !ident_edge(text, start, end) || scp_remote(text, end) {
            continue;
        }
        out.push(candidate(start, end, "email", PRI_PATTERN));
    }
}

/// `git@github.com:org/repo` is an ssh remote. `user@example.com:8080` is not:
/// a colon followed by a port stays an email plus a port.
fn scp_remote(text: &str, end: usize) -> bool {
    let mut chars = text[end..].chars();
    if chars.next() != Some(':') {
        return false;
    }
    matches!(
        chars.next(),
        Some(ch) if ch.is_ascii_alphabetic() || ch == '/' || ch == '~'
    )
}

fn ident_edge(text: &str, start: usize, end: usize) -> bool {
    edge_ok(text, start, end, |ch| {
        ch.is_ascii_alphanumeric() || ch == '_'
    })
}

/// Digit runs glued to an identifier, a hyphen, or a plus are order numbers
/// and version tags (`ORD-20990101-9993`, `v209901019993`), not personal data.
fn separated_edge(text: &str, start: usize, end: usize) -> bool {
    edge_ok(text, start, end, token_glue)
}

fn left_separated(text: &str, start: usize) -> bool {
    if !text.is_char_boundary(start) {
        return false;
    }
    start == 0 || !text[..start].chars().next_back().is_some_and(token_glue)
}

fn token_glue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+')
}

fn edge_ok(text: &str, start: usize, end: usize, bad: impl Fn(char) -> bool) -> bool {
    if end > text.len() || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return false;
    }
    let left = start == 0 || !text[..start].chars().next_back().is_some_and(&bad);
    let right = end == text.len() || !text[end..].chars().next().is_some_and(&bad);
    left && right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactSection;
    use crate::redact::Engine;
    use crate::vault::Vault;

    fn engine(pii: PiiSection) -> Engine {
        Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                internal_domains: Vec::new(),
                pii,
                ..RedactSection::default()
            },
        )
        .unwrap()
    }

    fn all_on() -> Engine {
        engine(PiiSection {
            email: true,
            phone: true,
            personnummer: true,
        })
    }

    fn rules(text: &str) -> Vec<String> {
        let mut engine = all_on();
        let (out, hits) = engine.redact_str(text).unwrap();
        assert_eq!(
            engine.restore_str(&out),
            text,
            "restore {text:?} from {out:?}"
        );
        hits.into_iter().filter_map(|hit| hit.rule).collect()
    }

    fn assert_rules(text: &str, expected: &[&str]) {
        assert_eq!(rules(text), expected, "{text}");
    }

    fn check_digit(first9: &str) -> char {
        assert_eq!(first9.len(), 9, "{first9}");
        let digits: Vec<u8> = first9.bytes().map(|byte| byte - b'0').collect();
        let sum: u32 = digits
            .iter()
            .enumerate()
            .map(|(index, &digit)| luhn_addend(index, digit))
            .sum();
        let check = (10 - (sum % 10)) % 10;
        char::from(b'0' + u8::try_from(check).unwrap())
    }

    fn pn10(yymmdd: &str, serial: &str, sep: &str) -> String {
        assert_eq!(yymmdd.len(), 6);
        assert_eq!(serial.len(), 3);
        let check = check_digit(&format!("{yymmdd}{serial}"));
        if sep.is_empty() {
            format!("{yymmdd}{serial}{check}")
        } else {
            format!("{yymmdd}{sep}{serial}{check}")
        }
    }

    fn pn12(yyyymmdd: &str, serial: &str, sep: &str) -> String {
        assert_eq!(yyyymmdd.len(), 8);
        assert_eq!(serial.len(), 3);
        let check = check_digit(&format!("{}{serial}", &yyyymmdd[2..]));
        if sep.is_empty() {
            format!("{yyyymmdd}{serial}{check}")
        } else {
            format!("{yyyymmdd}{sep}{serial}{check}")
        }
    }

    #[test]
    fn synthetic_checksum_fixtures() {
        // Year 2099 is not a person in any register. The check digit is real,
        // so the rule matches; the number is not an issued identity.
        assert_eq!(pn12("20990101", "999", "-"), "20990101-9993");
        assert_eq!(pn12("20990101", "999", ""), "209901019993");
        assert_eq!(pn12("20990101", "999", "+"), "20990101+9993");
        assert_eq!(pn10("990101", "999", "-"), "990101-9993");
        assert_eq!(pn10("990101", "999", "+"), "990101+9993");
        assert_eq!(pn10("990101", "999", ""), "9901019993");
        // Day 61 = 1 January, the samordningsnummer form of the same date.
        assert_eq!(pn12("20990161", "999", "-"), "20990161-9990");
        assert_eq!(pn10("990161", "999", "-"), "990161-9990");
        assert_eq!(pn10("990161", "999", "+"), "990161+9990");
        assert_eq!(pn10("990161", "999", ""), "9901619990");
        assert_eq!(pn12("20990229", "123", "-"), "20990229-1237");
        assert_eq!(pn10("990229", "123", "-"), "990229-1237");
    }

    #[test]
    fn personnummer_and_samordningsnummer_forms() {
        for sep in ["-", "+", ""] {
            assert_rules(&pn12("20990101", "999", sep), &["personnummer"]);
            assert_rules(&pn10("990101", "999", sep), &["personnummer"]);
            assert_rules(&pn12("20990161", "999", sep), &["samordningsnummer"]);
            assert_rules(&pn10("990161", "999", sep), &["samordningsnummer"]);
        }
        assert_rules(&pn12("20000229", "999", "-"), &["personnummer"]);
        let bad = "20990101-9994";
        assert_ne!(bad, pn12("20990101", "999", "-"));
        assert_rules(bad, &[]);
        assert_rules("20990229-1237", &[]);
        assert_rules("990229-1237", &[]);
        assert_rules(&pn12("20990431", "999", "-"), &[]);
    }

    #[test]
    fn identity_numbers_skip_dates_orders_versions_and_shas() {
        for keeper in [
            "2024-11-10",
            "1990-01-01",
            "2000-02-29",
            "08-12-2024",
            "20990101",
            "123456789012",
            "202411100000",
            "100200300400",
            "ORD-20990101-9993",
            "v209901019993",
            "1.2.3",
            "v0.1.0",
            "+1.2.3",
            "symveil-0.1.0",
            "2024.11.10",
            "a1b2c3d4e5f6789012345678901234567890abcd",
            "20990101 - 9993",
        ] {
            assert_rules(keeper, &[]);
        }
    }

    #[test]
    fn phones_cover_e164_and_swedish_formats() {
        for value in [
            "+46700000000",
            "+46 70 000 00 00",
            "+46-70-000-00-00",
            "+46 (0) 70 000 00 00",
            "+46(0)70-0000000",
            "0046 70 000 00 00",
            "+1 202 555 0100",
            "+12025550100",
        ] {
            assert_rules(value, &["phone-e164"]);
        }
        assert_rules("0700000000", &["phone-se"]);
        assert_rules("070-000 00 00", &["phone-se"]);
        assert_rules("070 000 00 00", &["phone-se"]);
        assert_rules("(070) 000 00 00", &["phone-se"]);
        assert_rules("08-12345678", &["phone-se"]);
        assert_rules("070-0000000", &["phone-se"]);
        assert_rules(
            "+46 70 000 00 00 20990101-9993",
            &["phone-e164", "personnummer"],
        );
        assert_rules("08-123 456 78", &["phone-se"]);
        assert_rules("08 123 456 78", &["phone-se"]);
        assert_rules("031-12 34 56", &["phone-se"]);
    }

    #[test]
    fn phones_skip_versions_dates_and_order_numbers() {
        for keeper in [
            "1.2.3",
            "v0.1.0",
            "+1.2.3",
            "symveil-0.1.0",
            "2024.11.10",
            "+1.202.555.0100",
            "+46.70.000.00.00",
            "2024-11-10",
            "1990-01-01",
            "08-12-2024",
            "123456789012",
            "202411100000",
            "0123456789",
            "0812345678",
            "0046700000000",
            "070123456789",
            "ORD-0700000000",
            "10:30",
            "08:30",
            "born 08-12-2024 today",
            "release 1.2.3 is out",
        ] {
            assert_rules(keeper, &[]);
        }
    }

    #[test]
    fn emails_keep_ssh_forms() {
        assert_rules("ada@example.com", &["email"]);
        assert_rules("Ada.Lovelace+tag@example.com", &["email"]);
        assert_rules("dev@example.co.uk", &["email"]);
        // No colon: this is the same shape as a mailbox, so it is masked.
        assert_rules("git@github.com", &["email"]);
        // A dotted host is masked. A single label is not.
        assert_rules("user@box.local", &["email"]);
        for keeper in [
            "user@host",
            "ssh user@host",
            "user@localhost",
            "git@github.com:acme/widgets.git",
            "ssh://user@host",
            "user@127.0.0.1",
        ] {
            assert_rules(keeper, &[]);
        }
        let dotted_ip = rules("ssh user@10.8.0.14");
        assert_eq!(dotted_ip, vec!["ipv4".to_string()]);
    }

    #[test]
    fn flags_are_independent_and_off_by_default() {
        let sample = "ada@example.com +46 70 000 00 00 20990101-9993";
        let mut off = engine(PiiSection::default());
        let (out, hits) = off.redact_str(sample).unwrap();
        assert!(hits.is_empty());
        assert_eq!(out, sample);

        let mut email_only = engine(PiiSection {
            email: true,
            ..PiiSection::default()
        });
        let (out, hits) = email_only.redact_str(sample).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.as_deref(), Some("email"));
        assert!(out.contains("+46 70 000 00 00"));
        assert!(out.contains("20990101-9993"));
        assert!(!out.contains("ada@example.com"));

        let mut phone_only = engine(PiiSection {
            phone: true,
            ..PiiSection::default()
        });
        let (out, hits) = phone_only.redact_str(sample).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.as_deref(), Some("phone-e164"));
        assert!(out.contains("ada@example.com"));
        assert!(out.contains("20990101-9993"));
        assert!(!out.contains("+46 70 000 00 00"));

        let mut id_only = engine(PiiSection {
            personnummer: true,
            ..PiiSection::default()
        });
        let (out, hits) = id_only.redact_str(sample).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.as_deref(), Some("personnummer"));
        assert_eq!(hits[0].category, Category::Pii);
        assert!(out.contains("ada@example.com"));
        assert!(out.contains("+46 70 000 00 00"));
    }

    #[test]
    fn allow_list_does_not_exempt_personal_data() {
        let mut engine = Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                allow: vec!["ada@example.com".into()],
                internal_domains: Vec::new(),
                pii: PiiSection {
                    email: true,
                    ..PiiSection::default()
                },
                ..RedactSection::default()
            },
        )
        .unwrap();
        let (out, hits) = engine.redact_str("mail ada@example.com").unwrap();
        assert!(!out.contains("ada@example.com"), "{out}");
        assert_eq!(hits[0].category, Category::Pii);
        assert_eq!(engine.restore_str(&out), "mail ada@example.com");
    }

    #[test]
    fn mixed_text_round_trips_and_keeps_punctuation() {
        let input = "Mail ada@example.com. Call +46 70 000 00 00 or 08-123 456 78 about 20990101-9993, not 20990101-9994, user@host, or 1.2.3.";
        let mut engine = all_on();
        let (out, hits) = engine.redact_str(input).unwrap();
        assert!(hits.iter().all(|hit| hit.category == Category::Pii));
        for secret in [
            "ada@example.com",
            "+46 70 000 00 00",
            "08-123 456 78",
            "20990101-9993",
        ] {
            assert!(!out.contains(secret), "{secret} in {out}");
        }
        for kept in ["20990101-9994", "user@host", "1.2.3"] {
            assert!(out.contains(kept), "{kept} missing from {out}");
        }
        assert!(out.contains("Mail "));
        assert!(out.contains(". Call "));
        assert_eq!(engine.restore_str(&out), input);
    }

    #[test]
    fn pii_does_not_disturb_secrets_or_addresses() {
        let mut engine = all_on();
        let input = "key AKIAIOSFODNN7EXAMPLE mail ada@example.com host 10.8.0.14 keep 127.0.0.1";
        let (out, hits) = engine.redact_str(input).unwrap();
        assert!(hits.iter().any(|hit| hit.category == Category::Secret));
        assert!(hits.iter().any(|hit| hit.category == Category::Pii));
        assert!(hits.iter().any(|hit| hit.category == Category::Ip));
        assert!(out.contains("127.0.0.1"));
        assert!(!out.contains("AKIA"));
        assert!(!out.contains("ada@example.com"));
        assert!(!out.contains("10.8.0.14"));
        assert_eq!(engine.restore_str(&out), input);
    }
}
