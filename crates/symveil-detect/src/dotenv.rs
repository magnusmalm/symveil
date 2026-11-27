//! Assignment values in dotenv-shaped text.
//!
//! The suffix rules (`env-assignment`, `env-quoted-assignment`) only match
//! uppercase names that end in `_KEY`, `_SECRET`, `_TOKEN`, `_PASSWORD`, or
//! `_PASS`. A `.env` file also holds passwords and session values under other
//! names. This pass redacts every assignment value, and only when the text
//! looks like a dotenv file or names a dotenv path.

use crate::secrets::{is_low_signal, SecretHit};

const RULE: &str = "dotenv-assignment";

/// Values of `KEY=VALUE` lines when `text` is a dotenv file, or when it names
/// a `.env` path and also contains an assignment.
///
/// A dotenv file is at least two assignment lines, and every other non-blank
/// line is a `#` comment. A leading `export`, one quote before the name,
/// quotes around the value, a trailing `#` comment, and a `cat -n` prefix
/// (`     1|` or `     1→`) are part of the line. Blank lines are ignored.
///
/// A path is `.env` or `.env.local` (and the other dotted suffixes) after
/// whitespace, a quote, or a path separator, or a filename that ends in
/// `.env` after `/` or `\`. `process.env` and `std::env` are not paths.
pub fn dotenv_assignment_hits(text: &str) -> Vec<SecretHit> {
    if !text.contains('=') {
        return Vec::new();
    }
    let path = mentions_dotenv_path(text);
    let mut assignments = Vec::new();
    let mut other = false;
    let mut offset = 0;
    for piece in text.split_inclusive('\n') {
        if other && !path {
            break;
        }
        let content = piece.strip_suffix('\n').unwrap_or(piece);
        let content = content.strip_suffix('\r').unwrap_or(content);
        let line_start = offset;
        offset += piece.len();
        match classify_line(content) {
            Line::Blank | Line::Comment => {}
            Line::Other => other = true,
            Line::Assignment(None) => assignments.push(None),
            Line::Assignment(Some((start, end))) => {
                assignments.push(Some((line_start + start, line_start + end)));
            }
        }
    }
    if other && !path {
        return Vec::new();
    }
    let file = !other && assignments.len() >= 2;
    if !file && !path {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for span in assignments.into_iter().flatten() {
        let value = &text[span.0..span.1];
        if is_low_signal(RULE, value) {
            continue;
        }
        hits.push(SecretHit {
            start: span.0,
            end: span.1,
            rule: RULE.to_string(),
        });
    }
    hits
}

enum Line {
    Blank,
    Comment,
    Other,
    /// Offsets of the value inside the line. `None` is an empty value.
    Assignment(Option<(usize, usize)>),
}

fn classify_line(line: &str) -> Line {
    let bytes = line.as_bytes();
    let mut i = strip_line_number(bytes);
    if i == 0 {
        i = skip_ws(bytes, 0);
    }
    if i >= bytes.len() {
        return Line::Blank;
    }
    if bytes[i] == b'#' {
        return Line::Comment;
    }
    if bytes[i..].starts_with(b"export") {
        let after = i + "export".len();
        if after < bytes.len() && matches!(bytes[after], b' ' | b'\t') {
            i = skip_ws(bytes, after);
        }
    }
    let mut quoted_name = false;
    if i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
        quoted_name = true;
        i += 1;
    }
    if i >= bytes.len() || !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        return Line::Other;
    }
    i += 1;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
        i += 1;
    }
    i = skip_ws(bytes, i);
    if i >= bytes.len() || bytes[i] != b'=' {
        return Line::Other;
    }
    i += 1;
    i = skip_ws(bytes, i);
    if i >= bytes.len() {
        return Line::Assignment(None);
    }
    let span = if bytes[i] == b'"' || bytes[i] == b'\'' {
        let quote = bytes[i];
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end] != quote {
            end += 1;
        }
        if end >= bytes.len() {
            return Line::Other;
        }
        (start, end)
    } else {
        let start = i;
        let mut end = i;
        while end < bytes.len() && bytes[end] != b'#' {
            end += 1;
        }
        while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        if quoted_name && end > start && matches!(bytes[end - 1], b'"' | b'\'') {
            end -= 1;
        }
        (start, end)
    };
    if span.0 == span.1 {
        Line::Assignment(None)
    } else {
        Line::Assignment(Some(span))
    }
}

/// Byte offset just after a `     1|` or `     1→` prefix. Zero when absent.
fn strip_line_number(bytes: &[u8]) -> usize {
    let mut i = skip_ws(bytes, 0);
    let digits = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == digits {
        return 0;
    }
    i = skip_ws(bytes, i);
    let marker = if i < bytes.len() && bytes[i] == b'|' {
        1
    } else if bytes
        .get(i..)
        .is_some_and(|rest| rest.starts_with("→".as_bytes()))
    {
        "→".len()
    } else {
        return 0;
    };
    skip_ws(bytes, i + marker)
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    i
}

fn mentions_dotenv_path(text: &str) -> bool {
    if !text.contains(".env") {
        return false;
    }
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(rel) = find_dot_env(&bytes[i..]) {
        let at = i + rel;
        if dotenv_path_at(bytes, at) {
            return true;
        }
        i = at + 1;
    }
    false
}

fn find_dot_env(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b".env")
}

fn dotenv_path_at(bytes: &[u8], at: usize) -> bool {
    if !dotenv_suffix_boundary(bytes, at + 4) {
        return false;
    }
    if path_prev_ok(bytes, at) {
        return true;
    }
    // `configs/fan.env`: the `.env` is glued to a filename after a separator.
    let mut j = at;
    while j > 0 {
        let prev = bytes[j - 1];
        if prev.is_ascii_alphanumeric() || matches!(prev, b'_' | b'-' | b'.') {
            j -= 1;
            continue;
        }
        return matches!(prev, b'/' | b'\\');
    }
    false
}

fn path_prev_ok(bytes: &[u8], at: usize) -> bool {
    if at == 0 {
        return true;
    }
    matches!(
        bytes[at - 1],
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b'/'
            | b'\\'
            | b'"'
            | b'\''
            | b'`'
            | b'('
            | b'['
            | b'{'
            | b'='
            | b':'
    )
}

fn dotenv_suffix_boundary(bytes: &[u8], mut i: usize) -> bool {
    if i >= bytes.len() {
        return true;
    }
    if bytes[i] == b'.' {
        i += 1;
        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
        {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    i >= bytes.len() || !bytes[i].is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_env_is_not_a_dotenv_path() {
        assert!(!mentions_dotenv_path("const mode = process.env.NODE_ENV"));
        assert!(!mentions_dotenv_path("std::env::var(\"PATH\")"));
        assert!(!mentions_dotenv_path("see foo.env in the notes"));
        assert!(mentions_dotenv_path("Read /repo/.env"));
        assert!(mentions_dotenv_path("file .env.local"));
        assert!(mentions_dotenv_path("configs/fan.env"));
        assert!(mentions_dotenv_path("configs\\fan.env"));
    }

    #[test]
    fn a_pure_file_redacts_every_value_and_keeps_low_signal() {
        let text = "\
# synthetic
export OPENAI_API_KEY=sk-Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1
PGPASSWORD=\"n0t-a-token-db-pass\"
SESSION_COOKIE='s3ssion-value-9f3a'
TOKEN_LIMIT=4096
API_KEY=changeme
";
        let hits = dotenv_assignment_hits(text);
        let values: Vec<&str> = hits.iter().map(|hit| &text[hit.start..hit.end]).collect();
        assert!(values.iter().any(|value| value.starts_with("sk-")));
        assert!(values.contains(&"n0t-a-token-db-pass"));
        assert!(values.contains(&"s3ssion-value-9f3a"));
        assert!(!values.contains(&"4096"));
        assert!(!values.contains(&"changeme"));
        assert!(hits.iter().all(|hit| hit.rule == "dotenv-assignment"));
    }

    #[test]
    fn numbered_read_output_is_still_a_file() {
        let text = "\
     1|# synthetic
     2|PGPASSWORD=n0t-a-token-db-pass
     3|SESSION_COOKIE=s3ssion-value-9f3a
";
        let hits = dotenv_assignment_hits(text);
        assert_eq!(hits.len(), 2);
        assert_eq!(&text[hits[0].start..hits[0].end], "n0t-a-token-db-pass");
    }

    #[test]
    fn one_assignment_in_prose_is_not_a_file() {
        let text =
            "connect with DATABASE_URL=postgres://app:db-url-password@db.internal.example/app\n";
        assert!(dotenv_assignment_hits(text).is_empty());
    }

    #[test]
    fn a_named_path_redacts_assignments_in_the_same_text() {
        let text = "\
contents of /repo/.env:
PGPASSWORD=n0t-a-token-db-pass
fn main() {}
";
        let hits = dotenv_assignment_hits(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(&text[hits[0].start..hits[0].end], "n0t-a-token-db-pass");
    }

    #[test]
    fn ordinary_code_is_left_alone() {
        let text = "\
fn main() {
    let session = \"s3ssion-value-9f3a\";
    println!(\"{session}\");
}
";
        assert!(dotenv_assignment_hits(text).is_empty());
        let with_process = "\
const mode = process.env.NODE_ENV;
SESSION_COOKIE=s3ssion-value-9f3a
";
        assert!(dotenv_assignment_hits(with_process).is_empty());
    }
}
