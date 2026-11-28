//! Direct reader for the `learned.toml` shape `to_toml` writes.
//!
//! `toml::from_str` builds a document tree before serde sees it. At a few
//! hundred thousand tables that tree is most of the load. This reader accepts
//! the written document, comments, basic and literal strings, and string
//! arrays. A construct it does not know returns [`Reject::Unsupported`] and
//! the caller uses the toml crate.

use anyhow::Error;

use crate::learned::{DecisionRecord, LearnedAllow, LearnedFile, LearnedNames, LearnedRule};

#[derive(Debug)]
pub enum Reject {
    Unsupported,
    Invalid(Error),
}

enum Section {
    Root,
    Names,
    Allow,
    Secret,
    Symbol,
    Decision,
}

enum Open {
    None,
    Secret(LearnedRule),
    Symbol(LearnedRule),
    Decision(DecisionRecord),
}

enum Header {
    Names,
    Allow,
    Secrets,
    Symbols,
    Decisions,
}

enum Value {
    String(String),
    Int(u32),
    Strings(Vec<String>),
}

struct Parser<'a> {
    text: &'a str,
    index: usize,
    file: LearnedFile,
    section: Section,
    seen: u8,
    names_done: bool,
    allow_done: bool,
    open: Open,
}

pub fn try_parse(text: &str) -> Result<LearnedFile, Reject> {
    if text.starts_with('\u{feff}') {
        return Err(Reject::Unsupported);
    }
    let mut parser = Parser {
        text,
        index: 0,
        file: LearnedFile {
            version: 1,
            names: LearnedNames::default(),
            secrets: Vec::new(),
            symbols: Vec::new(),
            allow: LearnedAllow::default(),
            decisions: Vec::new(),
        },
        section: Section::Root,
        seen: 0,
        names_done: false,
        allow_done: false,
        open: Open::None,
    };
    parser.document()?;
    parser.flush()?;
    Ok(parser.file)
}

impl<'a> Parser<'a> {
    fn document(&mut self) -> Result<(), Reject> {
        loop {
            let before = self.index;
            self.skip();
            if self.index >= self.text.len() {
                return Ok(());
            }
            if self.eat(b'[') {
                self.header()?;
            } else {
                self.assignment()?;
            }
            if self.index == before {
                return Err(Reject::Unsupported);
            }
        }
    }

    fn header(&mut self) -> Result<(), Reject> {
        let array = self.eat(b'[');
        self.skip_inline();
        let name_start = self.index;
        self.bare_key()?;
        let name_end = self.index;
        self.skip_inline();
        if self.text.as_bytes().get(self.index) == Some(&b'.') {
            return Err(Reject::Unsupported);
        }
        let closed = if array {
            self.eat(b']') && self.eat(b']')
        } else {
            self.eat(b']')
        };
        if !closed {
            return Err(Reject::Unsupported);
        }
        let name = &self.text[name_start..name_end];
        let header = match (array, name) {
            (false, "names") => Header::Names,
            (false, "allow") => Header::Allow,
            (true, "secrets") => Header::Secrets,
            (true, "symbols") => Header::Symbols,
            (true, "decisions") => Header::Decisions,
            _ => {
                return Err(Reject::Invalid(Error::msg(format!(
                    "learned.toml table `{name}` is not supported"
                ))));
            }
        };
        self.apply_header(header)
    }

    fn apply_header(&mut self, header: Header) -> Result<(), Reject> {
        self.flush()?;
        self.seen = 0;
        match header {
            Header::Names => {
                if self.names_done {
                    return Err(Reject::Invalid(Error::msg(
                        "learned.toml table `names` is repeated",
                    )));
                }
                self.names_done = true;
                self.section = Section::Names;
                self.open = Open::None;
            }
            Header::Allow => {
                if self.allow_done {
                    return Err(Reject::Invalid(Error::msg(
                        "learned.toml table `allow` is repeated",
                    )));
                }
                self.allow_done = true;
                self.section = Section::Allow;
                self.open = Open::None;
            }
            Header::Secrets => {
                self.section = Section::Secret;
                self.open = Open::Secret(LearnedRule {
                    name: String::new(),
                    regex: String::new(),
                });
            }
            Header::Symbols => {
                self.section = Section::Symbol;
                self.open = Open::Symbol(LearnedRule {
                    name: String::new(),
                    regex: String::new(),
                });
            }
            Header::Decisions => {
                self.section = Section::Decision;
                self.open = Open::Decision(DecisionRecord {
                    key: String::new(),
                    action: String::new(),
                    category: String::new(),
                    text: String::new(),
                });
            }
        }
        Ok(())
    }

    fn assignment(&mut self) -> Result<(), Reject> {
        let key_start = self.index;
        self.bare_key()?;
        let key_end = self.index;
        let key_len = key_end - key_start;
        // Keys in this file are short (`category` is the longest). Copying
        // avoids holding a borrow of the document across `store`.
        if key_len > 32 {
            return Err(Reject::Unsupported);
        }
        let mut key_buf = [0u8; 32];
        key_buf[..key_len].copy_from_slice(&self.text.as_bytes()[key_start..key_end]);
        self.skip();
        if !self.eat(b'=') {
            return Err(Reject::Unsupported);
        }
        self.skip();
        let value = self.value()?;
        let key = std::str::from_utf8(&key_buf[..key_len]).map_err(|_| Reject::Unsupported)?;
        self.store(key, value)
    }

    fn store(&mut self, key: &str, value: Value) -> Result<(), Reject> {
        let bit = match (&self.section, key) {
            (Section::Root, "version") => 1,
            (Section::Names, "terms") => 1,
            (Section::Names, "people") => 2,
            (Section::Allow, "entries") => 1,
            (Section::Secret | Section::Symbol, "name") => 1,
            (Section::Secret | Section::Symbol, "regex") => 2,
            (Section::Decision, "key") => 1,
            (Section::Decision, "action") => 2,
            (Section::Decision, "category") => 4,
            (Section::Decision, "text") => 8,
            _ => return Err(Reject::Unsupported),
        };
        if self.seen & bit != 0 {
            return Err(Reject::Invalid(Error::msg(format!(
                "learned.toml key `{key}` is repeated"
            ))));
        }
        match (&self.section, key, value) {
            (Section::Root, "version", Value::Int(number)) => self.file.version = number,
            (Section::Names, "terms", Value::Strings(items)) => self.file.names.terms = items,
            (Section::Names, "people", Value::Strings(items)) => self.file.names.people = items,
            (Section::Allow, "entries", Value::Strings(items)) => {
                self.file.allow.entries = items;
            }
            (Section::Secret, "name", Value::String(text)) => {
                let Open::Secret(rule) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                rule.name = text;
            }
            (Section::Secret, "regex", Value::String(text)) => {
                let Open::Secret(rule) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                rule.regex = text;
            }
            (Section::Symbol, "name", Value::String(text)) => {
                let Open::Symbol(rule) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                rule.name = text;
            }
            (Section::Symbol, "regex", Value::String(text)) => {
                let Open::Symbol(rule) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                rule.regex = text;
            }
            (Section::Decision, "key", Value::String(text)) => {
                let Open::Decision(decision) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                decision.key = text;
            }
            (Section::Decision, "action", Value::String(text)) => {
                let Open::Decision(decision) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                decision.action = text;
            }
            (Section::Decision, "category", Value::String(text)) => {
                let Open::Decision(decision) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                decision.category = text;
            }
            (Section::Decision, "text", Value::String(text)) => {
                let Open::Decision(decision) = &mut self.open else {
                    return Err(Reject::Unsupported);
                };
                decision.text = text;
            }
            _ => return Err(Reject::Unsupported),
        }
        self.seen |= bit;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Reject> {
        match std::mem::replace(&mut self.open, Open::None) {
            Open::None => {}
            Open::Secret(rule) => self.file.secrets.push(rule),
            Open::Symbol(rule) => self.file.symbols.push(rule),
            Open::Decision(decision) => self.file.decisions.push(decision),
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Value, Reject> {
        match self.text.as_bytes().get(self.index) {
            Some(b'"' | b'\'') => Ok(Value::String(self.string()?)),
            Some(b'[') => Ok(Value::Strings(self.string_array()?)),
            Some(byte) if byte.is_ascii_digit() => Ok(Value::Int(self.integer()?)),
            _ => Err(Reject::Unsupported),
        }
    }

    fn string_array(&mut self) -> Result<Vec<String>, Reject> {
        if !self.eat(b'[') {
            return Err(Reject::Unsupported);
        }
        let mut items = Vec::new();
        loop {
            self.skip();
            if self.eat(b']') {
                break;
            }
            if self.text.as_bytes().get(self.index) == Some(&b',') {
                return Err(Reject::Unsupported);
            }
            items.push(self.string()?);
            self.skip();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b']') {
                break;
            }
            return Err(Reject::Unsupported);
        }
        Ok(items)
    }

    fn string(&mut self) -> Result<String, Reject> {
        if self.text[self.index..].starts_with("\"\"\"")
            || self.text[self.index..].starts_with("'''")
        {
            return Err(Reject::Unsupported);
        }
        match self.text.as_bytes().get(self.index) {
            Some(b'"') => self.basic_string(),
            Some(b'\'') => self.literal_string(),
            _ => Err(Reject::Unsupported),
        }
    }

    fn basic_string(&mut self) -> Result<String, Reject> {
        if !self.eat(b'"') {
            return Err(Reject::Unsupported);
        }
        let start = self.index;
        let bytes = self.text.as_bytes();
        while self.index < bytes.len() {
            match bytes[self.index] {
                b'"' => {
                    let owned = self.text[start..self.index].to_string();
                    self.index += 1;
                    return Ok(owned);
                }
                b'\\' | b'\n' | b'\r' => break,
                _ => self.index += 1,
            }
        }
        let mut owned = String::new();
        owned.push_str(&self.text[start..self.index]);
        self.basic_rest(&mut owned)?;
        Ok(owned)
    }

    fn basic_rest(&mut self, owned: &mut String) -> Result<(), Reject> {
        let bytes = self.text.as_bytes();
        loop {
            if self.index >= bytes.len() {
                return Err(Reject::Invalid(Error::msg("unclosed string")));
            }
            match bytes[self.index] {
                b'"' => {
                    self.index += 1;
                    return Ok(());
                }
                b'\n' | b'\r' => return Err(Reject::Invalid(Error::msg("newline in string"))),
                b'\\' => {
                    self.index += 1;
                    self.push_escape(owned)?;
                }
                byte if byte < 128 => {
                    owned.push(byte as char);
                    self.index += 1;
                }
                _ => {
                    let ch = self.text[self.index..]
                        .chars()
                        .next()
                        .ok_or_else(|| Reject::Invalid(Error::msg("bad utf-8")))?;
                    owned.push(ch);
                    self.index += ch.len_utf8();
                }
            }
        }
    }

    fn push_escape(&mut self, owned: &mut String) -> Result<(), Reject> {
        let bytes = self.text.as_bytes();
        if self.index >= bytes.len() {
            return Err(Reject::Invalid(Error::msg("truncated escape")));
        }
        let mark = bytes[self.index];
        self.index += 1;
        let ch = match mark {
            b'b' => '\u{0008}',
            b't' => '\t',
            b'n' => '\n',
            b'f' => '\u{000c}',
            b'r' => '\r',
            b'"' => '"',
            b'\\' => '\\',
            b'u' => return self.push_unicode(owned),
            _ => return Err(Reject::Unsupported),
        };
        owned.push(ch);
        Ok(())
    }

    fn push_unicode(&mut self, owned: &mut String) -> Result<(), Reject> {
        let bytes = self.text.as_bytes();
        let hex = if bytes.get(self.index) == Some(&b'{') {
            self.index += 1;
            let start = self.index;
            while self.index < bytes.len() && bytes[self.index].is_ascii_hexdigit() {
                self.index += 1;
            }
            if self.index == start || self.index - start > 6 || bytes.get(self.index) != Some(&b'}')
            {
                return Err(Reject::Unsupported);
            }
            let hex = &self.text[start..self.index];
            self.index += 1;
            hex
        } else {
            if self.index + 4 > bytes.len() {
                return Err(Reject::Unsupported);
            }
            let hex = &self.text[self.index..self.index + 4];
            if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Reject::Unsupported);
            }
            self.index += 4;
            hex
        };
        let code = u32::from_str_radix(hex, 16).map_err(|_| Reject::Unsupported)?;
        let ch = char::from_u32(code).ok_or(Reject::Unsupported)?;
        owned.push(ch);
        Ok(())
    }

    fn literal_string(&mut self) -> Result<String, Reject> {
        if !self.eat(b'\'') {
            return Err(Reject::Unsupported);
        }
        let start = self.index;
        let bytes = self.text.as_bytes();
        while self.index < bytes.len() {
            match bytes[self.index] {
                b'\'' => {
                    let owned = self.text[start..self.index].to_string();
                    self.index += 1;
                    return Ok(owned);
                }
                b'\n' | b'\r' => return Err(Reject::Invalid(Error::msg("newline in string"))),
                _ => self.index += 1,
            }
        }
        Err(Reject::Invalid(Error::msg("unclosed string")))
    }

    fn integer(&mut self) -> Result<u32, Reject> {
        let bytes = self.text.as_bytes();
        if self.index >= bytes.len() || !bytes[self.index].is_ascii_digit() {
            return Err(Reject::Unsupported);
        }
        if bytes[self.index] == b'0'
            && self
                .index
                .checked_add(1)
                .is_some_and(|next| next < bytes.len() && bytes[next].is_ascii_digit())
        {
            return Err(Reject::Unsupported);
        }
        let mut number: u32 = 0;
        while self.index < bytes.len() && bytes[self.index].is_ascii_digit() {
            number = number
                .checked_mul(10)
                .and_then(|value| value.checked_add(u32::from(bytes[self.index] - b'0')))
                .ok_or(Reject::Unsupported)?;
            self.index += 1;
        }
        if self.index < bytes.len() {
            let next = bytes[self.index];
            if next == b'_' || next == b'.' || next.is_ascii_alphabetic() {
                return Err(Reject::Unsupported);
            }
        }
        Ok(number)
    }

    fn bare_key(&mut self) -> Result<(), Reject> {
        let bytes = self.text.as_bytes();
        if self.index >= bytes.len()
            || !(bytes[self.index].is_ascii_alphabetic() || bytes[self.index] == b'_')
        {
            return Err(Reject::Unsupported);
        }
        self.index += 1;
        while self.index < bytes.len() {
            let byte = bytes[self.index];
            if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' {
                self.index += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn skip(&mut self) {
        let bytes = self.text.as_bytes();
        while self.index < bytes.len() {
            match bytes[self.index] {
                b' ' | b'\t' | b'\n' | b'\r' => self.index += 1,
                b'#' => {
                    self.index += 1;
                    while self.index < bytes.len() && bytes[self.index] != b'\n' {
                        self.index += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn skip_inline(&mut self) {
        let bytes = self.text.as_bytes();
        while self.index < bytes.len() && (bytes[self.index] == b' ' || bytes[self.index] == b'\t')
        {
            self.index += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.text.as_bytes().get(self.index) == Some(&byte) {
            self.index += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::try_parse;
    use crate::learned::{DecisionRecord, LearnedAllow, LearnedFile, LearnedNames, LearnedRule};

    #[test]
    fn writer_output_and_hand_syntax_match_the_toml_crate() {
        let written = LearnedFile {
            version: 1,
            names: LearnedNames {
                terms: vec![
                    "say \"hi\"".into(),
                    "line\nbreak".into(),
                    "caf\u{00e9}".into(),
                ],
                people: vec!["Ren Testdotter".into()],
            },
            secrets: vec![LearnedRule {
                name: "learned-secret-example".into(),
                regex: r"\bsecret\b".into(),
            }],
            symbols: vec![LearnedRule {
                name: "learned-symbol-example".into(),
                regex: r"\bcode\b".into(),
            }],
            allow: LearnedAllow {
                entries: vec!["threshold".into()],
            },
            decisions: vec![DecisionRecord {
                key: "term:exempla".into(),
                action: "redact".into(),
                category: "name".into(),
                text: "Exempla".into(),
            }],
        };
        let text = written.to_toml().unwrap();
        let fast = try_parse(&text).expect("writer output stays on the direct reader");
        let slow: LearnedFile = toml::from_str(&text).unwrap();
        assert_eq!(fast, slow);

        let hand = "\
# comment\r
version = 1\r
\r
[names]\r
terms = [\"Exempla\", 'Ren',] # trailing comma\r
people = []\r
\r
[[secrets]]\r
name = 'learned-secret-example'\r
regex = '\\bsecret\\b'\r
\r
[[symbols]]\r
name = \"learned-symbol-example\"\r
regex = \"\\\\bcode\\\\b\"\r
\r
[allow]\r
entries = [\"threshold\"]\r
\r
[[decisions]]\r
key = \"term:exempla\"\r
action = \"keep\"\r
category = \"name\"\r
text = \"Exempla\"\r
";
        let fast = try_parse(hand).expect("hand syntax stays on the direct reader");
        let slow: LearnedFile = toml::from_str(hand).unwrap();
        assert_eq!(fast, slow);
        assert_eq!(
            fast.names.terms,
            vec!["Exempla".to_string(), "Ren".to_string()]
        );
        assert_eq!(fast.secrets[0].regex, r"\bsecret\b");
        assert_eq!(fast.symbols[0].regex, r"\bcode\b");
    }

    #[test]
    fn a_multiline_string_is_left_to_the_toml_crate() {
        let text = "\
version = 1

[[decisions]]
key = \"term:exempla\"
action = \"redact\"
category = \"name\"
text = \"\"\"
Exempla
\"\"\"
";
        assert!(matches!(try_parse(text), Err(super::Reject::Unsupported)));
        let via_parse = LearnedFile::parse(text).unwrap();
        let via_toml: LearnedFile = toml::from_str(text).unwrap();
        assert_eq!(via_parse, via_toml);
        assert_eq!(via_parse.decisions[0].text, "Exempla\n");
    }
}
