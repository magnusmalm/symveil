//! Streaming restore.
//!
//! A placeholder is the fixed ASCII token `@@sv:` + 8 hex digits + `@@` (15 bytes).
//! Chunk boundaries can land inside that token, or inside a UTF-8 scalar that sits
//! next to it. `ByteRestorer` holds back an incomplete UTF-8 tail and any suffix
//! that is still a legal prefix of a placeholder, then emits the restored prefix.

use std::collections::HashMap;

use crate::vault::TOKEN_LEN;

pub struct StreamRestorer {
    carry: String,
    map: HashMap<String, String>,
    json_escape: bool,
    restored: usize,
}

impl StreamRestorer {
    pub fn new(map: HashMap<String, String>, json_escape: bool) -> Self {
        Self {
            carry: String::new(),
            map,
            json_escape,
            restored: 0,
        }
    }

    pub fn push(&mut self, chunk: &str) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        if self.carry.is_empty() && !chunk.contains('@') {
            return chunk.to_string();
        }
        let mut data = String::with_capacity(self.carry.len() + chunk.len());
        data.push_str(&self.carry);
        data.push_str(chunk);
        let (emit, hold, restored) = restore_with_hold(&data, &self.map, self.json_escape);
        self.restored += restored;
        self.carry = hold;
        emit
    }

    pub fn finish(&mut self) -> String {
        std::mem::take(&mut self.carry)
    }

    pub fn restored(&self) -> usize {
        self.restored
    }
}

pub struct ByteRestorer {
    pending: Vec<u8>,
    inner: StreamRestorer,
}

impl ByteRestorer {
    pub fn new(map: HashMap<String, String>, json_escape: bool) -> Self {
        Self {
            pending: Vec::new(),
            inner: StreamRestorer::new(map, json_escape),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        if self.pending.is_empty() && !chunk.contains(&b'@') {
            if let Ok(text) = std::str::from_utf8(chunk) {
                return self.inner.push(text);
            }
        }
        self.pending.extend_from_slice(chunk);
        let decoded = drain_valid_utf8(&mut self.pending);
        self.inner.push(&decoded)
    }

    pub fn finish(&mut self) -> String {
        let pending = std::mem::take(&mut self.pending);
        let mut out = String::new();
        if !pending.is_empty() {
            let lossy = String::from_utf8_lossy(&pending);
            out.push_str(&self.inner.push(&lossy));
        }
        out.push_str(&self.inner.finish());
        out
    }

    pub fn restored(&self) -> usize {
        self.inner.restored()
    }
}

pub fn restore_all(
    bytes: &[u8],
    map: &HashMap<String, String>,
    json_escape: bool,
) -> (Vec<u8>, usize) {
    let mut restorer = ByteRestorer::new(map.clone(), json_escape);
    let mut out = restorer.push(bytes);
    out.push_str(&restorer.finish());
    let restored = restorer.restored();
    (out.into_bytes(), restored)
}

pub fn placeholder_ranges(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + TOKEN_LEN <= bytes.len() {
        if token_key_at(text, i).is_some() {
            ranges.push((i, i + TOKEN_LEN));
            i += TOKEN_LEN;
            continue;
        }
        i += 1;
    }
    ranges
}

pub fn json_escape(value: &str) -> String {
    match serde_json::to_string(value) {
        Ok(quoted) if quoted.len() >= 2 => quoted[1..quoted.len() - 1].to_string(),
        _ => value.to_string(),
    }
}

fn restore_with_hold(
    input: &str,
    map: &HashMap<String, String>,
    json_escape_replacements: bool,
) -> (String, String, usize) {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut restored = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' {
            match input[i..].find('@') {
                Some(rel) => {
                    out.push_str(&input[i..i + rel]);
                    i += rel;
                }
                None => {
                    out.push_str(&input[i..]);
                    break;
                }
            }
            continue;
        }
        if let Some(key) = token_key_at(input, i) {
            let raw = &input[i..i + TOKEN_LEN];
            if let Some(original) = map.get(&key) {
                if json_escape_replacements {
                    out.push_str(&json_escape(original));
                } else {
                    out.push_str(original);
                }
                restored += 1;
            } else {
                out.push_str(raw);
            }
            i += TOKEN_LEN;
            continue;
        }
        if is_incomplete_prefix(&input[i..]) {
            return (out, input[i..].to_string(), restored);
        }
        out.push('@');
        i += 1;
    }
    (out, String::new(), restored)
}

fn token_key_at(input: &str, i: usize) -> Option<String> {
    let bytes = input.as_bytes();
    if i + TOKEN_LEN > bytes.len() {
        return None;
    }
    if &bytes[i..i + 5] != b"@@sv:" || &bytes[i + 13..i + 15] != b"@@" {
        return None;
    }
    if !bytes[i + 5..i + 13].iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut hex = [0u8; 8];
    hex.copy_from_slice(&bytes[i + 5..i + 13]);
    for byte in &mut hex {
        *byte = byte.to_ascii_lowercase();
    }
    let hex = std::str::from_utf8(&hex).ok()?;
    Some(format!("@@sv:{hex}@@"))
}

fn is_incomplete_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() >= TOKEN_LEN {
        return false;
    }
    let head = b"@@sv:";
    if bytes.len() <= head.len() {
        return head.starts_with(bytes);
    }
    if &bytes[..5] != b"@@sv:" {
        return false;
    }
    let rest = &bytes[5..];
    if rest.len() <= 8 {
        return rest.iter().all(|byte| byte.is_ascii_hexdigit());
    }
    rest.len() == 9 && rest[..8].iter().all(|byte| byte.is_ascii_hexdigit()) && rest[8] == b'@'
}

fn drain_valid_utf8(pending: &mut Vec<u8>) -> String {
    let mut decoded = String::new();
    loop {
        if pending.is_empty() {
            break;
        }
        match std::str::from_utf8(pending) {
            Ok(text) => {
                decoded.push_str(text);
                pending.clear();
                break;
            }
            Err(err) => {
                let valid = err.valid_up_to();
                if valid > 0 {
                    if let Ok(text) = std::str::from_utf8(&pending[..valid]) {
                        decoded.push_str(text);
                    }
                    pending.drain(..valid);
                }
                match err.error_len() {
                    None => break,
                    Some(0) => break,
                    Some(len) => {
                        decoded.push('\u{FFFD}');
                        let drop_n = len.min(pending.len());
                        if drop_n == 0 {
                            break;
                        }
                        pending.drain(..drop_n);
                    }
                }
            }
        }
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::vault::Vault;

    fn sample() -> (HashMap<String, String>, String, String) {
        let mut vault = Vault::ephemeral();
        let function = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let secret = vault
            .assign(
                "AKIAIOSFODNN7EXAMPLE",
                Category::Secret,
                Some("aws-access-key-id".into()),
            )
            .unwrap();
        let text = format!("alpha {function} see @@ notes {secret} omega é @");
        let expected =
            "alpha aurora_rcc_enable_pll see @@ notes AKIAIOSFODNN7EXAMPLE omega é @".to_string();
        (vault.restore_map(), text, expected)
    }

    #[test]
    fn every_byte_split_round_trips() {
        let (map, text, expected) = sample();
        let bytes = text.as_bytes();
        for split in 0..=bytes.len() {
            let mut restorer = ByteRestorer::new(map.clone(), false);
            let mut out = restorer.push(&bytes[..split]);
            out.push_str(&restorer.push(&bytes[split..]));
            out.push_str(&restorer.finish());
            assert_eq!(out, expected, "split at {split}");
        }
    }

    #[test]
    fn every_window_round_trips() {
        let (map, text, expected) = sample();
        let bytes = text.as_bytes();
        for window in 1..12 {
            let mut restorer = ByteRestorer::new(map.clone(), false);
            let mut out = String::new();
            let mut index = 0;
            while index < bytes.len() {
                let end = (index + window).min(bytes.len());
                out.push_str(&restorer.push(&bytes[index..end]));
                index = end;
            }
            out.push_str(&restorer.finish());
            assert_eq!(out, expected, "window {window}");
        }
    }

    #[test]
    fn adjacent_placeholders_restore() {
        let (map, _, _) = sample();
        let mut vault = Vault::ephemeral();
        let a = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let b = vault
            .assign("AURORA_RCC_CTRL_REG", Category::Register, None)
            .unwrap();
        let mut map = map;
        map.insert(a.clone(), "aurora_rcc_enable_pll".to_string());
        map.insert(b.clone(), "AURORA_RCC_CTRL_REG".to_string());
        let text = format!("{a}{b}");
        let mut restorer = ByteRestorer::new(map, false);
        let mut out = String::new();
        for byte in text.as_bytes() {
            out.push_str(&restorer.push(&[*byte]));
        }
        out.push_str(&restorer.finish());
        assert_eq!(out, "aurora_rcc_enable_pllAURORA_RCC_CTRL_REG");
    }

    #[test]
    fn json_escape_survives_a_split_inside_the_token() {
        let mut vault = Vault::ephemeral();
        let token = vault
            .assign("p@ss\"word12", Category::Secret, Some("literal".into()))
            .unwrap();
        let map = vault.restore_map();
        let bytes = token.as_bytes();
        let mut restorer = ByteRestorer::new(map, true);
        let mut out = restorer.push(&bytes[..6]);
        out.push_str(&restorer.push(&bytes[6..]));
        out.push_str(&restorer.finish());
        assert_eq!(out, r#"p@ss\"word12"#);
        assert_eq!(restorer.restored(), 1);
    }

    #[test]
    fn unknown_token_is_left_in_place() {
        let map = HashMap::new();
        let mut restorer = StreamRestorer::new(map, false);
        let out = restorer.push("@@sv:0123abcd@@");
        assert_eq!(out, "@@sv:0123abcd@@");
        assert_eq!(restorer.restored(), 0);
    }

    #[test]
    fn uppercase_hex_matches_the_lowercase_key() {
        let mut vault = Vault::ephemeral();
        let token = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let upper = token.replace(&token[5..13], &token[5..13].to_ascii_uppercase());
        let mut restorer = StreamRestorer::new(vault.restore_map(), false);
        assert_eq!(restorer.push(&upper), "aurora_rcc_enable_pll");
    }

    #[test]
    fn json_escape_quotes_and_newlines() {
        assert_eq!(json_escape("a\"b\\c"), r#"a\"b\\c"#);
        assert_eq!(json_escape("line\n"), r#"line\n"#);
    }
}
