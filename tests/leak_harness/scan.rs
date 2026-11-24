//! Needles searched in raw upstream bytes.

pub fn leak_needles(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    push_unique(&mut out, value.to_string());
    push_unique(&mut out, value.to_lowercase());
    push_unique(&mut out, value.to_uppercase());
    push_unique(&mut out, json_escaped(value));
    push_unique(&mut out, percent_encode(value, true));
    push_unique(&mut out, percent_encode(value, false));
    let stripped: String = value
        .chars()
        .filter(|ch| !matches!(ch, ' ' | '-' | '\t'))
        .collect();
    if stripped != value && stripped.chars().count() >= 8 {
        push_unique(&mut out, stripped);
    }
    out.into_iter().filter(|needle| needle.len() >= 4).collect()
}

/// Forms that mean "the original text is still here" inside a JSON body.
pub fn presence_needles(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    push_unique(&mut out, value.to_string());
    push_unique(&mut out, json_escaped(value));
    push_unique(&mut out, unicode_escape(value, false));
    push_unique(&mut out, unicode_escape(value, true));
    out
}

pub fn contains_any(haystack: &[u8], needles: &[String]) -> Option<String> {
    needles
        .iter()
        .find(|needle| !needle.is_empty() && find_bytes(haystack, needle.as_bytes()))
        .cloned()
}

pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !out.iter().any(|seen| seen == &value) {
        out.push(value);
    }
}

fn json_escaped(value: &str) -> String {
    match serde_json::to_string(value) {
        Ok(quoted) if quoted.len() >= 2 => quoted[1..quoted.len() - 1].to_string(),
        _ => value.to_string(),
    }
}

fn percent_encode(value: &str, upper: bool) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        let plain = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if plain {
            out.push(char::from(byte));
        } else if upper {
            out.push_str(&format!("%{byte:02X}"));
        } else {
            out.push_str(&format!("%{byte:02x}"));
        }
    }
    out
}

fn unicode_escape(value: &str, upper: bool) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else if upper {
            out.push_str(&format!("\\u{:04X}", u32::from(ch)));
        } else {
            out.push_str(&format!("\\u{:04x}", u32::from(ch)));
        }
    }
    out
}
