//! Terminal previews. Secret values stay masked unless the caller opts in.

pub fn preview(text: &str, secretish: bool, reveal: bool) -> String {
    let flat: String = text
        .chars()
        .map(|ch| if ch == '\n' || ch == '\r' { ' ' } else { ch })
        .collect();
    if secretish && !reveal {
        return mask_secret(&flat);
    }
    let count = flat.chars().count();
    if count > 80 {
        let head: String = flat.chars().take(77).collect();
        format!("{head}...")
    } else {
        flat
    }
}

pub fn mask_secret(text: &str) -> String {
    let n = text.chars().count();
    format!("{} len={n}", mask_body(text))
}

/// Masked token without the length, so it can sit inside a source line.
pub fn mask_body(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 {
        return "•••".to_string();
    }
    if n <= 8 {
        return "•••".to_string();
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(n - 4).collect();
    format!("{head}…{tail}")
}

/// `low` under 3 bits, `mixed` under 4.5, otherwise `high`.
pub fn entropy_hint(text: &str) -> &'static str {
    let bits = shannon(text);
    if bits < 3.0 {
        "low"
    } else if bits < 4.5 {
        "mixed"
    } else {
        "high"
    }
}

/// Source line with `value` masked when it is secret-like.
pub fn line_with_value(line: &str, value: &str, secretish: bool, reveal: bool) -> String {
    let shown = if secretish && !reveal {
        mask_body(value)
    } else {
        preview(value, false, true)
    };
    let flat: String = line
        .chars()
        .map(|ch| if ch == '\n' || ch == '\r' { ' ' } else { ch })
        .collect();
    let replaced = if value.is_empty() {
        flat
    } else if secretish && !reveal {
        flat.replace(value, &shown)
    } else if let Some(pos) = flat.find(value) {
        let mut out = String::new();
        out.push_str(&flat[..pos]);
        out.push_str(&shown);
        out.push_str(&flat[pos + value.len()..]);
        out
    } else {
        flat
    };
    truncate_chars(&replaced, 160)
}

fn truncate_chars(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max.saturating_sub(3)).collect();
    format!("{head}...")
}

fn shannon(token: &str) -> f64 {
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = f64::from(count) / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::{mask_secret, preview};

    #[test]
    fn secret_preview_keeps_ends_and_length_only() {
        let value = "AKIAIOSFODNN7EXAMPLE";
        let masked = mask_secret(value);
        assert_eq!(masked, "AKIA…MPLE len=20");
        assert!(!masked.contains("IOSFODNN7EXA"));
        let shown = preview(value, true, false);
        assert_eq!(shown, masked);
        assert_eq!(preview(value, true, true), value);
    }

    #[test]
    fn short_secret_hides_the_body() {
        assert_eq!(mask_secret("short"), "••• len=5");
        assert_eq!(super::mask_body("short"), "•••");
    }

    #[test]
    fn context_line_masks_a_secret_and_keeps_a_name() {
        let line = "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";";
        let shown = super::line_with_value(line, "AKIAIOSFODNN7EXAMPLE", true, false);
        assert!(shown.contains("const KEY"), "{shown}");
        assert!(shown.contains("AKIA…MPLE"), "{shown}");
        assert!(!shown.contains("IOSFODNN7"), "{shown}");
        let name = super::line_with_value("// Exempla ships", "Exempla", false, false);
        assert!(name.contains("Exempla"), "{name}");
    }

    #[test]
    fn entropy_hint_marks_a_word_low() {
        assert_eq!(super::entropy_hint("Exempla"), "low");
        assert_ne!(super::entropy_hint("AKIAIOSFODNN7EXAMPLE"), "low");
    }
}
