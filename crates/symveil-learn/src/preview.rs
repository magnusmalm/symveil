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
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 {
        return "len=0".to_string();
    }
    if n <= 8 {
        return format!("••• len={n}");
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(n - 4).collect();
    format!("{head}…{tail} len={n}")
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
    }
}
