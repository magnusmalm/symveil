//! Inline image, document, and file content blocks.
//!
//! The default is to replace the block with a short text note. The bytes are
//! not forwarded and are not written to the audit log. A remote `http` or
//! `https` image URL is not fetched; the block stays and the URL string is
//! still scanned by the text rules. `data:` URLs are inline payloads.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{Map, Value};

use crate::config::BinaryMode;

/// One withheld block. The kind is `image`, `document`, or `file`. `bytes` is
/// the decoded length when the payload decoded, the raw length when it did
/// not, and zero when the block named no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryNote {
    pub kind: &'static str,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextType {
    Text,
    InputText,
}

impl TextType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::InputText => "input_text",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Image,
    Document,
    File,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Document => "document",
            Self::File => "file",
        }
    }
}

enum Shape {
    Anthropic { image: bool },
    ImageUrl,
    InputImage,
    File,
}

enum Payload {
    Decoded(Vec<u8>),
    /// Base64 or a data URL that did not decode. The length is the raw payload.
    Undecoded(usize),
    /// An `http` or `https` image URL. Not fetched.
    RemoteImage,
    /// A file id, a missing payload, or a URL that is not a remote image.
    Opaque,
}

struct Seen {
    kind: Kind,
    text_type: TextType,
    payload: Payload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Not a binary block, or a remote image URL. Keep walking.
    Recurse,
    /// Forward this object as it stands. Do not scan inside it.
    Leave,
    Replace {
        kind: &'static str,
        bytes: usize,
        text_type: TextType,
    },
}

pub(crate) fn decide(
    object: &Map<String, Value>,
    mode: BinaryMode,
    scan: impl FnOnce(&[u8]) -> bool,
) -> Decision {
    if mode == BinaryMode::Pass {
        return if is_binary_block(object) {
            Decision::Leave
        } else {
            Decision::Recurse
        };
    }
    let Some(seen) = inspect(object) else {
        return Decision::Recurse;
    };
    let kind = seen.kind;
    let text_type = seen.text_type;
    match mode {
        BinaryMode::Pass => Decision::Leave,
        BinaryMode::Block => match seen.payload {
            Payload::RemoteImage => Decision::Recurse,
            Payload::Decoded(bytes) => replace(kind, text_type, bytes.len()),
            Payload::Undecoded(len) => replace(kind, text_type, len),
            Payload::Opaque => replace(kind, text_type, 0),
        },
        BinaryMode::Scan => match seen.payload {
            Payload::RemoteImage => Decision::Recurse,
            Payload::Decoded(bytes) => {
                if scan(&bytes) {
                    replace(kind, text_type, bytes.len())
                } else {
                    Decision::Leave
                }
            }
            // No bytes to judge, or the bytes did not decode. Withhold.
            Payload::Undecoded(len) => replace(kind, text_type, len),
            Payload::Opaque => replace(kind, text_type, 0),
        },
    }
}

pub(crate) fn withheld_block(text_type: TextType, kind: &str, bytes: usize) -> Value {
    serde_json::json!({
        "type": text_type.as_str(),
        "text": format!("[symveil: {kind} withheld, {bytes} bytes]"),
    })
}

fn replace(kind: Kind, text_type: TextType, bytes: usize) -> Decision {
    Decision::Replace {
        kind: kind.as_str(),
        bytes,
        text_type,
    }
}

fn is_binary_block(object: &Map<String, Value>) -> bool {
    matches!(
        object.get("type").and_then(Value::as_str),
        Some("image" | "document" | "image_url" | "input_image" | "input_file" | "file")
    )
}

fn inspect(object: &Map<String, Value>) -> Option<Seen> {
    let ty = object.get("type").and_then(Value::as_str)?;
    let (kind, text_type, shape) = match ty {
        "image" => (
            Kind::Image,
            TextType::Text,
            Shape::Anthropic { image: true },
        ),
        "document" => (
            Kind::Document,
            TextType::Text,
            Shape::Anthropic { image: false },
        ),
        "image_url" => (Kind::Image, TextType::Text, Shape::ImageUrl),
        "input_image" => (Kind::Image, TextType::InputText, Shape::InputImage),
        "input_file" => (Kind::File, TextType::InputText, Shape::File),
        "file" => (Kind::File, TextType::Text, Shape::File),
        _ => return None,
    };
    let payload = match shape {
        Shape::Anthropic { image } => anthropic_source(object, image),
        Shape::ImageUrl => image_url_value(object.get("image_url")),
        Shape::InputImage => {
            if object.contains_key("image_url") {
                image_url_value(object.get("image_url"))
            } else {
                Payload::Opaque
            }
        }
        Shape::File => file_payload(object),
    };
    Some(Seen {
        kind,
        text_type,
        payload,
    })
}

fn anthropic_source(object: &Map<String, Value>, image: bool) -> Payload {
    let Some(source) = object.get("source").and_then(Value::as_object) else {
        if let Some(data) = object.get("data").and_then(Value::as_str) {
            return inline_b64(data);
        }
        return Payload::Opaque;
    };
    let source_type = source.get("type").and_then(Value::as_str).unwrap_or("");
    match source_type {
        "base64" => inline_b64(source.get("data").and_then(Value::as_str).unwrap_or("")),
        "url" => classify_url(
            source.get("url").and_then(Value::as_str).unwrap_or(""),
            image,
        ),
        "file" => Payload::Opaque,
        _ => {
            if let Some(data) = source.get("data").and_then(Value::as_str) {
                inline_b64(data)
            } else if let Some(url) = source.get("url").and_then(Value::as_str) {
                classify_url(url, image)
            } else {
                Payload::Opaque
            }
        }
    }
}

fn image_url_value(value: Option<&Value>) -> Payload {
    match value {
        Some(Value::String(url)) => classify_url(url, true),
        Some(Value::Object(map)) => {
            classify_url(map.get("url").and_then(Value::as_str).unwrap_or(""), true)
        }
        Some(_) | None => Payload::Opaque,
    }
}

fn file_payload(object: &Map<String, Value>) -> Payload {
    if let Some(data) = object.get("file_data").and_then(Value::as_str) {
        return classify_url(data, false);
    }
    if let Some(url) = object.get("file_url").and_then(Value::as_str) {
        return classify_url(url, false);
    }
    let Some(file) = object.get("file").and_then(Value::as_object) else {
        return Payload::Opaque;
    };
    if let Some(data) = file.get("file_data").and_then(Value::as_str) {
        return classify_url(data, false);
    }
    if let Some(url) = file
        .get("url")
        .or_else(|| file.get("file_url"))
        .and_then(Value::as_str)
    {
        return classify_url(url, false);
    }
    Payload::Opaque
}

fn classify_url(url: &str, allow_remote: bool) -> Payload {
    let url = url.trim();
    if url.is_empty() {
        return Payload::Opaque;
    }
    if starts_with_ignore_ascii_case(url, "data:") {
        return decode_data_url(url);
    }
    if allow_remote && is_http_url(url) {
        return Payload::RemoteImage;
    }
    if !url.contains("://") && looks_like_base64(url) {
        return inline_b64(url);
    }
    Payload::Opaque
}

fn decode_data_url(url: &str) -> Payload {
    let Some(rest) = strip_prefix_ignore_ascii_case(url, "data:") else {
        return Payload::Undecoded(url.len());
    };
    let Some((meta, data)) = rest.split_once(',') else {
        return Payload::Undecoded(url.len());
    };
    if meta.to_ascii_lowercase().contains("base64") {
        return match decode_b64(data) {
            Some(bytes) => Payload::Decoded(bytes),
            None => Payload::Undecoded(data.len()),
        };
    }
    Payload::Undecoded(data.len())
}

fn inline_b64(data: &str) -> Payload {
    match decode_b64(data) {
        Some(bytes) => Payload::Decoded(bytes),
        None => Payload::Undecoded(data.len()),
    }
}

fn decode_b64(data: &str) -> Option<Vec<u8>> {
    let cleaned: String = data
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(cleaned.as_bytes()) {
            return Some(bytes);
        }
    }
    None
}

fn looks_like_base64(text: &str) -> bool {
    let stripped: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    stripped.len() >= 16
        && stripped.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
        })
}

fn is_http_url(url: &str) -> bool {
    starts_with_ignore_ascii_case(url, "https://") || starts_with_ignore_ascii_case(url, "http://")
}

fn starts_with_ignore_ascii_case(text: &str, prefix: &str) -> bool {
    let bytes = text.as_bytes();
    let prefix = prefix.as_bytes();
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn strip_prefix_ignore_ascii_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    if starts_with_ignore_ascii_case(text, prefix) {
        Some(&text[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BinaryMode;

    fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    fn image(data: &str) -> Value {
        serde_json::json!({
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": data}
        })
    }

    fn decide_block(value: &Value) -> Decision {
        decide(value.as_object().unwrap(), BinaryMode::Block, |_| true)
    }

    #[test]
    fn block_replaces_inline_images_documents_and_files() {
        let png = b64(b"png-bytes");
        let cases = [
            image(&png),
            serde_json::json!({
                "type": "document",
                "source": {"type": "base64", "media_type": "application/pdf", "data": b64(b"%PDF")}
            }),
            serde_json::json!({
                "type": "image_url",
                "image_url": {"url": format!("data:image/png;base64,{png}")}
            }),
            serde_json::json!({
                "type": "image_url",
                "image_url": format!("data:image/png;base64,{png}")
            }),
            serde_json::json!({
                "type": "input_image",
                "image_url": format!("data:image/png;base64,{png}")
            }),
            serde_json::json!({
                "type": "input_file",
                "filename": "notes.pdf",
                "file_data": format!("data:application/pdf;base64,{}", b64(b"%PDF"))
            }),
            serde_json::json!({
                "type": "file",
                "file": {"filename": "notes.pdf", "file_data": format!("data:application/pdf;base64,{}", b64(b"%PDF"))}
            }),
            serde_json::json!({"type": "input_file", "file_id": "file_fake_0001"}),
            serde_json::json!({
                "type": "image",
                "source": {"type": "file", "file_id": "file_fake_0001"}
            }),
        ];
        for case in &cases {
            let decision = decide_block(case);
            assert!(
                matches!(decision, Decision::Replace { .. }),
                "{case} -> {decision:?}"
            );
        }
        match decide_block(&serde_json::json!({
            "type": "input_image",
            "image_url": format!("data:image/png;base64,{png}")
        })) {
            Decision::Replace {
                kind,
                text_type,
                bytes,
            } => {
                assert_eq!(kind, "image");
                assert_eq!(text_type, TextType::InputText);
                assert_eq!(bytes, b"png-bytes".len());
            }
            other => panic!("expected replace, got {other:?}"),
        }
        match decide_block(&serde_json::json!({
            "type": "file",
            "file": {"file_id": "file_fake_0001"}
        })) {
            Decision::Replace { kind, bytes, .. } => {
                assert_eq!(kind, "file");
                assert_eq!(bytes, 0);
            }
            other => panic!("expected replace, got {other:?}"),
        }
    }

    #[test]
    fn remote_image_urls_stay_and_other_urls_do_not() {
        let remote = serde_json::json!({
            "type": "image",
            "source": {"type": "url", "url": "https://cdn.example.test/a.png"}
        });
        assert!(matches!(decide_block(&remote), Decision::Recurse));
        let chat = serde_json::json!({
            "type": "image_url",
            "image_url": {"url": "http://cdn.example.test/a.png"}
        });
        assert!(matches!(decide_block(&chat), Decision::Recurse));
        let document = serde_json::json!({
            "type": "document",
            "source": {"type": "url", "url": "https://cdn.example.test/a.pdf"}
        });
        assert!(matches!(
            decide_block(&document),
            Decision::Replace {
                kind: "document",
                ..
            }
        ));
        let data = serde_json::json!({
            "type": "image",
            "source": {"type": "url", "url": format!("DATA:image/png;base64,{}", b64(b"png-bytes"))}
        });
        assert!(matches!(decide_block(&data), Decision::Replace { .. }));
        assert!(matches!(
            decide_block(&serde_json::json!({"type": "text", "text": "hello"})),
            Decision::Recurse
        ));
        assert!(matches!(
            decide_block(&serde_json::json!({"type": "tool_result", "tool_use_id": "toolu_x"})),
            Decision::Recurse
        ));
    }

    #[test]
    fn broken_base64_is_replaced_in_block_and_scan() {
        let broken = image("****");
        assert!(matches!(
            decide_block(&broken),
            Decision::Replace { bytes: 4, .. }
        ));
        let scan = decide(broken.as_object().unwrap(), BinaryMode::Scan, |_| false);
        assert!(matches!(scan, Decision::Replace { bytes: 4, .. }));
        let with_break = image(&format!("{}\n", b64(b"png-bytes")));
        match decide_block(&with_break) {
            Decision::Replace { bytes, .. } => assert_eq!(bytes, b"png-bytes".len()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn pass_leaves_the_block_and_scan_honors_the_predicate() {
        let block = image(&b64(b"png-bytes"));
        let map = block.as_object().unwrap();
        assert!(matches!(
            decide(map, BinaryMode::Pass, |_| true),
            Decision::Leave
        ));
        assert!(matches!(
            decide(map, BinaryMode::Scan, |bytes| bytes == b"png-bytes"),
            Decision::Replace { .. }
        ));
        assert!(matches!(
            decide(map, BinaryMode::Scan, |_| false),
            Decision::Leave
        ));
        let note = withheld_block(TextType::Text, "image", 9);
        assert_eq!(note["type"], "text");
        assert_eq!(note["text"], "[symveil: image withheld, 9 bytes]");
        assert!(!note["text"].as_str().unwrap().contains("png"));
    }
}
