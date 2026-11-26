//! Request `Content-Encoding`.
//!
//! `zstd`, `gzip`, `deflate`, and `br` are decoded before redaction. The proxy
//! forwards that plaintext and drops `Content-Encoding`. `Content-Length` is
//! the length of the redacted bytes. Recompressing would be a second failure
//! mode, and the bytes the upstream parser sees would no longer be the bytes
//! the redactor produced.
//!
//! A missing header and `identity` are plaintext. More than one coding, an
//! unknown coding, a decode error, or a decoded body over the size cap is a
//! [`Reject`]. The caller must not forward the original bytes.
//!
//! Response bodies are not decoded. [`compressed_response`] reports any coding
//! other than `identity` so the proxy can refuse the response. `Accept-Encoding`
//! is stripped on the request, and the HTTP client is built without transparent
//! decompression, so a normal upstream body is plaintext and can be de-tokenized.
//! A compressed response would leave placeholders inside compressed bytes.

use std::borrow::Cow;
use std::io::{self, Read};

use flate2::read::{GzDecoder, ZlibDecoder};

/// Largest zstd window this proxy will allocate. 2^25 is 32 MiB, the same
/// order as the decoded-body cap. A frame that asks for a larger window is
/// refused. Default compressors use a smaller window.
const ZSTD_WINDOW_LOG_MAX: u32 = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

#[derive(Debug)]
enum ClassifyError {
    Unsupported { encoding: String },
    Stacked,
}

/// Why a request body was not forwarded.
#[derive(Debug)]
pub enum Reject {
    Unsupported { encoding: String },
    Stacked,
    Decode { coding: &'static str },
    TooLarge { coding: &'static str, limit: usize },
}

impl Reject {
    pub fn status(&self) -> http::StatusCode {
        match self {
            Reject::Unsupported { .. } | Reject::Stacked => {
                http::StatusCode::UNSUPPORTED_MEDIA_TYPE
            }
            Reject::Decode { .. } => http::StatusCode::BAD_REQUEST,
            Reject::TooLarge { .. } => http::StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Reject::Unsupported { .. } => "unsupported-content-encoding",
            Reject::Stacked => "stacked-content-encoding",
            Reject::Decode { .. } => "content-encoding-decode",
            Reject::TooLarge { .. } => "decompressed-body-too-large",
        }
    }

    /// Short coding token for the audit log. Never the body.
    pub fn encoding(&self) -> Option<&str> {
        match self {
            Reject::Unsupported { encoding } => Some(encoding.as_str()),
            Reject::Stacked => None,
            Reject::Decode { coding } | Reject::TooLarge { coding, .. } => Some(*coding),
        }
    }

    pub fn message(&self) -> String {
        match self {
            Reject::Unsupported { encoding } => {
                format!("symveil refused this request: unsupported content-encoding ({encoding})")
            }
            Reject::Stacked => {
                "symveil refused this request: stacked content-encoding is not accepted".to_string()
            }
            Reject::Decode { coding } => {
                format!("symveil refused this request: could not decode content-encoding {coding}")
            }
            Reject::TooLarge { limit, .. } => {
                format!("symveil refused this request: decompressed body exceeds {limit} bytes")
            }
        }
    }
}

#[derive(Debug)]
pub struct Prepared<'a> {
    /// Coding the client sent. `identity` when the body was already plaintext.
    pub coding: &'static str,
    pub body: Cow<'a, [u8]>,
}

pub fn prepare_request<'a>(
    headers: &http::HeaderMap,
    body: &'a [u8],
    limit: usize,
) -> Result<Prepared<'a>, Reject> {
    let coding = match classify(headers) {
        Ok(coding) => coding,
        Err(ClassifyError::Unsupported { encoding }) => {
            return Err(Reject::Unsupported { encoding });
        }
        Err(ClassifyError::Stacked) => return Err(Reject::Stacked),
    };
    if let Coding::Identity = coding {
        if body.len() > limit {
            return Err(Reject::TooLarge {
                coding: "identity",
                limit,
            });
        }
        return Ok(Prepared {
            coding: "identity",
            body: Cow::Borrowed(body),
        });
    }
    let decoded = decode(coding, body, limit)?;
    Ok(Prepared {
        coding: coding_name(coding),
        body: Cow::Owned(decoded),
    })
}

/// `None` when the response body is plaintext. Otherwise a short label for
/// the audit log. The raw header bytes are not returned.
pub fn compressed_response(headers: &http::HeaderMap) -> Option<String> {
    match classify(headers) {
        Ok(Coding::Identity) => None,
        Ok(coding) => Some(coding_name(coding).to_string()),
        Err(ClassifyError::Stacked) => Some("stacked".to_string()),
        Err(ClassifyError::Unsupported { encoding }) => Some(encoding),
    }
}

fn coding_name(coding: Coding) -> &'static str {
    match coding {
        Coding::Identity => "identity",
        Coding::Gzip => "gzip",
        Coding::Deflate => "deflate",
        Coding::Brotli => "br",
        Coding::Zstd => "zstd",
    }
}

fn classify(headers: &http::HeaderMap) -> Result<Coding, ClassifyError> {
    let mut tokens = Vec::new();
    for value in headers.get_all(http::header::CONTENT_ENCODING) {
        let text = value.to_str().map_err(|_| ClassifyError::Unsupported {
            encoding: "invalid".to_string(),
        })?;
        for part in text.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.contains(';') || part.split_whitespace().nth(1).is_some() {
                return Err(ClassifyError::Unsupported {
                    encoding: sanitize_token(part),
                });
            }
            tokens.push(part.to_ascii_lowercase());
        }
    }
    if tokens.is_empty() {
        if headers.get(http::header::CONTENT_ENCODING).is_some() {
            return Err(ClassifyError::Unsupported {
                encoding: "invalid".to_string(),
            });
        }
        return Ok(Coding::Identity);
    }
    if tokens.len() > 1 {
        return Err(ClassifyError::Stacked);
    }
    match tokens[0].as_str() {
        "identity" => Ok(Coding::Identity),
        "gzip" => Ok(Coding::Gzip),
        "deflate" => Ok(Coding::Deflate),
        "br" => Ok(Coding::Brotli),
        "zstd" => Ok(Coding::Zstd),
        other => Err(ClassifyError::Unsupported {
            encoding: sanitize_token(other),
        }),
    }
}

fn sanitize_token(raw: &str) -> String {
    let token: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        .take(32)
        .collect();
    if token.is_empty() {
        "invalid".to_string()
    } else {
        token
    }
}

fn decode(coding: Coding, body: &[u8], limit: usize) -> Result<Vec<u8>, Reject> {
    match coding {
        Coding::Identity => {
            if body.len() > limit {
                Err(Reject::TooLarge {
                    coding: "identity",
                    limit,
                })
            } else {
                Ok(body.to_vec())
            }
        }
        Coding::Gzip => decode_reader(GzDecoder::new(body), limit, "gzip"),
        // HTTP `deflate` is the zlib wrapper (RFC 1950), not raw deflate.
        Coding::Deflate => decode_reader(ZlibDecoder::new(body), limit, "deflate"),
        Coding::Brotli => decode_reader(brotli::Decompressor::new(body, 4096), limit, "br"),
        Coding::Zstd => decode_zstd(body, limit),
    }
}

fn decode_zstd(body: &[u8], limit: usize) -> Result<Vec<u8>, Reject> {
    let mut decoder = zstd::Decoder::new(body).map_err(|_| Reject::Decode { coding: "zstd" })?;
    decoder
        .window_log_max(ZSTD_WINDOW_LOG_MAX)
        .map_err(|_| Reject::Decode { coding: "zstd" })?;
    read_limited(decoder, limit, "zstd")
}

fn decode_reader(reader: impl Read, limit: usize, coding: &'static str) -> Result<Vec<u8>, Reject> {
    read_limited(reader, limit, coding)
}

fn read_limited(
    mut reader: impl Read,
    limit: usize,
    coding: &'static str,
) -> Result<Vec<u8>, Reject> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8 * 1024];
    loop {
        if out.len() > limit {
            return Err(Reject::TooLarge { coding, limit });
        }
        let room = limit.saturating_add(1).saturating_sub(out.len());
        if room == 0 {
            return Err(Reject::TooLarge { coding, limit });
        }
        let chunk = room.min(buf.len());
        match reader.read(&mut buf[..chunk]) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Reject::Decode { coding }),
        }
    }
    if out.len() > limit {
        Err(Reject::TooLarge { coding, limit })
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn headers(value: &str) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        map.insert(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_str(value).unwrap(),
        );
        map
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zstd_compress(data: &[u8]) -> Vec<u8> {
        zstd::bulk::compress(data, 3).unwrap()
    }

    fn brotli_compress(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            writer.write_all(data).unwrap();
            writer.flush().unwrap();
        }
        out
    }

    fn round_trip(header: &str, expected: &str, compressed: &[u8], plain: &[u8]) {
        let prepared = prepare_request(&headers(header), compressed, 1024).unwrap();
        assert_eq!(prepared.coding, expected);
        assert_eq!(&prepared.body[..], plain);
    }

    #[test]
    fn each_supported_coding_round_trips() {
        let plain = br#"{"input":"Exempla flakt"}"#;
        round_trip("gzip", "gzip", &gzip(plain), plain);
        round_trip("deflate", "deflate", &zlib(plain), plain);
        round_trip("zstd", "zstd", &zstd_compress(plain), plain);
        round_trip("br", "br", &brotli_compress(plain), plain);
        round_trip(" Zstd ", "zstd", &zstd_compress(plain), plain);
    }

    #[test]
    fn identity_borrows_the_original_bytes() {
        let body = br#"{"a":1}"#;
        let prepared = prepare_request(&http::HeaderMap::new(), body, 1024).unwrap();
        assert_eq!(prepared.coding, "identity");
        assert!(matches!(prepared.body, Cow::Borrowed(_)));
        assert_eq!(&prepared.body[..], body);

        let prepared = prepare_request(&headers("identity"), body, 1024).unwrap();
        assert_eq!(&prepared.body[..], body);
    }

    #[test]
    fn unknown_stacked_and_corrupt_do_not_return_the_body() {
        let secret = b"AKIASVCNCANARYKEY001";
        let unknown = prepare_request(&headers("xz"), secret, 1024).unwrap_err();
        assert_eq!(unknown.reason(), "unsupported-content-encoding");
        assert_eq!(unknown.status(), http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(unknown.encoding(), Some("xz"));
        assert!(!unknown.message().contains("AKIA"));

        let stacked = prepare_request(&headers("gzip, zstd"), &gzip(secret), 1024).unwrap_err();
        assert_eq!(stacked.reason(), "stacked-content-encoding");
        assert_eq!(stacked.status().as_u16(), 415);
        assert!(!stacked.message().contains("AKIA"));

        let mut garbage = secret.to_vec();
        garbage.extend_from_slice(b" not-a-zstd-frame");
        let corrupt = prepare_request(&headers("zstd"), &garbage, 1024).unwrap_err();
        assert_eq!(corrupt.reason(), "content-encoding-decode");
        assert_eq!(corrupt.status(), http::StatusCode::BAD_REQUEST);
        assert!(!corrupt.message().contains("AKIA"));

        let mut map = http::HeaderMap::new();
        map.append(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        map.append(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        let two = prepare_request(&map, &gzip(secret), 1024).unwrap_err();
        assert_eq!(two.reason(), "stacked-content-encoding");
    }

    #[test]
    fn over_limit_outputs_are_rejected() {
        let gzip_blob = gzip(&[0u8; 64]);
        let err = prepare_request(&headers("gzip"), &gzip_blob, 16).unwrap_err();
        assert_eq!(err.reason(), "decompressed-body-too-large");
        assert_eq!(err.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
        assert!(err.message().contains("16"));
        assert!(gzip_blob.len() < 64);

        let zstd_blob = zstd_compress(&[0u8; 64]);
        let err = prepare_request(&headers("zstd"), &zstd_blob, 16).unwrap_err();
        assert_eq!(err.reason(), "decompressed-body-too-large");

        let exact = gzip(b"01234567");
        assert_eq!(
            prepare_request(&headers("gzip"), &exact, 8)
                .unwrap()
                .body
                .len(),
            8
        );
    }

    #[test]
    fn compressed_responses_are_not_plaintext() {
        assert!(compressed_response(&http::HeaderMap::new()).is_none());
        assert!(compressed_response(&headers(" identity ")).is_none());
        assert_eq!(
            compressed_response(&headers("gzip")).as_deref(),
            Some("gzip")
        );
        assert_eq!(
            compressed_response(&headers("zstd")).as_deref(),
            Some("zstd")
        );

        let mut stacked = http::HeaderMap::new();
        stacked.append(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_static("identity"),
        );
        stacked.append(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        assert_eq!(compressed_response(&stacked).as_deref(), Some("stacked"));

        let mut binary = http::HeaderMap::new();
        binary.insert(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        let label = compressed_response(&binary).unwrap();
        assert_eq!(label, "invalid");
        assert!(!label.contains('\u{ff}'));
    }
}
