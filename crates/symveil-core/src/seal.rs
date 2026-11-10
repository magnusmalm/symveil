//! AES-256-GCM for the vault file.
//!
//! The `aes-gcm` crate is the cipher. `OsRng` supplies key and nonce bytes.
//! This module does not implement a cipher, a mode, or a random-number generator.

use std::fs;
use std::io;
use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::aead::{AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::perms;

pub(crate) const CIPHER_NAME: &str = "aes-256-gcm";
pub(crate) const KEY_HEADER: &str = "symveil-vault-key-v1";
const AAD: &[u8] = b"symveil-vault-v2 aes-256-gcm";
const SEALED_VERSION: u32 = 2;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug)]
pub(crate) enum SealError {
    NotJson,
    NotObject,
    MissingVersion,
    UnsupportedVersion(u64),
    MixedPlaintext,
    UnknownCipher(String),
    Malformed(&'static str),
    DecryptFailed,
    Crypto,
}

#[derive(Debug)]
pub(crate) enum KeyError {
    Missing,
    Invalid(&'static str),
    Io(io::Error),
}

pub(crate) struct Envelope {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

pub(crate) enum Inspected {
    Plaintext,
    Sealed(Envelope),
}

#[derive(Serialize, Deserialize)]
struct SealedFile {
    version: u32,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

pub(crate) fn inspect(bytes: &[u8]) -> Result<Inspected, SealError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| SealError::NotJson)?;
    let Some(obj) = value.as_object() else {
        return Err(SealError::NotObject);
    };
    let version = match obj.get("version") {
        Some(serde_json::Value::Number(number)) => {
            number.as_u64().ok_or(SealError::MissingVersion)?
        }
        Some(_) | None => return Err(SealError::MissingVersion),
    };
    let looks_sealed =
        obj.contains_key("cipher") || obj.contains_key("ciphertext") || obj.contains_key("nonce");
    match (version, looks_sealed) {
        (1, false) => Ok(Inspected::Plaintext),
        (1, true) => Err(SealError::MixedPlaintext),
        (2, _) => Ok(Inspected::Sealed(parse_envelope(bytes)?)),
        (other, _) => Err(SealError::UnsupportedVersion(other)),
    }
}

pub(crate) fn open_envelope(key: &[u8; 32], envelope: &Envelope) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SealError::Crypto)?;
    let nonce = Nonce::from_slice(&envelope.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: envelope.ciphertext.as_slice(),
                aad: AAD,
            },
        )
        .map_err(|_| SealError::DecryptFailed)
}

pub(crate) fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SealError::Crypto)?;
    let nonce = random_nonce();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| SealError::Crypto)?;
    let file = SealedFile {
        version: SEALED_VERSION,
        cipher: CIPHER_NAME.to_string(),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    };
    let mut bytes = serde_json::to_vec_pretty(&file).map_err(|_| SealError::Crypto)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn read_key(path: &Path) -> Result<[u8; 32], KeyError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(KeyError::Missing),
        Err(err) => return Err(KeyError::Io(err)),
    };
    parse_key(&bytes).map_err(KeyError::Invalid)
}

pub(crate) fn write_new_key(path: &Path, key: &[u8; 32]) -> Result<(), KeyError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            perms::ensure_private_dir(parent).map_err(|err| KeyError::Io(io::Error::other(err)))?;
        }
    }
    perms::create_new_private(path, &encode_key(key)).map_err(KeyError::Io)
}

pub(crate) fn read_or_create_key(path: &Path) -> Result<[u8; 32], KeyError> {
    if path.exists() {
        return read_key(path);
    }
    let key = generate_key();
    match write_new_key(path, &key) {
        Ok(()) => Ok(key),
        Err(KeyError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => read_key(path),
        Err(err) => Err(err),
    }
}

fn parse_envelope(bytes: &[u8]) -> Result<Envelope, SealError> {
    let file: SealedFile =
        serde_json::from_slice(bytes).map_err(|_| SealError::Malformed("envelope"))?;
    if file.version != SEALED_VERSION {
        return Err(SealError::UnsupportedVersion(u64::from(file.version)));
    }
    if file.cipher != CIPHER_NAME {
        return Err(SealError::UnknownCipher(file.cipher));
    }
    let nonce = decode_nonce(&file.nonce)?;
    let ciphertext = STANDARD
        .decode(file.ciphertext.trim())
        .map_err(|_| SealError::Malformed("ciphertext"))?;
    if ciphertext.len() < TAG_LEN {
        return Err(SealError::Malformed("ciphertext"));
    }
    Ok(Envelope { nonce, ciphertext })
}

fn decode_nonce(text: &str) -> Result<[u8; NONCE_LEN], SealError> {
    let bytes = STANDARD
        .decode(text.trim())
        .map_err(|_| SealError::Malformed("nonce"))?;
    bytes.try_into().map_err(|_| SealError::Malformed("nonce"))
}

fn generate_key() -> [u8; 32] {
    let key = Aes256Gcm::generate_key(OsRng);
    let mut out = [0u8; 32];
    out.copy_from_slice(key.as_slice());
    out
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(nonce.as_slice());
    out
}

fn encode_key(key: &[u8; 32]) -> Vec<u8> {
    let body = STANDARD.encode(key);
    let mut out = Vec::with_capacity(KEY_HEADER.len() + body.len() + 2);
    out.extend_from_slice(KEY_HEADER.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body.as_bytes());
    out.push(b'\n');
    out
}

fn parse_key(bytes: &[u8]) -> Result<[u8; 32], &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "the key file is not UTF-8")?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let header = lines.next().ok_or("the key file is empty")?;
    let body = lines.next().ok_or("the key file has no key bytes")?;
    if lines.next().is_some() {
        return Err("the key file has trailing data");
    }
    if header != KEY_HEADER {
        return Err("the header is not symveil-vault-key-v1");
    }
    let decoded = STANDARD
        .decode(body)
        .map_err(|_| "the key body is not base64")?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| "the decoded key is not 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hides_the_plaintext_and_rejects_the_other_key() {
        let secret = b"round-trip-secret-4e91";
        let key = generate_key();
        let sealed = seal(&key, secret).unwrap();
        assert!(!sealed.windows(secret.len()).any(|window| window == secret));
        let Inspected::Sealed(envelope) = inspect(&sealed).unwrap() else {
            panic!("sealed file classified as plaintext");
        };
        assert_eq!(envelope.nonce.len(), NONCE_LEN);
        let opened = open_envelope(&key, &envelope).unwrap();
        assert_eq!(opened, secret);
        let other = generate_key();
        assert!(matches!(
            open_envelope(&other, &envelope),
            Err(SealError::DecryptFailed)
        ));
    }
}
