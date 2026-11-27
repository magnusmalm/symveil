//! The bench corpus redacts to a fixed byte string.
//!
//! A faster matcher has to keep this hash. The corpus is the `ci` profile of
//! the same generator the release bench uses, small enough for a debug test.

use sha2::{Digest, Sha256};
use symveil_core::bench_corpus::{planted_secrets, write_proxy_config, Corpus, Profile};
use symveil_core::config::Config;
use symveil_core::redact::Engine;
use symveil_core::vault::Vault;

const EXPECTED: &[(&str, &str)] = &[
    (
        "plain",
        "da674b34192946cebb9a5c7086fc0eeca1f8eeb25bb0efd0b6f352c3698ba092",
    ),
    (
        "openai-chat",
        "220ad7ce73224216e8060108242f3c0eea1220062d790248d3ad6066cf65a54e",
    ),
    (
        "anthropic-messages",
        "ed2b1e284747737425b8fc02ff2b9c48f2f7b70381750f1a5fa9434ed244b4b9",
    ),
];

#[test]
fn bench_corpus_redaction_is_byte_stable() {
    let corpus = Corpus::build(Profile::ci());
    let mut engine = corpus.engine();
    let mut mismatches = Vec::new();
    for (name, expected) in EXPECTED {
        let payload = corpus.payload(name);
        let (out, _) = engine.redact_bytes(&payload.bytes).expect("redact");
        let got = hex(&Sha256::digest(&out));
        if got != *expected {
            mismatches.push(format!("{name} {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "redaction bytes changed:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn bench_corpus_round_trips_and_hides_planted_values() {
    let corpus = Corpus::build(Profile::ci());
    let mut engine = corpus.engine();
    for payload in &corpus.payloads {
        let (redacted, hits) = engine.redact_bytes(&payload.bytes).expect("redact");
        assert!(!hits.is_empty(), "{} produced no hits", payload.name);
        let restored = restore(&engine, &redacted);
        assert_eq!(
            restored, payload.bytes,
            "{} did not round-trip",
            payload.name
        );
        let text = String::from_utf8(redacted).expect("redacted utf-8");
        for planted in planted_secrets() {
            assert!(
                !text.contains(&planted),
                "{} still contains {planted}",
                payload.name
            );
        }
        if payload.name == "plain" {
            assert!(
                text.contains("std::env"),
                "a Rust path was rewritten: {text}"
            );
        }
    }
}

#[test]
fn written_config_redacts_the_same_bytes() {
    let corpus = Corpus::build(Profile::ci());
    let dir = std::env::temp_dir().join(format!(
        "symveil-bench-cfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(".symveil.toml");
    write_proxy_config(&path, &corpus.redact).expect("write config");
    let text = std::fs::read_to_string(&path).expect("read config");
    let cfg = Config::parse(&text).expect("parse config");
    let mut from_file = Engine::new(Vault::ephemeral(), &cfg.redact).expect("engine");
    let mut in_memory = corpus.engine();
    for payload in &corpus.payloads {
        let (left, _) = in_memory.redact_bytes(&payload.bytes).expect("memory");
        let (right, _) = from_file.redact_bytes(&payload.bytes).expect("file");
        assert_eq!(left, right, "{}", payload.name);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn restore(engine: &Engine, redacted: &[u8]) -> Vec<u8> {
    let (out, _) = engine.restore_bytes(redacted, false);
    out
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}
