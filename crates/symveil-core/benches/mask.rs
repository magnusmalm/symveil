//! Criterion benches for redact and restore on the synthetic corpus.
//!
//! `SYMVEIL_BENCH_PROFILE=full` uses about 100k terms. The default profile is
//! `quick` so a bare `cargo bench` finishes. `scripts/bench.sh` sets the
//! profile. `--probe` prints one-shot timings for a term-count sweep and does
//! not run criterion.

use std::time::{Duration, Instant};

use criterion::{black_box, Criterion, Throughput};
use symveil_core::bench_corpus::{payloads, redact_section, Corpus, Profile};
use symveil_core::redact::Engine;
use symveil_core::vault::Vault;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--probe") {
        probe();
        return;
    }
    let profile = Profile::from_env();
    eprintln!(
        "criterion profile={} terms={} people={} filler_bytes={}",
        profile.name, profile.terms, profile.people, profile.filler_bytes
    );
    let mut criterion = Criterion::default()
        .configure_from_args()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    redact_restore(&mut criterion, profile);
}

fn redact_restore(c: &mut Criterion, profile: Profile) {
    let corpus = Corpus::build(profile);
    let plain = corpus.payload("plain").bytes.clone();
    let chat = corpus.payload("openai-chat").bytes.clone();
    let mut engine = corpus.engine();
    let _ = engine.redact_bytes(&plain);

    let mut group = c.benchmark_group(format!("mask/{}", profile.name));
    group.throughput(Throughput::Bytes(plain.len() as u64));
    group.bench_function("redact_plain", |b| {
        b.iter(|| {
            let (out, hits) = engine.redact_bytes(black_box(&plain)).expect("redact");
            black_box((out.len(), hits.len()));
        });
    });
    group.throughput(Throughput::Bytes(chat.len() as u64));
    group.bench_function("redact_openai_chat", |b| {
        b.iter(|| {
            let (out, hits) = engine.redact_bytes(black_box(&chat)).expect("redact");
            black_box((out.len(), hits.len()));
        });
    });
    let (redacted, _) = engine.redact_bytes(&plain).expect("redact");
    group.throughput(Throughput::Bytes(redacted.len() as u64));
    group.bench_function("restore_plain", |b| {
        b.iter(|| {
            let (out, restored) = engine.restore_bytes(black_box(&redacted), false);
            black_box((out.len(), restored));
        });
    });
    group.finish();
}

fn probe() {
    println!("probe,one redaction after compile,synthetic data");
    println!("terms,people,bytes,compile_ms,redact_ms,restore_ms,redact_mb_s,hits");
    let term_counts = [100usize, 1_000, 10_000, 100_000];
    let sizes = [16 * 1024usize, 64 * 1024, 256 * 1024];
    for terms in term_counts {
        for bytes in sizes {
            let mut profile = Profile::full();
            profile.terms = terms;
            profile.people = (terms / 50).clamp(10, 2_000);
            profile.domains = 8;
            profile.secret_rules = 8;
            profile.filler_bytes = bytes;
            profile.messages = 4;
            let started = Instant::now();
            let redact = redact_section(&profile);
            let mut engine = Engine::new(Vault::ephemeral(), &redact).expect("engine");
            let compile_ms = started.elapsed().as_secs_f64() * 1_000.0;
            let payload = payloads(&profile)
                .into_iter()
                .find(|item| item.name == "plain")
                .expect("plain");
            let started = Instant::now();
            let (redacted, hits) = engine.redact_bytes(&payload.bytes).expect("redact");
            let redact_ms = started.elapsed().as_secs_f64() * 1_000.0;
            let started = Instant::now();
            let (restored, _) = engine.restore_bytes(&redacted, false);
            let restore_ms = started.elapsed().as_secs_f64() * 1_000.0;
            let mb_s = (payload.bytes.len() as f64 / 1_000_000.0) / (redact_ms / 1_000.0);
            println!(
                "{terms},{},{},{compile_ms:.1},{redact_ms:.1},{restore_ms:.1},{mb_s:.3},{}",
                profile.people,
                payload.bytes.len(),
                hits.len()
            );
            let _ = std::io::Write::flush(&mut std::io::stdout());
            assert_eq!(restored, payload.bytes);
            std::hint::black_box(redacted.len());
            if redact_ms > 20_000.0 {
                println!("stop,terms={terms},redact_ms={redact_ms:.0},larger payloads skipped");
                break;
            }
        }
    }
}
