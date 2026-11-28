//! Every redact decision has to be masked after the proxy loads `learned.toml`.
//!
//! Hosts, domains, emails, ips, and secrets are `[[secrets]]` rules. Symbols
//! are `[[symbols]]` rules and are merged into the same scanner. Terms and
//! people use the name matcher. Skips are resume rows and are not rules.
//! Keeps are the allow list.

use std::time::{Duration, Instant};

use symveil::config::LearnedCounts;
use symveil::{Config, Engine, Vault};
use symveil_learn::{file_from_decisions, Decision, DecisionAction, LearnCategory};

fn decision(action: DecisionAction, category: LearnCategory, text: impl Into<String>) -> Decision {
    Decision::new(action, category, text)
}

fn masked(engine: &mut Engine, text: &str) -> String {
    let (out, _) = engine.redact_str(text).unwrap();
    assert_eq!(engine.restore_str(&out), text, "{out}");
    out
}

#[test]
fn every_redact_decision_is_masked_and_counted() {
    let email = "user@box.example";
    let domain = "box.example";
    let mut glued = decision(
        DecisionAction::Redact,
        LearnCategory::Secret,
        "SVCNAgentPassw0rd",
    );
    glued.sources = vec!["mysql -pSVCNAgentPassw0rd".into()];
    glued.left_glued = true;
    let decisions = vec![
        decision(DecisionAction::Redact, LearnCategory::Name, "Exempla"),
        decision(DecisionAction::Redact, LearnCategory::Name, "Exemplas"),
        decision(
            DecisionAction::Redact,
            LearnCategory::Person,
            "Ren Testdotter",
        ),
        decision(
            DecisionAction::Redact,
            LearnCategory::Secret,
            "synthSecretToken0001",
        ),
        glued,
        decision(DecisionAction::Redact, LearnCategory::Email, email),
        decision(DecisionAction::Redact, LearnCategory::Ip, "203.0.113.10"),
        decision(
            DecisionAction::Redact,
            LearnCategory::Host,
            "db.tundrahorn.example",
        ),
        decision(DecisionAction::Redact, LearnCategory::Domain, domain),
        decision(
            DecisionAction::Redact,
            LearnCategory::Symbol,
            "tundrahorn_fan_init",
        ),
        decision(DecisionAction::Redact, LearnCategory::Symbol, "TDH-4471"),
        decision(DecisionAction::Skip, LearnCategory::Symbol, "zephyr_marker"),
        decision(DecisionAction::Keep, LearnCategory::Symbol, "threshold"),
    ];
    let file = file_from_decisions(&decisions).unwrap();
    let counts = LearnedCounts::from_file(&file);
    assert_eq!(
        counts.terms, 2,
        "Exempla and Testdotter; Exemplas folds into Exempla"
    );
    assert_eq!(counts.people, 1);
    assert_eq!(counts.secrets, 2);
    assert_eq!(counts.emails, 1);
    assert_eq!(counts.ips, 1);
    assert_eq!(counts.hosts, 1);
    assert_eq!(
        counts.domains, 1,
        "a domain inside an email is still its own rule"
    );
    assert_eq!(counts.symbols, 2);
    assert_eq!(counts.skips, 1);
    assert_eq!(counts.keeps, 1);

    let mut cfg = Config::default();
    cfg.apply_learned_file(&file).unwrap();
    assert!(cfg.learned_loaded);
    assert_eq!(cfg.learned_counts, counts);
    let mut engine = Engine::new(Vault::ephemeral(), &cfg.redact).unwrap();

    for decision in &decisions {
        if decision.action != DecisionAction::Redact {
            continue;
        }
        let out = masked(&mut engine, &decision.text);
        assert!(
            !out.contains(&decision.text),
            "{} {} stayed visible: {out}",
            decision.category,
            decision.text
        );
    }
    let line = masked(&mut engine, "mysql -pSVCNAgentPassw0rd");
    assert!(!line.contains("SVCNAgentPassw0rd"), "{line}");
    let skipped = masked(&mut engine, "zephyr_marker");
    assert!(skipped.contains("zephyr_marker"), "{skipped}");
    let kept = masked(&mut engine, "threshold");
    assert!(kept.contains("threshold"), "{kept}");
}

#[test]
fn three_thousand_literal_rules_load_and_match() {
    let mut decisions = Vec::with_capacity(3_000);
    for index in 0..3_000 {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Secret,
            format!("synthSecret{index}Token"),
        ));
    }
    let text = file_from_decisions(&decisions).unwrap().to_toml().unwrap();
    let started = Instant::now();
    let mut cfg = Config::default();
    cfg.apply_learned_toml(&text).unwrap();
    let mut engine = Engine::new(Vault::ephemeral(), &cfg.redact).unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "loading 3000 literal rules took {elapsed:?}"
    );
    assert_eq!(cfg.learned_counts.secrets, 3_000);
    let out = masked(&mut engine, "prefix synthSecret1500Token suffix");
    assert!(!out.contains("synthSecret1500Token"), "{out}");
    assert!(out.contains("prefix"), "{out}");
}

/// Same shape as a real learned file: 204267 decisions, about 111k redact rules.
///
/// The 10915 terms are the name redact decisions after case-folding dedup.
/// They are not the 111377 non-name redact rules (secrets 25085, symbols
/// 36237, hosts 46040, domains 2000, emails 1000, ips 1015). People are 533
/// and their tokens are three letters, so they are not copied into the term
/// list. Skips are 80664 and write no rule. Keeps are 778 and are the allow
/// list. Those buckets add up to 204267. Nothing is dropped. `symveil check`
/// prints `decisions` and `terms` as separate numbers for that reason.
/// Reading that document with the toml crate was about a second. The direct
/// reader is what the parse gate below is holding onto.
///
/// Run with `cargo test --release --test learned_enforce -- --ignored --nocapture`.
#[test]
#[ignore = "release scale benchmark"]
fn scale_learned_file_loads_and_saves_quickly() {
    const SECRETS: usize = 25_085;
    const SYMBOLS: usize = 36_237;
    const HOSTS: usize = 46_040;
    const DOMAINS: usize = 2_000;
    const EMAILS: usize = 1_000;
    const IPS: usize = 1_015;
    const TERMS: usize = 10_915;
    const PEOPLE: usize = 533;
    const SKIPS: usize = 80_664;
    const KEEPS: usize = 778;

    let mut decisions = Vec::with_capacity(204_267);
    for index in 0..SECRETS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Secret,
            format!("sec{index}token"),
        ));
    }
    for index in 0..SYMBOLS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Symbol,
            format!("sym{index}ident"),
        ));
    }
    for index in 0..HOSTS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Host,
            format!("h{index}.example"),
        ));
    }
    for index in 0..DOMAINS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Domain,
            format!("d{index}.example"),
        ));
    }
    for index in 0..EMAILS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Email,
            format!("u{index}@box.example"),
        ));
    }
    for index in 0..IPS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Ip,
            format!("192.0.2.{index}"),
        ));
    }
    for index in 0..TERMS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Name,
            format!("tn{index:05}zq"),
        ));
    }
    for index in 0..PEOPLE {
        // Three-letter tokens stay people. A token of four letters would also
        // be filed as a term and change the term count.
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Person,
            format!("p{:02} q{:02}", index % 100, index / 100),
        ));
    }
    for index in 0..SKIPS {
        decisions.push(decision(
            DecisionAction::Skip,
            LearnCategory::Symbol,
            format!("skip{index}word"),
        ));
    }
    for index in 0..KEEPS {
        decisions.push(decision(
            DecisionAction::Keep,
            LearnCategory::Symbol,
            format!("keep{index}word"),
        ));
    }
    assert_eq!(decisions.len(), 204_267);

    let save_started = Instant::now();
    let file = file_from_decisions(&decisions).unwrap();
    let built = save_started.elapsed();
    let toml_started = Instant::now();
    let text = file.to_toml().unwrap();
    let toml_elapsed = toml_started.elapsed();
    let save_elapsed = save_started.elapsed();
    let counts = LearnedCounts::from_file(&file);
    assert_eq!(counts.terms, TERMS);
    assert_eq!(counts.people, PEOPLE);
    assert_eq!(counts.secrets, SECRETS);
    assert_eq!(counts.symbols, SYMBOLS);
    assert_eq!(counts.hosts, HOSTS);
    assert_eq!(counts.domains, DOMAINS);
    assert_eq!(counts.emails, EMAILS);
    assert_eq!(counts.ips, IPS);
    assert_eq!(counts.skips, SKIPS);
    assert_eq!(counts.keeps, KEEPS);
    assert_eq!(counts.decisions, 204_267);

    let load_started = Instant::now();
    let mut cfg = Config::default();
    let timing = cfg.apply_learned_toml_timed(&text).unwrap();
    let engine_started = Instant::now();
    let mut engine = Engine::new(Vault::ephemeral(), &cfg.redact).unwrap();
    let engine_elapsed = engine_started.elapsed();
    let load_elapsed = load_started.elapsed();

    let redact_started = Instant::now();
    let sample = "see sec10token and h10.example and tn00010zq and sym10ident and plain text";
    let out = masked(&mut engine, sample);
    let redact_elapsed = redact_started.elapsed();
    assert!(!out.contains("sec10token"), "{out}");
    assert!(!out.contains("h10.example"), "{out}");
    assert!(!out.contains("tn00010zq"), "{out}");
    assert!(!out.contains("sym10ident"), "{out}");
    assert!(out.contains("plain text"), "{out}");

    let body = "alpha beta gamma delta ".repeat(200);
    let body_started = Instant::now();
    let _ = masked(&mut engine, &body);
    let body_elapsed = body_started.elapsed();

    eprintln!(
        "scale decisions={} toml_bytes={} save={save_elapsed:?} build={built:?} toml={toml_elapsed:?} parse={:?} merge={:?} engine={engine_elapsed:?} load={load_elapsed:?} redact_hit={redact_elapsed:?} redact_miss={body_elapsed:?} body_bytes={}",
        decisions.len(),
        text.len(),
        timing.parse,
        timing.merge,
        body.len()
    );
    // toml::from_str on this file was about a second. The direct reader is
    // what keeps parse well under the load gate.
    let parse_limit = if cfg!(debug_assertions) {
        Duration::from_secs(10)
    } else {
        Duration::from_millis(500)
    };
    assert!(
        timing.parse < parse_limit,
        "learned.toml parse took {:?}",
        timing.parse
    );
    let save_limit = if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(5)
    };
    let load_limit = if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(2)
    };
    assert!(
        save_elapsed < save_limit,
        "quit+save at this scale took {save_elapsed:?}"
    );
    assert!(
        load_elapsed < load_limit,
        "learned.toml load plus engine startup took {load_elapsed:?}"
    );
}

/// 100k name terms plus the same ~111k literal rules as the 204k-decision file.
/// Decision count is higher than 200k because the literals and the terms are
/// both present. This test only prints timings. The 2s load gate stays on
/// `scale_learned_file_loads_and_saves_quickly`.
/// Run with `cargo test --release --test learned_enforce -- --ignored --nocapture`.
#[test]
#[ignore = "release scale benchmark"]
fn scale_100k_terms_with_literal_rules() {
    const SECRETS: usize = 25_085;
    const SYMBOLS: usize = 36_237;
    const HOSTS: usize = 46_040;
    const DOMAINS: usize = 2_000;
    const EMAILS: usize = 1_000;
    const IPS: usize = 1_015;
    const TERMS: usize = 100_000;
    const PEOPLE: usize = 2_000;
    const SKIPS: usize = 80_664;
    const KEEPS: usize = 778;

    let mut decisions = Vec::with_capacity(300_000);
    for index in 0..SECRETS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Secret,
            format!("sec{index}token"),
        ));
    }
    for index in 0..SYMBOLS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Symbol,
            format!("sym{index}ident"),
        ));
    }
    for index in 0..HOSTS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Host,
            format!("h{index}.example"),
        ));
    }
    for index in 0..DOMAINS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Domain,
            format!("d{index}.example"),
        ));
    }
    for index in 0..EMAILS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Email,
            format!("u{index}@box.example"),
        ));
    }
    for index in 0..IPS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Ip,
            format!("192.0.2.{index}"),
        ));
    }
    for index in 0..TERMS {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Name,
            format!("tn{index:06}zq"),
        ));
    }
    for index in 0..PEOPLE {
        decisions.push(decision(
            DecisionAction::Redact,
            LearnCategory::Person,
            format!("p{:02} q{:02}", index % 100, index / 100),
        ));
    }
    for index in 0..SKIPS {
        decisions.push(decision(
            DecisionAction::Skip,
            LearnCategory::Symbol,
            format!("skip{index}word"),
        ));
    }
    for index in 0..KEEPS {
        decisions.push(decision(
            DecisionAction::Keep,
            LearnCategory::Symbol,
            format!("keep{index}word"),
        ));
    }

    let save_started = Instant::now();
    let file = file_from_decisions(&decisions).unwrap();
    let text = file.to_toml().unwrap();
    let save_elapsed = save_started.elapsed();
    let counts = LearnedCounts::from_file(&file);
    assert_eq!(counts.terms, TERMS);
    assert_eq!(counts.people, PEOPLE);
    assert_eq!(counts.secrets, SECRETS);
    assert_eq!(counts.symbols, SYMBOLS);

    let load_started = Instant::now();
    let mut cfg = Config::default();
    cfg.apply_learned_toml(&text).unwrap();
    let mut engine = Engine::new(Vault::ephemeral(), &cfg.redact).unwrap();
    let load_elapsed = load_started.elapsed();

    let sample = "see sec10token and h10.example and tn000010zq and tn000010-zq and tn000010zqs and sym10ident and p00 q00 and plain text";
    let redact_started = Instant::now();
    let out = masked(&mut engine, sample);
    let redact_elapsed = redact_started.elapsed();
    assert!(!out.contains("sec10token"), "{out}");
    assert!(!out.contains("h10.example"), "{out}");
    assert!(!out.contains("tn000010zq"), "{out}");
    assert!(!out.contains("tn000010-zq"), "{out}");
    assert!(!out.contains("tn000010zqs"), "{out}");
    assert!(!out.contains("sym10ident"), "{out}");
    assert!(!out.contains("p00"), "{out}");
    assert!(out.contains("plain text"), "{out}");

    let body = "alpha beta gamma delta ".repeat(200);
    let body_started = Instant::now();
    let missed = masked(&mut engine, &body);
    let body_elapsed = body_started.elapsed();
    assert_eq!(missed, body);

    let wide = "alpha beta gamma delta epsilon ".repeat(4_000);
    let wide_started = Instant::now();
    let wide_out = masked(&mut engine, &wide);
    let wide_elapsed = wide_started.elapsed();
    assert_eq!(wide_out, wide);

    eprintln!(
        "scale100k decisions={} toml_bytes={} literals={} save={save_elapsed:?} load={load_elapsed:?} redact_hit={redact_elapsed:?} redact_miss={body_elapsed:?} body_bytes={} wide={wide_elapsed:?} wide_bytes={}",
        decisions.len(),
        text.len(),
        SECRETS + SYMBOLS + HOSTS + DOMAINS + EMAILS + IPS,
        body.len(),
        wide.len()
    );
}
