//! Scores a mechanical pass over the synthetic leak corpus.

use std::fs;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::extract;
use crate::model::{Decision, DecisionAction, LearnCategory};
use crate::session::is_low_signal;
use crate::store::{file_from_decisions, matching_regex};
use crate::walk::{self, WalkOptions};

#[derive(Deserialize)]
struct Seed {
    items: Vec<Item>,
    files: Vec<SeedFile>,
}

#[derive(Deserialize)]
struct Item {
    id: String,
    expect: String,
    family: String,
    value: String,
    carrier: String,
    locations: Vec<String>,
}

#[derive(Deserialize)]
struct SeedFile {
    path: String,
    kind: String,
    #[serde(default)]
    body: Option<String>,
}

#[test]
fn corpus_rules_match_their_source_and_leave_benign_words() {
    let seed_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/leak/seed.json");
    let seed: Seed = serde_json::from_str(&fs::read_to_string(&seed_path).unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "symveil-learn-corpus-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for file in &seed.files {
        if file.kind != "text" {
            continue;
        }
        let Some(body) = &file.body else {
            continue;
        };
        let path = root.join(&file.path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
    }
    let walked = walk::walk(
        &root,
        &WalkOptions {
            max_bytes: 1024 * 1024,
            gitignore: true,
            follow_symlinks: false,
            include_skipped: false,
        },
    )
    .unwrap();
    let candidates = extract::extract(&walked.files);
    let mut decisions = Vec::new();
    for candidate in &candidates {
        if is_low_signal(candidate) || candidate_bucket_other(candidate) {
            continue;
        }
        let mut decision = Decision::new(
            DecisionAction::Redact,
            candidate.category,
            candidate.text.clone(),
        );
        decision.sources = if candidate.sources.is_empty() {
            vec![candidate.context.clone()]
        } else {
            candidate.sources.clone()
        };
        decision.left_glued = candidate.left_glued;
        decision.right_glued = candidate.right_glued;
        decisions.push(decision);
    }

    for decision in decisions.iter().filter(|decision| {
        matches!(
            decision.category,
            LearnCategory::Secret
                | LearnCategory::Symbol
                | LearnCategory::Email
                | LearnCategory::Host
                | LearnCategory::Domain
                | LearnCategory::Ip
        )
    }) {
        let regex = matching_regex(
            &decision.text,
            &decision.sources,
            decision.left_glued,
            decision.right_glued,
        )
        .unwrap_or_else(|err| panic!("{err:#} for {}", decision.text));
        let re = Regex::new(&regex).unwrap();
        let lines: Vec<&str> = decision
            .sources
            .iter()
            .map(String::as_str)
            .filter(|line| line.contains(&decision.text))
            .collect();
        assert!(
            !lines.is_empty() && lines.iter().all(|line| re.is_match(line)),
            "rule {regex} missed a source for {}",
            decision.text
        );
    }

    let learned = file_from_decisions(&decisions).unwrap();
    let benign: Vec<&Item> = seed
        .items
        .iter()
        .filter(|item| item.family == "benign")
        .collect();
    assert_eq!(benign.len(), 14);
    for item in &benign {
        assert!(
            learned_touches(&learned, &item.value).is_none(),
            "benign `{}` was learned",
            item.value
        );
    }

    let agent = seed
        .items
        .iter()
        .find(|item| item.id == "agent-pass")
        .unwrap();
    assert!(
        learned_touches(&learned, &agent.value).is_some(),
        "agent password was not learned"
    );
    assert!(learned
        .names
        .people
        .iter()
        .any(|person| person == "Ren Testdotter"));
    assert!(learned_touches(&learned, "TDH-4471").is_some());
    assert!(learned_touches(&learned, "FAN-ALPHA-2").is_some());
    assert!(learned_touches(&learned, "FAN-BETA-9").is_some());

    let mut recalled = 0usize;
    let mut considered = 0usize;
    for item in &seed.items {
        if item.expect != "masked" {
            continue;
        }
        if item
            .locations
            .iter()
            .all(|location| location.starts_with("session:"))
        {
            continue;
        }
        let in_text = item.locations.iter().any(|location| {
            seed.files
                .iter()
                .any(|file| file.kind == "text" && file.path == *location && file.body.is_some())
        });
        if !in_text {
            continue;
        }
        considered += 1;
        if learned_touches(&learned, &item.value).is_some()
            || learned_touches(&learned, &item.carrier).is_some()
        {
            recalled += 1;
        }
    }
    let entries = learned.names.terms.len()
        + learned.names.people.len()
        + learned.secrets.len()
        + learned.symbols.len();
    let mut useful = 0usize;
    for term in learned
        .names
        .terms
        .iter()
        .chain(learned.names.people.iter())
    {
        if seed.items.iter().any(|item| {
            item.expect == "masked"
                && (covers_term(term, &item.value) || covers_term(term, &item.carrier))
        }) {
            useful += 1;
        }
    }
    for rule in learned.secrets.iter().chain(learned.symbols.iter()) {
        let re = Regex::new(&rule.regex).unwrap();
        if seed.items.iter().any(|item| {
            item.expect == "masked" && (re.is_match(&item.value) || re.is_match(&item.carrier))
        }) {
            useful += 1;
        }
    }
    let recall = recalled as f64 / considered as f64;
    let precision = if entries == 0 {
        0.0
    } else {
        useful as f64 / entries as f64
    };
    eprintln!(
        "learn corpus score: recalled {recalled}/{considered} ({:.0}%) useful {useful}/{entries} ({:.0}%)",
        recall * 100.0,
        precision * 100.0
    );
    assert!(
        recall >= 0.74,
        "recall {recalled}/{considered} is below the previous 74%"
    );
    assert!(
        precision > 0.50,
        "precision {useful}/{entries} did not beat 50%"
    );
    let _ = fs::remove_dir_all(&root);
}

fn candidate_bucket_other(candidate: &crate::model::Candidate) -> bool {
    candidate.category == LearnCategory::Symbol && candidate.rule.as_deref() != Some("product-code")
}

fn learned_touches(
    file: &symveil_detect::learned::LearnedFile,
    value: &str,
) -> Option<&'static str> {
    if file.names.terms.iter().any(|term| covers_term(term, value)) {
        return Some("term");
    }
    if file.names.people.iter().any(|person| {
        value.to_lowercase().contains(&person.to_lowercase())
            || person
                .split_whitespace()
                .all(|token| token.chars().count() >= 3 && covers_term(token, value))
    }) {
        return Some("person");
    }
    for rule in file.secrets.iter().chain(file.symbols.iter()) {
        if Regex::new(&rule.regex).unwrap().is_match(value) {
            return Some("rule");
        }
    }
    None
}

fn covers_term(term: &str, value: &str) -> bool {
    let needle = letters(term);
    if needle.len() < 3 {
        return false;
    }
    letters(value).contains(&needle)
}

fn letters(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}
