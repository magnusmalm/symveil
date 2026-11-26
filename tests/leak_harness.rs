//! Synthetic leak measurement with the A–D fixes combined. Configured names are
//! covered. The verdict stays NOT SAFE until three clean runs and a real-client
//! pass. Gated canaries that reach the mock fail this test.

#[path = "leak_harness/corpus.rs"]
mod corpus;
#[path = "leak_harness/mock.rs"]
mod mock;
#[path = "leak_harness/model.rs"]
mod model;
#[path = "leak_harness/proxy.rs"]
mod proxy;
#[path = "leak_harness/report.rs"]
mod report;
#[path = "leak_harness/scan.rs"]
mod scan;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use model::{Expect, Item, Seed};
use proxy::EchoMode;
use report::{CategoryRow, Check, Finding, ItemRow, Run, SideRow};
use serde_json::{json, Value};
use symveil::build_engine;
use symveil::config::{NamesSection, PiiSection, RedactSection, SecretRule, UserPattern};
use symveil::vault::Vault;

const COMMAND_FILES: &[&str] = &[
    "ops/printenv.txt",
    "ops/docker-inspect.json",
    "ops/pytest-traceback.txt",
    "home/jdoe/.bash_history",
    "ops/agent-settings.json",
    "logs/fan-error.log",
    "tools/test_fan.py",
];

#[test]
fn leak_corpus() {
    let root = manifest().join("target/leak-corpus");
    let name = root
        .file_name()
        .and_then(|item| item.to_str())
        .unwrap_or("");
    assert_eq!(name, "leak-corpus", "refusing to reset {name}");
    let seed = Seed::load(&manifest().join("tests/leak/seed.json")).expect("seed");
    corpus::generate(&seed, &root).expect("generate");
    assert!(
        root.join("firmware/tundrahorn_fan.c").is_file(),
        "corpus missing firmware/tundrahorn_fan.c"
    );
    eprintln!("corpus: {}", root.display());
}

#[test]
fn leak_canary_shapes() {
    let seed = Seed::load(&manifest().join("tests/leak/seed.json")).expect("seed");
    let mut engine = build_engine(Vault::ephemeral(), &evaluated_redact()).expect("engine");
    for item in &seed.items {
        let Some(rule) = item.rule.as_deref() else {
            continue;
        };
        if item.expect != Expect::Masked {
            continue;
        }
        let (output, hits) = engine
            .redact_str(&item.carrier)
            .unwrap_or_else(|err| panic!("{} redact: {err}", item.id));
        assert!(
            hits.iter().any(|hit| hit.rule.as_deref() == Some(rule)),
            "{} did not hit {rule}",
            item.id
        );
        assert!(
            !output.contains(&item.value),
            "{} carrier still contains the value",
            item.id
        );
    }
    for item in &seed.items {
        if item.expect == Expect::Masked {
            continue;
        }
        let (output, _) = engine
            .redact_str(&item.carrier)
            .unwrap_or_else(|err| panic!("{} redact: {err}", item.id));
        if item.id == "keep-numeric-env" {
            assert!(output.contains("12345678"), "{output}");
            assert!(!output.contains("TDH_API_KEY"), "{output}");
            continue;
        }
        if item.family == "path" {
            let lower = output.to_lowercase();
            assert!(!lower.contains("exempla"), "{} {output}", item.id);
            assert!(!lower.contains("tundrahorn"), "{} {output}", item.id);
            if item.carrier.contains("jdoe") {
                assert!(output.contains("jdoe"), "{output}");
            }
            continue;
        }
        assert_eq!(output, item.carrier, "visible carrier changed: {}", item.id);
    }
}

#[tokio::test]
async fn leak_measurement() {
    let run = measure().await.expect("measurement");
    let markdown = run.to_markdown();
    let mut problems = gate_problems(&run);
    if run.verdict != "NOT SAFE" {
        problems.push("verdict must be NOT SAFE on this free build".to_string());
    }
    let streak = run
        .reasons
        .iter()
        .any(|reason| reason.contains("three are required"));
    let clients = run
        .reasons
        .iter()
        .any(|reason| reason.contains("were not run"));
    if !streak || !clients {
        problems.push(
            "verdict must stay NOT SAFE until three clean runs and a real-client pass".to_string(),
        );
    }
    if run.reasons.iter().any(|reason| {
        reason
            .to_ascii_lowercase()
            .contains("names are not covered")
    }) {
        problems.push(
            "configured [redact.names] terms are covered; the verdict must not say otherwise"
                .to_string(),
        );
    }
    let gated = run.gated_leak_ids();
    if !gated.is_empty() {
        problems.push(format!("gated leaks: {}", gated.join(", ")));
    }
    if problems.is_empty() {
        eprintln!(
            "{}\ngated leaks: {}\nreport: {}/report.md",
            run.verdict,
            gated.len(),
            std::env::var("SYMVEIL_LEAK_OUT").unwrap_or_else(|_| "target/leak-report".into())
        );
        return;
    }
    eprintln!("{markdown}");
    panic!(
        "{}\nreport: {}",
        problems.join("\n"),
        report_dir().join("report.md").display()
    );
}

async fn measure() -> Result<Run> {
    let out = prepare_out()?;
    let seed = Seed::load(&manifest().join("tests/leak/seed.json"))?;
    let baseline = load_baseline(&manifest().join("tests/leak/baseline.json"))?;
    let idempotent = check_idempotent(&seed, &out)?;
    let corpus = out.join("corpus");
    corpus::generate(&seed, &corpus)?;
    let transcript = corpus::transcript(&corpus)?;
    let bundle = command_bundle(&corpus)?;
    let mut harness_errors = needle_collisions(&seed);
    let isolated = isolated_mask(&seed)?;

    let mock = mock::Mock::spawn().await;
    let home = out.join("home");
    let config = proxy::write_config(&corpus, &config_text("enforce", false, true, &[], None))?;
    let proxy = proxy::spawn_proxy(&bin(), &corpus, &config, &mock.base, &mock.base, &home)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("http client")?;
    if let Err(err) = proxy::wait_healthy(&client, &proxy.url).await {
        harness_errors.push(format!("{err:#}"));
        harness_errors.push(proxy.stderr());
    }

    let mut sent = Vec::new();
    let mut restores = Vec::new();
    let mut wire = Wire {
        client: &client,
        proxy: &proxy.url,
        sent: &mut sent,
        errors: &mut harness_errors,
    };
    send_corpus(&mut wire, &transcript, &bundle, &seed, &mut restores).await;
    drop(proxy);
    let recorded = mock.recorded();
    let sessions = pair_sessions(&sent, &recorded, &mut harness_errors);

    let cli = cli_text(&out, &transcript, &mut harness_errors)?;
    let json_files = cli_json_files(&out, &corpus, &seed, &mut harness_errors)?;
    let pii_off = pii_off(&out, &transcript, &seed, &mut harness_errors)?;
    let high_entropy = high_entropy_side(&out, &seed, &mut harness_errors)?;
    let policies = policy_checks(&out, &seed, &mut harness_errors).await;

    let run = assemble(
        &seed,
        &baseline,
        &sessions,
        &transcript,
        &cli,
        &json_files,
        &isolated,
        idempotent,
        restores,
        policies,
        pii_off,
        high_entropy,
        harness_errors,
    );
    run.write(&out)?;
    Ok(run)
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    seed: &Seed,
    baseline: &[String],
    sessions: &[Session],
    transcript: &str,
    cli: &str,
    json_files: &BTreeMap<String, Vec<String>>,
    isolated: &BTreeMap<String, bool>,
    idempotent: bool,
    restores: Vec<Check>,
    policies: Vec<Check>,
    pii_off: Vec<SideRow>,
    high_entropy: Vec<SideRow>,
    harness_errors: Vec<String>,
) -> Run {
    let mut items = Vec::new();
    let mut keep_missing = Vec::new();
    let mut false_positives = Vec::new();
    for item in &seed.items {
        let leaks = leak_sessions(item, sessions);
        let present_sessions = sessions_with(item, sessions);
        let present = !present_sessions.is_empty();
        let sent = sent_anywhere(item, sessions);
        let in_transcript = transcript.contains(&item.value);
        let cli_text_leak =
            item.expect == Expect::Masked && in_transcript && cli.contains(&item.value);
        let cli_json = json_files.get(&item.id).cloned().unwrap_or_default();
        let cli_json_gate = item.expect == Expect::Masked
            && isolated.get(&item.id).copied().unwrap_or(false)
            && !cli_json.is_empty();
        if item.family == "keep" && missing_where_sent(item, sessions) {
            keep_missing.push(item.id.clone());
        }
        if item.family == "benign" && sent && !present {
            false_positives.push(item.id.clone());
        }
        items.push(ItemRow {
            id: item.id.clone(),
            category: item.category.clone(),
            family: item.family.clone(),
            expect: expect_name(item.expect).to_string(),
            claim: claim_of(item).to_string(),
            proxy_leak_sessions: leaks,
            cli_text_leak,
            cli_json_files: cli_json,
            cli_json_gate,
            upstream_present: present,
            present_sessions,
            sent,
        });
    }
    let categories = category_rows(&items);
    let findings = findings_of(seed, &items, isolated);
    let fp_rise: Vec<String> = false_positives
        .iter()
        .filter(|id| !baseline.iter().any(|known| known == *id))
        .cloned()
        .collect();
    let gated: Vec<String> = items
        .iter()
        .filter(|row| row.expect == "masked")
        .filter(|row| {
            !row.sent
                || !row.proxy_leak_sessions.is_empty()
                || row.cli_text_leak
                || row.cli_json_gate
        })
        .map(|row| row.id.clone())
        .collect();
    let names_reached = items
        .iter()
        .any(|row| row.family == "work-code-name" && row.upstream_present);
    let restores_ok = restores.iter().all(|check| check.pass);
    let policies_ok = policies.iter().all(|check| check.pass);
    let pii_ok = pii_off.iter().all(|row| !row.masked);
    // A clean run includes a real-client pass. This harness never runs one.
    let real_client_pass = false;
    let this_run_clean = gated.is_empty()
        && !names_reached
        && fp_rise.is_empty()
        && keep_missing.is_empty()
        && restores_ok
        && policies_ok
        && pii_ok
        && idempotent
        && harness_errors.is_empty()
        && real_client_pass;
    let streak = if this_run_clean { 1 } else { 0 };
    let (verdict, reasons) = verdict(gated.is_empty(), names_reached, streak);
    let base64_leaked = items.iter().any(|row| {
        row.family == "base64" && (!row.proxy_leak_sessions.is_empty() || row.cli_text_leak)
    });
    Run {
        about: seed.about.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        sha: git_sha(),
        identifiers: cfg!(feature = "identifiers"),
        verdict,
        reasons,
        categories,
        items,
        findings,
        restores,
        policies,
        baseline: baseline.to_vec(),
        false_positives,
        fp_rise,
        keep_missing,
        idempotent,
        pii_off,
        high_entropy,
        streak,
        this_run_clean,
        harness_errors,
        recommendation: recommendation(base64_leaked, names_reached),
    }
}

fn verdict(gated_clear: bool, names_reached: bool, streak: u32) -> (String, Vec<String>) {
    let mut reasons = Vec::new();
    if names_reached {
        reasons.push(
            "Company, project, or code names reached the mock. [redact.names] covers those terms on this build. Safe for work code requires zero of those leaks."
                .to_string(),
        );
    }
    if !gated_clear {
        reasons.push(
            "One or more gated canaries reached a covered channel. The findings list the ids."
                .to_string(),
        );
    }
    if streak < 3 {
        reasons.push(format!(
            "Consecutive clean runs are {streak}; three are required. A clean run is zero gated leaks, zero work-code-name canaries upstream, and a real-client pass. This harness does not loop a run that is not clean."
        ));
    }
    reasons.push(
        "Claude Code and Grok Build were not run. tests/leak/RUNBOOK.md is the procedure for Magnus's host, on the synthetic repo only."
            .to_string(),
    );
    let label = if reasons.is_empty() {
        "SAFE"
    } else {
        "NOT SAFE"
    };
    (label.to_string(), reasons)
}

fn recommendation(base64_leaked: bool, names_reached: bool) -> String {
    let mut text = String::from(
        "NOT SAFE to point SymVeil at a real proprietary codebase until this config has three consecutive clean runs and a real-client pass on Magnus's host. [redact.names] covers the configured company, product, project, and person names. Usernames and whole paths are still not a rule.",
    );
    if names_reached {
        text.push_str(" The planted names reached the mock.");
    }
    if base64_leaked {
        text.push_str(
            " Base64-encoded secrets reached the mock with high_entropy left off. Turning that flag on is not the fix: decode base64 and rescan with the builtin rules.",
        );
    }
    text.push_str(
        " Real clients have not been run, and there is no streak of three clean runs. A synthetic-only trial with personal-data rules on and mode set to enforce is what tests/leak/RUNBOOK.md is for. That trial is still not a sandbox.",
    );
    text
}

fn gate_problems(run: &Run) -> Vec<String> {
    let mut problems = Vec::new();
    if !run.idempotent {
        problems.push("corpus generation was not idempotent".to_string());
    }
    for err in &run.harness_errors {
        problems.push(format!("harness: {err}"));
    }
    for row in &run.items {
        if row.expect != "masked" {
            continue;
        }
        if !row.sent {
            problems.push(format!("{} was never sent", row.id));
        }
        if !row.proxy_leak_sessions.is_empty() {
            problems.push(format!(
                "{} reached the mock ({})",
                row.id,
                row.proxy_leak_sessions.join(", ")
            ));
        }
        if row.cli_text_leak {
            problems.push(format!(
                "{} survived symveil redact on the transcript",
                row.id
            ));
        }
        if row.cli_json_gate {
            problems.push(format!(
                "{} survived symveil redact of a JSON file ({})",
                row.id,
                row.cli_json_files.join(", ")
            ));
        }
    }
    for id in &run.keep_missing {
        problems.push(format!("keep phrase disappeared: {id}"));
    }
    for id in &run.fp_rise {
        problems.push(format!("false positive rise: {id}"));
    }
    for check in run.restores.iter().chain(run.policies.iter()) {
        if !check.pass {
            problems.push(format!("{}: {}", check.name, check.detail));
        }
    }
    for row in &run.pii_off {
        if row.masked {
            problems.push(format!("{} was masked with personal data off", row.id));
        }
    }
    problems
}

fn findings_of(seed: &Seed, items: &[ItemRow], isolated: &BTreeMap<String, bool>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut name_ids = Vec::new();
    let mut name_sessions = BTreeSet::new();
    let mut name_locations = BTreeSet::new();
    for item in &seed.items {
        let row = items.iter().find(|row| row.id == item.id);
        let Some(row) = row else { continue };
        let locations: Vec<String> = item
            .locations
            .iter()
            .filter(|loc| !loc.starts_with("session:"))
            .cloned()
            .collect();
        if item.family == "work-code-name" {
            if row.upstream_present {
                name_ids.push(item.id.clone());
                name_sessions.extend(row.present_sessions.iter().cloned());
                name_locations.extend(locations.iter().cloned());
            }
            continue;
        }
        let gated = item.expect == Expect::Masked;
        let proxy_leak = gated && !row.proxy_leak_sessions.is_empty();
        let cli_leak = gated && row.cli_text_leak;
        let json_gate = gated
            && isolated.get(&item.id).copied().unwrap_or(false)
            && !row.cli_json_files.is_empty();
        let json_context = gated
            && !isolated.get(&item.id).copied().unwrap_or(false)
            && !row.cli_json_files.is_empty();
        if proxy_leak || cli_leak || json_gate {
            let mut sessions = row.proxy_leak_sessions.clone();
            if cli_leak {
                sessions.push("redact-cli".to_string());
            }
            if json_gate {
                sessions.extend(
                    row.cli_json_files
                        .iter()
                        .map(|path| format!("redact-cli:{path}")),
                );
            }
            out.push(Finding {
                id: item.id.clone(),
                severity: item.severity.clone().unwrap_or_else(|| "high".to_string()),
                sessions,
                locations: locations.clone(),
                repro: item.repro.clone().unwrap_or_else(|| {
                    format!(
                        "Canary {} reached a covered channel. The file corpus or the named session contains it.",
                        item.id
                    )
                }),
                fix: item.fix.clone().unwrap_or_else(|| {
                    "The evaluated config claims this shape. See the session list. Do not treat a missing rule as a pass."
                        .to_string()
                }),
            });
        }
        if json_context {
            out.push(Finding {
                id: format!("cli-json-context {}", item.id),
                severity: "medium".to_string(),
                sessions: row
                    .cli_json_files
                    .iter()
                    .map(|path| format!("redact-cli:{path}"))
                    .collect(),
                locations: locations.clone(),
                repro: format!(
                    "symveil redact on the JSON file still contains canary {}. The value alone is not a token; the proxy sees it only when the surrounding assignment is inside a string.",
                    item.id
                ),
                fix: "redact_bytes scans JSON string values and skips the key that sits beside them. Scan the raw text, or keep the assignment in view. This is not a proxy-channel leak by itself.".to_string(),
            });
        }
        let interesting = matches!(item.family.as_str(), "gap" | "exception" | "path");
        if interesting && row.upstream_present {
            out.push(Finding {
                id: item.id.clone(),
                severity: item.severity.clone().unwrap_or_else(|| "info".to_string()),
                sessions: row.present_sessions.clone(),
                locations,
                repro: item.repro.clone().unwrap_or_else(|| {
                    format!(
                        "Canary {} is not a claimed rule. It was present upstream.",
                        item.id
                    )
                }),
                fix: item.fix.clone().unwrap_or_else(|| {
                    "Not covered on this build. Do not count it as a pass.".to_string()
                }),
            });
        }
    }
    if !name_ids.is_empty() {
        out.insert(
            0,
            Finding {
                id: "work-code-names".to_string(),
                severity: "high".to_string(),
                sessions: name_sessions.into_iter().collect(),
                locations: name_locations.into_iter().collect(),
                repro: format!(
                    "Configured name terms reached the mock. Ids present upstream: {}.",
                    name_ids.join(", ")
                ),
                fix: "[redact.names] should have masked these terms. The safe-for-work-code verdict stays NOT SAFE until three clean runs and a real-client pass.".to_string(),
            },
        );
    }
    out
}

struct Session {
    name: String,
    sent: String,
    upstream: Vec<u8>,
}

fn leak_sessions(item: &Item, sessions: &[Session]) -> Vec<String> {
    if item.expect != Expect::Masked {
        return Vec::new();
    }
    let needles = scan::leak_needles(&item.value);
    let mut names = Vec::new();
    for session in sessions {
        if scan::contains_any(&session.upstream, &needles).is_some() {
            names.push(session.name.clone());
        }
    }
    names
}

fn sessions_with(item: &Item, sessions: &[Session]) -> Vec<String> {
    let needles = scan::presence_needles(&item.value);
    sessions
        .iter()
        .filter(|session| scan::contains_any(&session.upstream, &needles).is_some())
        .map(|session| session.name.clone())
        .collect()
}

fn sent_anywhere(item: &Item, sessions: &[Session]) -> bool {
    let needles = scan::presence_needles(&item.value);
    sessions
        .iter()
        .any(|session| needles.iter().any(|needle| session.sent.contains(needle)))
}

fn missing_where_sent(item: &Item, sessions: &[Session]) -> bool {
    // TDH is a configured name, so the keep is the numeric value, not the prefix.
    let needles = if item.id == "keep-numeric-env" {
        scan::presence_needles("12345678")
    } else {
        scan::presence_needles(&item.value)
    };
    let mut saw = false;
    for session in sessions {
        if !needles.iter().any(|needle| session.sent.contains(needle)) {
            continue;
        }
        saw = true;
        if scan::contains_any(&session.upstream, &needles).is_none() {
            return true;
        }
    }
    !saw
}

fn category_rows(items: &[ItemRow]) -> Vec<CategoryRow> {
    let mut groups: BTreeMap<(String, String), Vec<&ItemRow>> = BTreeMap::new();
    for item in items {
        groups
            .entry((item.category.clone(), item.claim.clone()))
            .or_default()
            .push(item);
    }
    groups
        .into_iter()
        .map(|((category, claim), rows)| {
            let planted = rows.len();
            let reached = rows.iter().filter(|row| row.upstream_present).count();
            if claim == "not-covered" {
                return CategoryRow {
                    category,
                    claim,
                    planted,
                    masked: None,
                    missed: 0,
                    reached,
                    status: "not covered".to_string(),
                };
            }
            let missed = rows
                .iter()
                .filter(|row| {
                    !row.sent
                        || !row.proxy_leak_sessions.is_empty()
                        || row.cli_text_leak
                        || row.cli_json_gate
                })
                .count();
            let status = if missed == 0 { "pass" } else { "leak" };
            CategoryRow {
                category,
                claim,
                planted,
                masked: Some(planted - missed),
                missed,
                reached,
                status: status.to_string(),
            }
        })
        .collect()
}

fn claim_of(item: &Item) -> &'static str {
    if item.family == "base64" {
        "measurement-bar"
    } else if item.expect == Expect::Masked {
        "covered"
    } else {
        "not-covered"
    }
}

fn expect_name(expect: Expect) -> &'static str {
    match expect {
        Expect::Masked => "masked",
        Expect::Visible => "visible",
        Expect::Keep => "keep",
    }
}

struct Wire<'a> {
    client: &'a reqwest::Client,
    proxy: &'a str,
    sent: &'a mut Vec<(String, String)>,
    errors: &'a mut Vec<String>,
}

async fn send_corpus(
    wire: &mut Wire<'_>,
    transcript: &str,
    bundle: &str,
    seed: &Seed,
    restores: &mut Vec<Check>,
) {
    let calls = [
        (
            "messages-transcript",
            "/v1/messages",
            EchoMode::None,
            messages_text(transcript, false),
        ),
        (
            "messages-tools",
            "/v1/messages",
            EchoMode::None,
            messages_tool(bundle),
        ),
        (
            "responses-transcript",
            "/v1/responses",
            EchoMode::None,
            responses_text(transcript, false),
        ),
        (
            "responses-tools",
            "/v1/responses",
            EchoMode::None,
            responses_tool(bundle),
        ),
    ];
    for (name, path, echo, body) in calls {
        post_sent(wire, name, path, echo, &body).await;
    }
    if let Ok(item) = seed.item("aws-json-key") {
        post_sent(
            wire,
            "json-key",
            "/v1/messages",
            EchoMode::None,
            &json_key_body(&item.value),
        )
        .await;
    }
    if let Ok(item) = seed.item("pn-json") {
        post_sent(
            wire,
            "json-number",
            "/v1/responses",
            EchoMode::None,
            &json_number_body(&item.value),
        )
        .await;
    }
    let text = seed.restore_text.clone();
    let tool = seed.restore_tool.clone();
    let restore_calls = [
        (
            "restore-messages-text",
            "/v1/messages",
            EchoMode::MessagesText,
            with_echo(messages_text("ping", false), &text),
            text.clone(),
        ),
        (
            "restore-messages-text-stream",
            "/v1/messages",
            EchoMode::MessagesTextStream,
            with_echo(messages_text("ping", true), &text),
            text.clone(),
        ),
        (
            "restore-responses-text",
            "/v1/responses",
            EchoMode::ResponsesText,
            with_echo(responses_text("ping", false), &text),
            text.clone(),
        ),
        (
            "restore-responses-text-stream",
            "/v1/responses",
            EchoMode::ResponsesTextStream,
            with_echo(responses_text("ping", true), &text),
            text,
        ),
        (
            "restore-messages-tool",
            "/v1/messages",
            EchoMode::MessagesToolStream,
            with_echo(messages_text("ping", true), &tool),
            tool.clone(),
        ),
        (
            "restore-responses-tool",
            "/v1/responses",
            EchoMode::ResponsesToolStream,
            with_echo(responses_text("ping", true), &tool),
            tool,
        ),
    ];
    for (name, path, echo, body, original) in restore_calls {
        let reply = post_sent(wire, name, path, echo, &body).await;
        let Some(reply) = reply else {
            restores.push(Check {
                name: name.to_string(),
                pass: false,
                detail: "request failed".to_string(),
            });
            continue;
        };
        let restored = proxy::restored_text(&reply.body, echo);
        let pass = reply.status == 200 && restored.as_ref().ok() == Some(&original);
        let detail = if pass {
            "restored text matches the original".to_string()
        } else {
            format!(
                "status {} restored_len {} expected_len {}",
                reply.status,
                restored.as_ref().map(|text| text.len()).unwrap_or(0),
                original.len()
            )
        };
        restores.push(Check {
            name: name.to_string(),
            pass,
            detail,
        });
    }
}

async fn post_sent(
    wire: &mut Wire<'_>,
    name: &str,
    path: &str,
    echo: EchoMode,
    body: &Value,
) -> Option<proxy::HttpReply> {
    let bytes = body.to_string();
    wire.sent.push((name.to_string(), bytes));
    match proxy::post_json(wire.client, wire.proxy, path, name, echo, body).await {
        Ok(reply) => Some(reply),
        Err(err) => {
            wire.errors.push(format!("{name}: {err:#}"));
            None
        }
    }
}

fn pair_sessions(
    sent: &[(String, String)],
    recorded: &[mock::Recorded],
    errors: &mut Vec<String>,
) -> Vec<Session> {
    let mut out = Vec::new();
    for (name, body) in sent {
        let hits: Vec<&mock::Recorded> =
            recorded.iter().filter(|hit| hit.session == *name).collect();
        if hits.is_empty() {
            errors.push(format!("{name} was not recorded by the mock"));
            continue;
        }
        let mut upstream = Vec::new();
        for hit in hits {
            if !hit.path.starts_with("/v1/") {
                errors.push(format!("{} was recorded at {}", name, hit.path));
            }
            upstream.extend(&hit.body);
            upstream.push(b'\n');
        }
        out.push(Session {
            name: name.clone(),
            sent: body.clone(),
            upstream,
        });
    }
    out
}

fn cli_text(out: &Path, transcript: &str, errors: &mut Vec<String>) -> Result<String> {
    let repo = out.join("cli-text");
    let config = proxy::write_config(&repo, &config_text("enforce", false, true, &[], None))?;
    let result = proxy::redact_stdin(
        &bin(),
        &repo,
        &config,
        &out.join("home-cli"),
        transcript.as_bytes(),
    )?;
    if result.code != 0 {
        errors.push(format!(
            "symveil redact exited {}: {}",
            result.code, result.stderr
        ));
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

fn cli_json_files(
    out: &Path,
    corpus: &Path,
    seed: &Seed,
    errors: &mut Vec<String>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let repo = out.join("cli-json");
    let config = proxy::write_config(&repo, &config_text("enforce", false, true, &[], None))?;
    let files = corpus::snapshot(corpus)?;
    let mut hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (rel, bytes) in files {
        if rel.split('/').any(|part| part == ".symveil") {
            continue;
        }
        if serde_json::from_slice::<Value>(&bytes).is_err() {
            continue;
        }
        let result = proxy::redact_stdin(&bin(), &repo, &config, &out.join("home-json"), &bytes)?;
        if result.code != 0 {
            errors.push(format!(
                "redact {rel} exited {}: {}",
                result.code, result.stderr
            ));
            continue;
        }
        let text = String::from_utf8_lossy(&result.stdout);
        for item in &seed.items {
            if item.expect != Expect::Masked {
                continue;
            }
            if !scan::find_bytes(&bytes, item.value.as_bytes()) {
                continue;
            }
            if text.contains(&item.value) {
                hits.entry(item.id.clone()).or_default().push(rel.clone());
            }
        }
    }
    Ok(hits)
}

fn pii_off(
    out: &Path,
    transcript: &str,
    seed: &Seed,
    errors: &mut Vec<String>,
) -> Result<Vec<SideRow>> {
    let repo = out.join("pii-off");
    let config = proxy::write_config(&repo, &config_text("enforce", false, false, &[], None))?;
    let result = proxy::redact_stdin(
        &bin(),
        &repo,
        &config,
        &out.join("home-pii"),
        transcript.as_bytes(),
    )?;
    if result.code != 0 {
        errors.push(format!(
            "pii-off redact exited {}: {}",
            result.code, result.stderr
        ));
    }
    let text = String::from_utf8_lossy(&result.stdout);
    let mut rows = Vec::new();
    for item in seed.items.iter().filter(|item| item.family == "pii") {
        if !transcript.contains(&item.value) {
            rows.push(SideRow {
                id: item.id.clone(),
                masked: false,
                detail: "not in the transcript".to_string(),
            });
            continue;
        }
        let absent = !text.contains(&item.value);
        let company_in_address = item.value.to_ascii_lowercase().contains("exempla");
        let local_kept = item
            .value
            .split('@')
            .next()
            .is_some_and(|local| !local.is_empty() && text.contains(local));
        if company_in_address {
            rows.push(SideRow {
                id: item.id.clone(),
                masked: !local_kept,
                detail: if local_kept {
                    "email rule is off; the configured term Exempla inside the domain is masked and the local-part stays".to_string()
                } else {
                    "local-part disappeared while personal data flags are off".to_string()
                },
            });
            continue;
        }
        rows.push(SideRow {
            id: item.id.clone(),
            masked: absent,
            detail: if absent {
                "absent from stdout while personal data flags are off".to_string()
            } else {
                "still present, as required when the flags are off".to_string()
            },
        });
    }
    Ok(rows)
}

fn high_entropy_side(out: &Path, seed: &Seed, errors: &mut Vec<String>) -> Result<Vec<SideRow>> {
    let repo = out.join("high-entropy");
    let config = proxy::write_config(&repo, &config_text("enforce", true, true, &[], None))?;
    let mut rows = Vec::new();
    for item in seed.items.iter().filter(|item| item.family == "base64") {
        let result = proxy::redact_stdin(
            &bin(),
            &repo,
            &config,
            &out.join("home-entropy"),
            item.value.as_bytes(),
        )?;
        if result.code != 0 {
            errors.push(format!("high_entropy {} exited {}", item.id, result.code));
        }
        let text = String::from_utf8_lossy(&result.stdout);
        let masked = !text.contains(&item.value);
        rows.push(SideRow {
            id: item.id.clone(),
            masked,
            detail: "side measurement only; high_entropy stays off for the gate".to_string(),
        });
    }
    Ok(rows)
}

async fn policy_checks(out: &Path, seed: &Seed, errors: &mut Vec<String>) -> Vec<Check> {
    let mut checks = Vec::new();
    let aws = seed
        .item("aws-access-key")
        .map(|item| item.value.clone())
        .ok();
    let pat = seed.item("github-pat").map(|item| item.value.clone()).ok();
    let custom = seed.item("custom-tdh").map(|item| item.value.clone()).ok();
    let Some(aws) = aws else {
        errors.push("missing aws-access-key".to_string());
        return checks;
    };
    checks.push(policy_block(out, &aws).await);
    if let Some(pat) = pat {
        checks.push(policy_warn(out, &pat).await);
    }
    checks.push(policy_observe(out, &aws).await);
    if let Some(custom) = custom {
        checks.push(policy_custom(out, &aws, &custom).await);
    }
    checks
}

async fn policy_block(out: &Path, aws: &str) -> Check {
    let repo = out.join("policy-block");
    let (proxy, mock, client) = match policy_proxy(
        &repo,
        &config_text(
            "enforce",
            false,
            true,
            &[("aws-access-key-id", "block")],
            None,
        ),
    )
    .await
    {
        Ok(started) => started,
        Err(err) => return fail("policy block", &format!("{err:#}")),
    };
    let text = format!("fläkt {aws}");
    let messages = proxy::post_json(
        &client,
        &proxy.url,
        "/v1/messages",
        "block-messages",
        EchoMode::None,
        &messages_text(&text, false),
    )
    .await;
    let responses = proxy::post_json(
        &client,
        &proxy.url,
        "/v1/responses",
        "block-responses",
        EchoMode::None,
        &responses_text(&text, false),
    )
    .await;
    drop(proxy);
    let recorded = mock.recorded();
    let mut detail = Vec::new();
    let mut pass = recorded.is_empty();
    if !recorded.is_empty() {
        detail.push(format!("mock saw {} requests", recorded.len()));
    }
    pass &= check_block("messages", messages, aws, true, &mut detail);
    pass &= check_block("responses", responses, aws, false, &mut detail);
    Check {
        name: "policy block aws-access-key-id".to_string(),
        pass,
        detail: if detail.is_empty() {
            "400 on /v1/messages and /v1/responses, nothing reached the mock".to_string()
        } else {
            detail.join("; ")
        },
    }
}

fn check_block(
    name: &str,
    reply: Result<proxy::HttpReply>,
    secret: &str,
    anthropic: bool,
    detail: &mut Vec<String>,
) -> bool {
    let Ok(reply) = reply else {
        detail.push(format!("{name} request failed"));
        return false;
    };
    let mut pass = reply.status == 400;
    if reply.status != 400 {
        detail.push(format!("{name} status {}", reply.status));
    }
    if reply.retry.as_deref() != Some("false") {
        pass = false;
        detail.push(format!("{name} x-should-retry {:?}", reply.retry));
    }
    if reply.body.contains(secret) {
        pass = false;
        detail.push(format!("{name} body contains the canary"));
    }
    if anthropic {
        if !reply.body.contains("invalid_request_error")
            || !reply.body.contains("\"type\":\"error\"")
        {
            pass = false;
            detail.push(format!("{name} is not an Anthropic error"));
        }
    } else if !reply.body.contains("symveil_blocked") {
        pass = false;
        detail.push(format!("{name} is not symveil_blocked"));
    }
    pass
}

async fn policy_warn(out: &Path, pat: &str) -> Check {
    let repo = out.join("policy-warn");
    let (proxy, mock, client) = match policy_proxy(
        &repo,
        &config_text("enforce", false, true, &[("github-pat", "warn")], None),
    )
    .await
    {
        Ok(started) => started,
        Err(err) => return fail("policy warn", &format!("{err:#}")),
    };
    let reply = proxy::post_json(
        &client,
        &proxy.url,
        "/v1/responses",
        "warn-pat",
        EchoMode::None,
        &responses_text(pat, false),
    )
    .await;
    drop(proxy);
    let recorded = mock.recorded();
    let upstream_has = recorded
        .iter()
        .any(|hit| scan::find_bytes(&hit.body, pat.as_bytes()));
    let status_ok = matches!(reply, Ok(ref item) if item.status == 200);
    Check {
        name: "policy warn github-pat".to_string(),
        pass: status_ok && upstream_has,
        detail: if status_ok && upstream_has {
            "200 and the mock received the token, which warn requires".to_string()
        } else {
            format!("status_ok {status_ok} upstream_has {upstream_has}")
        },
    }
}

async fn policy_observe(out: &Path, aws: &str) -> Check {
    let repo = out.join("policy-observe");
    let (proxy, mock, client) =
        match policy_proxy(&repo, &config_text("observe", false, true, &[], None)).await {
            Ok(started) => started,
            Err(err) => return fail("policy observe", &format!("{err:#}")),
        };
    let reply = proxy::post_json(
        &client,
        &proxy.url,
        "/v1/messages",
        "observe-aws",
        EchoMode::None,
        &messages_text(aws, false),
    )
    .await;
    drop(proxy);
    let recorded = mock.recorded();
    let upstream_has = recorded
        .iter()
        .any(|hit| scan::find_bytes(&hit.body, aws.as_bytes()));
    let status_ok = matches!(reply, Ok(ref item) if item.status == 200);
    Check {
        name: "policy observe".to_string(),
        pass: status_ok && upstream_has,
        detail: if status_ok && upstream_has {
            "observe forwarded the access key".to_string()
        } else {
            format!("status_ok {status_ok} upstream_has {upstream_has}")
        },
    }
}

async fn policy_custom(out: &Path, aws: &str, custom: &str) -> Check {
    let repo = out.join("policy-custom");
    let (proxy, mock, client) = match policy_proxy(
        &repo,
        &config_text("enforce", false, true, &[], Some("warn")),
    )
    .await
    {
        Ok(started) => started,
        Err(err) => return fail("policy custom warn", &format!("{err:#}")),
    };
    let text = format!("{custom} {aws}");
    let reply = proxy::post_json(
        &client,
        &proxy.url,
        "/v1/messages",
        "custom-warn",
        EchoMode::None,
        &messages_text(&text, false),
    )
    .await;
    drop(proxy);
    let recorded = mock.recorded();
    let has_custom = recorded
        .iter()
        .any(|hit| scan::find_bytes(&hit.body, custom.as_bytes()));
    let has_aws = recorded
        .iter()
        .any(|hit| scan::find_bytes(&hit.body, aws.as_bytes()));
    let status_ok = matches!(reply, Ok(ref item) if item.status == 200);
    let pass = status_ok && has_custom && !has_aws;
    Check {
        name: "policy custom warn beside aws redact".to_string(),
        pass,
        detail: if pass {
            "custom token was forwarded and the access key was not".to_string()
        } else {
            format!("status_ok {status_ok} custom {has_custom} aws {has_aws}")
        },
    }
}

async fn policy_proxy(
    repo: &Path,
    config_body: &str,
) -> Result<(proxy::Proxy, mock::Mock, reqwest::Client)> {
    let config = proxy::write_config(repo, config_body)?;
    let mock = mock::Mock::spawn().await;
    let home = repo.join("home");
    let proxy = proxy::spawn_proxy(&bin(), repo, &config, &mock.base, &mock.base, &home)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    proxy::wait_healthy(&client, &proxy.url).await?;
    Ok((proxy, mock, client))
}

fn fail(name: &str, detail: &str) -> Check {
    Check {
        name: name.to_string(),
        pass: false,
        detail: detail.to_string(),
    }
}

fn messages_text(text: &str, stream: bool) -> Value {
    json!({
        "model": "leak-probe",
        "max_tokens": 32,
        "stream": stream,
        "messages": [{"role": "user", "content": text}]
    })
}

fn messages_tool(text: &str) -> Value {
    json!({
        "model": "leak-probe",
        "max_tokens": 32,
        "stream": true,
        "messages": [{
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "toolu_leak",
                "content": text
            }]
        }]
    })
}

fn responses_text(text: &str, stream: bool) -> Value {
    json!({
        "model": "leak-probe",
        "stream": stream,
        "input": text
    })
}

fn responses_tool(text: &str) -> Value {
    json!({
        "model": "leak-probe",
        "stream": true,
        "input": [{
            "type": "function_call_output",
            "call_id": "call_leak",
            "output": text
        }]
    })
}

fn json_key_body(key: &str) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(key.to_string(), Value::String("x".into()));
    json!({
        "model": "leak-probe",
        "max_tokens": 8,
        "stream": false,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "fläkt"},
                {"type": "tool_result", "tool_use_id": "toolu_key", "content": Value::Object(object)}
            ]
        }]
    })
}

fn json_number_body(value: &str) -> Value {
    let number: u64 = value.parse().unwrap_or(0);
    json!({
        "model": "leak-probe",
        "stream": false,
        "input": "fläkt",
        "personnummer": number
    })
}

fn with_echo(mut body: Value, echo: &str) -> Value {
    if let Some(map) = body.as_object_mut() {
        map.insert("echo_me".to_string(), Value::String(echo.to_string()));
    }
    body
}

fn isolated_mask(seed: &Seed) -> Result<BTreeMap<String, bool>> {
    let mut engine = build_engine(Vault::ephemeral(), &evaluated_redact())?;
    let mut out = BTreeMap::new();
    for item in &seed.items {
        let (text, _) = engine.redact_str(&item.value)?;
        out.insert(item.id.clone(), !text.contains(&item.value));
    }
    Ok(out)
}

fn needle_collisions(seed: &Seed) -> Vec<String> {
    let mut errors = Vec::new();
    for item in seed
        .items
        .iter()
        .filter(|item| item.expect == Expect::Masked)
    {
        for needle in scan::leak_needles(&item.value) {
            for other in &seed.items {
                if other.id == item.id {
                    continue;
                }
                if other.expect != Expect::Masked
                    && other.family != "path"
                    && other.family != "work-code-name"
                    && other.value.contains(&needle)
                {
                    errors.push(format!("{} needle collides with {}", item.id, other.id));
                }
            }
        }
    }
    errors
}

fn evaluated_redact() -> RedactSection {
    RedactSection {
        internal_domains: vec![
            "corp".to_string(),
            "internal".to_string(),
            "lan".to_string(),
        ],
        pii: PiiSection {
            email: true,
            phone: true,
            personnummer: true,
        },
        secrets: vec![SecretRule {
            name: "tdh-factory-token".to_string(),
            regex: r"\btdh_live_[A-Za-z0-9]{16,}\b".to_string(),
            action: None,
        }],
        names: evaluated_names(),
        high_entropy: false,
        ..RedactSection::default()
    }
}

fn evaluated_names() -> NamesSection {
    NamesSection {
        terms: vec!["Exempla".into(), "Tundrahorn".into(), "TDH".into()],
        patterns: vec![
            UserPattern {
                name: "tdh-code".into(),
                regex: r"TDH-\d+".into(),
                category: None,
            },
            UserPattern {
                name: "fan-code".into(),
                regex: r"FAN-[A-Z]+-\d+".into(),
                category: None,
            },
        ],
        people: vec!["Ren Testdotter".into()],
    }
}

fn config_text(
    mode: &str,
    high_entropy: bool,
    pii: bool,
    builtin: &[(&str, &str)],
    custom_action: Option<&str>,
) -> String {
    let entropy = if high_entropy { "true" } else { "false" };
    let mut out = format!(
        "[proxy]\nlisten = \"127.0.0.1\"\nport = 9\ntimeout_secs = 30\naudit_log = \".symveil/audit.jsonl\"\nvault = \".symveil/vault.json\"\n\n[redact]\nmode = \"{mode}\"\nhigh_entropy = {entropy}\ninternal_domains = [\"corp\", \"internal\", \"lan\"]\n"
    );
    if pii {
        out.push_str("\n[redact.pii]\nemail = true\nphone = true\npersonnummer = true\n");
    }
    if !builtin.is_empty() {
        out.push_str("\n[redact.builtin]\n");
        for (name, action) in builtin {
            out.push_str(name);
            out.push_str(" = \"");
            out.push_str(action);
            out.push_str("\"\n");
        }
    }
    out.push_str("\n[[redact.secrets]]\nname = \"tdh-factory-token\"\nregex = '\\btdh_live_[A-Za-z0-9]{16,}\\b'\n");
    if let Some(action) = custom_action {
        out.push_str("action = \"");
        out.push_str(action);
        out.push_str("\"\n");
    }
    out.push_str(
        "\n[redact.names]\nterms = [\"Exempla\", \"Tundrahorn\", \"TDH\"]\npeople = [\"Ren Testdotter\"]\n\n[[redact.names.patterns]]\nname = \"tdh-code\"\nregex = 'TDH-\\d+'\n\n[[redact.names.patterns]]\nname = \"fan-code\"\nregex = 'FAN-[A-Z]+-\\d+'\n",
    );
    out
}

fn command_bundle(root: &Path) -> Result<String> {
    let mut out = String::new();
    for rel in COMMAND_FILES {
        let bytes = std::fs::read(root.join(rel)).with_context(|| format!("read {rel}"))?;
        out.push_str("===== ");
        out.push_str(rel);
        out.push_str(" =====\n");
        out.push_str(&String::from_utf8_lossy(&bytes));
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

fn check_idempotent(seed: &Seed, out: &Path) -> Result<bool> {
    let left = out.join("idem-a");
    let right = out.join("idem-b");
    corpus::generate(seed, &left)?;
    corpus::generate(seed, &right)?;
    let same = corpus::snapshot(&left)? == corpus::snapshot(&right)?;
    std::fs::remove_dir_all(&left)?;
    std::fs::remove_dir_all(&right)?;
    Ok(same)
}

fn load_baseline(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text)?;
    let ids = value
        .get("masked_ids")
        .and_then(Value::as_array)
        .context("baseline masked_ids")?;
    ids.iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .context("baseline id is not a string")
        })
        .collect()
}

fn prepare_out() -> Result<PathBuf> {
    let out = report_dir();
    let name = out.file_name().and_then(|item| item.to_str()).unwrap_or("");
    if name != "leak-report" && name != "symveil-leak-out" {
        bail!("refusing to reset {name}; name the directory leak-report or symveil-leak-out");
    }
    if out.components().any(|part| part.as_os_str() == "tmp") {
        bail!("refusing an output directory under tmp");
    }
    if out.exists() {
        std::fs::remove_dir_all(&out)?;
    }
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn report_dir() -> PathBuf {
    match std::env::var("SYMVEIL_LEAK_OUT") {
        Ok(value) => PathBuf::from(value),
        Err(_) => manifest().join("target/leak-report"),
    }
}

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_symveil"))
}

fn git_sha() -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(manifest())
        .output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}
