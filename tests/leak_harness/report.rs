//! JSON and Markdown for one measurement run. Values of canaries are not copied here.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct Check {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

#[derive(Clone)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub sessions: Vec<String>,
    pub locations: Vec<String>,
    pub repro: String,
    pub fix: String,
}

#[derive(Clone)]
pub struct CategoryRow {
    pub category: String,
    pub claim: String,
    pub planted: usize,
    pub masked: Option<usize>,
    pub missed: usize,
    pub reached: usize,
    pub status: String,
}

#[derive(Clone)]
pub struct ItemRow {
    pub id: String,
    pub category: String,
    pub family: String,
    pub expect: String,
    pub claim: String,
    pub proxy_leak_sessions: Vec<String>,
    pub cli_text_leak: bool,
    pub cli_json_files: Vec<String>,
    pub cli_json_gate: bool,
    pub upstream_present: bool,
    pub present_sessions: Vec<String>,
    pub sent: bool,
}

#[derive(Clone)]
pub struct SideRow {
    pub id: String,
    pub masked: bool,
    pub detail: String,
}

pub struct Run {
    pub about: String,
    pub version: String,
    pub sha: String,
    pub identifiers: bool,
    pub verdict: String,
    pub reasons: Vec<String>,
    pub categories: Vec<CategoryRow>,
    pub items: Vec<ItemRow>,
    pub findings: Vec<Finding>,
    pub restores: Vec<Check>,
    pub policies: Vec<Check>,
    pub baseline: Vec<String>,
    pub false_positives: Vec<String>,
    pub fp_rise: Vec<String>,
    pub keep_missing: Vec<String>,
    pub idempotent: bool,
    pub pii_off: Vec<SideRow>,
    pub high_entropy: Vec<SideRow>,
    pub streak: u32,
    pub this_run_clean: bool,
    pub harness_errors: Vec<String>,
    pub recommendation: String,
}

impl Run {
    pub fn write(&self, dir: &Path) -> Result<()> {
        let json_path = dir.join("report.json");
        let md_path = dir.join("report.md");
        std::fs::write(&json_path, serde_json::to_string_pretty(&self.to_json())?)?;
        std::fs::write(&md_path, self.to_markdown())?;
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "about": self.about,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "build": {
                "tier": if self.identifiers { "pro-feature" } else { "free" },
                "version": self.version,
                "sha": self.sha,
                "identifiers_feature": self.identifiers,
                "name_maskers_in_tree": false,
                "evaluated_config": {
                    "mode": "enforce",
                    "high_entropy": false,
                    "internal_domains": ["corp", "internal", "lan"],
                    "pii": {"email": true, "phone": true, "personnummer": true},
                    "custom_rules": ["tdh-factory-token"]
                }
            },
            "claimed_by_build": claimed(),
            "measurement_bar_extra": ["secret.base64"],
            "categories": self.categories.iter().map(category_json).collect::<Vec<_>>(),
            "items": self.items.iter().map(item_json).collect::<Vec<_>>(),
            "findings": self.findings.iter().map(finding_json).collect::<Vec<_>>(),
            "restores": self.restores.iter().map(check_json).collect::<Vec<_>>(),
            "policies": self.policies.iter().map(check_json).collect::<Vec<_>>(),
            "false_positives": {
                "baseline_masked_ids": self.baseline,
                "observed_masked_ids": self.false_positives,
                "rise": self.fp_rise
            },
            "keep_missing": self.keep_missing,
            "idempotent": self.idempotent,
            "pii_off": self.pii_off.iter().map(side_json).collect::<Vec<_>>(),
            "high_entropy_side": {
                "enabled_for_this_column_only": true,
                "rows": self.high_entropy.iter().map(side_json).collect::<Vec<_>>()
            },
            "consecutive_clean_runs": {
                "observed": self.streak,
                "required": 3,
                "this_run_clean": self.this_run_clean,
                "clean_means": "zero gated leaks, zero work-code-name canaries upstream, and a real-client pass"
            },
            "real_client": {
                "ran": false,
                "clients": ["Claude Code", "Grok Build"],
                "runbook": "tests/leak/RUNBOOK.md"
            },
            "harness_errors": self.harness_errors,
            "recommendation": self.recommendation,
            "does_not_sandbox": true
        })
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# SymVeil leak measurement");
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", self.about);
        let _ = writeln!(out);
        let _ = writeln!(out, "**Verdict: {}**", self.verdict);
        let _ = writeln!(out);
        let _ = writeln!(out, "Reasons:");
        for reason in &self.reasons {
            let _ = writeln!(out, "- {reason}");
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "## Build");
        let _ = writeln!(out);
        let tier = if self.identifiers {
            "identifiers feature on"
        } else {
            "free"
        };
        let _ = writeln!(out, "- Tier: {tier}");
        let _ = writeln!(out, "- Version: {}", self.version);
        let _ = writeln!(out, "- Git SHA: `{}`", self.sha);
        let _ = writeln!(
            out,
            "- Name maskers: `[redact.names]` in the free core (terms Exempla, Tundrahorn, TDH; patterns TDH-\\d+ and FAN-[A-Z]+-\\d+). The identifier index `identifiers` is {}.",
            if self.identifiers { "on" } else { "off" }
        );
        let _ = writeln!(
            out,
            "- Evaluated config: `mode = enforce`, `high_entropy = false`, internal domains `corp`, `internal`, `lan`, personal data email/phone/personnummer on, custom rule `tdh-factory-token`, `[redact.names]` terms Exempla, Tundrahorn, TDH."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## What this build claims");
        let _ = writeln!(out);
        for line in claimed() {
            let _ = writeln!(out, "- {line}");
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Base64 is a covered secrets category for this measurement. The build does not claim it while `high_entropy` is off. A base64 leak fails the run. Unclaimed categories are `not covered`, never a pass."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Categories");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| category | claim | planted | masked | missed | reached upstream | status |"
        );
        let _ = writeln!(out, "| --- | --- | ---: | ---: | ---: | ---: | --- |");
        for row in &self.categories {
            let masked = match row.masked {
                Some(count) => count.to_string(),
                None => "n/a".to_string(),
            };
            let _ = writeln!(
                out,
                "| {} | {} | {} | {masked} | {} | {} | {} |",
                row.category, row.claim, row.planted, row.missed, row.reached, row.status
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "## False positives");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Baseline masked ids: {}.",
            list_or(&self.baseline, "none")
        );
        let _ = writeln!(
            out,
            "Observed masked ids: {}.",
            list_or(&self.false_positives, "none")
        );
        let _ = writeln!(out, "Rise: {}.", list_or(&self.fp_rise, "none"));
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Keep phrases missing upstream: {}.",
            list_or(&self.keep_missing, "none")
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Findings");
        let _ = writeln!(out);
        if self.findings.is_empty() {
            let _ = writeln!(out, "No findings.");
        }
        for finding in &self.findings {
            let _ = writeln!(out, "### {}", finding.id);
            let _ = writeln!(out);
            let _ = writeln!(out, "- Severity: {}", finding.severity);
            let _ = writeln!(out, "- Sessions: {}", list_or(&finding.sessions, "none"));
            let _ = writeln!(out, "- Locations: {}", list_or(&finding.locations, "none"));
            let _ = writeln!(out, "- Repro: {}", finding.repro);
            let _ = writeln!(out, "- Suggested fix: {}", finding.fix);
            let _ = writeln!(out);
        }
        section_checks(&mut out, "Restore", &self.restores);
        section_checks(&mut out, "Policy", &self.policies);
        let _ = writeln!(out, "## Idempotence");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Second generation {}",
            if self.idempotent {
                "matched byte for byte and was deleted."
            } else {
                "differed."
            }
        );
        let _ = writeln!(out);
        side_section(&mut out, "Personal data off", &self.pii_off);
        side_section(
            &mut out,
            "high_entropy side measurement",
            &self.high_entropy,
        );
        let _ = writeln!(
            out,
            "This column turns `high_entropy` on for the three base64 strings only. It does not clear a leak on the evaluated config."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Consecutive clean runs");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Observed streak: {}. Required: 3. This run clean: {}.",
            self.streak,
            if self.this_run_clean { "yes" } else { "no" }
        );
        let _ = writeln!(
            out,
            "A clean run means zero gated leaks, zero work-code-name canaries upstream, and a real-client pass. The harness does not loop a run that is not clean."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Real clients");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Claude Code and Grok Build were not executed. The steps for Magnus's host, on the synthetic repo only, are in `tests/leak/RUNBOOK.md`."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Not covered");
        let _ = writeln!(out);
        for line in NOT_COVERED {
            let _ = writeln!(out, "- {line}");
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "## Recommendation");
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", self.recommendation);
        if !self.harness_errors.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "## Harness errors");
            let _ = writeln!(out);
            for err in &self.harness_errors {
                let _ = writeln!(out, "- {err}");
            }
        }
        out
    }
}

const NOT_COVERED: &[&str] = &[
    "SymVeil does not sandbox the agent. A file the agent reads stays on the machine until the client sends it through the proxy.",
    "Tools that post to another host, or any non-HTTP channel, bypass the proxy.",
    "Grok Build can send a session title to cli-chat-proxy.grok.com unless session_summary is the SymVeil model. That call is not in this harness.",
    "Server-side tools (web search, code interpreter) run at the provider when a real API is used.",
    "Authorization and x-api-key headers are forwarded on purpose. This is not a TLS intercept.",
    "PNG, PDF, and ZIP metadata are tested only as bytes an agent would inline, not by a format parser.",
    "Person names are not masked. Usernames are not masked. A path is masked only where a configured term appears; that is the name rule, not a path rule.",
    "The harness split \"AKIASVCNSPLIT\" \"KEY001\" concatenates to AKIA plus 15 characters, which is not an access key. A two-literal split that forms a real token is masked. Escapes and three-part splits are not reassembled. A password glued to -p with no digit, and a spaced -p argument, are not masked.",
    "Real Claude Code, Grok Build, Codex, and Cursor sessions were not run.",
];

fn claimed() -> Vec<&'static str> {
    vec![
        "Builtin secret rules, including gitlab-pat, azure-account-key, slack-token through 256 characters, sk-admin and sk-svcacct, repr-env-assignment, shell-password, split-string-literal, and base64-secret. JSON object keys, JSON numbers, and a labeled password value are scanned.",
        "Custom [[redact.secrets]] rules. This run adds tdh-factory-token.",
        "[redact.names] terms Exempla, Tundrahorn, and TDH, plus project-code patterns TDH-\\d+ and FAN-[A-Z]+-\\d+.",
        "IPv4 and IPv6, except the documented keeps (127.0.0.1, 0.0.0.0, 255.255.255.255, ::, ::1).",
        "Hostnames under internal domains corp, internal, and lan, including a label that contains an underscore.",
        "Email, phone, and Swedish personnummer, because this run opts in. They are not covered when the flags are off.",
        "high_entropy is off, so the build does not claim unlabeled base64 or other high-entropy blobs.",
    ]
}

fn category_json(row: &CategoryRow) -> Value {
    json!({
        "category": row.category,
        "claim": row.claim,
        "planted": row.planted,
        "masked": row.masked,
        "missed": row.missed,
        "reached_upstream": row.reached,
        "status": row.status
    })
}

fn item_json(row: &ItemRow) -> Value {
    json!({
        "id": row.id,
        "category": row.category,
        "family": row.family,
        "expect": row.expect,
        "claim": row.claim,
        "proxy_leak_sessions": row.proxy_leak_sessions,
        "cli_text_leak": row.cli_text_leak,
        "cli_json_files": row.cli_json_files,
        "cli_json_gate": row.cli_json_gate,
        "upstream_present": row.upstream_present,
        "present_sessions": row.present_sessions,
        "sent": row.sent
    })
}

fn finding_json(finding: &Finding) -> Value {
    json!({
        "id": finding.id,
        "severity": finding.severity,
        "sessions": finding.sessions,
        "locations": finding.locations,
        "repro": finding.repro,
        "suggested_fix": finding.fix
    })
}

fn check_json(check: &Check) -> Value {
    json!({
        "name": check.name,
        "pass": check.pass,
        "detail": check.detail
    })
}

fn side_json(row: &SideRow) -> Value {
    json!({
        "id": row.id,
        "masked": row.masked,
        "detail": row.detail
    })
}

fn list_or(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        empty.to_string()
    } else {
        items.join(", ")
    }
}

fn section_checks(out: &mut String, title: &str, checks: &[Check]) {
    let _ = writeln!(out, "## {title}");
    let _ = writeln!(out);
    if checks.is_empty() {
        let _ = writeln!(out, "None.");
    }
    for check in checks {
        let mark = if check.pass { "pass" } else { "fail" };
        let _ = writeln!(out, "- {mark} {}: {}", check.name, check.detail);
    }
    let _ = writeln!(out);
}

fn side_section(out: &mut String, title: &str, rows: &[SideRow]) {
    let _ = writeln!(out, "## {title}");
    let _ = writeln!(out);
    if rows.is_empty() {
        let _ = writeln!(out, "None.");
    }
    for row in rows {
        let state = if row.masked {
            "masked"
        } else {
            "still present"
        };
        let _ = writeln!(out, "- {} {state}. {}", row.id, row.detail);
    }
    let _ = writeln!(out);
}
