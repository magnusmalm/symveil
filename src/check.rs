//! `symveil check` and the short summary `proxy` prints on startup.
//!
//! The report lists effective settings. Name lists and secrets are counts,
//! never values. A learned-file parse error is not included: the parser quotes
//! the file, and the file holds the strings the proxy matches.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::{
    discover, resolve_path, Action, BinaryMode, Config, LearnedCounts, LearnedOrigin, PiiSection,
};
use crate::{build_engine, Hit, Vault};

const MAX_SAMPLE: usize = 32 * 1024 * 1024;
static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);
const LOCAL_ONLY_NOTICE: &str = "LOCAL ONLY. Original values are shown on this machine. Do not copy this output into a chat, a ticket, or a commit.";

const CODE_BINARY_PASS: &str = "binary_pass";
const CODE_CONFIG_GIT: &str = "config_git";
const CODE_LEARNED_GIT: &str = "learned_git";
const CODE_LEARNED_INVALID: &str = "learned_invalid";
const CODE_LEARNED_MISSING: &str = "learned_missing";
const CODE_LEARNED_MODE: &str = "learned_mode";
const CODE_LEARNED_UNREADABLE: &str = "learned_unreadable";
const CODE_LISTEN: &str = "listen_unusable";
const CODE_NO_CONFIG: &str = "no_config";
const CODE_PII_OFF: &str = "pii_off";
const CODE_TERMS_EMPTY: &str = "terms_empty";
const CODE_UNKNOWN_KEY: &str = "unknown_key";
const CODE_UPSTREAM_ANTHROPIC: &str = "upstream_anthropic";
const CODE_UPSTREAM_OPENAI: &str = "upstream_openai";
const CODE_VAULT_GIT: &str = "vault_git";
const CODE_VAULT_MODE: &str = "vault_mode";

/// What `check` should inspect. Paths are the same ones `proxy` uses.
pub struct Request {
    pub repo: PathBuf,
    pub config: Option<PathBuf>,
    /// Sample text already read by the caller. `None` skips redaction.
    pub sample: Option<String>,
    pub reveal: bool,
    pub port: Option<u16>,
    pub openai_base: Option<String>,
    pub anthropic_base: Option<String>,
    /// When set, the report includes per-phase durations and the learned file
    /// size. The line is counts and times only.
    pub timings: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileState {
    path: String,
    exists: bool,
    writable: bool,
    mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevealedValue {
    action: String,
    category: String,
    rule: String,
    original: String,
    placeholder: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SampleReport {
    reveal: bool,
    local_only: bool,
    notice: Option<String>,
    replacements: BTreeMap<String, usize>,
    forwarded: BTreeMap<String, usize>,
    blocked: BTreeMap<String, usize>,
    withheld: usize,
    values: Vec<RevealedValue>,
}

struct LearnedView {
    path: Option<PathBuf>,
    configured: bool,
    loaded: bool,
    counts: LearnedCounts,
    mode: Option<u32>,
    problem: Option<LearnedProblem>,
}

enum LearnedProblem {
    Missing,
    Unreadable,
    Invalid,
}

/// Effective settings and warnings. Fields that reach the output are counts,
/// paths, and booleans. Revealed sample values are stored only when `reveal`
/// was set, and only for spans the sample actually matched.
pub struct Report {
    config_found: bool,
    config_path: Option<String>,
    repo: String,
    vault: FileState,
    audit_log: FileState,
    audit_buffered: bool,
    binary_mode: String,
    pii_email: bool,
    pii_phone: bool,
    pii_personnummer: bool,
    internal_domains: Vec<String>,
    term_count: usize,
    people_count: usize,
    learned_path: Option<String>,
    learned_configured: bool,
    learned_loaded: bool,
    learned_counts: LearnedCounts,
    learned_mode: Option<String>,
    openai_base: String,
    anthropic_base: String,
    listen: String,
    port: u16,
    port_free: bool,
    timeout_secs: u64,
    mode: String,
    high_entropy: bool,
    dotenv: bool,
    home_paths: bool,
    pub warnings: Vec<Warning>,
    sample: Option<SampleReport>,
    timings: Option<Timings>,
}

impl Report {
    pub fn to_text(&self) -> String {
        let mut out = String::from("symveil check\n");
        push_line(
            &mut out,
            "config",
            &config_label(self.config_found, self.config_path.as_deref()),
        );
        push_line(&mut out, "repo", &self.repo);
        push_line(&mut out, "vault", &file_value(&self.vault));
        push_line(&mut out, "audit", &file_value(&self.audit_log));
        if self.audit_buffered {
            push_line(
                &mut out,
                "audit_flush",
                "buffered; a crash can lose the last lines still in the buffer",
            );
        }
        push_line(&mut out, "binaries", &self.binary_mode);
        push_line(&mut out, "pii", &pii_text(self));
        push_line(&mut out, "domains", &domains_text(&self.internal_domains));
        push_line(
            &mut out,
            "names",
            &format!("terms={} people={}", self.term_count, self.people_count),
        );
        push_line(&mut out, "learned", &learned_text(self));
        push_line(&mut out, "openai", &self.openai_base);
        push_line(&mut out, "anthropic", &self.anthropic_base);
        push_line(
            &mut out,
            "port",
            &format!("{}:{} free={}", self.listen, self.port, yes(self.port_free)),
        );
        push_line(&mut out, "timeout", &self.timeout_secs.to_string());
        push_line(&mut out, "mode", &self.mode);
        push_line(&mut out, "entropy", on(self.high_entropy));
        push_line(&mut out, "dotenv", on(self.dotenv));
        push_line(&mut out, "home_paths", on(self.home_paths));
        push_warnings(&mut out, &self.warnings);
        if let Some(sample) = &self.sample {
            push_sample(&mut out, sample);
        }
        if let Some(timings) = &self.timings {
            push_line(&mut out, "timings", &timings.line());
        }
        out
    }

    pub fn to_json(&self) -> Result<String> {
        let mut text = serde_json::to_string_pretty(&self.json_value())?;
        text.push('\n');
        Ok(text)
    }

    fn json_value(&self) -> Value {
        let mut body = serde_json::json!({
            "config": {
                "found": self.config_found,
                "path": self.config_path,
            },
            "repo": self.repo,
            "vault": file_json(&self.vault),
            "audit_log": file_json(&self.audit_log),
            "audit_buffered": self.audit_buffered,
            "binary_mode": self.binary_mode,
            "pii": {
                "email": self.pii_email,
                "phone": self.pii_phone,
                "personnummer": self.pii_personnummer,
            },
            "internal_domains": self.internal_domains,
            "names": {
                "terms": self.term_count,
                "people": self.people_count,
            },
            "learned": learned_json(self),
            "upstream": {
                "openai_base": self.openai_base,
                "anthropic_base": self.anthropic_base,
            },
            "listen": self.listen,
            "port": self.port,
            "port_free": self.port_free,
            "proxy": {
                "listen": self.listen,
                "port": self.port,
                "timeout_secs": self.timeout_secs,
                "mode": self.mode,
                "high_entropy": self.high_entropy,
                "dotenv": self.dotenv,
                "home_paths": self.home_paths,
                "openai_base": self.openai_base,
                "anthropic_base": self.anthropic_base,
                "vault": self.vault.path,
                "audit_log": self.audit_log.path,
                "audit_buffered": self.audit_buffered,
                "binary_mode": self.binary_mode,
                "pii": {
                    "email": self.pii_email,
                    "phone": self.pii_phone,
                    "personnummer": self.pii_personnummer,
                },
                "internal_domains": self.internal_domains,
                "names": {
                    "terms": self.term_count,
                    "people": self.people_count,
                },
            },
            "warnings": self.warnings.iter().map(|warning| {
                serde_json::json!({
                    "code": warning.code,
                    "message": warning.message,
                })
            }).collect::<Vec<_>>(),
            "sample": Value::Null,
        });
        if let Some(sample) = &self.sample {
            body["sample"] = sample_json(sample);
        }
        if let Some(timings) = &self.timings {
            body["timings"] = timings.json();
        }
        body
    }
}

/// Durations from one `check`. Bytes and milliseconds only: no paths and no
/// file text. `warnings_ms` includes the git exposure checks. `build` is
/// `debug` or `release`, which changes how long the same file takes.
struct Timings {
    build: &'static str,
    total: Duration,
    config_read: Duration,
    config_parse: Duration,
    learned_read: Duration,
    learned_parse: Duration,
    learned_merge: Duration,
    files: Duration,
    port: Duration,
    warnings: Duration,
    sample: Duration,
    other: Duration,
    learned_bytes: u64,
}

impl Timings {
    fn line(&self) -> String {
        format!(
            "build={} total_ms={} config_read_ms={} config_parse_ms={} learned_read_ms={} learned_parse_ms={} learned_merge_ms={} files_ms={} port_ms={} warnings_ms={} sample_ms={} other_ms={} learned_bytes={}",
            self.build,
            ms(self.total),
            ms(self.config_read),
            ms(self.config_parse),
            ms(self.learned_read),
            ms(self.learned_parse),
            ms(self.learned_merge),
            ms(self.files),
            ms(self.port),
            ms(self.warnings),
            ms(self.sample),
            ms(self.other),
            self.learned_bytes,
        )
    }

    fn json(&self) -> Value {
        serde_json::json!({
            "build": self.build,
            "total_ms": ms(self.total),
            "config_read_ms": ms(self.config_read),
            "config_parse_ms": ms(self.config_parse),
            "learned_read_ms": ms(self.learned_read),
            "learned_parse_ms": ms(self.learned_parse),
            "learned_merge_ms": ms(self.learned_merge),
            "files_ms": ms(self.files),
            "port_ms": ms(self.port),
            "warnings_ms": ms(self.warnings),
            "sample_ms": ms(self.sample),
            "other_ms": ms(self.other),
            "learned_bytes": self.learned_bytes,
        })
    }
}

fn ms(duration: Duration) -> f64 {
    let millis = duration.as_secs_f64() * 1_000.0;
    (millis * 10.0).round() / 10.0
}

struct Phases {
    config_read: Duration,
    config_parse: Duration,
    learned_read: Duration,
    learned_parse: Duration,
    learned_merge: Duration,
    files: Duration,
    port: Duration,
    warnings: Duration,
    sample: Duration,
    learned_bytes: u64,
}

impl Phases {
    fn new() -> Self {
        Self {
            config_read: Duration::ZERO,
            config_parse: Duration::ZERO,
            learned_read: Duration::ZERO,
            learned_parse: Duration::ZERO,
            learned_merge: Duration::ZERO,
            files: Duration::ZERO,
            port: Duration::ZERO,
            warnings: Duration::ZERO,
            sample: Duration::ZERO,
            learned_bytes: 0,
        }
    }

    fn finish(&self, total: Duration) -> Timings {
        let accounted = self
            .config_read
            .saturating_add(self.config_parse)
            .saturating_add(self.learned_read)
            .saturating_add(self.learned_parse)
            .saturating_add(self.learned_merge)
            .saturating_add(self.files)
            .saturating_add(self.port)
            .saturating_add(self.warnings)
            .saturating_add(self.sample);
        Timings {
            build: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            total,
            config_read: self.config_read,
            config_parse: self.config_parse,
            learned_read: self.learned_read,
            learned_parse: self.learned_parse,
            learned_merge: self.learned_merge,
            files: self.files,
            port: self.port,
            warnings: self.warnings,
            sample: self.sample,
            other: total.saturating_sub(accounted),
            learned_bytes: self.learned_bytes,
        }
    }
}

/// Config path `proxy` loaded, if one was found.
pub fn resolved_config_path(root: &Path, explicit: Option<&Path>) -> Option<PathBuf> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => discover(root)?,
    };
    Some(fs::canonicalize(&path).unwrap_or(path))
}

/// Short form of the check summary, for the proxy startup banner.
///
/// Names and secrets stay counts. This does not bind the port and does not
/// create the vault.
pub fn startup_lines(root: &Path, cfg: &Config, config_path: Option<&Path>) -> String {
    let origin = cfg.learned_origin(root);
    let learned = if cfg.learned_loaded {
        LearnedView {
            path: origin.as_ref().map(|item| item.path.clone()),
            configured: origin.as_ref().is_some_and(|item| item.configured),
            loaded: true,
            counts: cfg.learned_counts,
            mode: origin.as_ref().and_then(|item| unix_mode(&item.path)),
            problem: None,
        }
    } else {
        read_learned(origin, None, None)
    };
    let vault_mode = mode_of_file(&resolve_path(root, &cfg.proxy.vault));
    let warnings = collect_warnings(Facts {
        root,
        cfg,
        config_path,
        learned: &learned,
        unknown_keys: &[],
        vault_mode,
    });
    let config_display = config_path.map(display_path);
    let mut out = String::new();
    push_line(
        &mut out,
        "config",
        &config_label(config_display.is_some(), config_display.as_deref()),
    );
    push_line(&mut out, "pii", &pii_line(&cfg.redact.pii));
    push_line(
        &mut out,
        "domains",
        &domains_text(&cfg.redact.internal_domains),
    );
    push_line(&mut out, "names", &names_line(cfg));
    push_line(&mut out, "learned", &learned_line(&learned));
    for warning in &warnings {
        push_line(
            &mut out,
            "warning",
            &format!("[{}] {}", warning.code, warning.message),
        );
    }
    out
}

/// Build the check report. Does not create the vault, the audit log, or a listener
/// that stays open. A writable probe file is created and removed.
pub fn inspect(request: &Request) -> Result<Report> {
    let started = Instant::now();
    let mut phases = Phases::new();
    let root = canonicalize_repo(&request.repo)?;
    let (mut cfg, config_path, unknown_keys) =
        load_config(&root, request.config.as_deref(), &mut phases)?;
    let origin = cfg.learned_origin(&root);
    let learned = read_learned(origin, Some(&mut cfg), Some(&mut phases));
    apply_overrides(&mut cfg, request);
    let vault_path = resolve_path(&root, &cfg.proxy.vault);
    let audit_path = resolve_path(&root, &cfg.proxy.audit_log);
    let files_started = Instant::now();
    let vault = file_state(&vault_path);
    let audit_log = file_state(&audit_path);
    phases.files = files_started.elapsed();
    let port_started = Instant::now();
    let (port_free, listen_warning) = port_status(&cfg.proxy.listen, cfg.proxy.port);
    phases.port = port_started.elapsed();
    let warnings_started = Instant::now();
    let mut warnings = collect_warnings(Facts {
        root: &root,
        cfg: &cfg,
        config_path: config_path.as_deref(),
        learned: &learned,
        unknown_keys: &unknown_keys,
        vault_mode: mode_of_file(&vault_path),
    });
    if let Some(warning) = listen_warning {
        warnings.push(warning);
    }
    warnings.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then(left.message.cmp(&right.message))
    });
    phases.warnings = warnings_started.elapsed();
    let sample_started = Instant::now();
    let sample = match &request.sample {
        Some(text) => Some(redact_sample(&cfg, text, request.reveal)?),
        None => None,
    };
    phases.sample = sample_started.elapsed();
    let timings = request.timings.then(|| phases.finish(started.elapsed()));
    Ok(Report {
        config_found: config_path.is_some(),
        config_path: config_path.as_deref().map(display_path),
        repo: root.display().to_string(),
        vault,
        audit_log,
        audit_buffered: cfg.proxy.audit_buffered,
        binary_mode: cfg.binary.mode.to_string(),
        pii_email: cfg.redact.pii.email,
        pii_phone: cfg.redact.pii.phone,
        pii_personnummer: cfg.redact.pii.personnummer,
        internal_domains: cfg.redact.internal_domains.clone(),
        term_count: cfg.redact.names.terms.len(),
        people_count: cfg.redact.names.people.len(),
        learned_path: learned.path.as_deref().map(display_path),
        learned_configured: learned.configured,
        learned_loaded: learned.loaded,
        learned_counts: learned.counts,
        learned_mode: learned.mode.map(format_mode),
        openai_base: display_base(&cfg.proxy.openai_base),
        anthropic_base: display_base(&cfg.proxy.anthropic_base),
        listen: cfg.proxy.listen.clone(),
        port: cfg.proxy.port,
        port_free,
        timeout_secs: cfg.proxy.timeout_secs,
        mode: cfg.redact.mode.to_string(),
        high_entropy: cfg.redact.high_entropy,
        dotenv: cfg.redact.dotenv,
        home_paths: cfg.redact.home_paths,
        warnings,
        sample,
        timings,
    })
}

fn canonicalize_repo(repo: &Path) -> Result<PathBuf> {
    let root = repo
        .canonicalize()
        .with_context(|| format!("open {}", repo.display()))?;
    if !root.is_dir() {
        anyhow::bail!("{} is not a directory", root.display());
    }
    Ok(root)
}

fn load_config(
    root: &Path,
    explicit: Option<&Path>,
    phases: &mut Phases,
) -> Result<(Config, Option<PathBuf>, Vec<String>)> {
    let Some(path) = explicit.map(Path::to_path_buf).or_else(|| discover(root)) else {
        return Ok((Config::default(), None, Vec::new()));
    };
    let read_started = Instant::now();
    let text =
        fs::read_to_string(&path).with_context(|| format!("read config {}", path.display()))?;
    phases.config_read = read_started.elapsed();
    let parse_started = Instant::now();
    let loaded =
        Config::parse_lenient(&text).with_context(|| format!("parse config {}", path.display()))?;
    phases.config_parse = parse_started.elapsed();
    let display = fs::canonicalize(&path).unwrap_or(path);
    Ok((loaded.config, Some(display), loaded.unknown_keys))
}

fn apply_overrides(cfg: &mut Config, request: &Request) {
    if let Some(port) = request.port {
        cfg.proxy.port = port;
    }
    if let Some(base) = &request.openai_base {
        cfg.proxy.openai_base = base.clone();
    }
    if let Some(base) = &request.anthropic_base {
        cfg.proxy.anthropic_base = base.clone();
    }
}

fn read_learned(
    origin: Option<LearnedOrigin>,
    merge_into: Option<&mut Config>,
    mut phases: Option<&mut Phases>,
) -> LearnedView {
    let Some(origin) = origin else {
        return LearnedView::empty();
    };
    if !origin.path.exists() {
        return LearnedView::problem(
            origin.path,
            origin.configured,
            None,
            origin.configured.then_some(LearnedProblem::Missing),
        );
    }
    if !origin.path.is_file() {
        return LearnedView::problem(
            origin.path,
            origin.configured,
            None,
            Some(LearnedProblem::Unreadable),
        );
    }
    let mode = unix_mode(&origin.path);
    let read_started = Instant::now();
    let text = match fs::read_to_string(&origin.path) {
        Ok(text) => text,
        Err(_) => {
            if let Some(phases) = phases.as_mut() {
                phases.learned_read = read_started.elapsed();
            }
            return LearnedView::problem(
                origin.path,
                origin.configured,
                mode,
                Some(LearnedProblem::Unreadable),
            );
        }
    };
    if let Some(phases) = phases.as_mut() {
        phases.learned_read = read_started.elapsed();
        phases.learned_bytes = text.len() as u64;
    }
    // One parse. A failed merge leaves the caller's config unchanged.
    let loaded = if let Some(cfg) = merge_into {
        let mut trial = cfg.clone();
        let parse_started = Instant::now();
        match trial.apply_learned_toml_timed(&text) {
            Ok(timing) => {
                if let Some(phases) = phases.as_mut() {
                    phases.learned_parse = timing.parse;
                    phases.learned_merge = timing.merge;
                }
                let counts = trial.learned_counts;
                *cfg = trial;
                Some(counts)
            }
            Err(_) => {
                if let Some(phases) = phases.as_mut() {
                    phases.learned_parse = parse_started.elapsed();
                }
                None
            }
        }
    } else {
        let parse_started = Instant::now();
        let counts = LearnedCounts::parse(&text).ok();
        if let Some(phases) = phases.as_mut() {
            phases.learned_parse = parse_started.elapsed();
        }
        counts
    };
    let Some(counts) = loaded else {
        return LearnedView::problem(
            origin.path,
            origin.configured,
            mode,
            Some(LearnedProblem::Invalid),
        );
    };
    LearnedView {
        path: Some(origin.path),
        configured: origin.configured,
        loaded: true,
        counts,
        mode,
        problem: None,
    }
}

impl LearnedView {
    fn empty() -> Self {
        Self::problem(PathBuf::new(), false, None, None)
    }

    fn problem(
        path: PathBuf,
        configured: bool,
        mode: Option<u32>,
        problem: Option<LearnedProblem>,
    ) -> Self {
        let path = if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        };
        Self {
            path,
            configured,
            loaded: false,
            counts: LearnedCounts::default(),
            mode,
            problem,
        }
    }
}

struct Facts<'a> {
    root: &'a Path,
    cfg: &'a Config,
    config_path: Option<&'a Path>,
    learned: &'a LearnedView,
    unknown_keys: &'a [String],
    vault_mode: Option<u32>,
}

fn collect_warnings(facts: Facts<'_>) -> Vec<Warning> {
    let Facts {
        root,
        cfg,
        config_path,
        learned,
        unknown_keys,
        vault_mode,
    } = facts;
    let mut warnings = Vec::new();
    if config_path.is_none() {
        warnings.push(Warning {
            code: CODE_NO_CONFIG.to_string(),
            message: "no config file was found; defaults are in use".to_string(),
        });
    }
    for key in unknown_keys {
        warnings.push(Warning {
            code: CODE_UNKNOWN_KEY.to_string(),
            message: format!(
                "unknown config key `{key}`; the proxy rejects this config until the key is removed"
            ),
        });
    }
    if cfg.binary.mode == BinaryMode::Pass {
        warnings.push(Warning {
            code: CODE_BINARY_PASS.to_string(),
            message: "binary mode is pass; inline images, documents, and files are forwarded"
                .to_string(),
        });
    }
    if !cfg.redact.pii.enabled() {
        warnings.push(Warning {
            code: CODE_PII_OFF.to_string(),
            message: "personal data detectors are off (email, phone, personnummer)".to_string(),
        });
    }
    if cfg.redact.names.terms.is_empty() {
        warnings.push(Warning {
            code: CODE_TERMS_EMPTY.to_string(),
            message: "names.terms is empty".to_string(),
        });
    }
    if let Some(problem) = &learned.problem {
        if let Some(path) = &learned.path {
            warnings.push(learned_problem_warning(
                problem,
                learned.configured,
                &display_path(path),
            ));
        }
    }
    if let Some(mode) = learned.mode {
        if mode_looser_than_owner_rw(mode) {
            if let Some(path) = &learned.path {
                warnings.push(mode_warning(
                    CODE_LEARNED_MODE,
                    "learned file",
                    &display_path(path),
                    &format_mode(mode),
                ));
            }
        }
    }
    let vault_path = resolve_path(root, &cfg.proxy.vault);
    if let Some(mode) = vault_mode {
        if mode_looser_than_owner_rw(mode) {
            warnings.push(mode_warning(
                CODE_VAULT_MODE,
                "vault",
                &display_path(&vault_path),
                &format_mode(mode),
            ));
        }
    }
    if let Some(path) = config_path {
        push_git(&mut warnings, CODE_CONFIG_GIT, "config", path);
    }
    push_git(&mut warnings, CODE_VAULT_GIT, "vault", &vault_path);
    if let Some(path) = &learned.path {
        push_git(&mut warnings, CODE_LEARNED_GIT, "learned file", path);
    }
    if let Some(warning) = upstream_warning(CODE_UPSTREAM_OPENAI, "openai", &cfg.proxy.openai_base)
    {
        warnings.push(warning);
    }
    if let Some(warning) = upstream_warning(
        CODE_UPSTREAM_ANTHROPIC,
        "anthropic",
        &cfg.proxy.anthropic_base,
    ) {
        warnings.push(warning);
    }
    warnings
}

fn learned_problem_warning(problem: &LearnedProblem, configured: bool, path: &str) -> Warning {
    let (code, message) = match problem {
        LearnedProblem::Missing => (
            CODE_LEARNED_MISSING,
            format!("learned file {path} is configured but missing"),
        ),
        LearnedProblem::Unreadable if configured => (
            CODE_LEARNED_UNREADABLE,
            format!("learned file {path} is configured but unreadable"),
        ),
        LearnedProblem::Unreadable => (
            CODE_LEARNED_UNREADABLE,
            format!("learned file {path} is unreadable"),
        ),
        LearnedProblem::Invalid => (
            CODE_LEARNED_INVALID,
            format!("learned file {path} could not be loaded; the proxy will not start"),
        ),
    };
    Warning {
        code: code.to_string(),
        message,
    }
}

fn mode_warning(code: &str, kind: &str, path: &str, mode: &str) -> Warning {
    Warning {
        code: code.to_string(),
        message: format!("{kind} {path} is mode {mode}, which is more permissive than 0600"),
    }
}

fn upstream_warning(code: &str, which: &str, base: &str) -> Option<Warning> {
    if base_is_https_or_loopback(base) {
        return None;
    }
    Some(Warning {
        code: code.to_string(),
        message: format!(
            "{which}_base {} is not https and not a loopback host",
            display_base(base)
        ),
    })
}

fn push_git(warnings: &mut Vec<Warning>, code: &str, kind: &str, path: &Path) {
    let Some(exposure) = git_exposure(path) else {
        return;
    };
    let shown = display_path(path);
    let message = match exposure {
        GitExposure::Tracked => format!("{kind} {shown} is tracked by git and would be committed"),
        GitExposure::WouldCommit => {
            format!("{kind} {shown} is inside a git work tree and would be committed")
        }
    };
    warnings.push(Warning {
        code: code.to_string(),
        message,
    });
}

enum GitExposure {
    Tracked,
    WouldCommit,
}

/// Warn when a later `git add` would record the path.
///
/// A gitignored path is quiet: `.symveil/` is ignored so the vault is not
/// committed. A tracked file, or a file inside the work tree that no exclude
/// rule covers, is warned.
fn git_exposure(path: &Path) -> Option<GitExposure> {
    let start = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()?.to_path_buf()
    };
    if start.as_os_str().is_empty() {
        return None;
    }
    let top = git_stdout(&start, &["rev-parse", "--show-toplevel"])?;
    let top = PathBuf::from(top.trim());
    let top = fs::canonicalize(&top).unwrap_or(top);
    let candidate = canonical_for_compare(path);
    if !candidate.starts_with(&top) {
        return None;
    }
    let spec = candidate.to_str()?;
    if git_success(&top, &["ls-files", "--error-unmatch", "--", spec]) {
        return Some(GitExposure::Tracked);
    }
    match git_code(&top, &["check-ignore", "-q", "--", spec]) {
        Some(0) => None,
        Some(1) => Some(GitExposure::WouldCommit),
        _ => None,
    }
}

fn git_stdout(dir: &Path, args: &[&str]) -> Option<String> {
    let output = git_command(dir, args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn git_success(dir: &Path, args: &[&str]) -> bool {
    git_code(dir, args) == Some(0)
}

fn git_code(dir: &Path, args: &[&str]) -> Option<i32> {
    git_command(dir, args).status().ok()?.code()
}

fn git_command(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-c")
        .arg("safe.directory=*")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd
}

fn canonical_for_compare(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    let mut suffix = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        if let Ok(canon) = fs::canonicalize(&cursor) {
            let mut full = canon;
            for part in suffix.iter().rev() {
                full.push(part);
            }
            return full;
        }
        let Some(name) = cursor.file_name() else {
            return path.to_path_buf();
        };
        suffix.push(name.to_os_string());
        if !cursor.pop() {
            return path.to_path_buf();
        }
    }
}

fn file_state(path: &Path) -> FileState {
    if path.is_file() {
        return FileState {
            path: display_path(path),
            exists: true,
            writable: OpenOptions::new().read(true).write(true).open(path).is_ok(),
            mode: unix_mode(path).map(format_mode),
        };
    }
    if path.exists() {
        return FileState {
            path: display_path(path),
            exists: true,
            writable: false,
            mode: unix_mode(path).map(format_mode),
        };
    }
    let writable = nearest_existing_dir(path).is_some_and(|dir| can_create_in(&dir));
    FileState {
        path: display_path(path),
        exists: false,
        writable,
        mode: None,
    }
}

fn nearest_existing_dir(path: &Path) -> Option<PathBuf> {
    let mut cursor = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()?.to_path_buf()
    };
    loop {
        if cursor.is_dir() {
            return Some(cursor);
        }
        if !cursor.pop() {
            return None;
        }
    }
}

fn can_create_in(dir: &Path) -> bool {
    let seq = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe = dir.join(format!(".symveil-check-probe-{}-{seq}", std::process::id()));
    match open_probe(&probe) {
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn open_probe(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_probe_mode(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn set_probe_mode(options: &mut OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_probe_mode(_options: &mut OpenOptions) {}

fn mode_of_file(path: &Path) -> Option<u32> {
    if path.is_file() {
        unix_mode(path)
    } else {
        None
    }
}

fn unix_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        fs::metadata(path)
            .ok()
            .map(|meta| meta.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn mode_looser_than_owner_rw(mode: u32) -> bool {
    mode & 0o777 & !0o600 != 0
}

fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode & 0o777)
}

fn port_status(listen: &str, port: u16) -> (bool, Option<Warning>) {
    let addr = format!("{listen}:{port}");
    let Ok(socket) = addr.parse::<SocketAddr>() else {
        return (false, Some(listen_warning(&addr)));
    };
    match std::net::TcpListener::bind(socket) {
        Ok(listener) => {
            drop(listener);
            (true, None)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => (false, None),
        Err(_) => (false, Some(listen_warning(&addr))),
    }
}

fn listen_warning(addr: &str) -> Warning {
    Warning {
        code: CODE_LISTEN.to_string(),
        message: format!("listen address {addr} is not usable"),
    }
}

fn base_is_https_or_loopback(base: &str) -> bool {
    let trimmed = base.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    if scheme.eq_ignore_ascii_case("https") {
        return true;
    }
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let after_user = rest.rsplit_once('@').map(|(_, host)| host).unwrap_or(rest);
    let hostport = after_user.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.is_empty() {
        return false;
    }
    let host = if let Some(bracketed) = hostport.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    host_is_loopback(host)
}

fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback();
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return ip.is_loopback();
    }
    false
}

fn display_base(base: &str) -> String {
    let trimmed = base.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return trimmed.to_string();
    };
    let Some((userinfo, host)) = rest.split_once('@') else {
        return trimmed.to_string();
    };
    if userinfo.contains('/') {
        return trimmed.to_string();
    }
    format!("{scheme}://{host}")
}

fn display_path(path: &Path) -> String {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon.display().to_string();
    }
    if path.is_absolute() {
        return path.display().to_string();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path).display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn redact_sample(cfg: &Config, text: &str, reveal: bool) -> Result<SampleReport> {
    if text.len() > MAX_SAMPLE {
        anyhow::bail!("sample exceeds 32MiB");
    }
    // Ephemeral vault: check must not create or rewrite a vault file.
    // Stored vault literals are not applied. Configured rules and learned
    // lists are.
    let mut engine = build_engine(Vault::ephemeral(), &cfg.redact)?;
    engine.set_binary_mode(cfg.binary.mode);
    let hits = take_hits(&mut engine, text)?;
    let withheld = engine.take_binary_notes().len();
    drop(engine);
    Ok(sample_from_hits(&hits, withheld, reveal))
}

fn take_hits(engine: &mut crate::Engine, text: &str) -> Result<Vec<Hit>> {
    if serde_json::from_str::<Value>(text).is_ok() {
        let (bytes, hits) = engine.redact_bytes(text.as_bytes())?;
        drop(bytes);
        return Ok(hits);
    }
    let (redacted, hits) = engine.redact_str(text)?;
    drop(redacted);
    Ok(hits)
}

fn sample_from_hits(hits: &[Hit], withheld: usize, reveal: bool) -> SampleReport {
    let mut replacements = BTreeMap::new();
    let mut forwarded = BTreeMap::new();
    let mut blocked = BTreeMap::new();
    let mut values = Vec::new();
    for hit in hits {
        let bucket = match hit.action {
            Action::Redact => &mut replacements,
            Action::Warn => &mut forwarded,
            Action::Block => &mut blocked,
        };
        *bucket.entry(hit.category.as_str().to_string()).or_insert(0) += 1;
        if reveal {
            values.push(RevealedValue {
                action: hit.action.to_string(),
                category: hit.category.as_str().to_string(),
                rule: hit
                    .rule
                    .clone()
                    .unwrap_or_else(|| hit.category.as_str().to_string()),
                original: hit.original.clone(),
                placeholder: hit.placeholder.clone(),
            });
        }
    }
    values.sort_by(|left, right| {
        left.action
            .cmp(&right.action)
            .then(left.category.cmp(&right.category))
            .then(left.rule.cmp(&right.rule))
            .then(left.original.cmp(&right.original))
    });
    SampleReport {
        reveal,
        local_only: reveal,
        notice: reveal.then(|| LOCAL_ONLY_NOTICE.to_string()),
        replacements,
        forwarded,
        blocked,
        withheld,
        values,
    }
}

fn push_line(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("  {label:<12}{value}\n"));
}

fn push_warnings(out: &mut String, warnings: &[Warning]) {
    if warnings.is_empty() {
        push_line(out, "warnings", "none");
        return;
    }
    push_line(out, "warnings", &warnings.len().to_string());
    for warning in warnings {
        push_line(
            out,
            "warning",
            &format!("[{}] {}", warning.code, warning.message),
        );
    }
}

fn push_sample(out: &mut String, sample: &SampleReport) {
    push_line(
        out,
        "sample",
        &format!("replacements {}", format_counts(&sample.replacements)),
    );
    push_line(
        out,
        "sample",
        &format!("forwarded {}", format_counts(&sample.forwarded)),
    );
    push_line(
        out,
        "sample",
        &format!("blocked {}", format_counts(&sample.blocked)),
    );
    push_line(out, "sample", &format!("withheld {}", sample.withheld));
    if !sample.reveal {
        return;
    }
    if let Some(notice) = &sample.notice {
        push_line(out, "sample", notice);
    }
    for value in &sample.values {
        let shown = if value.placeholder.is_empty() {
            format!(
                "{} {} {} {}",
                value.action,
                value.category,
                value.rule,
                one_line(&value.original)
            )
        } else {
            format!(
                "{} {} {} {} -> {}",
                value.action,
                value.category,
                value.rule,
                one_line(&value.original),
                one_line(&value.placeholder)
            )
        };
        push_line(out, "sample", &shown);
    }
}

fn sample_json(sample: &SampleReport) -> Value {
    let mut value = serde_json::json!({
        "reveal": sample.reveal,
        "local_only": sample.local_only,
        "replacements": sample.replacements,
        "forwarded": sample.forwarded,
        "blocked": sample.blocked,
        "withheld": sample.withheld,
    });
    if let Some(notice) = &sample.notice {
        value["notice"] = Value::String(notice.clone());
    }
    if sample.reveal {
        value["values"] = serde_json::json!(sample
            .values
            .iter()
            .map(|value| {
                serde_json::json!({
                    "action": value.action,
                    "category": value.category,
                    "rule": value.rule,
                    "original": value.original,
                    "placeholder": value.placeholder,
                })
            })
            .collect::<Vec<_>>());
    }
    value
}

fn format_counts(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

fn file_value(state: &FileState) -> String {
    format!(
        "{} exists={} writable={} mode={}",
        state.path,
        yes(state.exists),
        yes(state.writable),
        state.mode.as_deref().unwrap_or("-")
    )
}

fn file_json(state: &FileState) -> Value {
    serde_json::json!({
        "path": state.path,
        "exists": state.exists,
        "writable": state.writable,
        "mode": state.mode,
    })
}

fn config_label(found: bool, path: Option<&str>) -> String {
    match path {
        Some(path) if found => path.to_string(),
        _ => "none (defaults)".to_string(),
    }
}

fn learned_text(report: &Report) -> String {
    let Some(path) = &report.learned_path else {
        return "none".to_string();
    };
    format!(
        "{path} configured={} loaded={} {} mode={}",
        yes(report.learned_configured),
        yes(report.learned_loaded),
        counts_text(&report.learned_counts),
        report.learned_mode.as_deref().unwrap_or("-")
    )
}

fn learned_line(learned: &LearnedView) -> String {
    let Some(path) = &learned.path else {
        return "none".to_string();
    };
    format!(
        "{} configured={} loaded={} {} mode={}",
        display_path(path),
        yes(learned.configured),
        yes(learned.loaded),
        counts_text(&learned.counts),
        learned
            .mode
            .map(format_mode)
            .unwrap_or_else(|| "-".to_string())
    )
}

fn counts_text(counts: &LearnedCounts) -> String {
    format!(
        "decisions={} terms={} people={} secrets={} emails={} ips={} hosts={} domains={} symbols={} skips={} keeps={}",
        counts.decisions,
        counts.terms,
        counts.people,
        counts.secrets,
        counts.emails,
        counts.ips,
        counts.hosts,
        counts.domains,
        counts.symbols,
        counts.skips,
        counts.keeps
    )
}

fn learned_json(report: &Report) -> Value {
    let counts = &report.learned_counts;
    serde_json::json!({
        "path": report.learned_path,
        "configured": report.learned_configured,
        "loaded": report.learned_loaded,
        "decisions": counts.decisions,
        "terms": counts.terms,
        "people": counts.people,
        "secrets": counts.secrets,
        "emails": counts.emails,
        "ips": counts.ips,
        "hosts": counts.hosts,
        "domains": counts.domains,
        "symbols": counts.symbols,
        "skips": counts.skips,
        "keeps": counts.keeps,
        "mode": report.learned_mode,
    })
}

fn pii_text(report: &Report) -> String {
    format!(
        "email={} phone={} personnummer={}",
        on(report.pii_email),
        on(report.pii_phone),
        on(report.pii_personnummer)
    )
}

fn pii_line(pii: &PiiSection) -> String {
    format!(
        "email={} phone={} personnummer={}",
        on(pii.email),
        on(pii.phone),
        on(pii.personnummer)
    )
}

fn names_line(cfg: &Config) -> String {
    format!(
        "terms={} people={}",
        cfg.redact.names.terms.len(),
        cfg.redact.names.people.len()
    )
}

fn domains_text(domains: &[String]) -> String {
    if domains.is_empty() {
        "none".to_string()
    } else {
        domains.join(" ")
    }
}

fn yes(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn on(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_bits_looser_than_owner_read_write_warn() {
        assert!(!mode_looser_than_owner_rw(0o600));
        assert!(!mode_looser_than_owner_rw(0o400));
        assert!(!mode_looser_than_owner_rw(0o200));
        assert!(mode_looser_than_owner_rw(0o644));
        assert!(mode_looser_than_owner_rw(0o640));
        assert!(mode_looser_than_owner_rw(0o700));
        assert!(mode_looser_than_owner_rw(0o607));
    }

    #[test]
    fn upstream_bases_accept_https_and_loopback_only() {
        assert!(base_is_https_or_loopback("https://api.openai.invalid"));
        assert!(base_is_https_or_loopback("HTTPS://api.openai.invalid"));
        assert!(base_is_https_or_loopback("http://127.0.0.1:9"));
        assert!(base_is_https_or_loopback("http://127.1.2.3"));
        assert!(base_is_https_or_loopback("http://localhost"));
        assert!(base_is_https_or_loopback("http://LOCALHOST:9"));
        assert!(base_is_https_or_loopback("http://[::1]:9"));
        assert!(!base_is_https_or_loopback("http://upstream.invalid"));
        assert!(!base_is_https_or_loopback("http://192.0.2.10"));
        assert!(!base_is_https_or_loopback("http://0.0.0.0:9"));
        assert!(!base_is_https_or_loopback("ftp://127.0.0.1"));
        assert!(!base_is_https_or_loopback("api.openai.invalid"));
        assert!(!base_is_https_or_loopback(""));
        assert!(!base_is_https_or_loopback("https://"));
    }

    #[test]
    fn display_base_strips_userinfo() {
        let shown = display_base("https://user:s3cret-token@api.openai.invalid/v1");
        assert_eq!(shown, "https://api.openai.invalid/v1");
        assert!(!shown.contains("s3cret-token"));
        assert_eq!(display_base("http://127.0.0.1:9"), "http://127.0.0.1:9");
    }

    #[test]
    fn sample_counts_hide_originals_until_reveal() {
        let hit = Hit {
            original: "AKIAIOSFODNN7EXAMPLE".to_string(),
            placeholder: "@@sv:0123abcd@@".to_string(),
            category: crate::Category::Secret,
            rule: Some("aws-access-key-id".to_string()),
            action: Action::Redact,
        };
        let hidden = sample_from_hits(std::slice::from_ref(&hit), 0, false);
        assert!(hidden.values.is_empty());
        assert!(!hidden.local_only);
        assert_eq!(hidden.replacements.get("secret").copied(), Some(1));
        let mut text = String::new();
        push_sample(&mut text, &hidden);
        assert!(!text.contains("AKIA"));
        assert!(!text.contains("@@sv:"));
        assert!(text.contains("secret=1"));

        let shown = sample_from_hits(&[hit], 0, true);
        let mut text = String::new();
        push_sample(&mut text, &shown);
        assert!(text.contains("LOCAL ONLY"));
        assert!(text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(text.contains("@@sv:0123abcd@@"));
        assert!(shown.local_only);
    }
}
