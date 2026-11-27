//! `symveil learn`: a local, read-only scan that helps you fill redaction lists.
//!
//! No HTTP client, no sockets, no model. The dependency crate is
//! `symveil-detect`. A list produced here is input to the proxy. It is not a
//! guarantee that a later request is clean, and this command does not sandbox
//! the tree.

#![forbid(unsafe_code)]

#[cfg(test)]
mod corpus;
mod extract;
#[cfg(test)]
mod guard;
mod model;
mod offline;
mod preview;
mod progress;
mod session;
mod stoplist;
mod store;
mod walk;

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

pub use model::{Decision, LearnCategory};
pub use offline::assert_offline;
pub use progress::stderr_is_tty;

pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Options {
    pub root: PathBuf,
    /// Override the output path. Default is the user config `learned.toml`.
    pub out: Option<PathBuf>,
    /// Print a masked summary and do not prompt or write.
    pub report: bool,
    /// Print full secret values. Off by default.
    pub reveal: bool,
    pub max_bytes: u64,
    /// When false, `.gitignore` rules are not applied. `.git` and build
    /// directories are still skipped.
    pub gitignore: bool,
    /// Follow symlinks that resolve inside the scan root. Default is off,
    /// and a link that resolves outside the root is never followed.
    pub follow_symlinks: bool,
    /// Also scan build directories other than `.git`, and text inside files
    /// that are normally skipped by extension.
    pub include_skipped: bool,
    /// Glob patterns that are not scanned. Independent of the built-in
    /// directory list and of `--include-skipped`.
    pub exclude: Vec<String>,
    pub progress: ProgressMode,
    /// When stderr is a terminal, progress is redrawn in place.
    pub progress_tty: bool,
    /// A file at least this slow is named on stderr and in the report.
    pub slow_threshold: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressMode {
    Auto,
    On,
    Off,
}

impl ProgressMode {
    fn enabled(self) -> bool {
        match self {
            Self::Auto | Self::On => true,
            Self::Off => false,
        }
    }
}

/// CLI entry. Refuses to run when LLM or proxy endpoint variables are set.
pub fn run(opts: Options) -> Result<()> {
    assert_offline()?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    execute(&opts, &mut stdin.lock(), &mut stdout.lock())
}

/// Scan and, unless `report`, prompt. Does not read proxy settings.
pub fn execute(opts: &Options, stdin: &mut dyn BufRead, stdout: &mut dyn Write) -> Result<()> {
    execute_io(opts, stdin, stdout, progress::stderr_sink())
}

pub fn execute_io(
    opts: &Options,
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: Box<dyn Write + Send>,
) -> Result<()> {
    reject_url_path(&opts.root)?;
    let root = opts
        .root
        .canonicalize()
        .with_context(|| format!("open {}", opts.root.display()))?;
    if !root.is_dir() {
        bail!("{} is not a directory", root.display());
    }
    let walked = walk::walk(
        &root,
        &walk::WalkOptions {
            max_bytes: opts.max_bytes,
            gitignore: opts.gitignore,
            follow_symlinks: opts.follow_symlinks,
            include_skipped: opts.include_skipped,
            exclude: opts.exclude.clone(),
        },
    )?;
    let total_bytes = walked.files.iter().map(|file| file.text.len() as u64).sum();
    let ticker = progress::Progress::start(
        opts.progress.enabled(),
        opts.progress_tty,
        walked.files.len(),
        total_bytes,
        opts.slow_threshold,
        stderr,
    );
    let parts: Vec<extract::Prepared> = walked
        .files
        .par_iter()
        .map(|file| {
            ticker.note_current(&file.relative);
            let started = std::time::Instant::now();
            let prepared = extract::prepare(&file.text);
            ticker.finish_file(&file.relative, file.text.len() as u64, started.elapsed());
            prepared
        })
        .collect();
    ticker.finish();
    let slow = ticker.slow_files();
    let mut candidates = extract::candidates_from(&walked.files, parts);
    if opts.report {
        report::write_report(&walked, &candidates, opts.reveal, &slow, stdout)?;
        return Ok(());
    }
    let out = output_path(opts)?;
    ensure_outside_root(&root, &out)?;
    let decisions = if out.is_file() {
        store::load_decisions(&out)?
    } else {
        Vec::new()
    };
    session::mark_related(&mut candidates, &decisions);
    let decisions = session::review(
        opts.reveal,
        &walked,
        &mut candidates,
        decisions,
        stdin,
        stdout,
    )?;
    let file = store::file_from_decisions(&decisions)?;
    let bytes = file.to_toml()?;
    store::write_private(&out, bytes.as_bytes())?;
    writeln!(
        stdout,
        "wrote {} ({} decisions)",
        out.display(),
        decisions.len()
    )?;
    Ok(())
}

fn reject_url_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.contains("://") {
        bail!(
            "symveil learn scans a local directory and refuses `{text}` because it is a URL. It does not open a network connection."
        );
    }
    Ok(())
}

fn output_path(opts: &Options) -> Result<PathBuf> {
    if let Some(path) = &opts.out {
        if path.is_absolute() {
            Ok(path.clone())
        } else {
            Ok(std::env::current_dir()
                .context("current directory")?
                .join(path))
        }
    } else {
        symveil_detect::learned::default_path()
            .context("HOME is not set, so there is no default learned.toml path. Pass --out.")
    }
}

fn ensure_outside_root(root: &Path, out: &Path) -> Result<()> {
    let parent = out.parent().filter(|dir| !dir.as_os_str().is_empty());
    let Some(parent) = parent else {
        bail!("refusing to write learned.toml into the scanned tree");
    };
    let ancestor = existing_ancestor(parent);
    let canon = ancestor
        .canonicalize()
        .with_context(|| format!("open {}", ancestor.display()))?;
    if canon.starts_with(root) {
        bail!(
            "refusing to write {} inside the scanned tree {}",
            out.display(),
            root.display()
        );
    }
    Ok(())
}

fn existing_ancestor(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() || current.parent().is_none() {
            return current;
        }
        current.pop();
    }
}

mod report {
    use std::io::Write;

    use anyhow::Result;

    use crate::model::Candidate;
    use crate::preview::preview;
    use crate::walk::Walked;

    pub fn write_report(
        walked: &Walked,
        candidates: &[Candidate],
        reveal: bool,
        slow: &[crate::progress::SlowFile],
        stdout: &mut dyn Write,
    ) -> Result<()> {
        let stats = &walked.stats;
        writeln!(stdout, "symveil learn report")?;
        writeln!(
            stdout,
            "offline, read-only. no model, no network. secrets are masked unless --reveal."
        )?;
        writeln!(
            stdout,
            "files {}  candidates {}  skipped_dir {}  skipped_gitignore {}  skipped_symlink {}  skipped_large {}  skipped_binary {}",
            walked.files.len(),
            candidates.len(),
            stats.dirs,
            stats.gitignore,
            stats.symlinks,
            stats.large,
            stats.binary
        )?;
        let skips = crate::walk::skip_summary(stats);
        if !skips.is_empty() {
            writeln!(stdout, "{skips}")?;
        }
        writeln!(
            stdout,
            "a name in this list is a candidate, not proof it must be redacted, and absence is not proof it is safe to send."
        )?;
        let mut current = None;
        for candidate in candidates {
            if current != Some(candidate.category) {
                current = Some(candidate.category);
                writeln!(stdout)?;
                writeln!(stdout, "[{}]", candidate.category.as_str())?;
            }
            let body = preview(&candidate.text, candidate.secretish, reveal);
            let rule = candidate
                .rule
                .as_deref()
                .map(|rule| format!(" rule={rule}"))
                .unwrap_or_default();
            writeln!(
                stdout,
                "{body}{rule}  hits={} files={}  {}:{}",
                candidate.occurrences, candidate.files, candidate.first_file, candidate.first_line
            )?;
        }
        crate::progress::write_slow_summary(slow, stdout)?;
        Ok(())
    }
}

#[cfg(test)]
mod scan_tests {
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "symveil-learn-scan-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn options(root: PathBuf, progress: ProgressMode, slow: Duration) -> Options {
        Options {
            root,
            out: None,
            report: true,
            reveal: false,
            max_bytes: DEFAULT_MAX_BYTES,
            gitignore: true,
            follow_symlinks: false,
            include_skipped: false,
            exclude: Vec::new(),
            progress,
            progress_tty: false,
            slow_threshold: slow,
        }
    }

    #[test]
    fn a_zero_threshold_names_the_slow_file() {
        let root = temp_dir("slow");
        std::fs::write(root.join("slow.txt"), "fn tundrahorn_fan_init() {}\n").unwrap();
        let opts = options(root.clone(), ProgressMode::Off, Duration::ZERO);
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut stdout = Vec::new();
        let mut stdin = Cursor::new(Vec::<u8>::new());
        execute_io(
            &opts,
            &mut stdin,
            &mut stdout,
            Box::new(progress::SharedBuf::new(Arc::clone(&buf))),
        )
        .unwrap();
        let stderr = String::from_utf8(buf.lock().expect("stderr").clone()).unwrap();
        let report = String::from_utf8(stdout).unwrap();
        assert!(stderr.contains("slow file"), "{stderr}");
        assert!(stderr.contains("slow.txt"), "{stderr}");
        assert!(report.contains("slow files:"), "{report}");
        assert!(!report.contains("symveil learn:"), "{report}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn quiet_scan_omits_the_ticker() {
        let root = temp_dir("quiet");
        std::fs::write(root.join("keep.txt"), "fn tundrahorn_fan_init() {}\n").unwrap();
        let opts = options(root.clone(), ProgressMode::Off, Duration::from_secs(2));
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut stdout = Vec::new();
        let mut stdin = Cursor::new(Vec::<u8>::new());
        execute_io(
            &opts,
            &mut stdin,
            &mut stdout,
            Box::new(progress::SharedBuf::new(Arc::clone(&buf))),
        )
        .unwrap();
        let stderr = String::from_utf8(buf.lock().expect("stderr").clone()).unwrap();
        assert!(!stderr.contains("symveil learn:"), "quiet stderr: {stderr}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
