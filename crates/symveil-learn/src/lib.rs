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
mod session;
mod stoplist;
mod store;
mod walk;

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

pub use model::{Decision, LearnCategory};
pub use offline::assert_offline;

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
        },
    )?;
    let mut candidates = extract::extract(&walked.files);
    if opts.report {
        report::write_report(&walked, &candidates, opts.reveal, stdout)?;
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
        Ok(())
    }
}
