//! Read-only walk. Nothing here creates, truncates, or renames a file in the tree.
//! Symlinks are skipped unless the caller asks to follow them, and a link that
//! resolves outside the root is never opened.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use regex::Regex;

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".gradle",
    ".hg",
    ".next",
    ".nuxt",
    ".svn",
    ".symveil",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
    "venv",
];

const BINARY_EXT: &[&str] = &[
    "a", "bin", "bmp", "bz2", "class", "dll", "dylib", "eot", "exe", "gif", "gz", "ico", "jar",
    "jpeg", "jpg", "mov", "mp3", "mp4", "o", "pdf", "png", "pyc", "pyo", "so", "sqlite", "ttf",
    "wasm", "webp", "woff", "woff2", "xz", "zip", "7z",
];

#[derive(Debug, Clone)]
pub struct WalkOptions {
    pub max_bytes: u64,
    pub gitignore: bool,
    pub follow_symlinks: bool,
}

#[derive(Debug, Default)]
pub struct WalkStats {
    pub dirs: usize,
    pub gitignore: usize,
    pub symlinks: usize,
    pub large: usize,
    pub binary: usize,
    pub unreadable: usize,
}

#[derive(Debug)]
pub struct WalkedFile {
    pub relative: String,
    pub text: String,
}

#[derive(Debug, Default)]
pub struct Walked {
    pub files: Vec<WalkedFile>,
    pub stats: WalkStats,
    pub warnings: Vec<String>,
}

#[derive(Clone)]
struct GitRule {
    base: String,
    negation: bool,
    dir_only: bool,
    regex: Regex,
}

pub fn walk(root: &Path, opts: &WalkOptions) -> Result<Walked> {
    let mut walked = Walked::default();
    let mut seen = HashSet::new();
    walk_dir(root, root, opts, &[], &mut seen, &mut walked)?;
    walked.files.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(walked)
}

fn walk_dir(
    root: &Path,
    dir: &Path,
    opts: &WalkOptions,
    inherited: &[GitRule],
    seen: &mut HashSet<PathBuf>,
    walked: &mut Walked,
) -> Result<()> {
    if !seen.insert(dir.to_path_buf()) {
        return Ok(());
    }
    let mut rules = inherited.to_vec();
    if opts.gitignore {
        append_gitignore(root, dir, &mut rules);
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            walked
                .warnings
                .push(format!("skip {}: {err}", dir.display()));
            walked.stats.unreadable += 1;
            return Ok(());
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => paths.push(entry.path()),
            Err(err) => {
                walked
                    .warnings
                    .push(format!("skip entry in {}: {err}", dir.display()));
                walked.stats.unreadable += 1;
            }
        }
    }
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) => {
                walked
                    .warnings
                    .push(format!("skip {}: {err}", path.display()));
                walked.stats.unreadable += 1;
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            if !opts.follow_symlinks {
                walked.stats.symlinks += 1;
                continue;
            }
            follow_link(root, &path, &name, opts, &rules, seen, walked)?;
            continue;
        }
        if meta.is_dir() {
            if skip_dir(&name) {
                walked.stats.dirs += 1;
                continue;
            }
            if let Some(rel) = relative_slash(root, &path) {
                if ignored(&rules, &rel, true) {
                    walked.stats.gitignore += 1;
                    continue;
                }
            }
            walk_dir(root, &path, opts, &rules, seen, walked)?;
            continue;
        }
        if meta.is_file() {
            consider_file(root, &path, meta.len(), &rules, opts, walked);
        }
    }
    Ok(())
}

fn follow_link(
    root: &Path,
    path: &Path,
    name: &str,
    opts: &WalkOptions,
    rules: &[GitRule],
    seen: &mut HashSet<PathBuf>,
    walked: &mut Walked,
) -> Result<()> {
    let canon = match fs::canonicalize(path) {
        Ok(canon) => canon,
        Err(_) => {
            walked.stats.symlinks += 1;
            return Ok(());
        }
    };
    if !canon.starts_with(root) {
        walked.stats.symlinks += 1;
        return Ok(());
    }
    let meta = match fs::metadata(&canon) {
        Ok(meta) => meta,
        Err(_) => {
            walked.stats.symlinks += 1;
            return Ok(());
        }
    };
    if meta.is_dir() {
        if skip_dir(name) {
            walked.stats.dirs += 1;
            return Ok(());
        }
        walk_dir(root, &canon, opts, rules, seen, walked)?;
        return Ok(());
    }
    if meta.is_file() {
        consider_file(root, &canon, meta.len(), rules, opts, walked);
    }
    Ok(())
}

fn consider_file(
    root: &Path,
    path: &Path,
    len: u64,
    rules: &[GitRule],
    opts: &WalkOptions,
    walked: &mut Walked,
) {
    let Some(rel) = relative_slash(root, path) else {
        walked.stats.symlinks += 1;
        return;
    };
    if ignored(rules, &rel, false) {
        walked.stats.gitignore += 1;
        return;
    }
    if len > opts.max_bytes {
        walked.stats.large += 1;
        return;
    }
    if binary_ext(path) {
        walked.stats.binary += 1;
        return;
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            walked.warnings.push(format!("skip {rel}: {err}"));
            walked.stats.unreadable += 1;
            return;
        }
    };
    if bytes.contains(&0) {
        walked.stats.binary += 1;
        return;
    }
    let Ok(text) = String::from_utf8(bytes) else {
        walked.stats.binary += 1;
        return;
    };
    walked.files.push(WalkedFile {
        relative: rel,
        text,
    });
}

fn skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name)
}

fn binary_ext(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    let lower = ext.to_ascii_lowercase();
    BINARY_EXT.iter().any(|item| *item == lower)
}

fn relative_slash(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    if rel.as_os_str().is_empty() {
        return None;
    }
    Some(rel.to_string_lossy().replace('\\', "/"))
}

fn append_gitignore(root: &Path, dir: &Path, rules: &mut Vec<GitRule>) {
    let path = dir.join(".gitignore");
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return;
    }
    let Ok(text) = fs::read_to_string(&path) else {
        return;
    };
    let base = relative_slash(root, dir).unwrap_or_default();
    rules.extend(parse_gitignore(&text, &base));
}

fn parse_gitignore(text: &str, base: &str) -> Vec<GitRule> {
    let mut rules = Vec::new();
    for raw in text.lines() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let negation = line.starts_with('!');
        if negation {
            line = line[1..].trim();
        }
        if line.is_empty() {
            continue;
        }
        let dir_only = line.ends_with('/');
        if dir_only {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }
        let anchored = line.starts_with('/') || line.contains('/');
        let pattern = line.trim_start_matches('/');
        let Ok(regex) = glob_to_regex(pattern, anchored) else {
            continue;
        };
        rules.push(GitRule {
            base: base.to_string(),
            negation,
            dir_only,
            regex,
        });
    }
    rules
}

fn glob_to_regex(pattern: &str, anchored: bool) -> Result<Regex, regex::Error> {
    let mut re = String::from(if anchored { "^" } else { "(^|.*/)" });
    let chars: Vec<char> = pattern.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '*' if chars.get(index + 1) == Some(&'*') => {
                if chars.get(index + 2) == Some(&'/') {
                    re.push_str("(.*/)?");
                    index += 3;
                } else {
                    re.push_str(".*");
                    index += 2;
                }
            }
            '*' => {
                re.push_str("[^/]*");
                index += 1;
            }
            '?' => {
                re.push_str("[^/]");
                index += 1;
            }
            ch => {
                re.push_str(&regex::escape(&ch.to_string()));
                index += 1;
            }
        }
    }
    re.push('$');
    Regex::new(&re)
}

fn ignored(rules: &[GitRule], rel: &str, is_dir: bool) -> bool {
    let mut matched = false;
    for rule in rules {
        if rule.matches(rel, is_dir) {
            matched = !rule.negation;
        }
    }
    matched
}

impl GitRule {
    fn matches(&self, rel_to_root: &str, is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        let relative = if self.base.is_empty() {
            rel_to_root.to_string()
        } else {
            let prefix = format!("{}/", self.base);
            if rel_to_root == self.base {
                String::new()
            } else if let Some(rest) = rel_to_root.strip_prefix(&prefix) {
                rest.to_string()
            } else {
                return false;
            }
        };
        if relative.is_empty() {
            return false;
        }
        self.regex.is_match(&relative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_tree(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "symveil-walk-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn skips_git_build_symlinks_gitignore_and_large_files() {
        let root = temp_tree("skip");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("src/keep.txt"), "Exempla token\n").unwrap();
        fs::write(root.join(".git/hidden.txt"), "hidden-from-git\n").unwrap();
        fs::write(root.join("target/out.txt"), "hidden-from-target\n").unwrap();
        fs::write(root.join(".gitignore"), "secret.env\n*.log\n").unwrap();
        fs::write(root.join("secret.env"), "hidden-from-gitignore\n").unwrap();
        fs::write(root.join("noise.log"), "hidden-log\n").unwrap();
        fs::write(root.join("blob.bin"), [0u8, 1, 2, 3]).unwrap();
        fs::write(root.join("wide.txt"), "x".repeat(50)).unwrap();
        let outside = temp_tree("outside");
        fs::write(outside.join("secret.txt"), "outside-secret-token\n").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("link.txt")).unwrap();
        let before = fs::read(root.join("src/keep.txt")).unwrap();
        let modified = fs::metadata(root.join("src/keep.txt"))
            .unwrap()
            .modified()
            .unwrap();

        let walked = walk(
            &root,
            &WalkOptions {
                max_bytes: 16,
                gitignore: true,
                follow_symlinks: false,
            },
        )
        .unwrap();
        let joined = walked
            .files
            .iter()
            .map(|file| file.text.clone())
            .collect::<String>();
        assert!(joined.contains("Exempla"));
        assert!(!joined.contains("hidden-from-git"));
        assert!(!joined.contains("hidden-from-target"));
        assert!(!joined.contains("hidden-from-gitignore"));
        assert!(!joined.contains("hidden-log"));
        assert!(!joined.contains("outside-secret-token"));
        assert!(walked.files.iter().all(|file| file.relative != "wide.txt"));
        assert!(walked.stats.large >= 1);
        assert!(walked.stats.symlinks >= 1);
        assert_eq!(fs::read(root.join("src/keep.txt")).unwrap(), before);
        assert_eq!(
            fs::metadata(root.join("src/keep.txt"))
                .unwrap()
                .modified()
                .unwrap(),
            modified
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn gitignore_can_be_turned_off() {
        let root = temp_tree("no-ignore");
        fs::write(root.join(".gitignore"), "secret.env\n").unwrap();
        fs::write(root.join("secret.env"), "visible-when-ignored-off\n").unwrap();
        let walked = walk(
            &root,
            &WalkOptions {
                max_bytes: 1024,
                gitignore: false,
                follow_symlinks: false,
            },
        )
        .unwrap();
        let joined = walked
            .files
            .iter()
            .map(|file| file.text.clone())
            .collect::<String>();
        assert!(joined.contains("visible-when-ignored-off"));
        let _ = fs::remove_dir_all(&root);
    }
}
