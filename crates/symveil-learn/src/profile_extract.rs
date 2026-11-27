//! Ignored profiler for `symveil learn` extraction. Not part of CI.
//! Run: SYMVEIL_LEARN_PROFILE=1 cargo test -p symveil-learn --release --lib profile_ -- --ignored --nocapture

use std::io::Write;
use std::time::Instant;

use regex::Regex;
use symveil_detect::secrets::{high_entropy_hits, scan_secrets};

use crate::walk::WalkedFile;

use super::{extract, extract_file, lex};

fn time<T>(label: &str, body: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let value = body();
    eprintln!("stage {label} {:?}", started.elapsed());
    value
}

fn count_matches(label: &str, re: &Regex, text: &str) {
    time(label, || re.find_iter(text).count());
}

fn minified_js(bytes: usize) -> String {
    let mut out = String::with_capacity(bytes);
    let mut n = 0u32;
    while out.len() + 80 < bytes {
        let chunk = format!(
            "function f{n}(a,b){{return a+b+\"cdn{n}.assets.example\";}}var s{n}=\"abcdefghijklmnopqrstuvwxyz012345\";"
        );
        out.push_str(&chunk);
        n += 1;
    }
    out
}

fn source_blob(bytes: usize) -> String {
    let mut out = String::with_capacity(bytes);
    let mut n = 0u32;
    while out.len() + 160 < bytes {
        let chunk = format!(
            "fn widget_{n}_init() {{\n    // Exempla ships the Tundrahorn fan.\n    let host = \"db{n}.tundrahorn.internal\";\n    let mail = \"ren.testdotter@tundrahorn.example\";\n    let ip = \"10.9.{}.{}\";\n    const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\n}}\n",
            (n / 250) % 250,
            n % 250
        );
        out.push_str(&chunk);
        n += 1;
    }
    out
}

fn long_line(bytes: usize) -> String {
    let token = "alpha_beta_gamma_delta_";
    let mut out = String::with_capacity(bytes + token.len());
    while out.len() < bytes {
        out.push_str(token);
    }
    out.truncate(bytes);
    out
}

#[test]
#[ignore]
fn profile_one_megabyte_shapes() {
    let minified = minified_js(1_000_000);
    let source = source_blob(1_000_000);
    let line = long_line(1_000_000);
    eprintln!("minified_len {}", minified.len());

    time("scan_secrets minified", || scan_secrets(&minified).len());
    time("entropy minified", || high_entropy_hits(&minified).len());
    time("lex minified", || {
        let (comments, strings) = lex(&minified);
        comments.len() + strings.len()
    });
    time("extract_file minified", || extract_file(&minified).len());
    time("extract one minified file", || {
        extract(&[WalkedFile {
            relative: "web/app.min.js".to_string(),
            text: minified.clone(),
        }])
        .len()
    });

    time("scan_secrets source", || scan_secrets(&source).len());
    time("entropy source", || high_entropy_hits(&source).len());
    time("lex source", || {
        let (comments, strings) = lex(&source);
        comments.len() + strings.len()
    });
    time("extract_file source", || extract_file(&source).len());

    time("scan_secrets long", || scan_secrets(&line).len());
    time("entropy long", || high_entropy_hits(&line).len());
    time("extract_file long", || extract_file(&line).len());
    let short_line = long_line(64 * 1024);
    time("extract 64KiB long line", || {
        extract(&[WalkedFile {
            relative: "gen/long.txt".to_string(),
            text: short_line,
        }])
        .len()
    });

    count_matches("HOST minified", &super::HOST, &minified);
    count_matches("EMAIL minified", &super::EMAIL, &minified);
    count_matches("URL minified", &super::URL, &minified);
    count_matches("IPV4 minified", &super::IPV4, &minified);
    count_matches("IDENT minified", &super::IDENT, &minified);
    count_matches("PERSON minified", &super::PERSON_PAIR, &minified);
    count_matches("CAP minified", &super::CAP_WORD, &minified);
    count_matches("HOST long", &super::HOST, &line);
    count_matches("IDENT long", &super::IDENT, &line);
    count_matches("PERSON long", &super::PERSON_PAIR, &line);
}

fn ident_files(count: usize) -> Vec<WalkedFile> {
    (0..count)
        .map(|index| {
            let mut text = String::new();
            for slot in 0..40 {
                let n = index * 40 + slot;
                text.push_str(&format!(
                    "fn name{n}_handler() {{ /* code TDH-4471 */ let _ = TDH_FAN_MAX; }}\n"
                ));
            }
            WalkedFile {
                relative: format!("src/file_{index}.rs"),
                text,
            }
        })
        .collect()
}

fn write_repeat(path: &std::path::Path, byte: u8, len: usize) {
    let file = std::fs::File::create(path).unwrap();
    let mut writer = std::io::BufWriter::new(file);
    let chunk = vec![byte; 64 * 1024];
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len());
        writer.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    writer.flush().unwrap();
}

/// Non-git tree shaped like a vendored embedded-Linux BSP plus a smaller
/// project. About 17k files, ~157 MB of text, ~2.1M lines. Roughly 80% of the
/// text is C, u-boot style board code, recipes, and patches under `bsp/`.
/// `build/`, `vendor/`, and the other built-in skip dirs hold bulk that the
/// default scan must not read. There is no `.git` and no `.gitignore`.
fn bench_paths() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    (
        base.join("learn-bench-corpus"),
        base.join("learn-bench-corpus.ok"),
        base.join("learn-bench-corpus.meta"),
    )
}

fn ensure_synthetic_tree(root: &std::path::Path) -> TreeStats {
    let (_, marker, meta_path) = bench_paths();
    if marker.is_file()
        && root.join("bsp").is_dir()
        && std::fs::read_to_string(&marker).ok().as_deref() == Some("bsp-v3\n")
    {
        let meta = std::fs::read_to_string(&meta_path).unwrap();
        eprintln!("reusing synthetic tree at {} ({meta})", root.display());
        return TreeStats::parse(&meta);
    }
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).unwrap();
    let started = Instant::now();
    let mut stats = TreeStats::default();
    let mut dirs = std::collections::HashSet::new();

    let mut add_file = |path: &std::path::Path, data: &[u8], kind: FileKind| {
        if let Some(parent) = path.parent() {
            let mut cursor = parent.to_path_buf();
            let mut chain = Vec::new();
            while cursor != root && cursor.starts_with(root) {
                chain.push(cursor.clone());
                if !cursor.pop() {
                    break;
                }
            }
            for dir in chain.into_iter().rev() {
                dirs.insert(dir);
            }
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, data).unwrap();
        stats.files += 1;
        stats.bytes += data.len() as u64;
        if kind.scanned_text() {
            let text = std::str::from_utf8(data).unwrap();
            let lines = text.lines().count() as u64;
            stats.text_files += 1;
            stats.text_bytes += data.len() as u64;
            stats.lines += lines;
            if kind.bsp() {
                stats.bsp_files += 1;
                stats.bsp_bytes += data.len() as u64;
                stats.bsp_lines += lines;
            }
        }
    };

    for index in 0..TEXT_FILES {
        let (rel, kind) = text_file(index);
        let body = render_file(kind, index);
        add_file(&root.join(&rel), body.as_bytes(), kind);
    }

    let mut binary = vec![0u8, 1, 2, 3, 255];
    binary.extend(b"binary-ish blob");
    binary.resize(2048, 9);
    for index in 0..240 {
        add_file(
            &root.join(format!("assets/bin{index}.bin")),
            &binary,
            FileKind::Binary,
        );
    }

    let skip_body = b"VENDOR_SHOULD_SKIP synth bulk that the default scan must not read\n";
    let mut skip_blob = Vec::new();
    while skip_blob.len() < 2 * 1024 * 1024 {
        skip_blob.extend_from_slice(skip_body);
    }
    for (rel, copies) in [
        ("build/tmp/work/out.txt", 4u64),
        ("node_modules/synth-pkg/index.js", 2),
        ("dist/bundle.js", 1),
        ("target/debug/notes.txt", 1),
        ("vendor/third/lib.c", 6),
        (".venv/lib/const.py", 1),
        ("__pycache__/mod.py", 1),
    ] {
        let mut data = Vec::new();
        for _ in 0..copies {
            data.extend_from_slice(&skip_blob);
        }
        add_file(&root.join(rel), &data, FileKind::SkippedBulk);
    }
    std::fs::create_dir_all(root.join("blobs")).unwrap();
    for index in 0..4 {
        let path = root.join(format!("blobs/oversized{index}.dat"));
        write_repeat(&path, b'Z', 8 * 1024 * 1024);
        stats.files += 1;
        stats.bytes += 8 * 1024 * 1024;
        if let Some(parent) = path.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }

    stats.dirs = dirs.len();
    let meta = stats.meta_line();
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&meta_path, &meta).unwrap();
    std::fs::write(&marker, b"bsp-v3\n").unwrap();
    eprintln!("generated synthetic tree {meta} {:?}", started.elapsed());
    stats
}

const TEXT_FILES: u32 = 16_800;
const BSP_FILES: u32 = 13_440;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Kernel,
    Uboot,
    Recipe,
    Patch,
    Project,
    Long,
    Minified,
    Binary,
    SkippedBulk,
}

impl FileKind {
    fn scanned_text(self) -> bool {
        !matches!(self, Self::Binary | Self::SkippedBulk)
    }

    fn bsp(self) -> bool {
        matches!(
            self,
            Self::Kernel | Self::Uboot | Self::Recipe | Self::Patch
        )
    }
}

#[derive(Clone, Copy, Default)]
struct TreeStats {
    files: usize,
    dirs: usize,
    bytes: u64,
    text_files: usize,
    text_bytes: u64,
    lines: u64,
    bsp_files: usize,
    bsp_bytes: u64,
    bsp_lines: u64,
}

impl TreeStats {
    fn meta_line(self) -> String {
        format!(
            "files={} dirs={} bytes={} text_files={} text_bytes={} lines={} bsp_files={} bsp_bytes={} bsp_lines={}",
            self.files,
            self.dirs,
            self.bytes,
            self.text_files,
            self.text_bytes,
            self.lines,
            self.bsp_files,
            self.bsp_bytes,
            self.bsp_lines
        )
    }

    fn parse(meta: &str) -> Self {
        let mut stats = Self::default();
        for part in meta.split_whitespace() {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let value: u64 = value.parse().unwrap();
            match key {
                "files" => stats.files = value as usize,
                "dirs" => stats.dirs = value as usize,
                "bytes" => stats.bytes = value,
                "text_files" => stats.text_files = value as usize,
                "text_bytes" => stats.text_bytes = value,
                "lines" => stats.lines = value,
                "bsp_files" => stats.bsp_files = value as usize,
                "bsp_bytes" => stats.bsp_bytes = value,
                "bsp_lines" => stats.bsp_lines = value,
                _ => {}
            }
        }
        stats
    }
}

fn text_file(index: u32) -> (String, FileKind) {
    let leaf = index / 3;
    let slot = index % 3;
    let layer = leaf / 80;
    let group = (leaf / 10) % 8;
    let bsp = index < BSP_FILES;
    let top = if !bsp {
        "src"
    } else if layer.is_multiple_of(3) {
        "bsp/kernel"
    } else if layer % 3 == 1 {
        "bsp/u-boot"
    } else {
        "bsp/meta"
    };
    let dir = format!("{top}/l{layer}/g{group}/p{leaf}");
    let (name, kind) = if !bsp {
        if index >= TEXT_FILES - 6 {
            (format!("long_{slot}.txt"), FileKind::Long)
        } else if index >= TEXT_FILES - 10 {
            (format!("app_{slot}.min.js"), FileKind::Minified)
        } else {
            (format!("mod_{slot}.py"), FileKind::Project)
        }
    } else {
        match slot {
            0 => (format!("synth_{leaf}.c"), FileKind::Kernel),
            1 => (format!("board_{leaf}.c"), FileKind::Uboot),
            _ if leaf.is_multiple_of(2) => (format!("synth_{leaf}.bb"), FileKind::Recipe),
            _ => (format!("board_{leaf}.patch"), FileKind::Patch),
        }
    };
    (format!("{dir}/{name}"), kind)
}

fn render_file(kind: FileKind, index: u32) -> String {
    match kind {
        FileKind::Long => {
            let mut out = String::new();
            let token = "alpha_beta_gamma_delta_";
            while out.len() < 48 * 1024 {
                out.push_str(token);
            }
            out.push('\n');
            out
        }
        FileKind::Minified => {
            let mut out = String::new();
            let mut n = 0u32;
            while out.len() < 64 * 1024 {
                out.push_str("function f");
                out.push_str(&n.to_string());
                out.push_str("(a,b){return a+b;}var s");
                out.push_str(&n.to_string());
                out.push_str("=\"abcdefghijklmnopqrstuvwxyz012345\";");
                n += 1;
            }
            out.push('\n');
            out
        }
        FileKind::Binary | FileKind::SkippedBulk => String::new(),
        other => pad_lines(&header_for(other, index), 126),
    }
}

fn header_for(kind: FileKind, index: u32) -> String {
    match kind {
        FileKind::Kernel => format!(
            "#include <synth/module.h>\n#include \"synth_board.h\"\n\n/* Exempla Tundrahorn synthetic kernel driver. */\nstatic int synth_gpio_probe(int pin)\n{{\n    if (pin < 0) {{\n        return -1;\n    }}\n    return pin + {index};\n}}\n"
        ),
        FileKind::Uboot => format!(
            "#include <synth/common.h>\n#include \"synth_board.h\"\n\n/* Exempla Tundrahorn synthetic board bring-up. */\nint board_early_init(void)\n{{\n    return synth_gpio_probe({index});\n}}\n"
        ),
        FileKind::Recipe => format!(
            "SUMMARY = \"Synthetic gpio controller {index}\"\nLICENSE = \"CLOSED\"\nSRC_URI = \"file://synth_gpio.c file://board.patch\"\nS = \"${{WORKDIR}}/synth\"\n\ndo_install() {{\n    install -d ${{D}}${{bindir}}\n}}\n"
        ),
        FileKind::Patch => format!(
            "diff --git a/synth/gpio.c b/synth/gpio.c\n--- a/synth/gpio.c\n+++ b/synth/gpio.c\n@@ -8,6 +8,7 @@ static int synth_gpio_request(int pin)\n {{\n+    /* board hook {index} */\n     return pin;\n"
        ),
        FileKind::Project => {
            "def synth_board_init():\n    host = \"db.tundrahorn.internal\"\n    return host\n"
                .to_string()
        }
        FileKind::Long | FileKind::Minified | FileKind::Binary | FileKind::SkippedBulk => {
            String::new()
        }
    }
}

/// Repeat a fixed-width comment until `lines` newlines are present.
fn pad_lines(header: &str, lines: usize) -> String {
    let mut out = String::with_capacity(lines * 74);
    out.push_str(header);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    let mut have = out.bytes().filter(|byte| *byte == b'\n').count();
    while have < lines {
        out.push_str(
            "    /* synth tundrahorn padding line for the local scan corpus.............. */\n",
        );
        have += 1;
    }
    out
}

#[test]
#[ignore]
fn profile_synthetic_tree() {
    let (root, _, _) = bench_paths();
    let root = root.as_path();
    let stats = ensure_synthetic_tree(root);
    assert!(
        (16_000..18_500).contains(&stats.files),
        "files {}",
        stats.files
    );
    assert!((5_000..7_500).contains(&stats.dirs), "dirs {}", stats.dirs);
    assert!(
        (145_000_000..175_000_000).contains(&stats.text_bytes),
        "text bytes {}",
        stats.text_bytes
    );
    assert!(
        (1_900_000..2_300_000).contains(&stats.lines),
        "lines {}",
        stats.lines
    );
    let fraction = stats.bsp_bytes as f64 / stats.text_bytes as f64;
    assert!(
        (0.75..0.85).contains(&fraction),
        "bsp fraction {fraction} bytes {}",
        stats.bsp_bytes
    );
    assert!(
        !root.join(".git").exists(),
        "benchmark tree must not be a git repo"
    );
    assert!(root.join("build").is_dir());
    assert!(root.join("vendor").is_dir());
    assert!(root.join("node_modules").is_dir());
    eprintln!(
        "shape files={} dirs={} bytes={} text_bytes={} lines={} bsp_bytes={} fraction={fraction:.3}",
        stats.files, stats.dirs, stats.bytes, stats.text_bytes, stats.lines, stats.bsp_bytes
    );

    let started = Instant::now();
    let walked = crate::walk::walk(
        root,
        &crate::walk::WalkOptions {
            max_bytes: crate::DEFAULT_MAX_BYTES,
            gitignore: true,
            follow_symlinks: false,
            include_skipped: false,
            exclude: Vec::new(),
        },
    )
    .unwrap();
    let walk_elapsed = started.elapsed();
    let text_bytes: u64 = walked.files.iter().map(|file| file.text.len() as u64).sum();
    eprintln!(
        "walk files={} text_bytes={text_bytes} skipped_large={} binary={} gitignore={} dirs={} {:?}",
        walked.files.len(),
        walked.stats.large,
        walked.stats.binary,
        walked.stats.gitignore,
        walked.stats.dirs,
        walk_elapsed
    );
    let started = Instant::now();
    let found = extract(&walked.files);
    let extract_elapsed = started.elapsed();
    eprintln!(
        "extract candidates={} {:?} total {:?} cores={}",
        found.len(),
        extract_elapsed,
        walk_elapsed + extract_elapsed,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
}

#[test]
#[ignore]
fn profile_promote_scaling() {
    for count in [30usize, 60, 120] {
        let files = ident_files(count);
        let bytes: usize = files.iter().map(|file| file.text.len()).sum();
        let started = Instant::now();
        let found = extract(&files);
        eprintln!(
            "extract files={count} bytes={bytes} candidates={} {:?}",
            found.len(),
            started.elapsed()
        );
    }
}
