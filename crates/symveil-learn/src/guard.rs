//! Fails the build if `symveil learn` grows a network dependency.
//!
//! The check reads `Cargo.lock` and the crate sources. It does not run Cargo,
//! so it cannot deadlock on the package lock during `cargo test`.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::Path;

#[test]
fn learn_crate_does_not_pull_network_crates() {
    let banned = banned_names();
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = fs::read_to_string(&lock_path).expect("workspace Cargo.lock");
    let packages = parse_lock(&lock);
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from(["symveil-learn".to_string()]);
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        for package in packages.iter().filter(|package| package.name == name) {
            for dep in &package.deps {
                queue.push_back(dep.clone());
            }
        }
    }
    assert!(
        seen.contains("symveil-learn"),
        "symveil-learn is missing from Cargo.lock"
    );
    let mut hits: Vec<_> = seen
        .iter()
        .filter(|name| banned.iter().any(|item| item == name.as_str()))
        .cloned()
        .collect();
    hits.sort();
    assert!(
        hits.is_empty(),
        "symveil-learn dependency closure includes network crates: {}",
        hits.join(", ")
    );

    let detect = Path::new(env!("CARGO_MANIFEST_DIR")).join("../symveil-detect");
    for root in [Path::new(env!("CARGO_MANIFEST_DIR")), detect.as_path()] {
        scan_tree(&root.join("src"), &banned);
        let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_clean(
            &root.join("Cargo.toml").display().to_string(),
            &manifest,
            &banned,
        );
    }
}

fn scan_tree(dir: &Path, banned: &[String]) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            scan_tree(&path, banned);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        assert_clean(&path.display().to_string(), &text, banned);
    }
}

fn assert_clean(label: &str, text: &str, banned: &[String]) {
    for name in banned {
        if name.len() < 4 {
            continue;
        }
        assert!(
            !text.contains(name),
            "{label} mentions `{name}`; learn stays offline"
        );
    }
}

fn banned_names() -> Vec<String> {
    const PARTS: &[&[&str]] = &[
        &["req", "west"],
        &["hy", "per"],
        &["hy", "per-util"],
        &["ur", "eq"],
        &["tok", "io"],
        &["ax", "um"],
        &["h2"],
        &["socket", "2"],
        &["mi", "o"],
        &["rust", "ls"],
        &["native-", "tls"],
        &["tungsten", "ite"],
        &["tok", "io-", "rust", "ls"],
        &["Tcp", "Stream"],
        &["Tcp", "Listener"],
        &["Udp", "Socket"],
        &["Unix", "Stream"],
        &["std::", "net"],
    ];
    PARTS.iter().map(|parts| parts.concat()).collect()
}

struct Package {
    name: String,
    deps: Vec<String>,
}

fn parse_lock(text: &str) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut name: Option<String> = None;
    let mut deps = Vec::new();
    let mut in_deps = false;
    let flush = |name: &mut Option<String>, deps: &mut Vec<String>, packages: &mut Vec<Package>| {
        if let Some(name) = name.take() {
            packages.push(Package {
                name,
                deps: std::mem::take(deps),
            });
        }
    };
    for line in text.lines() {
        if line.starts_with("[[package]]") {
            flush(&mut name, &mut deps, &mut packages);
            in_deps = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            name = Some(unquote(rest));
            continue;
        }
        if line.trim() == "dependencies = [" {
            in_deps = true;
            continue;
        }
        if in_deps {
            if line.trim() == "]" {
                in_deps = false;
                continue;
            }
            let dep = unquote(line.trim().trim_end_matches(','));
            if let Some(dep_name) = dep.split_whitespace().next() {
                if !dep_name.is_empty() {
                    deps.push(dep_name.to_string());
                }
            }
        }
    }
    flush(&mut name, &mut deps, &mut packages);
    packages
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}
