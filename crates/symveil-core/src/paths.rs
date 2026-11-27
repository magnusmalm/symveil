//! Home-directory usernames.
//!
//! `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, and `~user` mask the
//! username only, so the rest of the path stays and restore puts the name
//! back. The process username is also masked as a bare word, except for a
//! short list of account names that show up in ordinary text. `~/` has no
//! username and stays. This does not stop a tool from reading the directory.

use anyhow::{Context, Result};
use regex::Regex;

use crate::category::Category;
use crate::config::RedactSection;
use crate::masker::{Boundary, Candidate, Masker, PRI_PATTERN};

const BARE_STOP: &[&str] = &[
    "admin", "app", "daemon", "data", "default", "guest", "home", "local", "nobody", "node",
    "public", "root", "shared", "test", "ubuntu", "user", "users", "www",
];

pub struct PathMasker {
    home: Regex,
    windows: Regex,
    tilde: Regex,
    /// Bare word plus its pattern. The word is the fast reject.
    username: Option<(String, Regex)>,
}

impl PathMasker {
    pub fn from_config(redact: &RedactSection) -> Result<Option<Self>> {
        if !redact.home_paths {
            return Ok(None);
        }
        let explicit = redact
            .username
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        let (name, bare_even_if_common) = match explicit {
            Some(name) => (Some(name.to_string()), true),
            None => (env_username(), false),
        };
        Ok(Some(Self::compile(name.as_deref(), bare_even_if_common)?))
    }

    fn compile(username: Option<&str>, bare_even_if_common: bool) -> Result<Self> {
        let username = username.filter(|name| bare_username_ok(name, bare_even_if_common));
        let username = match username {
            Some(name) => {
                let pattern = Regex::new(&format!(r"\b{}\b", regex::escape(name)))
                    .with_context(|| format!("username pattern for {name}"))?;
                Some((name.to_string(), pattern))
            }
            None => None,
        };
        Ok(Self {
            home: Regex::new(
                r"(?i)(?:^|[^A-Za-z0-9_])/(?:home|Users)/([A-Za-z0-9_][A-Za-z0-9._-]{1,31})",
            )
            .context("home path pattern")?,
            windows: Regex::new(r"(?i)[A-Za-z]:[\\/]Users[\\/]([A-Za-z0-9_][A-Za-z0-9._-]{1,31})")
                .context("windows profile pattern")?,
            tilde: Regex::new(r"(?:^|[^A-Za-z0-9_])~([A-Za-z0-9_][A-Za-z0-9._-]{1,31})")
                .context("tilde user pattern")?,
            username,
        })
    }
}

fn env_username() -> Option<String> {
    let name = std::env::var("USER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("USERNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })?;
    Some(name.trim().to_string())
}

fn bare_username_ok(name: &str, bare_even_if_common: bool) -> bool {
    let count = name.chars().count();
    if !(2..=32).contains(&count) {
        return false;
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
    {
        return false;
    }
    bare_even_if_common || !BARE_STOP.contains(&name.to_ascii_lowercase().as_str())
}

impl Masker for PathMasker {
    fn name(&self) -> &'static str {
        "paths"
    }

    fn collect(&self, text: &str) -> Vec<Candidate> {
        let mut out = Vec::new();
        // The bench filler has none of these. A regex scan of that text is
        // the cost this reject avoids.
        if text.contains('/') || text.contains('\\') || text.contains('~') {
            self.push_group(&mut out, text, &self.home, "home-path");
            self.push_group(&mut out, text, &self.windows, "home-path");
            self.push_group(&mut out, text, &self.tilde, "home-path");
        }
        if let Some((name, pattern)) = &self.username {
            if text.contains(name) {
                self.push_group(&mut out, text, pattern, "local-username");
            }
        }
        out
    }
}

impl PathMasker {
    fn push_group(&self, out: &mut Vec<Candidate>, text: &str, pattern: &Regex, rule: &str) {
        for caps in pattern.captures_iter(text) {
            let Some(user) = caps.get(1).or_else(|| caps.get(0)) else {
                continue;
            };
            if user.start() == user.end() {
                continue;
            }
            out.push(Candidate {
                start: user.start(),
                end: user.end(),
                category: Category::Secret,
                rule: Some(rule.to_string()),
                priority: PRI_PATTERN,
                boundary: Boundary::None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactSection;
    use crate::redact::Engine;
    use crate::vault::Vault;

    fn engine(username: Option<&str>, home_paths: bool) -> Engine {
        Engine::new(
            Vault::ephemeral(),
            &RedactSection {
                internal_domains: Vec::new(),
                home_paths,
                username: username.map(str::to_string),
                ..RedactSection::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn home_paths_mask_the_username_and_round_trip() {
        let mut engine = engine(Some("jdoe"), true);
        let input = "\
cd /home/jdoe/proj
cd /Users/jdoe/proj
cd C:\\Users\\jdoe\\proj
owner ~jdoe
the user jdoe ran it
see https://cdn.example/home/index and ~/docs and std::env and process.env
TOKEN_LIMIT=4096
/usr/bin stays
";
        let (out, hits) = engine.redact_str(input).unwrap();
        assert!(!out.contains("jdoe"), "{out}");
        assert!(out.contains("/home/"), "{out}");
        assert!(out.contains("/Users/"), "{out}");
        assert!(out.contains("Users"), "{out}");
        assert!(out.contains("~/docs"), "{out}");
        assert!(out.contains("cdn.example/home/index"), "{out}");
        assert!(out.contains("std::env"), "{out}");
        assert!(out.contains("process.env"), "{out}");
        assert!(out.contains("TOKEN_LIMIT=4096"), "{out}");
        assert!(out.contains("/usr/bin"), "{out}");
        assert!(hits
            .iter()
            .any(|hit| hit.rule.as_deref() == Some("home-path")));
        assert!(hits
            .iter()
            .any(|hit| hit.rule.as_deref() == Some("local-username")));
        assert_eq!(engine.restore_str(&out), input);
    }

    #[test]
    fn home_paths_off_leaves_the_path() {
        let mut engine = engine(Some("jdoe"), false);
        let input = "cd /home/jdoe/proj and the user jdoe";
        let (out, _) = engine.redact_str(input).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn a_common_account_name_is_not_a_bare_word() {
        let masker = PathMasker::compile(Some("ubuntu"), false).unwrap();
        let text = "the ubuntu package and /home/ubuntu/proj";
        let hits = masker.collect(text);
        assert!(hits
            .iter()
            .all(|hit| hit.rule.as_deref() == Some("home-path")));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(&text[hits[0].start..hits[0].end], "ubuntu");
        let explicit = PathMasker::compile(Some("ubuntu"), true).unwrap();
        let bare = explicit.collect("the ubuntu package");
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].rule.as_deref(), Some("local-username"));
    }
}
