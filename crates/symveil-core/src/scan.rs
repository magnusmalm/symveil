use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;

use crate::category::Category;
use crate::masker::{Boundary, Candidate, Masker, PRI_PATTERN};
use crate::secrets::SecretHit;

/// Live detection of addresses and internal hostnames. This is part of the
/// free proxy: it does not use the identifier index.
pub struct NetworkMasker {
    hostnames: Option<Regex>,
}

impl NetworkMasker {
    pub(crate) fn compile(domains: &[String]) -> Result<Self> {
        Ok(Self {
            hostnames: hostname_regex(domains)?,
        })
    }
}

impl Masker for NetworkMasker {
    fn name(&self) -> &'static str {
        "network"
    }

    fn collect(&self, text: &str) -> Vec<Candidate> {
        let mut out = Vec::new();
        for hit in ipv4_hits(text).into_iter().chain(ipv6_hits(text)) {
            out.push(Candidate {
                start: hit.start,
                end: hit.end,
                category: Category::Ip,
                rule: Some(hit.rule),
                priority: PRI_PATTERN,
                boundary: Boundary::Ip,
            });
        }
        if let Some(regex) = &self.hostnames {
            for hit in hostname_hits(text, regex) {
                out.push(Candidate {
                    start: hit.start,
                    end: hit.end,
                    category: Category::Hostname,
                    rule: Some(hit.rule),
                    priority: PRI_PATTERN,
                    boundary: Boundary::Ident,
                });
            }
        }
        out
    }
}

const IPV4_PATTERN: &str = r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";

/// Maximal hex-and-colon run. `std::net::Ipv6Addr` decides whether the run is
/// an address. A leftmost-first alternation would stop on a short prefix such
/// as `2001:db8::` inside `2001:db8::1`, and the `regex` crate has no lookaround.
const IPV6_PATTERN: &str = r"(?i)[0-9a-f:]*:[0-9a-f:]*";

static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(IPV4_PATTERN).expect("ipv4 regex"));
static IPV6: LazyLock<Regex> = LazyLock::new(|| Regex::new(IPV6_PATTERN).expect("ipv6 regex"));

pub fn ipv4_hits(text: &str) -> Vec<SecretHit> {
    bounded_hits(text, &IPV4, "ipv4", ip_edge_ok, |value| {
        !matches!(value, "0.0.0.0" | "127.0.0.1" | "255.255.255.255")
    })
}

pub fn ipv6_hits(text: &str) -> Vec<SecretHit> {
    bounded_hits(text, &IPV6, "ipv6", ipv6_edge_ok, is_redactable_ipv6)
}

fn is_redactable_ipv6(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower == "::" || lower == "::1" {
        return false;
    }
    lower.parse::<std::net::Ipv6Addr>().is_ok()
}

pub fn hostname_regex(domains: &[String]) -> Result<Option<Regex>> {
    let suffixes: Vec<String> = domains
        .iter()
        .map(|domain| domain.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
        .map(|domain| regex::escape(&domain))
        .collect();
    if suffixes.is_empty() {
        return Ok(None);
    }
    let pattern = format!(
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{})\b",
        suffixes.join("|")
    );
    let regex = Regex::new(&pattern).context("compile internal hostname regex")?;
    Ok(Some(regex))
}

pub fn hostname_hits(text: &str, regex: &Regex) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for matched in regex.find_iter(text) {
        if matched.as_str().len() > 253 {
            continue;
        }
        hits.push(SecretHit {
            start: matched.start(),
            end: matched.end(),
            rule: "internal-hostname".to_string(),
        });
    }
    hits
}

fn bounded_hits(
    text: &str,
    regex: &Regex,
    rule: &str,
    edge_ok: fn(&str, usize, usize) -> bool,
    keep: impl Fn(&str) -> bool,
) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for matched in regex.find_iter(text) {
        let start = matched.start();
        let end = matched.end();
        if !edge_ok(text, start, end) || !keep(matched.as_str()) {
            continue;
        }
        hits.push(SecretHit {
            start,
            end,
            rule: rule.to_string(),
        });
    }
    hits
}

fn ip_edge_ok(text: &str, start: usize, end: usize) -> bool {
    let bad = |c: char| c.is_ascii_digit() || c == '.';
    !edge_is(text, start, true, bad) && !edge_is(text, end, false, bad)
}

fn ipv6_edge_ok(text: &str, start: usize, end: usize) -> bool {
    let bad = |c: char| c.is_ascii_hexdigit() || c == ':';
    !edge_is(text, start, true, bad) && !edge_is(text, end, false, bad)
}

fn edge_is(text: &str, at: usize, before: bool, bad: impl Fn(char) -> bool) -> bool {
    let ch = if before {
        if at == 0 {
            return false;
        }
        text[..at].chars().next_back()
    } else {
        if at >= text.len() {
            return false;
        }
        text[at..].chars().next()
    };
    ch.is_some_and(bad)
}
