//! Line prompts. A blank line ends the name list. Each later line is one decision.

use std::collections::HashSet;
use std::io::{BufRead, Write};

use anyhow::{Context, Result};

use crate::extract;
use crate::model::{Candidate, Decision, DecisionAction, LearnCategory, GROUP_ORDER};
use crate::preview::preview;
use crate::walk::Walked;

pub fn mark_related(candidates: &mut [Candidate], decisions: &[Decision]) {
    let terms = related_terms(decisions);
    for candidate in candidates {
        let lower = candidate.text.to_lowercase();
        candidate.related = terms.iter().any(|term| lower.contains(term));
    }
}

fn related_terms(decisions: &[Decision]) -> Vec<String> {
    decisions
        .iter()
        .filter(|decision| {
            decision.action == DecisionAction::Redact
                && matches!(
                    decision.category,
                    LearnCategory::Name | LearnCategory::Person
                )
        })
        .flat_map(|decision| {
            decision
                .text
                .split_whitespace()
                .map(|word| word.to_lowercase())
                .filter(|word| word.chars().count() >= 3)
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn review(
    reveal: bool,
    walked: &Walked,
    candidates: &mut Vec<Candidate>,
    mut decisions: Vec<Decision>,
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
) -> Result<Vec<Decision>> {
    let stats = &walked.stats;
    writeln!(stdout, "symveil learn")?;
    writeln!(
        stdout,
        "Offline and read-only. No model and no network connection."
    )?;
    writeln!(
        stdout,
        "This builds lists the proxy can merge. It does not guarantee nothing leaks, and it does not sandbox the tree."
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
    for warning in &walked.warnings {
        writeln!(stdout, "warning: {warning}")?;
    }
    writeln!(
        stdout,
        "Type company, product, project, and people names. One per line. A line with a space is a person. Blank line when done."
    )?;
    loop {
        write!(stdout, "name> ")?;
        stdout.flush().context("flush prompt")?;
        match read_line(stdin)? {
            None => {
                writeln!(stdout, "end of input, saving")?;
                return Ok(decisions);
            }
            Some(line) if line.trim().is_empty() => break,
            Some(line) => match classify_typed(line.trim()) {
                Ok((category, text)) => {
                    let decision = Decision::new(DecisionAction::Redact, category, text);
                    writeln!(
                        stdout,
                        "added {} as {}",
                        decision.text,
                        decision.category.as_str()
                    )?;
                    decisions.retain(|existing| existing.key != decision.key);
                    decisions.push(decision);
                }
                Err(message) => writeln!(stdout, "{message}")?,
            },
        }
    }

    let terms = related_terms(&decisions);
    extract::surface_terms(&walked.files, &terms, candidates);
    mark_related(candidates, &decisions);
    sort_for_review(candidates);

    let decided: HashSet<String> = decisions
        .iter()
        .map(|decision| decision.key.clone())
        .collect();
    let pending: Vec<Candidate> = candidates
        .iter()
        .filter(|candidate| !decided.contains(&candidate.key))
        .cloned()
        .collect();
    if pending.is_empty() {
        writeln!(stdout, "nothing undecided")?;
        return Ok(decisions);
    }
    writeln!(
        stdout,
        "commands: redact [category] | keep | skip | quit | all redact [category] | all keep | all skip | help"
    )?;
    writeln!(
        stdout,
        "categories: name, person, secret, symbol, host, email, domain, ip"
    )?;
    writeln!(
        stdout,
        "keep writes an allow entry. Builtin secret rules still mask a secret, and personal-data rules still mask an email when [redact.pii] is on."
    )?;

    for category in GROUP_ORDER {
        let items: Vec<Candidate> = pending
            .iter()
            .filter(|candidate| candidate.category == *category)
            .cloned()
            .collect();
        if items.is_empty() {
            continue;
        }
        writeln!(stdout, "group {}  {}", category.as_str(), items.len())?;
        let mut index = 0;
        while index < items.len() {
            let candidate = &items[index];
            writeln!(
                stdout,
                "[{}/{}] {}  {}{}  hits={} files={}  {}:{}",
                index + 1,
                items.len(),
                candidate.category.as_str(),
                preview(&candidate.text, candidate.secretish, reveal),
                candidate
                    .rule
                    .as_deref()
                    .map(|rule| format!(" rule={rule}"))
                    .unwrap_or_default(),
                candidate.occurrences,
                candidate.files,
                candidate.first_file,
                candidate.first_line
            )?;
            if candidate.related {
                writeln!(stdout, "related to a name you typed")?;
            }
            loop {
                write!(stdout, "> ")?;
                stdout.flush().context("flush prompt")?;
                let Some(line) = read_line(stdin)? else {
                    writeln!(stdout, "end of input, saving")?;
                    return Ok(decisions);
                };
                match parse_command(&line) {
                    Ok(Command::Help) => {
                        writeln!(
                            stdout,
                            "redact [category] | keep | skip | quit | all redact [category] | all keep | all skip"
                        )?;
                    }
                    Ok(Command::Quit) => return Ok(decisions),
                    Ok(Command::Skip) => {
                        index += 1;
                        break;
                    }
                    Ok(Command::Keep) => {
                        record(
                            &mut decisions,
                            candidate,
                            DecisionAction::Keep,
                            candidate.category,
                        );
                        index += 1;
                        break;
                    }
                    Ok(Command::Redact(category)) => {
                        let category = category.unwrap_or(candidate.category);
                        record(&mut decisions, candidate, DecisionAction::Redact, category);
                        index += 1;
                        break;
                    }
                    Ok(Command::AllSkip) => {
                        index = items.len();
                        break;
                    }
                    Ok(Command::AllKeep) => {
                        for item in &items[index..] {
                            record(&mut decisions, item, DecisionAction::Keep, item.category);
                        }
                        index = items.len();
                        break;
                    }
                    Ok(Command::AllRedact(category)) => {
                        for item in &items[index..] {
                            let chosen = category.unwrap_or(item.category);
                            record(&mut decisions, item, DecisionAction::Redact, chosen);
                        }
                        index = items.len();
                        break;
                    }
                    Err(message) => writeln!(stdout, "{message}")?,
                }
            }
        }
    }
    Ok(decisions)
}

fn record(
    decisions: &mut Vec<Decision>,
    candidate: &Candidate,
    action: DecisionAction,
    category: LearnCategory,
) {
    decisions.retain(|existing| existing.key != candidate.key);
    decisions.push(Decision {
        key: candidate.key.clone(),
        action,
        category,
        text: candidate.text.clone(),
    });
}

fn sort_for_review(candidates: &mut [Candidate]) {
    candidates.sort_by(|left, right| {
        right
            .related
            .cmp(&left.related)
            .then(left.category.rank().cmp(&right.category.rank()))
            .then(right.occurrences.cmp(&left.occurrences))
            .then(right.files.cmp(&left.files))
            .then(left.text.to_lowercase().cmp(&right.text.to_lowercase()))
            .then(left.text.cmp(&right.text))
    });
}

enum Command {
    Redact(Option<LearnCategory>),
    Keep,
    Skip,
    Quit,
    AllRedact(Option<LearnCategory>),
    AllKeep,
    AllSkip,
    Help,
}

fn parse_command(line: &str) -> std::result::Result<Command, String> {
    let mut parts = line.split_whitespace();
    let Some(first) = parts.next() else {
        return Err("empty command; try help".to_string());
    };
    let first = first.to_ascii_lowercase();
    match first.as_str() {
        "help" | "h" | "?" => Ok(Command::Help),
        "keep" | "k" => no_extra(parts, Command::Keep),
        "skip" | "s" => no_extra(parts, Command::Skip),
        "quit" | "q" => no_extra(parts, Command::Quit),
        "redact" | "r" => Ok(Command::Redact(optional_category(parts)?)),
        "all" => parse_all(parts),
        other => Err(format!(
            "unknown command `{other}`; expected redact, keep, skip, quit, all, or help"
        )),
    }
}

fn parse_all(mut parts: std::str::SplitWhitespace<'_>) -> std::result::Result<Command, String> {
    let Some(action) = parts.next() else {
        return Err("all needs redact, keep, or skip".to_string());
    };
    match action.to_ascii_lowercase().as_str() {
        "keep" | "k" => no_extra(parts, Command::AllKeep),
        "skip" | "s" => no_extra(parts, Command::AllSkip),
        "redact" | "r" => Ok(Command::AllRedact(optional_category(parts)?)),
        other => Err(format!(
            "unknown group command `{other}`; expected redact, keep, or skip"
        )),
    }
}

fn optional_category(
    mut parts: std::str::SplitWhitespace<'_>,
) -> std::result::Result<Option<LearnCategory>, String> {
    let Some(word) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some() {
        return Err("too many words".to_string());
    }
    LearnCategory::parse(word)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "unknown category `{word}`; expected name, person, secret, symbol, host, email, domain, or ip"
            )
        })
}

fn no_extra(
    mut parts: std::str::SplitWhitespace<'_>,
    command: Command,
) -> std::result::Result<Command, String> {
    if parts.next().is_some() {
        Err("too many words".to_string())
    } else {
        Ok(command)
    }
}

fn classify_typed(line: &str) -> std::result::Result<(LearnCategory, String), String> {
    let text = line.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return Err("empty name".to_string());
    }
    let tokens: Vec<&str> = text.split(' ').collect();
    if tokens.len() == 1 {
        if alnum_len(tokens[0]) < 3 {
            return Err(format!("`{text}` needs at least 3 letters or digits"));
        }
        Ok((LearnCategory::Name, text))
    } else {
        for token in &tokens {
            if alnum_len(token) < 3 {
                return Err(format!(
                    "`{text}` has a token shorter than 3 letters or digits"
                ));
            }
        }
        Ok((LearnCategory::Person, text))
    }
}

fn alnum_len(token: &str) -> usize {
    token.chars().filter(|ch| ch.is_alphanumeric()).count()
}

fn read_line(stdin: &mut dyn BufRead) -> Result<Option<String>> {
    let mut buf = String::new();
    let read = stdin.read_line(&mut buf).context("read prompt")?;
    if read == 0 {
        return Ok(None);
    }
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use std::collections::HashSet;

    use super::*;
    use crate::walk::{WalkStats, WalkedFile};

    #[test]
    fn scripted_stdin_redacts_keeps_skips_and_can_resume() {
        let text = "\
// Exempla ships Tundrahorn.
// Exempla again.
fn tundrahorn_fan_init() {}
const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";
let host = \"db.tundrahorn.internal\";
let ip = \"10.9.8.7\";
";
        let walked = Walked {
            files: vec![WalkedFile {
                relative: "src/fan.rs".to_string(),
                text: text.to_string(),
            }],
            stats: WalkStats::default(),
            warnings: Vec::new(),
        };
        let mut candidates = extract::extract(&walked.files);
        let script = "\
Exempla
Ren Testdotter

all redact
all keep
all skip
quit
";
        let mut input = Cursor::new(script);
        let mut output = Vec::new();
        let decisions = review(
            false,
            &walked,
            &mut candidates,
            Vec::new(),
            &mut input,
            &mut output,
        )
        .unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("added Exempla as name"), "{rendered}");
        assert!(
            rendered.contains("added Ren Testdotter as person"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret value leaked into the transcript: {rendered}"
        );
        assert!(
            rendered.contains("AKIA…MPLE") || rendered.contains("len=20"),
            "{rendered}"
        );
        assert!(decisions.iter().any(|decision| {
            decision.text == "Exempla" && decision.action == DecisionAction::Redact
        }));
        assert!(decisions
            .iter()
            .any(|decision| decision.text == "Ren Testdotter"));
        let secret = decisions
            .iter()
            .find(|decision| decision.category == LearnCategory::Secret)
            .expect("secret group was redacted");
        assert_eq!(secret.action, DecisionAction::Redact);
        assert!(secret.text.contains("AKIA"));

        let decided: HashSet<String> = decisions
            .iter()
            .map(|decision| decision.key.clone())
            .collect();
        let mut again = extract::extract(&walked.files);
        mark_related(&mut again, &decisions);
        let pending: Vec<_> = again
            .iter()
            .filter(|candidate| !decided.contains(&candidate.key))
            .map(|candidate| candidate.key.clone())
            .collect();
        assert!(
            pending.iter().all(|key| !key.contains("AKIA")),
            "decided secret still pending: {pending:?}"
        );
        assert!(pending.iter().all(|key| key != "term:exempla"));
    }

    #[test]
    fn parse_commands() {
        assert!(matches!(
            parse_command("redact host").unwrap(),
            Command::Redact(Some(LearnCategory::Host))
        ));
        assert!(matches!(
            parse_command("all keep").unwrap(),
            Command::AllKeep
        ));
        assert!(parse_command("redact nope").is_err());
    }
}
