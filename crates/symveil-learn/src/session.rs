//! Line prompts. Names come first, then a category triage. A group is decided
//! together unless the user drills in.

use std::collections::HashSet;
use std::io::{BufRead, Write};

use anyhow::{Context, Result};

use crate::extract;
use crate::model::{Candidate, Decision, DecisionAction, LearnCategory};
use crate::preview::{entropy_hint, line_with_value, mask_body, preview};
use crate::stoplist::{is_common, is_stopped};
use crate::walk::{skip_summary, Walked};

const LEGEND: &str =
    "[r]edact  [k]eep  [s]kip  [a]ll-in-group  [?]help  [q]uit+save  [d]rill  [b]ack  [v] hidden";

const SHOWN_IN_GROUP: usize = 8;

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Secret,
    Related,
    Address,
    Name,
    Other,
}

impl Bucket {
    fn title(self) -> &'static str {
        match self {
            Self::Secret => "Secrets",
            Self::Related => "Related",
            Self::Address => "Hosts",
            Self::Name => "Names",
            Self::Other => "Other",
        }
    }

    fn menu(self) -> &'static str {
        match self {
            Self::Secret => "secrets",
            Self::Related => "related",
            Self::Address => "hosts/emails/ips",
            Self::Name => "names",
            Self::Other => "other",
        }
    }

    fn key(self) -> char {
        match self {
            Self::Secret => '1',
            Self::Related => '2',
            Self::Address => '3',
            Self::Name => '4',
            Self::Other => '5',
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Secret => 0,
            Self::Related => 1,
            Self::Address => 2,
            Self::Name => 3,
            Self::Other => 4,
        }
    }

    fn all() -> [Self; 5] {
        [
            Self::Secret,
            Self::Related,
            Self::Address,
            Self::Name,
            Self::Other,
        ]
    }
}

enum Phase {
    Triage,
    Group(Bucket),
    Drill { bucket: Bucket, index: usize },
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
    let skips = skip_summary(stats);
    if !skips.is_empty() {
        writeln!(stdout, "{skips}")?;
    }
    for warning in &walked.warnings {
        writeln!(stdout, "warning: {warning}")?;
    }
    writeln!(
        stdout,
        "Type company, product, project, and people names. One per line. A line with a space is a person."
    )?;
    writeln!(
        stdout,
        "[enter] add this name  [blank] start triage  [?]help  [q]uit+save"
    )?;
    loop {
        write!(stdout, "name> ")?;
        stdout.flush().context("flush prompt")?;
        match read_line(stdin)? {
            None => {
                writeln!(stdout, "end of input, saving")?;
                write_save_summary(&decisions, candidates, stdout)?;
                return Ok(decisions);
            }
            Some(line) if line.trim().is_empty() => break,
            Some(line) if is_help(&line) => write_help(stdout)?,
            Some(line) if is_quit(&line) => {
                write_save_summary(&decisions, candidates, stdout)?;
                return Ok(decisions);
            }
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

    let mut show_hidden = false;
    let mut phase = Phase::Triage;
    loop {
        let pending = pending_of(candidates, &decisions);
        let hidden = hidden_count(&pending, show_hidden);
        let decided = decided_count(candidates, &decisions);
        let total = candidates.len();
        match &phase {
            Phase::Triage => {
                writeln!(
                    stdout,
                    "{}",
                    format_progress("Triage", None, decided, total, hidden)
                )?;
                write_triage(&pending, show_hidden, stdout)?;
                writeln!(stdout, "{LEGEND}")?;
                write!(stdout, "triage> ")?;
            }
            Phase::Group(bucket) => {
                let items = visible(&pending, *bucket, show_hidden);
                writeln!(
                    stdout,
                    "{} · {} shown · overall {decided}/{total} decided · {hidden} hidden low-signal",
                    bucket.title(),
                    items.len()
                )?;
                writeln!(stdout, "{LEGEND}")?;
                write_group(*bucket, &items, reveal, stdout)?;
                write!(stdout, "> ")?;
            }
            Phase::Drill { bucket, index } => {
                let items = visible(&pending, *bucket, show_hidden);
                if items.is_empty() {
                    writeln!(stdout, "{} has nothing to review", bucket.menu())?;
                    phase = Phase::Triage;
                    continue;
                }
                let index = (*index).min(items.len() - 1);
                writeln!(
                    stdout,
                    "{}",
                    format_progress(
                        bucket.title(),
                        Some((index + 1, items.len())),
                        decided,
                        total,
                        hidden
                    )
                )?;
                writeln!(stdout, "{LEGEND}")?;
                write_item(&items[index], reveal, stdout)?;
                write!(stdout, "> ")?;
            }
        }
        stdout.flush().context("flush prompt")?;
        let Some(line) = read_line(stdin)? else {
            writeln!(stdout, "end of input, saving")?;
            write_save_summary(&decisions, candidates, stdout)?;
            return Ok(decisions);
        };
        if line.trim().is_empty() {
            continue;
        }
        match parse_command(&line) {
            Ok(Command::Help) => write_help(stdout)?,
            Ok(Command::Quit) => {
                write_save_summary(&decisions, candidates, stdout)?;
                return Ok(decisions);
            }
            Ok(Command::Toggle) => {
                show_hidden = !show_hidden;
                if show_hidden {
                    writeln!(stdout, "showing low-signal candidates")?;
                } else {
                    writeln!(stdout, "hiding low-signal candidates")?;
                }
            }
            Ok(Command::Pick(bucket)) => phase = Phase::Group(bucket),
            Ok(Command::Back) => {
                phase = match phase {
                    Phase::Drill { bucket, .. } => Phase::Group(bucket),
                    _ => Phase::Triage,
                }
            }
            Ok(Command::Drill) => match phase {
                Phase::Group(bucket) => phase = Phase::Drill { bucket, index: 0 },
                Phase::Drill { .. } => {}
                Phase::Triage => {
                    writeln!(stdout, "pick a category first: 1 secrets, 2 related, 3 hosts/emails/ips, 4 names, 5 other")?;
                }
            },
            Ok(command) => match apply_decision(
                command,
                &phase,
                &pending,
                show_hidden,
                &mut decisions,
                stdout,
            )? {
                Apply::Stay => {}
                Apply::Triage => phase = Phase::Triage,
                Apply::Next => {
                    if let Phase::Drill { bucket, index } = &mut phase {
                        *index += 1;
                        let items =
                            visible(&pending_of(candidates, &decisions), *bucket, show_hidden);
                        if *index >= items.len() {
                            phase = Phase::Triage;
                        }
                    }
                }
                Apply::Consumed => {
                    if let Phase::Drill { bucket, index } = &phase {
                        let items =
                            visible(&pending_of(candidates, &decisions), *bucket, show_hidden);
                        if *index >= items.len() {
                            phase = Phase::Triage;
                        }
                    }
                }
            },
            Err(message) => writeln!(stdout, "{message}")?,
        }
    }
}

enum Apply {
    Stay,
    Triage,
    /// Skip: the candidate stays pending, so the cursor moves on.
    Next,
    /// Redact or keep: the candidate leaves the list, so the same index is the next one.
    Consumed,
}

fn apply_decision(
    command: Command,
    phase: &Phase,
    pending: &[Candidate],
    show_hidden: bool,
    decisions: &mut Vec<Decision>,
    stdout: &mut dyn Write,
) -> Result<Apply> {
    let (Phase::Group(bucket) | Phase::Drill { bucket, .. }) = phase else {
        writeln!(
            stdout,
            "pick a category first: 1 secrets, 2 related, 3 hosts/emails/ips, 4 names, 5 other"
        )?;
        return Ok(Apply::Stay);
    };
    let items = visible(pending, *bucket, show_hidden);
    if items.is_empty() {
        writeln!(
            stdout,
            "nothing to decide in {}. [v] hidden shows once-only names and symbols, [b]ack returns.",
            bucket.menu()
        )?;
        return Ok(Apply::Stay);
    }
    match phase {
        Phase::Group(bucket) => apply_group(command, *bucket, &items, decisions, stdout),
        Phase::Drill { index, .. } => {
            let index = (*index).min(items.len() - 1);
            apply_one(command, &items, index, decisions, stdout)
        }
        Phase::Triage => Ok(Apply::Stay),
    }
}

fn apply_group(
    command: Command,
    bucket: Bucket,
    items: &[Candidate],
    decisions: &mut Vec<Decision>,
    stdout: &mut dyn Write,
) -> Result<Apply> {
    match command {
        Command::AllRedact(None) if bucket == Bucket::Other => {
            writeln!(
                stdout,
                "`a` skips {} in other. That group is mostly code words. Type `a redact` to redact the ones shown.",
                items.len()
            )?;
            Ok(Apply::Triage)
        }
        Command::Redact(category) | Command::AllRedact(category) => {
            for item in items {
                let chosen = category.unwrap_or(item.category);
                record(decisions, item, DecisionAction::Redact, chosen);
            }
            writeln!(stdout, "redact {} in this group", items.len())?;
            Ok(Apply::Triage)
        }
        Command::Keep | Command::AllKeep => {
            for item in items {
                record(decisions, item, DecisionAction::Keep, item.category);
            }
            writeln!(stdout, "keep {} in this group", items.len())?;
            Ok(Apply::Triage)
        }
        Command::Skip | Command::AllSkip => {
            writeln!(stdout, "skip {} in this group (not written)", items.len())?;
            Ok(Apply::Triage)
        }
        Command::Help
        | Command::Quit
        | Command::Toggle
        | Command::Pick(_)
        | Command::Back
        | Command::Drill => Ok(Apply::Stay),
    }
}

fn apply_one(
    command: Command,
    items: &[Candidate],
    index: usize,
    decisions: &mut Vec<Decision>,
    stdout: &mut dyn Write,
) -> Result<Apply> {
    let item = &items[index];
    match command {
        Command::Redact(category) => {
            let chosen = category.unwrap_or(item.category);
            record(decisions, item, DecisionAction::Redact, chosen);
            writeln!(stdout, "redact {}", chosen.as_str())?;
            Ok(Apply::Consumed)
        }
        Command::Keep => {
            record(decisions, item, DecisionAction::Keep, item.category);
            writeln!(stdout, "keep")?;
            Ok(Apply::Consumed)
        }
        Command::Skip => {
            writeln!(stdout, "skip (not written)")?;
            Ok(Apply::Next)
        }
        Command::AllRedact(category) => {
            for item in &items[index..] {
                let chosen = category.unwrap_or(item.category);
                record(decisions, item, DecisionAction::Redact, chosen);
            }
            writeln!(stdout, "redact {} from here", items.len() - index)?;
            Ok(Apply::Triage)
        }
        Command::AllKeep => {
            for item in &items[index..] {
                record(decisions, item, DecisionAction::Keep, item.category);
            }
            writeln!(stdout, "keep {} from here", items.len() - index)?;
            Ok(Apply::Triage)
        }
        Command::AllSkip => {
            writeln!(
                stdout,
                "skip {} from here (not written)",
                items.len() - index
            )?;
            Ok(Apply::Triage)
        }
        Command::Help
        | Command::Quit
        | Command::Toggle
        | Command::Pick(_)
        | Command::Back
        | Command::Drill => Ok(Apply::Stay),
    }
}

fn write_triage(pending: &[Candidate], show_hidden: bool, stdout: &mut dyn Write) -> Result<()> {
    writeln!(
        stdout,
        "Pick a category. Likely-sensitive groups come first. Low-signal candidates (seen once, a common word, or a code word) stay hidden until [v]."
    )?;
    writeln!(
        stdout,
        "Phone numbers, Swedish personnummer, and IPv6 are left to the proxy. Phone and personnummer apply only when [redact.pii] is on. This pass does not list them."
    )?;
    let mut parts = Vec::new();
    for bucket in Bucket::all() {
        let count = visible(pending, bucket, show_hidden).len();
        parts.push(format!("{} {}", bucket.menu(), count));
    }
    writeln!(stdout, "{}", parts.join(" · "))?;
    let mut keys = Vec::new();
    for bucket in Bucket::all() {
        keys.push(format!("[{}] {}", bucket.key(), bucket.menu()));
    }
    writeln!(stdout, "{}", keys.join("  "))?;
    Ok(())
}

fn write_group(
    bucket: Bucket,
    items: &[Candidate],
    reveal: bool,
    stdout: &mut dyn Write,
) -> Result<()> {
    if items.is_empty() {
        writeln!(
            stdout,
            "nothing shown in {}. [v] hidden includes once-only names and symbols.",
            bucket.menu()
        )?;
        return Ok(());
    }
    writeln!(
        stdout,
        "group {}  {}  [a] decides all of them, [d]rill opens one at a time",
        bucket.menu(),
        items.len()
    )?;
    for (index, item) in items.iter().take(SHOWN_IN_GROUP).enumerate() {
        writeln!(stdout, "{}.", index + 1)?;
        write_item(item, reveal, stdout)?;
    }
    if items.len() > SHOWN_IN_GROUP {
        writeln!(
            stdout,
            "… and {} more. [a]ll-in-group applies to all {}.",
            items.len() - SHOWN_IN_GROUP,
            items.len()
        )?;
    }
    Ok(())
}

fn write_item(candidate: &Candidate, reveal: bool, stdout: &mut dyn Write) -> Result<()> {
    let shown = if candidate.secretish && !reveal {
        mask_body(&candidate.text)
    } else {
        preview(&candidate.text, false, true)
    };
    let rule = candidate
        .rule
        .as_deref()
        .map(|rule| format!("  rule {rule}"))
        .unwrap_or_default();
    writeln!(
        stdout,
        "  {}  {shown}  len {}  entropy {}  {}:{}  hits {} files {}{rule}",
        candidate.category.as_str(),
        candidate.text.chars().count(),
        entropy_hint(&candidate.text),
        candidate.first_file,
        candidate.first_line,
        candidate.occurrences,
        candidate.files
    )?;
    if !candidate.context.is_empty() {
        let line = line_with_value(
            &candidate.context,
            &candidate.text,
            candidate.secretish,
            reveal,
        );
        if candidate.secretish && !reveal {
            writeln!(
                stdout,
                "    {line} (len {})",
                candidate.text.chars().count()
            )?;
        } else {
            writeln!(stdout, "    {line}")?;
        }
    }
    if candidate.related {
        writeln!(stdout, "    related to a name you typed")?;
    }
    Ok(())
}

fn write_help(stdout: &mut dyn Write) -> Result<()> {
    writeln!(stdout, "{LEGEND}")?;
    writeln!(
        stdout,
        "r / redact [category]  write this candidate as a redaction. A name or person goes to [redact.names]. A secret or symbol becomes a [[redact.secrets]] rule. Host, email, domain, and ip use that category."
    )?;
    writeln!(
        stdout,
        "k / keep               write an allow entry. Exact text. A builtin secret is still masked, and email is still masked when [redact.pii] email is on."
    )?;
    writeln!(
        stdout,
        "s / skip               decide later. Skip is not written. The next run shows it again."
    )?;
    writeln!(
        stdout,
        "a / all-in-group       on secrets, related names, addresses, and names, `a` redacts the shown rows. On other identifiers, `a` skips them; `a redact` redacts those shown. `a keep` allows, `a skip` leaves them. Hidden low-signal rows are not included."
    )?;
    writeln!(
        stdout,
        "d / drill              one candidate at a time. b goes back to the group."
    )?;
    writeln!(
        stdout,
        "1-5                    secrets, then matches of names you typed, then hosts/emails/ips, then names, then other identifiers."
    )?;
    writeln!(
        stdout,
        "v / hidden             toggle once-only names, symbols, domains, and code words. Secrets, emails, ips, and hosts stay listed."
    )?;
    writeln!(
        stdout,
        "q / quit+save          print what learned.toml will contain, then save. The file is mode 0600."
    )?;
    writeln!(
        stdout,
        "Names you type are stored as redact decisions and also surface identifiers that contain them."
    )?;
    Ok(())
}

fn write_save_summary(
    decisions: &[Decision],
    candidates: &[Candidate],
    stdout: &mut dyn Write,
) -> Result<()> {
    let decided: HashSet<&str> = decisions
        .iter()
        .map(|decision| decision.key.as_str())
        .collect();
    let pending_secrets: Vec<&Candidate> = candidates
        .iter()
        .filter(|candidate| candidate.category == LearnCategory::Secret)
        .filter(|candidate| !decided.contains(candidate.key.as_str()))
        .collect();
    if !pending_secrets.is_empty() {
        writeln!(
            stdout,
            "Undecided secrets, not written ({}). Open [1] secrets before quit if one of these should be redacted:",
            pending_secrets.len()
        )?;
        for candidate in pending_secrets.iter().take(12) {
            writeln!(
                stdout,
                "  {}  {}:{}  {}",
                mask_body(&candidate.text),
                candidate.first_file,
                candidate.first_line,
                candidate.rule.as_deref().unwrap_or("secret")
            )?;
        }
        if pending_secrets.len() > 12 {
            writeln!(stdout, "  … and {} more", pending_secrets.len() - 12)?;
        }
    }
    writeln!(stdout, "Will write to learned.toml:")?;
    let mut names = Vec::new();
    let mut people = Vec::new();
    let mut secrets = 0usize;
    let mut symbols = 0usize;
    let mut hosts = 0usize;
    let mut other = 0usize;
    let mut keeps = 0usize;
    for decision in decisions {
        match (decision.action, decision.category) {
            (DecisionAction::Keep, _) => keeps += 1,
            (DecisionAction::Redact, LearnCategory::Name) => names.push(decision.text.as_str()),
            (DecisionAction::Redact, LearnCategory::Person) => people.push(decision.text.as_str()),
            (DecisionAction::Redact, LearnCategory::Secret) => secrets += 1,
            (DecisionAction::Redact, LearnCategory::Symbol) => symbols += 1,
            (DecisionAction::Redact, LearnCategory::Host | LearnCategory::Domain) => hosts += 1,
            (DecisionAction::Redact, _) => other += 1,
        }
    }
    writeln!(
        stdout,
        "  redact names: {}",
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(", ")
        }
    )?;
    writeln!(
        stdout,
        "  redact people: {}",
        if people.is_empty() {
            "none".to_string()
        } else {
            people.join(", ")
        }
    )?;
    writeln!(stdout, "  redact secrets: {secrets} (values not printed)")?;
    writeln!(stdout, "  redact symbols: {symbols}")?;
    writeln!(stdout, "  redact hosts: {hosts}")?;
    writeln!(stdout, "  redact other: {other}")?;
    writeln!(stdout, "  keep (allow list): {keeps}")?;
    writeln!(
        stdout,
        "skip is not written. A keep does not stop a builtin secret rule."
    )?;
    Ok(())
}

pub fn format_progress(
    title: &str,
    at: Option<(usize, usize)>,
    decided: usize,
    total: usize,
    hidden: usize,
) -> String {
    let head = match at {
        Some((index, len)) => format!("{title} {index}/{len}"),
        None => title.to_string(),
    };
    format!("{head} · overall {decided}/{total} decided · {hidden} hidden low-signal")
}

fn pending_of(candidates: &[Candidate], decisions: &[Decision]) -> Vec<Candidate> {
    let decided: HashSet<&str> = decisions
        .iter()
        .map(|decision| decision.key.as_str())
        .collect();
    let mut pending: Vec<Candidate> = candidates
        .iter()
        .filter(|candidate| !decided.contains(candidate.key.as_str()))
        .cloned()
        .collect();
    pending.sort_by(|left, right| {
        bucket(left)
            .rank()
            .cmp(&bucket(right).rank())
            .then(right.occurrences.cmp(&left.occurrences))
            .then(left.text.to_lowercase().cmp(&right.text.to_lowercase()))
    });
    pending
}

fn visible(pending: &[Candidate], bucket_wanted: Bucket, show_hidden: bool) -> Vec<Candidate> {
    pending
        .iter()
        .filter(|candidate| bucket(candidate) == bucket_wanted)
        .filter(|candidate| show_hidden || !is_low_signal(candidate))
        .cloned()
        .collect()
}

fn decided_count(candidates: &[Candidate], decisions: &[Decision]) -> usize {
    let decided: HashSet<&str> = decisions
        .iter()
        .map(|decision| decision.key.as_str())
        .collect();
    candidates
        .iter()
        .filter(|candidate| decided.contains(candidate.key.as_str()))
        .count()
}

fn hidden_count(pending: &[Candidate], show_hidden: bool) -> usize {
    if show_hidden {
        0
    } else {
        pending
            .iter()
            .filter(|candidate| is_low_signal(candidate))
            .count()
    }
}

/// Secrets, emails, addresses, hosts, full person names, and product codes
/// stay visible. A name you typed stays visible. Common words, seen-once
/// names, and plain words seen fewer than three times stay hidden.
pub(crate) fn is_low_signal(candidate: &Candidate) -> bool {
    if candidate.related || candidate.category == LearnCategory::Secret {
        return false;
    }
    if candidate.rule.as_deref() == Some("product-code") {
        return false;
    }
    if candidate.category == LearnCategory::Person && candidate.text.contains(char::is_whitespace) {
        return false;
    }
    if matches!(
        candidate.category,
        LearnCategory::Email | LearnCategory::Ip | LearnCategory::Host
    ) {
        return false;
    }
    if is_stopped(&candidate.text) || is_common(&candidate.text) {
        return true;
    }
    let plain = !candidate.text.contains('_')
        && !candidate.text.contains('-')
        && !candidate.text.chars().any(|ch| ch.is_ascii_digit());
    if plain
        && candidate.occurrences < 3
        && matches!(
            candidate.category,
            LearnCategory::Symbol | LearnCategory::Name | LearnCategory::Domain
        )
    {
        return true;
    }
    candidate.occurrences <= 1
        && matches!(
            candidate.category,
            LearnCategory::Symbol
                | LearnCategory::Name
                | LearnCategory::Domain
                | LearnCategory::Person
        )
}

fn bucket(candidate: &Candidate) -> Bucket {
    if candidate.category == LearnCategory::Secret {
        return Bucket::Secret;
    }
    if candidate.rule.as_deref() == Some("product-code") {
        return Bucket::Name;
    }
    if candidate.related {
        return Bucket::Related;
    }
    match candidate.category {
        LearnCategory::Secret => Bucket::Secret,
        LearnCategory::Email | LearnCategory::Ip | LearnCategory::Host | LearnCategory::Domain => {
            Bucket::Address
        }
        LearnCategory::Name | LearnCategory::Person => Bucket::Name,
        LearnCategory::Symbol => Bucket::Other,
    }
}

fn record(
    decisions: &mut Vec<Decision>,
    candidate: &Candidate,
    action: DecisionAction,
    category: LearnCategory,
) {
    decisions.retain(|existing| existing.key != candidate.key);
    let mut decision = Decision {
        key: candidate.key.clone(),
        action,
        category,
        text: candidate.text.clone(),
        sources: candidate.sources.clone(),
        left_glued: candidate.left_glued,
        right_glued: candidate.right_glued,
    };
    if decision.sources.is_empty() && !candidate.context.is_empty() {
        decision.sources.push(candidate.context.clone());
    }
    decisions.push(decision);
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
    Drill,
    Back,
    Toggle,
    Pick(Bucket),
}

fn parse_command(line: &str) -> std::result::Result<Command, String> {
    let mut parts = line.split_whitespace();
    let Some(first) = parts.next() else {
        return Err("empty command; try ?".to_string());
    };
    let first = first.to_ascii_lowercase();
    if let Some(bucket) = pick_bucket(&first) {
        return no_extra(parts, Command::Pick(bucket));
    }
    match first.as_str() {
        "help" | "h" | "?" => Ok(Command::Help),
        "keep" | "k" => no_extra(parts, Command::Keep),
        "skip" | "s" => no_extra(parts, Command::Skip),
        "quit" | "q" => no_extra(parts, Command::Quit),
        "drill" | "d" => no_extra(parts, Command::Drill),
        "back" | "b" => no_extra(parts, Command::Back),
        "hidden" | "v" => no_extra(parts, Command::Toggle),
        "redact" | "r" => Ok(Command::Redact(optional_category(parts)?)),
        "all" | "a" => parse_all(parts),
        other => Err(format!(
            "unknown command `{other}`; try ? for [r]edact [k]eep [s]kip [a]ll-in-group [q]uit+save"
        )),
    }
}

fn pick_bucket(word: &str) -> Option<Bucket> {
    match word {
        "1" | "secret" | "secrets" => Some(Bucket::Secret),
        "2" | "related" => Some(Bucket::Related),
        "3" | "host" | "hosts" | "address" | "addresses" => Some(Bucket::Address),
        "4" | "name" | "names" => Some(Bucket::Name),
        "5" | "other" | "symbol" | "symbols" => Some(Bucket::Other),
        _ => None,
    }
}

fn parse_all(mut parts: std::str::SplitWhitespace<'_>) -> std::result::Result<Command, String> {
    let Some(action) = parts.next() else {
        return Ok(Command::AllRedact(None));
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
    LearnCategory::parse(word).map(Some).ok_or_else(|| {
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

fn is_help(line: &str) -> bool {
    matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "?" | "h" | "help"
    )
}

fn is_quit(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "q" | "quit")
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

    use super::*;
    use crate::walk::{WalkStats, WalkedFile};

    fn walked(text: &str) -> Walked {
        Walked {
            files: vec![WalkedFile {
                relative: "src/fan.rs".to_string(),
                text: text.to_string(),
            }],
            stats: WalkStats::default(),
            warnings: Vec::new(),
        }
    }

    fn sample(text: &str, category: LearnCategory, occurrences: u64, related: bool) -> Candidate {
        Candidate {
            key: crate::model::key_for(category, text),
            text: text.to_string(),
            category,
            rule: None,
            occurrences,
            files: 1,
            first_file: "src/fan.rs".to_string(),
            first_line: 1,
            context: format!("let value = \"{text}\";"),
            sources: vec![format!("let value = \"{text}\";")],
            left_glued: false,
            right_glued: false,
            related,
            secretish: category.secretish(),
        }
    }

    #[test]
    fn scripted_stdin_redacts_keeps_skips_and_can_resume() {
        let text = "\
fn zephyr_marker() {}
fn zephyr_marker() {}
fn quill_marker() {}
// Exempla ships Tundrahorn.
// Exempla again.
fn tundrahorn_fan_init() {}
const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";
let host = \"db.tundrahorn.internal\";
let ip = \"10.9.8.7\";
";
        let walked = walked(text);
        let mut candidates = extract::extract(&walked.files);
        let script = "\
?
Exempla
Ren Testdotter

1
a
3
k
5
s
q
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
        assert!(rendered.contains("[r]edact"), "{rendered}");
        assert!(rendered.contains("[q]uit+save"), "{rendered}");
        assert!(rendered.contains("learned.toml"), "{rendered}");
        assert!(rendered.contains("hidden low-signal"), "{rendered}");
        assert!(rendered.contains("added Exempla as name"), "{rendered}");
        assert!(
            rendered.contains("added Ren Testdotter as person"),
            "{rendered}"
        );
        assert!(
            rendered.contains("db.tundrahorn.internal"),
            "host should be shown in full: {rendered}"
        );
        assert!(
            rendered.contains("zephyr_marker"),
            "repeated symbol should be shown: {rendered}"
        );
        assert!(
            !rendered.contains("quill_marker"),
            "once-only symbol should stay hidden: {rendered}"
        );
        assert!(
            !rendered.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret value leaked into the transcript: {rendered}"
        );
        assert!(rendered.contains("AKIA…MPLE"), "{rendered}");
        assert!(
            rendered.contains("const KEY"),
            "secret preview should keep the source line: {rendered}"
        );
        assert!(
            rendered.contains("Will write to learned.toml:"),
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
        assert!(decisions.iter().any(|decision| {
            decision.action == DecisionAction::Keep && decision.text.contains("tundrahorn.internal")
        }));
        assert!(decisions
            .iter()
            .all(|decision| decision.text != "zephyr_marker"));

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
        assert!(
            pending.iter().any(|key| key.contains("zephyr_marker")),
            "skipped symbol should remain pending: {pending:?}"
        );
    }

    #[test]
    fn low_signal_hides_a_single_symbol_and_keeps_secrets() {
        let once = sample("zephyr_marker", LearnCategory::Symbol, 1, false);
        let twice = sample("zephyr_marker", LearnCategory::Symbol, 2, false);
        let related = sample("zephyr_marker", LearnCategory::Symbol, 1, true);
        let secret = sample("AKIAIOSFODNN7EXAMPLE", LearnCategory::Secret, 1, false);
        let name = sample("Exempla", LearnCategory::Name, 3, false);
        let rare = sample("Exempla", LearnCategory::Name, 2, false);
        let common = sample("threshold", LearnCategory::Symbol, 8, false);
        let host = sample("db.tundrahorn.internal", LearnCategory::Host, 1, false);
        assert!(is_low_signal(&once));
        assert!(!is_low_signal(&twice));
        assert!(!is_low_signal(&related));
        assert!(!is_low_signal(&secret));
        assert!(!is_low_signal(&name));
        assert!(is_low_signal(&rare));
        assert!(is_low_signal(&common));
        assert!(!is_low_signal(&host));
    }

    #[test]
    fn buckets_follow_sensitivity() {
        let secret = sample("AKIAIOSFODNN7EXAMPLE", LearnCategory::Secret, 1, true);
        let related = sample("tundrahorn_fan", LearnCategory::Symbol, 2, true);
        let host = sample("db.tundrahorn.internal", LearnCategory::Host, 1, false);
        let email = sample("fan@exempla.test", LearnCategory::Email, 1, false);
        let name = sample("Exempla", LearnCategory::Name, 2, false);
        let symbol = sample("zephyr_marker", LearnCategory::Symbol, 2, false);
        assert!(bucket(&secret).rank() < bucket(&related).rank());
        assert!(bucket(&related).rank() < bucket(&host).rank());
        assert_eq!(bucket(&host).rank(), bucket(&email).rank());
        assert!(bucket(&host).rank() < bucket(&name).rank());
        assert!(bucket(&name).rank() < bucket(&symbol).rank());
    }

    #[test]
    fn progress_counts_name_the_group_and_the_hidden_rest() {
        let line = format_progress("Secrets", Some((3, 12)), 15, 248, 33);
        assert_eq!(
            line,
            "Secrets 3/12 · overall 15/248 decided · 33 hidden low-signal"
        );
        let triage = format_progress("Triage", None, 2, 10, 4);
        assert_eq!(
            triage,
            "Triage · overall 2/10 decided · 4 hidden low-signal"
        );
        let pending = vec![
            sample("AKIAIOSFODNN7EXAMPLE", LearnCategory::Secret, 1, false),
            sample("zephyr_marker", LearnCategory::Symbol, 1, false),
            sample("zephyr_marker_two", LearnCategory::Symbol, 2, false),
        ];
        assert_eq!(hidden_count(&pending, false), 1);
        assert_eq!(hidden_count(&pending, true), 0);
        assert_eq!(visible(&pending, Bucket::Secret, false).len(), 1);
        assert_eq!(visible(&pending, Bucket::Other, false).len(), 1);
        assert_eq!(visible(&pending, Bucket::Other, true).len(), 2);
    }

    #[test]
    fn parse_commands() {
        assert!(matches!(
            parse_command("redact host").unwrap(),
            Command::Redact(Some(LearnCategory::Host))
        ));
        assert!(matches!(
            parse_command("a").unwrap(),
            Command::AllRedact(None)
        ));
        assert!(matches!(
            parse_command("all keep").unwrap(),
            Command::AllKeep
        ));
        assert!(matches!(
            parse_command("3").unwrap(),
            Command::Pick(Bucket::Address)
        ));
        assert!(matches!(parse_command("v").unwrap(), Command::Toggle));
        assert!(parse_command("redact nope").is_err());
    }
}
