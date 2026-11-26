//! Candidates and the decisions a person records about them.

use std::fmt;

use symveil_detect::learned::DecisionRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LearnCategory {
    Secret,
    Email,
    Ip,
    Host,
    Domain,
    Name,
    Person,
    Symbol,
}

impl LearnCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Email => "email",
            Self::Ip => "ip",
            Self::Host => "host",
            Self::Domain => "domain",
            Self::Name => "name",
            Self::Person => "person",
            Self::Symbol => "symbol",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "secret" => Some(Self::Secret),
            "email" => Some(Self::Email),
            "ip" | "ipv4" | "ipv6" => Some(Self::Ip),
            "host" | "hostname" => Some(Self::Host),
            "domain" => Some(Self::Domain),
            "name" | "company" | "product" | "project" => Some(Self::Name),
            "person" | "people" => Some(Self::Person),
            "symbol" | "ident" | "identifier" => Some(Self::Symbol),
            _ => None,
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Secret => 0,
            Self::Email => 1,
            Self::Ip => 2,
            Self::Host => 3,
            Self::Domain => 4,
            Self::Name => 5,
            Self::Person => 6,
            Self::Symbol => 7,
        }
    }

    pub fn strength(self) -> u8 {
        match self {
            Self::Secret => 80,
            Self::Email => 70,
            Self::Ip => 60,
            Self::Host => 50,
            Self::Domain => 40,
            Self::Person => 30,
            Self::Name => 20,
            Self::Symbol => 10,
        }
    }

    /// Values the terminal hides unless `--reveal`.
    pub fn secretish(self) -> bool {
        matches!(self, Self::Secret)
    }
}

impl fmt::Display for LearnCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAction {
    Redact,
    Keep,
}

impl DecisionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Redact => "redact",
            Self::Keep => "keep",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "redact" => Some(Self::Redact),
            "keep" => Some(Self::Keep),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub key: String,
    pub action: DecisionAction,
    pub category: LearnCategory,
    pub text: String,
    /// Source lines that contain `text`. Empty when the user typed the value.
    /// Not written to `learned.toml`; used to check the generated regex.
    pub sources: Vec<String>,
    /// A word character sits against the value in some source line, so a
    /// leading or trailing `\b` would miss that line.
    pub left_glued: bool,
    pub right_glued: bool,
}

impl Decision {
    pub fn new(action: DecisionAction, category: LearnCategory, text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            key: key_for(category, &text),
            action,
            category,
            text,
            sources: Vec::new(),
            left_glued: false,
            right_glued: false,
        }
    }

    pub fn to_record(&self) -> DecisionRecord {
        DecisionRecord {
            key: self.key.clone(),
            action: self.action.as_str().to_string(),
            category: self.category.as_str().to_string(),
            text: self.text.clone(),
        }
    }

    pub fn from_record(record: &DecisionRecord) -> Option<Self> {
        let action = DecisionAction::parse(&record.action)?;
        let category = LearnCategory::parse(&record.category)?;
        Some(Self {
            key: record.key.clone(),
            action,
            category,
            text: record.text.clone(),
            sources: Vec::new(),
            left_glued: false,
            right_glued: false,
        })
    }
}

/// Secrets keep their exact spelling. Other categories share one key so a
/// later run does not ask again about the same word in another bucket.
pub fn key_for(category: LearnCategory, text: &str) -> String {
    match category {
        LearnCategory::Secret => format!("secret:{text}"),
        _ => format!("term:{}", normalize_term(text)),
    }
}

pub fn normalize_term(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: String,
    pub text: String,
    pub category: LearnCategory,
    pub rule: Option<String>,
    pub occurrences: u64,
    pub files: usize,
    pub first_file: String,
    pub first_line: u32,
    /// Source line of the first hit, so the prompt can show the value in place.
    pub context: String,
    /// A few source lines, used to check that a generated rule matches.
    pub sources: Vec<String>,
    pub left_glued: bool,
    pub right_glued: bool,
    pub related: bool,
    pub secretish: bool,
}
