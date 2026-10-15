//! Plugin interface for redaction.
//!
//! The free proxy always installs the secret and network maskers. Identifier
//! and code-name masking is a separate crate that implements [`Masker`] and is
//! compiled only behind the `identifiers` feature of the `symveil` binary.

use crate::category::Category;

/// Higher values win when two candidates cover the same span.
pub const PRI_LITERAL: u8 = 1;
pub const PRI_PATTERN: u8 = 2;
pub const PRI_SECRET: u8 = 3;

/// How the engine checks the characters on either side of a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// ASCII identifier characters (`[A-Za-z0-9_]`) end the match.
    Ident,
    /// Digits and dots end the match, so a longer dotted quad is not cut short.
    Ip,
    /// The match is taken as the masker reported it.
    None,
}

/// A span a masker wants replaced. The engine drops overlaps, allow-listed
/// terms, and matches that fail `boundary`.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub start: usize,
    pub end: usize,
    pub category: Category,
    pub rule: Option<String>,
    pub priority: u8,
    pub boundary: Boundary,
}

/// A masking plugin. Implementations find spans. They do not assign
/// placeholders or write the vault; [`crate::redact::Engine`] does that so
/// every plugin shares one stable `@@sv:…@@` map.
pub trait Masker: Send {
    fn name(&self) -> &'static str;

    fn collect(&self, text: &str) -> Vec<Candidate>;
}

pub fn boundary_for(category: Category) -> Boundary {
    match category {
        Category::Secret => Boundary::None,
        Category::Ip => Boundary::Ip,
        Category::Function
        | Category::Type
        | Category::Macro
        | Category::Field
        | Category::Enumerator
        | Category::Register
        | Category::Codename
        | Category::Hostname
        | Category::Identifier => Boundary::Ident,
    }
}
