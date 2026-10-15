use std::fmt;

use serde::{Deserialize, Serialize};

/// Why a span was eligible for redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Function,
    Type,
    Macro,
    Register,
    Field,
    Enumerator,
    Codename,
    Hostname,
    Ip,
    Secret,
    Identifier,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Type => "type",
            Self::Macro => "macro",
            Self::Register => "register",
            Self::Field => "field",
            Self::Enumerator => "enumerator",
            Self::Codename => "codename",
            Self::Hostname => "hostname",
            Self::Ip => "ip",
            Self::Secret => "secret",
            Self::Identifier => "identifier",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "function" => Some(Self::Function),
            "type" => Some(Self::Type),
            "macro" => Some(Self::Macro),
            "register" => Some(Self::Register),
            "field" => Some(Self::Field),
            "enumerator" | "enum" => Some(Self::Enumerator),
            "codename" | "code" => Some(Self::Codename),
            "hostname" | "host" => Some(Self::Hostname),
            "ip" | "ipv4" | "ipv6" => Some(Self::Ip),
            "secret" => Some(Self::Secret),
            "identifier" | "ident" => Some(Self::Identifier),
            _ => None,
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Secret => 100,
            Self::Ip => 90,
            Self::Hostname => 80,
            Self::Register => 70,
            Self::Macro => 60,
            Self::Function => 50,
            Self::Type => 40,
            Self::Enumerator => 30,
            Self::Field => 20,
            Self::Codename => 15,
            Self::Identifier => 10,
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
