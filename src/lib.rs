//! SymVeil command-line crate.
//!
//! The free build masks secrets. `--features identifiers` links the proprietary
//! code-name plugin.

#![forbid(unsafe_code)]

mod plugins;

pub use symveil_core::{
    audit, category, config, masker, proxy, redact, scan, secrets, stream, vault, Category, Config,
    Engine, Hit, Masker, Vault,
};

#[cfg(feature = "identifiers")]
pub use symveil_identifiers::{index_repo, IndexOptions, IndexReport};

use symveil_core::config::RedactSection;

pub fn build_engine(vault: Vault, redact: &RedactSection) -> anyhow::Result<Engine> {
    let mut vault = vault;
    let extra = plugins::extra_maskers(&mut vault, redact)?;
    Engine::with_maskers(vault, redact, extra)
}
