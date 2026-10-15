//! Where paid maskers attach. The open-core tree leaves this hook empty.

use anyhow::Result;
use symveil_core::config::RedactSection;
use symveil_core::masker::Masker;
use symveil_core::vault::Vault;

#[cfg(feature = "identifiers")]
pub fn extra_maskers(vault: &mut Vault, redact: &RedactSection) -> Result<Vec<Box<dyn Masker>>> {
    let masker = symveil_identifiers::install_masker(vault, redact)?;
    Ok(vec![masker])
}

#[cfg(not(feature = "identifiers"))]
pub fn extra_maskers(vault: &mut Vault, redact: &RedactSection) -> Result<Vec<Box<dyn Masker>>> {
    let _ = vault;
    if !redact.deny.is_empty() || !redact.patterns.is_empty() {
        eprintln!(
            "symveil: this build masks secrets only; ignoring {} deny term(s) and {} code-name pattern(s)",
            redact.deny.len(),
            redact.patterns.len()
        );
    }
    Ok(Vec::new())
}
