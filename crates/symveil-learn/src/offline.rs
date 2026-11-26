//! Runtime gate for `symveil learn`.
//!
//! The command does not read `[proxy]` and does not open a socket. If the
//! process environment is set up to point an HTTP client or a model client at
//! an endpoint, learn refuses instead of continuing in that process.

use anyhow::{bail, Result};

/// Environment variables that would tell an HTTP or model client where to
/// connect. Learn does not read their values to make a request. If any is
/// set, the command exits.
const ENDPOINT_VARS: &[&str] = &[
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "ANTHROPIC_BASE_URL",
    "GROK_XAI_API_BASE_URL",
    "GROK_MODELS_BASE_URL",
    "SYMVEIL_OPENAI_BASE",
    "SYMVEIL_ANTHROPIC_BASE",
    "SYMVEIL_LEARN_ENDPOINT",
    "SYMVEIL_LEARN_MODEL",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "SOCKS_PROXY",
    "https_proxy",
    "http_proxy",
    "all_proxy",
    "socks_proxy",
];

/// Config fields learn does not load. Present so a later edit that threads
/// them into this command has to go through this function, which always fails.
const UNREAD_PROXY_FIELDS: &[&str] = &["openai_base", "anthropic_base", "listen"];

pub fn assert_offline() -> Result<()> {
    debug_assert!(UNREAD_PROXY_FIELDS.contains(&"openai_base"));
    debug_assert!(UNREAD_PROXY_FIELDS.contains(&"anthropic_base"));
    let mut found = Vec::new();
    for key in ENDPOINT_VARS {
        if std::env::var_os(key).is_some_and(|value| !value.is_empty()) {
            found.push(*key);
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    bail!(
        "symveil learn refuses to run while LLM or proxy settings are present ({}). It does not contact a network and will not read those values or [proxy]. Unset them and run again.",
        found.join(", ")
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::assert_offline;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn refuses_when_a_model_endpoint_is_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        let key = "SYMVEIL_LEARN_ENDPOINT";
        let previous = std::env::var_os(key);
        std::env::set_var(key, "http://127.0.0.1:9");
        let err = assert_offline().unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains(key), "{message}");
        assert!(message.contains("refuses"), "{message}");
        assert!(!message.contains("127.0.0.1"), "{message}");
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn allows_a_clean_environment() {
        let _guard = ENV_LOCK.lock().unwrap();
        let key = "SYMVEIL_LEARN_MODEL";
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        assert_offline().unwrap();
        if let Some(value) = previous {
            std::env::set_var(key, value);
        }
    }
}
