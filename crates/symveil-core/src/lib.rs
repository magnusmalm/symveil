//! Free tier of SymVeil: a local proxy that masks secrets before they reach a
//! cloud model and restores them in the response.
//!
//! Identifier and code-name masking is not in this crate. It is a [`Masker`]
//! plugin loaded by the `symveil` binary when that binary is built with the
//! `identifiers` feature.

#![forbid(unsafe_code)]

pub mod audit;
pub mod category;
pub mod config;
pub mod masker;
pub mod proxy;
pub mod redact;
pub mod scan;
pub mod secrets;
pub mod stream;
pub mod vault;

pub use category::Category;
pub use config::Config;
pub use masker::{Boundary, Candidate, Masker};
pub use redact::{Engine, Hit};
pub use vault::Vault;
