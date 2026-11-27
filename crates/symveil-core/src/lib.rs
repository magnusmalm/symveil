//! Free tier of SymVeil: a local proxy that masks secrets before they reach a
//! cloud model and restores them in the response. Personal-data rules are
//! installed only when `[redact.pii]` turns them on.
//!
//! Company, product, project, and person names are masked when `[redact.names]`
//! lists them. The identifier index is a [`Masker`] plugin loaded by the `symveil`
//! binary when that binary is built with the `identifiers` feature.

#![forbid(unsafe_code)]

mod binary;
mod encoding;
mod keystore;
mod perms;
mod seal;

pub mod audit;
/// Synthetic workloads for the bench harness and the byte-stability test.
/// Not part of the proxy.
#[doc(hidden)]
pub mod bench_corpus;
pub mod category;
pub mod config;
pub mod masker;
pub mod names;
pub mod pii;
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
