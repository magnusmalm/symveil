//! Secret shapes and the `learned.toml` document.
//!
//! No HTTP client and no sockets. `symveil learn` depends on this crate
//! instead of the proxy crate so its dependency set stays offline.

#![forbid(unsafe_code)]

pub mod dotenv;
pub mod learned;
mod learned_fast;
pub mod literals;
pub mod secrets;
