# Contributing

Thanks for looking at the free tier of SymVeil.

## Setup

Install a stable Rust toolchain with `rustfmt` and `clippy`. `rust-toolchain.toml` names both.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`cargo build` and `cargo build --no-default-features` both produce the secret-masking proxy.

## Changes

- Keep the proxy local. It binds to loopback unless the user points `listen` elsewhere, and it should keep doing that by default.
- Do not log secret values. The audit log records the rule, the length, and the placeholder.
- New secret rules belong next to the existing builtin list, with a regression test that the value is masked and then restored.
- Run `cargo fmt --all` before sending a change.

## Pull requests

Open a pull request against `main`. CI runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
