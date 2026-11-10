#!/bin/sh
# Scripted demo for integrations/claude-code. Builds symveil when SYMVEIL_BIN is unset.
set -eu
cd "$(dirname "$0")"
if [ -z "${SYMVEIL_BIN:-}" ]; then
  cargo build -q --manifest-path ../../Cargo.toml --bin symveil
  SYMVEIL_BIN="../../target/debug/symveil"
  export SYMVEIL_BIN
fi
exec python3 ./demo.py
