#!/bin/sh
# Reproducible SymVeil bench. Synthetic data only. The proxy talks to a
# 127.0.0.1 mock and does not contact a real model host.
#
#   scripts/bench.sh           # ~100k terms, 100 KB to 5 MB payloads
#   scripts/bench.sh --quick   # short run used by the non-gating CI job
#
# A scaling sweep (not part of the default measurement):
#   cargo bench --locked -p symveil-core --bench mask -- --probe
set -eu
cd "$(dirname "$0")/.."

profile=full
if [ "${1:-}" = "--quick" ]; then
  profile=quick
elif [ "${1:-}" != "" ]; then
  echo "usage: scripts/bench.sh [--quick]" >&2
  exit 2
fi

echo "== machine =="
uname -srm || true
rustc --version

echo "== release binary =="
cargo build --release --locked --bin symveil

export SYMVEIL_BIN="$PWD/target/release/symveil"
export SYMVEIL_BENCH_PROFILE="$profile"

echo "== criterion ($profile) =="
cargo bench --locked -p symveil-core --bench mask

echo "== proxy e2e ($profile) =="
cargo bench --locked --bench proxy_e2e
