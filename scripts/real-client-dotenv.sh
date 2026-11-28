#!/bin/sh
# Start a throwaway proxy and a loopback capture in front of the upstream.
#
# Copies tests/fixtures/dotenv-repo/.env into a temp directory, listens on
# 127.0.0.1, and prints the claude command for that directory. After Enter or
# Ctrl-C, prints whether each fixture value was in a captured request body.
# Does not print the values. Deletes the temp directory on exit.
#
# This does not sandbox the client. A tool can still read the file locally.
# The capture only shows what the proxy forwarded.
#
# SYMVEIL_BIN and SYMVEIL_CAPTURE_BIN default to the release binaries.
# SYMVEIL_CAPTURE_UPSTREAM defaults to the Anthropic HTTPS origin.
# SYMVEIL_REAL_CLIENT_STATUS, when set, receives the same status lines as stdout.

set -eu

script_dir=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd) || exit 1
repo=$(unset CDPATH; cd -- "${script_dir}/.." && pwd) || exit 1

fixture=${repo}/tests/fixtures/dotenv-repo/.env
symveil_bin=${SYMVEIL_BIN:-${repo}/target/release/symveil}
capture_bin=${SYMVEIL_CAPTURE_BIN:-${repo}/target/release/symveil-capture}
upstream=${SYMVEIL_CAPTURE_UPSTREAM:-https://api.anthropic.com}

die() {
  printf 'symveil: %s\n' "$1" >&2
  exit 1
}

if [ ! -f "${fixture}" ]; then
  die "missing fixture ${fixture}"
fi
if [ ! -x "${symveil_bin}" ] || [ ! -x "${capture_bin}" ]; then
  die "build first: cargo build --release"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/symveil-real-client.XXXXXX")
chmod 700 "${work}"
proxy_pid=
capture_pid=
do_scan=0
cleaned=0

stop_children() {
  if [ -n "${proxy_pid}" ]; then
    kill "${proxy_pid}" 2>/dev/null || true
    wait "${proxy_pid}" 2>/dev/null || true
    proxy_pid=
  fi
  if [ -n "${capture_pid}" ]; then
    kill "${capture_pid}" 2>/dev/null || true
    wait "${capture_pid}" 2>/dev/null || true
    capture_pid=
  fi
}

finish() {
  if [ "${cleaned}" -eq 1 ]; then
    return 0
  fi
  cleaned=1
  stop_children
  rm -rf "${work}"
}

report() {
  if [ "${do_scan}" -ne 1 ]; then
    return 0
  fi
  do_scan=0
  stop_children
  "${capture_bin}" scan --fixture "${work}/.env" --bodies "${bodies}"
}

trap finish EXIT
trap 'report || true; exit 130' INT
trap 'report || true; exit 143' TERM

status() {
  printf '%s\n' "$1"
  if [ -n "${SYMVEIL_REAL_CLIENT_STATUS:-}" ]; then
    printf '%s\n' "$1" >> "${SYMVEIL_REAL_CLIENT_STATUS}"
  fi
}

match_prefix() {
  file=$1
  prefix=$2
  while IFS= read -r line; do
    case ${line} in
      "${prefix}"*)
        printf '%s' "${line#"${prefix}"}"
        return 0
        ;;
    esac
  done < "${file}"
  return 1
}

wait_for() {
  file=$1
  prefix=$2
  pid=$3
  label=$4
  err=$5
  i=0
  while [ "${i}" -lt 200 ]; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      printf 'symveil: %s exited\n' "${label}" >&2
      if [ -f "${err}" ]; then
        tail -n 40 "${err}" >&2 || true
      fi
      return 1
    fi
    if [ -f "${file}" ]; then
      if url=$(match_prefix "${file}" "${prefix}"); then
        printf '%s' "${url}"
        return 0
      fi
    fi
    i=$((i + 1))
    sleep 0.05
  done
  printf 'symveil: %s did not listen\n' "${label}" >&2
  if [ -f "${err}" ]; then
    tail -n 40 "${err}" >&2 || true
  fi
  return 1
}

cp "${fixture}" "${work}/.env"
chmod 600 "${work}/.env"
cat > "${work}/.symveil.toml" <<'EOF'
[proxy]
listen = "127.0.0.1"
port = 0
timeout_secs = 0

[redact]
mode = "enforce"
dotenv = true
learned = "learned.toml"
EOF
printf '%s\n' 'version = 1' > "${work}/learned.toml"
chmod 600 "${work}/.symveil.toml" "${work}/learned.toml"
mkdir -p "${work}/home"
chmod 700 "${work}/home"
bodies=${work}/bodies

env -i PATH="${PATH}" \
  "${capture_bin}" forward \
  --listen 127.0.0.1:0 \
  --upstream "${upstream}" \
  --bodies "${bodies}" \
  > "${work}/capture.out" 2> "${work}/capture.err" &
capture_pid=$!

if ! capture_url=$(wait_for "${work}/capture.out" "listening " "${capture_pid}" "capture" "${work}/capture.err"); then
  exit 1
fi
case ${capture_url} in
  http://127.0.0.1:*) ;;
  *)
    die "capture listened on an unexpected address"
    ;;
esac

env -i PATH="${PATH}" HOME="${work}/home" SYMVEIL_TEST_FILE_KEY=1 \
  "${symveil_bin}" proxy \
  --repo "${work}" \
  --config "${work}/.symveil.toml" \
  --port 0 \
  --anthropic-base "${capture_url}" \
  --openai-base "${capture_url}" \
  > "${work}/proxy.out" 2> "${work}/proxy.err" &
proxy_pid=$!

if ! proxy_url=$(wait_for "${work}/proxy.err" "symveil listening on " "${proxy_pid}" "proxy" "${work}/proxy.err"); then
  exit 1
fi
case ${proxy_url} in
  http://127.0.0.1:*) ;;
  *)
    die "proxy listened on an unexpected address"
    ;;
esac

status "dir=${work}"
status "proxy=${proxy_url}"
status "capture=${capture_url}"
status "bodies=${bodies}"
status "ready"
printf '\n'
printf 'Temp directory (removed when this script exits):\n'
printf '  %s\n' "${work}"
printf '\n'
printf 'Run this, ask Claude to read the .env file and summarize it, then come back here and press Enter:\n'
printf '\n'
printf "  cd '%s' && ANTHROPIC_BASE_URL='%s' CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 ENABLE_CLAUDEAI_MCP_SERVERS=false claude --strict-mcp-config\n" \
  "${work}" "${proxy_url}"
printf '\n'
printf 'Press Enter after Claude exits. Ctrl-C prints the same lines and deletes the directory.\n'

do_scan=1
read -r _ || true
report
