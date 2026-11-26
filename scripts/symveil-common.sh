# Shared by scripts/symveil-claude and scripts/symveil-grok.
# Sets symveil_proxy to the origin (no /v1 suffix) or exits without returning
# when the proxy is not reachable. Does not print API keys or tokens.

symveil_prepare() {
  symveil_host=${SYMVEIL_HOST:-127.0.0.1}
  symveil_port=${SYMVEIL_PORT:-8787}
  if [ -n "${SYMVEIL_PROXY:-}" ]; then
    symveil_proxy=${SYMVEIL_PROXY}
  else
    symveil_proxy="http://${symveil_host}:${symveil_port}"
  fi
  symveil_proxy=${symveil_proxy%/}

  case ${symveil_proxy} in
    *[[:cntrl:]]*)
      echo "symveil: proxy URL contains a control character; not starting the client" >&2
      exit 1
      ;;
  esac

  case ${symveil_proxy} in
    http://*|https://*) ;;
    *)
      echo "symveil: proxy URL must be http or https; not starting the client" >&2
      exit 1
      ;;
  esac

  # Drop userinfo so a URL that embeds a secret is not written to stderr.
  symveil_label=${symveil_proxy}
  case ${symveil_label} in
    *://*@*)
      symveil_scheme=${symveil_label%%://*}
      symveil_rest=${symveil_label#*://}
      symveil_rest=${symveil_rest##*@}
      symveil_label="${symveil_scheme}://${symveil_rest}"
      ;;
  esac

  if ! command -v curl >/dev/null 2>&1; then
    echo "symveil: curl is required to check the proxy; not starting the client" >&2
    exit 1
  fi

  symveil_health=$(
    curl --proto '=http,https' -fsS --max-time 3 "${symveil_proxy}/health" 2>/dev/null
  ) || {
    echo "symveil: proxy at ${symveil_label} is not reachable; not starting the client" >&2
    exit 1
  }

  if [ "${#symveil_health}" -gt 256 ]; then
    echo "symveil: proxy health check returned an unexpected body; not starting the client" >&2
    exit 1
  fi

  symveil_ok='"status":"ok"'
  case ${symveil_health} in
    *"${symveil_ok}"*) ;;
    *)
      echo "symveil: proxy health check did not report status ok; not starting the client" >&2
      exit 1
      ;;
  esac
}

# Executing this file does nothing useful. The launch scripts source it.
case ${0##*/} in
  symveil-common.sh)
    echo "symveil: this file is sourced by symveil-claude and symveil-grok" >&2
    exit 1
    ;;
esac
