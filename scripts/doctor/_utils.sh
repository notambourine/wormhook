# shellcheck shell=bash
# shellcheck disable=SC2034  # WORMHOOK_* constants are consumed by the checks that source this
# Sourcing exit 0 stops the caller; deps.sh emits the missing-jq alarm before this guard.
command -v jq >/dev/null 2>&1 || exit 0

# Bash 3.2 and BSD date lack a subsecond clock.
__WH_T0=$(jq -n now 2>/dev/null) || __WH_T0=""
# A zero default would report the whole Unix epoch.
__wh_dur() {
  local d
  [[ -n "${__WH_T0:-}" ]] || { printf '0.0'; return; }
  d=$(jq -n --argjson t0 "$__WH_T0" 'now - $t0' 2>/dev/null) || d=0
  printf '%.1f' "$d"
}

# shellcheck source=scripts/wormhook-const.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../wormhook-const.sh" 2>/dev/null || true

WORMHOOK_DOCTOR_QUIET="${WORMHOOK_DOCTOR_QUIET:-}"
wh_silenced() { [[ -n "$WORMHOOK_DOCTOR_QUIET" || -n "$1" ]]; }

wh_emit() { jq -nc --arg sm "$1 ($(__wh_dur)s)" '{systemMessage:$sm}'; }
wh_emit_ctx() {
  jq -nc --arg sm "$1 ($(__wh_dur)s)" --arg ctx "$2" \
    '{systemMessage:$sm, hookSpecificOutput:{hookEventName:"SessionStart", additionalContext:$ctx}}'
}
wh_flag() {
  if [[ -n "${4:-}" ]]; then wh_emit_ctx "$1 [wormhook] $2 — $3" "$4"; else wh_emit "$1 [wormhook] $2 — $3"; fi
}
