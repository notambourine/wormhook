# shellcheck shell=bash
# shellcheck disable=SC2034  # WORMHOOK_* constants are consumed by the checks that source this
# Shared helpers for the SessionStart doctor checks. Sourced — no shebang, never executed.
#
# jq model (KEY-DECISION 2026-06-13): doctor/deps.sh owns the jq-missing "scans are OFF" 🔴 via a
# static printf raised before it sources this file. Every OTHER check inherits the fail-open
# below — sourcing a file that calls `exit` exits the CALLING shell, so this one guard disarms
# them all. Everything past it may rely on jq --arg (injection-safe).
command -v jq >/dev/null 2>&1 || exit 0

# Apple's /bin/bash is 3.2.57 (no $EPOCHREALTIME) and BSD `date` has no %N, so the sub-second
# clock is `jq -n now`. Stamped at source time, so the elapsed value covers the whole check.
__WH_T0=$(jq -n now 2>/dev/null) || __WH_T0=""
# Short-circuit on an EMPTY stamp: a `:-0` default would make jq report the whole Unix epoch.
__wh_dur() {
  local d
  [[ -n "${__WH_T0:-}" ]] || { printf '0.0'; return; }
  d=$(jq -n --argjson t0 "$__WH_T0" 'now - $t0' 2>/dev/null) || d=0
  printf '%.1f' "$d"
}

# Absent, these stay unset and coverage.sh self-skips to ⚪ rather than reporting a false ✗.
# shellcheck source=scripts/wormhook-const.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../wormhook-const.sh" 2>/dev/null || true

# WORMHOOK_SKIP_<ITEM>=1 silences one declined nudge; WORMHOOK_DOCTOR_QUIET=1 mutes them all.
# A silenced nudge degrades to ⚪ (acknowledged), never to actual silence.
WORMHOOK_DOCTOR_QUIET="${WORMHOOK_DOCTOR_QUIET:-}"
wh_silenced() { [[ -n "$WORMHOOK_DOCTOR_QUIET" || -n "$1" ]]; }

# One JSON object per check (the hook protocol allows one), all dynamic content through jq --arg.
# The " (x.xs)" suffix lands here, the lowest emit point, so every caller is stamped uniformly.
wh_emit() { jq -nc --arg sm "$1 ($(__wh_dur)s)" '{systemMessage:$sm}'; }
wh_emit_ctx() {
  jq -nc --arg sm "$1 ($(__wh_dur)s)" --arg ctx "$2" \
    '{systemMessage:$sm, hookSpecificOutput:{hookEventName:"SessionStart", additionalContext:$ctx}}'
}
# wh_flag <emoji> <check> <msg> [ctx] — the dashboard line shape; a 4th arg adds model context.
wh_flag() {
  if [[ -n "${4:-}" ]]; then wh_emit_ctx "$1 [wormhook] $2 — $3" "$4"; else wh_emit "$1 [wormhook] $2 — $3"; fi
}
