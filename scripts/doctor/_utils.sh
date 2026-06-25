# shellcheck shell=bash
# shellcheck disable=SC2034  # WORMHOOK_* constants are consumed by the checks that source this
# Shared helpers for the split SessionStart doctor checks (scripts/doctor/*.sh).
# Sourced — no shebang, never executed directly. Each doctor/<check>.sh sources this once,
# then emits exactly ONE jq object via the wh_* helpers below.
#
# jq model (KEY-DECISION 2026-06-13, refined for the 0.10.0 split): the jq-missing "scans are
# OFF" 🔴 alarm is owned SOLELY by doctor/deps.sh (a static printf raised BEFORE it sources this
# file). Every OTHER check inherits the silent fail-open below: sourcing a file that calls `exit`
# exits the CALLING shell, so the one guard here disarms all non-deps checks when jq is absent
# (deps.sh already shouted). A CI presence-assert guarantees deps.sh exists, so that single alarm
# can never silently vanish. Everything past this guard may rely on jq --arg (injection-safe).
command -v jq >/dev/null 2>&1 || exit 0

# Per-check runtime stamp. Captured at source time (the first few lines of every check), so the
# elapsed value below covers essentially the whole check. Apple's /bin/bash is 3.2.57 — no
# $EPOCHREALTIME (bash 5+) and BSD `date` has no %N, so the sub-second clock is `jq -n now` (jq is
# already this file's hard dependency — we exited above without it). Cost: one extra jq spawn per
# check, paid once at the single emit. printf %.1f rounds the float for display ("0.348" -> "0.3").
__WH_T0=$(jq -n now 2>/dev/null) || __WH_T0=""
# __wh_dur -> "x.x" seconds since source time (empty stamp / jq failure degrades to "0.0", never errors).
# Guard on an EMPTY stamp before subtracting: a `:-0` default would make jq compute `now - 0` (the
# whole Unix epoch) and report it as elapsed — so a missing stamp must short-circuit to 0.0.
__wh_dur() {
  local d
  [[ -n "${__WH_T0:-}" ]] || { printf '0.0'; return; }
  d=$(jq -n --argjson t0 "$__WH_T0" 'now - $t0' 2>/dev/null) || d=0
  printf '%.1f' "$d"
}

# Shared launchd-label + git-hook-marker constants (single source — see wormhook-const.sh), so the
# coverage probe detects exactly what wormhook-scan.sh installs. Absent (corrupt install) => the
# constants stay unset and coverage.sh self-skips to ⚪.
# shellcheck source=scripts/wormhook-const.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../wormhook-const.sh" 2>/dev/null || true

# Per-item noise control: set WORMHOOK_SKIP_<ITEM>=1 (repo or user settings.json "env") to silence
# a nudge you have consciously declined; WORMHOOK_DOCTOR_QUIET=1 mutes every soft nudge. A silenced
# soft nudge degrades to ⚪ (acknowledged), never to actual silence — an invisible check is the bug.
WORMHOOK_DOCTOR_QUIET="${WORMHOOK_DOCTOR_QUIET:-}"
# wh_silenced <skip-var-value> -> true when that nudge is muted (its skip var OR global QUIET set).
wh_silenced() { [[ -n "$WORMHOOK_DOCTOR_QUIET" || -n "$1" ]]; }

# Emit helpers — exactly one JSON object per check on stdout (the hook protocol allows one).
# All dynamic content flows through jq --arg, so paths/versions/filenames are injection-safe.
# Every line gets a " (x.xs)" runtime suffix (see __wh_dur). Appended here, the lowest emit point,
# so all callers (wh_flag and any direct wh_emit) are stamped uniformly — only additionalContext,
# which the model reads, is left untimed.
# wh_emit <systemMessage>                — user-facing line only (pure 🟢/⚪, no model action).
# wh_emit_ctx <systemMessage> <context>  — line + additionalContext (the model should act).
wh_emit() { jq -nc --arg sm "$1 ($(__wh_dur)s)" '{systemMessage:$sm}'; }
wh_emit_ctx() {
  jq -nc --arg sm "$1 ($(__wh_dur)s)" --arg ctx "$2" \
    '{systemMessage:$sm, hookSpecificOutput:{hookEventName:"SessionStart", additionalContext:$ctx}}'
}
# wh_flag <emoji> <check> <msg> [ctx] — enforce the dashboard line shape "<emoji> [wormhook] <check> — <msg>".
# A 4th arg attaches model-facing additionalContext; omit it for pure status lines.
wh_flag() {
  if [[ -n "${4:-}" ]]; then wh_emit_ctx "$1 [wormhook] $2 — $3" "$4"; else wh_emit "$1 [wormhook] $2 — $3"; fi
}
