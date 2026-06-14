#!/bin/bash
# SessionStart doctor — out-of-band trigger coverage. The Claude hook is one trigger, not the
# engine; wormhook-scan.sh adds the non-Claude triggers. Reports which are wired:
#   CLI on PATH · global git hook (all 3 of post-merge/post-checkout/post-rewrite) · hourly launchd sweep.
#   🟢 all wired.  🟡 any ✗ -> shows the ✓/✗ picture + points at /wormhook-setup (silenceable).
#   ⚪ silenced, or corrupt install (shared constants did not load).  launchd sweep is n/a off macOS.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

# Self-skip to ⚪ if the shared constants did not load (corrupt install) — without them the probe
# below cannot know what to look for, and a false "✗" would be a lie.
if [[ -z "${WORMHOOK_HOOK_MARKER:-}" || -z "${WORMHOOK_LAUNCHD_LABEL:-}" ]]; then
  wh_flag ⚪ coverage "n/a — shared constants did not load (corrupt install?)"
  exit 0
fi

_cli=✗; command -v wormhook-scan >/dev/null 2>&1 && _cli=✓
# git-hook is ✓ only when ALL THREE installed hooks carry the marker — a partial/corrupted install
# must not report full coverage.
_hook=✗
_hd=$(git config --global --get core.hooksPath 2>/dev/null); _hd="${_hd/#\~/$HOME}"
if [[ -n "$_hd" ]]; then
  _hk=0
  for _h in post-merge post-checkout post-rewrite; do
    [[ -f "$_hd/$_h" ]] && grep -qF "$WORMHOOK_HOOK_MARKER" "$_hd/$_h" 2>/dev/null && _hk=$((_hk+1))
  done
  [[ "$_hk" == 3 ]] && _hook=✓
fi
if [[ "$(uname -s)" == "Darwin" ]]; then
  _sweep=✗; launchctl print "gui/$(id -u)/$WORMHOOK_LAUNCHD_LABEL" >/dev/null 2>&1 && _sweep=✓
else
  _sweep="n/a"
fi

if [[ "$_cli" == "✓" && "$_hook" == "✓" && ( "$_sweep" == "✓" || "$_sweep" == "n/a" ) ]]; then
  wh_flag 🟢 coverage "out-of-band wired (CLI:$_cli git-hook:$_hook hourly-sweep:$_sweep)"
elif wh_silenced "${WORMHOOK_SKIP_COVERAGE:-}"; then
  wh_flag ⚪ coverage "out-of-band incomplete (CLI:$_cli git-hook:$_hook hourly-sweep:$_sweep) (silenced)"
else
  ctx="[coverage-status] wormhook's non-Claude triggers are not fully wired. Run /wormhook-setup in Claude to finish. Low priority — mention only if the user asks about fleet/out-of-band scanning."
  wh_flag 🟡 coverage "CLI:$_cli git-hook:$_hook hourly-sweep:$_sweep — run /wormhook-setup to finish [silence: WORMHOOK_SKIP_COVERAGE=1]" "$ctx"
fi
exit 0
