#!/bin/bash
# SessionStart doctor — wormhook's own runtime deps.
#   🔴 jq missing      -> the scanner cannot run; scans are OFF. THE one critical doctor case.
#   🟡 ripgrep missing -> content scans fall back to single-core grep (30.3s vs 0.7s on a 58k-file
#                         node_modules); silenceable via WORMHOOK_SKIP_RG=1.
#   ⚪ ripgrep missing but silenced.   🟢 both present.
#
# The jq-🔴 alarm is hand-rolled and STATIC — emitted with printf BEFORE sourcing _utils.sh,
# because jq is the very thing it reports missing. This check OWNS that alarm for the whole split
# (KEY-DECISION 2026-06-13 + 0.10.0): every other doctor/*.sh stays silent when jq is absent (it
# already shouted here). A CI presence-assert guarantees this file exists, so the alarm can never
# silently vanish; deps.sh is also registered FIRST among the doctor hooks in hooks.json.
set -uo pipefail

if ! command -v jq >/dev/null 2>&1; then
  printf '%s\n' '{"systemMessage":"🔴 [wormhook] deps — jq missing, scans are OFF (brew install jq)"}'
  exit 0
fi

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

# ripgrep: soft dependency — content scans fall back to slow grep without it.
if command -v rg >/dev/null 2>&1; then
  wh_flag 🟢 deps "jq + ripgrep present"
elif wh_silenced "${WORMHOOK_SKIP_RG:-}"; then
  wh_flag ⚪ deps "ripgrep absent — slow grep fallback (silenced)"
else
  wh_flag 🟡 deps "ripgrep absent — content scans use slow grep fallback (brew install ripgrep) [silence: WORMHOOK_SKIP_RG=1]"
fi
exit 0
