#!/bin/bash
# SessionStart doctor — wormhook's own runtime deps.
#   🔴 jq missing      -> the scanner cannot run; scans are OFF. THE one critical doctor case.
#   🟡 ripgrep missing -> content scans fall back to single-core grep (30.3s vs 0.7s on a 58k-file
#                         node_modules); silenceable via WORMHOOK_SKIP_RG=1.
#   ⚪ ripgrep missing but silenced.   Both present -> silent (see doctor/CLAUDE.md).
#
# The jq 🔴 is a static printf raised BEFORE sourcing _utils.sh, because jq is the very thing it
# reports missing. This check OWNS that alarm: every other doctor/*.sh stays silent without jq.
# A CI presence-assert keeps this file existing + registered FIRST, so the alarm cannot vanish.
set -uo pipefail

if ! command -v jq >/dev/null 2>&1; then
  printf '%s\n' '{"systemMessage":"🔴 [wormhook] deps — jq missing, scans are OFF (brew install jq)"}'
  exit 0
fi

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

if command -v rg >/dev/null 2>&1; then
  :
elif wh_silenced "${WORMHOOK_SKIP_RG:-}"; then
  wh_flag ⚪ deps "ripgrep absent — slow grep fallback (silenced)"
else
  wh_flag 🟡 deps "ripgrep absent — content scans use slow grep fallback (brew install ripgrep) [silence: WORMHOOK_SKIP_RG=1]"
fi
exit 0
