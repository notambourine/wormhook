#!/bin/bash
# Raise the missing-jq alarm before sourcing the helper, which exits when jq is absent.
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
