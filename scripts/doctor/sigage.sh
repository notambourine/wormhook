#!/bin/bash
# SessionStart doctor — signature-corpus age. Detection is retrospective and nothing else fails
# when the corpus goes stale, so a clean engine can be catching only last year's worms.
#   🟡 older than WORMHOOK_SIGAGE_MAX_DAYS (default 60) — run /update (silenceable).
#   ⚪ silenced, or WORMHOOK_SIGNATURES_ASOF missing/malformed.  Fresh => silent.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

# shellcheck source=scripts/malware-patterns.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../malware-patterns.sh" 2>/dev/null || true

ASOF="${WORMHOOK_SIGNATURES_ASOF:-}"
if [[ ! "$ASOF" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  wh_flag ⚪ sigage "WORMHOOK_SIGNATURES_ASOF missing/malformed in malware-patterns.sh — corpus age unknown (corrupt install?)"
  exit 0
fi

max="${WORMHOOK_SIGAGE_MAX_DAYS:-60}"
[[ "$max" =~ ^[0-9]+$ && "$max" -ge 1 ]] || max=60

days=$(jq -n --arg d "$ASOF" '((now - (($d + "T00:00:00Z") | fromdate)) / 86400) | floor' 2>/dev/null) || days=""
[[ "$days" =~ ^-?[0-9]+$ ]] || { wh_flag ⚪ sigage "cannot compute corpus age from $ASOF"; exit 0; }

(( days <= max )) && exit 0

if wh_silenced "${WORMHOOK_SKIP_SIGAGE:-}"; then
  wh_flag ⚪ sigage "corpus ${days}d old (silenced)"
  exit 0
fi
ctx="[sigage] The wormhook signature corpus was last verified against advisories on $ASOF (${days} days ago; threshold ${max}d). Detection of campaigns newer than that date is not guaranteed. Suggest running the wormhook /update skill (sweep Socket/Snyk/Wiz/Unit42/Mend/Microsoft/CISA advisories; land new IOCs or bump WORMHOOK_SIGNATURES_ASOF if nothing new). Low priority — mention only if the user asks about supply-chain coverage or signatures."
wh_flag 🟡 sigage "signature corpus last verified $ASOF (${days}d ago) — sweep advisories / run the update skill, then bump WORMHOOK_SIGNATURES_ASOF [silence: WORMHOOK_SKIP_SIGAGE=1]" "$ctx"
exit 0
