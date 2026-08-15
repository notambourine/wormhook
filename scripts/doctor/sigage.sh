#!/bin/bash
# SessionStart doctor — signature-corpus age. Signature detection is retrospective: the
# block tier only knows campaigns already landed in malware-patterns.sh, and nothing else
# fails when the corpus goes stale — a green engine can be detecting only last year's
# worms. The observable state is WORMHOOK_SIGNATURES_ASOF (malware-patterns.sh): the date
# the corpus was last verified against current advisories, bumped by the /update skill on
# every landed campaign or by hand after a sweep that found nothing new to land.
#   🟡 corpus older than WORMHOOK_SIGAGE_MAX_DAYS (default 60) — run /update (silenceable).
#   ⚪ stale but silenced, or the constant is missing/malformed (corrupt install).
#   Fresh is SILENT — advisory check, no green line (see doctor/CLAUDE.md).
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

# Fresh => silent (advisory check; a green line every session is the noise this
# check's siblings shed in the same change).
(( days <= max )) && exit 0

if wh_silenced "${WORMHOOK_SKIP_SIGAGE:-}"; then
  wh_flag ⚪ sigage "corpus ${days}d old (silenced)"
  exit 0
fi
ctx="[sigage] The wormhook signature corpus was last verified against advisories on $ASOF (${days} days ago; threshold ${max}d). Detection of campaigns newer than that date is not guaranteed. Suggest running the wormhook /update skill (sweep Socket/Snyk/Wiz/Unit42/Mend/Microsoft/CISA advisories; land new IOCs or bump WORMHOOK_SIGNATURES_ASOF if nothing new). Low priority — mention only if the user asks about supply-chain coverage or signatures."
wh_flag 🟡 sigage "signature corpus last verified $ASOF (${days}d ago) — sweep advisories / run the update skill, then bump WORMHOOK_SIGNATURES_ASOF [silence: WORMHOOK_SKIP_SIGAGE=1]" "$ctx"
exit 0
