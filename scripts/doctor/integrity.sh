#!/bin/bash
# This detects uncoordinated edits; an attacker who replaces the manifest can bypass it.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$SCRIPTS_DIR/integrity.sha256"

if [[ ! -r "$MANIFEST" ]]; then
  wh_flag 🟡 integrity "manifest missing ($MANIFEST) — engine integrity unverifiable; reinstall the plugin"
  exit 0
fi

bad="" checked=0
while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in ''|'#'*) continue ;; esac
  want="${line%% *}"
  file="${line##* }"
  # Reject paths outside scripts/.
  case "$file" in */*|'') bad="${bad:+$bad, }bad manifest entry"; continue ;; esac
  checked=$((checked+1))
  got="$(shasum -a 256 "$SCRIPTS_DIR/$file" 2>/dev/null | awk '{print $1}')"
  [[ "$got" == "$want" ]] || bad="${bad:+$bad, }$file"
done < "$MANIFEST"

if [[ -n "$bad" ]]; then
  wh_flag 🔴 integrity "$bad does NOT match the shipped manifest — scanner may be tampered with; no wormhook verdict can be trusted" \
    "[wormhook] SELF-INTEGRITY FAILURE: $bad differs from the shipped SHA-256 manifest (scripts/integrity.sha256). A modified engine can report green while scanning nothing. State this to the user plainly, treat every wormhook verdict as unreliable, and advise reinstalling the plugin from https://github.com/notambourine/wormhook before trusting any further scan."
  exit 0
fi
if [[ "$checked" -eq 0 ]]; then
  wh_flag 🟡 integrity "manifest has no entries — engine integrity unverifiable; reinstall the plugin"
  exit 0
fi
exit 0
