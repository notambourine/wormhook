#!/bin/bash
# SessionStart doctor — self-integrity of the engine + signature corpus (issue #61). One
# appended `exit 0` silences every surface (the PreToolUse block, the UPS monitor, the launchd
# sweep, the git hooks) while every scan keeps reporting clean; this closes that silent case.
# It raises the bar to a COORDINATED edit only — an attacker who can edit the engine can also
# regenerate the manifest, and there is no signing or self-healing here.
#   🔴 hash mismatch — NOT silenceable, same class as the deps.sh jq alarm.
#   🟡 manifest missing/empty — cannot verify; fail open, loud.  Match => silent.
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
  # No slashes, so a doctored manifest cannot point the check outside scripts/.
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
