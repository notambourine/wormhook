#!/bin/bash
# SessionStart doctor — self-integrity of the engine + signature corpus (issue #61).
#   🔴 hash mismatch -> scripts/wormhook.sh or scripts/malware-patterns.sh differs from the
#                       shipped SHA-256 manifest: the scanner itself may be tampered with
#                       (one appended `exit 0` silences every surface — the PreToolUse block,
#                       the UPS monitor, the launchd sweep, the git hooks — while the
#                       dashboard keeps printing green). NOT silenceable.
#   🟡 manifest missing/empty -> cannot verify (corrupt install); fail open, loud.
#   🟢 both files match.
#
# Scope: this raises the bar from a one-line append to a COORDINATED edit. An attacker who
# can edit the engine can also regenerate scripts/integrity.sha256 — the check does not
# survive that and does not try to (no signing, no self-healing). What it closes is the
# silent case: a neutered engine that keeps reporting healthy. Like the deps.sh jq alarm,
# this 🔴 is deliberately NOT silenceable via WORMHOOK_SKIP_*/WORMHOOK_DOCTOR_QUIET —
# tampering must never be quietable. CI keeps the manifest honest (a stale manifest is a
# red PR), and the existing version-bump tripwire makes an engine edit without a version
# move a red PR too.
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
  # Entries come from our committed manifest, but keep them on a leash anyway: no
  # slashes, so a doctored manifest cannot point the check outside scripts/.
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
wh_flag 🟢 integrity "engine + signatures match the shipped manifest ($checked/$checked files)"
exit 0
