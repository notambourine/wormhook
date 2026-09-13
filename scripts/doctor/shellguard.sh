#!/bin/bash
# RC text cannot prove which wrapper is active; report only a visible conflict.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

rc_files=()
for f in "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [[ -f "$f" ]] && rc_files+=("$f")
done

(( ${#rc_files[@]} == 0 )) && exit 0

grep -lE 'wormhook-scan[[:space:]]+shell-init' "${rc_files[@]}" >/dev/null 2>&1 || exit 0

clobber=$(grep -lE '^[[:space:]]*(npm|pnpm|yarn|bun|npx)[[:space:]]*\([[:space:]]*\)[[:space:]]*\{[^}]*sfw' "${rc_files[@]}" 2>/dev/null) || true

if [[ -n "$clobber" ]]; then
  cf=${clobber//$'\n'/ }
  if wh_silenced "${WORMHOOK_SKIP_SHELLGUARD:-}"; then
    wh_flag ⚪ shellguard "wrapper clobber present (silenced)"
    exit 0
  fi
  ctx="[shellguard-clobber] The shell exec-guard and a separate Socket Firewall wrapper both define npm()/pnpm()/etc in the user's rc ($cf); whichever loads last silently clobbers the other, disabling a layer. Tell them to replace the bare sfw wrapper with the composed chain (wormhook guard -> sfw -> real binary) — /wormhook-setup prints it. This reads rc TEXT only; it cannot see the runtime, so it confirms the anti-pattern is present, not which layer currently loses."
  wh_flag 🟡 shellguard "wrapper clobber — exec-guard + a bare sfw npm()-style wrapper coexist in $cf; compose them (/wormhook-setup) [silence: WORMHOOK_SKIP_SHELLGUARD=1]" "$ctx"
  exit 0
fi

exit 0
