#!/bin/bash
# SessionStart doctor — shell exec-guard hygiene (clobber detection). The opt-in exec-guard
# (eval "$(wormhook-scan shell-init)") wraps npm/pnpm/yarn/bun/npx as shell functions. If the user
# ALSO keeps a separate Socket Firewall wrapper (npm() { sfw npm "$@"; }), the two define the same
# names and whichever rc block loads last silently clobbers the other — disabling a layer (the
# wormhook local-IOC guard OR the sfw registry firewall).
#
# What is OBSERVABLE here is the rc-file TEXT on disk (a plain file read, like coverage.sh greps
# the git-hook files) — NOT the interactive runtime (which functions actually won the clobber,
# which load order ran): a non-interactive SessionStart hook cannot see that. So this check only
# flags the definite clobber ANTI-PATTERN in the text; it never asserts a setup is correctly
# composed (that is the non-observable positive). It reads the live $HOME rc files the shell loads
# (not any dotfiles repo). False-negative-only by design: it skips sourced fragments/includes and
# multi-line function bodies, so it can MISS a clobber but never cries wolf on a correct setup
# (the composed block's PM functions call _sc_run, not sfw, so they do not match).
#   🟡 clobber: exec-guard + a bare `sfw` PM wrapper coexist -> compose them (/wormhook-setup).
#   🟢 exec-guard wired, no clobber.   ⚪ not wired (opt-in), no rc files, or silenced.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

rc_files=()
for f in "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [[ -f "$f" ]] && rc_files+=("$f")
done

if (( ${#rc_files[@]} == 0 )); then
  wh_flag ⚪ shellguard "no shell rc files found — exec-guard status unknown"
  exit 0
fi

# Is the opt-in exec-guard wired at all? (Both the standalone eval line and the composed block
# carry `wormhook-scan shell-init`.) grep -l is portable to BSD (macOS) and GNU grep.
if ! grep -lE 'wormhook-scan[[:space:]]+shell-init' "${rc_files[@]}" >/dev/null 2>&1; then
  wh_flag ⚪ shellguard "shell exec-guard not wired (opt-in: eval \"\$(wormhook-scan shell-init)\")"
  exit 0
fi

# Guard is wired. Clobber anti-pattern = a package-manager function whose body calls `sfw`
# DIRECTLY (e.g. `npm() { sfw npm "$@"; }`). The composed block's PM functions call `_sc_run`
# (sfw is reached only inside that helper), so they do NOT match — no false positive on a correct
# setup. uv/cargo are intentionally sfw-only and not PM names here, so they never trip this.
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

wh_flag 🟢 shellguard "shell exec-guard wired, no wrapper clobber"
exit 0
