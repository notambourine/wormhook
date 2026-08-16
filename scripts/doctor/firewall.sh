#!/bin/bash
# SessionStart doctor — companion install-time firewalls, NOT wormhook deps: Socket Firewall
# (sfw) and safedep/vet own the registry boundary wormhook deliberately cedes.
#   🟡 one/both absent (silenceable).  ⚪ silenced.  Both present => silent.
# sfw had an untrusted-dir .sfw.config RCE (CVE-2025-64726, fixed 0.15.5), so the nudge says
# "keep it current" — a hard-coded version floor goes stale.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

miss=()
command -v sfw >/dev/null 2>&1 || wh_silenced "${WORMHOOK_SKIP_SFW:-}" || miss+=("Socket Firewall (sfw): install-time registry firewall — install & keep current (https://docs.socket.dev/docs/socket-firewall) [silence: WORMHOOK_SKIP_SFW=1]")
command -v vet >/dev/null 2>&1 || wh_silenced "${WORMHOOK_SKIP_VET:-}" || miss+=("safedep/vet: dependency CVE/malicious-package audit (https://github.com/safedep/vet) [silence: WORMHOOK_SKIP_VET=1]")

# An absence that is silenced still shows as ⚪ — silencing hides the nag, not the fact.
if (( ${#miss[@]} == 0 )); then
  if ! command -v sfw >/dev/null 2>&1 || ! command -v vet >/dev/null 2>&1; then
    wh_flag ⚪ firewall "install-time firewall(s) absent (silenced)"
  fi
  exit 0
fi

msg="install-time registry defense incomplete:"
for _m in "${miss[@]}"; do msg+=$'\n  • '"$_m"; done
ctx="[firewall-status] wormhook is the local lock; it cedes the install-time registry boundary to sfw + vet. One or both are absent. Low priority — mention only if the user is working on dependencies/installs/supply-chain. Run-alongside, not instead."
wh_flag 🟡 firewall "$msg" "$ctx"
exit 0
