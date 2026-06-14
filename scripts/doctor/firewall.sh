#!/bin/bash
# SessionStart doctor — companion install-time firewalls (NOT wormhook deps; the registry-boundary
# layer wormhook deliberately cedes). wormhook is local/no-network by design; these own malicious-
# version blocking, typosquats, and publish-age/reputation scoring at install time.
#   - Socket Firewall (sfw): wraps the package manager and blocks risky installs live.
#   - safedep/vet:           dependency CVE + malicious-package + license scan.
#   🟢 both present.  🟡 one/both absent (names which; silenceable).  ⚪ absent but silenced.
# When sfw is present, also attaches a model-facing COMPOSITION advisory: if the user also runs
# wormhook's shell exec-guard, the two must chain in ONE wrapper (guard -> sfw -> real), not run
# as two separate npm() blocks (last-loaded silently clobbers the other). Keyed ONLY on the
# reliable `command -v sfw` signal — never on rc introspection, since a SessionStart hook runs
# non-interactively and cannot see the user's interactive shell functions (a green light asserting
# "your rc is composed" would be a lie). It points at /wormhook-setup; it does not verify.
# NB: sfw had an untrusted-dir .sfw.config RCE (CVE-2025-64726, fixed 0.15.5) — the nudge says
# "keep it current" rather than pinning a version floor (a hard-coded floor goes stale).
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

miss=()
command -v sfw >/dev/null 2>&1 || wh_silenced "${WORMHOOK_SKIP_SFW:-}" || miss+=("Socket Firewall (sfw): install-time registry firewall — install & keep current (https://docs.socket.dev/docs/socket-firewall) [silence: WORMHOOK_SKIP_SFW=1]")
command -v vet >/dev/null 2>&1 || wh_silenced "${WORMHOOK_SKIP_VET:-}" || miss+=("safedep/vet: dependency CVE/malicious-package audit (https://github.com/safedep/vet) [silence: WORMHOOK_SKIP_VET=1]")

# Composition advisory (model-facing), keyed ONLY on the reliable `command -v sfw` signal. We
# cannot see the user's interactive rc from a non-interactive SessionStart hook, so this never
# claims to verify their setup — it fires whenever sfw is present, regardless of the light color.
compose_ctx=""
if command -v sfw >/dev/null 2>&1; then
  compose_ctx="[firewall-compose] sfw is installed. If the user also runs wormhook's shell exec-guard (eval \"\$(wormhook-scan shell-init)\"), it MUST be composed with sfw in ONE wrapper chain (wormhook guard -> sfw -> real binary), NOT defined as two separate npm()/pnpm() blocks — whichever rc block loads last silently clobbers the other, disabling a layer. Point them at /wormhook-setup for the composed block. Advisory only; cannot verify their rc from a SessionStart hook."
fi

# Fully present (or every absence silenced): green if both tools are actually on PATH, else ⚪.
# A non-empty compose_ctx rides along as the model-facing context (empty -> wh_flag omits it).
if (( ${#miss[@]} == 0 )); then
  if command -v sfw >/dev/null 2>&1 && command -v vet >/dev/null 2>&1; then
    wh_flag 🟢 firewall "install-time firewalls present (sfw + vet)" "$compose_ctx"
  else
    wh_flag ⚪ firewall "install-time firewall(s) absent (silenced)" "$compose_ctx"
  fi
  exit 0
fi

msg="install-time registry defense incomplete:"
for _m in "${miss[@]}"; do msg+=$'\n  • '"$_m"; done
ctx="[firewall-status] wormhook is the local lock; it cedes the install-time registry boundary to sfw + vet. One or both are absent. Low priority — mention only if the user is working on dependencies/installs/supply-chain. Run-alongside, not instead."
[[ -n "$compose_ctx" ]] && ctx+=$'\n'"$compose_ctx"
wh_flag 🟡 firewall "$msg" "$ctx"
exit 0
