#!/bin/bash
# Environment doctor: SILENT when wormhook's runtime deps are healthy AND its recommended
# companion install-firewalls are present AND the out-of-band triggers are wired; otherwise
# one 🟡 message with a per-item checklist. Runs at SessionStart alongside the scanner. Each
# soft item carries a [silence: WORMHOOK_SKIP_<ITEM>=1] hint so a consciously-declined nudge
# can be muted (repo or user settings.json "env"); WORMHOOK_DOCTOR_QUIET=1 mutes all soft items.
#
# Two jobs: (1) wormhook's own runtime deps (jq hard, ripgrep soft, version drift);
# (2) a nudge to install the install-time firewall layer wormhook deliberately does
# NOT do itself (Socket Firewall + safedep/vet) — registry intelligence, malicious-
# version blocking, typosquat/age scoring. wormhook is the local lock; those own the
# registry boundary. "Run alongside, not instead" — see README.
#
# KEY-DECISION 2026-06-06: deliberately jq-free. This is the watchdog for the
# case where wormhook.sh itself can't run (missing jq exits it on stderr only —
# invisible in the TUI, the same failure class as the "silent for a month" bug),
# so it may rely on nothing but bash. Hand-rolled JSON is safe here precisely
# because every output string is STATIC — nothing untrusted is interpolated
# (contrast wormhook.sh, which embeds scanned paths/commands and must route
# them through jq --arg to stay injection-proof). Do not add dynamic content
# to these messages without switching the emission to jq. Sole exception:
# the drift check below interpolates the two version strings AND the
# marketplace slug — all three pass a strict [0-9A-Za-z._+-] whitelist
# before interpolation; anything else drops the whole message.
set -uo pipefail

missing=""
note() { missing="${missing:+$missing\\n}  • $1"; }
# Per-item noise control: set WORMHOOK_SKIP_<ITEM>=1 — in repo .claude/settings.json or user
# ~/.claude/settings.json "env" — to silence a nudge you have consciously declined; or
# WORMHOOK_DOCTOR_QUIET=1 to mute every soft nudge below. The jq "scans are OFF" alarm is
# NEVER mutable — silencing it would reinstate the invisible-failure bug doctor exists to catch.
QUIET="${WORMHOOK_DOCTOR_QUIET:-}"
# soft <skip-var-value> <message>: record a silenceable nudge unless its skip var (or QUIET) is set.
soft() { [[ -n "$QUIET" || -n "$1" ]] && return 0; note "$2"; }

# jq: hard dependency — without it the scanner is OFF, not degraded. Not silenceable.
command -v jq &>/dev/null || \
  note "jq missing — scans are OFF (brew install jq)"

# ripgrep: soft dependency — content scans fall back to single-core grep
# (measured 30.3s vs 0.7s on a 58k-file node_modules).
command -v rg &>/dev/null || \
  soft "${WORMHOOK_SKIP_RG:-}" "ripgrep not found — content scans use slow grep fallback (brew install ripgrep) [silence: WORMHOOK_SKIP_RG=1]"

# Companion install-firewalls (NOT wormhook deps — the layer it cedes the registry
# boundary to). wormhook is local/no-network by design; these own malicious-version
# blocking, typosquats, and publish-age/reputation scoring at install time.
#   - Socket Firewall (sfw): wraps the package manager and blocks risky installs live.
#   - safedep/vet: dependency CVE + malicious-package + license scan.
# Static strings only (preserves the jq-free, no-dynamic-interpolation invariant above).
# NB: Socket Firewall had an untrusted-dir .sfw.config RCE (CVE-2025-64726, fixed 0.15.5);
# the nudge says "keep it current" rather than pin a version floor — a hard-coded floor
# goes stale, and a static "keep current" string preserves the no-interpolation invariant.
command -v sfw &>/dev/null || \
  soft "${WORMHOOK_SKIP_SFW:-}" "Socket Firewall (sfw) not found — install-time registry firewall missing; pair it with wormhook and keep it current (install: https://docs.socket.dev/docs/socket-firewall) [silence: WORMHOOK_SKIP_SFW=1]"
command -v vet &>/dev/null || \
  soft "${WORMHOOK_SKIP_VET:-}" "safedep/vet not found — no dependency CVE/malicious-package audit (install: https://github.com/safedep/vet) [silence: WORMHOOK_SKIP_VET=1]"

# Out-of-band coverage: which non-Claude triggers are wired (CLI on PATH / global git
# hook / hourly launchd sweep). Silent when all three are set up; otherwise one line
# showing the full ✓/✗ picture and pointing at the in-Claude installer. The ✓/✗ are
# fixed glyphs chosen by a conditional — no untrusted content is interpolated, so the
# jq-free / static-string invariant above still holds (the hooksPath VALUE is only used
# for a file test, never printed).
_cli=✗; command -v wormhook-scan &>/dev/null && _cli=✓
_hook=✗
_hd=$(git config --global --get core.hooksPath 2>/dev/null); _hd="${_hd/#\~/$HOME}"
[[ -n "$_hd" && -f "$_hd/post-merge" ]] && grep -q '>>> wormhook >>>' "$_hd/post-merge" 2>/dev/null && _hook=✓
if [[ "$(uname -s)" == "Darwin" ]]; then
  _sweep=✗; launchctl print "gui/$(id -u)/com.notambourine.wormhook-sweep" &>/dev/null && _sweep=✓
else
  _sweep="n/a"
fi
if [[ "$_cli" == "✗" || "$_hook" == "✗" || "$_sweep" == "✗" ]]; then
  soft "${WORMHOOK_SKIP_COVERAGE:-}" "out-of-band coverage — CLI:$_cli git-hook:$_hook hourly-sweep:$_sweep — run /wormhook-setup in Claude to finish [silence: WORMHOOK_SKIP_COVERAGE=1]"
fi

# Version drift: a `/plugin` marketplace refresh updates the clone but NOT the
# install pointer in installed_plugins.json, so the executing copy can lag the
# marketplace indefinitely (a stale pre-ripgrep install once spent 6 days
# timing out at 20s per session while the fix sat unused in the cache). The
# executing copy lives at plugins/cache/<marketplace>/<plugin>/<version>/;
# compare its manifest version against the marketplace clone's. No match on
# the cache layout (e.g. running from a dev checkout) => skip silently.
_ver() { sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -n1; }
PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$PLUGIN_ROOT" in
  */plugins/cache/*/*/*)
    mkt="${PLUGIN_ROOT#*/plugins/cache/}"; mkt="${mkt%%/*}"
    self_ver=$(_ver "$PLUGIN_ROOT/.claude-plugin/plugin.json")
    mkt_ver=$(_ver "${PLUGIN_ROOT%/cache/*}/marketplaces/$mkt/.claude-plugin/plugin.json")
    if [[ -n "$self_ver" && -n "$mkt_ver" && "$self_ver" != "$mkt_ver" && \
          "$self_ver$mkt_ver$mkt" != *[!0-9A-Za-z._+-]* ]]; then
      soft "${WORMHOOK_SKIP_DRIFT:-}" "running v$self_ver but marketplace has v$mkt_ver — run: claude plugin update wormhook@$mkt [silence: WORMHOOK_SKIP_DRIFT=1]"
    fi
    ;;
esac

# One 🟡, then each item on its own line (a checklist). Newlines are literal \n escapes in
# the hand-rolled JSON string — safe because every fragment is static (see header invariant).
[[ -z "$missing" ]] && exit 0
printf '{"systemMessage":"🟡 [wormhook] setup notes (each line silenceable — see [silence: …]):\\n%s"}\n' "$missing"
exit 0
