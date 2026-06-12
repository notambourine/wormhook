#!/bin/bash
# Environment doctor: SILENT when wormhook's runtime deps are healthy, one 🟡
# line when something is missing or degraded. Runs at SessionStart alongside the
# scanner.
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
note() { missing="${missing:+$missing; }$1"; }

# jq: hard dependency — without it the scanner is OFF, not degraded.
command -v jq &>/dev/null || \
  note "jq missing — scans are OFF (brew install jq)"

# ripgrep: soft dependency — content scans fall back to single-core grep
# (measured 30.3s vs 0.7s on a 58k-file node_modules).
command -v rg &>/dev/null || \
  note "ripgrep not found — content scans use slow grep fallback (brew install ripgrep)"

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
      note "running v$self_ver but marketplace has v$mkt_ver — run: claude plugin update wormhook@$mkt"
    fi
    ;;
esac

[[ -z "$missing" ]] && exit 0
printf '{"systemMessage":"🟡 [wormhook] %s"}\n' "$missing"
exit 0
