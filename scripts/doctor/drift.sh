#!/bin/bash
# SessionStart doctor — version drift. A `/plugin` marketplace refresh updates the clone but NOT the
# install pointer in installed_plugins.json, so the executing copy can lag the marketplace
# indefinitely (a stale pre-ripgrep install once spent 6 days timing out at 20s/session while the fix
# sat unused in the cache). The executing copy lives at plugins/cache/<marketplace>/<plugin>/<version>/;
# compare its manifest version against the marketplace clone's.
#   🟢 up to date.  🟡 self lags marketplace -> claude plugin update (silenceable).
#   ⚪ not a marketplace cache layout (dev checkout), or silenced.
# Version strings flow through jq --arg at emit time, so no whitelist is needed.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

_ver() { sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -n1; }
PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$PLUGIN_ROOT" in
  */plugins/cache/*/*/*)
    mkt="${PLUGIN_ROOT#*/plugins/cache/}"; mkt="${mkt%%/*}"
    self_ver=$(_ver "$PLUGIN_ROOT/.claude-plugin/plugin.json")
    mkt_ver=$(_ver "${PLUGIN_ROOT%/cache/*}/marketplaces/$mkt/.claude-plugin/plugin.json")
    if [[ -n "$self_ver" && -n "$mkt_ver" && "$self_ver" != "$mkt_ver" ]]; then
      if wh_silenced "${WORMHOOK_SKIP_DRIFT:-}"; then
        wh_flag ⚪ drift "running v$self_ver, marketplace has v$mkt_ver (silenced)"
      else
        wh_flag 🟡 drift "running v$self_ver but marketplace has v$mkt_ver — run: claude plugin update wormhook@$mkt [silence: WORMHOOK_SKIP_DRIFT=1]"
      fi
    else
      wh_flag 🟢 drift "up to date (v${self_ver:-?})"
    fi
    ;;
  *)
    wh_flag ⚪ drift "n/a — not a marketplace install (dev checkout)"
    ;;
esac
exit 0
