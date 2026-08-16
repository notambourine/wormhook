#!/bin/bash
# SessionStart doctor — version drift. A `/plugin` marketplace refresh updates the clone but
# NOT the install pointer, so the executing copy can lag indefinitely (one stale pre-ripgrep
# install spent 6 days timing out at 20s/session while the fix sat unused in the cache).
#   🟡 self lags marketplace (silenceable).  ⚪ silenced.  Up-to-date / dev checkout => silent.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

_ver() { sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -n1; }
# The ../.. fallback covers a direct/test invocation, where CLAUDE_PLUGIN_ROOT is unset.
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

case "$PLUGIN_ROOT" in
  */plugins/cache/*/*/*)
    rel="${PLUGIN_ROOT#*/plugins/cache/}"
    mkt="${rel%%/*}"; plug="${rel#*/}"; plug="${plug%%/*}"
    self_ver=$(_ver "$PLUGIN_ROOT/.claude-plugin/plugin.json")

    # A path source vendors the plugin in the marketplace clone; a url source does not, leaving
    # a sibling cache dir as the only local evidence (resolving a url needs a network call).
    mkt_root="${PLUGIN_ROOT%/cache/*}/marketplaces/$mkt"
    src=$(jq -r --arg n "$plug" \
      '[.plugins[]? | select(.name==$n) | .source | strings | select(startswith("."))] | first // empty' \
      "$mkt_root/.claude-plugin/marketplace.json" 2>/dev/null)
    mkt_ver=""
    if [[ -n "$src" ]]; then
      mkt_ver=$(_ver "$mkt_root/${src#./}/.claude-plugin/plugin.json")
    else
      # Sort on the version tuple, so 0.9.0 does not outrank 0.26.0; drop non-numeric dirs.
      mkt_ver=$(printf '%s\n' "${PLUGIN_ROOT%/*}"/*/ | sed 's:.*/\([^/]*\)/$:\1:' | jq -Rrs \
        'split("\n") | map(select(test("^[0-9]+(\\.[0-9]+)*$")))
         | sort_by(split(".") | map(tonumber)) | last // empty' 2>/dev/null)
    fi

    # Tuple compare, never string: "0.9.0" > "0.26.0" lexically would invert the verdict.
    if [[ -n "$self_ver" && -n "$mkt_ver" && "$self_ver" != "$mkt_ver" ]] && jq -e -n \
        --arg a "$self_ver" --arg b "$mkt_ver" \
        '[$a,$b] | map(split(".") | map(tonumber? // -1)) | .[0] < .[1]' >/dev/null 2>&1; then
      if wh_silenced "${WORMHOOK_SKIP_DRIFT:-}"; then
        wh_flag ⚪ drift "running v$self_ver, marketplace has v$mkt_ver (silenced)"
      else
        wh_flag 🟡 drift "running v$self_ver but marketplace has v$mkt_ver — run: claude plugin update $plug@$mkt [silence: WORMHOOK_SKIP_DRIFT=1]"
      fi
    fi
    ;;
esac
exit 0
