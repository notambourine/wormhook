#!/bin/bash
# Refreshing the marketplace does not update the installed plugin.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

_ver() { sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -n1; }
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

case "$PLUGIN_ROOT" in
  */plugins/cache/*/*/*)
    rel="${PLUGIN_ROOT#*/plugins/cache/}"
    mkt="${rel%%/*}"; plug="${rel#*/}"; plug="${plug%%/*}"
    self_ver=$(_ver "$PLUGIN_ROOT/.claude-plugin/plugin.json")

    # URL sources have no vendored copy; inspect sibling caches without network access.
    mkt_root="${PLUGIN_ROOT%/cache/*}/marketplaces/$mkt"
    src=$(jq -r --arg n "$plug" \
      '[.plugins[]? | select(.name==$n) | .source | strings | select(startswith("."))] | first // empty' \
      "$mkt_root/.claude-plugin/marketplace.json" 2>/dev/null)
    mkt_ver=""
    if [[ -n "$src" ]]; then
      mkt_ver=$(_ver "$mkt_root/${src#./}/.claude-plugin/plugin.json")
    else
      mkt_ver=$(printf '%s\n' "${PLUGIN_ROOT%/*}"/*/ | sed 's:.*/\([^/]*\)/$:\1:' | jq -Rrs \
        'split("\n") | map(select(test("^[0-9]+(\\.[0-9]+)*$")))
         | sort_by(split(".") | map(tonumber)) | last // empty' 2>/dev/null)
    fi

    # Compare numeric tuples: lexical ordering puts 0.9.0 above 0.26.0.
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
