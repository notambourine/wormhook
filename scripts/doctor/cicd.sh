#!/bin/bash
# SessionStart doctor — CI supply-chain gate coverage: does a workflow here `uses:` the
# published wormhook action? Only committed workflow TEXT is observable, so a hit proves the
# action is REFERENCED, never that it is enforced as a required check (GitHub API state, and
# wormhook makes no network calls). Relevance-gated to a repo that runs Actions AND ships an
# npm/PyPI manifest, so it cannot cry wolf on a repo with nothing to gate.
#   🟡 gate applicable but absent (silenceable).  ⚪ silenced.  Everything else silent.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

repo=$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null) || exit 0

# Gate 1: no Actions => not applicable (nudging a CI-less repo to adopt CI is overreach).
# find, not glob — portable, and it spans the .yml/.yaml split without nullglob.
wf_dir="$repo/.github/workflows"
wf_files=$(find "$wf_dir" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null)
[[ -d "$wf_dir" && -n "$wf_files" ]] || exit 0

# Match a `uses:` context, not a bare mention, so a doc reference cannot read as a wired gate.
# Loop, not xargs — filenames may have spaces.
hit=""
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  if grep -qE 'uses:[[:space:]]*\.?/?notambourine/wormhook' "$f" 2>/dev/null; then hit="$f"; break; fi
done <<< "$wf_files"
[[ -n "$hit" ]] && exit 0

# Gate 2: no npm/PyPI dep surface => nothing for the scanner to gate, so the nudge would be noise.
has_manifest=0
for m in package.json package-lock.json pnpm-lock.yaml yarn.lock pyproject.toml requirements.txt uv.lock; do
  [[ -f "$repo/$m" ]] && { has_manifest=1; break; }
done
[[ "$has_manifest" == 1 ]] || exit 0

if wh_silenced "${WORMHOOK_SKIP_CICD:-}"; then
  wh_flag ⚪ cicd "CI supply-chain gate not wired (silenced)"
  exit 0
fi
ctx="[cicd-coverage] This repo runs GitHub Actions and ships an npm/PyPI manifest but no workflow uses the wormhook action, so PRs are not scanned for supply-chain malware in CI. Suggest adding a job (uses: notambourine/wormhook@<version>) as a required status check, paired with a ruleset that blocks force pushes — see the wormhook README, 'Gate pull requests on GitHub'. Low priority — mention only if the user asks about CI / PR gating. This sees committed workflow TEXT only; it cannot confirm the check is enforced as required (that is GitHub API state)."
wh_flag 🟡 cicd "no wormhook CI gate — add the GitHub Action as a required PR check (see README) [silence: WORMHOOK_SKIP_CICD=1]" "$ctx"
exit 0
