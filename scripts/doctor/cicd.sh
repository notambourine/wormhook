#!/bin/bash
# Workflow text cannot prove that a check is required by branch protection.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

repo=$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null) || exit 0

wf_dir="$repo/.github/workflows"
wf_files=$(find "$wf_dir" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null)
[[ -d "$wf_dir" && -n "$wf_files" ]] || exit 0

wh_re='uses:[[:space:]]*\.?/?notambourine/wormhook'
# A reusable workflow hides its jobs; absence of a direct action reference proves nothing.
reusable_re='uses:[[:space:]]*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[^[:space:]]+\.ya?ml@'
hit=""
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  if grep -qE "$wh_re|$reusable_re" "$f" 2>/dev/null; then hit="$f"; break; fi
done <<< "$wf_files"
[[ -n "$hit" ]] && exit 0

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
