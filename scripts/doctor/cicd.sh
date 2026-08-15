#!/bin/bash
# SessionStart doctor — CI supply-chain gate coverage. wormhook ships action.yml, so the same
# engine can run as a required PR status check (github.com has no pre-receive hook — the merge
# gate is the reachable equivalent; pair with a ruleset that blocks force pushes). This check
# reports whether THIS repo wires that gate.
#
# What is OBSERVABLE here is committed TEXT on disk: the workflow files under .github/workflows
# and whether any `uses:` the published action. A non-interactive SessionStart hook cannot see
# branch-protection / required-status-check config (that is GitHub API state, and wormhook makes
# no network calls) — so the 🟢 asserts the action is REFERENCED, not that it is enforced as a
# required check. The nudge is tightly RELEVANCE-GATED so it never cries wolf: it speaks only for
# a repo that already runs GitHub Actions AND ships an npm/PyPI manifest (a real dep surface to
# gate). Anything else is ⚪ n/a, not a 🟡.
#   silent a workflow `uses:` notambourine/wormhook, or n/a (not a repo / no workflows / no manifest).
#   🟡 GitHub Actions + an npm/PyPI manifest present, but no wormhook gate -> add it (silenceable).
#   ⚪ gate absent but silenced.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

# Resolve the repo root from the session CWD (like wormhook-scan's git-hook).
# Not a repo => n/a => silent (advisory check, no n/a line — doctor/CLAUDE.md).
repo=$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null) || exit 0

# Relevance gate 1: does this repo run GitHub Actions at all? No workflows => the gate is not
# applicable (nudging a repo with no CI to adopt CI is overreach). Find, not glob — portable, and
# it handles the .yml/.yaml split without nullglob.
wf_dir="$repo/.github/workflows"
wf_files=$(find "$wf_dir" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null)
[[ -d "$wf_dir" && -n "$wf_files" ]] || exit 0   # no workflows => n/a => silent

# Is the published action already wired? Require it in a `uses:` context (not a bare mention in a
# comment) so a doc reference cannot produce a false 🟢. Loop, not xargs — filenames may have spaces.
hit=""
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  if grep -qE 'uses:[[:space:]]*\.?/?notambourine/wormhook' "$f" 2>/dev/null; then hit="$f"; break; fi
done <<< "$wf_files"
[[ -n "$hit" ]] && exit 0   # gate wired => silent (no green line)

# Relevance gate 2: only nudge a repo with a real npm/PyPI dep surface — otherwise there is nothing
# for the scanner to gate in CI, and the nudge would be noise.
has_manifest=0
for m in package.json package-lock.json pnpm-lock.yaml yarn.lock pyproject.toml requirements.txt uv.lock; do
  [[ -f "$repo/$m" ]] && { has_manifest=1; break; }
done
[[ "$has_manifest" == 1 ]] || exit 0   # no dep surface => n/a => silent

# Gate is applicable but absent.
if wh_silenced "${WORMHOOK_SKIP_CICD:-}"; then
  wh_flag ⚪ cicd "CI supply-chain gate not wired (silenced)"
  exit 0
fi
ctx="[cicd-coverage] This repo runs GitHub Actions and ships an npm/PyPI manifest but no workflow uses the wormhook action, so PRs are not scanned for supply-chain malware in CI. Suggest adding a job (uses: notambourine/wormhook@<version>) as a required status check, paired with a ruleset that blocks force pushes — see the wormhook README, 'Gate pull requests on GitHub'. Low priority — mention only if the user asks about CI / PR gating. This sees committed workflow TEXT only; it cannot confirm the check is enforced as required (that is GitHub API state)."
wh_flag 🟡 cicd "no wormhook CI gate — add the GitHub Action as a required PR check (see README) [silence: WORMHOOK_SKIP_CICD=1]" "$ctx"
exit 0
