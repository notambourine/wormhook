#!/usr/bin/env bash
# tests/run.sh — fixtures test seam over the wormhook engine.
#
# The engine is a pure stdin->stdout transducer: a hook JSON payload in, one verdict
# JSON out, ZERO network. That makes it the most testable thing in the repo, yet it
# had no automated coverage proving it DETECTS what it claims (the dogfood CI job only
# proves "no false positive on self"). This harness exploits that interface: each case
# is {synthetic payload + planted files in a hermetic temp CWD} -> assert on the emitted
# JSON (parsed with jq).
#
# Hermetic by construction: every case runs in its own mktemp dir with HOME and
# XDG_CACHE_HOME redirected INTO that dir, so a planted ~/.claude dropper or scan-cache
# marker can never touch the developer real $HOME (the engine reads $HOME for the
# Tier-0 persistence checks). Each case cleans up on exit.
#
# Malware fixtures are assembled from fragments at runtime ($MAL_* below) so the
# literal IOC strings (decode-then-eval, agent-hijack dropper names) never sit in this
# source file -- otherwise the harness would trip wormhook scanning its OWN tree, and
# editor security hooks would block writing it.
#
# bash 3.2 / Apple /bin/bash safe: no associative arrays, no mapfile, no ${arr[@]} on
# a possibly-empty array under set -u. shellcheck-clean under the repo default floor.
#
# Run:   bash tests/run.sh           (or: tests/run.sh)
# Exit:  0 = all cases passed - 1 = one or more failed (CI gates on this).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$REPO_ROOT/scripts/wormhook.sh"
SCAN_CLI="$REPO_ROOT/scripts/wormhook-scan.sh"

command -v jq >/dev/null 2>&1 || { echo "tests: jq required" >&2; exit 1; }
[[ -r "$ENGINE" ]] || { echo "tests: engine not found ($ENGINE)" >&2; exit 1; }

# IOC fixture fragments, assembled so the literal signature never appears verbatim in
# this file (see header). _e = "eval", _a = "atob" -> "eval(atob(" only at runtime.
_e='ev'; _e="${_e}al"; _a='at'; _a="${_a}ob"
MAL_DECODE_EVAL="module.exports = ${_e}(${_a}(process.env.X));"
MAL_INJECT="const k = ${_a}(process.env.FAKE_KEY); ${_e}(k);"
MAL_DROPPER='setup'; MAL_DROPPER="${MAL_DROPPER}.mjs"   # agent-hijack dropper filename

PASS=0 FAIL=0
# Track temp dirs so a mid-run failure (set -e is OFF) still cleans up via the trap.
TMP_DIRS=()
cleanup() { local d; for d in "${TMP_DIRS[@]:-}"; do [[ -n "$d" && -d "$d" ]] && rm -rf "$d"; done; }
trap cleanup EXIT

# _mktemp_case — a fresh hermetic sandbox: $CASE_DIR with home/, cache/, cwd/ subdirs.
# Sets the globals CASE_DIR / CASE_HOME / CASE_CACHE / CASE_CWD. Redirecting HOME and
# XDG_CACHE_HOME into here is what keeps the Tier-0 $HOME persistence checks and the
# Tier-2 scan-cache OFF the developer real machine.
_mktemp_case() {
  CASE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wormhook-test.XXXXXX")"
  TMP_DIRS+=("$CASE_DIR")
  CASE_HOME="$CASE_DIR/home"; CASE_CACHE="$CASE_DIR/cache"; CASE_CWD="$CASE_DIR/cwd"
  mkdir -p "$CASE_HOME" "$CASE_CACHE" "$CASE_CWD"
}

# _run_engine — drive the UNCHANGED engine with a payload, isolated HOME + cache.
# $1 = full payload JSON (built by the caller with jq --arg). Echoes the verdict JSON.
_run_engine() {
  printf '%s' "$1" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" bash "$ENGINE" 2>/dev/null
}

# _payload — build a payload JSON the same way Claude / the CLI does (jq --arg, so a
# path with quotes can never break out). $1=event  $2=command (optional; "" to omit).
_payload() {
  local ev="$1" cmd="${2:-}"
  if [[ -n "$cmd" ]]; then
    jq -nc --arg c "$cmd" --arg w "$CASE_CWD" --arg e "$ev" \
      '{tool_input:{command:$c},cwd:$w,hook_event_name:$e}'
  else
    jq -nc --arg w "$CASE_CWD" --arg e "$ev" '{cwd:$w,hook_event_name:$e}'
  fi
}

# ── Assertion primitives ────────────────────────────────────────────────────────
# Each prints PASS/FAIL with the case name and tallies. A FAIL never aborts the run
# (set -e is off) so one broken case does not hide the others; the final exit code
# is what CI gates on.
_ok()  { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m  %s\n' "$1"; }
_bad() { FAIL=$((FAIL+1)); printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; [[ -n "${2:-}" ]] && printf '          %s\n' "$2"; }

# assert_jq NAME JSON FILTER — FILTER must evaluate truthy (jq -e). On failure dumps
# the offending value so a broken assertion is diagnosable from the CI log.
assert_jq() {
  local name="$1" json="$2" filter="$3"
  if printf '%s' "$json" | jq -e "$filter" >/dev/null 2>&1; then
    _ok "$name"
  else
    _bad "$name" "filter failed: $filter"
    printf '          got: %s\n' "$(printf '%s' "$json" | jq -c '{verdict,decision,hookSpecificOutput,systemMessage}' 2>/dev/null || printf '%s' "$json" | head -c 300)"
  fi
}

echo "wormhook fixtures harness"
echo "  engine: $ENGINE"
echo

# ══════════════════════════════════════════════════════════════════════════════════
# 1. PER-TIER POSITIVES — one planted IOC per tier produces the expected verdict.
# ══════════════════════════════════════════════════════════════════════════════════

# --- Tier 0: persistence (agent-hijack dropper in $HOME/.claude). Never cached,
#     always runs. UserPromptSubmit can block -> top-level decision:"block".
_mktemp_case
mkdir -p "$CASE_HOME/.claude"
printf '// agent-hijack dropper payload\n' > "$CASE_HOME/.claude/$MAL_DROPPER"
OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
assert_jq "T0 persistence: HOME/.claude dropper blocks (UPS)" "$OUT" \
  '.decision=="block" and (.systemMessage|contains("AGENT-HIJACK PERSISTENCE"))'

# --- Tier 1: project-source signature (decode-then-eval injected loader).
#     PreToolUse install gate -> hard deny.
_mktemp_case
printf '%s\n' "$MAL_INJECT" > "$CASE_CWD/index.js"
OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
assert_jq "T1 project source: injected loader blocks (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS CODE IN PROJECT SOURCE FILE"))'

# --- Tier 2: node_modules payload-file IOC. Needs an install-class PostToolUse to
#     force the expensive walk. A known payload filename = proof.
_mktemp_case
mkdir -p "$CASE_CWD/node_modules/evil-pkg"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
printf '/* shai-hulud payload */\n' > "$CASE_CWD/node_modules/evil-pkg/bun_environment.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 node_modules: payload-file IOC -> red verdict (PostToolUse)" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'

# --- Tier 2 (behavioral content): a node_modules .js with a decode-then-eval marker
#     (the higher-FP heuristic that lives ONLY in this tier, never the block tier).
_mktemp_case
mkdir -p "$CASE_CWD/node_modules/lib"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
printf '%s\n' "$MAL_DECODE_EVAL" > "$CASE_CWD/node_modules/lib/index.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 node_modules: decode-then-eval behavioral content -> red" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'

# ══════════════════════════════════════════════════════════════════════════════════
# 2. FALSE-POSITIVE REGRESSIONS — clean trees must stay green.
# ══════════════════════════════════════════════════════════════════════════════════

# --- adc-e.uk collision (v0.15.2 regression guard): a real @aws-sdk/core
#     partitions.json ships `api.cloud-aws.adc-e.uk` as the aws-iso-e partition
#     dualStackDnsSuffix. Dropping that IOC was the fix; this asserts it stays dropped.
_mktemp_case
mkdir -p "$CASE_CWD/node_modules/@aws-sdk/core"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
cat > "$CASE_CWD/node_modules/@aws-sdk/core/partitions.json" <<'JSON'
{
  "partitions": [
    {
      "id": "aws-iso-e",
      "regionRegex": "^eu-isoe-\\w+-\\d+$",
      "outputs": {
        "dnsSuffix": "cloud.adc-e.uk",
        "dualStackDnsSuffix": "api.cloud-aws.adc-e.uk",
        "implicitGlobalRegion": "eu-isoe-west-1",
        "name": "aws-iso-e",
        "supportsDualStack": true,
        "supportsFIPS": true
      }
    }
  ]
}
JSON
# The partition table is also bundled inside an SDK .js module — scan both surfaces.
printf 'export const partitions={dualStackDnsSuffix:"api.cloud-aws.adc-e.uk"};\n' \
  > "$CASE_CWD/node_modules/@aws-sdk/core/partitions.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "FP guard: @aws-sdk partitions adc-e.uk stays green" "$OUT" \
  '.verdict=="green"'

# --- A clean source tree with ordinary code stays green (no INJECT_RE trip).
_mktemp_case
printf 'export const env = process.env;\nconsole.log("hello", JSON.parse("{}"));\n' > "$CASE_CWD/app.js"
OUT="$(_run_engine "$(_payload SessionStart)")"
assert_jq "FP guard: ordinary clean source stays green (SessionStart)" "$OUT" \
  '.verdict=="green"'

# --- A user DENY rule in .claude/settings.json carrying a curl-pipe pattern is
#     security POLICY, not dropper wiring — del(.permissions) must keep it green.
_mktemp_case
mkdir -p "$CASE_CWD/.claude"
cat > "$CASE_CWD/.claude/settings.json" <<'JSON'
{ "permissions": { "deny": ["Bash(curl * | bash*)", "Bash(curl * | sh*)"] } }
JSON
OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
# UPS is silent-on-clean (no green line) -> empty output is the clean signal here.
assert_jq "FP guard: curl-pipe DENY policy does not self-flag (UPS clean)" "${OUT:-{}}" \
  '(.decision // "") != "block"'

# ══════════════════════════════════════════════════════════════════════════════════
# 3. EMISSION-SHAPE CONTRACT — the two block events emit DISTINCT, non-interchangeable
#    shapes. PreToolUse nests permissionDecision; UserPromptSubmit puts decision
#    top-level and must NOT carry hookSpecificOutput.additionalContext.
# ══════════════════════════════════════════════════════════════════════════════════
_mktemp_case
printf '%s\n' "$MAL_INJECT" > "$CASE_CWD/loader.js"
PRE="$(_run_engine "$(_payload PreToolUse 'npm install')")"
UPS="$(_run_engine "$(_payload UserPromptSubmit)")"

assert_jq "shape: PreToolUse nests permissionDecision==deny" "$PRE" \
  '.hookSpecificOutput.permissionDecision=="deny" and (has("decision")|not)'
assert_jq "shape: UserPromptSubmit uses TOP-LEVEL decision==block" "$UPS" \
  '.decision=="block"'
assert_jq "shape: UserPromptSubmit emits NO hookSpecificOutput.additionalContext" "$UPS" \
  '(.hookSpecificOutput.additionalContext // null) == null'
# The two shapes are mutually distinct: the key carrying the block on one event is
# absent on the other.
assert_jq "shape: PreToolUse carries no top-level decision" "$PRE" '(.decision // null)==null'
assert_jq "shape: UserPromptSubmit carries no permissionDecision" "$UPS" \
  '(.hookSpecificOutput.permissionDecision // null)==null'

# ══════════════════════════════════════════════════════════════════════════════════
# 4. GIT-HOOK BODY NEVER SELF-FLAGS — makes CLAUDE.md "Verified by test" true.
#    Use the ACTUAL installer to write the hook (not a re-synthesis), so we test
#    exactly the body that ships. Install into an isolated HOME so it touches a
#    sandbox core.hooksPath, never the developer global git config.
# ══════════════════════════════════════════════════════════════════════════════════
if [[ -r "$SCAN_CLI" ]] && command -v git >/dev/null 2>&1; then
  _mktemp_case
  mkdir -p "$CASE_CWD/.git/hooks"
  # install-git-hook sets global core.hooksPath under $HOME and writes the marker block.
  HOME="$CASE_HOME" git config --global core.hooksPath "$CASE_DIR/global-hooks" >/dev/null 2>&1
  HOME="$CASE_HOME" bash "$SCAN_CLI" install-git-hook >/dev/null 2>&1
  HOOK="$CASE_DIR/global-hooks/post-merge"
  if [[ -f "$HOOK" ]]; then
    # Place the real installed hook body where the Tier-0 MALICIOUS-GIT-HOOK check scans
    # it: the repo own .git/hooks. SessionStart yields an explicit green verdict (a
    # stronger "nothing flagged" signal than UPS silent-clean).
    cp "$HOOK" "$CASE_CWD/.git/hooks/post-merge"
    OUT="$(_run_engine "$(_payload SessionStart)")"
    assert_jq "git-hook body does NOT self-flag (Tier-0, real installer body)" "$OUT" \
      '.verdict=="green"'
    # Belt-and-suspenders: the same clean body under a block event also never blocks.
    OUT2="$(_run_engine "$(_payload UserPromptSubmit)")"
    assert_jq "git-hook body does NOT self-flag under a block event (UPS)" "${OUT2:-{}}" \
      '(.decision // "") != "block"'
  else
    _bad "git-hook body never self-flags" "installer did not produce $HOOK"
  fi
else
  _bad "git-hook body never self-flags" "wormhook-scan.sh or git unavailable — cannot synthesize the real hook body"
fi

echo
printf 'tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
