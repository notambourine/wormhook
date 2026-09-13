#!/bin/bash
# CISA: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem

# Datadog: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/

# Microsoft: https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/

# Wiz (Mini): https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised

# Semgrep: https://semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/

# Socket: https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning

# Socket (Jun 2026): https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious

# Snyk (AntV, May 2026): https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/

# Unit42 (TeamPCP/npm landscape): https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/

# Mend (SAP-CAP via Claude Code): https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/

# Microsoft (AsyncAPI/Miasma, Jul 2026): https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/

# Elastic (ChainDrop, Aug 2026): https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain

# Microsoft (ChainDrop, Aug 2026): https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/

# JFrog (ChainDrop, Aug 2026): https://research.jfrog.com/post/shai-hulud-is-back-august/

# Phoenix Security: https://phoenix.security/trapdoor-supply-chain-ai-poisoning-npm-pypi-crates/

# Checkmarx: https://checkmarx.com/zero-post/npm-hit-by-shai-hulud-the-self-replicating-supply-chain-attack/

# StepSecurity: https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack

# Unit42 (ChainDrop): https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/

# A9-0522 markers are field-observed; no vendor advisory is available.

set -uo pipefail

command -v jq &>/dev/null || { echo "Error: jq required" >&2; exit 1; }

# Bash 3.2 and BSD date lack a subsecond clock.
WH_T0=$(jq -n now 2>/dev/null) || WH_T0=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MALWARE_PATTERNS="$SCRIPT_DIR/malware-patterns.sh"
# shellcheck source=/dev/null
[[ -r "$MALWARE_PATTERNS" ]] && source "$MALWARE_PATTERNS"
if [[ -z "${MALWARE_INJECT_RE:-}" || -z "${MALWARE_CONTENT_RE:-}" ]]; then
  # Missing signatures are an install fault; report degraded coverage without blocking.
  echo "wormhook: signatures unavailable ($MALWARE_PATTERNS) — skipping scan" >&2
  jq -nc --arg msg "🟡 [wormhook] signatures unavailable ($MALWARE_PATTERNS) — scan SKIPPED. Reinstall the plugin." '{systemMessage: $msg}'
  exit 0
fi

PAYLOAD=$(cat)
COMMAND=$(echo "$PAYLOAD" | jq -r '.tool_input.command // ""')
CWD=$(echo "$PAYLOAD" | jq -r '.cwd // ""')
EVENT=$(echo "$PAYLOAD" | jq -r '.hook_event_name // ""')
# Older hook configs omit the event name.
[[ -z "$EVENT" ]] && { [[ -n "$COMMAND" ]] && EVENT="PreToolUse" || EVENT="SessionStart"; }

NODE_MODULES="${CWD}/node_modules"

# Keep hooks.json filters broader than these regexes or valid commands will skip scanning.
GATE_RE='^\s*(npm (ci|install|i|add|run|test|exec)|pnpm (install|i|add|run|exec|dlx)|yarn( (install|add|run))?|bun (install|add|i|run|x)|npx|node)(\s|$)'
INSTALL_RE='^\s*(npm (ci|install|i|add)|pnpm (install|i|add)|yarn( (install|add))?|bun (install|add|i))(\s|$)'
# Scan after git writes the new files.
GIT_RE='^\s*git\s+(-C\s+\S+\s+)?(pull|merge|checkout|switch|rebase)(\s|$)'
# Python loads .pth files before user code, so scan before starting the interpreter.
PYGATE_RE='^\s*(pip|pip3|pipx|uv|python|python3)(\s|$)'
PYINSTALL_RE='^\s*((pip|pip3|pipx)\s+install|uv\s+(add|sync|(pip\s+install)))(\s|$)'

# Splitting quoted separators may add scans; blocking still requires a finding.
WH_SUBCMDS=""
[[ -n "$COMMAND" ]] && WH_SUBCMDS=$(printf '%s\n' "$COMMAND" \
  | awk '{ gsub(/[;&|]+/, "\n"); print }' \
  | sed -E 's/^[[:space:]]*((env|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*)[[:space:]]+)*//')
WH_DIROPT_STRIP='s/[[:space:]](--prefix|--cwd|--dir|-C)[= ][^[:space:]]+//g'
WH_SUBCMDS_N=""
[[ -n "$WH_SUBCMDS" ]] && WH_SUBCMDS_N=$(printf '%s\n' "$WH_SUBCMDS" | sed -E "$WH_DIROPT_STRIP")
_cmd_class() {  # 0 => some subcommand matches the class regex in $1
  [[ -n "$WH_SUBCMDS_N" ]] && printf '%s\n' "$WH_SUBCMDS_N" | grep -qE "$1"
}

TARGET_DIRS=("$CWD")
_add_target() { local d; for d in "${TARGET_DIRS[@]}"; do [[ "$d" == "$1" ]] && return 0; done; TARGET_DIRS+=("$1"); }
_resolve_dir() {  # $1 = path token  $2 = base dir -> absolute path (not canonicalized)
  # shellcheck disable=SC2088  # the "~"* arms match a LITERAL tilde, expanded here on purpose
  case "$1" in
    /*)        printf '%s' "$1" ;;
    "~"|"~/"*) printf '%s%s' "$HOME" "${1#\~}" ;;
    *)         printf '%s/%s' "$2" "$1" ;;
  esac
}
if [[ -n "$WH_SUBCMDS" ]]; then
  _vcwd="$CWD"
  while IFS= read -r _seg; do
    [[ -z "$_seg" ]] && continue
    case "$_seg" in
      cd)     _vcwd="$HOME"; continue ;;
      cd\ *)
        _d="${_seg#cd }"; _d="${_d#"${_d%%[![:space:]]*}"}"
        _d="${_d%%[[:space:]]*}"
        _d="${_d#[\"\']}"; _d="${_d%[\"\']}"
        [[ -n "$_d" && "$_d" != "-" ]] && _vcwd=$(_resolve_dir "$_d" "$_vcwd")
        continue ;;
    esac
    printf '%s\n' "$_seg" | sed -E "$WH_DIROPT_STRIP" | grep -qE "$GATE_RE|$GIT_RE|$PYGATE_RE" || continue
    _t="$_vcwd"
    _d=$(printf '%s\n' "$_seg" | sed -nE 's/.*[[:space:]](--prefix|--cwd|--dir|-C)[= ]([^[:space:]]+).*/\2/p' | head -n1)
    [[ -n "$_d" ]] && _t=$(_resolve_dir "$_d" "$_vcwd")
    [[ -d "$_t" ]] && _add_target "$_t"
  done <<<"$WH_SUBCMDS"
fi

# Include ignored, hidden, and NUL-padded files so payloads cannot evade content scans.
RG_BIN=$(command -v rg || true)
_rg_ok() {  # 0 => rg compiles this pattern; a grep-only signature falls back, never mis-parses
  [[ -n "$RG_BIN" ]] || return 1
  printf '' | "$RG_BIN" -q -e "$1" 2>/dev/null
  [[ $? -ne 2 ]]
}

# Directory mtimes miss in-place overwrites; the TTL bounds this cache gap.
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/notambourine/malware-scan"
MARKER="$CACHE_DIR/$(printf '%s' "$CWD" | shasum -a 256 | awk '{print $1}')"
_tree_mtime() {
  # Changes inside .cache and .vite remain invisible to the cache until its TTL expires.
  local statv=(stat -c %Y)
  stat -f %m "$NODE_MODULES" &>/dev/null && statv=(stat -f %m)
  local m
  m=$(timeout 5 find "$NODE_MODULES" -maxdepth 2 \( -name .cache -o -name .vite \) -prune -o -type d -exec "${statv[@]}" {} + 2>/dev/null | sort -rn | sed -n '1p') || return 1
  printf '%s' "${m:-0}"
}
_scan_key() {
  local c m sig=none
  for c in package-lock.json pnpm-lock.yaml yarn.lock bun.lock; do
    [[ -f "$CWD/$c" ]] && { sig=$(shasum -a 256 "$CWD/$c" | awk '{print $1}'); break; }
  done
  m=$(_tree_mtime) || return 1
  printf '%s:%s' "$sig" "$m"
}
deps_changed() {
  [[ -d "$NODE_MODULES" ]] || return 1
  [[ -f "$MARKER" ]] || return 0
  local ttl="${WORMHOOK_T2_TTL_HOURS:-24}"
  [[ "$ttl" =~ ^[0-9]+$ && "$ttl" -ge 1 ]] || ttl=24
  [[ -n "$(find "$MARKER" -mmin +"$((ttl * 60))" 2>/dev/null)" ]] && return 0
  local saved current; read -r saved < "$MARKER"
  current=$(_scan_key) || return 0
  [[ "$saved" == "$current" ]] && return 1 || return 0
}

MODE=session_start
RUN_T1=0 RUN_T2=0 UPDATE_CACHE=0
case "$EVENT" in
  PreToolUse)
    MODE=pre_tool
    if _cmd_class "$GATE_RE"; then
      RUN_T1=1
      # An install has not written its dependencies yet; PostToolUse scans the result.
      _cmd_class "$INSTALL_RE" || { deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }; }
    elif _cmd_class "$PYGATE_RE"; then
      RUN_T1=1
    else
      exit 0
    fi
    ;;
  PostToolUse)
    MODE=post_tool
    if _cmd_class "$INSTALL_RE"; then
      RUN_T1=1; RUN_T2=1; UPDATE_CACHE=1
    elif _cmd_class "$GIT_RE"; then
      RUN_T1=1
      deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }
    elif _cmd_class "$PYINSTALL_RE"; then
      RUN_T1=1
    else
      exit 0
    fi
    ;;
  UserPromptSubmit)
    MODE=prompt_submit; RUN_T1=1; RUN_T2=0
    ;;
  *)
    MODE=session_start; RUN_T1=1
    deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }
    ;;
esac



# Use permissionDecision: exit 2 sends the reason only to the model.
ALERTS="" SUMMARY=""

# CLI adapters consume structured findings; do not parse display text.
FINDINGS=""

WARNINGS=""
warn() { WARNINGS="${WARNINGS:+$WARNINGS; }$1"; }

WORMHOOK_QUARANTINE="${WORMHOOK_QUARANTINE:-}"
QUARANTINE_LOG="$CACHE_DIR/quarantine.log"
WH_QUAR_NOTE=""
_quarantine() {  # $1 = exact-match artifact path -> WH_QUAR_NOTE (one line for the alert body)
  WH_QUAR_NOTE=""
  [[ "$WORMHOOK_QUARANTINE" == 1 ]] || return 0
  if [[ -L "$1" ]]; then
    WH_QUAR_NOTE="QUARANTINE SKIPPED: symbolic link at $1; inspect its target manually."
    return 0
  fi
  local dest
  dest="$1.wormhook-quarantined.$(date +%s)"
  if [[ ! -e "$dest" && ! -L "$dest" ]] && mv -n "$1" "$dest" 2>/dev/null && [[ ! -e "$1" ]]; then
    if chmod 000 "$dest" 2>/dev/null; then
      WH_QUAR_NOTE="QUARANTINED (reversible): renamed to $dest with permissions 000. Running processes are unaffected."
    else
      WH_QUAR_NOTE="QUARANTINE INCOMPLETE: renamed to $dest but chmod failed; inspect permissions manually."
    fi
    mkdir -p "$CACHE_DIR" 2>/dev/null && printf '%s\t%s\t%s\n' \
      "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" "$dest" >> "$QUARANTINE_LOG" 2>/dev/null
  else
    WH_QUAR_NOTE="QUARANTINE FAILED (permissions? root-owned?): artifact is still live — run the steps below manually."
  fi
}
alert() {
  local block
  block=$(cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨  $1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
)
  ALERTS="${ALERTS}${block}"$'\n'
  SUMMARY="${SUMMARY}• ${1}"$'\n'
  FINDINGS="${FINDINGS}$(jq -nc --arg t "$1" --arg b "$2" '{title:$t,body:$b}')"$'\n'
  if [[ "$MODE" == "pre_tool" ]]; then
    jq -n --arg title "$1" --arg body "$2" '{
      systemMessage: ("🚨 wormhook BLOCKED this command — supply-chain IOC detected:\n" + $title + "\n\n" + $body),
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: ("[wormhook] Blocked install/run: " + $title + ". State this block to the user plainly and do NOT attempt to work around it or re-run the command until the user confirms the machine is clean.\n" + $body)
      }
    }'
    exit 0
  elif [[ "$MODE" == "prompt_submit" ]]; then
    # UserPromptSubmit forbids combining decision with additionalContext.
    jq -n --arg title "$1" --arg body "$2" '{
      decision: "block",
      reason: ("[wormhook] Blocked this turn: " + $title + ". State this block to the user plainly and do NOT proceed or work around it until the user confirms the machine is clean.\n" + $body),
      systemMessage: ("🚨 wormhook BLOCKED this turn — supply-chain IOC detected:\n" + $title + "\n\n" + $body)
    }'
    exit 0
  fi
}
_in_list() { local n="$1"; shift; local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }



# Bash 3.2 can misparse apostrophes inside a heredoc nested in command substitution.
persistence_check() {  # $1=title  $2=lead  $3=numbered-steps
  alert "$1" "$(cat <<BODY
$2
${WH_QUAR_NOTE:+$WH_QUAR_NOTE}
${COMMAND:+Command blocked: $COMMAND}

Immediate steps:
$3
BODY
)"
}

WH_PERSIST_HIT=""
_persist_scan() {
  local _i _op _candidates _c _raw _target
  for _i in "$@"; do
    _op="${WORMHOOK_PERSIST_TEST[$_i]}"
    _candidates="${WORMHOOK_PERSIST_PATHS[$_i]}"
    WH_PERSIST_HIT=""
    # shellcheck disable=SC2086  # intentional split on spaces into candidate paths
    for _raw in $_candidates; do
      for _target in "${TARGET_DIRS[@]}"; do
        _c="${_raw//__HOME__/$HOME}"
        _c="${_c//__CWD__/$_target}"
        if [[ "$_op" == "-f" && -f "$_c" ]] || [[ "$_op" == "-d" && -d "$_c" ]] || [[ "$_op" == "-e" && -e "$_c" ]]; then
          WH_PERSIST_HIT="$_c"; break 2
        fi
      done
    done
    [[ -z "$WH_PERSIST_HIT" ]] && continue
    # A group with several artifacts quarantines one per scan.
    _quarantine "$WH_PERSIST_HIT"
    case "${WORMHOOK_PERSIST_KEYS[$_i]}" in
      axios_rat)
        persistence_check "AXIOS RAT PERSISTENCE DETECTED" \
          "Found Axios/plain-crypto-js RAT binary at: /Library/Caches/com.apple.act.mond
This file masquerades as an Apple daemon but is a DPRK (Sapphire Sleet) RAT." \
          "  1. Kill: sudo pkill -f com.apple.act.mond
  2. Remove: sudo rm -f /Library/Caches/com.apple.act.mond
  3. Rotate ALL credentials (GitHub, npm, Cloudflare, SSH keys)
  4. Check: ps aux | grep -E 'act\.mond|sfrclak' (other persistence)
  5. Report: support@npmjs.com"
        ;;
      shai_hulud_2)
        persistence_check "SHAI-HULUD 2.0 PERSISTENCE DETECTED" \
          "Found Shai-Hulud 2.0 runner install at: $HOME/.dev-env
This directory contains a malicious GitHub Actions runner used for credential exfil." \
          "  1. Remove: command rm -rf \"$HOME/.dev-env\"
  2. Rotate ALL credentials (GitHub, npm, cloud providers)
  3. Check GitHub for repos matching [0-9a-z]{18} with stolen creds
  4. Check: ps aux | grep actions-runner"
        ;;
      agent_hijack)
        persistence_check "AGENT-HIJACK PERSISTENCE DETECTED" \
          "Found Mini Shai-Hulud agent-hijack dropper: $WH_PERSIST_HIT
This installs into an AI-agent/editor config dir and wires a SessionStart hook so
the credential-stealer re-runs on every Claude Code / VS Code launch." \
          "  1. Remove: command rm -f \"$WH_PERSIST_HIT\"
  2. Inspect SessionStart/PreToolUse hooks in .claude/settings.json (project AND
     ~/.claude/settings.json) for entries you did not add — the dropper injects one
  3. If ~/.claude/ is hit and you sync that dir across machines: STOP — do not
     sync (it would propagate). Clean the synced source first, then re-sync.
  4. Rotate: npm tokens, GitHub PATs/OIDC trusts, SSH keys, cloud creds
  5. git log --all --since=\"2026-04-01\" for unexpected commits / impersonation"
        ;;
      gh_token_monitor)
        persistence_check "GH-TOKEN-MONITOR PERSISTENCE DETECTED" \
          "Found Shai-Hulud token-monitor persistence unit: $WH_PERSIST_HIT
This re-launches a GitHub-token harvester on login." \
          "  1. Unload: launchctl unload \"$WH_PERSIST_HIT\" 2>/dev/null; command rm -f \"$WH_PERSIST_HIT\"
     (Linux: systemctl --user disable --now gh-token-monitor; rm \"$WH_PERSIST_HIT\")
  2. Rotate ALL GitHub PATs/OIDC trusts and npm tokens
  3. Check: ps aux | grep -i gh-token"
        ;;
      kitty_monitor)
        persistence_check "KITTY-MONITOR PERSISTENCE DETECTED" \
          "Found AntV/TeamPCP-wave persistence artifact: $WH_PERSIST_HIT
This installs a background daemon (~/.local/share/kitty/cat.py) that polls the GitHub
commit-search API hourly for attacker commands — its presence means the payload has
ALREADY run on this machine." \
          "  1. Unload: launchctl unload \"\$HOME/Library/LaunchAgents/com.user.kitty-monitor.plist\" 2>/dev/null
     (Linux: systemctl --user disable --now kitty-monitor)
  2. Remove: command rm -f \"\$HOME/Library/LaunchAgents/com.user.kitty-monitor.plist\" \\
       \"\$HOME/.config/systemd/user/kitty-monitor.service\" \"\$HOME/.local/share/kitty/cat.py\"
  3. Check: ps aux | grep -iE 'kitty.*cat\.py|cat\.py' (kill any running daemon)
  4. Rotate ALL GitHub PATs/OIDC trusts, npm tokens, SSH keys, cloud + LLM API keys
  5. git log --all --since=\"2026-04-01\" for unexpected commits / impersonation"
        ;;
      hades_ssh)
        persistence_check "HADES SSH-PROPAGATION DROPPER DETECTED" \
          "Found Hades/Miasma SSH-propagation dropper at: /tmp/.sshu-setup.js
This is written by the Bun-staged JS stealer to spread over SSH to other hosts —
its presence means the payload has ALREADY run on this machine." \
          "  1. Remove: command rm -f /tmp/.sshu-setup.js
  2. Check: ps aux | grep -iE 'bun|_index\.js' (kill any running stager)
  3. Audit ~/.ssh/known_hosts + authorized_keys and recent SSH egress for spread
  4. Rotate ALL credentials (SSH keys, GitHub PATs/OIDC, npm/PyPI tokens, cloud)
  5. Inspect site-packages *.pth startup hooks (the PyPI delivery vector)"
        ;;
      miasma_rat)
        # The space-delimited table cannot represent the macOS Application Support path.
        persistence_check "MIASMA RAT PERSISTENCE DETECTED" \
          "Found Miasma RAT persistence artifact: $WH_PERSIST_HIT
The AsyncAPI compromise (miasma-train-p1) runs at module IMPORT (no lifecycle script)
and persists as NodeJS/sync.js plus a miasma-monitor login unit; a .miasma directory
means the payload has ALREADY run on this machine." \
          "  1. Remove: command rm -rf \"\$HOME/.config/.miasma\" and every NodeJS/sync.js copy
     (also check \"\$HOME/Library/Application Support/NodeJS/sync.js\" on macOS)
  2. Linux: systemctl --user disable --now miasma-monitor 2>/dev/null; command rm -f \"\$HOME/.config/systemd/user/miasma-monitor.service\"
  3. Check: ps aux | grep -iE 'sync\.js|miasma' (kill any running RAT)
  4. Rotate ALL credentials (npm/GitHub tokens, SSH keys, cloud + k8s creds)
  5. Audit installed @asyncapi/* versions against the Microsoft advisory list"
        ;;
    esac
  done
}

_persist_scan 0 1 2   # axios_rat, shai_hulud_2, agent_hijack

# Config entries can survive deletion of the dropper that wrote them.
cfg_list=(
  "${HOME}/.claude/settings.json" "${HOME}/.cursor/mcp.json"
  "${HOME}/.continue/config.json" "${HOME}/.windsurf/mcp.json"
)
for _t in "${TARGET_DIRS[@]}"; do
  cfg_list+=( "$_t/.claude/settings.json" "$_t/.cursor/mcp.json"
              "$_t/.vscode/mcp.json"      "$_t/.vscode/tasks.json" )
done
for cfg in "${cfg_list[@]}"; do
  [[ -f "$cfg" ]] || continue
  # Permission rules can mention remote execution without executing it.
  cfg_hit=$(jq -r 'del(.permissions) | [.. | strings] | .[]' "$cfg" 2>/dev/null \
    | grep -iE "$MALWARE_DROPPER_TOKENS_RE|$MALWARE_REMOTE_EXEC_RE" | head -1)
  [[ -z "$cfg_hit" ]] && continue
  alert "INJECTED AGENT CONFIG DETECTED" "$(cat <<BODY
A value in $cfg references a known agent-hijack dropper, or pipes a remote script to a shell:
  $cfg_hit
This is how Mini Shai-Hulud / SANDWORM_MODE re-runs its payload on every Claude Code,
Cursor, VS Code, Continue, or Windsurf launch — as a SessionStart hook or a rogue
MCP server (even after deleting the dropper file), or as an inline curl-to-shell hook
command with no dropper file at all.
${COMMAND:+Command blocked: $COMMAND}

Immediate steps:
  1. Open $cfg and remove the hooks/mcpServers entry referencing the string above
     (you did not add it)
  2. If this is under \$HOME and you sync that dir: STOP — do not sync (would
     propagate). Clean the synced source first, then re-sync.
  3. Rotate: npm tokens, GitHub PATs/OIDC trusts, SSH keys, cloud + LLM API keys
  4. git log --all --since="2026-04-01" for unexpected commits / impersonation
BODY
)"
done


# Prose may document dropper tokens; only check its hidden Unicode.
zw_list=( "${cfg_list[@]}" "${HOME}/.claude/CLAUDE.md" "${HOME}/AGENTS.md" "${HOME}/.cursorrules" )
for _t in "${TARGET_DIRS[@]}"; do
  zw_list+=( "$_t/CLAUDE.md" "$_t/.claude/CLAUDE.md" "$_t/AGENTS.md" "$_t/.cursorrules" )
done
zw_files=()
for zwf in "${zw_list[@]}"; do [[ -f "$zwf" ]] && zw_files+=( "$zwf" ); done
if [[ ${#zw_files[@]} -gt 0 ]]; then
  zw_file=$(LC_ALL=C grep -laE "$MALWARE_ZEROWIDTH_RE" "${zw_files[@]}" 2>/dev/null | head -1)
  if [[ -n "$zw_file" ]]; then
    zw_line=$(LC_ALL=C grep -naE "$MALWARE_ZEROWIDTH_RE" "$zw_file" 2>/dev/null | head -1 | cut -d: -f1)
    alert "HIDDEN UNICODE IN AGENT CONFIG" "$(cat <<BODY
$zw_file carries a zero-width Unicode character at line ${zw_line:-?}.
${COMMAND:+Command blocked: $COMMAND}
Nothing legitimate writes one into an agent config. TrapDoor (May 2026) planted
CLAUDE.md and .cursorrules holding instructions built from U+200B/200C/200D/2060/FEFF:
your agent tokenizes every one of them, and your editor shows you none of them.
An emoji ZWJ sequence, a leading byte-order mark, and Persian/Urdu/Hindi U+200C
orthography are all exempted, so this is not one of those.

Immediate steps:
  1. Reveal them: LC_ALL=C grep -naE \$'\\xe2\\x80\\x8b|\\xe2\\x80\\x8c|\\xe2\\x80\\x8d|\\xe2\\x81\\xa0|\\xef\\xbb\\xbf' "$zw_file"
  2. git log -p -- "$zw_file"  (find the commit that added the line)
  3. Delete the hidden text, or the whole file if you did not author it
  4. Assume the agent already followed it: rotate npm/GitHub tokens, SSH keys,
     cloud + LLM API keys, and check ~/.ssh/authorized_keys and crontab -l
BODY
)"
  fi
fi

# Worktrees store .git as a file; ask git for the hooks directory.
git_hook_dirs=()
for _t in "${TARGET_DIRS[@]}"; do
  repo_hooks=$(git -C "$_t" rev-parse --git-path hooks 2>/dev/null) || repo_hooks=""
  [[ -n "$repo_hooks" ]] || repo_hooks="$_t/.git/hooks"
  [[ "$repo_hooks" == /* ]] || repo_hooks="$_t/$repo_hooks"
  git_hook_dirs+=("$repo_hooks")
done
tmpl_dir=$(git config --global --get init.templateDir 2>/dev/null) && [[ -n "$tmpl_dir" ]] && git_hook_dirs+=("${tmpl_dir/#\~/$HOME}/hooks")
for hd in "${git_hook_dirs[@]}"; do
  for h in pre-commit pre-push post-checkout post-merge; do
    [[ -f "$hd/$h" ]] || continue
    gh_hit=$(grep -iE "$MALWARE_DROPPER_TOKENS_RE|$MALWARE_REMOTE_EXEC_RE" "$hd/$h" 2>/dev/null | head -1)
    [[ -z "$gh_hit" ]] && continue
    alert "MALICIOUS GIT HOOK DETECTED" "$(cat <<BODY
A git hook runs a known dropper / pipes a remote script to a shell:
  $hd/$h
  $gh_hit
${COMMAND:+Command blocked: $COMMAND}
SANDWORM_MODE installs pre-commit/pre-push hooks (directly, or globally via
init.templateDir, or per-repo via core.hooksPath) to add a carrier dependency and
exfiltrate tokens on every commit/push.

Immediate steps:
  1. Inspect and remove the offending hook: $hd/$h
  2. Audit global template: git config --global --get init.templateDir
     and per-repo: git config --get core.hooksPath  (unset if you did not add it)
  3. Rotate: GitHub PATs/OIDC trusts, npm tokens, SSH keys
BODY
)"
  done
done

_persist_scan 3 4   # gh_token_monitor, kitty_monitor
_persist_scan 5     # hades_ssh
_persist_scan 6     # miasma_rat


# Do not run Python to discover roots: that would execute the startup hooks being scanned.
py_roots=()
for _t in "${TARGET_DIRS[@]}"; do
  for _u in "$_t/.venv" "$_t/venv" "$_t/env" "$_t/.tox"; do
    [[ -d "$_u" ]] && py_roots+=("$_u")
  done
done
case "${VIRTUAL_ENV:-}" in
  ""|"${CWD}/.venv"|"${CWD}/venv"|"${CWD}/env"|"${CWD}/.tox") : ;;
  *) [[ -d "$VIRTUAL_ENV" ]] && py_roots+=("$VIRTUAL_ENV") ;;
esac
[[ -n "${CONDA_PREFIX:-}" && -d "${CONDA_PREFIX:-}" ]] && py_roots+=("$CONDA_PREFIX")
# Exclude /usr/lib: it is managed by the OS package manager.
for _u in "$HOME"/.local/lib/python*/site-packages \
          "$HOME"/Library/Python/*/lib/python/site-packages \
          /opt/homebrew/lib/python*/site-packages \
          /usr/local/lib/python*/site-packages \
          /usr/local/lib/python*/dist-packages \
          /Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages \
          "$HOME"/.pyenv/versions/*/lib/python*/site-packages \
          "$HOME"/.local/share/uv/python/*/lib/python*/site-packages; do
  [[ -d "$_u" ]] && py_roots+=("$_u")
done
pth_files=()
if [[ ${#py_roots[@]} -gt 0 ]]; then
  py_paths=$(timeout 5 find "${py_roots[@]}" -maxdepth 5 -name '*.pth' -type f 2>/dev/null)
  [[ $? -eq 0 ]] || warn "Python .pth scan failed or timed out (coverage incomplete)"
  while IFS= read -r _p; do [[ -n "$_p" ]] && pth_files+=("$_p"); done <<<"$py_paths"
fi
for _t in "${TARGET_DIRS[@]}"; do
  for _p in "$_t"/*.pth; do [[ -f "$_p" ]] && pth_files+=("$_p"); done
done
if [[ ${#pth_files[@]} -gt 0 ]]; then
  for pth in "${pth_files[@]}"; do
    pth_reason="" pth_base="${pth##*/}" pth_exact=0 WH_QUAR_NOTE=""
    if [[ "$pth_base" == "$MALWARE_PTH_IOC_NAME" ]]; then
      pth_reason="known-bad filename ($MALWARE_PTH_IOC_NAME)"; pth_exact=1
    elif [[ "$(shasum -a 256 "$pth" 2>/dev/null | awk '{print $1}')" == "$MALWARE_PTH_IOC_HASH" ]]; then
      pth_reason="known-bad SHA256 ($MALWARE_PTH_IOC_HASH)"; pth_exact=1
    else
      pth_m=$(grep -niE "$MALWARE_PTH_RE" "$pth" 2>/dev/null | head -1)
      [[ -n "$pth_m" ]] && pth_reason="executes code on interpreter start: $pth_m"
    fi
    [[ -z "$pth_reason" ]] && continue
    [[ "$pth_exact" == 1 ]] && _quarantine "$pth"
    alert "MALICIOUS PYTHON .pth STARTUP HOOK DETECTED" "$(cat <<BODY
A Python .pth startup hook runs code on every interpreter start:
  $pth
  $pth_reason
${WH_QUAR_NOTE:+$WH_QUAR_NOTE}
${COMMAND:+Command blocked: $COMMAND}
The Hades/Miasma PyPI wave (MCP typosquats: openai-mcp, langchain-core-mcp,
tiktoken-mcp, ...) drops a *.pth into site-packages that downloads Bun and runs a
bundled _index.js credential stealer — auto-executed by Python with no install step.

Immediate steps:
  1. Remove the .pth: command rm -f "$pth"
  2. Uninstall the carrier package and purge its site-packages dir
  3. Check: ls -la /tmp/.sshu-setup.js ; ps aux | grep -iE 'bun|_index\.js'
  4. pip/uv list — audit for typosquats (openai-mcp, langchain-core-mcp, mem8, …)
  5. Rotate ALL credentials (PyPI/npm tokens, GitHub PATs/OIDC, SSH keys, cloud, LLM API keys)
  6. Reinstall Python deps from a clean, pinned, hash-verified lockfile
BODY
)"
  done
fi

so_files=()
if [[ ${#py_roots[@]} -gt 0 ]]; then
  py_paths=$(timeout 5 find "${py_roots[@]}" -maxdepth 5 -name '*.abi3.so' -type f 2>/dev/null)
  [[ $? -eq 0 ]] || warn "Python native-module scan failed or timed out (coverage incomplete)"
  while IFS= read -r _s; do [[ -n "$_s" ]] && so_files+=("$_s"); done <<<"$py_paths"
fi
for _t in "${TARGET_DIRS[@]}"; do
  for _s in "$_t"/*.abi3.so; do [[ -f "$_s" ]] && so_files+=("$_s"); done
done
# Bash 3.2 treats an empty array expansion under set -u as an unbound variable.
if [[ ${#so_files[@]} -gt 0 ]]; then
for so in "${so_files[@]}"; do
  so_base="${so##*/}" so_bad=0
  for _bad in "${MALWARE_NATIVE_SO_NAMES[@]}"; do [[ "$so_base" == "$_bad" ]] && so_bad=1; done
  [[ "$so_bad" == 1 ]] || continue
  _quarantine "$so"
  alert "MALICIOUS NATIVE PYTHON MODULE DETECTED" "$(cat <<BODY
A compiled Python extension matching a known Hades/Miasma payload is present:
  $so
${WH_QUAR_NOTE:+$WH_QUAR_NOTE}
${COMMAND:+Command blocked: $COMMAND}
The Hades/Miasma PyPI wave ships native .abi3.so modules that execute a credential
stealer when Python imports the carrier package — no install step, no .pth needed.

Immediate steps:
  1. Remove the module: command rm -f "$so"
  2. Uninstall the carrier package and purge its site-packages dir
  3. pip/uv list — audit for typosquats (openai-mcp, langchain-core-mcp, tiktoken-mcp, ...)
  4. Rotate ALL credentials (PyPI/npm tokens, GitHub PATs/OIDC, SSH keys, cloud, LLM API keys)
  5. Reinstall Python deps from a clean, pinned, hash-verified lockfile
BODY
)"
done
fi

if [[ "$RUN_T1" == 1 ]]; then
  # Workspace lifecycle scripts run during a root install, including one that later fails.
  _ws_globs() {  # $1 = root dir -> workspace glob patterns, one per line
    [[ -f "$1/package.json" ]] && jq -r '.workspaces // []
      | if type == "object" then (.packages // []) else . end | .[]?' "$1/package.json" 2>/dev/null
    [[ -f "$1/pnpm-workspace.yaml" ]] && sed -nE "s/^[[:space:]]*-[[:space:]]*[\"']?([^\"']+)[\"']?[[:space:]]*\$/\1/p" "$1/pnpm-workspace.yaml"
  }
  manifests=()
  _add_manifest() { local m; for m in ${manifests[@]+"${manifests[@]}"}; do [[ "$m" == "$1" ]] && return 0; done; manifests+=("$1"); }
  for _t in "${TARGET_DIRS[@]}"; do
    [[ -f "$_t/package.json" ]] && _add_manifest "$_t/package.json"
    while IFS= read -r _g; do
      [[ -z "$_g" || "$_g" == \!* ]] && continue
      # Leave the workspace pattern unquoted for glob expansion; -f rejects unmatched literals.
      for _m in "$_t"/$_g/package.json; do
        [[ -f "$_m" && "$_m" != */node_modules/* ]] && _add_manifest "$_m"
      done
    done < <(_ws_globs "$_t")
  done
  for PKG_JSON in ${manifests[@]+"${manifests[@]}"}; do
    bad_scripts=$(jq -r '.scripts // {} | to_entries[]
      | select(.key | test("^(pre|post)?install$|^prepare$"))
      | .value' "$PKG_JSON" 2>/dev/null \
      | grep -iE "$MALWARE_DROPPER_TOKENS_RE"'|bun\.sh/install|node .*\.cjs.*curl|curl[^|]*\|[^|]*(sh|node|bash)' || true)
    [[ -z "$bad_scripts" ]] && continue
    alert "MALICIOUS LIFECYCLE SCRIPT IN package.json" "$(cat <<BODY
$PKG_JSON has an install-lifecycle script matching a known Shai-Hulud dropper:
$bad_scripts
${COMMAND:+Command blocked: $COMMAND}

This runs automatically on npm/pnpm/yarn/bun install (preinstall fires even if
install later fails — and a root install runs the lifecycle of every workspace).
Do NOT install.
  1. git log -p -- "$PKG_JSON"  (find who injected it)
  2. Reinstall third-party deps with --ignore-scripts until cleared
  3. Rotate npm tokens + GitHub PATs if this was already installed once
BODY
)"
  done

  rc_list=()
  for _t in "${TARGET_DIRS[@]}"; do
    rc_list+=( "$_t/.releaserc" "$_t/.releaserc.json" "$_t/.releaserc.yaml"
               "$_t/.releaserc.yml" "$_t/.release-it.json" "$_t/release.config.js" )
  done
  for rc in "${rc_list[@]}"; do
    [[ -f "$rc" ]] || continue
    rc_hit=$(grep -iE "$MALWARE_RELEASERC_RE" "$rc" 2>/dev/null | head -1)
    [[ -z "$rc_hit" ]] && continue
    alert "MALICIOUS RELEASE CONFIG" "$(cat <<BODY
$rc contains an injected publish-time exec step:
  $rc_hit
${COMMAND:+Command blocked: $COMMAND}
SANDWORM_MODE poisons .releaserc/.release-it.json with @semantic-release/exec to
require() a hidden carrier dependency when the package is published.

Immediate steps:
  1. git log -p -- "$rc"  (find who added the exec step)
  2. Remove the exec/require carrier line
  3. Rotate npm publish tokens
BODY
)"
  done

  for _t in "${TARGET_DIRS[@]}"; do
    [[ -d "$_t/.github/workflows" ]] || continue
    wf_hit=$(grep -rilE "$MALWARE_WORKFLOW_RE" "$_t/.github/workflows" 2>/dev/null | head -1)
    # Checkmarx published only the dropper filename.
    [[ -n "$wf_hit" ]] || wf_hit=$(find "$_t/.github/workflows" -type f 2>/dev/null \
      | grep -iE "$MALWARE_WORKFLOW_NAME_RE" | head -1)
    if [[ -n "$wf_hit" ]]; then
      alert "MALICIOUS GITHUB ACTIONS WORKFLOW" "$(cat <<BODY
$wf_hit is a known campaign dropper by name, or references a campaign marker.
${COMMAND:+Command blocked: $COMMAND}
SANDWORM_MODE injects a workflow (often pull_request_target, so it runs with repo
secrets on untrusted PR code) that calls ci-quality/code-quality-check to exfiltrate
secrets. Shai-Hulud 1.0 writes shai-hulud-workflow.yml into every repo a stolen
token can reach and POSTs the secrets to webhook.site.

Immediate steps:
  1. git log -p -- "$wf_hit"
  2. Remove the workflow and any pull_request_target job that builds untrusted PR code
  3. Rotate ALL repository + org secrets (Actions secrets, OIDC trusts, deploy keys)
  4. Rotating alone is not enough: while the workflow is committed, the next CI run
     leaks the new secrets too. Remove it first.
BODY
)"
    fi
  done


  # Do not time out Tier 1: a partial source scan could miss a blocking finding.
  src_roots=("$CWD")
  for _t in "${TARGET_DIRS[@]}"; do
    case "$_t" in "$CWD"|"$CWD"/*) : ;; *) src_roots+=("$_t") ;; esac
  done
  if _rg_ok "$MALWARE_INJECT_RE"; then
    inject_out=$("$RG_BIN" -la --no-ignore --hidden \
      -g '*.{js,mjs,cjs,ts,mts,cts,jsx,tsx}' \
      -g '!node_modules' -g '!.git' \
      -g '!dist' -g '!build' -g '!.next' -g '!.output' \
      -e "$MALWARE_INJECT_RE" "${src_roots[@]}" 2>/dev/null)
  else
    inject_out=$(grep -rlE "$MALWARE_INJECT_RE" "${src_roots[@]}" \
      --include="*.js"  --include="*.mjs" --include="*.cjs" \
      --include="*.ts"  --include="*.mts" --include="*.cts" \
      --include="*.jsx" --include="*.tsx" \
      --exclude-dir=node_modules --exclude-dir=.git \
      --exclude-dir=dist --exclude-dir=build --exclude-dir=.next --exclude-dir=.output \
      2>/dev/null)
  fi
  src_rc=$?
  [[ "$src_rc" -le 1 ]] || warn "source content scan failed (exit $src_rc; coverage incomplete)"
  inject_hit=$(head -n1 <<<"$inject_out")
  if [[ -n "$inject_hit" ]]; then
    alert "MALICIOUS CODE IN PROJECT SOURCE FILE" "$(cat <<BODY
Found malware fingerprint in: $inject_hit
This matches an injected-loader / SSR-injection attack pattern.
${COMMAND:+Command blocked: $COMMAND}

This means attacker had repo write access. Check immediately:
  1. git log --all --since="2025-09-01" --pretty=format:"%h %an %ae %ad %s"
  2. git log -p "$inject_hit" (see what was injected)
  3. git revert <bad-commit> --no-edit
  4. Revoke ALL GitHub personal access tokens
  5. Check force-push history: git reflog | grep force
BODY
)"
  fi
fi


# Common filenames require a matching hash; a name alone is insufficient.
PAYLOAD_FILES=(
  "setup_bun.js" "set_bun.js" "bun_environment.js" "com.apple.act.mond"
  "c0nt3nts.json" "c9nt3nts.json" "3nvir0nm3nt.json" "cl0vd.json"
  "actionsSecrets.json" "truffleSecrets.json" "gh-token-monitor.sh"
)
HASH_IOC_FILES=( "router_init.js" "router_runtime.js" "tanstack_runner.js" "opensearch_init.js" "setup_bun.js" "bun_environment.js" "math_init.js" "Math_Symbol.js" "setup.mjs" "node-ipc.cjs" )
HASH_IOC_HASHES=(
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
  "1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898"
  "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
  "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
  "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"
  "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
  # Elastic names the same payload Math_Symbol.js; both basenames need hash checks.
  "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
  "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
  "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
  # node-ipc.cjs is a legitimate entry point; require its payload hash.
  "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144"
)

if [[ "$RUN_T2" == 1 && -d "$NODE_MODULES" ]]; then
  find_expr=() ; first=1
  for n in "${PAYLOAD_FILES[@]}" "${HASH_IOC_FILES[@]}"; do
    if [[ $first == 1 ]]; then find_expr+=( -name "$n" ); first=0; else find_expr+=( -o -name "$n" ); fi
  done
  # Capture output directly so the timeout status survives.
  ioc_paths=$(timeout 20 find "$NODE_MODULES" -maxdepth 6 \( "${find_expr[@]}" \) -type f 2>/dev/null)
  ioc_rc=$?
  [[ "$ioc_rc" -eq 0 ]] || warn "node_modules IOC-filename walk failed or timed out (exit $ioc_rc; coverage incomplete)"
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    base="${path##*/}"
    if _in_list "$base" "${PAYLOAD_FILES[@]}"; then
      alert "NPM SUPPLY-CHAIN MALWARE DETECTED" "$(cat <<BODY
Found malware payload file: $base
Location: $path
${COMMAND:+Command blocked: $COMMAND}

Immediate steps:
  1. Run: command rm -rf "$NODE_MODULES"
  2. Rotate GitHub, npm, Cloudflare, OpenAI credentials NOW
  3. Run: ps aux | grep node (kill any running infected processes)
  4. Check: /Library/Caches/com.apple.act.mond (Axios RAT persistence)
  5. Report: support@npmjs.com
  6. Use: npm ci --ignore-scripts (safer reinstall)
BODY
)"
    fi
    if _in_list "$base" "${HASH_IOC_FILES[@]}"; then
      actual=$(shasum -a 256 "$path" 2>/dev/null | awk '{print $1}')
      for expected in "${HASH_IOC_HASHES[@]}"; do
        [[ "$actual" == "$expected" ]] || continue
        alert "NPM SUPPLY-CHAIN MALWARE DETECTED (SHA256 IOC)" "$(cat <<BODY
File matches known-bad SHA256 hash.
File: $path
Bad hash: $expected
${COMMAND:+Command blocked: $COMMAND}

Source: a known payload hash - TanStack wave (getsession exfil) or ChainDrop/keyv (Aug 2026).
Action:
  1. Run: command rm -rf "$NODE_MODULES"
  2. Pin @tanstack/* versions in lockfile with verified 'integrity' fields
  3. Rotate: npm tokens, GitHub PATs/OIDC trusts, AWS/Vault/k8s creds
  4. Audit ~/.claude/ and project .vscode/ for router_runtime.js, setup.mjs,
     and unfamiliar entries in settings.json hooks or tasks.json
  5. git log --all --author=claude@users.noreply.github.com  (impersonation)
  6. Report: support@npmjs.com
BODY
)"
        break
      done
    fi
  done <<<"$ioc_paths"

  # Set the engine label before scanning to preserve the scan exit status.
  if _rg_ok "$MALWARE_CONTENT_RE"; then
    t2_engine="rg"
    hit_out=$(timeout 20 "$RG_BIN" -la --max-count=1 --no-ignore --hidden \
      -g '*.{js,mjs,cjs}' -e "$MALWARE_CONTENT_RE" "$NODE_MODULES" 2>/dev/null)
  else
    t2_engine="grep fallback; rg missing or pattern incompatible"
    hit_out=$(timeout 20 grep -rlEm1 --include="*.js" --include="*.mjs" --include="*.cjs" "$MALWARE_CONTENT_RE" "$NODE_MODULES" 2>/dev/null)
  fi
  t2_rc=$?
  [[ "$t2_rc" -le 1 ]] || warn "node_modules content scan ($t2_engine) failed or timed out (exit $t2_rc; coverage incomplete)"
  hitfile=$(head -n1 <<<"$hit_out")
  if [[ -n "$hitfile" ]]; then
    matched="(unidentified)"
    for pattern in "${MALWARE_CONTENT_FINGERPRINTS[@]}"; do
      grep -qE "$pattern" "$hitfile" 2>/dev/null && { matched="$pattern"; break; }
    done
    alert "NPM SUPPLY-CHAIN MALWARE DETECTED" "$(cat <<BODY
Found malware fingerprint matching: $matched
Infected file: $hitfile
${COMMAND:+Command blocked: $COMMAND}

Known campaigns: Shai-Hulud (credential stealer/worm), Axios (DPRK RAT), SANDWORM_MODE (AI toolchain poisoning).
Harvests: GitHub tokens, SSH keys, npm tokens, crypto wallets, .env files, cloud credentials.

Immediate steps:
  1. Run: command rm -rf "$NODE_MODULES"
  2. Rotate ALL credentials: GitHub, npm, Cloudflare, OpenAI, SSH keys
  3. Check: ps aux | grep node (kill infected processes)
  4. Check: lsof -i | grep ESTABLISHED | grep node (exfil connections)
  5. Check: /Library/Caches/com.apple.act.mond (Axios RAT)
  6. Check: ~/.dev-env/ (Shai-Hulud 2.0 runner install)
  7. Report: support@npmjs.com
BODY
)"
  fi
fi

if [[ "$UPDATE_CACHE" == 1 && -z "$ALERTS" && -z "$WARNINGS" && -d "$NODE_MODULES" ]]; then
  if cache_key=$(_scan_key); then
    mkdir -p "$CACHE_DIR" && printf '%s\n' "$cache_key" > "$MARKER"
  else
    warn "dependency cache fingerprint failed or timed out (cache not refreshed)"
  fi
fi

if [[ "$MODE" != "pre_tool" && -n "$ALERTS" ]]; then
  evname="SessionStart"; [[ "$MODE" == "post_tool" ]] && evname="PostToolUse"
  count=$(printf '%s' "$SUMMARY" | grep -c '•')
  findings_json=$(printf '%s' "$FINDINGS" | jq -sc .)
  # Claude ignores these extra keys; CLI adapters consume them.
  jq -n --arg ctx "$ALERTS" --arg sum "$SUMMARY" --arg ev "$evname" --arg n "$count" --argjson findings "$findings_json" '{
    verdict: "red",
    findings: $findings,
    systemMessage: ("🚨 wormhook: " + $n + " critical supply-chain IOC(s) detected in this repo.\nDo NOT run npm/node installs until resolved:\n" + $sum + "\nSee the assistant message for full remediation steps."),
    hookSpecificOutput: {
      hookEventName: $ev,
      additionalContext: ("[wormhook] CRITICAL supply-chain IOC findings in this repo. State these to the user plainly, then REFUSE to run any npm/node/install command (and decline to \"work around\" the block) until the user confirms the machine is clean:\n" + $ctx)
    }
  }'
fi

if [[ -z "$ALERTS" ]]; then
  SCOPE="persistence"
  [[ "$RUN_T1" == 1 ]] && SCOPE+=" + source"
  if [[ "$RUN_T2" == 1 && -d "$NODE_MODULES" ]]; then
    SCOPE+=" + node_modules"
  elif [[ -d "$NODE_MODULES" ]]; then
    SCOPE+=" + node_modules (cached, deps unchanged)"
  fi
  # An absent start time must not become zero, which would report the whole Unix epoch.
  DUR=""
  if [[ "$MODE" == "session_start" ]]; then
    __elapsed=0
    [[ -n "${WH_T0:-}" ]] && __elapsed=$(jq -n --argjson t0 "$WH_T0" 'now - $t0' 2>/dev/null || echo 0)
    DUR=" ($(printf '%.1f' "$__elapsed")s)"
  fi
  if [[ -n "$WARNINGS" ]]; then
    jq -nc --arg msg "🟡 [wormhook] passed with caveats ($SCOPE)$DUR — $WARNINGS" '{verdict: "yellow", systemMessage: $msg}'
  elif [[ "$MODE" != "prompt_submit" ]]; then
    jq -nc --arg msg "🟢 [wormhook] clean ($SCOPE)$DUR" '{verdict: "green", systemMessage: $msg}'
  fi
fi

exit 0
