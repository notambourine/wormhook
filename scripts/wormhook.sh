#!/bin/bash
# Tiered supply-chain malware scan. Runs on SessionStart, PreToolUse, PostToolUse,
# UserPromptSubmit. PreToolUse and UserPromptSubmit can hard-block; the other two only warn
# (see the alert() KEY-DECISION for the three emission shapes).
#
# NO NETWORK: every tier is a local filesystem/stat/grep operation. Registry intelligence
# (typosquats, malicious-version blocking, publish age) is ceded to Socket Firewall + vet.
#
# Two behaviors backstop the signature tiers where they are structurally blind: Python
# execution gating runs the Tier-0 .pth sweep BEFORE an interpreter loads a poisoned
# site-packages hook, and the UserPromptSubmit monitor re-runs T0+T1 every human turn.
#
# Sources:
#   - Shai-Hulud 1.0 (Sep 2025): global['!']=X-YYYY fingerprint, crypto drainer
#   - Shai-Hulud 2.0 (Nov 2025): self-replicating worm, GitHub exfil, 796 packages
#   - Shai-Hulud 3.0 (Dec 2025): enhanced obfuscation, "Goldox-T3chs" marker, c0nt3nts.json
#   - Mini Shai-Hulud (Apr-Jun 2026): npm+PyPI; TanStack/SAP-CAP/AntV/TeamPCP; git-tanstack.com
#       typosquat, AGENT-HIJACK via .claude/.vscode setup.mjs + router_runtime.js + injected
#       SessionStart hooks + tasks.json "runOn":"folderOpen"; kitty-monitor unit + cat.py daemon;
#       ctf-scramble-v2 salt, firedalazer / OhNoWhatsGoingOnWithGitHub C2, __DAEMONIZED guard,
#       russian-locale kill-switch, audit.checkmarx.cx C2
#   - SANDWORM_MODE (Feb 2026): AI toolchain poisoning, MCP injection, SSH propagation
#   - Axios/plain-crypto-js (Mar 2026): Sapphire Sleet (DPRK) RAT via sfrclak.com C2
#   - Hades/Miasma PyPI wave (Jun 2026): MCP typosquats (openai-mcp, langchain-core-mcp,
#       tiktoken-mcp, instructor-mcp) ship a *.pth hook that downloads Bun + runs _index.js;
#       import-time .abi3.so modules (ensmallen_haswell/core2); /tmp/.sshu-setup.js SSH
#       propagation; thebeautiful{march,snads}oftime C2-discovery strings
#   - AsyncAPI / Miasma RAT "miasma-train-p1" (Jul 2026): IMPORT-TIME loader on require(),
#       defeating --ignore-scripts; NodeJS/sync.js + ~/.config/.miasma + miasma-monitor unit;
#       M-RED-TEAM v6.4 / _miasma._tcp markers, IPFS-staged second stage (2 CIDs)
#   - ChainDrop / keyv-cacheable (Aug 2026): keyv@6.0.0 preinstall -> setup.mjs loader +
#       math_init.js payload (hash IOCs); C2 resolved from ETH contract 0xE1f2…3103 (the
#       address is the on-disk constant; domains stay in the network layer)
#   - Remote-eval loader (recurring): atob(process.env.FAKE_KEY) -> fetch -> eval
#   - CISA: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
#   - Datadog: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
#   - Microsoft: https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/
#   - Wiz (Mini): https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
#   - Semgrep: https://semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/
#   - Socket: https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning
#   - Socket (Jun 2026): https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious
#   - Snyk (AntV, May 2026): https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/
#   - Unit42 (TeamPCP/npm landscape): https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/
#   - Mend (SAP-CAP via Claude Code): https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/
#   - Microsoft (AsyncAPI/Miasma, Jul 2026): https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
#   - Elastic (ChainDrop, Aug 2026): https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain
#   - Microsoft (ChainDrop, Aug 2026): https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
#   - JFrog (ChainDrop, Aug 2026): https://research.jfrog.com/post/shai-hulud-is-back-august/
#
# KEY-DECISION 2026-06-01: tiered execution. node_modules costs ~4-27s on a large repo but
# only changes on install; the source/persistence scans cost ~26ms yet the threat moves on
# every edit, pull, and agent launch. So:
#   Tier 0 (persistence + agent-hook injection): cheap stats, ALWAYS run, NEVER cached —
#           a poisoned ~/.claude hook re-runs every launch, so it must outrank the cache.
#   Tier 1 (project source + package.json lifecycle): cheap, every gated event.
#   Tier 2 (node_modules content/IOC scan): expensive, only when deps changed.
# Tier 0's pure path-existence IOCs live in the WORMHOOK_PERSIST_* arrays in
# malware-patterns.sh; _persist_scan below is the iterator. The content/behavioral
# persistence checks stay inline because they inspect file CONTENTS, not just existence.

set -uo pipefail

command -v jq &>/dev/null || { echo "Error: jq required" >&2; exit 1; }

# bash 3.2 has no $EPOCHREALTIME and BSD `date` no %N, so `jq -n now` is the sub-second clock.
# Stamped here, right after the jq check, so it spans the whole scan.
WH_T0=$(jq -n now 2>/dev/null) || WH_T0=""

# Resolve signatures relative to this script's own dir, so the plugin works wherever it installs.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MALWARE_PATTERNS="$SCRIPT_DIR/malware-patterns.sh"
# shellcheck source=/dev/null
[[ -r "$MALWARE_PATTERNS" ]] && source "$MALWARE_PATTERNS"
if [[ -z "${MALWARE_INJECT_RE:-}" || -z "${MALWARE_CONTENT_RE:-}" ]]; then
  # Fail loud but open: a missing signature file is an install fault, not a malware event,
  # so it must not brick every npm/node command. systemMessage, so the USER sees the degradation.
  echo "wormhook: signatures unavailable ($MALWARE_PATTERNS) — skipping scan" >&2
  jq -nc --arg msg "🟡 [wormhook] signatures unavailable ($MALWARE_PATTERNS) — scan SKIPPED. Reinstall the plugin." '{systemMessage: $msg}'
  exit 0
fi

PAYLOAD=$(cat)
COMMAND=$(echo "$PAYLOAD" | jq -r '.tool_input.command // ""')
CWD=$(echo "$PAYLOAD" | jq -r '.cwd // ""')
EVENT=$(echo "$PAYLOAD" | jq -r '.hook_event_name // ""')
# Back-compat: an older config may not send hook_event_name — infer it from command presence.
[[ -z "$EVENT" ]] && { [[ -n "$COMMAND" ]] && EVENT="PreToolUse" || EVENT="SessionStart"; }

NODE_MODULES="${CWD}/node_modules"

# GATE = npm/node commands worth a scan; INSTALL = the node_modules-mutating subset. `if` ⊇ regex
# vs hooks.json (CLAUDE.md). Per-SUBCOMMAND: a whole-string `^` dropped `cd x && npm i` (#56).
GATE_RE='^\s*(npm (ci|install|i|add|run|test|exec)|pnpm (install|i|add|run|exec|dlx)|yarn( (install|add|run))?|bun (install|add|i|run|x)|npx|node)(\s|$)'
INSTALL_RE='^\s*(npm (ci|install|i|add)|pnpm (install|i|add)|yarn( (install|add))?|bun (install|add|i))(\s|$)'
# GIT ops land new source — .pth/.claude persistence, lifecycle scripts — with no npm
# involved. PostToolUse only: pre-op the new files do not exist yet.
GIT_RE='^\s*git\s+(-C\s+\S+\s+)?(pull|merge|checkout|switch|rebase)(\s|$)'
# Python AUTO-EXECUTES a site-packages *.pth at interpreter start, so PYGATE must fire the Tier-0
# sweep first; PYINSTALL is the mutating subset. `make`/`./` stay ungated: no signatures, FP tax.
PYGATE_RE='^\s*(pip|pip3|pipx|uv|python|python3)(\s|$)'
PYINSTALL_RE='^\s*((pip|pip3|pipx)\s+install|uv\s+(add|sync|(pip\s+install)))(\s|$)'

# Subcommand decomposition (#56). Over-splitting inside a quoted string is accepted: a spurious
# segment can only ADD a scan, and a block still needs a real finding.
WH_SUBCMDS=""
[[ -n "$COMMAND" ]] && WH_SUBCMDS=$(printf '%s\n' "$COMMAND" \
  | awk '{ gsub(/[;&|]+/, "\n"); print }' \
  | sed -E 's/^[[:space:]]*((env|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*)[[:space:]]+)*//')
# Deleting the dir-option pairs lets `npm --prefix X install` match the verb-adjacent class
# regexes unchanged. The RAW segments keep the option — target derivation reads it below.
WH_DIROPT_STRIP='s/[[:space:]](--prefix|--cwd|--dir|-C)[= ][^[:space:]]+//g'
WH_SUBCMDS_N=""
[[ -n "$WH_SUBCMDS" ]] && WH_SUBCMDS_N=$(printf '%s\n' "$WH_SUBCMDS" | sed -E "$WH_DIROPT_STRIP")
_cmd_class() {  # 0 => some subcommand matches the class regex in $1
  [[ -n "$WH_SUBCMDS_N" ]] && printf '%s\n' "$WH_SUBCMDS_N" | grep -qE "$1"
}

# Target-dir derivation (#57). `cd packages/api && npm install` runs its lifecycle scripts there
# while the session cwd stays at the root, so Tier 1 tracks a virtual cwd; unresolvable => $CWD.
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
        _d="${_seg#cd }"; _d="${_d#"${_d%%[![:space:]]*}"}"   # ltrim
        _d="${_d%%[[:space:]]*}"                              # first arg only
        _d="${_d#[\"\']}"; _d="${_d%[\"\']}"                  # strip simple quoting
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

# KEY-DECISION 2026-06-06: prefer rg — BSD grep takes 30.3s on a 58k-file node_modules vs rg 0.7s.
# --no-ignore --hidden (else malware hides behind its own .gitignore), -a (NUL padding != binary).
RG_BIN=$(command -v rg || true)
_rg_ok() {  # 0 => rg compiles this pattern; a grep-only signature falls back, never mis-parses
  [[ -n "$RG_BIN" ]] || return 1
  printf '' | "$RG_BIN" -q -e "$1" 2>/dev/null
  [[ $? -ne 2 ]]
}

# Tier-2 cache key = lockfile hash + node_modules dir-tree mtime, so it is blind to an in-place
# OVERWRITE — exactly how Shai-Hulud 2.0 spreads locally (#55). deps_changed ages it out instead.
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/notambourine/malware-scan"
MARKER="$CACHE_DIR/$(printf '%s' "$CWD" | shasum -a 256 | awk '{print $1}')"
_tree_mtime() {
  # Depth 2, because creating a file bumps its PARENT dir's mtime: that reaches a payload 3 levels
  # in. ACCEPTED GAP: .cache/.vite are pruned from the key, so churn inside them hides until TTL.
  local statv=(stat -c %Y)                       # GNU
  stat -f %m "$NODE_MODULES" &>/dev/null && statv=(stat -f %m)  # BSD/macOS
  local m
  m=$(timeout 5 find "$NODE_MODULES" -maxdepth 2 \( -name .cache -o -name .vite \) -prune -o -type d -exec "${statv[@]}" {} + 2>/dev/null | sort -rn | head -n1)
  printf '%s' "${m:-0}"
}
_scan_key() {
  local c sig=none
  for c in package-lock.json pnpm-lock.yaml yarn.lock bun.lock; do
    [[ -f "$CWD/$c" ]] && { sig=$(shasum -a 256 "$CWD/$c" | awk '{print $1}'); break; }
  done
  printf '%s:%s' "$sig" "$(_tree_mtime)"
}
deps_changed() {            # 0 = changed/never-scanned/expired (=> scan); 1 = unchanged (=> skip)
  [[ -d "$NODE_MODULES" ]] || return 1
  [[ -f "$MARKER" ]] || return 0
  local ttl="${WORMHOOK_T2_TTL_HOURS:-24}"
  [[ "$ttl" =~ ^[0-9]+$ && "$ttl" -ge 1 ]] || ttl=24   # garbage/0 => default, never "never expire"
  [[ -n "$(find "$MARKER" -mmin +"$((ttl * 60))" 2>/dev/null)" ]] && return 0
  local saved; read -r saved < "$MARKER"
  [[ "$saved" == "$(_scan_key)" ]] && return 1 || return 0
}

MODE=session_start          # alert() blocks only in pre_tool / prompt_submit mode
RUN_T1=0 RUN_T2=0 UPDATE_CACHE=0
case "$EVENT" in
  PreToolUse)
    MODE=pre_tool
    if _cmd_class "$GATE_RE"; then
      RUN_T1=1
      # On install-class the node_modules walk would read the OLD tree; PostToolUse rescans it.
      _cmd_class "$INSTALL_RE" || { deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }; }
    elif _cmd_class "$PYGATE_RE"; then
      RUN_T1=1                                           # T0's .pth gate is the point; T2 is n/a
    else
      exit 0                                             # not a command we gate
    fi
    ;;
  PostToolUse)
    MODE=post_tool
    if _cmd_class "$INSTALL_RE"; then
      RUN_T1=1; RUN_T2=1; UPDATE_CACHE=1                # fresh deps => full scan + refresh
    elif _cmd_class "$GIT_RE"; then
      # git rewrote the tree: source, lifecycle scripts, and .pth/.claude persistence can all
      # arrive with no install. T2 only if the dep fingerprint drifted with it.
      RUN_T1=1
      deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }
    elif _cmd_class "$PYINSTALL_RE"; then
      RUN_T1=1                                           # a fresh .pth can have just landed
    else
      exit 0                                             # not install-, git-, nor pyinstall-class
    fi
    ;;
  UserPromptSubmit)
    # Continuous monitor: cheap tiers every human turn, and unlike SessionStart it can BLOCK.
    # Never T2, which keeps the turn at ~26ms. A UPS payload carries no command => COMMAND="".
    MODE=prompt_submit; RUN_T1=1; RUN_T2=0
    ;;
  *)  # SessionStart (or unknown): cheap tiers always; heavy tier only on cache miss
    MODE=session_start; RUN_T1=1
    deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }
    ;;
esac

# alert() emits three non-interchangeable shapes keyed on MODE; CLAUDE.md, "Dispatch model",
# holds that schema contract, and the per-branch notes below hold only what it cannot say.

# KEY-DECISION 2026-06-01: SessionStart CANNOT abort a session — there is no continue:false for
# it, and exit 2 just dumps stderr and proceeds. A startup warning is the strongest it gets.

# KEY-DECISION 2026-06-01 (rev): PreToolUse denies via permissionDecision, never exit 2 — exit 2
# routes the alert to stderr, which reaches the MODEL only, so the user never saw the block.
ALERTS="" SUMMARY=""

# NDJSON findings are the structured contract the out-of-band CLI consumes, so rewording a
# banner cannot silently break its parsing and dedup.
FINDINGS=""

# A degraded run (scan timeout) reports 🟡 and never refreshes the cache: a truncated scan is
# not a clean scan.
WARNINGS=""
warn() { WARNINGS="${WARNINGS:+$WARNINGS; }$1"; }

# Opt-in quarantine (#59): rename + chmod 000, never kill/unload/delete — containment would
# invert the fail-open bias. Exact-match IOCs only; a behavioral match stays report-only.
WORMHOOK_QUARANTINE="${WORMHOOK_QUARANTINE:-}"
QUARANTINE_LOG="$CACHE_DIR/quarantine.log"
WH_QUAR_NOTE=""
_quarantine() {  # $1 = exact-match artifact path -> WH_QUAR_NOTE (one line for the alert body)
  WH_QUAR_NOTE=""
  [[ -n "$WORMHOOK_QUARANTINE" ]] || return 0
  local dest
  dest="$1.wormhook-quarantined.$(date +%s)"
  if mv "$1" "$dest" 2>/dev/null; then
    chmod 000 "$dest" 2>/dev/null || true
    WH_QUAR_NOTE="QUARANTINED (reversible): renamed to $dest + chmod 000. It can no longer fire."
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
    # One exit-0 emission carries all three channels: the deny, the user's 🚨, the model's reason.
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
    # UPS puts the decision TOP-LEVEL, and `decision` is MUTUALLY EXCLUSIVE with
    # hookSpecificOutput.additionalContext, so neither that nor hookSpecificOutput is emitted.
    jq -n --arg title "$1" --arg body "$2" '{
      decision: "block",
      reason: ("[wormhook] Blocked this turn: " + $title + ". State this block to the user plainly and do NOT proceed or work around it until the user confirms the machine is clean.\n" + $body),
      systemMessage: ("🚨 wormhook BLOCKED this turn — supply-chain IOC detected:\n" + $title + "\n\n" + $body)
    }'
    exit 0
  fi
}
_in_list() { local n="$1"; shift; local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }

# ══ TIER 0: persistence + agent-hook injection — cheap stats, ALWAYS, NEVER cached ══

# Shared frame for the path-existence persistence alerts, so a skeleton change is one edit. The
# bespoke bodies below have no uniform "found path -> steps" shape and stay inline.

# bash 3.2: this heredoc's literal text has no apostrophe, so the $(cat <<BODY) parser gotcha
# cannot trip. LEAD/STEPS arrive as double-quoted args, where an apostrophe is plain data.
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

# Driver over the WORMHOOK_PERSIST_* table, whose rows are path-EXISTENCE IOCs. Callers pass
# INDICES, so the table checks stay interleaved with the inline content checks, in order.
WH_PERSIST_HIT=""
_persist_scan() {
  local _i _op _path _candidates _c
  for _i in "$@"; do
    _op="${WORMHOOK_PERSIST_TEST[$_i]}"
    # Word-split is safe: no table path contains a space, and no element can be empty.
    _candidates="${WORMHOOK_PERSIST_PATHS[$_i]}"
    _candidates="${_candidates//__HOME__/$HOME}"
    _candidates="${_candidates//__CWD__/$CWD}"
    WH_PERSIST_HIT=""
    # shellcheck disable=SC2086  # intentional split on spaces into candidate paths
    for _c in $_candidates; do
      if [[ "$_op" == "-f" && -f "$_c" ]] || [[ "$_op" == "-d" && -d "$_c" ]] || [[ "$_op" == "-e" && -e "$_c" ]]; then
        WH_PERSIST_HIT="$_c"; break
      fi
    done
    [[ -z "$WH_PERSIST_HIT" ]] && continue
    # Every row is exact-match by construction, so every hit is quarantine-eligible. A group
    # with further member paths converges over runs: one quarantine per scan.
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
        # A poisoned ~/.claude file re-runs every launch and PROPAGATES if that dir is synced,
        # so the table covers both $HOME and the project dir.
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
        # Unit names and the cat.py path are campaign-specific, taken verbatim from Snyk's AntV
        # write-up. Same class as gh_token_monitor above.
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
        # The macOS drop path holds a space, so the table cannot list it; the cross-platform
        # .miasma lock dir is what fires there.
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

# Agent-config injection. Matching the WIRED entry, not just the dropper file, still catches a
# dropper that injected the config and then deleted itself. Schemas differ, so scan every string.
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
  # del(.permissions): a user's own `Bash(curl * | bash*)` DENY rule would FP on
  # MALWARE_REMOTE_EXEC_RE. It is security POLICY, never the wiring a dropper hijacks.
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

# Ask git for the hooks dir: in a WORKTREE .git is a FILE, so the literal path scanned
# nothing (#60). The literal fallback covers a missing git or a non-repo $CWD.
repo_hooks=$(git -C "$CWD" rev-parse --git-path hooks 2>/dev/null) || repo_hooks=""
[[ -n "$repo_hooks" ]] || repo_hooks="${CWD}/.git/hooks"
[[ "$repo_hooks" == /* ]] || repo_hooks="${CWD}/${repo_hooks}"
git_hook_dirs=("$repo_hooks")
tmpl_dir=$(git config --global --get init.templateDir 2>/dev/null) && [[ -n "$tmpl_dir" ]] && git_hook_dirs+=("${tmpl_dir/#\~/$HOME}/hooks")
hooks_path=$(git -C "$CWD" config --get core.hooksPath 2>/dev/null) && [[ -n "$hooks_path" && "$hooks_path" != "$repo_hooks" ]] && git_hook_dirs+=("$hooks_path")
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

# Python AUTO-RUNS a site-packages *.pth at interpreter start. A legit one only touches
# sys.path, which is what keeps MALWARE_PTH_RE near-zero-FP.

# Seed roots for BOTH Python sweeps. Globs, not `python3 -c "import site"`: an interpreter
# reports only ITSELF, a pyenv/uv machine has N others, and it costs a spawn every turn.
py_roots=("${CWD}/.venv" "${CWD}/venv" "${CWD}/env" "${CWD}/.tox")
case "${VIRTUAL_ENV:-}" in
  ""|"${CWD}/.venv"|"${CWD}/venv"|"${CWD}/env"|"${CWD}/.tox") : ;;  # empty or already seeded
  *) [[ -d "$VIRTUAL_ENV" ]] && py_roots+=("$VIRTUAL_ENV") ;;
esac
[[ -n "${CONDA_PREFIX:-}" && -d "${CONDA_PREFIX:-}" ]] && py_roots+=("$CONDA_PREFIX")
# User + global site-packages (#58) — where `pip install` outside a venv lands, the exact
# audience the MCP typosquats target. /usr/lib stays out: apt-owned, pip never writes there.
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
while IFS= read -r _p; do [[ -n "$_p" ]] && pth_files+=("$_p"); done < <(
  timeout 5 find "${py_roots[@]}" -maxdepth 5 -name '*.pth' -type f 2>/dev/null
)
for _p in "${CWD}"/*.pth; do [[ -f "$_p" ]] && pth_files+=("$_p"); done
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
    # Name/hash IOCs only — an unattended rename demands exact-match confidence.
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

# A compiled .abi3.so runs at package import, and a binary is opaque to the content greps every
# other tier relies on — so the exact basename is the only handle a tree scan has.
so_files=()
while IFS= read -r _s; do [[ -n "$_s" ]] && so_files+=("$_s"); done < <(
  timeout 5 find "${py_roots[@]}" -maxdepth 5 -name '*.abi3.so' -type f 2>/dev/null
)
for _s in "${CWD}"/*.abi3.so; do [[ -f "$_s" ]] && so_files+=("$_s"); done
# bash 3.2 + `set -u`: expanding "${so_files[@]}" on an EMPTY array is an unbound-variable error.
if [[ ${#so_files[@]} -gt 0 ]]; then
for so in "${so_files[@]}"; do
  so_base="${so##*/}" so_bad=0
  for _bad in "${MALWARE_NATIVE_SO_NAMES[@]}"; do [[ "$so_base" == "$_bad" ]] && so_bad=1; done
  [[ "$so_bad" == 1 ]] || continue
  _quarantine "$so"   # exact-basename IOC (zero FP) => quarantine-eligible
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

# ══ TIER 1: project source + package.json lifecycle — cheap (~26ms), every event ══
if [[ "$RUN_T1" == 1 ]]; then
  # The one check that fires BEFORE malicious code executes: preinstall runs even when the
  # install later fails. A root install runs EVERY workspace's preinstall, so read them all (#57).
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
      # Unquoted on purpose. No nullglob on bash 3.2, so a no-match leaves the literal '*'
      # path — which the -f test then rejects.
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

  # Release-config poisoning: `@semantic-release/exec` alone is legit, so MALWARE_RELEASERC_RE
  # matches only the carrier tell — a publish-time require() of a hidden dep.
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

  # Workflow poisoning: pull_request_target alone is legit and NOT flagged. Only the campaign
  # fingerprints in MALWARE_WORKFLOW_RE trip this.
  for _t in "${TARGET_DIRS[@]}"; do
    [[ -d "$_t/.github/workflows" ]] || continue
    wf_hit=$(grep -rilE "$MALWARE_WORKFLOW_RE" "$_t/.github/workflows" 2>/dev/null | head -1)
    if [[ -n "$wf_hit" ]]; then
      alert "MALICIOUS GITHUB ACTIONS WORKFLOW" "$(cat <<BODY
$wf_hit references a known supply-chain campaign action / marker.
${COMMAND:+Command blocked: $COMMAND}
SANDWORM_MODE injects a workflow (often pull_request_target, so it runs with repo
secrets on untrusted PR code) that calls ci-quality/code-quality-check to exfiltrate
secrets.

Immediate steps:
  1. git log -p -- "$wf_hit"
  2. Remove the workflow and any pull_request_target job that builds untrusted PR code
  3. Rotate ALL repository + org secrets (Actions secrets, OIDC trusts, deploy keys)
BODY
)"
    fi
  done

  # An attacker with write access injects the loader into ANY file, so scan the tree broadly;
  # a narrow INJECT_RE is what keeps FPs down on minified bundles.

  # KEY-DECISION 2026-06-06: NO timeout here. Tier 1 BLOCKS, so a truncated walk is a coverage
  # hole, not a degradation — a 15s ceiling once fired on a 149-file tree from post-wake load.
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

# ══ TIER 2: node_modules content/IOC scan — expensive, only when deps changed ══

# PAYLOAD names are proof on their own; HASH_IOC names need the hash, since router_runtime.js
# and friends can be legit. One find traversal covers both.
PAYLOAD_FILES=(
  "setup_bun.js" "set_bun.js" "bun_environment.js" "com.apple.act.mond"
  "c0nt3nts.json" "c9nt3nts.json" "3nvir0nm3nt.json" "cl0vd.json"
  "actionsSecrets.json" "truffleSecrets.json" "gh-token-monitor.sh"
)
HASH_IOC_FILES=( "router_init.js" "router_runtime.js" "tanstack_runner.js" "opensearch_init.js" "setup_bun.js" "bun_environment.js" "math_init.js" "Math_Symbol.js" "setup.mjs" )
HASH_IOC_HASHES=(
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
  "1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898"
  "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
  "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
  "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"
  "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
  # ChainDrop / keyv wave (Aug 2026): math_init.js payload (Elastic names the same hash
  # Math_Symbol.js, so both basenames are listed) + the two setup.mjs loader variants.
  "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
  "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
  "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
)

if [[ "$RUN_T2" == 1 && -d "$NODE_MODULES" ]]; then
  find_expr=() ; first=1
  for n in "${PAYLOAD_FILES[@]}" "${HASH_IOC_FILES[@]}"; do
    if [[ $first == 1 ]]; then find_expr+=( -name "$n" ); first=0; else find_expr+=( -o -name "$n" ); fi
  done
  # Capture, not a process substitution, so the timeout's exit 124 stays observable — a
  # truncated walk must report a caveat, never pass as clean.
  ioc_paths=$(timeout 20 find "$NODE_MODULES" -maxdepth 6 \( "${find_expr[@]}" \) -type f 2>/dev/null)
  [[ $? -eq 124 ]] && warn "node_modules IOC-filename walk timed out at 20s (coverage incomplete)"
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

  # One combined gate pass; a hit is rare enough to re-grep that file per-pattern for the name.
  # Set the engine label BEFORE the scan, so the $? test still reads the scan's exit status.
  if _rg_ok "$MALWARE_CONTENT_RE"; then
    t2_engine="rg"
    hit_out=$(timeout 20 "$RG_BIN" -la --max-count=1 --no-ignore --hidden \
      -g '*.{js,mjs,cjs}' -e "$MALWARE_CONTENT_RE" "$NODE_MODULES" 2>/dev/null)
  else
    t2_engine="grep fallback; rg missing or pattern incompatible"
    hit_out=$(timeout 20 grep -rlEm1 --include="*.js" --include="*.mjs" --include="*.cjs" "$MALWARE_CONTENT_RE" "$NODE_MODULES" 2>/dev/null)
  fi
  [[ $? -eq 124 ]] && warn "node_modules content scan ($t2_engine) timed out at 20s (coverage incomplete)"
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

# Only a CLEAN, COMPLETE scan refreshes the cache: a timed-out walk is not a clean scan, so
# leaving it uncached makes the next event retry the full walk.
if [[ "$UPDATE_CACHE" == 1 && -z "$ALERTS" && -z "$WARNINGS" && -d "$NODE_MODULES" ]]; then
  mkdir -p "$CACHE_DIR" && _scan_key > "$MARKER"
fi

# Both channels: systemMessage is the loud part the user sees, additionalContext is what makes
# the model refuse follow-up installs. SessionStart cannot abort, so this is its strongest signal.
if [[ "$MODE" != "pre_tool" && -n "$ALERTS" ]]; then
  evname="SessionStart"; [[ "$MODE" == "post_tool" ]] && evname="PostToolUse"
  count=$(printf '%s' "$SUMMARY" | grep -c '•')
  findings_json=$(printf '%s' "$FINDINGS" | jq -sc .)
  # Claude Code ignores the extra top-level keys; the CLI adapter reads them.
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

# KEY-DECISION 2026-06-06: a clean pass prints 🟢 and a degraded one 🟡, so "scanned clean" and
# "hook never ran" cannot look identical. No additionalContext: the status line is for the human.
if [[ -z "$ALERTS" ]]; then
  SCOPE="persistence"
  [[ "$RUN_T1" == 1 ]] && SCOPE+=" + source"
  if [[ "$RUN_T2" == 1 && -d "$NODE_MODULES" ]]; then
    SCOPE+=" + node_modules"
  elif [[ -d "$NODE_MODULES" ]]; then
    SCOPE+=" + node_modules (cached, deps unchanged)"
  fi
  # SessionStart only: on a per-turn or blocking event the latency is the user's own command,
  # not a dashboard metric. An empty stamp must short-circuit — `now - 0` is the whole epoch.
  DUR=""
  if [[ "$MODE" == "session_start" ]]; then
    __elapsed=0
    [[ -n "${WH_T0:-}" ]] && __elapsed=$(jq -n --argjson t0 "$WH_T0" 'now - $t0' 2>/dev/null || echo 0)
    DUR=" ($(printf '%.1f' "$__elapsed")s)"
  fi
  if [[ -n "$WARNINGS" ]]; then
    # A degraded pass speaks on EVERY event, prompt_submit included: a silently degraded
    # monitor is invisible exactly when it matters.
    jq -nc --arg msg "🟡 [wormhook] passed with caveats ($SCOPE)$DUR — $WARNINGS" '{verdict: "yellow", systemMessage: $msg}'
  elif [[ "$MODE" != "prompt_submit" ]]; then
    # The 🟢 is suppressed for prompt_submit only: it fires every human turn, so printing one
    # each time would spam the transcript.
    jq -nc --arg msg "🟢 [wormhook] clean ($SCOPE)$DUR" '{verdict: "green", systemMessage: $msg}'
  fi
fi

exit 0
