#!/bin/bash
# Tiered supply-chain malware scan. Runs on SessionStart, PreToolUse, PostToolUse,
# UserPromptSubmit. Two events can hard-block: PreToolUse (permissionDecision:"deny")
# and UserPromptSubmit (top-level decision:"block"); Session/Post can only warn. See the
# Alert helper KEY-DECISION for the three distinct emission shapes.
#
# NO NETWORK: every tier is a local filesystem/stat/grep operation. The install-time
# *firewall* job (registry intelligence: typosquats, malicious-version blocking, age/
# reputation) is deliberately ceded to Socket Firewall (sfw) + safedep/vet — doctor/firewall.sh
# nudges you to install them. wormhook is the independent, local, near-zero-FP lock.
#
# Two behaviors backstop the signature tiers where they're structurally blind:
#   - Python execution gating: pip/uv/pipx/python on PreToolUse trigger the Tier-0
#     .pth sweep BEFORE the interpreter auto-executes a poisoned site-packages startup hook.
#   - UserPromptSubmit monitor: re-runs T0+T1 every human turn and can block —
#     the hook layer's approximation of a continuous filesystem watcher. Silent when clean.
#
# Sources:
#   - Shai-Hulud 1.0 (Sep 2025): global['!']=X-YYYY fingerprint, crypto drainer
#   - Shai-Hulud 2.0 (Nov 2025): self-replicating worm, GitHub exfil, 796 packages
#   - Shai-Hulud 3.0 (Dec 2025): enhanced obfuscation, "Goldox-T3chs" marker, c0nt3nts.json
#   - Mini Shai-Hulud (Apr-Jun 2026): cross-ecosystem (npm+PyPI), TanStack/SAP-CAP/AntV/
#       TeamPCP, git-tanstack.com typosquat + Session-network exfil, AGENT-HIJACK persistence
#       via .claude/.vscode setup.mjs + router_runtime.js + injected SessionStart hooks +
#       .vscode/tasks.json "runOn":"folderOpen"; kitty-monitor LaunchAgent/systemd unit +
#       ~/.local/share/kitty/cat.py daemon; ctf-scramble-v2 PBKDF2 salt, firedalazer /
#       OhNoWhatsGoingOnWithGitHub C2 keywords, __DAEMONIZED guard, russian-locale kill-switch,
#       audit.checkmarx.cx C2
#   - SANDWORM_MODE (Feb 2026): AI toolchain poisoning, MCP injection, SSH propagation
#   - Axios/plain-crypto-js (Mar 2026): Sapphire Sleet (DPRK) RAT via sfrclak.com C2
#   - Hades/Miasma/Mini Shai-Hulud PyPI wave (Jun 2026): MCP-typosquat PyPI packages
#       (openai-mcp, langchain-core-mcp, tiktoken-mcp, instructor-mcp, ...) ship a
#       weaponized *.pth startup hook that downloads Bun + runs _index.js (Hades JS
#       stealer); native import-time .abi3.so modules (ensmallen_haswell/core2) that
#       execute on package import with no .pth; /tmp/.sshu-setup.js SSH propagation;
#       thebeautiful{march,snads}oftime fallback C2-discovery strings. Targets
#       bioinformatics + MCP developers.
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
#
# KEY-DECISION 2026-06-01: tiered execution. Scanning node_modules costs ~4-27s on a
# large repo (8600 files) but it only changes on install; the source/persistence scans
# cost ~26ms but the threat changes constantly (every edit/pull/agent launch). So:
#   Tier 0 (persistence + agent-hook-injection): cheap stats, ALWAYS run, NEVER cached.
#   Tier 1 (project source + package.json lifecycle): cheap, run on every gated event.
#   Tier 2 (node_modules content/IOC scan): expensive, run only when deps changed
#           (install-class PostToolUse, or SessionStart with a stale cache marker).
# A poisoned ~/.claude hook re-runs on every launch, so Tier 0 must outrank the cache.

set -uo pipefail

command -v jq &>/dev/null || { echo "Error: jq required" >&2; exit 1; }

# Scan-runtime stamp for the SessionStart status line (see the "(x.xs)" suffix below). Captured
# here — jq just confirmed present — so it spans the whole scan (signature load + payload parse +
# tiers). bash 3.2 has no $EPOCHREALTIME and BSD `date` no %N, so `jq -n now` is the sub-second
# clock; printf %.1f formats it. Used only on the session_start status line, so the blocking
# pre_tool/prompt_submit paths pay nothing.
WH_T0=$(jq -n now 2>/dev/null) || WH_T0=""

# Malware signatures: single source of truth, bundled alongside this hook so a
# pattern added once reaches every scan tier. Resolve relative to this script's own
# dir — works regardless of where the plugin is installed (don't depend on $HOME).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MALWARE_PATTERNS="$SCRIPT_DIR/malware-patterns.sh"
# shellcheck source=/dev/null
[[ -r "$MALWARE_PATTERNS" ]] && source "$MALWARE_PATTERNS"
if [[ -z "${MALWARE_INJECT_RE:-}" || -z "${MALWARE_CONTENT_RE:-}" ]]; then
  # Fail loud but open: a missing config file is an install fault, not a malware
  # event — don't brick every npm/node command over it. systemMessage (not bare
  # stderr) so the degraded state is visible to the USER, not just debug logs.
  echo "wormhook: signatures unavailable ($MALWARE_PATTERNS) — skipping scan" >&2
  jq -nc --arg msg "🟡 [wormhook] signatures unavailable ($MALWARE_PATTERNS) — scan SKIPPED. Reinstall the plugin." '{systemMessage: $msg}'
  exit 0
fi

PAYLOAD=$(cat)
COMMAND=$(echo "$PAYLOAD" | jq -r '.tool_input.command // ""')
CWD=$(echo "$PAYLOAD" | jq -r '.cwd // ""')
EVENT=$(echo "$PAYLOAD" | jq -r '.hook_event_name // ""')
# Back-compat: older configs may not send hook_event_name — infer from command presence.
[[ -z "$EVENT" ]] && { [[ -n "$COMMAND" ]] && EVENT="PreToolUse" || EVENT="SessionStart"; }

NODE_MODULES="${CWD}/node_modules"

# Command classes. GATE = the npm/node commands we care about at all; INSTALL = the
# subset that mutates node_modules (the only thing that can introduce a new dep IOC).
# Keep these in sync with the `if` globs in hooks/hooks.json (`if` ⊇ regex) — see the
# "Two sources of truth" note in CLAUDE.md.
GATE_RE='^\s*(npm (ci|install|i|add|run|test|exec)|pnpm (install|i|add|run|exec|dlx)|yarn( (install|add|run))?|bun (install|add|i|run|x)|npx|node)(\s|$)'
INSTALL_RE='^\s*(npm (ci|install|i|add)|pnpm (install|i|add)|yarn( (install|add))?|bun (install|add|i))(\s|$)'
# GIT = working-tree-rewriting git ops. pull/merge/checkout/switch/rebase land new
# source — including .pth/.claude persistence and package.json lifecycle scripts —
# with no npm involved, so they need a Tier 0+1 sweep too. PostToolUse only: pre-op
# the new files don't exist yet (see the case below). Tolerate a leading `-C <dir>`.
GIT_RE='^\s*git\s+(-C\s+\S+\s+)?(pull|merge|checkout|switch|rebase)(\s|$)'
# PYGATE = Python interpreters/installers. They don't touch node_modules, but Python
# AUTO-EXECUTES a site-packages *.pth on every interpreter start (the Hades/Miasma PyPI
# vector) — so any of these must trigger a PreToolUse Tier-0 sweep so the .pth check runs
# BEFORE the interpreter loads it. PYINSTALL = the subset that mutates site-packages (a
# fresh .pth can land), warranting a PostToolUse re-scan. `make`/`./` deliberately NOT
# gated: too broad, no matching signatures, pure FP/latency tax. Keep `if` ⊇ regex.
PYGATE_RE='^\s*(pip|pip3|pipx|uv|python|python3)(\s|$)'
PYINSTALL_RE='^\s*((pip|pip3|pipx)\s+install|uv\s+(add|sync|(pip\s+install)))(\s|$)'

# ── Fast content greps: ripgrep when available ────────────────────────────────
# KEY-DECISION 2026-06-06: the two content scans (Tier 1 project source, Tier 2
# node_modules fingerprints) prefer rg over grep. Measured on a 58k-file
# node_modules: BSD grep 30.3s single-core (blows the 20s Tier-2 ceiling => a
# permanent 🟡 on every deps change), rg 0.7s parallel — 43x. Verdict parity
# verified per-pattern (7/7 IOC strings agree) and per-traversal (hidden files,
# depth, exclusion globs). rg needs --no-ignore --hidden for grep-equivalent
# coverage (else malware hides behind a .gitignore it ships itself) and -a so
# NUL-byte padding can't get a file classified binary and skipped. Each pattern
# is compile-gated at runtime: a future signature using grep-only syntax falls
# back to grep for that scan rather than mis-parse — degradation fails toward
# scanning, never away from it.
RG_BIN=$(command -v rg || true)
_rg_ok() {  # 0 => rg exists and compiles this pattern
  [[ -n "$RG_BIN" ]] || return 1
  printf '' | "$RG_BIN" -q -e "$1" 2>/dev/null
  [[ $? -ne 2 ]]
}

# ── Scan-cache (Tier 2 only) ──────────────────────────────────────────────────
# Marker stores a key = lockfile hash + node_modules dir-tree mtime (depth ≤2).
# Match => deps unchanged since the last CLEAN scan => skip the expensive walk.
# Derived state, never synced.
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/notambourine/malware-scan"
MARKER="$CACHE_DIR/$(printf '%s' "$CWD" | shasum -a 256 | awk '{print $1}')"
_tree_mtime() {
  # Max mtime over node_modules itself + dirs ≤2 levels deep. Creating/removing
  # a file bumps its PARENT dir's mtime, so depth-2 dir mtimes catch a payload
  # planted up to 3 levels in (pkg roots, @scope/pkg roots — where the known IOC
  # payload files live). Root-only mtime missed anything below the top level: a
  # hand-planted node_modules/<pkg>/payload between installs rode the clean
  # cache until the lockfile changed. Empty/timeout output => 0 => key mismatch
  # => Tier 2 re-scans (degradation fails toward scanning, never away from it).
  #
  # Build-tool scratch dirs (.cache: prettier/babel/eslint; .vite: dev-server
  # optimizer) are pruned from the KEY ONLY: they churn on every format/build,
  # invalidating the clean-scan marker daily for repos whose deps never changed.
  # ACCEPTED GAP: a payload planted inside a pruned dir is key-invisible — Tier 2
  # only re-walks it when the lockfile or a tracked dir changes, a window that
  # can stay open indefinitely in a stable repo. Accepted because these dirs are
  # tool-managed scratch, not require()d code paths, and the alternative was a
  # daily false re-scan. NOTE: creating/removing the pruned dir itself still
  # bumps node_modules' root mtime; only churn INSIDE these dirs is hidden.
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
deps_changed() {            # 0 = changed/never-scanned (=> scan); 1 = unchanged (=> skip)
  [[ -d "$NODE_MODULES" ]] || return 1
  [[ -f "$MARKER" ]] || return 0
  local saved; read -r saved < "$MARKER"
  [[ "$saved" == "$(_scan_key)" ]] && return 1 || return 0
}

# ── Execution plan from the event ─────────────────────────────────────────────
MODE=session_start          # alert() blocks only in pre_tool mode
RUN_T1=0 RUN_T2=0 UPDATE_CACHE=0
case "$EVENT" in
  PreToolUse)
    MODE=pre_tool
    if echo "$COMMAND" | grep -qE "$GATE_RE"; then
      RUN_T1=1
      # install-class: the package.json lifecycle gate (Tier 1) is the pre-execution
      # check that matters; the heavy node_modules walk is the OLD state, low value —
      # PostToolUse re-scans the fresh tree. exec-class: scan only if deps drifted.
      echo "$COMMAND" | grep -qE "$INSTALL_RE" || { deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }; }
    elif echo "$COMMAND" | grep -qE "$PYGATE_RE"; then
      # Python interpreter/installer: Tier 0 (always) is the .pth gate we need pre-exec;
      # add Tier 1. NEVER Tier 2 (node_modules irrelevant).
      RUN_T1=1
    else
      exit 0                                             # not a command we gate
    fi
    ;;
  PostToolUse)
    MODE=post_tool
    if echo "$COMMAND" | grep -qE "$INSTALL_RE"; then
      RUN_T1=1; RUN_T2=1; UPDATE_CACHE=1                # fresh deps => full scan + refresh
    elif echo "$COMMAND" | grep -qE "$GIT_RE"; then
      # git just rewrote the working tree: new source + lifecycle scripts + .pth/.claude
      # persistence can all arrive with no install. Tier 0 always runs; add Tier 1, and
      # Tier 2 only if the dep fingerprint drifted (e.g. the pull moved package-lock.json).
      RUN_T1=1
      deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }
    elif echo "$COMMAND" | grep -qE "$PYINSTALL_RE"; then
      # pip/uv install just landed: a malicious *.pth can be freshly written into
      # site-packages. Re-run Tier 0 (the .pth gate) + Tier 1; node_modules is untouched.
      RUN_T1=1
    else
      exit 0                                             # not install-, git-, nor pyinstall-class
    fi
    ;;
  UserPromptSubmit)
    # Continuous monitor: re-run the cheap, fast-changing tiers at every human turn and —
    # unlike SessionStart — BLOCK on a finding. T0 (always) + T1 only; NEVER T2 (node_modules
    # changes only on install, already gated) keeps this ~26ms/turn. No command on a UPS
    # payload => COMMAND="" => the ${COMMAND:+…} alert interpolations omit cleanly.
    MODE=prompt_submit; RUN_T1=1; RUN_T2=0
    ;;
  *)  # SessionStart (or unknown): cheap tiers always; heavy tier only on cache miss
    MODE=session_start; RUN_T1=1
    deps_changed && { RUN_T2=1; UPDATE_CACHE=1; }
    ;;
esac

# ── Alert helper ──────────────────────────────────────────────────────────────
# THREE delivery shapes, by event (see KEY-DECISION below). The block-event schemas are
# NOT interchangeable — PreToolUse nests its decision; UserPromptSubmit puts it top-level:
#   PreToolUse:               hookSpecificOutput.permissionDecision:"deny" (hard block) +
#                             `systemMessage` (loud, shown to the USER at block time) +
#                             permissionDecisionReason (instructs the model) — one exit-0 JSON.
#   UserPromptSubmit:         top-level decision:"block" (hard block) + `systemMessage` (USER) +
#                             `reason` (model). decision is MUTUALLY EXCLUSIVE with
#                             hookSpecificOutput.additionalContext on UPS, so neither is emitted.
#   SessionStart/PostToolUse: accumulate, then emit `systemMessage` (loud, shown to
#                             the USER) + `additionalContext` (instructs the model).
# KEY-DECISION 2026-06-01: SessionStart CANNOT abort the session — Claude Code has no
# continue:false / decision:block for it (confirmed via hooks docs), and exit 2 there
# just dumps stderr and proceeds. So "refuse to boot" is impossible; the strongest we
# get is (1) a clean `systemMessage` warning to the human at startup, and (2) the
# hard block on the actual npm/node command.
# KEY-DECISION 2026-06-01 (rev): PreToolUse blocks via permissionDecision:"deny", NOT
# exit 2. Both are documented hard blocks (verified against the hooks docs — exit-2 is
# not "the only" block), but exit-2 routes its alert to STDERR, which Claude Code shows
# to the MODEL only — so the user never saw the 🚨 at block time unless the model chose
# to relay it. The deny+systemMessage form blocks the command AND surfaces the alert to
# the human directly AND feeds the model a refuse-to-work-around reason — all three,
# which exit-2 cannot. Earlier we relied on additionalContext/stderr alone — that only
# talks to the model and reads as a soft flag; bare stderr+exit 0 is invisible in the TUI
# (the "silent for a month" bug). A broad all-Bash exit-2 quarantine was rejected: the
# remediation steps below are themselves Bash, so it would lock the user out of fixing
# the machine.
ALERTS="" SUMMARY=""
# Machine-readable findings (NDJSON, one {title,body} per alert), slurped into the
# `findings` array on the SessionStart/PostToolUse verdict. This is the structured
# contract the out-of-band CLI consumes instead of screen-scraping ALERTS/SUMMARY —
# rewording a banner no longer silently breaks the adapter's parsing/dedup.
FINDINGS=""
# Degraded-but-not-infected conditions (scan timeouts etc). A run with warnings
# reports 🟡 instead of 🟢 and never refreshes the clean-scan cache — a truncated
# scan is not a clean scan.
WARNINGS=""
warn() { WARNINGS="${WARNINGS:+$WARNINGS; }$1"; }
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
    # Hard block on the actual npm/node command. permissionDecision:"deny" blocks it;
    # systemMessage shows the 🚨 to the USER directly at block time (exit-2's stderr
    # would reach the model only); permissionDecisionReason tells the model to state the
    # block plainly and not work around it. One exit-0 emission, all three channels.
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
    # UserPromptSubmit hard block. The UPS schema differs from PreToolUse: the decision is
    # a TOP-LEVEL "block" (not nested permissionDecision), and `decision` is MUTUALLY
    # EXCLUSIVE with hookSpecificOutput.additionalContext — so we emit neither additionalContext
    # nor hookSpecificOutput. `reason` reaches the MODEL (refuse-to-proceed); `systemMessage`
    # reaches the USER (the 🚨). One exit-0 emission. (Verified against code.claude.com/docs/en/hooks.)
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

# Axios/plain-crypto-js RAT persistence (macOS).
if [[ -f "/Library/Caches/com.apple.act.mond" ]]; then
  alert "AXIOS RAT PERSISTENCE DETECTED" "$(cat <<BODY
Found Axios/plain-crypto-js RAT binary at: /Library/Caches/com.apple.act.mond
This file masquerades as an Apple daemon but is a DPRK (Sapphire Sleet) RAT.
${COMMAND:+Command blocked: $COMMAND}

Immediate steps:
  1. Kill: sudo pkill -f com.apple.act.mond
  2. Remove: sudo rm -f /Library/Caches/com.apple.act.mond
  3. Rotate ALL credentials (GitHub, npm, Cloudflare, SSH keys)
  4. Check: ps aux | grep -E 'act\.mond|sfrclak' (other persistence)
  5. Report: support@npmjs.com
BODY
)"
fi

# Shai-Hulud 2.0 GitHub-runner install.
if [[ -d "$HOME/.dev-env" ]]; then
  alert "SHAI-HULUD 2.0 PERSISTENCE DETECTED" "$(cat <<BODY
Found Shai-Hulud 2.0 runner install at: $HOME/.dev-env
This directory contains a malicious GitHub Actions runner used for credential exfil.

Immediate steps:
  1. Remove: command rm -rf "$HOME/.dev-env"
  2. Rotate ALL credentials (GitHub, npm, cloud providers)
  3. Check GitHub for repos matching [0-9a-z]{18} with stolen creds
  4. Check: ps aux | grep actions-runner
BODY
)"
fi

# Agent-hijack dropper FILES (Mini Shai-Hulud). A poisoned file in ~/.claude/ re-runs
# on every launch and, if that dir is synced across machines, would PROPAGATE — so
# check both $HOME and the project dir.
for hp in \
  "${CWD}/.claude/setup.mjs"   "${CWD}/.claude/router_runtime.js" \
  "${CWD}/.vscode/setup.mjs"   "${CWD}/.vscode/router_runtime.js" \
  "${HOME}/.claude/setup.mjs"  "${HOME}/.claude/router_runtime.js"; do
  [[ -e "$hp" ]] || continue
  alert "AGENT-HIJACK PERSISTENCE DETECTED" "$(cat <<BODY
Found Mini Shai-Hulud agent-hijack dropper: $hp
This installs into an AI-agent/editor config dir and wires a SessionStart hook so
the credential-stealer re-runs on every Claude Code / VS Code launch.
${COMMAND:+Command blocked: $COMMAND}

Immediate steps:
  1. Remove: command rm -f "$hp"
  2. Inspect SessionStart/PreToolUse hooks in .claude/settings.json (project AND
     ~/.claude/settings.json) for entries you did not add — the dropper injects one
  3. If ~/.claude/ is hit and you sync that dir across machines: STOP — do not
     sync (it would propagate). Clean the synced source first, then re-sync.
  4. Rotate: npm tokens, GitHub PATs/OIDC trusts, SSH keys, cloud creds
  5. git log --all --since="2026-04-01" for unexpected commits / impersonation
BODY
)"
done

# Agent-config injection CHAIN: the dropper wires itself into an AI-agent/editor
# config so it re-runs on launch — as a SessionStart hook (Mini Shai-Hulud) OR a
# rogue MCP server entry (SANDWORM_MODE) OR a VS Code task with "runOn":"folderOpen"
# (SAP-CAP/AntV wave: the task re-runs `node .claude/setup.mjs` on every project open).
# Detecting the WIRED entry (not just the file) catches the case where the dropper ran
# once, injected the config, then deleted its on-disk file. Schemas differ across tools,
# so scan EVERY string value. Two pattern classes flag: a known dropper token (e.g. a
# folderOpen task referencing setup.mjs) OR the file-LESS inline form — a hook/MCP entry
# whose command IS a remote-script-to-shell pipe (curl … | sh), which names no dropper
# file. MALWARE_REMOTE_EXEC_RE is shared with the git-hook scan below: same injected-
# command threat, so the same block-safe behavioral marker applies to both surfaces.
for cfg in \
  "${CWD}/.claude/settings.json"  "${HOME}/.claude/settings.json" \
  "${CWD}/.cursor/mcp.json"       "${HOME}/.cursor/mcp.json" \
  "${CWD}/.vscode/mcp.json"       "${HOME}/.continue/config.json" \
  "${CWD}/.vscode/tasks.json"     "${HOME}/.windsurf/mcp.json"; do
  [[ -f "$cfg" ]] || continue
  # del(.permissions): permission allow/deny rules legitimately carry behavioral
  # patterns (e.g. a `Bash(curl * | bash*)` DENY rule the user added for safety),
  # which would FP on MALWARE_REMOTE_EXEC_RE. They are user security POLICY, never the
  # executable wiring a dropper hijacks — the dropper injects .hooks/.mcpServers/tasks,
  # all of which survive the del. (No-op on the non-Claude configs without .permissions.)
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

# Git-hook / template-dir injection (SANDWORM_MODE): a poisoned pre-commit/pre-push
# hook — installed directly, or globally via init.templateDir, or per-repo via
# core.hooksPath — re-runs the dropper on every commit/push and silently adds the
# carrier dependency. This is a top "inject into a repo we pseudo-trust" vector.
git_hook_dirs=("${CWD}/.git/hooks")
tmpl_dir=$(git config --global --get init.templateDir 2>/dev/null) && [[ -n "$tmpl_dir" ]] && git_hook_dirs+=("${tmpl_dir/#\~/$HOME}/hooks")
hooks_path=$(git -C "$CWD" config --get core.hooksPath 2>/dev/null) && [[ -n "$hooks_path" ]] && git_hook_dirs+=("$hooks_path")
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

# gh-token-monitor persistence (LaunchAgent / systemd user unit).
for gp in \
  "${HOME}/Library/LaunchAgents/com.user.gh-token-monitor.plist" \
  "${HOME}/.config/systemd/user/gh-token-monitor.service"; do
  [[ -e "$gp" ]] || continue
  alert "GH-TOKEN-MONITOR PERSISTENCE DETECTED" "$(cat <<BODY
Found Shai-Hulud token-monitor persistence unit: $gp
This re-launches a GitHub-token harvester on login.

Immediate steps:
  1. Unload: launchctl unload "$gp" 2>/dev/null; command rm -f "$gp"
     (Linux: systemctl --user disable --now gh-token-monitor; rm "$gp")
  2. Rotate ALL GitHub PATs/OIDC trusts and npm tokens
  3. Check: ps aux | grep -i gh-token
BODY
)"
done

# kitty-monitor persistence (AntV/TeamPCP wave). A background daemon (cat.py) is
# installed under ~/.local/share/kitty/ and registered as a login-persistent unit —
# a LaunchAgent on macOS, a systemd user service on Linux — that polls the GitHub
# commit-search API hourly for attacker commands. Same class as gh-token-monitor above;
# the unit names and the cat.py path are campaign-specific (Snyk AntV, verbatim).
for kp in \
  "${HOME}/Library/LaunchAgents/com.user.kitty-monitor.plist" \
  "${HOME}/.config/systemd/user/kitty-monitor.service" \
  "${HOME}/.local/share/kitty/cat.py"; do
  [[ -e "$kp" ]] || continue
  alert "KITTY-MONITOR PERSISTENCE DETECTED" "$(cat <<BODY
Found AntV/TeamPCP-wave persistence artifact: $kp
This installs a background daemon (~/.local/share/kitty/cat.py) that polls the GitHub
commit-search API hourly for attacker commands — its presence means the payload has
ALREADY run on this machine.
${COMMAND:+Command blocked: $COMMAND}

Immediate steps:
  1. Unload: launchctl unload "\$HOME/Library/LaunchAgents/com.user.kitty-monitor.plist" 2>/dev/null
     (Linux: systemctl --user disable --now kitty-monitor)
  2. Remove: command rm -f "\$HOME/Library/LaunchAgents/com.user.kitty-monitor.plist" \\
       "\$HOME/.config/systemd/user/kitty-monitor.service" "\$HOME/.local/share/kitty/cat.py"
  3. Check: ps aux | grep -iE 'kitty.*cat\.py|cat\.py' (kill any running daemon)
  4. Rotate ALL GitHub PATs/OIDC trusts, npm tokens, SSH keys, cloud + LLM API keys
  5. git log --all --since="2026-04-01" for unexpected commits / impersonation
BODY
)"
done

# Hades/Miasma SSH-propagation dropper (PyPI wave). The JS stealer writes this to
# spread over SSH to other hosts — its presence means the payload already executed.
if [[ -f "/tmp/.sshu-setup.js" ]]; then
  alert "HADES SSH-PROPAGATION DROPPER DETECTED" "$(cat <<BODY
Found Hades/Miasma SSH-propagation dropper at: /tmp/.sshu-setup.js
This is written by the Bun-staged JS stealer to spread over SSH to other hosts —
its presence means the payload has ALREADY run on this machine.
${COMMAND:+Command blocked: $COMMAND}

Immediate steps:
  1. Remove: command rm -f /tmp/.sshu-setup.js
  2. Check: ps aux | grep -iE 'bun|_index\.js' (kill any running stager)
  3. Audit ~/.ssh/known_hosts + authorized_keys and recent SSH egress for spread
  4. Rotate ALL credentials (SSH keys, GitHub PATs/OIDC, npm/PyPI tokens, cloud)
  5. Inspect site-packages *.pth startup hooks (the PyPI delivery vector)
BODY
)"
fi

# Weaponized Python .pth startup hook (Hades/Miasma PyPI wave). A malicious PyPI
# package (MCP typosquats like openai-mcp / langchain-core-mcp) drops a *.pth into
# site-packages; Python AUTO-RUNS its import-prefixed line on every interpreter
# start, downloading Bun and executing the bundled _index.js stealer. This is a
# persistence hook in the same class as an injected SessionStart hook — caught here
# regardless of how it arrived (pip/uv are not gated). Bounded find over the
# project's venv layouts + any stray committed .pth; legit .pth files only touch
# sys.path, so MALWARE_PTH_RE (process spawn / socket / URL fetch / bun) is near-0 FP.
pth_files=()
while IFS= read -r _p; do [[ -n "$_p" ]] && pth_files+=("$_p"); done < <(
  timeout 5 find "${CWD}/.venv" "${CWD}/venv" "${CWD}/env" "${CWD}/.tox" \
    -maxdepth 4 -name '*.pth' -type f 2>/dev/null
)
for _p in "${CWD}"/*.pth; do [[ -f "$_p" ]] && pth_files+=("$_p"); done
if [[ ${#pth_files[@]} -gt 0 ]]; then
  for pth in "${pth_files[@]}"; do
    pth_reason="" pth_base="${pth##*/}"
    if [[ "$pth_base" == "$MALWARE_PTH_IOC_NAME" ]]; then
      pth_reason="known-bad filename ($MALWARE_PTH_IOC_NAME)"
    elif [[ "$(shasum -a 256 "$pth" 2>/dev/null | awk '{print $1}')" == "$MALWARE_PTH_IOC_HASH" ]]; then
      pth_reason="known-bad SHA256 ($MALWARE_PTH_IOC_HASH)"
    else
      pth_m=$(grep -niE "$MALWARE_PTH_RE" "$pth" 2>/dev/null | head -1)
      [[ -n "$pth_m" ]] && pth_reason="executes code on interpreter start: $pth_m"
    fi
    [[ -z "$pth_reason" ]] && continue
    alert "MALICIOUS PYTHON .pth STARTUP HOOK DETECTED" "$(cat <<BODY
A Python .pth startup hook runs code on every interpreter start:
  $pth
  $pth_reason
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

# Native import-time payload (Hades/Miasma PyPI wave): a compiled .abi3.so extension
# module that runs a credential stealer the moment Python imports the carrier package —
# the binary analogue of the .pth hook above, needing no install step and no .pth. A
# compiled binary is opaque to the content greps every other tier relies on, so the
# exact basename (MALWARE_NATIVE_SO_NAMES) is the only tree-scan handle. Same bounded
# venv walk as the .pth sweep; legit .abi3.so files are enumerated but only the two
# known-bad campaign artifacts flag (zero FP).
so_files=()
while IFS= read -r _s; do [[ -n "$_s" ]] && so_files+=("$_s"); done < <(
  timeout 5 find "${CWD}/.venv" "${CWD}/venv" "${CWD}/env" "${CWD}/.tox" \
    -maxdepth 4 -name '*.abi3.so' -type f 2>/dev/null
)
for _s in "${CWD}"/*.abi3.so; do [[ -f "$_s" ]] && so_files+=("$_s"); done
# Count-guard the iteration: under bash 3.2 + `set -u`, expanding "${so_files[@]}"
# on an EMPTY array is an unbound-variable error (mirrors the .pth block above).
if [[ ${#so_files[@]} -gt 0 ]]; then
for so in "${so_files[@]}"; do
  so_base="${so##*/}" so_bad=0
  for _bad in "${MALWARE_NATIVE_SO_NAMES[@]}"; do [[ "$so_base" == "$_bad" ]] && so_bad=1; done
  [[ "$so_bad" == 1 ]] || continue
  alert "MALICIOUS NATIVE PYTHON MODULE DETECTED" "$(cat <<BODY
A compiled Python extension matching a known Hades/Miasma payload is present:
  $so
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
  # Install-time: scan package.json lifecycle scripts for dropper patterns. This is
  # the one check that fires BEFORE malicious code executes (preinstall fires even
  # if install later fails), so it's the real pre-install gate.
  PKG_JSON="${CWD}/package.json"
  if [[ -f "$PKG_JSON" ]]; then
    bad_scripts=$(jq -r '.scripts // {} | to_entries[]
      | select(.key | test("^(pre|post)?install$|^prepare$"))
      | .value' "$PKG_JSON" 2>/dev/null \
      | grep -iE "$MALWARE_DROPPER_TOKENS_RE"'|bun\.sh/install|node .*\.cjs.*curl|curl[^|]*\|[^|]*(sh|node|bash)' || true)
    if [[ -n "$bad_scripts" ]]; then
      alert "MALICIOUS LIFECYCLE SCRIPT IN package.json" "$(cat <<BODY
package.json has an install-lifecycle script matching a known Shai-Hulud dropper:
$bad_scripts
${COMMAND:+Command blocked: $COMMAND}

This runs automatically on npm/pnpm/yarn/bun install (preinstall fires even if
install later fails). Do NOT install.
  1. git log -p -- package.json  (find who injected it)
  2. Reinstall third-party deps with --ignore-scripts until cleared
  3. Rotate npm tokens + GitHub PATs if this was already installed once
BODY
)"
    fi
  fi

  # Release-config poisoning (SANDWORM_MODE): an injected semantic-release / release-it
  # exec step that require()s a hidden carrier dep at publish time. `@semantic-release/
  # exec` alone is legit, so MALWARE_RELEASERC_RE matches only the carrier tell.
  for rc in "${CWD}/.releaserc" "${CWD}/.releaserc.json" "${CWD}/.releaserc.yaml" \
            "${CWD}/.releaserc.yml" "${CWD}/.release-it.json" "${CWD}/release.config.js"; do
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

  # Workflow poisoning (SANDWORM_MODE ci-quality campaign): known-bad action/persona
  # slugs in .github/workflows. pull_request_target alone is legit and NOT flagged —
  # only the campaign fingerprints (see MALWARE_WORKFLOW_RE) trip this.
  if [[ -d "${CWD}/.github/workflows" ]]; then
    wf_hit=$(grep -rilE "$MALWARE_WORKFLOW_RE" "${CWD}/.github/workflows" 2>/dev/null | head -1)
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
  fi

  # Project source scan: an attacker with repo write-access can inject the loader into
  # ANY file (Microsoft's case was server/routes/api/auth.js), so scan the tree broadly.
  # Narrow INJECT_RE keeps FPs down on minified bundles; build/VCS dirs excluded.
  # KEY-DECISION 2026-06-06: NO timeout on this grep. Tier 1 is the tier that BLOCKS,
  # so a truncated walk here is a coverage hole, not a graceful degradation. A 15s
  # ceiling once fired on a 149-file tree (4ms scan when healthy) purely from
  # post-wake system load — a false-alarm 🟡 with no self-healing. The walk is still
  # bounded by the hook-level `timeout` in hooks.json (the harness kills the whole
  # hook past that), which is set high enough that only a genuinely pathological
  # tree hits it.
  if _rg_ok "$MALWARE_INJECT_RE"; then
    inject_out=$("$RG_BIN" -la --no-ignore --hidden \
      -g '*.{js,mjs,cjs,ts,mts,cts,jsx,tsx}' \
      -g '!node_modules' -g '!.git' \
      -g '!dist' -g '!build' -g '!.next' -g '!.output' \
      -e "$MALWARE_INJECT_RE" "$CWD" 2>/dev/null)
  else
    inject_out=$(grep -rlE "$MALWARE_INJECT_RE" "$CWD" \
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
# Known payload filenames (name == proof) vs hash-IOC filenames (name needs hash
# confirmation; e.g. router_runtime.js can be legit). One find traversal for both.
PAYLOAD_FILES=(
  "setup_bun.js" "set_bun.js" "bun_environment.js" "com.apple.act.mond"
  "c0nt3nts.json" "c9nt3nts.json" "3nvir0nm3nt.json" "cl0vd.json"
  "actionsSecrets.json" "truffleSecrets.json" "gh-token-monitor.sh"
)
HASH_IOC_FILES=( "router_init.js" "router_runtime.js" "tanstack_runner.js" "opensearch_init.js" "setup_bun.js" "bun_environment.js" )
HASH_IOC_HASHES=(
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
  "1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898"
  "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
  "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
  "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"
  "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
)

if [[ "$RUN_T2" == 1 && -d "$NODE_MODULES" ]]; then
  # Single traversal for every IOC filename (was 17 separate find passes).
  find_expr=() ; first=1
  for n in "${PAYLOAD_FILES[@]}" "${HASH_IOC_FILES[@]}"; do
    if [[ $first == 1 ]]; then find_expr+=( -name "$n" ); first=0; else find_expr+=( -o -name "$n" ); fi
  done
  # Capture find's output (not a process substitution) so a timeout (exit 124) is
  # observable — a truncated walk must report ⚠️, not pass as clean.
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

Source: TanStack @tanstack/* supply-chain compromise. Exfil to filev2.getsession.org.
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

  # Content fingerprints: ONE combined gate pass (was 14 separate walks). On a hit —
  # rare — re-grep the single offending file per-pattern to name the campaign.
  # Name the engine in the timeout warning: "timed out" with no engine hid a
  # week of grep-fallback timeouts whose actual cause (no rg in the executing
  # copy) was diagnosable from the message alone. Engine label must be set
  # BEFORE the scan so the $? test still sees the scan's exit status.
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

# Refresh the scan cache only after a CLEAN, COMPLETE expensive scan (no alerts
# reached here; in pre_tool mode a finding would have emitted a deny and exited
# already). A timed-out walk (WARNINGS) is not a clean scan — don't cache it, so
# the next event retries the full walk.
if [[ "$UPDATE_CACHE" == 1 && -z "$ALERTS" && -z "$WARNINGS" && -d "$NODE_MODULES" ]]; then
  mkdir -p "$CACHE_DIR" && _scan_key > "$MARKER"
fi

# SessionStart/PostToolUse: deliver on BOTH channels — `systemMessage` is shown to
# the user directly (the loud part), `additionalContext` instructs the model to refuse
# follow-up installs. SessionStart can't abort, so this is the strongest startup signal.
if [[ "$MODE" != "pre_tool" && -n "$ALERTS" ]]; then
  evname="SessionStart"; [[ "$MODE" == "post_tool" ]] && evname="PostToolUse"
  count=$(printf '%s' "$SUMMARY" | grep -c '•')
  findings_json=$(printf '%s' "$FINDINGS" | jq -sc .)
  # Top-level `verdict` + `findings` are the machine-readable contract (extra keys are
  # ignored by Claude Code); systemMessage/additionalContext remain the human channels.
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

# ── Always-on status line ─────────────────────────────────────────────────────
# KEY-DECISION 2026-06-06: a clean pass prints 🟢 and a degraded pass 🟡 via
# `systemMessage` (the only channel guaranteed to reach the USER) so that silence
# is never ambiguous — before this, "scanned clean" and "hook never ran" looked
# identical, the same invisibility class as the "silent for a month" bug. Findings
# stay 🚨 via the alert paths above. No additionalContext on green/yellow: status
# is for the human; the model needs no instruction when nothing is wrong.
# Glyphs are 🟢/🟡 + a `[wormhook]` tag (not ✅/⚠️) to match the traffic-light
# convention of sibling SessionStart status hooks, so multiple lights read as one
# uniform dashboard strip.
if [[ -z "$ALERTS" ]]; then
  SCOPE="persistence"
  [[ "$RUN_T1" == 1 ]] && SCOPE+=" + source"
  if [[ "$RUN_T2" == 1 && -d "$NODE_MODULES" ]]; then
    SCOPE+=" + node_modules"
  elif [[ -d "$NODE_MODULES" ]]; then
    SCOPE+=" + node_modules (cached, deps unchanged)"
  fi
  # Scan-runtime suffix " (x.xs)" — SessionStart only, matching the doctor dashboard lights it sits
  # beside. The per-turn/blocking events (pre_tool/post_tool/prompt_submit) stay unsuffixed: their
  # latency is the user's own command, not a dashboard metric. Guard on a non-empty stamp before
  # subtracting — a `:-0` default would make jq report `now - 0` (the whole Unix epoch) as the scan
  # time; an empty stamp (jq-now failed at startup) short-circuits to "(0.0s)".
  DUR=""
  if [[ "$MODE" == "session_start" ]]; then
    __elapsed=0
    [[ -n "${WH_T0:-}" ]] && __elapsed=$(jq -n --argjson t0 "$WH_T0" 'now - $t0' 2>/dev/null || echo 0)
    DUR=" ($(printf '%.1f' "$__elapsed")s)"
  fi
  if [[ -n "$WARNINGS" ]]; then
    # A degraded pass speaks on EVERY event, including prompt_submit — a silently degraded
    # continuous monitor is the invisibility bug all over again.
    jq -nc --arg msg "🟡 [wormhook] passed with caveats ($SCOPE)$DUR — $WARNINGS" '{verdict: "yellow", systemMessage: $msg}'
  elif [[ "$MODE" != "prompt_submit" ]]; then
    # Clean 🟢 is suppressed for prompt_submit ONLY: it fires every human turn, so a 🟢 each
    # time would spam the transcript. The continuous monitor stays silent when healthy and
    # speaks only on a finding (🚨 block above) or degradation (🟡 above). (Note: the SessionStart
    # doctor checks, by contrast, now emit a 🟢 every session — that is the dashboard, not a per-turn monitor.)
    jq -nc --arg msg "🟢 [wormhook] clean ($SCOPE)$DUR" '{verdict: "green", systemMessage: $msg}'
  fi
fi

exit 0
