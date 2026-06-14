#!/bin/bash
# Environment doctor: SILENT when wormhook's runtime deps are healthy AND its recommended
# companion install-firewalls are present AND the out-of-band triggers are wired; otherwise
# one 🟡 message with a per-item checklist. Runs at SessionStart alongside the scanner. Each
# soft item carries a [silence: WORMHOOK_SKIP_<ITEM>=1] hint so a consciously-declined nudge
# can be muted (repo or user settings.json "env"); WORMHOOK_DOCTOR_QUIET=1 mutes all soft items.
#
# Three jobs: (1) wormhook's own runtime deps (jq hard, ripgrep soft, version drift) +
# out-of-band coverage; (2) a nudge to install the install-time firewall layer wormhook
# deliberately does NOT do itself (Socket Firewall + safedep/vet) — registry intelligence,
# malicious-version blocking, typosquat/age scoring. wormhook is the local lock; those own
# the registry boundary. "Run alongside, not instead" — see README.
# (3) an OPT-IN blast-radius exposure audit (WORMHOOK_POSTURE_AUDIT) — a read-only punch
# list of high-value, long-lived secrets sitting in the exact paths the worms harvest. This
# is the "how bad if detection misses" layer (issue #15), not detection itself: it is
# ADVISORY ONLY and can NEVER block (doctor.sh emits systemMessage, never a decision).
# Default OFF — a passphrase-less key you have accepted is a nag, not an IOC; opt in
# per-machine and measure the noise before it earns a default-on slot.
#
# KEY-DECISION 2026-06-13: hybrid jq model (supersedes the 2026-06-06 "fully jq-free" rule).
# The ONE thing doctor exists to catch is "jq is missing => the scanner is silently OFF" —
# the same failure class as the "silent for a month" bug. That single alarm MUST therefore
# emit without jq, so it stays a hand-rolled static printf in the early-exit below. EVERYTHING
# ELSE only matters when jq is present (a missing-jq machine has no working scanner to nudge
# about), so it is built with `jq --arg`. That buys two things the old static-only rule cost
# us: real newlines instead of literal \n bookkeeping, and injection-safe interpolation of
# dynamic content (version strings, key filenames, the finding count) — so the exposure audit
# can name the actual offending key files without being an injection hole. The rule is now:
# the jq-missing alarm is static and dependency-free; every other line goes through jq --arg.
set -uo pipefail

# ── The one irreducible static line ─────────────────────────────────────────────────────
# jq is the scanner's HARD dependency: without it wormhook.sh exits on stderr only (invisible
# in the TUI) and scans are OFF. doctor must say so WITHOUT needing jq itself. Hand-rolled,
# fully static, no interpolation — and never silenceable (muting it would reinstate the
# invisible-failure bug doctor exists to catch). Everything past here may rely on jq.
if ! command -v jq &>/dev/null; then
  printf '{"systemMessage":"🟡 [wormhook] jq missing — scans are OFF (brew install jq)"}\n'
  exit 0
fi

# notes[] = setup/firewall/coverage checklist · audit[] = exposure-audit findings. Both are
# joined and JSON-encoded once, at the end, by jq --arg — so any line may carry dynamic content.
notes=(); audit=()
note() { notes+=("$1"); }
# Per-item noise control: set WORMHOOK_SKIP_<ITEM>=1 — in repo .claude/settings.json or user
# ~/.claude/settings.json "env" — to silence a nudge you have consciously declined; or
# WORMHOOK_DOCTOR_QUIET=1 to mute every soft nudge below.
QUIET="${WORMHOOK_DOCTOR_QUIET:-}"
# soft <skip-var-value> <message>: record a silenceable nudge unless its skip var (or QUIET) is set.
soft() { [[ -n "$QUIET" || -n "$1" ]] && return 0; note "$2"; }

# Shared launchd-label + git-hook-marker constants (single source — see wormhook-const.sh),
# so the coverage probe below detects exactly what wormhook-scan.sh installs. If absent (corrupt
# install), the constants stay unset and the coverage block self-skips.
# shellcheck source=scripts/wormhook-const.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/wormhook-const.sh" 2>/dev/null || true

# ripgrep: soft dependency — content scans fall back to single-core grep
# (measured 30.3s vs 0.7s on a 58k-file node_modules).
command -v rg &>/dev/null || \
  soft "${WORMHOOK_SKIP_RG:-}" "ripgrep not found — content scans use slow grep fallback (brew install ripgrep) [silence: WORMHOOK_SKIP_RG=1]"

# Companion install-firewalls (NOT wormhook deps — the layer it cedes the registry
# boundary to). wormhook is local/no-network by design; these own malicious-version
# blocking, typosquats, and publish-age/reputation scoring at install time.
#   - Socket Firewall (sfw): wraps the package manager and blocks risky installs live.
#   - safedep/vet: dependency CVE + malicious-package + license scan.
# NB: Socket Firewall had an untrusted-dir .sfw.config RCE (CVE-2025-64726, fixed 0.15.5);
# the nudge says "keep it current" rather than pin a version floor — a hard-coded floor goes stale.
command -v sfw &>/dev/null || \
  soft "${WORMHOOK_SKIP_SFW:-}" "Socket Firewall (sfw) not found — install-time registry firewall missing; pair it with wormhook and keep it current (install: https://docs.socket.dev/docs/socket-firewall) [silence: WORMHOOK_SKIP_SFW=1]"
command -v vet &>/dev/null || \
  soft "${WORMHOOK_SKIP_VET:-}" "safedep/vet not found — no dependency CVE/malicious-package audit (install: https://github.com/safedep/vet) [silence: WORMHOOK_SKIP_VET=1]"

# Out-of-band coverage: which non-Claude triggers are wired (CLI on PATH / global git
# hook / hourly launchd sweep). Silent when all three are set up; otherwise one line
# showing the full ✓/✗ picture and pointing at the in-Claude installer.
# Self-skip if the shared constants did not load (corrupt install).
if [[ -n "${WORMHOOK_HOOK_MARKER:-}" && -n "${WORMHOOK_LAUNCHD_LABEL:-}" ]]; then
_cli=✗; command -v wormhook-scan &>/dev/null && _cli=✓
# git-hook is ✓ only when ALL THREE hooks the installer writes carry the marker —
# checking just post-merge would report full coverage on a partial/corrupted install.
_hook=✗
_hd=$(git config --global --get core.hooksPath 2>/dev/null); _hd="${_hd/#\~/$HOME}"
if [[ -n "$_hd" ]]; then
  _hk=0
  for _h in post-merge post-checkout post-rewrite; do
    [[ -f "$_hd/$_h" ]] && grep -qF "$WORMHOOK_HOOK_MARKER" "$_hd/$_h" 2>/dev/null && _hk=$((_hk+1))
  done
  [[ "$_hk" == 3 ]] && _hook=✓
fi
if [[ "$(uname -s)" == "Darwin" ]]; then
  _sweep=✗; launchctl print "gui/$(id -u)/$WORMHOOK_LAUNCHD_LABEL" &>/dev/null && _sweep=✓
else
  _sweep="n/a"
fi
if [[ "$_cli" == "✗" || "$_hook" == "✗" || "$_sweep" == "✗" ]]; then
  soft "${WORMHOOK_SKIP_COVERAGE:-}" "out-of-band coverage — CLI:$_cli git-hook:$_hook hourly-sweep:$_sweep — run /wormhook-setup in Claude to finish [silence: WORMHOOK_SKIP_COVERAGE=1]"
fi
fi

# Version drift: a `/plugin` marketplace refresh updates the clone but NOT the
# install pointer in installed_plugins.json, so the executing copy can lag the
# marketplace indefinitely (a stale pre-ripgrep install once spent 6 days
# timing out at 20s per session while the fix sat unused in the cache). The
# executing copy lives at plugins/cache/<marketplace>/<plugin>/<version>/;
# compare its manifest version against the marketplace clone's. No match on
# the cache layout (e.g. running from a dev checkout) => skip silently. The
# version strings flow through jq --arg at emit time, so no whitelist is needed.
_ver() { sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -n1; }
PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$PLUGIN_ROOT" in
  */plugins/cache/*/*/*)
    mkt="${PLUGIN_ROOT#*/plugins/cache/}"; mkt="${mkt%%/*}"
    self_ver=$(_ver "$PLUGIN_ROOT/.claude-plugin/plugin.json")
    mkt_ver=$(_ver "${PLUGIN_ROOT%/cache/*}/marketplaces/$mkt/.claude-plugin/plugin.json")
    if [[ -n "$self_ver" && -n "$mkt_ver" && "$self_ver" != "$mkt_ver" ]]; then
      soft "${WORMHOOK_SKIP_DRIFT:-}" "running v$self_ver but marketplace has v$mkt_ver — run: claude plugin update wormhook@$mkt [silence: WORMHOOK_SKIP_DRIFT=1]"
    fi
    ;;
esac

# ── Blast-radius exposure audit (issue #15) — OPT-IN, advisory, never blocks. ────────────
# A read-only punch list of long-lived secrets sitting in the exact paths the worms harvest:
# "how bad if detection misses." All checks are pure stat/grep. Findings flow through jq --arg
# at emit time, so a finding may safely name the actual offending file — no secret VALUE is
# ever read into the message, only paths/filenames. Scoped to the three lowest-FP checks from
# the issue's "suggested next step" (passphrase-less SSH · plaintext GitHub token · live-looking
# .env); the npm-token and static-AWS-creds candidates are deferred until these three's FP rate
# is measured on real machines.
case "${WORMHOOK_POSTURE_AUDIT:-}" in
  ""|0|false|no|off|FALSE|NO|OFF) ;;  # default OFF — opt in per-machine
  *)
    # 1) Passphrase-less SSH private keys. `ssh-keygen -y -P '' -f <key>` exits 0 ONLY when the
    #    key has no passphrase (it never prompts, because -P supplies one) — more robust than
    #    grepping for "ENCRYPTED", which misses the new OpenSSH key format. One ~/.ssh sweep
    #    (skip pubkeys/known_hosts/config); ssh-keygen rejects non-keys, so the survivors are
    #    real private keys. Names them in the finding (jq --arg makes that injection-safe).
    if command -v ssh-keygen &>/dev/null; then
      _open=()
      for _k in "$HOME"/.ssh/*; do
        [[ -f "$_k" ]] || continue
        case "$_k" in *.pub|*/known_hosts|*/known_hosts.old|*/config|*/authorized_keys|*/authorized_keys2) continue ;; esac
        ssh-keygen -y -P '' -f "$_k" &>/dev/null && _open+=("$(basename "$_k")")
      done
      (( ${#_open[@]} )) && audit+=("passphrase-less SSH private key(s) in ~/.ssh: ${_open[*]} — add a passphrase (ssh-keygen -p) or move to a hardware/agent-held key")
    fi
    # 2) Plaintext GitHub token on disk or in env. A classic PAT (ghp_) does NOT expire by
    #    default — the worst exfil prize; an OAuth token (gho_) is the gh-CLI equivalent. Match
    #    the token PREFIX only; the matched value is never echoed.
    _pat=0
    for _f in "$HOME/.git-credentials" "$HOME/.config/gh/hosts.yml"; do
      [[ -f "$_f" ]] && grep -Eq 'gh[po]_[A-Za-z0-9]{20,}' "$_f" 2>/dev/null && _pat=1
    done
    for _v in "${GH_TOKEN:-}" "${GITHUB_TOKEN:-}"; do
      case "$_v" in ghp_*|gho_*) _pat=1 ;; esac
    done
    (( _pat )) && audit+=("plaintext GitHub token (classic ghp_/oauth gho_) in ~/.git-credentials, gh config, or env — prefer a fine-grained, expiring PAT or a credential helper")
    # 3) A .env in the working directory carrying a *recognizable* live credential (not merely
    #    KEY=…) — requiring a real token shape (AWS AKIA / GitHub / OpenAI sk- / Google AIza /
    #    PEM private key) keeps this near-zero-FP versus flagging every .env placeholder.
    if [[ -f "$PWD/.env" ]] && \
       grep -Eq '(AKIA[0-9A-Z]{16}|gh[posru]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)' "$PWD/.env" 2>/dev/null; then
      audit+=("plaintext .env in this repo holds a live-looking secret — inject from a secrets manager and keep .env out of git")
    fi
    ;;
esac

# Assemble the one-object payload. The hook protocol allows EXACTLY ONE JSON object on stdout,
# so every 🟡 block lands inside a single systemMessage built here with real newlines and
# JSON-encoded once by jq --arg (which escapes everything — the reason any line above may carry
# dynamic content). Each block is included only when it has at least one line. The count check
# also guards the bash 3.2 quirk where "${arr[@]}" on an empty array trips set -u.
msg=""
if (( ${#notes[@]} )); then
  msg="🟡 [wormhook] setup notes (each line silenceable — see [silence: …]):"
  for _l in "${notes[@]}"; do msg+=$'\n  • '"$_l"; done
fi
if (( ${#audit[@]} )); then
  [[ -n "$msg" ]] && msg+=$'\n'
  msg+="🟡 [wormhook] exposure audit — ${#audit[@]} long-lived secret class(es) in worm-targeted paths (what gets exfiltrated if detection misses):"
  for _l in "${audit[@]}"; do msg+=$'\n  • '"$_l"; done
  msg+=$'\n  ↳ shrink the blast radius: passphrase-protect keys, prefer short-lived/fine-grained tokens, keep secrets in a manager not plaintext .env. [advisory only; export WORMHOOK_POSTURE_AUDIT=0 to mute]'
fi
[[ -z "$msg" ]] && exit 0
jq -cn --arg m "$msg" '{systemMessage:$m}'
