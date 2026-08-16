#!/bin/bash
# SessionStart doctor — blast-radius exposure audit (issue #15): long-lived secrets sitting in
# the exact paths the worms harvest, answering "how bad if detection misses". Advisory only.
# No secret VALUE ever reaches the message, only paths. Held to three near-zero-FP checks so it
# stays a punch list, not a nag (npm-token and static-AWS-creds candidates stay deferred).
#   🟡 N secret class(es) found.  Nothing found => silent.
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

audit=()

# 1) Passphrase-less SSH keys. `ssh-keygen -y -P ''` exits 0 only on a key with no passphrase and
#    never prompts — grepping "ENCRYPTED" instead would miss the new OpenSSH key format.
if command -v ssh-keygen >/dev/null 2>&1; then
  _open=()
  for _k in "$HOME"/.ssh/*; do
    [[ -f "$_k" ]] || continue
    case "$_k" in *.pub|*/known_hosts|*/known_hosts.old|*/config|*/authorized_keys|*/authorized_keys2) continue ;; esac
    ssh-keygen -y -P '' -f "$_k" >/dev/null 2>&1 && _open+=("$(basename "$_k")")
  done
  (( ${#_open[@]} )) && audit+=("passphrase-less SSH private key(s) in ~/.ssh: ${_open[*]} — add a passphrase (ssh-keygen -p) or move to a hardware/agent-held key")
fi

# 2) Plaintext GitHub token. A classic PAT (ghp_) does NOT expire by default — the worst exfil
#    prize; gho_ is the gh-CLI equivalent. Prefix match only; the value is never echoed.
_pat=0
for _f in "$HOME/.git-credentials" "$HOME/.config/gh/hosts.yml"; do
  [[ -f "$_f" ]] && grep -Eq 'gh[po]_[A-Za-z0-9]{20,}' "$_f" 2>/dev/null && _pat=1
done
for _v in "${GH_TOKEN:-}" "${GITHUB_TOKEN:-}"; do
  case "$_v" in ghp_*|gho_*) _pat=1 ;; esac
done
(( _pat )) && audit+=("plaintext GitHub token (classic ghp_/oauth gho_) in ~/.git-credentials, gh config, or env — prefer a fine-grained, expiring PAT or a credential helper")

# 3) Requiring a real token SHAPE (not merely KEY=…) keeps this off every .env placeholder.
if [[ -f "$PWD/.env" ]] && \
   grep -Eq '(AKIA[0-9A-Z]{16}|gh[posru]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)' "$PWD/.env" 2>/dev/null; then
  audit+=("plaintext .env in this repo holds a live-looking secret — inject from a secrets manager and keep .env out of git")
fi

(( ${#audit[@]} == 0 )) && exit 0

msg="🟡 [wormhook] exposure — ${#audit[@]} long-lived secret class(es) in worm-targeted paths (what gets exfiltrated if detection misses):"
for _l in "${audit[@]}"; do msg+=$'\n  • '"$_l"; done
msg+=$'\n  ↳ shrink the blast radius: passphrase-protect keys, prefer short-lived/fine-grained tokens, keep secrets in a manager not plaintext .env. [advisory only]'
ctx="[exposure-audit] Advisory only — NEVER blocks. ${#audit[@]} class(es) of long-lived secret sit in paths supply-chain worms harvest. Surface to the user only when relevant (working with keys/tokens/secrets); suggest shrinking the blast radius."
wh_emit_ctx "$msg" "$ctx"
exit 0
