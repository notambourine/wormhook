#!/bin/bash
set -uo pipefail

# shellcheck source=scripts/doctor/_utils.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/_utils.sh"

audit=()

# ssh-keygen handles OpenSSH keys that lack an ENCRYPTED header without prompting.
if command -v ssh-keygen >/dev/null 2>&1; then
  _open=()
  for _k in "$HOME"/.ssh/*; do
    [[ -f "$_k" ]] || continue
    case "$_k" in *.pub|*/known_hosts|*/known_hosts.old|*/config|*/authorized_keys|*/authorized_keys2) continue ;; esac
    ssh-keygen -y -P '' -f "$_k" >/dev/null 2>&1 && _open+=("$(basename "$_k")")
  done
  (( ${#_open[@]} )) && audit+=("passphrase-less SSH private key(s) in ~/.ssh: ${_open[*]} — add a passphrase (ssh-keygen -p) or move to a hardware/agent-held key")
fi

_pat=0
for _f in "$HOME/.git-credentials" "$HOME/.config/gh/hosts.yml"; do
  [[ -f "$_f" ]] && grep -Eq 'gh[po]_[A-Za-z0-9]{20,}' "$_f" 2>/dev/null && _pat=1
done
for _v in "${GH_TOKEN:-}" "${GITHUB_TOKEN:-}"; do
  case "$_v" in ghp_*|gho_*) _pat=1 ;; esac
done
(( _pat )) && audit+=("plaintext GitHub token (classic ghp_/oauth gho_) in ~/.git-credentials, gh config, or env — prefer a fine-grained, expiring PAT or a credential helper")

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
