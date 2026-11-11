# shellcheck shell=bash
# shellcheck disable=SC2034  # these are consumed by the scripts that source this file

# Keep this label outside the IOC sets to avoid self-detection.
WORMHOOK_LAUNCHD_LABEL="com.notambourine.wormhook-sweep"

WORMHOOK_HOOK_MARKER="# >>> wormhook >>>"
WORMHOOK_HOOK_MARKER_END="# <<< wormhook <<<"

WORMHOOK_CHAIN_MARKER="# >>> wormhook chain >>>"
WORMHOOK_CHAIN_MARKER_END="# <<< wormhook chain <<<"
# reference-transaction and post-index-change fire per ref or index write; a shim there slows git.
WORMHOOK_CHAIN_HOOKS="applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg commit-msg post-commit pre-rebase post-checkout post-merge pre-push post-rewrite pre-auto-gc push-to-checkout sendemail-validate"
