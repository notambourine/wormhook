# shellcheck shell=bash
# shellcheck disable=SC2034  # these are consumed by the scripts that source this file
# Shared constants for the wormhook out-of-band surface. Sourced by BOTH wormhook-scan.sh
# (the installer/status — writes the launchd plist + git-hook marker) and doctor/coverage.sh
# (via doctor/_utils.sh — the coverage probe reads them). Single definition so a rename of the
# launchd label or the git-hook marker can NOT drift between the writer and the reader (the
# "doctor lies forever" failure the README warns about).
#
# Pure assignments only — NO logic, NO jq, NO command substitution. Keep it dependency-light so
# the sourcing checks stay simple; absent/corrupt, the constants stay unset and coverage.sh
# self-skips to ⚪ rather than reporting a false ✗.
# Not executable; no shebang (it is only ever sourced).

# launchd LaunchAgent label for the hourly sweep. Org-namespaced; deliberately NOT a string
# any IOC set matches (see README — keeps the engine from flagging our own agent).
WORMHOOK_LAUNCHD_LABEL="com.notambourine.wormhook-sweep"

# Delimiters of the block appended to a global git hook. install writes them, status/doctor
# detect them, uninstall strips between them — all keyed on byte-for-byte agreement here.
WORMHOOK_HOOK_MARKER="# >>> wormhook >>>"
WORMHOOK_HOOK_MARKER_END="# <<< wormhook <<<"
