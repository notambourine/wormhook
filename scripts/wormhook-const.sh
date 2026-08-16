# shellcheck shell=bash
# shellcheck disable=SC2034  # these are consumed by the scripts that source this file
# Shared constants for the out-of-band surface, sourced by the writer (wormhook-scan.sh) and the
# reader (doctor/coverage.sh) alike, so a rename cannot drift between them and make the doctor
# lie forever. Pure assignments only — no logic, no jq, no command substitution — so a corrupt
# copy leaves them unset and coverage.sh self-skips instead of reporting a false ✗.

# Deliberately NOT a string any IOC set matches, so the engine cannot flag our own agent.
WORMHOOK_LAUNCHD_LABEL="com.notambourine.wormhook-sweep"

# install writes these, status/doctor detect them, uninstall strips between them — all keyed
# on byte-for-byte agreement here.
WORMHOOK_HOOK_MARKER="# >>> wormhook >>>"
WORMHOOK_HOOK_MARKER_END="# <<< wormhook <<<"
