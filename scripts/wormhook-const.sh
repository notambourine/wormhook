# shellcheck shell=bash
# shellcheck disable=SC2034  # these are consumed by the scripts that source this file

# Keep this label outside the IOC sets to avoid self-detection.
WORMHOOK_LAUNCHD_LABEL="com.notambourine.wormhook-sweep"

WORMHOOK_HOOK_MARKER="# >>> wormhook >>>"
WORMHOOK_HOOK_MARKER_END="# <<< wormhook <<<"
