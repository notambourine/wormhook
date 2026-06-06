#!/bin/bash
# Environment doctor: SILENT when wormhook's runtime deps are healthy, one 🟡
# line when something is missing or degraded. Runs at SessionStart alongside the
# scanner.
#
# KEY-DECISION 2026-06-06: deliberately jq-free. This is the watchdog for the
# case where wormhook.sh itself can't run (missing jq exits it on stderr only —
# invisible in the TUI, the same failure class as the "silent for a month" bug),
# so it may rely on nothing but bash. Hand-rolled JSON is safe here precisely
# because every output string is STATIC — nothing untrusted is interpolated
# (contrast wormhook.sh, which embeds scanned paths/commands and must route
# them through jq --arg to stay injection-proof). Do not add dynamic content
# to these messages without switching the emission to jq.
set -uo pipefail

missing=""
note() { missing="${missing:+$missing; }$1"; }

# jq: hard dependency — without it the scanner is OFF, not degraded.
command -v jq &>/dev/null || \
  note "jq missing — scans are OFF (brew install jq)"

# ripgrep: soft dependency — content scans fall back to single-core grep
# (measured 30.3s vs 0.7s on a 58k-file node_modules).
command -v rg &>/dev/null || \
  note "ripgrep not found — content scans use slow grep fallback (brew install ripgrep)"

[[ -z "$missing" ]] && exit 0
printf '{"systemMessage":"🟡 [wormhook] %s"}\n' "$missing"
exit 0
