---
paths:
  - "scripts/wormhook-scan.sh"
  - "scripts/wormhook-scan.conf.sample"
  - "action.yml"
  - "commands/wormhook-setup.md"
---

# Maintain scan adapters

Reuse the engine and preserve its verdict across every entry point.

- Synthesize hook payloads with `jq --arg`; never duplicate detection in adapters. Return 0 for clean, 1 for findings, and 2 for degraded coverage. Keep git hooks advisory and let shell guards block only findings.
- Keep installers opt-in, idempotent, reversible, and non-clobbering. Preserve existing git hooks and hook paths. Escape plist values. Keep generated hook bodies free of dropper tokens so they cannot self-flag.
- Keep executable launcher identity stable across releases to avoid repeated macOS background-item alerts. Prefer the installed-plugin manifest, then the pointer file. Bake the config path into the launcher for launchd environments without XDG variables. Remove legacy symlinks before copying over them.
- Discover repositories beneath scan roots while pruning dependencies. Honor literal mode and per-machine config. Load optional package-manager wrappers after version managers, compose with Socket Firewall, and never wrap node. Keep double-underscore helpers: Claude shell snapshots omit single-underscore functions.
- Keep the Action a verdict adapter. Require a protected-branch check to gate merges. Bump plugin metadata for adapter behavior changes and verify emitted shell code as well as the generator.
