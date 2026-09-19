# Maintain wormhook

Keep detection local, blocks precise, and incomplete coverage visible.

- Keep detection and signatures in `scripts/`, event wiring in `hooks/`, and adapters free of detection logic. Preserve one registered object per event and hook filters broad enough to reach every engine command class.
- Preserve compound commands, environment prefixes, directory options, target directories, and workspace lifecycle checks. Never run an interpreter to discover startup files that it could execute.
- Never cache persistence or source scans, time out source scans, or cache incomplete results. Invalidate dependency caches when the engine or corpus changes. Report missing signatures and scan failures; fail open in interactive hooks.
- Limit hard blocks to PreToolUse and UserPromptSubmit. Preserve their distinct decision schemas and keep clean prompts silent. Pass untrusted values through `jq --arg`.
- Require primary-source evidence and near-zero false positives for blocking signatures. Route ambiguous indicators to warnings. Follow `.claude/skills/` for campaign reviews; update the review date only after checking advisories.
- Keep quarantine opt-in, reversible, and exact-match-only. Never kill, unload, or delete artifacts. Preserve symlink targets.
- Preserve Bash 3.2 compatibility and Bash/Zsh-compatible signature regexes. Source shared helpers; never execute them. Avoid apostrophes in heredocs nested inside command substitution.
- Keep `scripts/doctor/` checks local, silent when healthy or inapplicable, and limited to one JSON object per registered check. Give each concern one executable script and one SessionStart command. Treat configuration text as evidence of setup, never proof of enforcement.
- Let the dependency doctor alone print the static missing-jq alarm before sourcing helpers; register it before other doctors. Keep missing-jq and integrity alarms unsilenceable. Show acknowledged optional findings as ⚪ instead of hiding them.
- Preserve adapter exit codes: 0 clean, 1 findings, 2 review needed or incomplete coverage. Keep git hooks advisory and let shell guards block only findings. Keep the Action a verdict adapter and require branch protection to gate merges.
- Keep installers opt-in, idempotent, reversible, and non-clobbering. Preserve existing git hooks and hook paths; escape plist values. Keep generated hooks free of dropper tokens.
- Keep launcher identity stable across releases. Prefer the installed-plugin manifest, then the pointer file. Bake the config path into launchd launchers and remove legacy symlinks before copying over them.
- Discover repositories beneath scan roots while pruning dependencies. Honor literal mode and per-machine config. Load shell guards after version managers, compose with Socket Firewall, and never wrap node. Keep double-underscore helpers because Claude shell snapshots omit single-underscore functions.
- Regenerate the integrity manifest after engine or corpus edits. Bump plugin metadata for behavior changes. Leave CI-covered checks to CI; run local checks only to reproduce fixes or verify macOS compatibility. Check emitted shell code when changing its generator.
- Keep operational guidance in the README, campaign coverage in the plugin description, and advisory provenance beside the corpus. Publish through the existing `notambourine/claude` marketplace row; never add a marketplace here.
- Keep maintainer instructions in this file only. Allow only the root maintainer-context warning during schema validation.
