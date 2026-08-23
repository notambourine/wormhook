# Maintain wormhook

Treat `README.md` as the user-facing contract. Keep only maintainer rules here.

## Work from these sources

- Use `scripts/wormhook.sh` as the engine. It reads hook JSON from stdin, dispatches on
  `hook_event_name` and command class, runs Tiers 0–2, and emits the verdict.
- Put every signature in `scripts/malware-patterns.sh`. Use extended regular expressions
  that parse identically in Bash and Zsh.
- Keep one SessionStart health concern in each `scripts/doctor/*.sh` file. Read
  `scripts/doctor/CLAUDE.md` before editing one. Source `_utils.sh`; never execute it.
- Keep fleet scans, launchd, the global git hook, and shell integration in
  `scripts/wormhook-scan.sh` and its sample config. Follow `.claude/rules/scan-adapters.md`
  when changing an adapter contract.
- Wire events in `hooks/hooks.json`. Keep plugin metadata in `.claude-plugin/plugin.json`.

## Preserve these invariants

- Bump `.claude-plugin/plugin.json` for every behavior PR that changes `scripts/` or
  `hooks/`. Do not bump it for docs-only changes.
- Do not add `marketplace.json`. Publish this plugin through its row in
  `notambourine/claude`.
- Give the marketplace row the browse tagline. Limit `plugin.json`'s description to
  campaign, IOC, and blocking detail. Put operational surfaces in `README.md`. Do not sync
  the two descriptions or add a parity check. Do not use Markdown links in `plugin.json`'s
  description.
- Keep the root `CLAUDE.md` warning as the sole allowlisted warning in `validate.yml`.
- Let only `doctor/deps.sh` print `jq missing, scans are OFF` without `jq`. Keep that static
  `printf` before any `jq` use. Let every other doctor source `_utils.sh` and inherit its
  `command -v jq || exit 0` guard. Use `jq --arg` after the guard. Keep `deps.sh` first in
  `hooks.json`.
- Route every untrusted path and command in `wormhook.sh` through `jq --arg`.
- Run Tier 0 on every event. Never cache it.
- Fail open and report 🟡 when signatures are missing or a scan times out. Do not refresh
  the clean cache after degraded coverage. Do not apply a timeout to Tier 1.
- Scale false-positive tolerance with blast radius. Require evidence-backed, near-zero-FP
  signatures in a blocking tier. Move noisy but useful behavior to a warning tier; do not
  delete it.
- Keep quarantine opt-in, reversible, and exact-match-only. Let
  `WORMHOOK_QUARANTINE=1` rename eligible Tier-0 artifacts to
  `<path>.wormhook-quarantined.<epoch>`, apply `chmod 000`, and log to the cache directory.
  Limit eligibility to `WORMHOOK_PERSIST_*`, known-bad `.pth` names or hashes, and
  known-bad `.abi3.so` basenames. Never quarantine a behavioral match. Never kill, unload,
  or delete. Degrade to an advisory when rename fails.
- Regenerate `scripts/integrity.sha256` after editing `wormhook.sh` or
  `malware-patterns.sh`:

  ```bash
  (cd scripts && shasum -a 256 wormhook.sh malware-patterns.sh > integrity.sha256)
  ```

- Keep the integrity and missing-`jq` alarms unsilenceable.
- Make no network calls. Leave registry intelligence, typosquat detection, publish age, and
  malicious-version blocking to Socket Firewall and `safedep/vet`.
- Update `WORMHOOK_SIGNATURES_ASOF` on every signature review, including reviews that add no
  patterns. Let `doctor/sigage.sh` warn after `WORMHOOK_SIGAGE_MAX_DAYS`, default 60.

## Preserve dispatch behavior

Match commands per subcommand, not against the raw command string. Split on `;`, `&&`, `||`,
and `|`. Strip leading `VAR=value` assignments, a bare `env` prefix, and directory-option
pairs (`--prefix`, `--cwd`, `--dir`, or `-C` plus their value). Keep `^\s*` anchored to a
segment start. Gate commands such as `cd sub && npm install`, `CI=1 npm install`, and
`npm --prefix X install`.

Scan `~/.claude`, `$CWD`, and each target directory addressed by the command. Track `cd`
across segments and honor directory options. For lifecycle gates, scan every target
workspace manifest from `package.json` workspaces and `pnpm-workspace.yaml`. Keep Tier 2 and
its cache rooted at `$CWD`.

Allow only `PreToolUse` and `UserPromptSubmit` to hard-block. Make `PreToolUse` emit
`hookSpecificOutput.permissionDecision: "deny"`. Make `UserPromptSubmit` emit top-level
`decision: "block"`. Let `SessionStart` and `PostToolUse` warn only.

- Run `GIT_RE` only at `PostToolUse`, after the rewritten files exist.
- Run `PYGATE_RE` for `pip`, `pip3`, `pipx`, `uv`, `python`, and `python3` at `PreToolUse`.
  Limit it to Tiers 0 and 1. Run `PYINSTALL_RE` after installs to rescan Tiers 0 and 1.
  Leave `make` and direct `./` execution ungated.
- Run `UserPromptSubmit` on every human turn with Tiers 0 and 1 only. Keep it silent when
  clean and visible when degraded. Keep `COMMAND` empty so optional command text disappears.
- Preserve the three `alert()` schemas. Nest `permissionDecision` and
  `permissionDecisionReason` below `hookSpecificOutput` for `pre_tool`. Emit top-level
  `decision`, `reason`, and `systemMessage` for `prompt_submit`; never combine its decision
  with `hookSpecificOutput.additionalContext`. Accumulate `systemMessage` and
  `additionalContext` for `session_start` and `post_tool`.

## Keep hook filters broader than engine regexes

Treat the regex block in `wormhook.sh` as canonical. Keep the `if` globs in
`hooks/hooks.json` as a coarse superset so they never suppress a valid engine match. Accept
an extra process spawn rather than a missed scan. Do not remove the pre-filter.

Give `UserPromptSubmit` no `if` condition because its payload has no command.

Register exactly one hook object per event. Make the single `PreToolUse` or `PostToolUse`
filter the union of every gated command class. Do not split a matcher into sibling hook
objects; compound commands can otherwise trigger duplicate scans.

## Verify the changed layer

- After changing shell scripts, parse every file with macOS Bash 3.2, then lint:

  ```bash
  for f in scripts/*.sh scripts/doctor/*.sh; do /bin/bash -n "$f"; done
  shellcheck scripts/*.sh scripts/doctor/*.sh
  ```

- Avoid apostrophes inside heredocs nested in `$(...)`. Bash 3.2 can swallow the closing
  parenthesis even when newer Bash versions parse it.
- After changing `hooks.json` or a manifest, run
  `jq -e . hooks/hooks.json .claude-plugin/*.json`.
- Smoke-test a hook by piping a synthetic payload:

  ```bash
  echo '{"tool_input":{"command":"git pull"},"cwd":"/tmp/x","hook_event_name":"PostToolUse"}' | bash scripts/wormhook.sh
  ```

- Follow `.claude/skills/update/SKILL.md` for a new campaign. Update
  `malware-patterns.sh`, the provenance header in `wormhook.sh`, the source in `README.md`,
  the plugin version, and `WORMHOOK_SIGNATURES_ASOF`.
- Regenerate `scripts/integrity.sha256` after changing the engine or signatures.
- Update both the engine regex and the `hooks.json` superset when adding a gated verb.
