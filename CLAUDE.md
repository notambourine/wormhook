# wormhook - operating context for Claude

A tiered shell hook that scans for npm/node (and landed PyPI) supply-chain malware and blocks
at `PreToolUse` and `UserPromptSubmit`. `README.md` is the user-facing doc. This file holds
the maintainer invariants the code does not state.

## Layout

- `scripts/wormhook.sh` - the engine. Reads a hook JSON payload on stdin, dispatches by
  `hook_event_name` plus command class, runs Tiers 0-2, emits a verdict.
- `scripts/malware-patterns.sh` - single source of truth for signatures, sourced by the
  engine. Extended-regex only; must parse identically under bash and zsh.
- `scripts/doctor/*.sh` - SessionStart health checks, one concern per file. Read
  `scripts/doctor/CLAUDE.md` before adding or editing one. `_utils.sh` is sourced, never
  executed.
- `scripts/wormhook-scan.sh` (plus `...conf.sample`) - the out-of-band CLI: fleet scans, the
  hourly launchd sweep, the global git hook. Its adapter contract (verbs, git hook,
  shell-init, `action.yml`, installers) lives in `.claude/rules/scan-adapters.md`,
  paths-scoped to the adapter files.
- `hooks/hooks.json` - event to script wiring. `.claude-plugin/plugin.json` - the manifest.

## Invariants

- **Behavior PRs must bump `.claude-plugin/plugin.json`.** CI fails a PR touching `scripts/`
  or `hooks/` without a forward version move. Docs-only changes need no bump.
- **Ship no `marketplace.json`.** This repo is a plugin listed as a row in
  `notambourine/claude`; a second marketplace here would make a teammate add two marketplaces
  to get one plugin. The browse tagline lives in that catalog row - edit it there.
  `plugin.json`'s description carries campaign, IOC, and blocking detail ONLY, because the
  reader is deciding whether to trust a plugin about to scan their filesystem. Operational
  surfaces (CLI, sweeps, CI gate, dashboard) belong in the README. A markdown link in that
  field renders as dead text at inspect time; plain "see the README for ..." prose is fine.
  The two descriptions have different jobs: never sync them, and there is no parity check.
- **`claude plugin validate . --strict` warns on the root `CLAUDE.md`.** That warning is
  allowlisted by name in `validate.yml` and is the ONLY one, because this file is maintainer
  context, not context shipped to a plugin consumer. Every other warning fails CI.
- **Hybrid jq model.** The one line the doctor must emit without `jq` - `jq missing, scans
  are OFF` - is a static `printf` at the top of `doctor/deps.sh` ONLY, which owns that alarm:
  a check that needed `jq` would go silent in the exact case it exists to catch. Every other
  check inherits `doctor/_utils.sh`'s `command -v jq || exit 0` at source time; sourcing a
  file that `exit`s exits the caller. Everything past the guard uses `jq --arg`. CI derives
  the check list from `hooks.json` and asserts each exists, is executable, and that `deps.sh`
  is first.
- **`wormhook.sh` must route all scanned paths and commands through `jq --arg`.** It embeds
  untrusted filenames and commands into output; bare interpolation is an injection hole.
- **Tier 0 always runs and is never cached.** A poisoned `~/.claude` hook re-runs every
  launch, so persistence detection outranks the Tier-2 deps-changed cache.
- **Fail open, loud.** A missing signature file or a scan `timeout` degrades to 🟡 and never
  refreshes the clean-scan cache. It never bricks `npm`/`node` and never silently passes as
  🟢. Exception: Tier 1, the blocking tier, has no `timeout` ceiling - a truncated walk there
  is a coverage hole, not an acceptable degradation.
- **FP-tolerance scales with blast radius. Route a noisy-but-real signature down a tier;
  never drop it.** A block-tier match bricks a clean `npm install` or a human turn, so it
  demands a near-zero-FP, evidence-backed signature. A `node_modules` or warn-tier match is a
  🟡 you clear, so behavioral heuristics (`/dev/tcp/`, decode-then-eval) live there, never in
  the project-source block.
- **Quarantine is opt-in, exact-match-only, and reversible.** `WORMHOOK_QUARANTINE=1` (engine
  env; CLI `--quarantine` just exports it) renames a Tier-0 artifact to
  `<path>.wormhook-quarantined.<epoch>`, `chmod 000`s it, and logs to the cache dir.
  Eligible: the `WORMHOOK_PERSIST_*` table, known-bad `.pth` name or hash, known-bad
  `.abi3.so` basenames. NEVER a behavioral match - an unattended rename demands exact-match
  confidence. Never kill, unload, or delete; a failed rename degrades to the advisory alert.
  Default off on every surface.
- **The integrity manifest must move with the engine.** Editing `wormhook.sh` or
  `malware-patterns.sh` means regenerating `scripts/integrity.sha256`:
  `(cd scripts && shasum -a 256 wormhook.sh malware-patterns.sh > integrity.sha256)`.
  `doctor/integrity.sh` verifies it every SessionStart and CI fails on a stale manifest. The
  tamper 🔴 is NOT silenceable, same class as the jq alarm.
- **No network calls, ever.** Every tier is local: `stat`, `grep`, `jq` over the filesystem.
  Registry intelligence (malicious-version blocking, typosquats, publish-age) is ceded to
  Socket Firewall (`sfw`) and `safedep/vet`; `doctor/firewall.sh` nudges the user to install
  them. A tempting registry lookup belongs in `sfw` or `vet`, not here.
- **Signature currency is tracked.** `WORMHOOK_SIGNATURES_ASOF` in `malware-patterns.sh` is
  the date the corpus was last verified against advisories; `doctor/sigage.sh` nags past
  `WORMHOOK_SIGAGE_MAX_DAYS` (default 60). Bump it on every `/update` pass, including when a
  sweep lands nothing new.

## Dispatch model

`wormhook.sh` picks tiers and block-ability from `EVENT` (`hook_event_name`) plus the command,
matched against `GATE_RE`/`INSTALL_RE`/`GIT_RE`/`PYGATE_RE`/`PYINSTALL_RE`.

**The regexes match per SUBCOMMAND, not the raw string.** The command splits at
`;`/`&&`/`||`/`|`; leading `VAR=value` assignments and a bare `env` prefix are stripped; and
dir-option pairs (`--prefix`/`--cwd`/`--dir`/`-C` plus value) are deleted from the matching
copy. So `cd sub && npm install`, `CI=1 npm install`, and `npm --prefix X install` all gate.
`^\s*` anchors a segment start.

The engine scans `~/.claude`, `$CWD`, and every target dir the command operates on (a `cd` is
tracked through segments; dir options are honoured). The lifecycle gate also walks each
target's workspace manifests (`package.json` `workspaces` plus `pnpm-workspace.yaml`), since a
root install runs every workspace's lifecycle. Tier 2 and its cache stay `$CWD`-rooted.

Two events can hard-block: `PreToolUse` (`hookSpecificOutput.permissionDecision: "deny"`) and
`UserPromptSubmit` (top-level `decision:"block"`). `SessionStart` and `PostToolUse` run after
the point of no return and only warn.

- `GIT_RE` (pull/merge/checkout/switch/rebase) is PostToolUse-only; pre-op the new files do
  not exist yet.
- `PYGATE_RE` (pip/pip3/pipx/uv/python/python3) is PreToolUse, T0+T1 only, NEVER T2: the
  Tier-0 `.pth` sweep must run before the interpreter auto-executes a poisoned site-packages
  startup hook. `PYINSTALL_RE` is the PostToolUse subset (a fresh `.pth` can land), T0+T1
  re-scan. `make` and `./` stay ungated: no matching signatures, pure FP and latency tax.
- `UserPromptSubmit` is the continuous monitor: T0+T1 only, NEVER T2, fires every human turn,
  and can block. It carries no command (`COMMAND=""`, so the `${COMMAND:+...}` interpolations
  omit cleanly). It is silent-on-clean (the 🟢 is suppressed for `MODE=prompt_submit`). The 🟡
  path is NOT suppressed - a silently-degraded monitor is an invisible failure.
- **`alert()` emits three non-interchangeable shapes** keyed on `MODE`. `pre_tool` nests
  `permissionDecision` and `permissionDecisionReason` under `hookSpecificOutput`.
  `prompt_submit` uses top-level `decision:"block"` plus `reason` (model) and `systemMessage`
  (user); on UPS, `decision` is mutually exclusive with
  `hookSpecificOutput.additionalContext`, so neither is emitted. `session_start` and
  `post_tool` accumulate and emit `systemMessage` plus `additionalContext`.

### Two sources of truth: keep `if` a superset of the regex

"Which commands trigger a scan" is encoded twice: the `if` globs in `hooks/hooks.json` (a
coarse perf pre-filter whose only job is to not spawn bash on every `ls`) and the regexes in
`wormhook.sh` (the precise gate). An `if` broader than the regex costs one wasted spawn; an
`if` narrower means the hook silently never fires. The canonical statement lives at the regex
block in `wormhook.sh`; CI asserts the superset. Do not collapse the `if` away to DRY it -
that spawns the script on every command.

`UserPromptSubmit` is exempt: its payload carries no command, so its entry has no `if` and no
matcher. It fires every prompt and the script gates on `EVENT` alone.

**One hook object per event. Never split into sibling entries.** `PreToolUse` and
`PostToolUse` each register exactly one hook object whose `if` is the union of every gated
command class. Sibling objects under one `matcher` fire independently with no cross-entry
dedup, and the `if` filter fails open on a compound command it cannot parse, so N siblings
means N duplicate scans. The single unioned object caps fail-open at one spawn; `wormhook.sh`
re-derives the precise class internally.

## Working here

- After editing scripts, syntax-check with the real shebang shell (Apple `/bin/bash` is
  3.2.57; a Homebrew bash passes files 3.2 rejects) and lint. `bash -n` parses only its FIRST
  file arg, and `scripts/*.sh` does not recurse:
  `for f in scripts/*.sh scripts/doctor/*.sh; do /bin/bash -n "$f"; done` then
  `shellcheck scripts/*.sh scripts/doctor/*.sh` (CI uses the default floor).
- **bash 3.2 gotcha in `$(...)`:** its parser miscounts a lone `'` (apostrophe) even inside a
  heredoc body, swallowing the closing `)`. Use no contractions in any
  `alert "..." "$(cat <<BODY ... BODY)"` body - write "it has" and "do not". Only
  `/bin/bash -n` catches it.
- After editing `hooks.json` or the manifests: `jq -e . hooks/hooks.json .claude-plugin/*.json`.
- Smoke-test a path by piping a synthetic payload:
  `echo '{"tool_input":{"command":"git pull"},"cwd":"/tmp/x","hook_event_name":"PostToolUse"}' | bash scripts/wormhook.sh`
- New campaign: follow the `/update` skill (`.claude/skills/update/SKILL.md`). Patterns to
  `malware-patterns.sh`, provenance
  header in `wormhook.sh`, Source in `README.md`, bump `plugin.json`, bump
  `WORMHOOK_SIGNATURES_ASOF`.
- Any edit to `wormhook.sh` or `malware-patterns.sh` means regenerating
  `scripts/integrity.sha256` (see Invariants) or CI goes red.
- New gated verb: update both the regex in `wormhook.sh` and the `if` glob in
  `hooks/hooks.json`, keeping `if` a superset of the regex.
