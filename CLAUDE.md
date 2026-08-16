# wormhook — operating context for Claude

A Claude Code plugin: a tiered shell hook that scans for npm/node (and landed PyPI)
supply-chain malware and blocks at `PreToolUse` and `UserPromptSubmit`. `README.md` holds
the user-facing docs; this file holds the maintainer invariants that are not obvious from
the code.

## Layout

- `scripts/wormhook.sh` — the engine. Reads a hook JSON payload on stdin, dispatches by
  `hook_event_name` + command class, runs Tiers 0–2, emits a verdict.
- `scripts/malware-patterns.sh` — **single source of truth** for signatures, sourced by
  the engine. Extended-regex only (must parse identically under bash and zsh).
- `scripts/doctor/*.sh` — SessionStart health checks, **one concern per file**. The design
  contract (emission classes, jq rules) lives in `scripts/doctor/CLAUDE.md` — read it
  before adding or editing a check. `_utils.sh` is sourced, never executed.
- `scripts/wormhook-scan.sh` — the out-of-band CLI (+ `…conf.sample`): fleet scans, the
  hourly launchd sweep, the global git hook. Its adapter contract (verbs, git hook,
  shell-init, `action.yml`, installers) lives in `.claude/rules/scan-adapters.md`,
  paths-scoped to the adapter files.
- `hooks/hooks.json` — event → script wiring. `.claude-plugin/{plugin,marketplace}.json` — manifests.

## Invariants (don't break these)

- **Behavior PRs must bump `.claude-plugin/plugin.json`.** CI fails a PR that touches
  `scripts/` or `hooks/` without a forward version move. Docs-only changes need no bump.
- **The two `description` fields have different jobs — never sync them.**
  `marketplace.json` carries a one-line browse tagline. `plugin.json` carries the full
  install/inspect description: campaign + IOC + blocking detail ONLY — the reader is
  deciding whether to trust a plugin about to scan their filesystem. Operational surfaces
  (CLI, sweeps, CI gate, dashboard) belong in the README; a markdown link in the field
  renders as dead text at inspect time (plain "see the README for …" prose is fine).
  There is deliberately no parity check.
- **Hybrid jq model.** The one line the doctor must emit without `jq` — `jq missing,
  scans are OFF` — is a static `printf` at the top of `doctor/deps.sh` **only**, which
  owns that alarm: if the check needed `jq` it would go silent in the exact case it
  exists to catch. Every other check inherits a single silent fail-open — `doctor/_utils.sh`
  runs `command -v jq || exit 0` at source time (sourcing a file that `exit`s exits the
  caller). Everything past the guard uses `jq --arg` (real newlines, injection-safe). A CI
  step (deriving the list from `hooks.json`) asserts every registered check exists + is
  executable and `deps.sh` is first.
- **`wormhook.sh` must route all scanned paths/commands through `jq --arg`.** It embeds
  untrusted filenames/commands into output; bare interpolation is an injection hole.
- **Tier 0 always runs and is never cached.** A poisoned `~/.claude` hook re-runs every
  launch, so persistence detection outranks the Tier-2 deps-changed cache.
- **Fail open, loud.** A missing signature file or a scan `timeout` degrades to 🟡 (and
  never refreshes the clean-scan cache) — it never bricks `npm`/`node` and never silently
  passes as 🟢. Exception: Tier 1, the *blocking* tier, has no `timeout` ceiling — a
  truncated walk there is a coverage hole, not an acceptable degradation.
- **FP-tolerance scales with blast radius — route a noisy-but-real signature down a tier,
  do not drop it.** A block-tier match (PreToolUse / UserPromptSubmit) bricks a clean
  `npm install` or a human turn, so it demands a near-zero-FP, evidence-backed signature.
  A `node_modules`/warn-tier match is a 🟡 you clear, so the behavioral heuristics
  (`/dev/tcp/`, decode-then-eval) live there, never in the project-source block.
- **Quarantine is opt-in, exact-match-only, and reversible.** `WORMHOOK_QUARANTINE=1`
  (engine env; CLI `--quarantine` just exports it) renames a Tier-0 artifact to
  `<path>.wormhook-quarantined.<epoch>` + `chmod 000` and logs to the cache dir.
  Eligible: the `WORMHOOK_PERSIST_*` table, known-bad `.pth` name/hash, known-bad
  `.abi3.so` basenames — **never** a behavioral match (an unattended rename demands
  exact-match confidence). Never kill/unload/delete; a failed rename degrades to the
  advisory alert. Default off on every surface.
- **The integrity manifest must move with the engine.** `scripts/integrity.sha256` holds
  the SHA-256 of `wormhook.sh` + `malware-patterns.sh`; `doctor/integrity.sh` verifies it
  every SessionStart. Editing either file ⇒ regenerate: `(cd scripts && shasum -a 256
  wormhook.sh malware-patterns.sh > integrity.sha256)` — CI fails on a stale manifest.
  The tamper 🔴 is NOT silenceable (same class as the jq alarm).
- **No network calls — ever.** Every tier is local (stat/grep/jq over the filesystem).
  Registry intelligence (malicious-version blocking, typosquats, publish-age) is ceded to
  Socket Firewall (`sfw`) + `safedep/vet`; `doctor/firewall.sh` nudges the user to install
  them. A tempting registry lookup belongs in `sfw`/`vet`, not here.
- **Signature currency is tracked.** `WORMHOOK_SIGNATURES_ASOF` in `malware-patterns.sh`
  is the date the corpus was last verified against advisories; `doctor/sigage.sh` nags
  past `WORMHOOK_SIGAGE_MAX_DAYS` (default 60). Bump it on every `/update` pass — also
  when a sweep lands nothing new.

## Dispatch model

`wormhook.sh` picks tiers and block-ability from `EVENT` (`hook_event_name`) + the
command, matched against `GATE_RE`/`INSTALL_RE`/`GIT_RE`/`PYGATE_RE`/`PYINSTALL_RE`.
**The regexes match per SUBCOMMAND, not the raw string**: the command splits at
`;`/`&&`/`||`/`|`, leading `VAR=value` assignments and a bare `env` prefix are stripped,
and dir-option pairs (`--prefix`/`--cwd`/`--dir`/`-C` + value) are deleted from the
matching copy — so `cd sub && npm install`, `CI=1 npm install`, and
`npm --prefix X install` all gate. `^\s*` anchors a *segment* start. The engine scans
`~/.claude`, `$CWD`, **and every target dir the command operates on** (a `cd` is tracked
through segments; the dir options are honoured); the lifecycle gate also walks each
target's workspace manifests (`package.json` `workspaces` + `pnpm-workspace.yaml`), since
a root install runs every workspace's lifecycle. Tier 2 and its cache stay `$CWD`-rooted.

**Two events can hard-block:** `PreToolUse` (`hookSpecificOutput.permissionDecision:
"deny"`) and `UserPromptSubmit` (**top-level** `decision:"block"`).
`SessionStart`/`PostToolUse` run after the point of no return and only warn.

- `GIT_RE` (pull/merge/checkout/switch/rebase) is **PostToolUse-only** — pre-op the new
  files don't exist yet.
- `PYGATE_RE` (pip/pip3/pipx/uv/python/python3) is **PreToolUse** → T0+T1 only, **never
  T2**: the Tier-0 `.pth` sweep must run *before* the interpreter auto-executes a
  poisoned site-packages startup hook. `PYINSTALL_RE` is the PostToolUse subset (a fresh
  `.pth` can land) → T0+T1 re-scan. `make`/`./` stay ungated: no matching signatures,
  pure FP/latency tax.
- `UserPromptSubmit` is the **continuous monitor**: T0+T1 only, **never T2**, fires every
  human turn, and *can block*. It carries no command (`COMMAND=""`, so the `${COMMAND:+…}`
  interpolations omit cleanly). It is **silent-on-clean** (the 🟢 is suppressed for
  `MODE=prompt_submit`); the 🟡 path is NOT suppressed — a silently-degraded monitor is
  an invisible failure.
- **`alert()` emits three non-interchangeable shapes** keyed on `MODE`: `pre_tool` nests
  `permissionDecision`/`permissionDecisionReason` under `hookSpecificOutput`;
  `prompt_submit` uses **top-level** `decision:"block"` + `reason` (model) +
  `systemMessage` (user) — on UPS `decision` is **mutually exclusive** with
  `hookSpecificOutput.additionalContext`, so neither is emitted; `session_start`/
  `post_tool` accumulate and emit `systemMessage` + `additionalContext`.

### Two sources of truth — keep them in sync (`if` ⊇ regex)

"Which commands trigger a scan" is encoded twice: the `if` globs in `hooks/hooks.json`
(a coarse perf pre-filter — its only job is to not spawn bash on every `ls`) and the
regexes in `wormhook.sh` (the precise gate). The invariant is **`if` ⊇ regex**: `if`
broader than the regex is a free wasted spawn; `if` **narrower** means the hook silently
never fires. The canonical statement lives at the regex block in `wormhook.sh`; CI
asserts the superset. Don't collapse the `if` away to "DRY" it — that spawns the script
on every command.

**`UserPromptSubmit` is exempt**: its payload carries no command, so its entry has no
`if` and no matcher — it fires every prompt and the script gates on `EVENT` alone.

**One hook object per event — never split into sibling entries.** Each of
`PreToolUse`/`PostToolUse` registers **exactly one** hook object whose `if` is the union
of every gated command class. Sibling objects under one `matcher` fire independently (no
cross-entry dedup), and the `if` filter is best-effort and **fails open** on a compound
command it can't parse — N siblings → N duplicate scans. The single unioned object caps
fail-open at one spawn; `wormhook.sh` re-derives the precise class internally.

## Working here

- After editing scripts: syntax-check with the **real shebang shell** (Apple `/bin/bash`
  is 3.2.57 — a Homebrew bash passes files 3.2 rejects) and lint. `bash -n` parses only
  its **first** file arg, and `scripts/*.sh` does not recurse:
  `for f in scripts/*.sh scripts/doctor/*.sh; do /bin/bash -n "$f"; done` then
  `shellcheck scripts/*.sh scripts/doctor/*.sh` (CI uses the default floor).
- **bash 3.2 gotcha in `$(…)`:** its parser miscounts a lone `'` (apostrophe) even inside
  a heredoc body, swallowing the closing `)`. So **no contractions** in any
  `alert "..." "$(cat <<BODY … BODY)"` body — write "it has"/"do not". Only `/bin/bash -n`
  catches it.
- After editing `hooks.json`/manifests: `jq -e . hooks/hooks.json .claude-plugin/*.json`.
- Smoke-test a path by piping a synthetic payload:
  `echo '{"tool_input":{"command":"git pull"},"cwd":"/tmp/x","hook_event_name":"PostToolUse"}' | bash scripts/wormhook.sh`
- New campaign → follow the `/update` skill (`.claude/skills/update/SKILL.md`): patterns
  to `malware-patterns.sh`, provenance header in `wormhook.sh`, Source in `README.md`,
  bump `plugin.json`, bump `WORMHOOK_SIGNATURES_ASOF`.
- Any edit to `wormhook.sh` or `malware-patterns.sh` → regenerate
  `scripts/integrity.sha256` (see Invariants) or CI goes red.
- New command class (a new gated verb) → update **both** the regex in `wormhook.sh` and
  the `if` glob in `hooks/hooks.json`, keeping `if` ⊇ regex.
