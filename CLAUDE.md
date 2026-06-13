# wormhook — operating context for Claude

A Claude Code plugin: a tiered shell hook that scans for npm/node (and landed PyPI)
supply-chain malware and blocks at `PreToolUse`. User-facing docs are in `README.md`;
this file is the maintainer/agent context — the invariants and gotchas that aren't
obvious from the code.

## Layout

- `scripts/wormhook.sh` — the scanner. Reads a hook JSON payload on stdin, dispatches by
  `hook_event_name` + command class, runs Tiers 0–2, emits a verdict.
- `scripts/malware-patterns.sh` — **single source of truth** for signatures, sourced by
  the hook. Add a campaign here once and every tier picks it up. Extended-regex only
  (must parse identically under bash and zsh).
- `scripts/doctor.sh` — silent-unless-degraded SessionStart health check (deps + version drift).
- `hooks/hooks.json` — event → script wiring. `.claude-plugin/{plugin,marketplace}.json` — manifests.

## Invariants (don't break these)

- **Behavior PRs must bump `.claude-plugin/plugin.json`.** A CI tripwire fails the PR if
  the version doesn't move forward on a behavioral change. README/comment-only changes
  don't need it; anything touching the scripts does.
- **`doctor.sh` stays `jq`-free.** It's the watchdog for the case where `wormhook.sh`
  can't run (missing `jq`), so it depends on nothing but bash. Its JSON is hand-rolled
  and safe *only because every string is static* — don't interpolate dynamic content
  without switching that line to `jq`.
- **`wormhook.sh` must route all scanned paths/commands through `jq --arg`.** It embeds
  untrusted filenames/commands into output; bare interpolation is an injection hole.
- **Tier 0 always runs and is never cached.** A poisoned `~/.claude` hook re-runs every
  launch, so persistence detection must outrank the Tier-2 deps-changed cache.
- **Fail open, loud.** A missing signature file or a scan `timeout` degrades to 🟡 (and
  never refreshes the clean-scan cache) — it never bricks `npm`/`node` and never silently
  passes as 🟢. The one tier with no `timeout` ceiling is Tier 1, the *blocking* tier: a
  truncated walk there is a coverage hole, not an acceptable degradation.
- **Signatures only get a block-tier home if they're near-zero-FP.** Higher-FP behavioral
  patterns are scoped to the `node_modules` tier (third-party deps); see README's
  "deliberately doesn't do" for what's held back and why. The line is FP-safety, not effort.

## Dispatch model

`wormhook.sh` decides *which tiers run* and *whether it can block* from two inputs:
`EVENT` (`hook_event_name`) and the command, matched against `GATE_RE` / `INSTALL_RE` /
`GIT_RE`. The scan engine itself is **CWD-driven** — it scans `$CWD` and `~/.claude`
regardless of the command. Only `PreToolUse` can hard-block (`permissionDecision:
"deny"`); `SessionStart`/`PostToolUse` run after the point of no return and can only warn.

- `GIT_RE` (pull/merge/checkout/switch/rebase) is **PostToolUse-only** — pre-op the new
  files don't exist yet, so a pre-scan is pure cost.

### Two sources of truth — keep them in sync (`if` ⊇ regex)

"Which commands trigger a scan" is encoded twice: the `if` globs in `hooks/hooks.json`
and the `GATE_RE`/`INSTALL_RE`/`GIT_RE` regexes in `wormhook.sh`. They're **not**
duplicates — the `if` glob is a *coarse perf pre-filter* (its only job is to not spawn
bash on every `ls`/`git status`), and the regex is the *precise gate*. The invariant is
**`if` ⊇ regex**, not equality: `if` broader than the regex is free (a wasted spawn that
exits 0); `if` **narrower** is the bug — the hook silently never fires and the scan is
skipped with no signal. JSON can't hold a comment, so the canonical statement lives at
the regex block in `wormhook.sh`; this is the mirror. (Don't drop the `if` to "DRY" it to
one source — that spawns the script on every command; the latency tax isn't worth it.)

## Working here

- After editing scripts: `bash -n scripts/*.sh` and `shellcheck -S warning scripts/*.sh`.
- After editing `hooks.json`/manifests: `jq -e . hooks/hooks.json .claude-plugin/*.json`.
- Smoke-test a path by piping a synthetic payload:
  `echo '{"tool_input":{"command":"git pull"},"cwd":"/tmp/x","hook_event_name":"PostToolUse"}' | bash scripts/wormhook.sh`
- New campaign → add patterns to `malware-patterns.sh`, update the provenance header in
  `wormhook.sh`, add the Source to `README.md`, bump `plugin.json`.
- New **command class** (a new gated verb) → update **both** the regex in `wormhook.sh`
  *and* the matching `if` glob in `hooks/hooks.json`, keeping `if` ⊇ regex (see above).
