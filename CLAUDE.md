# wormhook — operating context for Claude

A Claude Code plugin: a tiered shell hook that scans for npm/node (and landed PyPI)
supply-chain malware and blocks at `PreToolUse` and `UserPromptSubmit`. User-facing docs
are in `README.md`; this file is the maintainer/agent context — the invariants and gotchas
that aren't obvious from the code.

## Layout

- `scripts/wormhook.sh` — the scanner. Reads a hook JSON payload on stdin, dispatches by
  `hook_event_name` + command class, runs Tiers 0–2, emits a verdict.
- `scripts/malware-patterns.sh` — **single source of truth** for signatures, sourced by
  the hook. Add a campaign here once and every tier picks it up. Extended-regex only
  (must parse identically under bash and zsh).
- `scripts/doctor.sh` — silent-unless-degraded SessionStart health check (wormhook deps +
  version drift + a nudge to install the ceded install-firewall layer: Socket Firewall, `vet`).
- `hooks/hooks.json` — event → script wiring. `.claude-plugin/{plugin,marketplace}.json` — manifests.

## Invariants (don't break these)

- **Behavior PRs must bump `.claude-plugin/plugin.json`.** A CI tripwire fails the PR if
  the version doesn't move forward on a behavioral change. README/comment-only changes
  don't need it; anything touching the scripts does.
- **`plugin.json` and `marketplace.json` descriptions must match byte-for-byte.** A separate
  CI check (`Check description parity`) fails the PR on drift. If you edit one `description`,
  edit the other — `.claude-plugin/marketplace.json`'s `.plugins[] | select(.name=="wormhook")`.
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
- **FP-tolerance scales with blast radius — route a noisy-but-real signature down a tier,
  do not drop it.** A block-tier match (PreToolUse / UserPromptSubmit) bricks a clean
  `npm install` or a human turn and is un-workaroundable, so it demands a near-zero-FP,
  evidence-backed signature. A `node_modules`/warn-tier match is a 🟡 you clear, so it
  tolerates higher-FP behavioral patterns. So the behavioral heuristics (`/dev/tcp/`,
  decode-then-eval) live in the `node_modules` tier, not the project-source block — see
  `malware-patterns.sh` and README's "deliberately doesn't do". A missed detection is worse
  than a cleared warning: when a real signature is too noisy for the block tier, move it to
  a lower-blast tier rather than discard it.
- **No network calls — ever.** Every tier is local (stat/grep/jq over the filesystem). The
  install-time registry-firewall job (malicious-version blocking, typosquats, publish-age/
  reputation) is **ceded to Socket Firewall (`sfw`) + `safedep/vet`**; `doctor.sh` nudges the
  user to install them. If you're tempted to add a registry lookup (e.g. a publish-age
  "cooldown"), that belongs in `sfw`/`vet`, not here — independence and zero-network are the
  design bet, and a hook can't transparently route an install through a firewall anyway (it
  can only allow/deny). See README "deliberately doesn't do".

## Dispatch model

`wormhook.sh` decides *which tiers run* and *whether it can block* from two inputs:
`EVENT` (`hook_event_name`) and the command, matched against `GATE_RE` / `INSTALL_RE` /
`GIT_RE` / `PYGATE_RE` / `PYINSTALL_RE`. The scan engine itself is **CWD-driven** — it scans
`$CWD` and `~/.claude` regardless of the command. **Two events can hard-block:** `PreToolUse`
(`hookSpecificOutput.permissionDecision:"deny"`) and `UserPromptSubmit` (**top-level**
`decision:"block"`). `SessionStart`/`PostToolUse` run after the point of no return and only warn.

- `GIT_RE` (pull/merge/checkout/switch/rebase) is **PostToolUse-only** — pre-op the new
  files don't exist yet, so a pre-scan is pure cost.
- `PYGATE_RE` (pip/pip3/pipx/uv/python/python3) is **PreToolUse** → T0+T1 only. The point is
  to run the Tier-0 `.pth` sweep *before* the interpreter auto-executes a poisoned
  site-packages startup hook. **Never T2** (node_modules irrelevant). `PYINSTALL_RE` is the PostToolUse
  subset (a fresh `.pth` can land) → T0+T1 re-scan. `make`/`./` are deliberately *not* gated:
  too broad, no matching signatures, pure FP/latency tax — gate only where coverage exists.
- `UserPromptSubmit` is the **continuous monitor**: T0+T1 only (the fast-changing tiers),
  **never T2**, fires every human turn, and *can block*. It carries no command (`COMMAND=""`),
  so the `${COMMAND:+…}` alert interpolations omit cleanly. It is **silent-on-clean** — the
  always-on 🟢 status line is suppressed for `MODE=prompt_submit` (a 🟢 every prompt spams the
  transcript); it speaks only on a finding (🚨 block) or degradation (🟡). The 🟡 path is NOT
  suppressed — a silently-degraded continuous monitor is the invisibility bug all over again.
- **`alert()` emits three non-interchangeable shapes** keyed on `MODE`: `pre_tool` nests
  `permissionDecision`/`permissionDecisionReason` under `hookSpecificOutput`; `prompt_submit`
  uses **top-level** `decision:"block"` + `reason` (model) + `systemMessage` (user) — on UPS
  `decision` is **mutually exclusive** with `hookSpecificOutput.additionalContext`, so neither
  is emitted; `session_start`/`post_tool` accumulate and emit `systemMessage` + `additionalContext`.

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

**`UserPromptSubmit` is exempt** from `if ⊇ regex`: a UPS payload carries no command, so its
`hooks.json` entry has **no `if` and no matcher** — it fires every prompt by design, and the
script gates it purely on `EVENT`. There's no command-class regex to keep it in sync with.

## Working here

- After editing scripts: syntax-check with the **real shebang shell** (Apple `/bin/bash` is
  3.2.57), and lint. `bash -n` only parses its **first** file arg — loop, don't glob:
  `for f in scripts/*.sh; do /bin/bash -n "$f"; done` then `shellcheck -S warning scripts/*.sh`.
  (A Homebrew bash on `$PATH` will pass files that 3.2 rejects — always check with `/bin/bash`.)
- **bash 3.2 gotcha in `$(…)`:** its command-substitution parser miscounts a lone `'`
  (apostrophe) even inside a heredoc body, swallowing the closing `)`. So **no contractions**
  ("it's", "don't") in any `alert "..." "$(cat <<BODY … BODY)"` body — write "it has"/"do not".
  `bash -n` under a newer bash won't catch it; only `/bin/bash` will.
- After editing `hooks.json`/manifests: `jq -e . hooks/hooks.json .claude-plugin/*.json`.
- Smoke-test a path by piping a synthetic payload:
  `echo '{"tool_input":{"command":"git pull"},"cwd":"/tmp/x","hook_event_name":"PostToolUse"}' | bash scripts/wormhook.sh`
- New campaign → add patterns to `malware-patterns.sh`, update the provenance header in
  `wormhook.sh`, add the Source to `README.md`, bump `plugin.json`.
- New **command class** (a new gated verb) → update **both** the regex in `wormhook.sh`
  *and* the matching `if` glob in `hooks/hooks.json`, keeping `if` ⊇ regex (see above).
