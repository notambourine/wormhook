# scripts/doctor/ - SessionStart status-light contract

Each file here is ONE health check, registered as its own `SessionStart` hook in
`hooks/hooks.json`, emitting at most ONE `🟡/🔴/⚪` status light. The hybrid-jq invariant is
authoritative in the root `CLAUDE.md`.

## The contract

- **One concern = one file = one hook = one emit.** To add a concern, add a
  `doctor/<concern>.sh` and register it. NEVER concatenate a second concern into an existing
  check's `systemMessage` or `additionalContext`. A `\n`-joined second concern renders as one
  muddied light (whose emoji? whose state?) instead of two independently-silenceable ones.

- **A status light requires an OBSERVABLE state.** A check earns a light only if the hook can
  observe its pass/fail from a non-interactive `SessionStart` context: `command -v`,
  `git config --get`, `launchctl print`, a file stat. A permanent colored line with nothing to
  verify is a false-🟡 nag, and it erodes trust in the lights that do mean something.

  The line to hold: **assert the negative, never the positive.** Detect a misconfiguration you
  can observe; never claim a setup is correct, which is usually the non-observable half.

  Worked example, `shellguard.sh` (exec-guard vs Socket Firewall). Whether the wrappers are
  correctly composed lives in the interactive runtime - which function won the clobber, what
  load order ran - and a non-interactive hook cannot see it, so the check never emits a "you
  are composed" proof. The clobber anti-pattern (a bare `sfw` PM wrapper coexisting with the
  exec-guard) is plain rc-file TEXT on disk, so the check reads that text and is
  false-negative-only: 🟡 only when the anti-pattern literally co-occurs, ⚪ when the guard is
  not wired, never an assertion it cannot verify. How-to-compose guidance lives in `README.md`
  and `/wormhook-setup`, not the light.

- **Every check speaks only on a finding. No check emits a 🟢.** A check emits a finding
  (🟡/🔴) or a silenced finding (⚪); healthy and not-applicable are silent. That includes the
  two ALARM checks, `deps.sh` (jq) and `integrity.sh` (tamper): their findings are the loudest
  lines the doctor has and are NOT silenceable, but their healthy state is as quiet as any
  nudge's. The CI presence-assert covers the never-ran case at PR time, so a green line proves
  nothing and a row of them is transcript noise. A declined nudge degrades to ⚪ via
  `WORMHOOK_SKIP_<ITEM>=1` (or `WORMHOOK_DOCTOR_QUIET=1` for all), never to actual silence.

- **`deps.sh` owns the jq-missing 🔴 and is registered FIRST.** It raises the static `printf`
  "scans are OFF" alarm before sourcing `_utils.sh`. Every other check inherits `_utils.sh`'s
  silent jq fail-open (`command -v jq || exit 0` at source time; sourcing a file that `exit`s
  exits the caller). CI derives the check list from `hooks.json` and asserts each exists, is
  executable, and that `deps.sh` is first.

- **Emit only via the `wh_*` helpers** in `_utils.sh`: one object per check, all dynamic
  content through `jq --arg` so paths and filenames cannot break the JSON. Match the flag
  vocabulary of the existing user-level status-light hooks.

## Adding a check

1. New `doctor/<concern>.sh`, `chmod +x`. Confirm the concern has an observable state (rule 2).
2. Source `_utils.sh`; emit at most one `wh_flag <emoji> <concern> "<msg>" ["<ctx>"]`.
3. Register it as its own `SessionStart` hook in `hooks/hooks.json`. CI derives the
   presence-assert from there, so there is no list or count to update.
4. Behavior change means bumping `.claude-plugin/plugin.json`.
