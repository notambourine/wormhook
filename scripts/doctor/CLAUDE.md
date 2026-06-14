# scripts/doctor/ — SessionStart status-light contract

Each file here is ONE focused health check, registered as its own `SessionStart` hook in
`hooks/hooks.json`, emitting exactly ONE `🟢/🟡/🔴/⚪` status light every session. This file is
the design contract that the 0.10.0 split (#22) established but only recorded in its commit
message — captured here so the next change does not silently undo it. The authoritative
hybrid-jq invariant stays in the root `CLAUDE.md`; this file does not duplicate it.

## The contract (don't break these)

- **One concern = one file = one hook = one emit.** The `SessionStart` protocol surfaces exactly
  one JSON object per hook (the `wh_*` helpers in `_utils.sh` emit one). To add a concern, add a
  `doctor/<concern>.sh` and register it in `hooks.json` — **never** concatenate a second concern
  into an existing check's `systemMessage` *or* `additionalContext`. The old monolithic
  `doctor.sh` crammed every check into one emit via `systemMessage` string concat; the split
  **deleted that concat** because independent emits replace it. A `\n`-joined second concern in
  one emit is that anti-pattern returning: it renders as one muddied light (whose emoji? whose
  state?) instead of two honest, independently-silenceable lights.

- **A status light requires an OBSERVABLE, verifiable state.** A check earns a light only if the
  hook can actually observe its pass/fail from a *non-interactive* `SessionStart` context —
  `command -v`, `git config --get`, `launchctl print`, a file stat. A concern with no observable
  state does **not** belong here: a persistent colored line with nothing to verify is either a
  permanent false-🟡 nag (cry-wolf) or a meaningless line, and either way it erodes trust in the
  lights that *do* mean something. Worked example (the reason this rule is written down):
  shell-exec-guard ↔ Socket Firewall **composition** lives in the user's **interactive rc**, which
  a `SessionStart` hook cannot see — so it is taught in `README.md` + `/wormhook-setup`, NOT
  emitted as a doctor light. Observe an *ingredient* (e.g. `command -v sfw`) only to drive a real
  status; never promote advice-with-no-observable-state to a light.

- **Always-on, never silent-unless-degraded.** Every check emits its light every session — silence
  is the invisible-failure bug the split fixed (ran-and-fine vs never-ran is ambiguous). A
  consciously-declined soft nudge degrades to ⚪ via `WORMHOOK_SKIP_<ITEM>=1` (or
  `WORMHOOK_DOCTOR_QUIET=1` for all), never to actual silence.

- **`deps.sh` owns the jq-missing 🔴 and is registered FIRST.** It raises the static `printf`
  "scans are OFF" alarm *before* sourcing `_utils.sh`; every other check inherits `_utils.sh`'s
  silent jq fail-open (`command -v jq || exit 0` at source time — sourcing a file that `exit`s
  exits the caller). CI asserts all six `doctor/*.sh` exist + are executable and `deps.sh` is
  first in `hooks.json`. See root `CLAUDE.md` for the full hybrid-jq invariant (authoritative).

- **Emit only via the `wh_*` helpers** (`_utils.sh`): one object per check, all dynamic content
  through `jq --arg` (injection-safe — paths/versions/filenames can be named without breaking
  the JSON). Match the flag vocabulary to the existing user-level status-light hooks.

## Adding a check

1. New `doctor/<concern>.sh` — confirm the concern has an observable state first (see rule 2).
2. Source `_utils.sh`; emit exactly one `wh_flag <emoji> <concern> "<msg>" ["<ctx>"]`.
3. Register it as its own `SessionStart` hook object in `hooks/hooks.json`.
4. Update the CI presence-assert count and the root `CLAUDE.md` Layout list.
5. It is a behavior change → bump `.claude-plugin/plugin.json`.
