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
  lights that *do* mean something. The line to hold is **assert the negative, never the positive**:
  detect a definite *misconfiguration* you can observe; never claim a setup is *correct* (that is
  usually the non-observable half). Worked example — `shellguard.sh` (exec-guard ↔ Socket Firewall):
  whether the wrappers are *correctly composed* lives in the **interactive runtime** (which function
  won the clobber, what load order ran) and a non-interactive hook cannot see it — so the check
  never emits a "you are composed" 🟢-as-proof. But the clobber **anti-pattern** (a bare `sfw` PM
  wrapper coexisting with the exec-guard) is plain **rc-file TEXT on disk**, as observable as the
  git-hook files `coverage.sh` greps. So the check reads that text and is *false-negative-only*: it
  🟡s only when the anti-pattern literally co-occurs (never cries wolf on a correct/composed rc),
  ⚪ when the guard is not wired (opt-in), and never asserts correctness it cannot verify. The
  *how-to-compose* guidance still lives in `README.md` + `/wormhook-setup`, not the light.

- **Always-on, never silent-unless-degraded.** Every check emits its light every session — silence
  is the invisible-failure bug the split fixed (ran-and-fine vs never-ran is ambiguous). A
  consciously-declined soft nudge degrades to ⚪ via `WORMHOOK_SKIP_<ITEM>=1` (or
  `WORMHOOK_DOCTOR_QUIET=1` for all), never to actual silence.

- **`deps.sh` owns the jq-missing 🔴 and is registered FIRST.** It raises the static `printf`
  "scans are OFF" alarm *before* sourcing `_utils.sh`; every other check inherits `_utils.sh`'s
  silent jq fail-open (`command -v jq || exit 0` at source time — sourcing a file that `exit`s
  exits the caller). CI derives the check list from `hooks.json` and asserts each exists + is
  executable and `deps.sh` is first. See root `CLAUDE.md` for the full hybrid-jq invariant.

- **Emit only via the `wh_*` helpers** (`_utils.sh`): one object per check, all dynamic content
  through `jq --arg` (injection-safe — paths/versions/filenames can be named without breaking
  the JSON). Match the flag vocabulary to the existing user-level status-light hooks.

## Adding a check

1. New `doctor/<concern>.sh` — confirm the concern has an observable state first (rule 2); `chmod +x`.
2. Source `_utils.sh`; emit exactly one `wh_flag <emoji> <concern> "<msg>" ["<ctx>"]`.
3. Register it as its own `SessionStart` hook in `hooks/hooks.json` — CI derives the presence-assert
   from there, so there is no list or count to update.
4. Behavior change → bump `.claude-plugin/plugin.json`.
