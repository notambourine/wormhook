---
description: Interactively set up wormhook's out-of-Claude scanning (CLI, git-pull audit, hourly sweep, scan roots)
allowed-tools: Bash, AskUserQuestion
---

You are running the **wormhook out-of-band setup wizard**. Goal: get this machine covered by
wormhook *outside* Claude Code — an on-demand `wormhook-scan` CLI, a git-pull audit, and an
hourly local sweep — with zero manual command-hunting. The detection engine is unchanged; you
are only wiring up *triggers*.

## 0. Resolve the CLI script

Set `SCRIPT` to the first of these that exists, then use it for every command below:

```bash
SCRIPT="$(claude plugin root wormhook 2>/dev/null)/scripts/wormhook-scan.sh"
[ -f "$SCRIPT" ] || SCRIPT="$HOME/.claude/plugins/marketplaces/notambourine/scripts/wormhook-scan.sh"
[ -f "$SCRIPT" ] && echo "using: $SCRIPT" || echo "NOT FOUND"
```

If neither exists, tell the user wormhook does not appear to be installed and stop.

## 1. Show current coverage

Run `bash "$SCRIPT" status` and read it back to the user in one line (what is already wired,
what is missing). Do not re-install anything already marked installed.

## 2. Ask what to enable

Use **AskUserQuestion** (multiSelect) offering only the pieces that `status` showed as *not*
installed:

- **CLI on PATH** — symlink `wormhook-scan` into `~/.local/bin` so you can run
  `wormhook-scan ~/code/*/` anytime (morning / pause-moment fleet checks).
- **Git-pull audit** — a global git hook: every `git pull`/`checkout` prints a **loud red
  report if the update pulled in a supply-chain IOC**, so you see it *before* you run
  `npm run dev`. ⚠️ This sets/uses your **global** `core.hooksPath` (affects all repos) —
  call that out and let them decline.
- **Hourly sweep** — a launchd LaunchAgent that scans your repos hourly in the background
  (local, **zero LLM tokens**), with a desktop notification + logfile on any finding. (macOS
  only; on Linux it prints a systemd/cron line instead.)

If no config file exists yet (per `status`), also ask where they keep their git repos — offer
common roots (`~/code`, `~/sandbox/git-repos`, `~/work`) plus "Other" for a custom path/glob.

## 3. Apply only the selected pieces

- **Scan roots** (if given): run `bash "$SCRIPT" config --init`, then append each chosen root
  as its own line to the config file shown by `status` (e.g. `~/code/*/`). Confirm the path.
- **CLI**: `bash "$SCRIPT" install-cli` — then note if `~/.local/bin` is not on their `$PATH`.
- **Git-pull audit**: `bash "$SCRIPT" install-git-hook`.
- **Hourly sweep**: `bash "$SCRIPT" install-launchd` (mention `--every SECONDS` to retune).

## 4. Confirm

Run `bash "$SCRIPT" status` again and summarize what changed plus how to reverse each piece
(`uninstall-git-hook`, `uninstall-launchd`, or remove the `~/.local/bin` symlink). Keep the
whole interaction concise; never install anything the user did not pick.
