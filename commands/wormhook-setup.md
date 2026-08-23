---
description: Interactively set up wormhook's out-of-Claude scanning (CLI, git-pull audit, hourly sweep, scan roots)
allowed-tools: Bash, AskUserQuestion
---

Run the wormhook out-of-band setup wizard. Goal: cover this machine outside Claude Code with
an on-demand `wormhook-scan` CLI, a git-pull audit, and an hourly local sweep. The detection
engine is unchanged; you are wiring up triggers.

## 0. Resolve the CLI script

Set `SCRIPT` to the first of these that exists, then use it for every command below:

```bash
SCRIPT="${CLAUDE_PLUGIN_ROOT:+$CLAUDE_PLUGIN_ROOT/scripts/wormhook-scan.sh}"
# Fallback searches every install layout: marketplace dir, and the external_plugins/ nesting
# a plugin gets when it is installed through another marketplace's catalog.
[ -f "$SCRIPT" ] || SCRIPT="$(find "$HOME/.claude/plugins" -maxdepth 6 -path '*/scripts/wormhook-scan.sh' -print 2>/dev/null | head -1)"
[ -f "$SCRIPT" ] && echo "using: $SCRIPT" || echo "NOT FOUND"
```

If neither exists, tell the user wormhook does not appear to be installed and stop.

## 1. Show current coverage

Run `bash "$SCRIPT" status` and read it back in one line: what is wired, what is missing. Do
not re-install anything already marked installed.

## 2. Ask what to enable

Use AskUserQuestion (multiSelect), offering only the pieces `status` showed as not installed:

- **CLI on PATH** - puts `wormhook-scan` in `~/.local/bin` so they can run
  `wormhook-scan ~/code/*/` anytime.
- **Git-pull audit** - a global git hook. Every `git pull`/`checkout` prints a loud red report
  if the update pulled in a supply-chain IOC, before they run `npm run dev`. ⚠️ This
  sets or uses their global `core.hooksPath`, affecting all repos. Call that out and let them
  decline.
- **Hourly sweep** - a launchd LaunchAgent that scans their repos hourly in the background,
  local and zero LLM tokens, with a desktop notification and logfile on any finding. macOS
  only; on Linux it prints a systemd or cron line instead. If they pick this, also ask whether
  the sweep should quarantine exact-match persistence artifacts (`--quarantine`: reversible
  rename plus `chmod 000`, behavioral matches stay report-only). Default is report-only.
  Never preselect quarantine.

If `status` shows no config file yet, also ask where they keep their git repos. Offer common
roots (`~/code`, `~/sandbox/git-repos`, `~/work`) plus "Other" for a custom path or glob.

## 3. Apply only the selected pieces

- **Scan roots** (if given): run `bash "$SCRIPT" config --init`, then append each chosen root
  as its own line to the config file shown by `status` (e.g. `~/code/*/`). Confirm the path.
- **CLI**: `bash "$SCRIPT" install-cli`. Note if `~/.local/bin` is not on their `$PATH`.
- **Git-pull audit**: `bash "$SCRIPT" install-git-hook`.
- **Hourly sweep**: `bash "$SCRIPT" install-launchd`. Mention `--every SECONDS` to retune, and
  append `--quarantine` only if they opted in.

## 4. Confirm

Run `bash "$SCRIPT" status` again. Summarize what changed and how to reverse each piece
(`uninstall-git-hook`, `uninstall-launchd`, or removing `~/.local/bin/wormhook-scan`). Keep
the whole interaction short. Never install anything the user did not pick.

## 5. Optional: shell exec-guard (manual, paste-only)

The git hook warns after a pull. The exec-guard refuses to run `npm`/`pnpm`/`yarn`/`bun`/`npx`
in a repo with a live IOC, the out-of-Claude analog of the `PreToolUse` block.

It is opt-in and paste-only: it defines shell functions in the user's rc, which this wizard
does NOT edit, per wormhook's no-auto-install rule. Offer to print the block; the user pastes
it into `~/.zshrc`/`~/.bashrc` AFTER any version manager (nvm/fnm/asdf). Skip if they decline.

Detect Socket Firewall and print the matching block:

```bash
command -v sfw >/dev/null 2>&1 && echo sfw-present || echo sfw-absent
```

- **sfw absent** - the standalone guard:
  ```bash
  eval "$(wormhook-scan shell-init)"
  ```
- **sfw present** - compose them in ONE wrapper chain (wormhook guard, then sfw, then the real
  binary). Do NOT also keep a separate `npm() { sfw npm ... }` block: two blocks defining the
  same name silently clobber each other (last loaded wins), disabling a layer. Paste this
  single block, loaded last:
  ```bash
  command -v wormhook-scan >/dev/null 2>&1 && eval "$(wormhook-scan shell-init)"  # defines __wormhook_guard
  # Double-underscore helper names are load-bearing: Claude Code's shell snapshot drops
  # single-underscore functions (zsh completion namespace), which would brick npm in its Bash tool.
  __sc_run() {
    local pm="$1"; shift
    command -v __wormhook_guard >/dev/null 2>&1 && { __wormhook_guard || return 1; }
    if command -v sfw >/dev/null 2>&1; then command sfw "$pm" "$@"; else command "$pm" "$@"; fi
  }
  npm()  { __sc_run npm  "$@"; }
  pnpm() { __sc_run pnpm "$@"; }
  yarn() { __sc_run yarn "$@"; }
  bun()  { __sc_run bun  "$@"; }
  npx()  { __sc_run npx  "$@"; }
  ```

Every layer fails open to the real binary, so a missing sfw or wormhook-scan never bricks the
command. sfw is the preferred layer, never an assumed one; it can vanish on a version-manager
node switch. Tell the user it is a tripwire, not a sandbox: `command npm` or
`./node_modules/.bin/...` bypasses it.
