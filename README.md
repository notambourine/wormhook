# wormhook

wormhook blocks guarded Claude Code commands and human turns when local files match supply-chain malware signatures. It scans persistence, agent configuration, JavaScript/TypeScript source, and installed JavaScript dependencies without network calls.

```sh
claude plugin marketplace add notambourine/claude
claude plugin install wormhook@notambourine --scope user
```

Requires Bash and `jq`. Install `timeout` (GNU coreutils on macOS) to bound scan walks and `rg` for faster content scans; otherwise wormhook uses a built-in watchdog and `grep`.

| Trigger | Coverage | Finding |
| --- | --- | --- |
| Guarded JavaScript package-manager/runtime commands | Persistence and source; dependencies when stale, except before installs | Deny |
| Python, pip, pipx, and uv commands | Persistence and source | Deny |
| Each human prompt | Persistence and source | Block the turn |
| After installs or supported git updates | Persistence and source; JavaScript dependencies after installs or when stale | Warn |
| Session start | Persistence and source; dependencies when stale; health checks | Warn |

Clean prompts stay silent. Other clean scans show 🟢. Matches show 🚨. Ambiguous patterns and incomplete coverage show 🟡 and leave interactive commands unblocked. A prompt scan that outlives the hook timeout is killed silently; the next prompt or session start reports it, after that turn has run unscanned. See `scripts/` for command gates, detection, and advisory sources.

Run `/wormhook-setup` in Claude Code to install the CLI and choose optional git hooks or scheduled scans. Then:

```sh
wormhook-scan ~/code/
wormhook-scan --deep ~/code/app
wormhook-scan --persistence
wormhook-scan config --init
wormhook-scan status
```

Paths discover repositories beneath them; `--literal` scans the supplied directory. With no paths, the CLI reads `$WORMHOOK_SCAN_ROOTS` or `${XDG_CONFIG_HOME:-~/.config}/wormhook/scan-roots`. `WORMHOOK_CONFIG` overrides the config file. Config globs cannot contain spaces. Exit codes: `0` clean, `1` findings, `2` review needed, incomplete coverage, or invalid input.

Use the GitHub Action in a required PR check. Pin a release commit in place of `<sha>`. Install dependencies before the scan if they should be inspected.

```yaml
- uses: notambourine/wormhook@<sha>
  with:
    mode: deep
    fail-on: degraded
```

- **Coverage:** the plugin description lists campaigns; `scripts/` holds their signatures and primary advisories. Python coverage targets startup and persistence artifacts, not every installed package. PHP and Rust payloads are not scanned as source. A clean scan does not establish that code is safe.
- **Cache:** persistence and source are uncached. Dependency scans rerun when the engine, corpus, lockfile, or directory fingerprint changes, with a 24-hour expiry (`WORMHOOK_T2_TTL_HOURS`). `wormhook-scan --deps` sweeps also walk every dependency file and scan the ones whose change time is newer than the last scan, at any depth. A lockfile that changes without an install triggers the same walk in every caller instead of a full scan. Hooks, git hooks, and shell guards otherwise skip that walk, so an in-place overwrite stays unseen there until the next sweep or expiry; `--deep` forces a scan. `wormhook-scan` sweeps, `check`, and git hooks skip dependencies unless given `--deps`; the shell guards pass it, and `install-launchd --deps` bakes it into the sweep. Findings, dependency warnings, and incomplete dependency scans do not refresh the cache. Each dependency scan step stops after 20 seconds in hooks, git hooks, and shell guards, and after 10 minutes in `wormhook-scan` sweeps (`WORMHOOK_T2_TIMEOUT`, in seconds). Dependency scans cover the working directory and any directory a command targets with `cd`, `--prefix`, `--cwd`, `--dir`, or `-C`.
- **Containment:** `--quarantine` or `WORMHOOK_QUARANTINE=1` renames exact-match persistence artifacts to `<path>.wormhook-quarantined.<epoch>` and applies permissions `000`. Behavioral matches and symlinks are reported without quarantine. Restore the original path and permissions to undo it. Logs go under `${XDG_CACHE_HOME:-~/.cache}/notambourine/malware-scan/`. Running processes are unaffected.
- **Optional checks:** `install-launchd` adds a macOS sweep; `install-git-hook` adds git update scans; when it sets the global hooks path, each repository's own hooks still run. Their `uninstall-*` commands remove them. `eval "$(wormhook-scan shell-init)"` adds package-manager guards; load after version managers. With Socket Firewall, use `/wormhook-setup` to compose the wrappers. Direct binaries and `command npm` bypass the guard.
- **Health and limits:** startup checks report missing tools, stale signatures, modified scanner files, missing coverage, and credential exposure. `WORMHOOK_SKIP_<ITEM>=1` or `WORMHOOK_DOCTOR_QUIET=1` acknowledges optional nudges with ⚪. Missing `jq` and integrity alarms cannot be silenced. Replacing both scanner and checksum manifest bypasses integrity detection. Use registry and runtime defenses alongside wormhook.

MIT · [NoTambourine](https://notambourine.com)
