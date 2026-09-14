# wormhook

wormhook scans local files for supply-chain malware and blocks guarded Claude Code commands when it finds a match. It checks machine persistence, agent configuration, project source, and installed dependencies. It makes no network calls.

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

Clean prompts stay silent. Other scans show 🟢. Incomplete scans show 🟡 and fail open. Matches show 🚨. See `hooks/` and `scripts/` for the command filters.

Run `/wormhook-setup` in Claude Code to install the CLI and choose optional git hooks or scheduled scans. Then:

```sh
wormhook-scan ~/code/
wormhook-scan --deep ~/code/app
wormhook-scan --persistence
wormhook-scan config --init
wormhook-scan status
```

Paths discover repositories beneath them; `--literal` scans the supplied directory. With no paths, the CLI reads `$WORMHOOK_SCAN_ROOTS` or `${XDG_CONFIG_HOME:-~/.config}/wormhook/scan-roots`. `WORMHOOK_CONFIG` overrides the config file. Config globs cannot contain spaces. Exit codes: `0` clean, `1` findings, `2` incomplete coverage or invalid input.

Use the GitHub Action in a required PR check. Pin a release commit in place of `<sha>`. Install dependencies before the scan if they should be inspected.

```yaml
- uses: notambourine/wormhook@<sha>
  with:
    mode: deep
    fail-on: degraded
```

- **Coverage:** signatures include Shai-Hulud, ChainDrop, Miasma/Hades, Axios, SANDWORM_MODE, node-ipc, and TrapDoor indicators. The corpus and advisory provenance live in `scripts/`. This is pattern detection; a clean scan does not establish that code is safe.
- **Cache:** persistence and source are uncached. Dependency scans use lockfile and directory changes, with a 24-hour expiry (`WORMHOOK_T2_TTL_HOURS`). In-place overwrites can remain unseen until expiry; `--deep` forces a scan. Failed scans do not refresh the cache. Dependency scans stay rooted at the hook's working directory.
- **Containment:** `--quarantine` or `WORMHOOK_QUARANTINE=1` renames exact-match persistence artifacts to `<path>.wormhook-quarantined.<epoch>` and applies permissions `000`. Behavioral matches and symlinks are reported without quarantine. Restore the original path and permissions to undo it. Logs go under `${XDG_CACHE_HOME:-~/.cache}/notambourine/malware-scan/`. Running processes are unaffected.
- **Optional checks:** `install-launchd` adds a macOS sweep; `install-git-hook` adds git update scans. Their `uninstall-*` commands remove them. `eval "$(wormhook-scan shell-init)"` adds package-manager guards; load after version managers. With Socket Firewall, use `/wormhook-setup` to compose the wrappers. Direct binaries and `command npm` bypass the guard.
- **Health and limits:** startup checks report missing tools, stale signatures, modified scanner files, missing coverage, and credential exposure. `WORMHOOK_SKIP_<ITEM>=1` or `WORMHOOK_DOCTOR_QUIET=1` acknowledges optional nudges with ⚪. Missing `jq` and integrity alarms cannot be silenced. Replacing both scanner and checksum manifest bypasses integrity detection. Use registry and runtime defenses alongside wormhook.

MIT · [NoTambourine](https://notambourine.com)
