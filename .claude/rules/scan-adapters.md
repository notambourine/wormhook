---
paths:
  - "scripts/wormhook-scan.sh"
  - "scripts/wormhook-scan.conf.sample"
  - "action.yml"
  - "commands/wormhook-setup.md"
---

# Out-of-band adapters (`wormhook-scan.sh`)

The Claude hook is **one trigger, not the engine**. `wormhook-scan.sh` adds the rest
(verbs `scan`/`check`/`git-hook`/`shell-init`/`install-*`/`status`/`config`), plus the
GitHub Action in `action.yml`. The user-facing installer is `/wormhook-setup`
(`commands/wormhook-setup.md`). Doctor soft nudges are silenceable via
`WORMHOOK_SKIP_{RG,SFW,VET,COVERAGE,CICD,DRIFT,SHELLGUARD,SIGAGE}=1` (or
`WORMHOOK_DOCTOR_QUIET=1` for all), set in settings.json `env` — a silenced nudge
degrades to ⚪, never to actual silence. The jq 🔴 (`doctor/deps.sh`) and the tamper 🔴
(`doctor/integrity.sh`) are **not** silenceable.

- **Adapters never duplicate detection.** Every verb drives the *unchanged* `wormhook.sh`
  by synthesizing the same stdin payload Claude sends — `SessionStart` for fast,
  `PostToolUse`+`npm install` for `--deep` (forces T2). A new pattern/grep belongs in
  `malware-patterns.sh`, never in the CLI.
- **Same injection rule as the engine.** Paths reach the engine only through `jq -n --arg`
  payloads; the launchd plist escapes every value via `_xml`.
- **The git hook must never self-flag.** Its body calls only the local CLI — no
  `curl|…|sh`, no `MALWARE_DROPPER_TOKENS_RE` strings. `tests/run.sh` runs the real
  `install-git-hook` body through the Tier-0 scan and asserts a clean verdict; keep the
  body clean if you touch `_hook_block`.
- **Installers are opt-in, idempotent, non-clobbering, reversible.** `install-git-hook`
  cooperates with an existing `core.hooksPath` and appends a `# >>> wormhook >>>` marker
  block to a pre-existing hook (never overwrites); `uninstall-git-hook` removes only that
  block. launchd label: `com.notambourine.wormhook-sweep` (org-namespaced; in no IOC set).
- **Discovery, not glob-literal.** A scan path resolves to the git repo(s) at/under it
  (`node_modules` pruned); a `node_modules`/`dist` dir is never scanned *as a project*.
  `--literal` bypasses discovery.
- **Config is per-machine, never hardcoded**: roots from `$WORMHOOK_SCAN_ROOTS` or
  `${XDG_CONFIG_HOME:-~/.config}/wormhook/scan-roots`; `wormhook-scan.conf.sample` seeds
  `config --init`.
- **Exec-guard layering = git hook *warns*, shell-init *blocks*.** `shell-init` is the
  out-of-Claude analog of the `PreToolUse` block: scoped to `npm/pnpm/yarn/bun/npx`,
  **deliberately not `node`** (too hot a path; version-manager breakage), `command`-based
  so it never self-recurses, fails open if the CLI is absent, and loads **after**
  nvm/asdf. Keep it opt-in; do not add `node`.
- **`action.yml` is a thin `check`-verb wrapper** mapping the `0/1/2` exit contract to
  job pass/fail — no detection logic, no signatures, no network. It gates the **merge**
  (required status check + a force-push-blocking ruleset), not the push — github.com has
  no `pre-receive`. Its embedded `run:` shell is not covered by the `scripts/*.sh`
  shellcheck glob and `actionlint` rejects action-metadata files — lint it by extracting
  `.runs.steps[].run` into `shellcheck`.
- Editing `wormhook-scan.sh`, `action.yml`, or `commands/wormhook-setup.md` is a behavior
  change → bump `plugin.json`.
