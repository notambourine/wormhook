# wormhook

A Claude Code plugin that blocks npm/node supply-chain malware at the tool hook, before it
runs. It denies `npm`/`pnpm`/`yarn`/`bun`/`npx`/`node` commands that hit a known indicator of
compromise. Named for Shai-Hulud, the self-replicating npm worm.

It covers one layer: agent-boundary persistence (AGENT-HIJACK). Rogue `SessionStart` hooks
and `mcpServers` entries injected into `.claude`/`.cursor`/`.continue`/`.vscode` configs,
`.vscode/tasks.json` `folderOpen` auto-exec, weaponized Python `.pth` startup hooks, poisoned
git hooks, and login-persistent LaunchAgent/systemd units. Registry-layer tools do not see
that half of the kill chain, and it re-runs every time you open the project.

The install layer is already well served, so wormhook cedes it and runs alongside pnpm 11's
release-age [cooldown](https://pnpm.io/supply-chain-security),
[Socket Firewall](https://socket.dev/), and [`safedep/vet`](https://github.com/safedep/vet).

Built and maintained by [NoTambourine](https://notambourine.com).

## Install

```bash
claude plugin marketplace add notambourine/claude
claude plugin install wormhook@notambourine --scope user
```

Already on `wormhook@wormhook`? A marketplace has no rename path, so remove the old one first:

```bash
claude plugin uninstall wormhook@wormhook
claude plugin marketplace remove wormhook
claude plugin marketplace add notambourine/claude
claude plugin install wormhook@notambourine --scope user
```

Requires `jq` and `bash`. Content scans use
[`ripgrep`](https://github.com/BurntSushi/ripgrep) when present (43x faster than BSD grep on
large trees) and fall back to `grep`.

There is nothing to invoke. At `SessionStart` a doctor checks runtime deps,
[engine self-integrity](#threat-model-the-scanner-as-a-target), version drift,
signature-corpus age, out-of-band coverage, CI gate coverage,
[companion firewalls](#beyond-the-tiers), and
[credential exposure](#blast-radius-exposure-audit). Each check is silent when healthy and
otherwise prints the one-liner that fixes it, so a quiet launch is a clean one.

## Run it outside Claude

`wormhook-scan` runs the same engine (Tiers 0-2, same `malware-patterns.sh`) from any shell.
It is a thin adapter with no duplicated detection, so every signature update reaches it for
free.

Run **`/wormhook-setup`** inside Claude Code for an interactive installer, or by hand:

```bash
# put wormhook-scan on your PATH (~/.local/bin)
bash "$(jq -r '[.plugins|to_entries[]|select(.key|startswith("wormhook@"))|.value[0].installPath][0] // "."' \
  ~/.claude/plugins/installed_plugins.json 2>/dev/null)/scripts/wormhook-scan.sh" install-cli

wormhook-scan ~/code/*/            # scan every git repo under ~/code (node_modules pruned)
wormhook-scan                      # no args -> roots from your config (see below)
wormhook-scan --deep ~/code/myapp  # force the Tier-2 node_modules walk
wormhook-scan --persistence        # only the machine-wide ($HOME) persistence checks
```

Each path resolves to the git repo(s) at or under it, so point at parents. An org dir expands
to its repos; `node_modules` is pruned. A machine-wide finding (a poisoned `~/.claude`, a
rogue LaunchAgent) is reported once at the top, not per repo. Exit codes gate a script or CI
step: `0` clean, `1` critical or machine persistence, `2` degraded.

**Config.** With no path args, `wormhook-scan` reads newline-delimited paths and globs from
`${XDG_CONFIG_HOME:-~/.config}/wormhook/scan-roots` (or `$WORMHOOK_SCAN_ROOTS`).
`wormhook-scan config --init` seeds a commented sample.

**Two automatic triggers**, both opt-in, both local, zero tokens:

```bash
wormhook-scan install-launchd            # hourly background sweep (macOS launchd)
                                         #   notifies + logs; --every SECONDS to retune
wormhook-scan install-git-hook           # post-merge/checkout/rewrite audit on EVERY
                                         #   `git pull` in ANY terminal (not just Claude)
```

`install-launchd` runs a native LaunchAgent on a timer with no Claude session and no LLM
tokens. On Linux it prints a systemd-timer or cron line instead.

`install-git-hook` cooperates with an existing `core.hooksPath` and never clobbers a hook you
already have. Each `git pull`/`checkout` prints **`🟢 wormhook: <repo> clean`** or a red
report of what changed plus any IOC, so you see it before `npm run dev`. The changed-file
list is capped at 20 because a `git pull` inside Claude Code puts it in the model's context;
the trailing `N files changed` line gives the true total.

`wormhook-scan status` shows what is installed. `uninstall-launchd` and `uninstall-git-hook`
reverse cleanly.

**Optional exec-guard.** A post-merge hook only warns; it cannot stop files that already
landed. To refuse to *run* on a compromised repo outside Claude:

```bash
eval "$(wormhook-scan shell-init)"   # in ~/.zshrc/.bashrc, AFTER any nvm/asdf
```

It wraps `npm`/`pnpm`/`yarn`/`bun`/`npx` (not `node`) so they fast-scan the current repo and
refuse if it trips the engine, catching IOCs that arrived without a git pull. **It is a
tripwire, not a sandbox:** `command npm` or a direct `./node_modules/.bin/...` bypasses it,
and it fails open if `wormhook-scan` is absent.

**Already using Socket Firewall?** Do not keep a separate `npm() { sfw npm ... }` block. It
and the guard define the same names, so whichever loads last silently clobbers the other.
Chain them in one wrapper, each layer fail-open. `/wormhook-setup` prints this block:

```bash
eval "$(wormhook-scan shell-init)"   # defines __wormhook_guard
# Helper names are DOUBLE-underscore on purpose: Claude Code's shell snapshot drops
# single-underscore functions (zsh's `_name` completion namespace), which would leave the
# surviving npm/... wrappers calling an undefined helper - bricking npm inside its Bash tool.
__sc_run() {
  local pm="$1"; shift
  command -v __wormhook_guard >/dev/null 2>&1 && { __wormhook_guard || return 1; }
  if command -v sfw >/dev/null 2>&1; then command sfw "$pm" "$@"; else command "$pm" "$@"; fi
}
for pm in npm pnpm yarn bun npx; do eval "${pm}() { __sc_run ${pm} \"\$@\"; }"; done; unset pm
```

### Opt-in quarantine

A Tier-0 finding means the payload already ran, and by default the artifact keeps working
until a human acts. `WORMHOOK_QUARANTINE=1` contains the exact-match artifacts only: the
known persistence paths (droppers, LaunchAgents, `~/.dev-env`), a `.pth` matching the
known-bad name or SHA-256, and the known-bad `.abi3.so` basenames.

```bash
wormhook-scan --quarantine                    # one fleet scan with containment
wormhook-scan install-launchd --quarantine    # the hourly sweep contains at 03:00
# in Claude Code: settings.json -> "env": { "WORMHOOK_QUARANTINE": "1" }
```

Containment renames the artifact to `<path>.wormhook-quarantined.<epoch>` and `chmod 000`s
it: reversible, forensics-preserving, and dead on the next login or interpreter start.
Nothing is killed, unloaded, or deleted. Behavioral matches stay report-only, since an
unattended rename demands exact-match confidence. A root-owned artifact degrades to the
normal advisory. Every action is logged to
`~/.cache/notambourine/malware-scan/quarantine.log`.

It is off by default everywhere, because containment inverts the fail-open bias.

### Gate pull requests on GitHub (Action)

`action.yml` runs the same engine as a CI check on the checked-out tree:

```yaml
# .github/workflows/supply-chain.yml
name: supply-chain
on: pull_request
permissions:
  contents: read
jobs:
  wormhook:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: npm ci                       # optional - installs deps so the deep scan sees them
      - uses: notambourine/wormhook@<sha>  # vX.Y.Z (see "Pinning" below)
        # with:
        #   path: .            # dir to scan (default: workspace root)
        #   mode: deep         # deep = Tier-2 node_modules walk (default); fast = source-only
        #   fail-on: critical  # critical (default) | degraded (fail-closed on 🟡 too)
```

A 🚨 verdict fails the job (exit `1`) and prints the finding banner above the error
annotation. A 🟡 degraded scan passes unless you set `fail-on: degraded`. Like every other
trigger it is zero-network: `stat`, `grep`, and `jq` over the tree.

**Pinning.** Pin the commit a release tag points at and put that tag in a trailing comment,
so Dependabot version-tracks the action and opens one PR per wormhook release:

```sh
gh release view --repo notambourine/wormhook --json tagName,targetCommitish
```

Pinning a branch-head SHA that no tag points at is the failure mode: Dependabot resolves no
version, falls back to tracking `main`, and opens a PR for every commit in this repo.

**This gates the merge, not the push.** github.com has no `pre-receive` hook (GitHub
Enterprise Server only), so pair the action as a required status check with a ruleset that
blocks force pushes and requires a PR. Malware can sit on a feature branch; the failing check
stops the merge.

## How it works

The scan is tiered by cost times volatility, so the expensive part only runs when it can find
something new.

- **Tier 0, persistence and agent/dev-env injection.** Cheap stats, every event, never
  cached. RAT droppers (`com.apple.act.mond`), runner installs (`~/.dev-env`), agent-hijack
  droppers and rogue `mcpServers`/`hooks` entries across Claude Code/Cursor/Continue/
  Windsurf, poisoned git hooks, `gh-token-monitor` units, weaponized Python `.pth` startup
  hooks.
- **Tier 1, project source, `package.json` lifecycle, and CI config.** Cheap, every gated
  event. Install-lifecycle scripts, injected loaders in the source tree, `.github/workflows`
  and `.releaserc` poisoning. This tier blocks an install before it can run a dropper. It
  reads the manifest of the directory the command actually targets (`cd sub && npm install`,
  `npm --prefix`, `yarn --cwd`) and every workspace package's manifest (`workspaces` globs
  plus `pnpm-workspace.yaml`), because a root install runs each workspace's lifecycle.
  Compound and env-prefixed commands (`CI=1 npm install`) gate too.
- **Tier 2, `node_modules` content and IOC scan.** Expensive. Runs only when deps changed
  (keyed off lockfile hash plus `node_modules` dir mtimes 2 levels deep, cached under
  `~/.cache/notambourine/`) or when the last clean scan is older than 24 hours
  (`WORMHOOK_T2_TTL_HOURS`). The key cannot see an in-place overwrite of an existing dep file,
  so the cache ages out to bound that window. It fails open: a scan that hits its `timeout`
  reports 🟡, does not refresh the cache, and never blocks your launch.

### Beyond the tiers

- **Python execution gating.** `pip`/`pip3`/`pipx`/`uv`/`python`/`python3` trigger the Tier-0
  sweep at `PreToolUse`, so the `.pth` startup-hook check runs before the interpreter
  auto-executes a poisoned site-packages `.pth` (the Hades/Miasma PyPI vector). The sweep
  covers project venvs, the active `$VIRTUAL_ENV`/`$CONDA_PREFIX`, and the user and global
  site-packages a no-venv `pip install` lands in (`~/.local`, macOS `~/Library/Python`,
  Homebrew, `/usr/local`, python.org framework, every pyenv version, uv-managed
  interpreters). This gates execution to run the persistence scan early; it does not audit
  PyPI package contents.
- **`UserPromptSubmit` continuous monitor.** T0 and T1 re-run every human turn and, unlike
  `SessionStart`, can block. Persistence planted mid-session by a `pip install` or an agent
  file-write is caught at the next prompt rather than the next npm or git command. Silent
  when clean, since it would otherwise spam the transcript.
- **Companion-firewall nudge.** Blocking malicious or too-new package *versions* needs
  registry intelligence, which
  [Socket Firewall](https://docs.socket.dev/docs/socket-firewall) (`sfw`) and
  [`safedep/vet`](https://github.com/safedep/vet) do better than a hook can. wormhook stays
  fully local; the `SessionStart` `firewall` light nudges you to install them and goes silent
  once both are present.

### Blast-radius exposure audit

Detection has a false-negative rate, so the `SessionStart` `exposure` light answers the other
question: how bad is it when we miss? It prints a punch list of long-lived secrets sitting in
worm-targeted paths, and is silent when clean:

- **Passphrase-less SSH private keys**, detected via `ssh-keygen -y -P ''`, which catches the
  new OpenSSH key format that grepping for `ENCRYPTED` misses. It names the specific files.
- **Plaintext GitHub tokens**: a `ghp_` PAT (non-expiring by default) or `gho_` OAuth token
  in `~/.git-credentials`, the `gh` config, or `GH_TOKEN`/`GITHUB_TOKEN`.
- **A `.env` in the repo with a live-looking secret**, gated on a real credential shape (AWS
  `AKIA...`, GitHub/OpenAI/Google keys, a PEM block) rather than any `KEY=` line.

It is advisory and never blocks, because posture is not an IOC. It stays capped at these
three near-zero-FP checks so it can run every launch without becoming a nag; the rest of
blast-radius management is environmental (sandboxed credential context, expiring tokens,
hardware-held SSH keys, secrets-manager injection over `.env`) and lives outside this tool.

```mermaid
flowchart TD
    A([SessionStart<br/>on launch]):::evt
    B([PreToolUse<br/>npm / npx / pnpm / yarn / bun / node<br/>pip / pipx / uv / python]):::evt
    C([PostToolUse<br/>after install-class or pip/uv install]):::evt
    D([PostToolUse<br/>after git pull / merge / checkout / switch / rebase]):::evt
    E([UserPromptSubmit<br/>every human turn]):::evt

    B --> Bg{matches GATE_RE<br/>or PYGATE_RE?}
    Bg -- no --> ALLOW
    Bg -- yes --> T0
    C --> Cg{matches INSTALL_RE<br/>or PYINSTALL_RE?}
    Cg -- no --> ALLOW
    Cg -- yes --> T0
    D --> Dg{matches<br/>GIT_RE?}
    Dg -- no --> ALLOW
    Dg -- yes --> T0
    A --> T0
    E --> T0

    T0["<b>Tier 0</b> - persistence &amp; agent-hook injection<br/><i>cheap stats, ALWAYS, never cached</i>"]:::tier
    T0 --> T0c{IOC?}
    T0c -- hit --> G
    T0c -- clean --> T1

    T1["<b>Tier 1</b> - project source + package.json lifecycle<br/><i>cheap, every gated event</i>"]:::tier
    T1 --> T1c{IOC?}
    T1c -- hit --> G
    T1c -- clean --> CACHE

    CACHE{deps changed?<br/>lockfile hash + dir mtimes 2 deep, 24h TTL}:::cache
    CACHE -->|no, cache hit| DONE
    CACHE -->|yes or stale| T2

    T2["<b>Tier 2</b> - node_modules content/IOC scan<br/><i>expensive, only when deps changed</i>"]:::tier
    T2 --> T2c{IOC?}
    T2c -- hit --> G
    T2c -- clean --> DONE

    G{which<br/>event?}:::guard
    G -->|PreToolUse: deny + systemMessage| BLOCK([BLOCK]):::block
    G -->|UserPromptSubmit: decision block + systemMessage| BLOCK
    G -->|SessionStart or PostToolUse| SURFACE([warn: systemMessage + additionalContext]):::warn

    ALLOW([allow]):::ok
    DONE([done, allow, 🟢/🟡 status line]):::ok

    classDef evt fill:#1f6feb,stroke:#0d419d,color:#fff
    classDef tier fill:#161b22,stroke:#30363d,color:#e6edf3
    classDef cache fill:#3d2c00,stroke:#9e6a03,color:#ffdf5d
    classDef guard fill:#30363d,stroke:#6e7681,color:#fff
    classDef block fill:#67060c,stroke:#f85149,color:#fff
    classDef warn fill:#7d4e00,stroke:#d29922,color:#fff
    classDef ok fill:#0f5323,stroke:#3fb950,color:#fff
```

| Event | When | What |
|-------|------|------|
| `PreToolUse` | before an `npm`/`node`/... or `pip`/`uv`/`python` command | Tier 0-1 (plus Tier 2 if deps drifted); **blocks** on a hit (`permissionDecision: "deny"`) |
| `PostToolUse` | after an install-class or `pip`/`uv` install command | re-scan of the freshly written tree (Python installs re-run the Tier-0 `.pth` check); warns on a hit |
| `PostToolUse` | after a working-tree-rewriting `git` op (`pull`/`merge`/`checkout`/`switch`/`rebase`) | Tier 0-1 on the new tree (plus Tier 2 on dep drift); warns on a hit. Catches IOCs that arrive over git with no npm involved |
| `UserPromptSubmit` | every human turn | Tier 0-1 ([continuous monitor](#beyond-the-tiers)); **blocks** on a hit (`decision: "block"`). Silent when clean |
| `SessionStart` | on launch | Tier 0-1 (plus Tier 2 on a stale cache); warns on a hit |

Those five are the Claude-session triggers; the same tiers run outside Claude via
[`wormhook-scan`](#run-it-outside-claude).

`PreToolUse` and `UserPromptSubmit` are the hard blocks. They stop the command or turn
regardless of whether the model cooperates. `SessionStart` and `PostToolUse` run after the
point of no return and cannot abort, so they warn: a `systemMessage` to you plus
`additionalContext` telling the model to refuse follow-up installs.

Every scan ends with a one-line verdict, so silence is never ambiguous. 🟢 clean. 🟡 passed
with degraded coverage, meaning a `timeout` was hit or signatures are missing, and the cache
was not refreshed. 🚨 findings. Non-gated commands stay silent.

## What it detects

- **Shai-Hulud 1.0-3.0 and the Mini variant.** Obfuscation markers, runner fingerprints,
  ransom tokens, `git-tanstack` typosquat exfil, payload filenames, SHA256 IOCs.
- **SAP-CAP / AntV / TeamPCP wave** (Apr-Jun 2026). The `ctf-scramble-v2` PBKDF2 salt, the
  `firedalazer` and `OhNoWhatsGoingOnWithGitHub` GitHub-commit-search C2 keywords, the
  `__DAEMONIZED` guard, the russian-locale kill-switch, the C2 host `audit.checkmarx.cx`, and
  the `kitty-monitor` LaunchAgent/systemd unit plus its `~/.local/share/kitty/cat.py` daemon.
- **Axios / plain-crypto-js RAT** (Sapphire Sleet / DPRK). `com.apple.act.mond` persistence,
  `sfrclak` C2 beacons.
- **SANDWORM_MODE**, AI-toolchain poisoning. The marker, `*.workers.dev/{exfil,drain}` C2,
  `freefan`/`fanfree` DNS-tunnel domains, the drain bearer token.
- **Hades / Miasma PyPI wave** (Jun 2026). MCP typosquats (`openai-mcp`, `tiktoken-mcp`, ...)
  shipping a weaponized Python `.pth` startup hook (to Bun, to `_index.js`, the Hades
  stealer) and native import-time `.abi3.so` modules (`ensmallen_haswell`/`core2`) that
  execute on package import with no `.pth`, plus `/tmp/.sshu-setup.js` SSH propagation.
  Caught at Tier 0, and `pip`/`uv`/`python`
  [trigger that scan at `PreToolUse`](#beyond-the-tiers).
- **ChainDrop / keyv-cacheable wave** (Aug 2026). The `setup.mjs` loader and `math_init.js`
  payload by SHA256 hash, plus the Ethereum C2-resolution contract address embedded in the
  payload (`0xE1f2...3103`). The C2 domains resolve at runtime, so they belong to a network
  blocklist rather than a content grep. The GitHub commit-search fallback markers
  (`thebeautiful{march,snads}oftime`) were already covered.
- **"A9-0522" build** (Aug 2026, field-observed). A ChainDrop-lineage payload appended to a
  repo's own `tailwind.config.js` behind roughly 500 spaces of padding, resolving its C2 from
  wallet `0xa322e5f3...` over public Ethereum RPC. Blocks on the dot-form campaign tag
  (`global.i="A9-0522-4"`; the Shai-Hulud 1.0 signature only matched the bracket form) and
  the `:443/0x/{cl,ls}` endpoints. `obfuscator.io` `splitStrings` chops every host into
  10-char chunks, so a reassembled domain matches nothing on disk; the unsplit tag, wallet
  prefix, path, and `X-Payload-B6*` header are the handles. The `obfuscator.io` string-array
  accessor alias lands with it as a campaign-agnostic technique marker. The padding itself
  stays unmatched: `eslint-plugin-import` ships Babel output with 912-space runs.
- **Miasma RAT / AsyncAPI compromise** (`miasma-train-p1`, Jul 2026). An import-time loader
  that runs on `require()` and defeats `--ignore-scripts`. Tier-0 checks for `NodeJS/sync.js`,
  the `~/.config/.miasma` lock dir, and the `miasma-monitor` login unit, plus Tier-2 payload
  markers (`M-RED-TEAM v6.4`, `_miasma._tcp`) and the two IPFS second-stage CIDs.
- **Dev-env and CI injection.** Rogue `mcpServers` and SessionStart-hook entries across
  `.claude`/`.cursor`/`.continue`/`.vscode`, including a `.vscode/tasks.json` `folderOpen`
  task that re-runs `setup.mjs` on every project open. Poisoned git hooks
  (`init.templateDir`/`core.hooksPath`), `pull_request_target` workflows calling the
  `ci-quality/code-quality-check` action, `@semantic-release/exec` carrier injection.
- **Remote-eval loaders.** `atob(process.env....)` plus `eval`/`Function(await ...)`
  behavioral fingerprints, plus field-observed C2 and exfil hosts.
- **Campaign-agnostic behaviors** (`node_modules` tier only). Decode-then-`eval` droppers,
  `/dev/tcp/` reverse shells, `JSON.stringify(process.env)` bulk exfil. Higher-FP, so scoped
  to third-party deps.

The threat path this is organized around: a contributor or compromised maintainer's PR
slipping malware into a repo you already work in. Where `pull_request_target` and
`@semantic-release/exec` are legitimately common, the scans key off campaign-specific
fingerprints (the known-bad action slug, the carrier `require()`) so CI false positives stay
at zero.

## What it deliberately doesn't do

Each row needs context a synchronous, no-network hook lacks, and forcing it in would trade
away the near-zero false-positive rate that makes the block trustworthy. Run the owning layer
alongside.

| Check it doesn't do | Layer that owns it |
|---------------------|--------------------|
| Package existence / typosquatting / maintainer-change (needs registry lookups) | [Socket Firewall](https://docs.socket.dev/docs/socket-firewall), [`safedep/vet`](https://github.com/safedep/vet) |
| Version-age "cooldown" (refuse versions published in the last N days) | native now: pnpm [`minimumReleaseAge`](https://pnpm.io/supply-chain-security) (default-on in pnpm 11), npm `min-release-age`; also Socket Firewall |
| Known-CVE scanning (needs an advisory feed) | `vet`, `npm audit`, Dependabot |
| Secret detection | [`betterleaks`](https://github.com/betterleaks/betterleaks), `trufflehog` (this repo runs betterleaks over full history in CI) |
| Generic Actions hardening (unpinned actions, broad perms) | `actionlint`, `zizmor` |
| Runtime network monitoring (live C2/DNS exfil/sockets) | install-time sandbox / eBPF monitor |
| AST + reachability analysis | [depsec](https://depsec.dev/) |
| Flagging any `child_process` exec/spawn (block-tier FP catastrophe) | [GuardDog](https://github.com/DataDog/guarddog) (triage) |
| Credential-read to exfil (needs taint tracking) | GuardDog (`mode: taint`) |
| Auditing PyPI package contents (wormhook gates `pip`/`uv`/`python` execution only, to run the Tier-0 `.pth` check early) | install-time sandbox / `vet` / GuardDog |

The design bet is independence over coverage: a fast, no-network, near-zero-FP gate at the
agent boundary that trips on a specific, evidence-backed set of indicators.

## Threat model: the scanner as a target

The engine and its signatures live in the installed plugin dir under `$HOME`, writable by any
process with `$HOME` write access, which is the same access the AGENT-HIJACK campaigns
already use to write `~/.claude/setup.mjs`.

- **Covered:** a worm that writes a payload next to the scanner. Tier 0 re-runs on every
  event, uncached, exactly because `~/.claude` is attacker-writable.
- **Residual gap:** a worm that edits the plugin itself. One appended `exit 0` in
  `scripts/wormhook.sh`, or one emptied signature array, silences every surface at once, and
  a neutered engine still prints its green status line. `.tripwire-allow` deliberately exempts
  the engine and signature corpus from content scanning, because an IOC corpus looks like
  malware, so an external scanner does not flag the edit either.

The `SessionStart` `integrity` light closes the silent half of that gap. It verifies
`scripts/wormhook.sh` and `scripts/malware-patterns.sh` against a shipped SHA-256 manifest
(`scripts/integrity.sha256`) every launch and goes 🔴 on any mismatch. Like the jq "scans are
OFF" alarm, it is deliberately not silenceable. It cannot stop an attacker who also rewrites
the manifest, but it raises the bar from a one-line append to a coordinated edit, and a
neutered engine no longer reports green. CI regenerates-or-fails on the manifest, so a
legitimate engine change cannot ship a stale one. The plugin dir is also a git checkout:
`git -C <plugin-dir> status` shows any local modification, and a marketplace update restores
a clean copy.

## Signatures

All signatures live in [`scripts/malware-patterns.sh`](./scripts/malware-patterns.sh),
sourced by the hook so a new pattern reaches every tier at once. Patterns are extended regex
and parse identically under bash and zsh.

Signature detection is retrospective, so freshness is tracked. `WORMHOOK_SIGNATURES_ASOF`
records when the corpus was last verified against current advisories, and the `SessionStart`
`sigage` light goes 🟡 past `WORMHOOK_SIGAGE_MAX_DAYS` (default 60). A stale corpus would
otherwise keep reporting green while detecting only last year's campaigns.

## Sources

IOCs trace to primary vendor and government advisories. Per-marker provenance is mirrored in
the header of [`scripts/wormhook.sh`](./scripts/wormhook.sh).

- **CISA** - [npm ecosystem supply-chain compromise](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) (Shai-Hulud 1.0)
- **Microsoft** - [Shai-Hulud 2.0 guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- **Datadog** - [Shai-Hulud 2.0 npm worm](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- **Wiz** - [Mini Shai-Hulud: TanStack & more](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- **Semgrep** - [Axios supply-chain incident](https://semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/)
- **Socket** - [SANDWORM_MODE](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning), [Miasma & Hades (PyPI/MCP)](https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious)
- **Snyk** - [Mini Shai-Hulud hits AntV](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/) (`kitty-monitor`, `firedalazer`, `.vscode/tasks.json` `folderOpen`)
- **Unit 42** - [Monitoring npm supply-chain attacks](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) (`audit.checkmarx.cx`, `OhNoWhatsGoingOnWithGitHub` C2)
- **Mend** - [Shai-Hulud SAP CAP via Claude Code](https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/) (`ctf-scramble-v2`, `__DAEMONIZED`, russian-locale kill-switch)
- **Microsoft** - [AsyncAPI compromise & Miasma import-time payload](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) (`miasma-train-p1`, `NodeJS/sync.js`, `.miasma`, IPFS CIDs), [ChainDrop anatomy](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/)
- **Elastic** - [ChainDrop / keyv Shai-Hulud wave](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain) (payload hashes, ETH contract)
- **JFrog** - [Shai-Hulud is back (Aug 2026)](https://research.jfrog.com/post/shai-hulud-is-back-august/) (`math_init.js` hash pairing, runtime C2 resolution)
- **Field-observed, no advisory** - the "A9-0522" build. Its markers come from a sample
  recovered off a compromised account, not a named vendor page, so they sit a provenance tier
  below every entry above (the same class as `api.masscan.cloud` and `m-kosche.com`). Only
  the two zero-FP-verified markers reach the blocking tier; the rest stay warn-only.

## License

MIT. See [LICENSE](./LICENSE).
