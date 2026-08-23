# wormhook

wormhook is a local supply-chain tripwire for Claude Code. It stops package-manager and
runtime commands when known malware or persistence has landed in the repository, its
dependencies, or the surrounding developer environment.

Registry tools answer whether a package is safe to install. wormhook answers a different
question: has a known payload reached this machine, and is the agent about to run it? It
covers rogue hooks and MCP servers, `folderOpen` tasks, poisoned git hooks, weaponized Python
`.pth` files, persistent LaunchAgent or systemd units, and campaign-specific source and
`node_modules` indicators.

Use it alongside pnpm's release-age
[cooldown](https://pnpm.io/supply-chain-security),
[Socket Firewall](https://socket.dev/), or
[`safedep/vet`](https://github.com/safedep/vet). wormhook makes no network calls and does not
replace registry intelligence.

Named for Shai-Hulud, the self-replicating npm worm. Built and maintained by
[NoTambourine](https://notambourine.com).

## Install

```bash
claude plugin marketplace add notambourine/claude
claude plugin install wormhook@notambourine --scope user
```

Requires `bash` and `jq`. Content scans use
[`ripgrep`](https://github.com/BurntSushi/ripgrep) when available and fall back to `grep`.

There is nothing else to start. wormhook checks the environment when Claude opens, scans
before guarded commands run, rescans after installs and git operations, and monitors each
human turn for persistence written during the session. Clean checks stay quiet. A finding
blocks where Claude's hook lifecycle still permits a block and warns everywhere else.

The startup doctor also checks dependencies, plugin version, signature age,
[scanner integrity](#scanner-integrity), CI and out-of-band coverage, companion firewalls,
and [credential exposure](#credential-exposure). A failed check prints its repair command.

### Migrating from the old marketplace

Claude marketplaces have no rename path. Remove `wormhook@wormhook` before installing the
current plugin:

```bash
claude plugin uninstall wormhook@wormhook
claude plugin marketplace remove wormhook
claude plugin marketplace add notambourine/claude
claude plugin install wormhook@notambourine --scope user
```

## Protection model

Each scan moves from the cheapest, most volatile surface to the most expensive:

- **Tier 0 — machine persistence and agent injection.** Runs on every event and is never
  cached. It checks known droppers and runner installs, editor hooks and MCP configuration,
  git hooks, persistent services, and Python startup files.
- **Tier 1 — project source and execution wiring.** Runs on every gated event. It checks
  source loaders, lifecycle scripts, GitHub workflows, and release configuration. For package
  installs it resolves the actual target directory (`cd`, `--prefix`, or `--cwd`) and every
  workspace manifest reached by the root install. Compound and environment-prefixed commands
  are gated too.
- **Tier 2 — installed dependencies.** Scans `node_modules` when the lockfile changes,
  directory mtimes change two levels deep, or the last clean result exceeds the 24-hour
  `WORMHOOK_T2_TTL_HOURS` default. The TTL bounds the cache's blind spot for in-place file
  replacement. A timeout produces a degraded verdict and leaves the old cache stale.

Python commands (`pip`, `pip3`, `pipx`, `uv`, `python`, and `python3`) run Tier 0 before the
interpreter starts. The scan covers project, active virtual or Conda, user, Homebrew,
python.org, pyenv, and uv-managed site-package locations. This catches known poisoned `.pth`
startup hooks; it is not a general PyPI package audit.

| Claude event | Scan | Result on a finding |
|--------------|------|---------------------|
| Before `npm`, `node`, `pnpm`, `yarn`, `bun`, or `npx` | Tiers 0–1; Tier 2 when dependencies drift | Deny the command |
| Before `pip`, `pipx`, `uv`, or Python | Tiers 0–1 | Deny before a poisoned `.pth` can load |
| After an install | Rescan the written tree | Warn |
| After `git pull`, `merge`, `checkout`, `switch`, or `rebase` | Tiers 0–1; Tier 2 when dependencies drift | Warn |
| Every human turn | Tiers 0–1 | Block the turn; silent when clean |
| Session start | Tiers 0–1; Tier 2 when stale | Warn |

The scanner returns 🟢 clean, 🟡 degraded coverage, or 🚨 findings. Degraded scans fail open
and do not refresh the cache. Commands outside the gate stay silent.

## Protect work outside Claude

`wormhook-scan` exposes the same engine and signatures to shells, background jobs, and CI.
Run **`/wormhook-setup`** for an interactive install or put the CLI on `PATH` manually:

```bash
bash "$(jq -r '[.plugins|to_entries[]|select(.key|startswith("wormhook@"))|.value[0].installPath][0] // "."' \
  ~/.claude/plugins/installed_plugins.json 2>/dev/null)/scripts/wormhook-scan.sh" install-cli

wormhook-scan ~/code/*/            # every Git repo below ~/code; prunes node_modules
wormhook-scan                      # roots from the scan-roots config
wormhook-scan --deep ~/code/myapp  # force Tier 2
wormhook-scan --persistence        # machine-wide persistence only
```

Each path expands to the Git repositories at or below it. Machine-wide findings are reported
once, not once per repository. Exit codes are `0` for clean, `1` for critical findings or
machine persistence, and `2` for degraded coverage.

With no path, the CLI reads newline-delimited paths and globs from
`${XDG_CONFIG_HOME:-~/.config}/wormhook/scan-roots`, or `$WORMHOOK_SCAN_ROOTS` when set.
`wormhook-scan config --init` creates a commented sample.

### Persistent local checks

These opt-in checks run without Claude or LLM tokens:

```bash
wormhook-scan install-launchd   # hourly macOS sweep; --every SECONDS changes the interval
wormhook-scan install-git-hook  # audit every merge, checkout, and rewrite in any terminal
```

`install-launchd` creates a native macOS LaunchAgent. On Linux it prints an equivalent
systemd timer or cron entry. `install-git-hook` preserves an existing `core.hooksPath` and
existing hooks. Each checkout or pull prints `🟢 wormhook: <repo> clean` or a finding report;
changed-file output stops at 20 entries while retaining the exact total.

Use `wormhook-scan status` to inspect installed checks. `uninstall-launchd` and
`uninstall-git-hook` remove them.

### Shell guard

The git hook reports after files land. To refuse package-manager commands in a compromised
repository outside Claude, load the optional shell guard after nvm or asdf:

```bash
eval "$(wormhook-scan shell-init)"
```

It wraps `npm`, `pnpm`, `yarn`, `bun`, and `npx`, but not `node`. The guard is a tripwire,
not a sandbox: `command npm` and direct `node_modules/.bin` execution bypass it, and a missing
`wormhook-scan` fails open.

Socket Firewall defines the same wrapper names. Chain both checks so the last-loaded wrapper
does not replace the first; `/wormhook-setup` prints this configuration:

```bash
eval "$(wormhook-scan shell-init)"
# Claude drops single-underscore zsh functions from its shell snapshot.
__sc_run() {
  local pm="$1"; shift
  command -v __wormhook_guard >/dev/null 2>&1 && { __wormhook_guard || return 1; }
  if command -v sfw >/dev/null 2>&1; then command sfw "$pm" "$@"; else command "$pm" "$@"; fi
}
for pm in npm pnpm yarn bun npx; do eval "${pm}() { __sc_run ${pm} \"\$@\"; }"; done; unset pm
```

## Gate pull requests

The GitHub Action runs the same network-free engine against the checked-out tree:

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
      - run: npm ci                        # optional: lets the deep scan inspect dependencies
      - uses: notambourine/wormhook@<sha>  # vX.Y.Z
        # with:
        #   path: .            # default: workspace root
        #   mode: deep         # deep (default) or fast
        #   fail-on: critical  # critical (default) or degraded
```

🚨 fails the job with exit code `1`. 🟡 passes unless `fail-on: degraded` is set. Pin the
commit referenced by a release tag and retain the tag in the trailing comment so Dependabot
can track releases:

```sh
gh release view --repo notambourine/wormhook --json tagName,targetCommitish
```

An untagged branch-head SHA makes Dependabot track `main` instead of a release. The action
gates merges, not pushes; use a ruleset that requires this check and pull requests and blocks
force pushes. GitHub.com does not expose `pre-receive` hooks.

## Optional containment

Tier-0 findings may indicate that a payload has already run. wormhook reports them by
default. Quarantine is opt-in because unattended containment demands exact-match confidence.

```bash
wormhook-scan --quarantine                    # contain during one fleet scan
wormhook-scan install-launchd --quarantine    # contain during the hourly sweep at 03:00
# Claude settings.json: "env": { "WORMHOOK_QUARANTINE": "1" }
```

Quarantine applies only to known persistence paths, known-bad `.pth` names or SHA-256 hashes,
and known-bad `.abi3.so` basenames. It renames each artifact to
`<path>.wormhook-quarantined.<epoch>` and applies `chmod 000`; it does not kill processes,
unload services, or delete files. Behavioral findings remain report-only, and root-owned
artifacts fall back to an advisory. Actions are logged in
`~/.cache/notambourine/malware-scan/quarantine.log`.

## Credential exposure

Detection always has a false-negative rate. The startup exposure audit reports three
high-impact conditions that would widen the blast radius of a miss:

- SSH private keys without passphrases, tested with `ssh-keygen -y -P ''` and reported by
  filename.
- Plaintext `ghp_` or `gho_` GitHub tokens in `~/.git-credentials`, the `gh` config,
  `GH_TOKEN`, or `GITHUB_TOKEN`.
- Repository `.env` values shaped like AWS, GitHub, OpenAI, or Google credentials, or PEM
  blocks.

The audit is advisory: weak credential posture is not an indicator of compromise. Broader
protection belongs in expiring credentials, hardware-held SSH keys, sandboxed credential
contexts, and secret-manager injection.

## Detection coverage

- **Shai-Hulud 1.0–3.0 and the Mini variant.** Coverage includes obfuscation markers, runner
  fingerprints, ransom tokens, `git-tanstack` exfiltration, payload names, hashes, and the
  published `webhook.site` exfil ID. The v1 `shai-hulud-workflow.yml` dropper matches by
  basename because no payload body was published. The bare `webhook.site` domain is omitted;
  it appears in legitimate test fixtures.
- **SAP-CAP / AntV / TeamPCP wave** (Apr–Jun 2026). Coverage includes the
  `ctf-scramble-v2` PBKDF2 salt, the
  `firedalazer` and `OhNoWhatsGoingOnWithGitHub` GitHub-commit-search C2 keywords, the
  `__DAEMONIZED` guard, the Russian-locale kill switch, `audit.checkmarx.cx`, and
  the `kitty-monitor` LaunchAgent/systemd unit plus its `~/.local/share/kitty/cat.py` daemon.
- **Axios / plain-crypto-js RAT** (Sapphire Sleet / DPRK). Coverage includes
  `com.apple.act.mond` persistence and `sfrclak` C2 beacons.
- **SANDWORM_MODE AI-toolchain poisoning.** Coverage includes the campaign marker,
  `*.workers.dev/{exfil,drain}` C2 paths, the `freefan` and `fanfree` DNS-tunnel domains, and
  the drain bearer token.
- **node-ipc credential stealer** (May 2026). Three releases carried the same 80 KB
  obfuscated IIFE appended to `node-ipc.cjs`, firing on every `require()` with no lifecycle
  hook to gate. wormhook matches its custom base-16 alphabet (`0123456789GHJKMP`), hardcoded
  HMAC key, DNS-tunnel C2, and the payload hash. It does not block the three affected version
  numbers; [registry-aware tools own version blocking](#scope-boundaries).
- **Hades / Miasma PyPI wave** (Jun 2026). MCP typosquats (`openai-mcp`, `tiktoken-mcp`, ...)
  shipped a weaponized `.pth` startup hook, native import-time `.abi3.so` modules, and
  `/tmp/.sshu-setup.js` SSH propagation. Tier 0 checks their known names and hashes before
  `pip`, `uv`, or Python can load the startup hook.
- **ChainDrop / keyv-cacheable wave** (Aug 2026). The `setup.mjs` loader and `math_init.js`
  payload match by SHA-256, along with the Ethereum C2-resolution contract embedded in the
  payload (`0xE1f2...3103`; the C2 domains resolve at runtime, so the contract, not a domain,
  is the durable handle). Four domains served by that contract—`npm-cache.com`,
  `awqhnjewqjkl.icu`, `pypi-get.com`, and `js-mirror.com`—provide a Tier-2 backstop for
  builds that hardcode one. The wave's GitHub commit-search fallback markers
  (`thebeautiful{march,snads}oftime`) were already covered. Its Dune-themed payload strings
  are not useful signatures: Unit 42 recovered them from a Base91 table with 73 per-call
  alphabets, so the plaintext never reaches disk.
- **"A9-0522" build** (Aug 2026, field-observed). A ChainDrop-lineage payload appended to a
  repo's own `tailwind.config.js` behind roughly 500 spaces of padding, resolving its C2 from
  wallet `0xa322e5f3...` over public Ethereum RPC. Blocks on the dot-form campaign tag
  (`global.i="A9-0522-4"`) and `:443/0x/{cl,ls}` endpoints. Because `obfuscator.io`
  `splitStrings` fragments every host, the durable handles are the unsplit tag, wallet prefix,
  path, `X-Payload-B6*` header, and string-array accessor alias. Whitespace padding is
  intentionally ignored because legitimate Babel output contains longer runs.
- **Miasma RAT / AsyncAPI compromise** (`miasma-train-p1`, Jul 2026). An import-time loader
  runs on `require()` and defeats `--ignore-scripts`. Tier 0 checks `NodeJS/sync.js`, the
  `~/.config/.miasma` lock directory, and the `miasma-monitor` login unit. Tier 2 matches
  `M-RED-TEAM v6.4`, `_miasma._tcp`, and the two second-stage IPFS CIDs.
- **Dev-env and CI injection.** Rogue `mcpServers` and SessionStart-hook entries across
  `.claude`/`.cursor`/`.continue`/`.vscode`, including a `.vscode/tasks.json` `folderOpen`
  task that re-runs `setup.mjs` on every project open. Coverage also includes poisoned
  `init.templateDir` and `core.hooksPath` hooks, the known-bad
  `ci-quality/code-quality-check` action, and `@semantic-release/exec` carrier injection.
- **Prompt injection hidden in agent configs** (TrapDoor, May 2026). `trap-core.js` plants a
  `CLAUDE.md` or `.cursorrules` whose instructions are built from zero-width Unicode. Your
  agent tokenizes every codepoint; your editor renders none of them, so a poisoned config
  needs to execute nothing, only to be read. wormhook scans `CLAUDE.md`, `.claude/CLAUDE.md`,
  `AGENTS.md`, and `.cursorrules` for U+200B/200C/200D/2060/FEFF on a path that does not
  assume JSON. U+200B matches alone; the other codepoints require a printable ASCII neighbor
  to exempt emoji ZWJ sequences, leading byte-order marks, and legitimate Persian, Urdu, and
  Hindi text. Prose configs are checked only for hidden codepoints: documentation containing
  `curl ... | sh` is text, while a `settings.json` entry that runs it is execution wiring.
- **Remote-eval loaders.** `atob(process.env....)` plus `eval`/`Function(await ...)`
  behavioral fingerprints, plus field-observed C2 and exfil hosts.
- **Campaign-agnostic behaviors** (`node_modules` tier only). Decode-then-`eval` droppers,
  `/dev/tcp/` reverse shells, `JSON.stringify(process.env)` bulk exfil. Higher-FP, so scoped
  to third-party deps.

The primary threat path is a pull request from a contributor or compromised maintainer that
lands malware in an existing working copy. Common mechanisms such as `pull_request_target`
and `@semantic-release/exec` match only when paired with campaign-specific fingerprints; the
mechanism alone is not an IOC.

## Scope boundaries

These checks need network or runtime context that a synchronous local hook does not have.
Use the owning layer alongside wormhook.

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

wormhook favors an independent, fast, low-noise agent-boundary gate over broad but ambiguous
coverage.

## Scanner integrity

The engine and signatures live under `$HOME`. Any process that can write
`~/.claude/setup.mjs` may also be able to modify the scanner.

- **Covered:** payloads written beside the scanner. Tier 0 checks attacker-writable agent
  paths on every event without a cache.
- **Residual gap:** direct plugin tampering. An attacker could disable the engine or empty
  the signature set. `.tripwire-allow` excludes the engine and corpus from content scanning
  because an IOC corpus necessarily resembles malware.

At every launch, the `integrity` check compares `scripts/wormhook.sh` and
`scripts/malware-patterns.sh` with `scripts/integrity.sha256`. A mismatch is an unsilenceable
🔴 alert. An attacker who can also replace the manifest can bypass it, but a one-line engine
edit no longer looks healthy. CI rejects stale manifests. Because the plugin directory is a
Git checkout, `git -C <plugin-dir> status` reveals local changes and a marketplace update
restores the published copy.

## Signatures

[`scripts/malware-patterns.sh`](./scripts/malware-patterns.sh) is the single signature
source for every tier. Its extended regular expressions parse identically in Bash and Zsh.

`WORMHOOK_SIGNATURES_ASOF` records the last advisory review. The `SessionStart` `sigage`
check turns 🟡 after `WORMHOOK_SIGAGE_MAX_DAYS`, which defaults to 60.

## Sources

IOCs trace to primary vendor and government advisories. Per-marker provenance is mirrored in
the header of [`scripts/wormhook.sh`](./scripts/wormhook.sh).

- **CISA** - [npm ecosystem supply-chain compromise](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) (Shai-Hulud 1.0)
- **Microsoft** - [Shai-Hulud 2.0 guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- **Datadog** - [Shai-Hulud 2.0 npm worm](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- **Wiz** - [Mini Shai-Hulud: TanStack & more](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- **Semgrep** - [Axios supply-chain incident](https://semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/)
- **Socket** - [SANDWORM_MODE](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning), [Miasma & Hades (PyPI/MCP)](https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious)
- **Phoenix Security** - [TrapDoor: cross-ecosystem credential theft and AI-assistant poisoning](https://phoenix.security/trapdoor-supply-chain-ai-poisoning-npm-pypi-crates/) (zero-width Unicode in `CLAUDE.md` / `.cursorrules`)
- **Checkmarx** - [npm hit by Shai-Hulud](https://checkmarx.com/zero-post/npm-hit-by-shai-hulud-the-self-replicating-supply-chain-attack/) (`shai-hulud-workflow.yml`, the `webhook.site` exfil ID)
- **StepSecurity** - [Malicious node-ipc versions published to npm](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack) (base-16 alphabet, HMAC key, `node-ipc.cjs` hash, `sh.azurestaticprovider.net`)
- **Snyk** - [Mini Shai-Hulud hits AntV](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/) (`kitty-monitor`, `firedalazer`, `.vscode/tasks.json` `folderOpen`)
- **Unit 42** - [Monitoring npm supply-chain attacks](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) (`audit.checkmarx.cx`, `OhNoWhatsGoingOnWithGitHub` C2), [Inside a self-propagating npm worm](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) (ChainDrop C2 domains, Base91 layering)
- **Mend** - [Shai-Hulud SAP CAP via Claude Code](https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/) (`ctf-scramble-v2`, `__DAEMONIZED`, russian-locale kill-switch)
- **Microsoft** - [AsyncAPI compromise & Miasma import-time payload](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) (`miasma-train-p1`, `NodeJS/sync.js`, `.miasma`, IPFS CIDs), [ChainDrop anatomy](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/)
- **Elastic** - [ChainDrop / keyv Shai-Hulud wave](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain) (payload hashes, ETH contract)
- **JFrog** - [Shai-Hulud is back (Aug 2026)](https://research.jfrog.com/post/shai-hulud-is-back-august/) (`math_init.js` hash pairing, runtime C2 resolution)
- **Field-observed, no advisory** - the "A9-0522" build. Its markers sit a provenance tier
  below every entry above (same class as `api.masscan.cloud` and `m-kosche.com`): they come
  from a sample recovered off a compromised account, not a named vendor page, so only the two
  zero-FP-verified markers reach the blocking tier and the rest stay warn-only.

## License

MIT. See [LICENSE](./LICENSE).
