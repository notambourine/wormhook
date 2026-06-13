# wormhook

A Claude Code plugin that catches npm/node **supply-chain malware** at the hook —
before it can run. It binds to Claude Code's tool lifecycle and blocks `npm`/`pnpm`/
`yarn`/`bun`/`npx`/`node` commands when it finds a known indicator of compromise.
Named for the threat it headlines: Shai-Hulud, the self-replicating npm *worm* —
stopped at the hook.

**This is one lock, not the whole door.** It's not a replacement for an install-layer
firewall ([Socket Firewall](https://socket.dev/)) or a dependency auditor
([`safedep/vet`](https://github.com/safedep/vet)) — it's an *independent* layer at the
Claude Code agent boundary. Run it **alongside** those, not instead of them; the value
is independence — a worm that slips one lock still has to beat the others.

Built and maintained by [NoTambourine](https://notambourine.com).

## Install

```bash
claude plugin marketplace add notambourine/wormhook
claude plugin install wormhook@notambourine --scope user
```

Requires `jq` and `bash`. [`ripgrep`](https://github.com/BurntSushi/ripgrep) is
optional but strongly recommended — content scans use it when present (43× faster than
BSD grep on large trees) and fall back to `grep` otherwise. There's nothing to invoke;
it runs automatically. A silent doctor hook speaks up at `SessionStart` only when a
dependency is missing, the installed copy lags the marketplace, or a recommended
[companion firewall](#beyond-the-tiers) (Socket Firewall / `vet`) isn't installed — each
with the one-liner to fix it.

## How it works

The scan is **tiered by cost × volatility**, so the expensive part only runs when it
can find something new:

- **Tier 0 — persistence & agent/dev-env injection** (cheap stats, *every event, never cached*):
  RAT droppers (`com.apple.act.mond`), runner installs (`~/.dev-env`), agent-hijack
  droppers and rogue `mcpServers`/`hooks` entries across Claude Code/Cursor/Continue/
  Windsurf, poisoned git hooks, `gh-token-monitor` units, weaponized Python `.pth`
  startup hooks.
- **Tier 1 — project source, `package.json` lifecycle & CI config** (cheap, every gated
  event): install-lifecycle scripts, injected loaders in the source tree, and
  `.github/workflows` + `.releaserc` poisoning. This is the tier that **blocks** an
  install before it can run a dropper.
- **Tier 2 — `node_modules` content/IOC scan** (expensive): runs only when deps changed
  (keyed off lockfile hash + `node_modules` dir mtimes ≤2 deep, cached under
  `~/.cache/notambourine/`). **Fails open** — a scan that hits its `timeout` reports 🟡
  and doesn't refresh the cache, so it never blocks your launch.

### Beyond the tiers

Two behaviors backstop the signature tiers, and wormhook nudges you toward the install-time
firewall layer it deliberately doesn't reimplement:

- **Python execution gating.** `pip`/`pip3`/`pipx`/`uv`/`python`/`python3` trigger the
  Tier-0 sweep at `PreToolUse`, so the weaponized `.pth` startup-hook check runs **before**
  the interpreter auto-executes a poisoned site-packages `.pth` (the Hades/Miasma PyPI
  vector) — not just on the next npm/git command. (It gates *execution* to run the existing
  persistence scan early; it is **not** a full PyPI install auditor.)
- **`UserPromptSubmit` continuous monitor.** The cheap tiers (T0 + T1) re-run at **every
  human turn** and — unlike `SessionStart` — can **block**. This is the hook layer's closest
  approximation of a continuous filesystem watcher: persistence planted mid-session (a `pip
  install`, an agent file-write) is caught at the next prompt, not the next npm/git command.
  Silent when clean (it would otherwise spam the transcript); speaks only on a finding or 🟡.
- **Companion-firewall nudge (no network in wormhook itself).** Blocking *malicious or
  too-new package versions* at the registry boundary needs registry intelligence — exactly
  what [Socket Firewall](https://docs.socket.dev/docs/socket-firewall) (`sfw`, a live install
  firewall) and [`safedep/vet`](https://github.com/safedep/vet) (dependency CVE + malicious-
  package audit) do, and far better than a hook can. Rather than reimplement a thin version
  of that with its own network calls, wormhook stays **fully local** and the `SessionStart`
  doctor nudges you (once, silently if present) to install them — "run alongside, not
  instead." `sfw` is the direct answer to "stop me installing a poisoned version."

```mermaid
flowchart TD
    A([SessionStart<br/>on launch]):::evt
    B([PreToolUse<br/>npm / npx / pnpm / yarn / bun / node<br/>· pip / pipx / uv / python]):::evt
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

    T0["<b>Tier 0</b> — persistence &amp; agent-hook injection<br/><i>cheap stats · ALWAYS · never cached</i>"]:::tier
    T0 --> T0c{IOC?}
    T0c -- hit --> G
    T0c -- clean --> T1

    T1["<b>Tier 1</b> — project source + package.json lifecycle<br/><i>cheap · every gated event</i>"]:::tier
    T1 --> T1c{IOC?}
    T1c -- hit --> G
    T1c -- clean --> CACHE

    CACHE{deps changed?<br/>lockfile hash + dir mtimes ≤2 deep}:::cache
    CACHE -- "no — cache hit" --> DONE
    CACHE -- "yes / stale" --> T2

    T2["<b>Tier 2</b> — node_modules content/IOC scan<br/><i>expensive · only when deps changed</i>"]:::tier
    T2 --> T2c{IOC?}
    T2c -- hit --> G
    T2c -- clean --> DONE

    G{which<br/>event?}:::guard
    G -- "PreToolUse<br/>(deny + systemMessage)" --> BLOCK([BLOCK]):::block
    G -- "UserPromptSubmit<br/>(decision:block + systemMessage)" --> BLOCK
    G -- "SessionStart / PostToolUse" --> SURFACE([warn · systemMessage + additionalContext]):::warn

    ALLOW([allow]):::ok
    DONE([done · allow · 🟢/🟡 status line]):::ok

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
| `PreToolUse` | before an `npm`/`node`/… or `pip`/`uv`/`python` command | Tier 0–1 (+ Tier 2 if deps drifted); **blocks** on a hit (`permissionDecision: "deny"`) |
| `PostToolUse` | after an install-class or `pip`/`uv` install command | re-scan of the freshly written tree (Python installs re-run the Tier-0 `.pth` check); warns on a hit |
| `PostToolUse` | after a working-tree-rewriting `git` op (`pull`/`merge`/`checkout`/`switch`/`rebase`) | Tier 0–1 on the new tree (+ Tier 2 on dep drift); warns on a hit. Catches persistence/source IOCs that arrive over git with **no npm involved** |
| `UserPromptSubmit` | every human turn | Tier 0–1 ([continuous monitor](#beyond-the-tiers)); **blocks** on a hit (`decision: "block"`). Silent when clean |
| `SessionStart` | on launch | Tier 0–1 (+ Tier 2 on a stale cache); warns on a hit |

**The hard blocks are at `PreToolUse` and `UserPromptSubmit`** — they stop the command/turn
regardless of whether the model cooperates (`permissionDecision: "deny"` and a top-level
`decision: "block"` respectively). `SessionStart`/`PostToolUse` run after the point of no
return and can't abort, so they *warn* (a `systemMessage` to you + `additionalContext`
telling the model to refuse follow-up installs) rather than block.

Every scan ends with a one-line verdict so silence is never ambiguous: 🟢 clean,
🟡 passed with degraded coverage (a `timeout` was hit, or signatures are missing — never
refreshes the cache), 🚨 findings. Non-gated commands stay silent.

## What it detects

- **Shai-Hulud 1.0–3.0 + the Mini variant** — obfuscation markers, runner fingerprints,
  ransom tokens, `git-tanstack` typosquat exfil, payload filenames, SHA256 IOCs.
- **Axios / plain-crypto-js RAT** (Sapphire Sleet / DPRK) — `com.apple.act.mond`
  persistence, `sfrclak` C2 beacons.
- **SANDWORM_MODE** — AI-toolchain poisoning: the marker, `*.workers.dev/{exfil,drain}`
  C2, `freefan`/`fanfree` DNS-tunnel domains, the drain bearer token.
- **Hades / Miasma PyPI wave** (Jun 2026) — MCP typosquats (`openai-mcp`, `tiktoken-mcp`,
  …) shipping a weaponized Python `.pth` startup hook (→ Bun → `_index.js` Hades stealer),
  `/tmp/.sshu-setup.js` SSH propagation. Caught at Tier 0, and `pip`/`uv`/`python` now
  [trigger that scan at `PreToolUse`](#beyond-the-tiers) so it runs **before** the interpreter
  auto-executes a poisoned `.pth` — not just on the next npm/git command.
- **Dev-env & CI injection** — rogue `mcpServers`/SessionStart-hook entries, poisoned git
  hooks (`init.templateDir`/`core.hooksPath`), `pull_request_target` workflows calling the
  `ci-quality/code-quality-check` action, `@semantic-release/exec` carrier injection.
- **Remote-eval loaders** — `atob(process.env.…)` + `eval`/`Function(await …)` behavioral
  fingerprints, plus field-observed C2/exfil hosts.
- **Campaign-agnostic behaviors** (`node_modules` tier only) — decode-then-`eval`
  droppers, `/dev/tcp/` reverse shells, `JSON.stringify(process.env)` bulk exfil. Higher-FP,
  so scoped to third-party deps.

The lock is organized around one path: a contributor or compromised maintainer's PR
slipping malware into a repo you already work in. Where `pull_request_target` and
`@semantic-release/exec` are *legitimately common*, the scans key off campaign-specific
fingerprints (the known-bad action slug, the carrier `require()`) — not the generic
feature — to keep CI false positives at zero.

## What it deliberately doesn't do

A narrow lock on purpose: each row below needs context a synchronous, no-network hook
lacks, and forcing it in would trade away the near-zero false-positive rate that makes
the block trustworthy. Run the owning layer alongside — the `SessionStart` doctor nudges
you to install the install-firewall ones (Socket Firewall, `vet`).

| Check it doesn't do | Layer that owns it |
|---------------------|--------------------|
| Package existence / typosquatting / version-age / maintainer-change (needs registry lookups) | [Socket Firewall](https://docs.socket.dev/docs/socket-firewall), [`safedep/vet`](https://github.com/safedep/vet) |
| Known-CVE scanning (needs an advisory feed) | `vet`, `npm audit`, Dependabot |
| Secret detection | `gitleaks`, `trufflehog` |
| Generic Actions hardening (unpinned actions, broad perms) | `actionlint`, `zizmor` |
| Runtime network monitoring (live C2/DNS exfil/sockets) | install-time sandbox / eBPF monitor |
| AST + reachability analysis | [depsec](https://depsec.dev/) |
| Flagging any `child_process` exec/spawn (block-tier FP catastrophe) | [GuardDog](https://github.com/DataDog/guarddog) (triage) |
| Credential-read → exfil (needs taint tracking) | GuardDog (`mode: taint`) |
| Auditing PyPI **package contents** (wormhook gates `pip`/`uv`/`python` *execution* only — to run the Tier-0 `.pth` check early — it doesn't inspect the installed package tree) | install-time sandbox / `vet` / GuardDog |

The design bet is **independence over coverage**: a fast, no-network, near-zero-FP gate
at the agent boundary that trips on a specific, evidence-backed set of indicators.

## Signatures

All signatures live in one file — [`scripts/malware-patterns.sh`](./scripts/malware-patterns.sh) —
sourced by the hook so a new pattern reaches every tier at once. Patterns are extended
regex and parse identically under bash and zsh.

## Sources

IOCs trace to primary vendor and government advisories (the per-marker provenance is
mirrored in the header of [`scripts/wormhook.sh`](./scripts/wormhook.sh)):

- **CISA** — [npm ecosystem supply-chain compromise](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) (Shai-Hulud 1.0)
- **Microsoft** — [Shai-Hulud 2.0 guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- **Datadog** — [Shai-Hulud 2.0 npm worm](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- **Wiz** — [Mini Shai-Hulud: TanStack & more](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- **Semgrep** — [Axios supply-chain incident](https://semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/)
- **Socket** — [SANDWORM_MODE](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning) · [Miasma & Hades (PyPI/MCP)](https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious)

## License

MIT. See [LICENSE](./LICENSE).
