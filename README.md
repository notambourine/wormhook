# npm-malware-scan

A Claude Code plugin that scans for npm/node **supply-chain malware** before it
can run. It hooks into Claude Code's tool lifecycle and blocks `npm`/`pnpm`/
`yarn`/`bun`/`npx`/`node` commands when it finds a known indicator of compromise.

Built and maintained by [NoTambourine](https://notambourine.com).

## Install

```bash
claude plugin marketplace add notambourine/npm-malware-scan
claude plugin install npm-malware-scan@notambourine --scope user
```

Requires `jq` and `bash` on `PATH`. There is no command to invoke — once
installed, it runs automatically.

## How it works

The scan is **tiered by cost × volatility**, so the expensive part only runs when
it can actually find something new:

- **Tier 0 — persistence & agent-hook injection** (cheap stat checks, every event):
  RAT droppers (`com.apple.act.mond`), Shai-Hulud runner installs (`~/.dev-env`),
  agent-hijack droppers in `.claude/`/`.vscode/`, injected hook entries in
  `settings.json`, and `gh-token-monitor` launch units.
- **Tier 1 — project source & `package.json` lifecycle** (cheap, every gated event):
  scans install-lifecycle scripts and the project tree for injected loaders. This
  is the check that fires *before* an install can execute a dropper.
- **Tier 2 — `node_modules` content/IOC scan** (expensive): runs only when
  dependencies actually changed, keyed off the lockfile hash + `node_modules`
  mtime (cached under `~/.cache/notambourine/`).

It binds to three events:

| Event | When | What |
|-------|------|------|
| `PreToolUse` | before an `npm`/`node`/… command | Tier 0–1 (+ Tier 2 if deps drifted); **blocks** (exit 2) on a hit |
| `PostToolUse` | right after an install-class command | full re-scan of the freshly written tree |
| `SessionStart` | on launch | Tier 0–1 (+ Tier 2 on a stale cache); surfaces findings as context |

## What it detects

- **Shai-Hulud 1.0–3.0 and the Mini variant** — obfuscation markers, runner
  fingerprints, dead-man's-switch ransom tokens, `git-tanstack` typosquat exfil,
  known payload filenames, and SHA256 IOCs.
- **Axios / plain-crypto-js RAT** (Sapphire Sleet / DPRK) — `com.apple.act.mond`
  persistence and `sfrclak` C2 beacons.
- **SANDWORM_MODE** — AI-toolchain poisoning markers.
- **Remote-eval loaders** — `atob(process.env.…)` + `eval`/`Function(await …)`
  behavioral fingerprints, where the C2 URL is hidden in an env var and the
  payload is fetched at runtime (no in-tree payload signature to match).

Detection draws on advisories from CISA, Microsoft, Datadog, Wiz, Semgrep, and
Socket — see the header of [`scripts/npm-malware-scan.sh`](./scripts/npm-malware-scan.sh)
for the full source list.

## Signatures

All signatures live in one file — [`scripts/malware-patterns.sh`](./scripts/malware-patterns.sh) —
sourced by the hook so a new pattern reaches every tier at once. This is the
canonical home for the patterns; add a campaign here and every scan surface picks
it up. Patterns are extended regex (`grep -E`) and parse identically under bash
and zsh, so the same file can back a shell `git`-merge gate as well as the hook.

## License

MIT. See [LICENSE](./LICENSE).
