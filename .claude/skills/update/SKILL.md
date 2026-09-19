---
name: update
description: Verify primary advisories and add local detection for supply-chain campaigns. Use for signature updates, new worm coverage, and campaign reviews.
---

# Adding a new campaign to wormhook

Turn a fresh advisory into a verified, correctly-tiered patch PR. Read
[`AGENTS.md`](../../../AGENTS.md) first.

The one rule that governs everything below: **a wrong block-tier signature is worse than an
omission.** Every literal lands only after you have confirmed it verbatim against a named
primary advisory. Distrust IOC aggregators and your own prior summaries. Confabulated
indicators are the failure mode this process exists to catch.

## 1. Source

Pull IOCs from primary vendor and government advisories, not secondary roundups:

- Socket, Snyk, Wiz, Unit 42 (Palo Alto), Mend, Phoenix Security, Aikido, StepSecurity,
  Datadog, Microsoft, CISA, JFrog. Each campaign usually has 3-6 of these covering it.
- Extract only what a no-network, local-filesystem grep can match:
  - exact filenames and paths (droppers, `.pth` names, LaunchAgent/systemd unit names)
  - SHA256 of single-artifact payloads, useful only when paired with a known filename
  - attacker-owned C2 and exfil hosts
  - unique payload-internal strings (obfuscation salts, C2 command keywords, kill-switch log
    lines, env-var guards). Highest-value, lowest-FP class.
  - agent-config injection specifics: which file under `.claude`/`.cursor`/`.continue`/
    `.vscode`, and the exact injected key, value, and command
- If you fan out research agents, treat their output as candidates, never facts. Agents pad
  and confabulate. The list always shrinks at step 2.

## 2. Verify (the hard gate)

For EACH candidate, `WebFetch` the cited primary advisory and confirm the exact literal,
including casing and punctuation. Record the source URL next to it. Mark each:

- **CONFIRMED** - exact string found on a named primary page. Eligible to land.
- **UNCONFIRMED** - no primary source. Do NOT land; hold for a second source.
- **REFUTED or redundant** - wrong, or already covered by an existing pattern. Drop.

Before adding anything, `grep` the candidate against
[`scripts/malware-patterns.sh`](../../../scripts/malware-patterns.sh). A substring match means
it is already covered; `m-kosche.com` already matches `t.m-kosche.com`. Read
[`scripts/wormhook.sh`](../../../scripts/wormhook.sh) to confirm a gap is real;
`/tmp/.sshu-setup.js` is already a Tier-0 literal.

## 3. Place by tier (blast-radius rule)

FP-tolerance scales with blast radius. Route a noisy-but-real signature down a tier; do not
drop it.

| IOC kind | Home | File |
|---|---|---|
| Unique nonsense string (salt, C2 keyword, kill-switch) | `MALWARE_CONTENT_FINGERPRINTS` (Tier 2, node_modules) | `malware-patterns.sh` |
| ...and it is unique enough to be block-safe in your own source | also add to `MALWARE_INJECT_RE` (Tier 1, project-source block) | `malware-patterns.sh` |
| Attacker C2 / exfil host | `MALWARE_CONTENT_FINGERPRINTS` (escape the dots) | `malware-patterns.sh` |
| Dropper string referenced from an agent/editor config | `MALWARE_DROPPER_TOKENS_RE` | `malware-patterns.sh` |
| New persistence file / LaunchAgent / systemd unit | Tier-0 path table; require content when the name is ambiguous | `malware-patterns.sh` |
| New agent-config surface (e.g. a new editor's settings file) | the Tier-0 config-injection `cfg` loop | `wormhook.sh` |
| `.pth` behavior / single-artifact `.pth` | `MALWARE_PTH_RE` / `MALWARE_PTH_IOC_NAME`+`_HASH` | `malware-patterns.sh` |
| node_modules payload filename, name == proof | `PAYLOAD_FILES` | `malware-patterns.sh` |
| ...filename that can be legit | `HASH_IOC_FILES` + `HASH_IOC_HASHES` (name + hash) | `malware-patterns.sh` |

Reject these as out of architecture. Note each in the PR; do not silently skip:

- GitHub repo-name and dead-drop-description regexes. wormhook scans the local FS, not the
  GitHub API.
- Blanket SHA256 hashing of every dep. wormhook hashes only when a filename already matched.
- Anything needing a registry or network lookup (version-age, typosquat, maintainer-change).
  Ceded to Socket Firewall and `vet` by design; see the README "deliberately doesn't do".
- Generic filenames (`index.js`, `execution.js`) as bare `PAYLOAD_FILES`. They FP. Only their
  path-anchored form, inside a specific config dir, is block-safe.

## 4. Provenance

Keep advisory URLs beside the signatures in the corpus. Keep campaign coverage in the
plugin description and operational limits in the README; do not duplicate IOC catalogs.

## 5. Bump and sync manifests

A behavioral change, meaning anything touching the scripts, MUST:

- bump `version` in `.claude-plugin/plugin.json`, or a CI tripwire fails the PR
- set `WORMHOOK_SIGNATURES_ASOF` in `scripts/malware-patterns.sh` to today, including when a
  sweep lands nothing new. The constant means "verified current as of", and `doctor/sigage.sh`
  nags when it ages out.
- update `.claude-plugin/plugin.json`'s `description` if the new campaign belongs in the full
  install/inspect description. The browse tagline lives in the `notambourine/claude` catalog
  row, not this repo; touch it there only if the one-line pitch genuinely changed. The two are
  NOT kept in sync and there is no parity check.

## 6. Verify the change

Leave schema checks, ShellCheck, and the full fixture harness to CI. Verify changed shell
code under macOS `/bin/bash` 3.2 and reproduce new detections with inert fixtures. Isolate
HOME, XDG cache/config, and working directories. Expect deny/block only for confirmed IOCs;
ambiguous patterns produce yellow warnings. Add negative fixtures for plausible benign uses.

Regenerate the integrity manifest after changing the engine or corpus.

For a single isolated reproduction:

```bash
case_dir=$(mktemp -d); fixture_home="$case_dir/home"; mkdir -p "$fixture_home/proj"
# Plant an inert artifact under the isolated home or project.
jq -nc --arg cwd "$fixture_home/proj" \
  '{tool_input:{command:"npm install"},cwd:$cwd,hook_event_name:"PreToolUse"}' \
  | HOME="$fixture_home" XDG_CACHE_HOME="$case_dir/cache" XDG_CONFIG_HOME="$case_dir/config" \
    /bin/bash scripts/wormhook.sh | jq -r '.hookSpecificOutput.permissionDecision'
rm -rf "$case_dir"
```

bash-3.2 gotcha: no contractions inside an `alert "..." "$(cat <<BODY ... BODY)"` body. The
3.2 command-substitution parser miscounts a lone `'`. Write "do not", not "don't".

## 7. PR

Branch off `main`, draft PR by default. Subject in the `feat:` or `fix:` form with the version
(`feat: Tier-0 detection for <campaign> (vX.Y.Z)`). In the body, list each landed signature
with its primary-source URL, and call out anything deliberately rejected and why, so the
reviewer can see the coverage boundary was a choice.
