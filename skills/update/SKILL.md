---
name: update
description: Add detection for a new npm/PyPI supply-chain worm or campaign to wormhook. Use when a new advisory drops (Socket/Snyk/Wiz/Unit42/Mend/Microsoft/Datadog/CISA/JFrog) and you want to source its IOCs, verify them against primary sources, place each signature in the right tier, and open a patch PR. Triggers: "add a signature", "new Shai-Hulud variant", "update wormhook for <campaign>", "a new worm dropped".
---

# Adding a new campaign to wormhook

This is the end-to-end process for turning a fresh advisory into a verified, correctly-tiered
patch PR. The invariants this depends on live in [`CLAUDE.md`](../../CLAUDE.md) — read its
"Invariants" and "Working here" sections first; this skill is the procedure, not a re-statement
of the rules.

The one rule that governs everything below: **a wrong block-tier signature is worse than an
omission.** Every literal lands only after you have confirmed it verbatim against a *named
primary advisory*. Distrust IOC aggregators and your own prior summaries — confabulated
indicators are the failure mode this process exists to catch.

## 1. Source

Pull the IOCs from primary vendor/government advisories, not secondary roundups:

- **Socket, Snyk, Wiz, Unit 42 (Palo Alto), Mend, Phoenix Security, Aikido, StepSecurity,
  Datadog, Microsoft, CISA, JFrog.** Each campaign usually has 3–6 of these covering it.
- Extract only what a **no-network, local-filesystem grep** can match:
  - exact **filenames** and **paths** (droppers, `.pth` names, LaunchAgent/systemd unit names)
  - **SHA256** of single-artifact payloads (only useful when paired with a known filename)
  - attacker-owned **C2 / exfil hosts**
  - **unique payload-internal strings** (obfuscation salts, C2 command keywords, kill-switch
    log lines, env-var guards) — the highest-value, lowest-FP class
  - **agent-config injection** specifics: which file under `.claude`/`.cursor`/`.continue`/
    `.vscode`, and the exact injected key/value/command
- If a fan-out of research agents is used, treat their output as **candidates, never facts** —
  agents pad and confabulate. The list always shrinks at step 2.

## 2. Verify (the hard gate)

For **each** candidate, `WebFetch` the cited primary advisory and confirm the exact literal
(casing, punctuation). Record the source URL next to it. Mark each:

- **CONFIRMED** — exact string found on a named primary page → eligible to land.
- **UNCONFIRMED** — no primary source → **do not land** (hold for a second source).
- **REFUTED / redundant** — wrong, or already covered by an existing pattern → drop.

Before adding anything, `grep` the candidate against [`scripts/malware-patterns.sh`](../../scripts/malware-patterns.sh)
— substring matches mean it is already covered (e.g. `m-kosche.com` already matches
`t.m-kosche.com`). And read [`scripts/wormhook.sh`](../../scripts/wormhook.sh) to confirm a
"gap" is real (e.g. `/tmp/.sshu-setup.js` is already a Tier-0 literal).

## 3. Place by tier (blast-radius rule)

FP-tolerance scales with blast radius — route a noisy-but-real signature *down* a tier, do not
drop it. Where each kind of IOC goes:

| IOC kind | Home | File |
|---|---|---|
| Unique nonsense string (salt, C2 keyword, kill-switch) | `MALWARE_CONTENT_FINGERPRINTS` (Tier 2, node_modules) | `malware-patterns.sh` |
| …and it is unique enough to be block-safe in *your own* source | also add to `MALWARE_INJECT_RE` (Tier 1, project-source block) | `malware-patterns.sh` |
| Attacker C2 / exfil host | `MALWARE_CONTENT_FINGERPRINTS` (escape the dots) | `malware-patterns.sh` |
| Dropper string referenced from an agent/editor config | `MALWARE_DROPPER_TOKENS_RE` | `malware-patterns.sh` |
| New persistence file / LaunchAgent / systemd unit | a Tier-0 file-existence check or loop | `wormhook.sh` |
| New agent-config surface (e.g. a new editor's settings file) | the Tier-0 config-injection `cfg` loop | `wormhook.sh` |
| `.pth` behavior / single-artifact `.pth` | `MALWARE_PTH_RE` / `MALWARE_PTH_IOC_NAME`+`_HASH` | `malware-patterns.sh` |
| node_modules payload filename, name == proof | `PAYLOAD_FILES` | `wormhook.sh` |
| …filename that *can* be legit | `HASH_IOC_FILES` + `HASH_IOC_HASHES` (name + hash) | `wormhook.sh` |

**Reject** (out of architecture — note it in the PR, do not silently skip):
- GitHub-**repo-name** / dead-drop-description regexes — wormhook scans the local FS, not the
  GitHub API.
- Blanket SHA256 hashing of every dep — wormhook hashes only when a filename already matched.
- Anything needing a **registry/network lookup** (version-age, typosquat, maintainer-change) —
  ceded to Socket Firewall + `vet` by design; see the README "deliberately doesn't do".
- Generic filenames (`index.js`, `execution.js`) as bare `PAYLOAD_FILES` — they FP. Only their
  path-anchored form (e.g. inside a specific config dir) is block-safe.

## 4. Provenance

Keep the three provenance surfaces in sync (they are the audit trail that every signature
traces to a real advisory):

- the **Sources header block** in `scripts/wormhook.sh` (campaign line + advisory URLs)
- the **"What it detects"** list in `README.md`
- the **Sources** section in `README.md`

## 5. Bump + sync manifests

A behavioral change (anything touching the scripts) **must**:

- bump `version` in `.claude-plugin/plugin.json` (a CI tripwire fails the PR otherwise)
- if the `description` changed, mirror it **byte-for-byte** into
  `.claude-plugin/marketplace.json` (`.plugins[] | select(.name=="wormhook").description`) —
  a CI parity check fails on drift

## 6. Verify the change

```bash
# Syntax under the REAL shebang shell (Apple bash 3.2 — a Homebrew bash hides 3.2-only errors)
for f in scripts/*.sh; do /bin/bash -n "$f"; done
shellcheck -S warning scripts/*.sh
jq -e . hooks/hooks.json .claude-plugin/*.json >/dev/null

# Description parity
diff <(jq -r .description .claude-plugin/plugin.json) \
     <(jq -r '.plugins[]|select(.name=="wormhook").description' .claude-plugin/marketplace.json)
```

Then **smoke-test each new detection** with a synthetic payload in an isolated temp `HOME`/`CWD`
(so nothing touches real dirs). Pattern — expect a `deny` for block-tier, `🚨` for warn-tier,
`🟢` for a clean tree:

```bash
TMP=$(mktemp -d); FH="$TMP/home"; mkdir -p "$FH/proj"
# …plant the artifact under $TMP/proj or $FH…
echo '{"tool_input":{"command":"npm install"},"cwd":"'"$TMP/proj"'","hook_event_name":"PreToolUse"}' \
  | HOME="$FH" bash scripts/wormhook.sh | jq -r '.hookSpecificOutput.permissionDecision'
rm -rf "$TMP"
```

bash-3.2 gotcha: no contractions inside an `alert "..." "$(cat <<BODY … BODY)"` body — the 3.2
command-substitution parser miscounts a lone `'`. Write "do not", not "don't".

## 7. PR

Branch off `main`, draft PR by default. Subject in the `feat:`/`fix:` form with the version
(e.g. `feat: Tier-0 detection for <campaign> (vX.Y.Z)`). In the body, list each landed signature
with its primary-source URL, and call out anything deliberately **rejected** (and why) so the
reviewer can see the coverage boundary was a choice, not an oversight.
