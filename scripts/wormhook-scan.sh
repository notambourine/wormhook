#!/bin/bash
# wormhook-scan — run the wormhook engine OUTSIDE Claude Code.
#
# wormhook.sh fires only on Claude hook events; this CLI is the out-of-band surface
# (morning/manual fleet checks, an hourly launchd sweep, a global git hook) so the same
# detection covers `git pull` in a plain terminal and "came back to the machine after a
# while". Every verb is a THIN ADAPTER over the UNCHANGED engine: it synthesizes the same
# stdin payload Claude would send and parses the same verdict. NO detection logic lives
# here — wormhook.sh + malware-patterns.sh stay the single source of truth.
#
#   fast (default): {"cwd":DIR,"hook_event_name":"SessionStart"}            => T0+T1 (+T2 on cache-miss)
#   --deep:         {...,"PostToolUse",tool_input.command:"npm install"}    => forces T2
#   --persistence:  fast scan of an empty dir => only the $HOME/global T0 checks run
#
# Verbs: scan (default) · install-cli · install-launchd · install-git-hook
#        uninstall-launchd · uninstall-git-hook · status · config · help
#
# bash 3.2 + zsh portable (Apple /bin/bash is 3.2.57): NO associative arrays, NO mapfile,
# and NO apostrophes inside $(cat <<BODY ...) bodies (the 3.2 command-substitution gotcha).
set -uo pipefail

command -v jq >/dev/null 2>&1 || { echo "wormhook-scan: jq required (brew install jq)" >&2; exit 1; }

# ── Resolve our own real path through any symlink (e.g. ~/.local/bin/wormhook-scan) so we
#    can find the sibling engine, whether installed from the marketplace clone or a checkout.
SOURCE="${BASH_SOURCE[0]}"
while [[ -h "$SOURCE" ]]; do
  _dir="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$_dir/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
SELF="$SCRIPT_DIR/$(basename "$SOURCE")"
ENGINE="$SCRIPT_DIR/wormhook.sh"

_die() { echo "wormhook-scan: $1" >&2; exit "${2:-1}"; }
[[ -r "$ENGINE" ]] || _die "engine not found next to this script ($ENGINE)"
# Shared launchd-label + git-hook-marker constants (single source; see wormhook-const.sh).
# shellcheck source=scripts/wormhook-const.sh disable=SC1091
. "$SCRIPT_DIR/wormhook-const.sh" 2>/dev/null || _die "constants not found ($SCRIPT_DIR/wormhook-const.sh)"
LABEL="$WORMHOOK_LAUNCHD_LABEL"

# Verdict exit codes — the single source for the 0/1/2 convention in cmd_help and every
# scan/check/git-hook return (and the shell-init guard keys on EXIT_CRIT=1).
readonly EXIT_OK=0 EXIT_CRIT=1 EXIT_DEGRADED=2

CONFIG="${WORMHOOK_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/wormhook/scan-roots}"
SAMPLE="$SCRIPT_DIR/wormhook-scan.conf.sample"
SWEEP_LOG="${WORMHOOK_LOG:-$HOME/Library/Logs/wormhook-sweep.log}"

# ── Engine driver ──────────────────────────────────────────────────────────────
# Echoes the engine's single JSON verdict for one directory. Payload built with jq
# --arg so a path with spaces/quotes cannot break out (same rule the engine follows).
_scan_one() {  # $1=dir  $2=fast|deep
  local dir="$1" mode="$2" payload
  if [[ "$mode" == deep ]]; then
    payload=$(jq -nc --arg c "$dir" '{cwd:$c,hook_event_name:"PostToolUse",tool_input:{command:"npm install"}}')
  else
    payload=$(jq -nc --arg c "$dir" '{cwd:$c,hook_event_name:"SessionStart"}')
  fi
  printf '%s' "$payload" | bash "$ENGINE" 2>/dev/null
}
_glyph() {  # stdin: engine JSON -> 🟢/🟡/🚨. Prefer the machine-readable `verdict`; fall back
            # to the systemMessage glyph prefix (older engine output / version drift). A
            # missing/garbled verdict resolves to 🟡 — degraded, never silently green.
  local g
  g=$(jq -r '
    (.verdict // "") as $v
    | if   $v=="red"    then "🚨"
      elif $v=="yellow" then "🟡"
      elif $v=="green"  then "🟢"
      else (.systemMessage // "") as $m
        | if   ($m|startswith("🚨")) then "🚨"
          elif ($m|startswith("🟡")) then "🟡"
          elif ($m|startswith("🟢")) then "🟢"
          else "🟡" end
      end' 2>/dev/null)
  case "$g" in "🚨"|"🟡"|"🟢") printf '%s' "$g" ;; *) printf '🟡' ;; esac
}
# Alert TITLEs from a verdict (one per line). Block titles render as "🚨  TITLE" at
# line-start inside additionalContext; the systemMessage uses a single space, so this
# matches blocks only. Titles are clean strings (no globs) => safe for set membership.
_titles() {  # finding titles, one per line. Prefer structured .findings[].title; fall back
             # to scraping the additionalContext banner (older engine output / version drift).
  local j; j=$(cat)
  if printf '%s' "$j" | jq -e '(.findings // []) | length > 0' >/dev/null 2>&1; then
    printf '%s' "$j" | jq -r '.findings[].title'
  else
    printf '%s' "$j" | jq -r '.hookSpecificOutput.additionalContext // ""' 2>/dev/null | grep '^🚨  ' | sed 's/^🚨  //'
  fi
}
# Per-finding identity keys (one base64 token per line) for the global-vs-local dedup.
# Keyed on the FULL {title,body} — the body carries the matched path — NOT the class-level
# title, so a real per-repo finding is never masked by a same-titled global finding (e.g. a
# poisoned global core.hooksPath would otherwise collapse an identically-titled local
# .git/hooks finding to 🟢). base64 keeps a multi-line body as a single grep -Fx token.
# Empty for older engine output (no .findings) => every finding treated local (safe: never masks).
_keys() { jq -r '(.findings // []) | .[] | (.title + "\u001f" + .body) | @base64' 2>/dev/null; }
_detail() { jq -r '.hookSpecificOutput.additionalContext // .systemMessage // ""' 2>/dev/null; }
_systemmsg() { jq -r '.systemMessage // ""' 2>/dev/null; }
# Generic verdict render+exit for single-repo verbs: prints _detail on 🚨, else the status
# line, unless quiet; returns the EXIT_* code. (cmd_git_hook keeps its own loud post-pull
# banner but shares EXIT_* and _systemmsg; cmd_scan's fleet loop has its own dedup/render.)
_render_verdict() {  # $1=engine JSON  $2=quiet(0/1)  -> echoes, returns EXIT_*
  local out="$1" quiet="$2" glyph; glyph=$(printf '%s' "$out" | _glyph)
  case "$glyph" in
    "🚨") [[ "$quiet" == 1 ]] || printf '%s' "$out" | _detail; return "$EXIT_CRIT" ;;
    "🟡") [[ "$quiet" == 1 ]] || printf '%s' "$out" | _systemmsg; return "$EXIT_DEGRADED" ;;
    *)    [[ "$quiet" == 1 ]] || printf '%s' "$out" | _systemmsg; return "$EXIT_OK" ;;
  esac
}
_notify() {  # title, message — argv-passed (never interpolated into AppleScript)
  command -v osascript >/dev/null 2>&1 || return 0
  osascript -e 'on run argv' -e 'display notification (item 2 of argv) with title (item 1 of argv)' \
    -e 'end run' "$1" "$2" >/dev/null 2>&1 || true
}

# ── Roots resolution: argv PATHS > $WORMHOOK_SCAN_ROOTS > config file ────────────
# A "base" is what the user points at (a repo, an org dir of repos, or any dir).
# Globs in env/config are expanded here (leading ~ -> $HOME). Note: unquoted glob
# expansion word-splits on whitespace, so root globs must not contain spaces.
_expand_into() {  # appends existing dirs from a glob/path line to the global BASES[]
  local raw="$1" g; raw="${raw/#\~/$HOME}"
  set +f
  for g in $raw; do [[ -d "$g" ]] && BASES+=("$g"); done
}
_read_config_lines() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] && _expand_into "$line"
  done < "$CONFIG"
}
# Git repos at/under a base: prune node_modules (perf + correctness) and never descend
# into .git. Bounded by WORMHOOK_DEPTH (default 4) so an org dir of repos resolves but a
# deep tree does not run away.
_discover_repos() {  # $1=base -> repo roots, one per line
  find "$1" -maxdepth "${WORMHOOK_DEPTH:-4}" -name node_modules -prune \
    -o -name .git -prune -print 2>/dev/null | while IFS= read -r g; do printf '%s\n' "${g%/.git}"; done
}
# Turn a base into concrete scan targets (appends to TARGETS[]): the repo itself if it is
# one; else the repos under it; else the dir itself (so an arbitrary non-repo dir still
# scans) — but never a dependency/build dir, where a literal scan would be wrong/slow.
_collect_targets() {  # $1=base
  local base="${1%/}" found=0 r
  if [[ -e "$base/.git" ]]; then TARGETS+=("$base"); return; fi
  while IFS= read -r r; do [[ -n "$r" ]] && { TARGETS+=("$r"); found=1; }; done < <(_discover_repos "$base")
  [[ "$found" == 1 ]] && return
  case "${base##*/}" in
    node_modules|.git|dist|build|.next|.output|vendor|.cache)
      echo "wormhook-scan: no repos under $base — skipping (dependency/build dir)" >&2; return ;;
  esac
  TARGETS+=("$base")
}

# ══ scan ═════════════════════════════════════════════════════════════════════════
cmd_scan() {
  local mode=fast quiet=0 notify=0 json=0 persistence=0 literal=0 logfile=""
  BASES=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --deep) mode=deep ;;
      --fast) mode=fast ;;
      --persistence) persistence=1 ;;
      --literal) literal=1 ;;
      -q|--quiet-if-clean) quiet=1 ;;
      --notify) notify=1 ;;
      --json) json=1 ;;
      --log) shift; logfile="${1:-}" ;;
      --log=*) logfile="${1#--log=}" ;;
      -h|--help) cmd_help; return 0 ;;
      --) shift; while [[ $# -gt 0 ]]; do [[ -d "$1" ]] && BASES+=("$1"); shift; done; break ;;
      -*) _die "unknown scan flag: $1" 2 ;;
      *) [[ -d "$1" ]] && BASES+=("$1") || echo "wormhook-scan: skipping non-dir: $1" >&2 ;;
    esac
    shift
  done

  # ── Global persistence pass (once): an empty CWD so only the $HOME/global T0 checks
  #    fire. Its finding KEYS define "global"; per-repo findings matching them are not
  #    repeated. (Keys, not titles — see _keys: a class-level title would over-match.)
  local gtmp gout gdetail global_titles global_keys
  gtmp=$(mktemp -d)
  gout=$(_scan_one "$gtmp" fast)
  rmdir "$gtmp" 2>/dev/null || command rm -rf "$gtmp" 2>/dev/null
  global_titles=$(printf '%s' "$gout" | _titles)
  global_keys=$(printf '%s' "$gout" | _keys)
  gdetail=$(printf '%s' "$gout" | _detail)
  local had_global=0; [[ -n "$global_titles" ]] && had_global=1

  if [[ "$persistence" == 1 ]]; then
    if [[ "$had_global" == 1 ]]; then
      printf '\n🚨 wormhook-scan: machine persistence detected\n\n%s\n' "$gdetail"
      [[ "$notify" == 1 ]] && _notify "wormhook: persistence detected" "$(printf '%s' "$global_titles" | head -n1)"
      [[ -n "$logfile" ]] && printf '%s  PERSISTENCE: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$(printf '%s' "$global_titles" | tr '\n' ';')" >> "$logfile"
      return "$EXIT_CRIT"
    fi
    [[ "$quiet" == 1 ]] || printf '🟢 [wormhook-scan] no machine persistence artifacts\n'
    [[ -n "$logfile" ]] && printf '%s  persistence clean\n' "$(date '+%Y-%m-%dT%H:%M:%S')" >> "$logfile"
    return "$EXIT_OK"
  fi

  # Default bases from env/config when no PATHS were given.
  if [[ ${#BASES[@]} -eq 0 ]]; then
    if [[ -n "${WORMHOOK_SCAN_ROOTS:-}" ]]; then
      local r; for r in $WORMHOOK_SCAN_ROOTS; do _expand_into "$r"; done
    elif [[ -r "$CONFIG" ]]; then
      _read_config_lines
    else
      _die "no paths given and no config at $CONFIG (run: wormhook-scan config --init)" 2
    fi
  fi
  [[ ${#BASES[@]} -eq 0 ]] && _die "no scannable directories resolved" 2

  # Expand bases -> concrete repo targets (unless --literal: scan exactly what was given).
  TARGETS=()
  local b
  if [[ "$literal" == 1 ]]; then
    for b in "${BASES[@]}"; do TARGETS+=("${b%/}"); done
  else
    for b in "${BASES[@]}"; do _collect_targets "$b"; done
  fi
  [[ ${#TARGETS[@]} -eq 0 ]] && _die "no git repos found under the given path(s) (use --literal to scan a non-repo dir)" 2

  # De-dupe (a repo can be reached via multiple bases / overlapping globs).
  local uniq=() seen=() d x dup
  for d in "${TARGETS[@]}"; do
    d="${d%/}"; dup=0
    for x in "${seen[@]:-}"; do [[ "$x" == "$d" ]] && { dup=1; break; }; done
    [[ "$dup" == 0 ]] && { uniq+=("$d"); seen+=("$d"); }
  done
  ROOTS=("${uniq[@]}")

  # ── Per-repo scans ─────────────────────────────────────────────────────────────
  local n=${#ROOTS[@]} g=0 y=0 r=0 i=0
  local P_GLYPH=() P_DISP=() P_TAIL=() P_DETAIL=() NDJSON=""
  for d in "${ROOTS[@]}"; do
    i=$((i+1))
    local out glyph disp tail rtitles rkeys localflag k
    out=$(_scan_one "$d" "$mode")
    glyph=$(printf '%s' "$out" | _glyph)
    disp="${d/#$HOME/~}"
    # Parse titles once per repo — reused by the table tail and --json. Skipped on a clean,
    # non-json repo where nothing reads them (avoids a jq fork per green repo on a sweep).
    rtitles=""
    [[ "$glyph" == "🚨" || "$json" == 1 ]] && rtitles=$(printf '%s' "$out" | _titles)
    localflag=0
    if [[ "$glyph" == "🚨" ]]; then
      # A 🚨 is "local" if ANY of its finding keys is not in the global set. Keys carry the
      # matched path, so a per-repo finding never collapses into a same-titled global one.
      rkeys=$(printf '%s' "$out" | _keys)
      if [[ -z "$rkeys" ]]; then
        localflag=1
      else
        while IFS= read -r k; do
          [[ -z "$k" ]] && continue
          printf '%s\n' "$global_keys" | grep -Fxq "$k" || localflag=1
        done <<<"$rkeys"
      fi
    elif [[ "$glyph" == "🟡" ]]; then
      localflag=1
    fi
    # Collapse "🚨 but only global findings" to locally-clean (global shown once up top).
    [[ "$glyph" == "🚨" && "$localflag" == 0 ]] && glyph="🟢"
    # Table tail: first finding title, else the cleaned status-line caveat — from the titles
    # already parsed above, not a second _titles pass.
    tail=$(printf '%s' "$rtitles" | head -n1)
    [[ -n "$tail" ]] || tail=$(printf '%s' "$out" | _systemmsg | sed 's/^🟡 \[wormhook\] //; s/^🟢 \[wormhook\] //' | head -n1)

    case "$glyph" in
      "🚨") r=$((r+1)); P_DETAIL+=("$disp"$'\x1f'"$(printf '%s' "$out" | _detail)") ;;
      "🟡") y=$((y+1)) ;;
      *)    g=$((g+1)) ;;
    esac
    P_GLYPH+=("$glyph"); P_DISP+=("$disp"); P_TAIL+=("$tail")
    if [[ "$json" == 1 ]]; then
      NDJSON+="$(jq -nc --arg p "$d" --arg s "$glyph" --argjson f "$(printf '%s' "$rtitles" | jq -Rsc 'split("\n")|map(select(length>0))')" '{path:$p,status:$s,findings:$f}')"$'\n'
    fi
  done

  if [[ "$json" == 1 ]]; then
    printf '%s' "$NDJSON" | jq -s --argjson global "$(printf '%s' "$global_titles" | jq -R . | jq -sc .)" '{global_persistence:$global,repos:.}'
    [[ "$r" -gt 0 || "$had_global" == 1 ]] && return "$EXIT_CRIT"; [[ "$y" -gt 0 ]] && return "$EXIT_DEGRADED"; return "$EXIT_OK"
  fi

  # ── Render ───────────────────────────────────────────────────────────────────
  local any_finding=0; [[ "$r" -gt 0 || "$y" -gt 0 || "$had_global" == 1 ]] && any_finding=1
  if [[ "$quiet" == 1 && "$any_finding" == 0 ]]; then
    [[ -n "$logfile" ]] && printf '%s  clean (%d repos, %s)\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$n" "$mode" >> "$logfile"
    return "$EXIT_OK"
  fi

  if [[ "$quiet" == 0 ]]; then
    printf '\nwormhook-scan · %s · %d repo(s)\n\n' "$mode" "$n"
    for ((i=0; i<${#P_GLYPH[@]}; i++)); do
      if [[ "${P_GLYPH[$i]}" == "🟢" ]]; then
        printf '  %s %s\n' "${P_GLYPH[$i]}" "${P_DISP[$i]}"
      else
        printf '  %s %-34s %s\n' "${P_GLYPH[$i]}" "${P_DISP[$i]}" "${P_TAIL[$i]}"
      fi
    done
    printf '\n%d scanned · %d 🟢 · %d 🟡 · %d 🚨\n' "$n" "$g" "$y" "$r"
  fi

  if [[ "$had_global" == 1 ]]; then
    printf '\n🚨 MACHINE PERSISTENCE — affects every repo on this machine\n\n%s\n' "$gdetail"
  fi
  for x in "${P_DETAIL[@]:-}"; do
    [[ -z "$x" ]] && continue
    printf '\n🚨 %s\n%s\n' "${x%%$'\x1f'*}" "${x#*$'\x1f'}"
  done

  if [[ -n "$logfile" ]]; then
    printf '%s  %d repos · %d green %d yellow %d red%s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" \
      "$n" "$g" "$y" "$r" "$([[ "$had_global" == 1 ]] && printf ' · MACHINE-PERSISTENCE')" >> "$logfile"
  fi
  if [[ "$notify" == 1 && "$any_finding" == 1 ]]; then
    _notify "wormhook: $r critical, $y degraded" "$([[ "$had_global" == 1 ]] && printf 'MACHINE PERSISTENCE + ')$n repos scanned"
  fi

  [[ "$r" -gt 0 || "$had_global" == 1 ]] && return "$EXIT_CRIT"
  [[ "$y" -gt 0 ]] && return "$EXIT_DEGRADED"
  return "$EXIT_OK"
}

# ══ install-cli ════════════════════════════════════════════════════════════════
cmd_install_cli() {
  local bindir="$HOME/.local/bin"
  mkdir -p "$bindir"
  ln -sf "$SELF" "$bindir/wormhook-scan"
  ln -sf "$SELF" "$bindir/wormhook"
  echo "linked: $bindir/wormhook-scan -> $SELF"
  echo "linked: $bindir/wormhook       -> $SELF"
  case ":$PATH:" in
    *":$bindir:"*) : ;;
    *) echo "note: $bindir is not on \$PATH — add it (e.g. export PATH=\"\$HOME/.local/bin:\$PATH\")" ;;
  esac
}

# ══ install-launchd ══════════════════════════════════════════════════════════════
_xml() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }
cmd_install_launchd() {
  local every=3600 paths=() bin noload=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --every) shift; every="${1:-3600}" ;;
      --every=*) every="${1#--every=}" ;;
      --no-load) noload=1 ;;
      *) [[ -d "$1" ]] && paths+=("$1") || echo "skipping non-dir: $1" >&2 ;;
    esac
    shift
  done
  [[ "$every" =~ ^[0-9]+$ ]] || _die "--every must be seconds (integer)" 2
  if [[ "$(uname -s)" != "Darwin" ]]; then
    cat <<TXT
wormhook-scan: launchd is macOS-only. On Linux, add a systemd user timer or cron line:

  # crontab -e
  @hourly $SELF scan --fast --quiet-if-clean --notify --log "$SWEEP_LOG"
TXT
    return 0
  fi
  command -v wormhook-scan >/dev/null 2>&1 && bin="$(command -v wormhook-scan)" || bin="$SELF"
  local plist="$HOME/Library/LaunchAgents/$LABEL.plist"
  mkdir -p "$HOME/Library/LaunchAgents" "$(dirname "$SWEEP_LOG")"
  # ProgramArguments: bin scan --fast --quiet-if-clean --notify --log LOG [paths...]
  local args=("$bin" scan --fast --quiet-if-clean --notify --log "$SWEEP_LOG")
  # bash 3.2 (Apple /bin/bash) aborts on "${paths[@]}" when paths is an empty array
  # under `set -u` — and no-PATHS is the default form (config/env roots). Guard the append.
  [[ ${#paths[@]} -gt 0 ]] && args+=("${paths[@]}")
  { printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    printf '<plist version="1.0"><dict>\n'
    printf '  <key>Label</key><string>%s</string>\n' "$LABEL"
    printf '  <key>ProgramArguments</key><array>\n'
    local a; for a in "${args[@]}"; do printf '    <string>%s</string>\n' "$(_xml "$a")"; done
    printf '  </array>\n'
    printf '  <key>RunAtLoad</key><true/>\n'
    printf '  <key>StartInterval</key><integer>%s</integer>\n' "$every"
    printf '  <key>StandardOutPath</key><string>%s</string>\n' "$(_xml "$SWEEP_LOG")"
    printf '  <key>StandardErrorPath</key><string>%s</string>\n' "$(_xml "$SWEEP_LOG")"
    printf '</dict></plist>\n'
  } > "$plist"
  command -v plutil >/dev/null 2>&1 && ! plutil -lint "$plist" >/dev/null 2>&1 && _die "generated plist failed plutil -lint: $plist"
  if [[ "$noload" == 1 ]]; then echo "wrote (not loaded): $plist"; return 0; fi
  launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
  if launchctl bootstrap "gui/$(id -u)" "$plist" 2>/dev/null; then
    echo "installed + loaded: $plist (every ${every}s)"
  else
    echo "wrote $plist but launchctl bootstrap failed — load manually:"
    echo "  launchctl bootstrap gui/$(id -u) \"$plist\""
  fi
  echo "log: $SWEEP_LOG"
}
cmd_uninstall_launchd() {
  local plist="$HOME/Library/LaunchAgents/$LABEL.plist"
  launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
  [[ -f "$plist" ]] && { command rm -f "$plist"; echo "removed: $plist"; } || echo "not installed"
}

# ══ install-git-hook ═════════════════════════════════════════════════════════════
_hook_block() {
  # Marker delimiters come from the shared constant (single source). The body must stay
  # clean of dropper tokens so the engine's MALICIOUS-GIT-HOOK Tier-0 check never self-flags.
  printf '%s\n' "$WORMHOOK_HOOK_MARKER"
  cat <<'BLOCK'
# Added by `wormhook-scan install-git-hook`. Out-of-band on-pull audit; fail-open.
# Forward the hook name + git's args so the report can show the correct changed-file
# range per hook (post-checkout passes <old> <new>; merge/rebase set ORIG_HEAD).
command -v wormhook-scan >/dev/null 2>&1 && wormhook-scan git-hook "$(basename "$0")" "$@" || true
BLOCK
  printf '%s\n' "$WORMHOOK_HOOK_MARKER_END"
}
cmd_install_git_hook() {
  local hookdir; hookdir="$(git config --global --get core.hooksPath 2>/dev/null || true)"
  if [[ -z "$hookdir" ]]; then
    hookdir="${XDG_CONFIG_HOME:-$HOME/.config}/wormhook/git-hooks"
    git config --global core.hooksPath "$hookdir"
    echo "note: set global core.hooksPath=$hookdir (now applies to ALL your repos)"
  fi
  hookdir="${hookdir/#\~/$HOME}"
  mkdir -p "$hookdir"
  local h f
  for h in post-merge post-checkout post-rewrite; do
    f="$hookdir/$h"
    if [[ ! -f "$f" ]]; then
      { printf '#!/usr/bin/env bash\n'; _hook_block; } > "$f"
      chmod +x "$f"; echo "created: $f"
    elif grep -qF "$WORMHOOK_HOOK_MARKER" "$f"; then
      echo "ok (already wired): $f"
    else
      { printf '\n'; _hook_block; } >> "$f"
      chmod +x "$f"; echo "appended wormhook block: $f"
    fi
  done
}
cmd_uninstall_git_hook() {
  local hookdir; hookdir="$(git config --global --get core.hooksPath 2>/dev/null || true)"
  [[ -z "$hookdir" ]] && { echo "no global core.hooksPath set"; return 0; }
  hookdir="${hookdir/#\~/$HOME}"
  local h f tmp
  for h in post-merge post-checkout post-rewrite; do
    f="$hookdir/$h"
    { [[ -f "$f" ]] && grep -qF "$WORMHOOK_HOOK_MARKER" "$f"; } || continue
    tmp="$f.wh.$$"
    # Strip the marker..end block (exact string compare on $0 — robust to chars in the marker).
    awk -v o="$WORMHOOK_HOOK_MARKER" -v c="$WORMHOOK_HOOK_MARKER_END" \
      '$0==o{s=1} !s{print} $0==c{s=0}' "$f" > "$tmp"
    # If only a bare shebang (or nothing) remains, drop the file entirely.
    if ! grep -qvE '^[[:space:]]*$|^#!' "$tmp"; then
      command rm -f "$f" "$tmp"; echo "removed (was wormhook-only): $f"
    else
      mv "$tmp" "$f"; chmod +x "$f"; echo "unwired: $f"
    fi
  done
}

# ══ status / config / help ═══════════════════════════════════════════════════════
cmd_status() {
  echo "engine:   $ENGINE"
  echo "config:   $CONFIG $([[ -r "$CONFIG" ]] && echo '(present)' || echo '(missing — config --init)')"
  if [[ -r "$CONFIG" ]]; then
    BASES=(); _read_config_lines; TARGETS=()
    local b; for b in "${BASES[@]:-}"; do [[ -n "$b" ]] && _collect_targets "$b"; done
    echo "roots:    ${#BASES[@]} base(s) -> ${#TARGETS[@]} repo(s)"
  fi
  local b="$HOME/.local/bin/wormhook-scan"
  echo "cli link: $([[ -L "$b" ]] && echo "$b -> $(readlink "$b")" || echo 'not linked (install-cli)')"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && echo "launchd:  loaded ($LABEL)" || echo "launchd:  not loaded (install-launchd)"
  fi
  local hookdir; hookdir="$(git config --global --get core.hooksPath 2>/dev/null || true)"; hookdir="${hookdir/#\~/$HOME}"
  if [[ -n "$hookdir" ]]; then
    local _n=0 _h
    for _h in post-merge post-checkout post-rewrite; do
      [[ -f "$hookdir/$_h" ]] && grep -qF "$WORMHOOK_HOOK_MARKER" "$hookdir/$_h" 2>/dev/null && _n=$((_n+1))
    done
    if [[ "$_n" == 3 ]]; then echo "git hook: installed in $hookdir (3/3 hooks)"
    elif [[ "$_n" -gt 0 ]]; then echo "git hook: PARTIAL ($_n/3 in $hookdir) — re-run install-git-hook"
    else echo "git hook: not installed (install-git-hook)"; fi
  else
    echo "git hook: not installed (install-git-hook)"
  fi
  [[ -f "$SWEEP_LOG" ]] && { echo "last sweep:"; tail -n 3 "$SWEEP_LOG" | sed 's/^/  /'; }
}
cmd_config() {
  case "${1:-}" in
    --show) if [[ -r "$CONFIG" ]]; then cat "$CONFIG"; else _die "no config at $CONFIG" 2; fi ;;
    --init|"")
      if [[ -e "$CONFIG" ]]; then echo "config exists: $CONFIG"; return 0; fi
      mkdir -p "$(dirname "$CONFIG")"
      if [[ -r "$SAMPLE" ]]; then cp "$SAMPLE" "$CONFIG"; else
        cat > "$CONFIG" <<'CONF'
# wormhook-scan roots — one path or glob per line; # comments allowed.
# Each teammate edits this for their own machine. Globs expand at scan time.
# ~/sandbox/git-repos/*/
# ~/sandbox/git-repos/*/*/
# ~/code/
CONF
      fi
      echo "wrote: $CONFIG  (edit it to point at where you keep your repos)" ;;
    *) _die "config: use --init or --show" 2 ;;
  esac
}
cmd_help() {
  cat <<TXT
wormhook-scan — run the wormhook supply-chain scanner outside Claude Code.

USAGE
  wormhook-scan [PATHS...] [--deep|--fast] [--persistence] [--literal] [-q] [--notify] [--log F] [--json]
  wormhook-scan check [DIR] [-q]          # one-repo verdict (exec-guard primitive)
  wormhook-scan shell-init                # print opt-in npm/pnpm/yarn/bun/npx exec-guard
  wormhook-scan git-hook                  # used by installed git hooks (loud on-pull report)
  wormhook-scan install-cli
  wormhook-scan install-launchd [--every SECONDS] [--no-load] [PATHS...]
  wormhook-scan install-git-hook
  wormhook-scan uninstall-launchd | uninstall-git-hook
  wormhook-scan status
  wormhook-scan config --init | --show

  Tip: in Claude Code, run /wormhook-setup for an interactive installer.
  Exec-guard (opt-in; refuses npm/pnpm/yarn/bun/npx on a dirty repo, outside Claude):
    eval "$(wormhook-scan shell-init)"    # in ~/.zshrc/.bashrc, AFTER nvm/asdf

SCAN
  PATHS are repos, org dirs of repos, or any dir; each resolves to the git repo(s)
  at/under it (node_modules pruned). No PATHS -> \$WORMHOOK_SCAN_ROOTS or $CONFIG.
  --fast (default)  Tier 0+1 (+Tier 2 only if deps drifted) — ~26ms/repo.
  --deep            force the Tier-2 node_modules walk.
  --persistence     only the machine-wide (\$HOME) persistence checks.
  --literal         scan exactly the given dirs (skip git-repo discovery).
  -q                silent when clean (for hooks / launchd).
  Exit: 0 clean · 1 critical (or machine persistence) · 2 degraded.
TXT
}

# ══ git-hook ═════════════════════════════════════════════════════════════════════
# Invoked by the installed post-merge/post-checkout/post-rewrite hooks. On an IOC it
# prints a LOUD red banner right after the `git pull` — showing what the update changed
# and the finding — so you SEE it and do not go on to run `npm run dev`. A post-op hook
# cannot block the pull (the files already landed); the human-visible error is the gate.
# Fail-open: any error exits 0 so it never wedges a git operation.
cmd_git_hook() {
  local hook="${1:-}"; [ $# -gt 0 ] && shift   # $1=hook name; remaining "$@" are git's hook args
  local repo changed="" out glyph
  repo=$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null) || return 0
  # Pick the "files this update changed" range HONESTLY per hook. ORIG_HEAD is the
  # pre-op HEAD only for merge/rebase; post-checkout instead passes <prev> <new> on
  # argv (and a third flag arg: 1=branch move, 0=file checkout => no meaningful range).
  # Legacy installs forward no hook name (hook="") => fall through to the ORIG_HEAD path.
  case "$hook" in
    post-checkout)
      [ "${3:-1}" = 1 ] && [ -n "${1:-}" ] && [ -n "${2:-}" ] && \
        changed=$(git -C "$repo" diff --stat "$1" "$2" 2>/dev/null | tail -n 50) ;;
    *)
      git -C "$repo" rev-parse -q --verify ORIG_HEAD >/dev/null 2>&1 && \
        changed=$(git -C "$repo" diff --stat ORIG_HEAD HEAD 2>/dev/null | tail -n 50) ;;
  esac
  out=$(_scan_one "$repo" fast); glyph=$(printf '%s' "$out" | _glyph)
  if [[ "$glyph" == "🚨" ]]; then
    printf '\033[1;31m\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n⛔  wormhook: SUPPLY-CHAIN IOC after a git update\n    %s\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' "${repo/#$HOME/~}"
    [[ -n "${changed:-}" ]] && printf '\n📋 files this update changed:\n%s\n' "$changed"
    printf '%s\n' "$(printf '%s' "$out" | _detail)"
    printf '\033[1;31m\n⚠  Do NOT run npm/node/dev in this repo until you have cleared the finding above.\033[0m\n'
    # shellcheck disable=SC2016  # literal instruction text shown to the user, not an expansion
    printf '   (optional backstop: eval "$(wormhook-scan shell-init)" makes npm/pnpm refuse to run here automatically.)\n'
    return "$EXIT_CRIT"
  fi
  [[ "$glyph" == "🟡" ]] && printf '%s' "$out" | _systemmsg
  return "$EXIT_OK"
}

# ══ check ════════════════════════════════════════════════════════════════════════
# Single-repo fast verdict — the exec-guard primitive (one engine pass, no fleet/dedup,
# minimal latency). Exit 0 clean · 1 critical · 2 degraded.
cmd_check() {
  local dir="$PWD" mode=fast quiet=0 a
  for a in "$@"; do
    case "$a" in
      -q|--quiet-if-clean) quiet=1 ;;
      --deep) mode=deep ;;
      -*) ;;
      *) [[ -d "$a" ]] && dir="$a" ;;
    esac
  done
  _render_verdict "$(_scan_one "$dir" "$mode")" "$quiet"
}

# ══ shell-init ═══════════════════════════════════════════════════════════════════
# Opt-in exec-guard: the out-of-Claude analog of the PreToolUse block. Wraps the JS
# package managers (NOT `node` — too hot a path) so they refuse to run in a repo with a
# live IOC, scan-on-exec so it catches code that arrived without a git hook firing.
# Enable: eval "$(wormhook-scan shell-init)"  — add to ~/.zshrc / ~/.bashrc AFTER any
# version manager (nvm/asdf), since it defines npm/pnpm/yarn/bun/npx as functions.
cmd_shell_init() {
  cat <<'SH'
# wormhook exec-guard (eval "$(wormhook-scan shell-init)") — refuse npm/pnpm/yarn/bun/npx
# in a repo with a live supply-chain IOC. The out-of-Claude analog of the PreToolUse block.
# Load AFTER nvm/asdf. Not airtight (a direct ./node_modules/.bin/… or `command npm`
# bypasses it) — a tripwire, not a sandbox. Fail-open if wormhook-scan is absent.
_wormhook_guard() {
  command -v wormhook-scan >/dev/null 2>&1 || return 0
  # Exit codes: 0 clean · 1 critical (IOC) · 2 degraded. Block ONLY on 1 — a degraded
  # scan (missing dep, timeout, unparseable verdict) must FAIL OPEN, not brick npm with
  # a false "IOC" message. The engine is fail-open by design; the guard must match.
  wormhook-scan check "$PWD" -q; local rc=$?
  [ "$rc" -eq 1 ] || return 0
  printf '\033[1;31m⛔ wormhook blocked this command: supply-chain IOC in %s\n   run `wormhook-scan .` for detail; clear it before re-running.\033[0m\n' "$PWD" >&2
  return 1
}
npm()  { _wormhook_guard && command npm  "$@"; }
pnpm() { _wormhook_guard && command pnpm "$@"; }
yarn() { _wormhook_guard && command yarn "$@"; }
bun()  { _wormhook_guard && command bun  "$@"; }
npx()  { _wormhook_guard && command npx  "$@"; }
SH
}

# ── Dispatch ─────────────────────────────────────────────────────────────────────
case "${1:-}" in
  install-cli)         shift; cmd_install_cli "$@" ;;
  install-launchd)     shift; cmd_install_launchd "$@" ;;
  install-git-hook)    shift; cmd_install_git_hook "$@" ;;
  uninstall-launchd)   shift; cmd_uninstall_launchd "$@" ;;
  uninstall-git-hook)  shift; cmd_uninstall_git_hook "$@" ;;
  status)              shift; cmd_status "$@" ;;
  config)              shift; cmd_config "$@" ;;
  check)               shift; cmd_check "$@" ;;
  git-hook)            shift; cmd_git_hook "$@" ;;
  shell-init)          shift; cmd_shell_init "$@" ;;
  help|-h|--help)      cmd_help ;;
  scan)                shift; cmd_scan "$@" ;;
  *)                   cmd_scan "$@" ;;   # default verb: scan (PATHS/flags)
esac
