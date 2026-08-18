#!/usr/bin/env bash
# Aegis — macOS patch runner. Apple updates via softwareupdate, apps via
# Homebrew (run as the console user, never root). JSON audit line for Wazuh.
# Never reboots unless --allow-reboot.
#
# Usage:
#   sudo ./patch-mac.sh [--dry-run] [--allow-reboot] [--group NAME]
set -uo pipefail

DRY_RUN=0; ALLOW_REBOOT=0; GROUP="mac"
LOG_DIR="/var/log/aegis"; LOG="${LOG_DIR}/aegis-patch.log"; START=$(date +%s)

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --allow-reboot) ALLOW_REBOOT=1 ;;
    --group) GROUP="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac; shift
done

[ "$(id -u)" -eq 0 ] || { echo "Aegis: run with sudo" >&2; exit 1; }
mkdir -p "$LOG_DIR"

HOST=$(scutil --get ComputerName 2>/dev/null || hostname)
STATUS="success"; ERRORS=""; OS_UPDATES=0; BREW_UPDATES=0; CASK_UPDATES=0; CASKS_ADOPTED=0; PIP_UPDATES=0; REBOOT_REQ=0

# Vendor apps to bring under brew management ("cask_id:App bundle.app"). Apps
# installed straight from the vendor (Adobe, NoMachine, Zoom, ...) are invisible
# to `brew upgrade`; `brew install --cask --adopt <cask>` adopts an app that is
# ALREADY present in /Applications — never installs new software — and hands its
# future patching to brew. ADOPT IS DEFAULT-ON (Mark 2026-08-03: mac fleet must
# manage/patch every vendor app). The curated map is the override list (cask
# names that differ from the app-bundle slug, e.g. zoom.us.app -> zoom); every
# OTHER .app in /Applications is attempted via a slug-derived cask name too.
CASKS_TO_MANAGE=(
  "adobe-acrobat-reader:Adobe Acrobat Reader.app"
  "nomachine:NoMachine.app"
  "google-chrome:Google Chrome.app"
  "firefox:Firefox.app"
  "zoom:zoom.us.app"
  "microsoft-teams:Microsoft Teams.app"
)
CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null)
note_err(){ STATUS="error"; ERRORS="${ERRORS}${ERRORS:+; }$1"; }
# note_warn: carry a non-fatal condition (e.g. pip index offline) in the SAME
# errors field WITHOUT flipping STATUS to error — mirrors the AEGIS-WARN string
# the softwareupdate-timeout path emits. A wedged/offline PyPI must NOT fail the
# whole run; it's a warning, not a patch failure.
note_warn(){ ERRORS="${ERRORS}${ERRORS:+; }AEGIS-WARN: $1"; }

# Rosetta trap (hit live 2026-08-03, Ascend Macs): the Wazuh agent binary on
# Apple Silicon can run as x86_64 (Rosetta) — every AR child inherits that arch,
# and `brew` REFUSES the ARM default prefix from a Rosetta shell ("Error: Cannot
# install under Rosetta 2 in ARM default prefix (/opt/homebrew)!"), failing ALL
# brew commands instantly. /opt/homebrew exists ONLY on ARM Macs, so its presence
# is the gate: wrap brew shells in `arch -arm64` when we're on Apple Silicon.
BREW_ARCH=()
[ -d /opt/homebrew ] && BREW_ARCH=(arch -arm64)

# Run a brew command AS THE CONSOLE USER and, on failure, fold the REAL brew
# stderr into the errors field. Without this the errors field only ever said
# "brew upgrade failed" — the actual cause (e.g. git "dubious ownership",
# /opt/homebrew not writable, missing CLT) lived only in aegis-app.log, which
# the agent's json localfile silently drops. Now every brew failure is
# self-diagnosing straight from the Wazuh record (rule 100106). We prefer the
# telltale error lines and cap length so the one-line JSON stays sane.
brew_run(){  # $1 = failure label, $2 = command string (run under bash -lc)
  local label="$1" cmd="$2" out rc msg
  # cd /tmp FIRST, in the ENGINE's (root) context BEFORE sudo: bash's shell-init
  # resolves $PWD from getcwd() at startup — if the inherited CWD (e.g.
  # /var/ossec/...) is unreadable by the console user, bash bails with
  # "shell-init: error retrieving current directory" and brew refuses ("Error:
  # $PWD must be set"). cd inside the command string is too late. The subshell
  # cds as root, then sudo spawns bash from /tmp (world-accessible). -H sets
  # HOME to the console user's home so brew's bootsnap/cache land in THEIR
  # ~/Library/Caches/Homebrew; without it brew inherited the AR parent's HOME
  # (e.g. /Users/veteranop-ops or /var/root) and died with Errno::EACCES on a
  # cache path the console user can't write (H2621609).
  out=$( (cd /tmp && sudo -H -u "$CONSOLE_USER" "${BREW_ARCH[@]}" bash -lc "$cmd") 2>&1); rc=$?
  [ "$rc" -eq 0 ] && return 0
  msg=$(printf '%s\n' "$out" | grep -iE 'error|fatal|denied|permission|not permitted|dubious|read-?only|no such|command not found|xcrun' | tail -2 | tr '\n' ' ')
  [ -n "$msg" ] || msg=$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -2 | tr '\n' ' ')
  msg=$(printf '%s' "$msg" | cut -c1-400)
  # Environmental vs engine failure (H2621609 v0.5.4). Homebrew rolls the
  # per-cask failures of `upgrade`/`--adopt` up into "Problems with multiple
  # casks:" ONLY after it has evaluated each cask — so that marker, and the
  # individual causes we hit across the fleet, are all MACHINE STATE the engine
  # cannot resolve non-interactively:
  #   - a cask up/adopt step that shells out to `sudo` on a box where the console
  #     user has no passwordless sudo ("a password is required" / "a terminal is
  #     required to read the password" — metasploit msfremove, wireshark rm,
  #     the `chmod -R a+rX` adopt does on slack/telegram/duckduckgo),
  #   - a missing App source ("App source '...' is not there" — mumble, sherlock),
  #   - a dead vendor download / 404 (vnc-viewer),
  #   - a Caskroom-vs-/Applications version skew ("... but is X for /Applications"
  #     — balenaetcher),
  #   - a cask's own launchctl probe (pearcleaner).
  #   - the brew-cask --adopt chmod step failing headless on Ascend Mac minis
  #     (claude/obsidian/visual-studio-code/google-chrome, nightly since
  #     2026-08-13, M2623001): `sudo -E -- chmod -R a+rX /Applications/*.app`
  #     exits 1 with EMPTY output when the console user has no passwordless
  #     sudo — brew reports "Failure while executing; ... exited with 1.
  #     Here's the output:" with nothing after. The Apple update still
  #     installed (apple_updates=1); only the adopt step is environmental.
  # None are patch-engine bugs; flipping the WHOLE run to error on them buries a
  # genuine regression and pages on state a patch pass can't fix. Downgrade to
  # AEGIS-WARN. Everything else — brew itself broken, Rosetta trap, git dubious
  # ownership, HOME/PWD unset, Caskroom perms, formulae-API network down — has NO
  # such marker and stays a real error. Classify on the FULL output, not $msg.
  if printf '%s\n' "$out" | grep -qiE 'Problems with multiple casks|a password is required|a terminal is required to read the password|App source .* is not there|Download failed|curl: \([0-9]+\)|returned error: (40[0-9]|50[0-9])|launchctl|but is .* for /Applications|Failure while executing;.*chmod -R a\+rX'; then
    note_warn "$label (environmental, rc=$rc): ${msg:-no output}"
    return 1
  fi
  note_err "$label (rc=$rc): ${msg:-no output}"
  return 1
}

# Adopt a vendor app already present in /Applications into brew so brew manages
# and patches it. $1 = absolute app path. Never installs new software (adopt
# only acts on apps that exist). Silent-skips Apple system apps (bundle id
# com.apple.*) and casks that don't exist in the tap; counts real adoptions.
# Errors that ARE real (installer failures, permissions) fold into the errors
# field via brew_run. Also handles the dry-run case: report-only, no adopt.
adopt_app(){  # $1 = app path
  local app="$1" cask="" pair="" bid="" base out rc
  [ -d "$app" ] || return 0
  # 1) curated override (cask != slug), 2) slug-derived cask (lowercase, spaces->dashes)
  for pair in "${CASKS_TO_MANAGE[@]}"; do
    [ "$app" = "/Applications/${pair#*:}" ] && cask="${pair%%:*}" && break
  done
  if [ -z "$cask" ]; then
    base=$(basename "$app" .app)
    cask=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
  fi
  # skip Apple system apps (Safari, Mail, ...) — never adopt those
  bid=$(defaults read "$app/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || true)
  case "$bid" in com.apple.*) return 0 ;; esac
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "DRY RUN — would adopt: $cask ($(basename "$app"))"
    return 0
  fi
  # cask-exists gate: brew install --cask --adopt on a NONEXISTENT cask prints
  # "To install <suggestion>, run: ..." and exits 1 — that's a slug miss, not a
  # failure. Check `brew info --cask` first so misses stay SILENT (no error
  # noise) while real adopt attempts keep their full error text.
  if ! (cd /tmp && sudo -H -u "$CONSOLE_USER" "${BREW_ARCH[@]}" bash -lc "$BREW info --cask \"$cask\" >/dev/null 2>&1"); then
    return 0
  fi
  # PKG-CASK SKIP (2026-08-04, H2621511): brew --adopt on a pkg-type cask
  # shells out to /usr/sbin/installer -pkg, which requires GUI/admin auth and
  # FAILS headless with rc=1 (observed: NoMachine, Zoom, Teams, Google Drive on
  # Ascend-MBP-1 — 5 CRITICAL alerts in 24h). Detect the artifact type from
  # `brew info --json=v2` generically (any ".pkg" artifact ⇒ skip the whole
  # adopt path for that cask) instead of a brittle denylist, so future
  # pkg-backed apps hit the same safe skip. Skipped ≠ error: no note_err, no
  # status flip — the cask stays in CASKS_TO_MANAGE for a future GUI adopt.
  # ADOPT-ALL remains default-on for drag-drop .app bundles (Mark 2026-08-03).
  if (cd /tmp && sudo -H -u "$CONSOLE_USER" "${BREW_ARCH[@]}" bash -lc \
      "$BREW info --json=v2 --cask \"$cask\" 2>/dev/null" | grep -q '\.pkg'); then
    echo "pkg cask $cask — requires GUI adopt (installer -pkg fails headless); skipped"
    return 0
  fi
  if brew_run "adopt $cask failed" "$BREW install --cask --adopt \"$cask\""; then
    CASKS_ADOPTED=$((CASKS_ADOPTED + 1))
    echo "adopted: $cask"
  fi
}

# --- emit safety ---
# Every value below is interpolated into a ONE-LINE JSON record that Wazuh's
# logcollector reads with <log_format>json</log_format>. A stray newline or quote
# makes the line unparseable and logcollector drops it AT THE AGENT — the run then
# completes having reported nothing, which is indistinguishable from never running.
# num()  guarantees an integer field; jstr() escapes a string field.
num(){ case "${1:-}" in ''|*[!0-9]*) printf '0' ;; *) printf '%s' "$1" ;; esac; }
jstr(){ printf '%s' "${1:-}" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# --- Apple software updates ---
# 2>&1: softwareupdate writes its banner and "No new software available." to
# stderr, so discarding stderr left $AVAIL routinely empty.
# TIMEOUT: a wedged softwareupdated daemon makes `softwareupdate -l` hang
# FOREVER (observed on Ascend MBP-1/MBP-2, 2026-08-01 — every run for 30 days
# dispatched but never completed; runs hung while the machines were awake).
# Time-box it so the run COMPLETES with a diagnosable result instead of dying
# silently: on timeout, $AVAIL becomes an AEGIS-WARN the result line carries.
SU_TIMEOUT=180
OUT="$LOG_DIR/swupd_list.$$"
softwareupdate -l > "$OUT" 2>&1 &
SUPID=$!
( sleep "$SU_TIMEOUT"; kill -9 "$SUPID" 2>/dev/null ) &
KILLER=$!
wait "$SUPID" 2>/dev/null
kill "$KILLER" 2>/dev/null
if [ -s "$OUT" ]; then
  AVAIL=$(cat "$OUT")
else
  AVAIL="AEGIS-WARN: softwareupdate -l timed out after ${SU_TIMEOUT}s (softwareupdated wedged? try: sudo killall softwareupdated)"
fi
rm -f "$OUT"
# grep -c prints "0" AND exits 1 when nothing matches, so a `|| echo 0` fallback
# appends a SECOND zero -> the literal bytes "0\n0". That both corrupted the JSON
# record and made `[ "$OS_UPDATES" -gt 0 ]` a bash error, silently skipping the
# install below. Use `|| true` and sanitize. [[:space:]] replaces the GNU-only \s,
# which BSD/macOS grep does not honour (so this never matched on a Mac).
OS_UPDATES=$(num "$(printf '%s\n' "$AVAIL" | grep -c -E '^[[:space:]]*\* ' || true)")
printf '%s\n' "$AVAIL" | grep -qiE 'restart|shut down' && REBOOT_REQ=1

if [ "$DRY_RUN" -eq 1 ]; then
  echo "DRY RUN — Apple updates available: $OS_UPDATES"
  printf '%s\n' "$AVAIL"
else
  if [ "$OS_UPDATES" -gt 0 ]; then
    if [ "$ALLOW_REBOOT" -eq 1 ]; then
      softwareupdate -ia --restart --agree-to-license || note_err "softwareupdate failed"
    else
      softwareupdate -ia --agree-to-license || note_err "softwareupdate failed"
    fi
  fi
fi

# --- Homebrew (as the logged-in user; brew refuses to run as root) ---
# Formulae AND casks. Casks reach the GUI third-party apps (Adobe Acrobat, NoMachine,
# Chrome, ...) that softwareupdate never touches — this is the macOS analogue of the
# Windows user-context winget pass. Casks flagged auto_updates are skipped unless you
# add --greedy (aggressive; re-touches self-updating apps), so we stay non-greedy.
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
  # cd /tmp BEFORE sudo (same reason as brew_run: execd hands us an unreadable
  # CWD, e.g. /Library/Ossec, and the console user's shell-init getcwd() fails).
  # PATH bootstrap: `bash -lc` login shell does NOT put /opt/homebrew/bin on PATH
  # for a non-brew login profile, so a bare `command -v brew` returned empty and
  # the whole brew block was skipped (brew_ran=0). Prepend the standard Homebrew
  # prefixes so detection resolves to the absolute brew path used downstream.
  BREW=$( (cd /tmp && sudo -H -u "$CONSOLE_USER" bash -lc 'export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"; command -v brew') 2>/dev/null || true)
  if [ -n "$BREW" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "DRY RUN — brew outdated (formulae + casks):"
      (cd /tmp && sudo -H -u "$CONSOLE_USER" "${BREW_ARCH[@]}" bash -lc "$BREW update >/dev/null 2>&1; $BREW outdated; echo '-- casks --'; $BREW outdated --cask") || true
      BREW_UPDATES=$((cd /tmp && sudo -H -u "$CONSOLE_USER" "${BREW_ARCH[@]}" bash -lc "$BREW outdated | wc -l") 2>/dev/null | tr -d ' ' || echo 0)
      CASK_UPDATES=$((cd /tmp && sudo -H -u "$CONSOLE_USER" "${BREW_ARCH[@]}" bash -lc "$BREW outdated --cask | wc -l") 2>/dev/null | tr -d ' ' || echo 0)
    else
      brew_run "brew upgrade failed" "$BREW update && $BREW upgrade && $BREW cleanup"
      brew_run "brew cask upgrade failed" "$BREW upgrade --cask"
      BREW_UPDATES=1; CASK_UPDATES=1
      # ADOPT-ALL (default, Mark 2026-08-03): bring EVERY vendor app already in
      # /Applications under brew management so brew patches it. Curated overrides
      # first, then every other .app (system apps skipped via com.apple.* bid).
      # The glob pass skips paths already handled by the curated list (no
      # associative arrays — macOS ships bash 3.2).
      for pair in "${CASKS_TO_MANAGE[@]}"; do
        adopt_app "/Applications/${pair#*:}"
      done
      for app in /Applications/*.app; do
        already=0; pair2=""
        for pair2 in "${CASKS_TO_MANAGE[@]}"; do
          [ "$app" = "/Applications/${pair2#*:}" ] && already=1 && break
        done
        [ "$already" -eq 1 ] && continue
        adopt_app "$app"
      done
    fi
  fi
fi

# --- pip user-site upgrades (as the logged-in user) ---
# WHY: 69 of 75 Wazuh vuln findings on the Macs are Python packages that ship
# with the system interpreters — CLT pip 21.2.4 (/usr/bin/python3) AND brew pip
# (/opt/homebrew/bin/python3), plus setuptools/urllib3/requests/wheel/certifi/...
# softwareupdate never touches them and brew only manages brew's OWN python, so
# these findings NEVER clear on the normal cycle. We upgrade them into the
# USER's site-packages (~/.local, ~/Library/Python/<ver>/lib/python/site-packages)
# — SIP-safe, no writes to system dirs, no root inside the user context. Console
# user only (root has no meaningful user-site and pip-as-root is a footgun), same
# guard the brew block uses. Only the well-known SYSTEM interpreters below; venvs
# are never enumerated, so we never touch a project's pinned deps.
#
# PEP 668: modern CLT/brew python ship an EXTERNALLY-MANAGED marker; even a
# --user install refuses with "externally-managed-environment" unless
# --break-system-packages is passed. We try the clean form first and only fall
# back when stderr actually says so (constraint 4).
#
# Time-box (PIP_TIMEOUT): both `pip list --outdated` and `pip install` need the
# network — a wedged PyPI index would hang the run forever. run_timed mirrors the
# SU_TIMEOUT kill-background pattern: a hang becomes a COMPLETED run + warning.
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
  PIP_TIMEOUT=120
  # Run a console-user shell command with a hard timeout. Combined output -> $2.
  # Returns the command's rc, or a non-zero (137 = SIGKILL) if the killer fired.
  run_timed(){  # $1 = command string (bash -lc as console user), $2 = outfile
    local cmd="$1" outf="$2" pid killer rc
    # cd /tmp BEFORE the sudo -u transition: execd hands the AR child a CWD the
    # console user cannot access (observed: /Library/Ossec), so python's
    # os.getcwd() throws PermissionError and pip aborts. -H sets HOME to the
    # console user's home so `pip install --user` lands in THEIR ~/.local, not
    # root's. (Same cd-first pattern as brew_run.)
    ( cd /tmp && sudo -H -u "$CONSOLE_USER" bash -lc "$cmd" ) > "$outf" 2>&1 &
    pid=$!
    ( sleep "$PIP_TIMEOUT"; kill -9 "$pid" 2>/dev/null ) &
    killer=$!
    wait "$pid" 2>/dev/null; rc=$?
    kill "$killer" 2>/dev/null
    return "$rc"
  }
  # Known SYSTEM interpreters ONLY (CLT, Apple-Silicon brew, Intel brew/local).
  # Missing paths and pip-less pythons are skipped silently. Space-separated so
  # the loop stays bash-3.2 plain (no arrays needed here).
  PIP_PYTHONS="/usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3"
  for PY in $PIP_PYTHONS; do
    [ -x "$PY" ] || continue
    # Must actually expose pip (a bare CLT python3 may not) — probe quietly.
    # cd /tmp first: under the Wazuh Active-Response (execd) path the AR child
    # inherits an unreadable CWD (/Library/Ossec); `sudo -u <user> python -m pip`
    # then dies with `PermissionError: [Errno 13]` in os.getcwd(), so the probe
    # returned rc!=0 and `|| continue` silently skipped EVERY interpreter — the
    # pip block never ran under AR (worked fine over an SSH shell whose CWD the
    # user could read). H2621609. -H matches run_timed for HOME consistency.
    (cd /tmp && sudo -H -u "$CONSOLE_USER" "$PY" -m pip --version) >/dev/null 2>&1 || continue

    POUT="$LOG_DIR/pip_outdated.$$"
    run_timed "$PY -m pip list --outdated --format=json --disable-pip-version-check" "$POUT"; prc=$?
    if [ "$prc" -ne 0 ]; then
      # offline / wedged index / timeout — warn, keep STATUS success (constraint 5)
      note_warn "pip list --outdated failed ($PY rc=$prc — offline or wedged index?); skipped"
      rm -f "$POUT"; continue
    fi
    # Parse names from the JSON array WITHOUT jq (not on stock macOS). grep -oE
    # prints one match per line regardless of the array being one physical line.
    OUTDATED=$(grep -oE '"name":[[:space:]]*"[^"]+"' "$POUT" | sed -E 's/^"name":[[:space:]]*"//; s/"$//')
    rm -f "$POUT"
    [ -n "$OUTDATED" ] || continue          # nothing outdated for this interpreter
    N=$(printf '%s\n' "$OUTDATED" | grep -c .)

    if [ "$DRY_RUN" -eq 1 ]; then
      # Dry-run stays dry: report count + would-upgrade names, install nothing.
      PIP_UPDATES=$((PIP_UPDATES + N))
      echo "DRY RUN — pip outdated ($N) for $PY:"
      printf '%s\n' "$OUTDATED"
      continue
    fi

    # One upgrade transaction per interpreter. Upgrading pip ITSELF is desired
    # (CLT pip 21.2.4 is one of the flagged packages). OUTDATED is NEWLINE-
    # delimited (grep -oE emits one name per line). run_timed embeds the command
    # as a STRING into `bash -lc "$cmd"`, so an embedded newline is a COMMAND
    # SEPARATOR: pip would receive only the FIRST name and every following name
    # would run as its own command ("six: command not found", rc=127) — the live
    # v0.5.3 apply failure (H2621609). Flatten to a single SPACE-separated arg
    # list before embedding; pip names never contain spaces so word-splitting
    # inside the console-user shell is safe.
    OUTDATED_ARGS=$(printf '%s\n' "$OUTDATED" | tr '\n' ' ')
    PINS="$LOG_DIR/pip_install.$$"
    run_timed "$PY -m pip install --user --upgrade $OUTDATED_ARGS" "$PINS"; irc=$?
    if [ "$irc" -eq 0 ]; then
      PIP_UPDATES=$((PIP_UPDATES + N)); echo "pip upgraded ($N) for $PY"
    elif grep -qi 'externally-managed' "$PINS"; then
      # PEP 668 fallback — retry ONCE allowing the user-site install past the marker.
      run_timed "$PY -m pip install --user --upgrade --break-system-packages $OUTDATED_ARGS" "$PINS"; irc=$?
      if [ "$irc" -eq 0 ]; then
        PIP_UPDATES=$((PIP_UPDATES + N)); echo "pip upgraded ($N, PEP668 fallback) for $PY"
      else
        pmsg=$(grep -iE 'error|fatal|denied|not permitted|no such|not found|could not' "$PINS" | tail -2 | tr '\n' ' ' | cut -c1-400)
        note_err "pip upgrade failed ($PY rc=$irc): ${pmsg:-no output}"
      fi
    else
      pmsg=$(grep -iE 'error|fatal|denied|not permitted|no such|not found|could not' "$PINS" | tail -2 | tr '\n' ' ' | cut -c1-400)
      note_err "pip upgrade failed ($PY rc=$irc): ${pmsg:-no output}"
    fi
    rm -f "$PINS"
  done
fi

DUR=$(( $(date +%s) - START ))
JSON=$(printf '{"timestamp":"%s","tool":"aegis","host":"%s","os_family":"macos","group":"%s","dry_run":%s,"apple_updates":%s,"brew_ran":%s,"cask_ran":%s,"casks_adopted":%s,"pip_updates":%s,"reboot_required":%s,"errors":"%s","duration_sec":%s,"status":"%s"}' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(jstr "$HOST")" "$(jstr "$GROUP")" \
  "$([ $DRY_RUN -eq 1 ] && echo true || echo false)" "$(num "$OS_UPDATES")" "$(num "$BREW_UPDATES")" "$(num "$CASK_UPDATES")" "$(num "$CASKS_ADOPTED")" "$(num "$PIP_UPDATES")" \
  "$([ $REBOOT_REQ -eq 1 ] && echo true || echo false)" "$(jstr "$ERRORS")" "$(num "$DUR")" "$(jstr "$STATUS")")

echo "$JSON" >> "$LOG"; echo "$JSON"
