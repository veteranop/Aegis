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
STATUS="success"; ERRORS=""; OS_UPDATES=0; BREW_UPDATES=0; CASK_UPDATES=0; CASKS_ADOPTED=0; REBOOT_REQ=0

# Curated vendor apps to bring under brew management ("cask_id:App bundle.app"). Apps
# installed straight from the vendor (Adobe, NoMachine, ...) are invisible to
# `brew upgrade`; adopting them installs the latest (patches the finding) and hands
# future upkeep to brew. We ONLY adopt apps that are already present — never install new.
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

# Run a brew command AS THE CONSOLE USER and, on failure, fold the REAL brew
# stderr into the errors field. Without this the errors field only ever said
# "brew upgrade failed" — the actual cause (e.g. git "dubious ownership",
# /opt/homebrew not writable, missing CLT) lived only in aegis-app.log, which
# the agent's json localfile silently drops. Now every brew failure is
# self-diagnosing straight from the Wazuh record (rule 100106). We prefer the
# telltale error lines and cap length so the one-line JSON stays sane.
brew_run(){  # $1 = failure label, $2 = command string (run under bash -lc)
  local label="$1" cmd="$2" out rc msg
  out=$(sudo -u "$CONSOLE_USER" bash -lc "$cmd" 2>&1); rc=$?
  [ "$rc" -eq 0 ] && return 0
  msg=$(printf '%s\n' "$out" | grep -iE 'error|fatal|denied|permission|not permitted|dubious|read-?only|no such|command not found|xcrun' | tail -2 | tr '\n' ' ')
  [ -n "$msg" ] || msg=$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -2 | tr '\n' ' ')
  msg=$(printf '%s' "$msg" | cut -c1-240)
  note_err "$label (rc=$rc): ${msg:-no output}"
  return 1
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
  BREW=$(sudo -u "$CONSOLE_USER" bash -lc 'command -v brew' 2>/dev/null || true)
  if [ -n "$BREW" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "DRY RUN — brew outdated (formulae + casks):"
      sudo -u "$CONSOLE_USER" bash -lc "$BREW update >/dev/null 2>&1; $BREW outdated; echo '-- casks --'; $BREW outdated --cask" || true
      BREW_UPDATES=$(sudo -u "$CONSOLE_USER" bash -lc "$BREW outdated | wc -l" 2>/dev/null | tr -d ' ' || echo 0)
      CASK_UPDATES=$(sudo -u "$CONSOLE_USER" bash -lc "$BREW outdated --cask | wc -l" 2>/dev/null | tr -d ' ' || echo 0)
    else
      brew_run "brew upgrade failed" "$BREW update && $BREW upgrade && $BREW cleanup"
      brew_run "brew cask upgrade failed" "$BREW upgrade --cask"
      BREW_UPDATES=1; CASK_UPDATES=1
      # adopt curated vendor-installed apps into brew so they actually get patched
      for pair in "${CASKS_TO_MANAGE[@]}"; do
        cask="${pair%%:*}"; app="${pair#*:}"
        [ -d "/Applications/$app" ] || continue          # present only — never install new software
        if brew_run "adopt $cask failed" "$BREW install --cask --adopt \"$cask\""; then
          CASKS_ADOPTED=$((CASKS_ADOPTED + 1))
        fi
      done
    fi
  fi
fi

DUR=$(( $(date +%s) - START ))
JSON=$(printf '{"timestamp":"%s","tool":"aegis","host":"%s","os_family":"macos","group":"%s","dry_run":%s,"apple_updates":%s,"brew_ran":%s,"cask_ran":%s,"casks_adopted":%s,"reboot_required":%s,"errors":"%s","duration_sec":%s,"status":"%s"}' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(jstr "$HOST")" "$(jstr "$GROUP")" \
  "$([ $DRY_RUN -eq 1 ] && echo true || echo false)" "$(num "$OS_UPDATES")" "$(num "$BREW_UPDATES")" "$(num "$CASK_UPDATES")" "$(num "$CASKS_ADOPTED")" \
  "$([ $REBOOT_REQ -eq 1 ] && echo true || echo false)" "$(jstr "$ERRORS")" "$(num "$DUR")" "$(jstr "$STATUS")")

echo "$JSON" >> "$LOG"; echo "$JSON"
