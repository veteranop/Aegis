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

# --- Apple software updates ---
AVAIL=$(softwareupdate -l 2>/dev/null || true)
OS_UPDATES=$(printf '%s\n' "$AVAIL" | grep -c -E '^\s*\* ' || echo 0)
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
      sudo -u "$CONSOLE_USER" bash -lc "$BREW update && $BREW upgrade && $BREW cleanup" || note_err "brew upgrade failed"
      sudo -u "$CONSOLE_USER" bash -lc "$BREW upgrade --cask" || note_err "brew cask upgrade failed"
      BREW_UPDATES=1; CASK_UPDATES=1
      # adopt curated vendor-installed apps into brew so they actually get patched
      for pair in "${CASKS_TO_MANAGE[@]}"; do
        cask="${pair%%:*}"; app="${pair#*:}"
        [ -d "/Applications/$app" ] || continue          # present only — never install new software
        if sudo -u "$CONSOLE_USER" bash -lc "$BREW install --cask --adopt \"$cask\""; then
          CASKS_ADOPTED=$((CASKS_ADOPTED + 1))
        else
          note_err "adopt $cask failed"
        fi
      done
    fi
  fi
fi

DUR=$(( $(date +%s) - START ))
JSON=$(printf '{"timestamp":"%s","tool":"aegis","host":"%s","os_family":"macos","group":"%s","dry_run":%s,"apple_updates":%s,"brew_ran":%s,"cask_ran":%s,"casks_adopted":%s,"reboot_required":%s,"errors":"%s","duration_sec":%s,"status":"%s"}' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HOST" "$GROUP" \
  "$([ $DRY_RUN -eq 1 ] && echo true || echo false)" "${OS_UPDATES:-0}" "${BREW_UPDATES:-0}" "${CASK_UPDATES:-0}" "${CASKS_ADOPTED:-0}" \
  "$([ $REBOOT_REQ -eq 1 ] && echo true || echo false)" "$ERRORS" "$DUR" "$STATUS")

echo "$JSON" >> "$LOG"; echo "$JSON"
