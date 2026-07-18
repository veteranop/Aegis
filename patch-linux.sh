#!/usr/bin/env bash
# Aegis — Linux patch runner. Detects apt or dnf/yum. Honors holds. Writes a
# JSON audit line the Wazuh agent ships. Never reboots unless --allow-reboot.
#
# Usage:
#   sudo ./patch-linux.sh [--dry-run] [--allow-reboot] [--group NAME] [--exclusions FILE]
set -uo pipefail

DRY_RUN=0; ALLOW_REBOOT=0; GROUP="personal"; EXCL_FILE=""
LOG_DIR="/var/log/aegis"; LOG="${LOG_DIR}/aegis-patch.log"
START=$(date +%s)

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --allow-reboot) ALLOW_REBOOT=1 ;;
    --group) GROUP="$2"; shift ;;
    --exclusions) EXCL_FILE="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac; shift
done

[ "$(id -u)" -eq 0 ] || { echo "Aegis: must run as root" >&2; exit 1; }
mkdir -p "$LOG_DIR"

HOST=$(hostname); STATUS="success"; ERRORS=""; UPDATED=0; REBOOT_REQ=0; REBOOT_DONE=0
note_err(){ STATUS="error"; ERRORS="${ERRORS}${ERRORS:+; }$1"; }

# exclusions (requires jq; optional). Format: {"<group>":{"apt":["pkg"],"dnf":["pkg"]}}
read_excl(){ # $1 = key (apt|dnf)
  [ -n "$EXCL_FILE" ] && [ -f "$EXCL_FILE" ] && command -v jq >/dev/null 2>&1 || return 0
  jq -r --arg g "$GROUP" --arg k "$1" '.[$g][$k][]? // empty' "$EXCL_FILE" 2>/dev/null
}

if command -v apt-get >/dev/null 2>&1; then
  MGR="apt"
  for p in $(read_excl apt); do apt-mark hold "$p" >/dev/null 2>&1; done
  if [ "$DRY_RUN" -eq 1 ]; then
    apt-get update -qq
    echo "DRY RUN — upgradable:"; apt-get -s upgrade | grep -E '^Inst ' || true
    UPDATED=$(apt-get -s upgrade | grep -c '^Inst ' || true)
  else
    apt-get update -qq || note_err "apt update failed"
    UPDATED=$(apt-get -s upgrade | grep -c '^Inst ' || echo 0)
    DEBIAN_FRONTEND=noninteractive apt-get -y upgrade || note_err "apt upgrade failed"
    apt-get -y autoremove >/dev/null 2>&1
  fi
  [ -f /var/run/reboot-required ] && REBOOT_REQ=1

elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  MGR=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
  EXARGS=""; for p in $(read_excl dnf); do EXARGS="$EXARGS --exclude=$p"; done
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "DRY RUN — check-update:"; $MGR $EXARGS check-update || true
    UPDATED=$($MGR $EXARGS -q check-update 2>/dev/null | grep -c . || echo 0)
  else
    UPDATED=$($MGR $EXARGS -q check-update 2>/dev/null | grep -c . || echo 0)
    $MGR -y $EXARGS upgrade || note_err "$MGR upgrade failed"
  fi
  command -v needs-restarting >/dev/null 2>&1 && { needs-restarting -r >/dev/null 2>&1 || REBOOT_REQ=1; }
else
  note_err "no supported package manager (apt/dnf/yum)"; MGR="unknown"
fi

DUR=$(( $(date +%s) - START ))
JSON=$(printf '{"timestamp":"%s","tool":"aegis","host":"%s","os_family":"linux","mgr":"%s","group":"%s","dry_run":%s,"pkgs_updated":%s,"reboot_required":%s,"reboot_performed":%s,"errors":"%s","duration_sec":%s,"status":"%s"}' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HOST" "${MGR:-unknown}" "$GROUP" \
  "$([ $DRY_RUN -eq 1 ] && echo true || echo false)" "${UPDATED:-0}" \
  "$([ $REBOOT_REQ -eq 1 ] && echo true || echo false)" \
  "$([ $REBOOT_DONE -eq 1 ] && echo true || echo false)" "$ERRORS" "$DUR" "$STATUS")

echo "$JSON" >> "$LOG"; echo "$JSON"

if [ "$REBOOT_REQ" -eq 1 ] && [ "$ALLOW_REBOOT" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
  echo "Aegis: rebooting (updates require it)"; systemctl reboot
fi
