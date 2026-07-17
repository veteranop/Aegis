#!/usr/bin/env bash
# Aegis engine (Linux/macOS) — the "bolt-on Wazuh app".
# Reads this machine's Wazuh agent label `aegis.role` -> role policy (roles.json)
# -> runs patch-linux.sh (apt/dnf) or patch-mac.sh (softwareupdate/brew). Client-
# agnostic: no client data here. Optional `aegis.pin` label = per-machine LOB pins.
# DRY RUN unless --apply. Logs a JSON line to /var/log/aegis/aegis-app.log for Wazuh.
#
# Usage: sudo ./aegis.sh [--apply] [--role NAME]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROLES="$HERE/roles.json"
OSSEC="${OSSEC_DIR:-/var/ossec}"
LOGDIR="/var/log/aegis"
APPLY=0; ROLE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --role) ROLE="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac; shift
done

get_label() {  # $1 = label key
  for f in "$OSSEC/etc/ossec.conf" "$OSSEC/etc/shared/merged.mg" "$OSSEC/etc/shared/agent.conf"; do
    [ -f "$f" ] || continue
    v=$(grep -oE "<label key=\"$1\"[^>]*>[^<]+</label>" "$f" 2>/dev/null | sed -E 's/.*>([^<]+)<.*/\1/' | head -1)
    [ -n "$v" ] && { echo "$v"; return 0; }
  done
  return 0
}

[ -z "$ROLE" ] && ROLE="$(get_label aegis.role)"
[ -n "$ROLE" ] || { echo "Aegis: no 'aegis.role' Wazuh label - refusing to patch blind" >&2; exit 1; }

# policy from roles.json (python3 for portable JSON parse)
REBOOT=$(python3 -c "import json,sys;d=json.load(open('$ROLES'));r=d.get('$ROLE');print('' if r is None else r.get('reboot',''))" 2>/dev/null || echo "")
[ -n "$REBOOT" ] || { echo "Aegis: role '$ROLE' not in roles.json" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) PATCH="$HERE/patch-mac.sh" ;;
  *)      PATCH="$HERE/patch-linux.sh" ;;
esac

ARGS=(--group "$ROLE")
[ "$APPLY" -eq 0 ] && ARGS+=(--dry-run)
[ "$REBOOT" = "auto" ] && [ "$APPLY" -eq 1 ] && ARGS+=(--allow-reboot)

echo "Aegis: role=$ROLE | reboot=$REBOOT | os=$(uname -s) | apply=$APPLY"
mkdir -p "$LOGDIR" 2>/dev/null || true
printf '{"timestamp":"%s","tool":"aegis","app":"engine","host":"%s","role":"%s","reboot":"%s","apply":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname)" "$ROLE" "$REBOOT" \
  "$([ $APPLY -eq 1 ] && echo true || echo false)" >> "$LOGDIR/aegis-app.log" 2>/dev/null || true

exec bash "$PATCH" "${ARGS[@]}"
