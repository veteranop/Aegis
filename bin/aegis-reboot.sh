#!/bin/bash
# aegis-reboot - reboot ONLY when the box actually needs one.
#
# Fired by aegis-patch-all.sh --reboot as the Active-Response command
# aegis-reboot-nix0 (macOS/Linux) or aegis-reboot-win0 (Windows).
#
# v2 2026-10-28 (ticket M2629504): DEBT-GATED. v1 rebooted unconditionally, which
# meant a Mac whose role policy is reboot:never could still be forced down, and a
# box with no pending work churned every night. Now:
#     aegis-reboot           -> reboot if a restart is actually needed, else no-op
#     aegis-reboot --check   -> report the decision only, never reboots
# Every run appends a JSON line to /var/log/aegis/aegis-app.log, which the Wazuh
# agent already ships (tool=aegis -> rule 100100), so the decision is auditable.
LOG=/var/log/aegis/aegis-app.log
# SIGPIPE ordering (aegis-ops 5n): the FIRST stdout write is the execd handshake,
# then everything is redirected, so the child can never die writing to a closed
# pipe before it has done its work.
echo "Aegis: reboot wrapper v2 (debt-gated)"
mkdir -p /var/log/aegis 2>/dev/null || true
exec >> /var/log/aegis/aegis-reboot.log 2>&1 || true
MODE="${1:-reboot}"
OSF=linux
[ "$(uname -s)" = "Darwin" ] && OSF=macos

emit() {
  printf '{"timestamp":"%s","tool":"aegis","app":"reboot","host":"%s","os_family":"%s","wrapper":"v2-debt-gated","reboot_needed":%s,"reboot_reason":"%s","reboot_action":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname -s 2>/dev/null || hostname)" \
    "$OSF" "$1" "$2" "$3" >> "$LOG" 2>/dev/null || true
}

NEEDED=false
REASON=none

if [ "$OSF" = "macos" ]; then
  # Staged updates waiting for a restart are the strongest signal.
  if ls /Library/Updates/*.pkg >/dev/null 2>&1 || ls /Library/Updates/*.dist >/dev/null 2>&1; then
    NEEDED=true
    REASON=staged-updates
  else
    TMPO=$(mktemp /tmp/aegis-su.XXXXXX 2>/dev/null || echo "/tmp/aegis-su.$$")
    # Time-box softwareupdate: a wedged softwareupdated must not hang execd.
    if command -v perl >/dev/null 2>&1; then
      perl -e 'alarm 120; exec @ARGV' softwareupdate -l >"$TMPO" 2>&1 || true
    else
      softwareupdate -l >"$TMPO" 2>&1 || true
    fi
    if grep -qiE 'restart|shut down' "$TMPO" 2>/dev/null; then
      NEEDED=true
      REASON=update-requires-restart
    fi
    rm -f "$TMPO"
  fi
else
  if [ -f /var/run/reboot-required ]; then
    NEEDED=true
    REASON=reboot-required
  fi
fi

if [ "$MODE" = "--check" ]; then
  emit "$NEEDED" "$REASON" check
  echo "Aegis reboot: needed=$NEEDED reason=$REASON (check only, no action)"
  exit 0
fi

if [ "$NEEDED" = "true" ]; then
  # Schedule the restart FIRST, then log: nothing may kill this child before the
  # shutdown is queued.
  if shutdown -r +1 2>/dev/null || sudo -n shutdown -r +1 2>/dev/null; then
    emit true "$REASON" rebooting
    echo "Aegis reboot: needed ($REASON) - restarting in 1 minute"
    exit 0
  fi
  emit true "$REASON" reboot-failed
  echo "Aegis reboot: needed ($REASON) - shutdown FAILED"
  exit 1
fi

emit false "$REASON" skipped-no-debt
echo "Aegis reboot: not needed ($REASON) - skipping (debt-gated)"
exit 0
