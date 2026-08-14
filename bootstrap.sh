#!/usr/bin/env bash
# Aegis bootstrap (Linux/macOS) — one-time installer. Run with sudo.
#
# Bolts Aegis onto an existing Wazuh agent: downloads the pinned engine into the
# agent's active-response/bin, flips the agent's remote-command master switch
# (wazuh_command.remote_commands — shipped default OFF), makes the box AR-ready.
# Reads NO client data — role/policy come from the Wazuh label at run time.
#
# One-liner (private repo -> export a token first):
#   export AEGIS_TOKEN=ghp_...; export AEGIS_REF=v0.1
#   curl -fsSL -H "Authorization: token $AEGIS_TOKEN" \
#     "https://raw.githubusercontent.com/veteranop/Aegis/$AEGIS_REF/bootstrap.sh" | sudo -E bash
set -euo pipefail

REPO="${AEGIS_REPO:-veteranop/Aegis}"
REF="${AEGIS_REF:-main}"                 # PIN a tag/commit in prod
TOKEN="${AEGIS_TOKEN:-}"
NO_RC="${AEGIS_NO_REMOTE_COMMANDS:-0}"
case "$(uname -s)" in Darwin) OSSEC="${OSSEC_DIR:-/Library/Ossec}" ;; *) OSSEC="${OSSEC_DIR:-/var/ossec}" ;; esac

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -d "$OSSEC" ] || { echo "Wazuh agent not found at $OSSEC - install/enroll it first; Aegis rides on it" >&2; exit 1; }

# engine lives in aegis.d/ — bin/aegis itself must stay free for the AR wrapper
# FILE (ossec.conf's <executable>aegis</executable> resolves to bin/aegis)
DEST="$OSSEC/active-response/bin/aegis.d"
mkdir -p "$DEST"
AUTH=(); [ -n "$TOKEN" ] && AUTH=(-H "Authorization: token $TOKEN")

case "$(uname -s)" in Darwin) PATCH="patch-mac.sh" ;; *) PATCH="patch-linux.sh" ;; esac
# relay-first artifact fetch: try the manager's Aegis relay first (the relay is
# installed ON the Wazuh manager, not hardcoded per-site), then fall back to
# GitHub raw. Clients that can't reach raw.githubusercontent.com (observed:
# Ascend Macs hang on every outbound curl) still bootstrap via the manager
# relay. BASE_URL order: AEGIS_BASE_URL env override (e.g. a site LAN relay) >
# the Wazuh manager this agent reports to (from its own ossec.conf) > localhost.
BASE_URL="${AEGIS_BASE_URL:-}"
if [ -z "$BASE_URL" ]; then
  _mgr=""
  [ -f "$OSSEC/etc/ossec.conf" ] && \
    _mgr=$(grep -oE '<address>[^<]+</address>' "$OSSEC/etc/ossec.conf" 2>/dev/null | head -1 | sed -E 's#</?address>##g' | tr -d ' ')
  BASE_URL="http://${_mgr:-127.0.0.1}:8008"
fi
GH_BASE="https://raw.githubusercontent.com/$REPO/$REF"
fetch() {  # $1 relpath, $2 outfile — relay first, GitHub fallback (auth if set)
  if curl -fsSL --max-time 20 "$BASE_URL/$1" -o "$2" 2>/dev/null; then return 0; fi
  curl -fsSL --max-time 25 ${AUTH[@]+"${AUTH[@]}"} "$GH_BASE/$1" -o "$2"
}
for f in aegis.sh roles.json "$PATCH" SHA256SUMS; do
  fetch "$f" "$DEST/$f" || { echo "fetch failed: $f" >&2; exit 1; }
done
chmod +x "$DEST/aegis.sh" "$DEST/$PATCH"

# verify checksums for the files we pulled
if command -v sha256sum >/dev/null 2>&1; then SHA=sha256sum; else SHA="shasum -a 256"; fi
while read -r want name; do
  [ -f "$DEST/$name" ] || continue
  have=$($SHA "$DEST/$name" | awk '{print $1}')
  [ "$have" = "$want" ] || { echo "checksum mismatch on $name - refusing to install" >&2; exit 1; }
done < <(grep -E "$(printf '%s|' aegis.sh roles.json "$PATCH" | sed 's/|$//')" "$DEST/SHA256SUMS" 2>/dev/null || true)

# migrate pre-v0.4 layout: bin/aegis used to be the engine DIR, which collided
# with the wrapper file below (only ever held our own re-downloadable files)
[ -d "$OSSEC/active-response/bin/aegis" ] && rm -rf "$OSSEC/active-response/bin/aegis"

# AR wrapper so the Wazuh manager can invoke the engine (AR runs an executable in bin/)
cat > "$OSSEC/active-response/bin/aegis" <<'WRAP'
#!/usr/bin/env bash
exec "$(dirname "$0")/aegis.d/aegis.sh" "$@"
WRAP
chmod +x "$OSSEC/active-response/bin/aegis"

# LIVE apply wrapper — separate AR command so dry-run stays the default trigger
cat > "$OSSEC/active-response/bin/aegis-apply" <<'WRAP'
#!/usr/bin/env bash
# LIVE Aegis run: actually patches, may reboot per role policy
exec "$(dirname "$0")/aegis.d/aegis.sh" --apply "$@"
WRAP
chmod +x "$OSSEC/active-response/bin/aegis-apply"

# reboot wrapper — scheduled-maintenance reboot AR (used by the patch cron).
# Delayed so the patch result line flushes to the manager before the box goes
# down; first stdout line is the execd handshake (see aegis.sh SIGPIPE note),
# then everything is redirected so the child can never die on a closed pipe.
cat > "$OSSEC/active-response/bin/aegis-reboot" <<'WRAP'
#!/usr/bin/env bash
echo "Aegis: reboot scheduled"
exec >> /var/log/aegis/aegis-reboot.log 2>&1 || true
sleep 5
shutdown -r +1 2>/dev/null || sudo -n shutdown -r +1 2>/dev/null || { echo "Aegis: reboot unavailable"; exit 1; }
echo "reboot scheduled $(date -u +%H:%M:%SZ)"
WRAP
chmod +x "$OSSEC/active-response/bin/aegis-reboot"

# self-update wrapper + script — lets the manager push engine updates fleet-wide via
# the `aegis-nix-update` AR command. Re-pulls the engine + re-runs bootstrap, no restart.
cat > "$OSSEC/active-response/bin/aegis-update" <<'WRAP'
#!/usr/bin/env bash
exec "$(dirname "$0")/aegis.d/aegis-update.sh" "$@"
WRAP
chmod +x "$OSSEC/active-response/bin/aegis-update"
cat > "$DEST/aegis-update.sh" <<'UPD'
#!/usr/bin/env bash
# Aegis self-update: re-pull the pinned engine from the ref-recorded channel +
# re-run bootstrap, tracking the repo/ref recorded at install (/etc/aegis/ref).
# Runs with AEGIS_NO_RESTART=1. BASE_URL comes from /etc/aegis/ref (recorded at
# install); falls back to GitHub raw when the relay is unreachable.
set -e
REPO=veteranop/Aegis; REF=main; TOKEN=; BASE_URL=
[ -f /etc/aegis/ref ] && . /etc/aegis/ref 2>/dev/null || true
AUTH=(); [ -n "${TOKEN:-}" ] && AUTH=(-H "Authorization: token $TOKEN")
( [ -n "${BASE_URL:-}" ] && curl -fsSL --max-time 20 "$BASE_URL/bootstrap.sh" 2>/dev/null \
    || curl -fsSL ${AUTH[@]+"${AUTH[@]}"} --max-time 25 "https://raw.githubusercontent.com/$REPO/$REF/bootstrap.sh" ) \
  | AEGIS_REPO="$REPO" AEGIS_REF="$REF" AEGIS_BASE_URL="${BASE_URL:-}" AEGIS_TOKEN="${TOKEN:-}" AEGIS_NO_RESTART=1 bash
UPD
chmod +x "$DEST/aegis-update.sh"

# flip the agent's remote-command master switch (wazuh_command.remote_commands; default OFF)
if [ "$NO_RC" != "1" ]; then
  LIO="$OSSEC/etc/local_internal_options.conf"
  touch "$LIO"
  for opt in "wazuh_command.remote_commands=1" "logcollector.remote_commands=1"; do
    key="${opt%%=*}"
    grep -q "^${key}=" "$LIO" 2>/dev/null || echo "$opt" >> "$LIO"
  done
fi

mkdir -p /var/log/aegis

# SSH ops-key provisioning (AEGIS_SSH_KEY=0 to skip): hosts get the public key
# (dedicated ops user + sshd enabled); the private key stays on the ops side.
# This is how the MSP reaches managed hosts without per-host admin chores.
if [ "${AEGIS_SSH_KEY:-1}" = "1" ]; then
  OPS_USER="${AEGIS_OPS_USER:-veteranop-ops}"
  OPS_KEY_URL="$BASE_URL/keys/aegis-ops.pub"
  case "$(uname -s)" in
    Darwin)
      id "$OPS_USER" 2>/dev/null || sysadminctl -addUser "$OPS_USER" -admin -password "$(openssl rand -base64 24 2>/dev/null || echo 'AegisBoot0!')" 2>/dev/null || true
      HOMEDIR="/Users/$OPS_USER"
      systemsetup -setremotelogin on >/dev/null 2>&1 || true
      ;;
    *)
      id "$OPS_USER" 2>/dev/null || useradd -m -s /bin/bash "$OPS_USER" 2>/dev/null || true
      command -v usermod >/dev/null 2>&1 && usermod -aG sudo "$OPS_USER" 2>/dev/null || true
      HOMEDIR="/home/$OPS_USER"
      systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || service ssh start 2>/dev/null || true
      ;;
  esac
  if [ -n "${HOMEDIR:-}" ]; then
    mkdir -p "$HOMEDIR/.ssh"
    if curl -fsSL --max-time 20 "$OPS_KEY_URL" 2>/dev/null | grep -q .; then
      curl -fsSL --max-time 20 "$OPS_KEY_URL" 2>/dev/null >> "$HOMEDIR/.ssh/authorized_keys"
    else
      fetch "keys/aegis-ops.pub" "$HOMEDIR/.ssh/aegis-ops.pub.tmp" 2>/dev/null
      [ -s "$HOMEDIR/.ssh/aegis-ops.pub.tmp" ] && cat "$HOMEDIR/.ssh/aegis-ops.pub.tmp" >> "$HOMEDIR/.ssh/authorized_keys"
      rm -f "$HOMEDIR/.ssh/aegis-ops.pub.tmp"
    fi
    sort -u -o "$HOMEDIR/.ssh/authorized_keys" "$HOMEDIR/.ssh/authorized_keys" 2>/dev/null || true
    chmod 700 "$HOMEDIR/.ssh"; chmod 600 "$HOMEDIR/.ssh/authorized_keys"
    chown -R "$OPS_USER" "$HOMEDIR/.ssh" 2>/dev/null || true
    echo "aegis: ssh ops key provisioned for $OPS_USER"
  fi
fi

# record the repo/ref this box tracks so aegis-update re-pulls the same channel
mkdir -p /etc/aegis
{ echo "REPO=$REPO"; echo "REF=$REF"; echo "BASE_URL=$BASE_URL"; [ -n "${TOKEN:-}" ] && echo "TOKEN=$TOKEN"; } > /etc/aegis/ref

# role picker -> live from the start. Engine resolves: Wazuh label (authoritative)
# > /etc/aegis/role (this file) > refuse. AEGIS_ROLE env pre-selects; the menu
# reads /dev/tty so it works under `curl | sudo bash`.
SEL="${AEGIS_ROLE:-}"
ROLE_NAMES=()   # (no mapfile: macOS ships bash 3.2)
while IFS= read -r _r; do [ -n "$_r" ] && ROLE_NAMES+=("$_r"); done \
  < <(python3 -c "import json;print('\n'.join(json.load(open('$DEST/roles.json'))))" 2>/dev/null)
if [ -z "$SEL" ] && [ "${#ROLE_NAMES[@]}" -gt 0 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
  {
    echo ""
    echo "Select this machine's Aegis role (the manager's aegis.role label always overrides):"
    i=1; for r in ${ROLE_NAMES[@]+"${ROLE_NAMES[@]}"}; do echo "  $i) $r"; i=$((i+1)); done
    echo "  0) skip - identify via Wazuh label only"
    printf "Role [0-%s]: " "${#ROLE_NAMES[@]}"
  } > /dev/tty
  read -r sel < /dev/tty || sel=""
  case "$sel" in
    ''|*[!0-9]*) : ;;
    *) [ "$sel" -ge 1 ] && [ "$sel" -le "${#ROLE_NAMES[@]}" ] && SEL="${ROLE_NAMES[$((sel-1))]}" ;;
  esac
fi
if [ -n "$SEL" ]; then
  printf '%s\n' ${ROLE_NAMES[@]+"${ROLE_NAMES[@]}"} | grep -qx "$SEL" || { echo "role '$SEL' not in roles.json" >&2; exit 1; }
  mkdir -p /etc/aegis && printf '%s\n' "$SEL" > /etc/aegis/role
  echo "Aegis role -> '$SEL' (local file; manager label overrides)"
fi

# restart the agent — skipped on self-update (AEGIS_NO_RESTART=1) so an AR-triggered
# update doesn't bounce the agent running it.
if [ "${AEGIS_NO_RESTART:-0}" != "1" ]; then
  if command -v systemctl >/dev/null 2>&1; then systemctl restart wazuh-agent 2>/dev/null || true
  else "$OSSEC/bin/wazuh-control" restart 2>/dev/null || "$OSSEC/bin/ossec-control" restart 2>/dev/null || true; fi
fi

echo "Aegis installed -> $DEST (ref: $REF). remote_commands: $([ "$NO_RC" = 1 ] && echo false || echo true)."
echo "Next (manager side): set the group's aegis.role label + add the aegis-app.log <localfile>."
