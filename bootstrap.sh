#!/usr/bin/env bash
# Aegis bootstrap (Linux/macOS) — one-time installer. Run with sudo.
#
# Bolts Aegis onto an existing Wazuh agent: downloads the pinned engine into the
# agent's active-response/bin, enables remote_commands, makes the box AR-ready.
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

DEST="$OSSEC/active-response/bin/aegis"
mkdir -p "$DEST"
AUTH=(); [ -n "$TOKEN" ] && AUTH=(-H "Authorization: token $TOKEN")

case "$(uname -s)" in Darwin) PATCH="patch-mac.sh" ;; *) PATCH="patch-linux.sh" ;; esac
for f in aegis.sh roles.json "$PATCH" SHA256SUMS; do
  curl -fsSL "${AUTH[@]}" "https://raw.githubusercontent.com/$REPO/$REF/$f" -o "$DEST/$f"
done
chmod +x "$DEST/aegis.sh" "$DEST/$PATCH"

# verify checksums for the files we pulled
if command -v sha256sum >/dev/null 2>&1; then SHA=sha256sum; else SHA="shasum -a 256"; fi
while read -r want name; do
  [ -f "$DEST/$name" ] || continue
  have=$($SHA "$DEST/$name" | awk '{print $1}')
  [ "$have" = "$want" ] || { echo "checksum mismatch on $name - refusing to install" >&2; exit 1; }
done < <(grep -E "$(printf '%s|' aegis.sh roles.json "$PATCH" | sed 's/|$//')" "$DEST/SHA256SUMS" 2>/dev/null || true)

# AR wrapper so the Wazuh manager can invoke the engine (AR runs an executable in bin/)
cat > "$OSSEC/active-response/bin/aegis" <<'WRAP'
#!/usr/bin/env bash
exec "$(dirname "$0")/aegis/aegis.sh" "$@"
WRAP
chmod +x "$OSSEC/active-response/bin/aegis"

# enable remote_commands (the accepted-risk gate)
if [ "$NO_RC" != "1" ]; then
  LIO="$OSSEC/etc/local_internal_options.conf"
  touch "$LIO"
  for opt in "wazuh_command.remote_commands=1" "logcollector.remote_commands=1"; do
    key="${opt%%=*}"
    grep -q "^${key}=" "$LIO" 2>/dev/null || echo "$opt" >> "$LIO"
  done
fi

mkdir -p /var/log/aegis
# restart the agent
if command -v systemctl >/dev/null 2>&1; then systemctl restart wazuh-agent 2>/dev/null || true
else "$OSSEC/bin/wazuh-control" restart 2>/dev/null || "$OSSEC/bin/ossec-control" restart 2>/dev/null || true; fi

echo "Aegis installed -> $DEST (ref: $REF). remote_commands: $([ "$NO_RC" = 1 ] && echo false || echo true)."
echo "Next (manager side): set the group's aegis.role label + add the aegis-app.log <localfile>."
