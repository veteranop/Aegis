#!/usr/bin/env bash
# Aegis server-setup — run ONCE on the Wazuh MANAGER (not an agent). Root required.
#
# Configures the manager side so bootstrapped agents can be driven:
#   - creates the generic ROLE groups (personal/workstation/clinical/server/mac/linux)
#   - each group's shared agent.conf gets the `aegis.role` label (identity) + a
#     <localfile> so the Aegis app-log is shipped + monitored in Wazuh
#   - adds the Active-Response commands (aegis-win / aegis-nix) to ossec.conf so the
#     manager can trigger patching (PUT /active-response)
#   - a commented scheduled-wodle template per group (opt-in)
#
# Idempotent. Backs up ossec.conf. Then assign agents to a role group and trigger.
#
# One-liner (ON THE MANAGER):
#   curl -fsSL https://raw.githubusercontent.com/veteranop/Aegis/main/server-setup.sh | sudo bash
set -euo pipefail

OSSEC="${OSSEC_DIR:-/var/ossec}"
CONF="$OSSEC/etc/ossec.conf"
SHARED="$OSSEC/etc/shared"
ROLES=(personal workstation clinical server mac linux)

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
# must be a MANAGER, not just an agent
if [ ! -x "$OSSEC/bin/wazuh-analysisd" ] && [ ! -x "$OSSEC/bin/ossec-analysisd" ]; then
  echo "This is not a Wazuh MANAGER ($OSSEC/bin/wazuh-analysisd not found). Run server-setup on the server." >&2
  exit 1
fi

# find the wazuh unix owner (wazuh: newer, ossec: older)
OWNER=wazuh; id wazuh >/dev/null 2>&1 || OWNER=ossec

echo "== backing up ossec.conf =="
cp -a "$CONF" "$CONF.aegis.bak.$(date +%Y%m%d%H%M%S)"

# --- 1. Active-Response commands (idempotent) ---
if ! grep -q "<name>aegis-win</name>" "$CONF"; then
  echo "== adding Active-Response commands to ossec.conf =="
  AR_BLOCK=$(cat <<'XML'

  <!-- Aegis (added by server-setup) -->
  <command>
    <name>aegis-win</name>
    <executable>aegis.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <command>
    <name>aegis-nix</name>
    <executable>aegis</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>aegis-win</command>
    <location>local</location>
  </active-response>
  <active-response>
    <disabled>no</disabled>
    <command>aegis-nix</command>
    <location>local</location>
  </active-response>
XML
)
  # insert before the last </ossec_config>
  python3 - "$CONF" "$AR_BLOCK" <<'PY'
import sys
conf, block = sys.argv[1], sys.argv[2]
s = open(conf, encoding="utf-8").read()
idx = s.rfind("</ossec_config>")
s = s[:idx] + block + "\n" + s[idx:]
open(conf, "w", encoding="utf-8").write(s)
PY
else
  echo "== AR commands already present, skipping =="
fi

# --- 1b. LIVE apply commands (separate trigger: dry-run stays the default) ---
if ! grep -q "<name>aegis-win-apply</name>" "$CONF"; then
  echo "== adding Aegis APPLY commands to ossec.conf =="
  AR_BLOCK=$(cat <<'XML'

  <!-- Aegis LIVE apply (added by server-setup) — actually patches; may reboot per role policy -->
  <command>
    <name>aegis-win-apply</name>
    <executable>aegis-apply.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <command>
    <name>aegis-nix-apply</name>
    <executable>aegis-apply</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>aegis-win-apply</command>
    <location>local</location>
  </active-response>
  <active-response>
    <disabled>no</disabled>
    <command>aegis-nix-apply</command>
    <location>local</location>
  </active-response>
XML
)
  python3 - "$CONF" "$AR_BLOCK" <<'PY'
import sys
conf, block = sys.argv[1], sys.argv[2]
s = open(conf, encoding="utf-8").read()
idx = s.rfind("</ossec_config>")
s = s[:idx] + block + "\n" + s[idx:]
open(conf, "w", encoding="utf-8").write(s)
PY
else
  echo "== Aegis APPLY commands already present, skipping =="
fi

# --- 2. role groups + shared agent.conf (label + app-log localfile) ---
for role in "${ROLES[@]}"; do
  gdir="$SHARED/$role"; ac="$gdir/agent.conf"
  mkdir -p "$gdir"
  if [ ! -f "$ac" ] || ! grep -q "aegis.role" "$ac"; then
    echo "== group '$role': writing agent.conf (label + app-log) =="
    cat > "$ac" <<XML
<agent_config>
  <labels>
    <label key="aegis.role">$role</label>
  </labels>

  <!-- ship the Aegis app-log to Wazuh (Windows) -->
  <localfile>
    <location>C:\\ProgramData\\Aegis\\aegis-app.log</location>
    <log_format>json</log_format>
  </localfile>
  <!-- ship the Aegis app-log to Wazuh (Linux/macOS) -->
  <localfile>
    <location>/var/log/aegis/aegis-app.log</location>
    <log_format>json</log_format>
  </localfile>

  <!-- OPTIONAL scheduled patching (uncomment + set command path/interval to enable):
  <wodle name="command">
    <disabled>no</disabled>
    <tag>aegis</tag>
    <command>PATH-TO-aegis-wrapper</command>
    <interval>7d</interval>
    <run_on_start>no</run_on_start>
    <timeout>0</timeout>
  </wodle>
  -->
</agent_config>
XML
  else
    echo "== group '$role' already configured, skipping =="
  fi
done
chown -R "$OWNER:$OWNER" "$SHARED" 2>/dev/null || true

# --- 3. validate + restart the manager ---
echo "== validating config =="
if "$OSSEC/bin/wazuh-analysisd" -t 2>/dev/null || "$OSSEC/bin/ossec-analysisd" -t 2>/dev/null; then
  echo "== restarting manager =="
  systemctl restart wazuh-manager 2>/dev/null || "$OSSEC/bin/wazuh-control" restart
else
  echo "!! config test FAILED — NOT restarting. Restore from $CONF.aegis.bak.* and review." >&2
  exit 1
fi

cat <<DONE

Aegis manager setup complete.
  Role groups ready: ${ROLES[*]}
Next:
  1. Bootstrap each agent (one-liner from the README) — it enables remote_commands.
  2. Assign each agent to its role group (dashboard, or: /var/ossec/bin/agent_groups -a -i <id> -g <role>).
  3. Trigger a run:  curl -k -X PUT "https://127.0.0.1:55000/active-response?agents_list=<id>" \\
       -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \\
       -d '{"command":"aegis-win"}'   # or aegis-nix
DONE
