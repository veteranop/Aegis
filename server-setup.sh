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

# --- 1c. SELF-UPDATE commands — lets the manager push engine updates fleet-wide.
# The agent re-pulls the pinned engine from GitHub + re-runs bootstrap (no restart). ---
if ! grep -q "<name>aegis-win-update</name>" "$CONF"; then
  echo "== adding Aegis SELF-UPDATE commands to ossec.conf =="
  AR_BLOCK=$(cat <<'XML'

  <!-- Aegis self-update (added by server-setup) — re-pulls the engine + re-runs bootstrap -->
  <command>
    <name>aegis-win-update</name>
    <executable>aegis-update.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <command>
    <name>aegis-nix-update</name>
    <executable>aegis-update</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>aegis-win-update</command>
    <location>local</location>
  </active-response>
  <active-response>
    <disabled>no</disabled>
    <command>aegis-nix-update</command>
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
  echo "== Aegis SELF-UPDATE commands already present, skipping =="
fi

# --- 2. role groups + shared agent.conf (label + app-log/patch-log localfiles) ---
# Regenerated every run (fully generated content, no manual edits expected) so that
# adding a new localfile block here also lands on groups that were already configured
# by an older version of this script — only rewritten if content actually changed.
for role in "${ROLES[@]}"; do
  gdir="$SHARED/$role"; ac="$gdir/agent.conf"
  mkdir -p "$gdir"
  new_ac=$(mktemp)
  cat > "$new_ac" <<XML
<agent_config>
  <labels>
    <label key="aegis.role">$role</label>
  </labels>

  <!-- ship the Aegis engine (identity/dispatch) log to Wazuh -->
  <localfile>
    <location>C:\\ProgramData\\Aegis\\aegis-app.log</location>
    <log_format>json</log_format>
  </localfile>
  <localfile>
    <location>/var/log/aegis/aegis-app.log</location>
    <log_format>json</log_format>
  </localfile>

  <!-- ship the Aegis patch-run (results: apps/OS updated, errors, reboot) log to Wazuh -->
  <localfile>
    <location>C:\\ProgramData\\Aegis\\aegis-patch.log</location>
    <log_format>json</log_format>
  </localfile>
  <localfile>
    <location>/var/log/aegis/aegis-patch.log</location>
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
  if [ ! -f "$ac" ] || ! cmp -s "$new_ac" "$ac"; then
    echo "== group '$role': writing agent.conf (label + app-log + patch-log) =="
    mv "$new_ac" "$ac"
  else
    echo "== group '$role' already up to date, skipping =="
    rm -f "$new_ac"
  fi
done
chown -R "$OWNER:$OWNER" "$SHARED" 2>/dev/null || true

# --- 3. local rules: turn the app-log/patch-log JSON into Wazuh alerts ---
# No custom decoder needed: <log_format>json</log_format> on the localfile already gets
# Wazuh's built-in JSON auto-decode (decoded_as json, top-level keys under data.*).
# Rules are regenerated every run (fully generated, no manual edits expected) and only
# rewritten if content changed. Picked up automatically via the default etc/rules rule_dir.
RULES_FILE="$OSSEC/etc/rules/aegis_rules.xml"
new_rules=$(mktemp)
cat > "$new_rules" <<'XML'
<!--
  Aegis rules — turns aegis-app.log (engine identity/dispatch) and aegis-patch.log
  (patch-run results) JSON lines into Wazuh alerts. Auto-generated by server-setup.sh —
  do not hand-edit, it will be overwritten on the next run.
  Groups: aegis, patching, compliance. HIPAA §164.308(a)(5) (log + monitor) evidence.
-->
<group name="aegis,patching,compliance,">

  <!-- parent: any Aegis JSON line -->
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="tool">^aegis$</field>
    <description>Aegis: event on $(host)</description>
  </rule>

  <!-- engine (aegis-app.log): role resolution / dispatch -->
  <rule id="100101" level="3">
    <if_sid>100100</if_sid>
    <field name="app">^engine$</field>
    <description>Aegis: engine dispatch on $(host) - role=$(role) source=$(source)</description>
    <group>dispatch,</group>
  </rule>

  <rule id="100102" level="5">
    <if_sid>100101</if_sid>
    <field name="source">^local-file$</field>
    <description>Aegis: role resolved from LOCAL FILE (not centrally labeled) on $(host) - role=$(role)</description>
    <group>compliance,</group>
  </rule>

  <rule id="100103" level="10">
    <if_sid>100101</if_sid>
    <status>^error$</status>
    <description>Aegis: engine ERROR on $(host) - $(note)</description>
    <group>error,</group>
  </rule>

  <!-- patch runner (aegis-patch.log): actual apply/dry-run results.
       "status" is a Wazuh-reserved static field - must use the dedicated <status> tag,
       not <field name="status">, or the ruleset fails to load ("Field 'status' is static").
       <field> matching is OSMatch (literal/anchored), NOT full regex - "." and "+" are taken
       literally, so a "match anything" gate needs type="pcre2" to get real wildcard support.
       The patch log emits "os_family" (windows/linux/macos), NOT "os": Wazuh reserves data.os
       as an OBJECT (data.os.name, ...), so a plain-string data.os makes the indexer reject the
       WHOLE alert (mapper_parsing_exception) and no patch/error/escalation alert ever indexes. -->
  <rule id="100104" level="3">
    <if_sid>100100</if_sid>
    <field name="group" type="pcre2">.+</field>
    <description>Aegis: patch run completed on $(host) - group=$(group) os=$(os_family) status=$(status)</description>
    <group>patch_run,</group>
  </rule>

  <rule id="100105" level="5">
    <if_sid>100104</if_sid>
    <status>^success$</status>
    <field name="dry_run">^false$</field>
    <description>Aegis: patch successfully applied on $(host) - group=$(group) os=$(os_family)</description>
    <group>success,</group>
  </rule>

  <rule id="100106" level="10">
    <if_sid>100104</if_sid>
    <status>^error$</status>
    <description>Aegis: patch run ERROR on $(host) - group=$(group) os=$(os_family) (see full log for detail)</description>
    <group>error,</group>
  </rule>

  <rule id="100107" level="7">
    <if_sid>100104</if_sid>
    <field name="reboot_required">^true$</field>
    <description>Aegis: reboot required after patching on $(host) - group=$(group)</description>
    <group>reboot,</group>
  </rule>

  <rule id="100108" level="6">
    <if_sid>100104</if_sid>
    <field name="reboot_performed">^true$</field>
    <description>Aegis: reboot TRIGGERED after patching on $(host)</description>
    <group>reboot,</group>
  </rule>

  <!-- repeated failures from the same host = escalate -->
  <rule id="100109" level="12" frequency="3" timeframe="3600">
    <if_matched_sid>100106</if_matched_sid>
    <same_field>host</same_field>
    <description>Aegis: multiple patch errors from $(host) in the last hour - investigate</description>
    <group>error,multiple_failures,</group>
  </rule>

</group>
XML
if [ ! -f "$RULES_FILE" ] || ! cmp -s "$new_rules" "$RULES_FILE"; then
  echo "== writing Aegis local rules =="
  mv "$new_rules" "$RULES_FILE"
  chown "$OWNER:$OWNER" "$RULES_FILE" 2>/dev/null || true
  chmod 660 "$RULES_FILE" 2>/dev/null || true
else
  echo "== Aegis local rules already up to date, skipping =="
  rm -f "$new_rules"
fi

# --- 4. validate + restart the manager ---
echo "== validating config =="
if "$OSSEC/bin/wazuh-analysisd" -t 2>/dev/null || "$OSSEC/bin/ossec-analysisd" -t 2>/dev/null; then
  echo "== restarting manager =="
  systemctl restart wazuh-manager 2>/dev/null || "$OSSEC/bin/wazuh-control" restart
else
  echo "!! config test FAILED — NOT restarting. Restore from $CONF.aegis.bak.* and review." >&2
  exit 1
fi

# --- 5. Fleet Patching dashboard (optional, non-fatal) ---
# Installs the saved-objects bundle into Wazuh Dashboards via the indexer admin cert
# (no Dashboards password needed). Skipped cleanly if the bundle or cert isn't present;
# a failure here never blocks manager setup — import the .ndjson from the UI instead.
DASH_DIR="$(dirname "$0")/integrations/aegis/dashboards"
if [ -f "$DASH_DIR/install-dashboards.sh" ] && [ -f "$DASH_DIR/aegis-fleet-patching.ndjson" ]; then
  echo "== installing Fleet Patching dashboard =="
  if ! bash "$DASH_DIR/install-dashboards.sh" "$DASH_DIR/aegis-fleet-patching.ndjson"; then
    echo "!! dashboard install failed (non-fatal) — import $DASH_DIR/aegis-fleet-patching.ndjson via Dashboards UI." >&2
  fi
else
  echo "== (no dashboard bundle beside server-setup.sh; skipping dashboard install) =="
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
