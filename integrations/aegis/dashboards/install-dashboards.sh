#!/usr/bin/env bash
# install-dashboards.sh -- install the Aegis "Fleet Patching" dashboard into Wazuh.
#
# Writes the saved objects straight into the .kibana index using the indexer ADMIN
# CERTIFICATE (superadmin, bypasses OpenSearch system-index protection) -- so it needs
# no Dashboards password and runs fine from a root-owned server-setup.sh. Idempotent:
# the saved objects use fixed ids, so re-running overwrites them in place.
#
# Manual alternative (no shell): Dashboards -> Stack Management -> Saved Objects ->
# Import -> aegis-fleet-patching.ndjson (overwrite). Same result, done as a logged-in user.
#
# Env overrides: AEGIS_INDEXER, AEGIS_ADMIN_CERT, AEGIS_ADMIN_KEY, AEGIS_KIBANA_INDEX.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NDJSON="${1:-$HERE/aegis-fleet-patching.ndjson}"
INDEXER="${AEGIS_INDEXER:-https://127.0.0.1:9200}"
CERT="${AEGIS_ADMIN_CERT:-/etc/wazuh-indexer/certs/admin.pem}"
KEY="${AEGIS_ADMIN_KEY:-/etc/wazuh-indexer/certs/admin-key.pem}"
KIBANA_INDEX="${AEGIS_KIBANA_INDEX:-.kibana}"

[ -f "$NDJSON" ] || { echo "!! ndjson not found: $NDJSON" >&2; exit 1; }
[ -f "$CERT" ] && [ -f "$KEY" ] || {
  echo "!! admin cert/key not found ($CERT / $KEY)." >&2
  echo "   Set AEGIS_ADMIN_CERT/AEGIS_ADMIN_KEY, or import $NDJSON via the Dashboards UI." >&2
  exit 1; }

echo "== building .kibana bulk payload from $(basename "$NDJSON") =="
BULK="$(python3 - "$NDJSON" "$KIBANA_INDEX" <<'PY'
import sys, json, datetime
ndjson, index = sys.argv[1], sys.argv[2]
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
lines = []
for raw in open(ndjson, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    o = json.loads(raw)
    t = o["type"]
    src = {t: o["attributes"], "type": t,
           "references": o.get("references", []),
           "migrationVersion": o.get("migrationVersion", {}),
           "updated_at": now}
    lines.append(json.dumps({"index": {"_index": index, "_id": "%s:%s" % (t, o["id"])}}))
    lines.append(json.dumps(src))
sys.stdout.write("\n".join(lines) + "\n")
PY
)"

echo "== writing saved objects to $KIBANA_INDEX on $INDEXER =="
# NOTE: printf '%s\n' -- the _bulk API requires the body to end in a newline, and the
# $(...) that captured $BULK stripped the trailing one.
RESP="$(printf '%s\n' "$BULK" | curl -sk --cert "$CERT" --key "$KEY" \
  -X POST "$INDEXER/$KIBANA_INDEX/_bulk?refresh=true" \
  -H 'Content-Type: application/x-ndjson' --data-binary @- )"

printf '%s' "$RESP" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if d.get("error"):                       # top-level request failure
    sys.exit("!! bulk request failed: %s" % json.dumps(d["error"])[:200])
items = d.get("items", [])
if d.get("errors"):                      # per-item failures
    for it in items:
        r = it.get("index", {})
        if r.get("error"):
            print("  ERROR", r.get("_id"), r["error"].get("type"), str(r["error"].get("reason",""))[:120])
    sys.exit("!! bulk reported item errors")
if not items:
    sys.exit("!! bulk wrote 0 objects (empty payload?)")
print("   installed %d saved objects OK" % len(items))
'
echo "== done. Open Dashboards -> Dashboards -> \"Aegis - Fleet Patching\" =="
