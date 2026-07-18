# Aegis — Fleet Patching dashboard

A ready-to-import Wazuh Dashboards (OpenSearch Dashboards) bundle that visualizes the
Aegis patch engine: fleet activity over time, patch outcomes, per-role coverage, and
repeated-failure escalations.

Built as **dashboard-as-code** — a committed `.ndjson` you regenerate from a script,
not a one-off you click together in the UI (which would live only in one browser/tenant).

## Files
| File | What it is |
|---|---|
| `aegis-fleet-patching.ndjson` | The saved-objects bundle (6 visualizations + 1 dashboard). Import this. |
| `build_ndjson.py` | Generator for the `.ndjson` — edit panels here, then `python build_ndjson.py`. |
| `install-dashboards.sh` | Installs the bundle via the indexer admin cert (no Dashboards password needed). |

## Panels
- **Events Over Time** — stacked bars by `rule.id` (filter `rule.groups:aegis`).
- **Active Escalations** — count of `rule.id:100109` (repeated-failure correlation).
- **Fleet by Role** — donut of `data.role` from dispatch events (`rule.id:100101`).
- **Patch Outcome** — donut of `data.status` (success/error) over patch-log events
  (filter `rule.groups:aegis and data.status:*` — not `rule.groups:patch_run`, since
  error/success events reclassify to child rules that drop the `patch_run` group).
- **Hosts Needing Attention** — table of `agent.name` filtered on `rule.groups:"error"`
  (spans 100103 + 100106 + 100109 — a single `rule.id:100106` filter under-counts, because
  the event that trips the 100109 frequency threshold is reported under 100109, not 100106).
- **Header** — Markdown title panel.

The bundle **references** the existing `wazuh-alerts-*` index-pattern by id; it never ships
its own, so importing can't clobber Wazuh's.

## Install

### Option A — script (headless, idempotent)
Run on the Wazuh manager/indexer host (needs read access to the indexer admin cert):
```bash
./install-dashboards.sh            # uses ./aegis-fleet-patching.ndjson
```
Writes the saved objects straight into `.kibana` via the admin certificate (superadmin,
bypasses OpenSearch system-index protection). Re-running overwrites in place.
Env overrides: `AEGIS_INDEXER`, `AEGIS_ADMIN_CERT`, `AEGIS_ADMIN_KEY`, `AEGIS_KIBANA_INDEX`.

### Option B — UI (no shell)
Dashboards → **Stack Management → Saved Objects → Import** → pick
`aegis-fleet-patching.ndjson` → *Overwrite existing*. Then open
**Dashboards → "Aegis — Fleet Patching."**

## Regenerate
```bash
python build_ndjson.py     # rewrites aegis-fleet-patching.ndjson
```
Verified against OpenSearch Dashboards **2.19.5**. Saved objects are stamped
`migrationVersion 7.9.3` (OSD 2.19's "last known" schema version — stamping 7.10.0 makes
`_import` reject the bundle as "a more recent version").

## ⚠️ Data requirement — patch-run alerts must reach the indexer
The panels are only as good as the data. Aegis alerts must **index without mapping
conflicts**. Wazuh reserves several `data.*` fields as objects — notably **`data.os`**
(`data.os.name`, `data.os.version`, …). A patch-log field named `os` with a plain string
value collides with that object mapping and the indexer **rejects the whole document**
(`mapper_parsing_exception`), so patch/error/escalation alerts silently never appear here
(only dispatch alerts, which carry no `os`, would show). Keep Aegis patch-log field names
clear of reserved Wazuh objects (Aegis emits `os_family`, not `os`).
