#!/usr/bin/env python3
"""
Aegis "Fleet Patching" dashboard generator.

Emits an OpenSearch-Dashboards / Kibana-7.10-schema saved-objects .ndjson bundle
(visualizations + dashboard) that imports cleanly via the Saved Objects API or the
Dashboards UI (Stack Management -> Saved Objects -> Import).

Design notes (why it's built this way, not clicked together in the UI):
  * Reproducible + version-controlled: regenerate with `python build_ndjson.py`.
  * References the EXISTING `wazuh-alerts-*` index-pattern by id -- the bundle never
    ships its own index-pattern, so import can't clobber Wazuh's.
  * Aegis JSON fields decode under `data.*` (all keyword; aggregate directly, no
    `.keyword` suffix). `data.host` is the only field common to BOTH the engine log
    (aegis-app.log: data.role/source) and the patch log (aegis-patch.log:
    data.group/status). `rule.id` is the clean categorical for event-type splits.
  * "Hosts needing attention" filters on rule.groups:"error" (100103 + 100106 + 100109)
    NOT rule.id:100106 -- because the event that trips the 100109 frequency threshold is
    reported under 100109, so a single-rule filter undercounts errors by the escalations.

Verified against: OpenSearch Dashboards 2.19.5, index-pattern id `wazuh-alerts-*`.
"""
import json

INDEX_PATTERN_ID = "wazuh-alerts-*"
INDEX_REF_NAME = "kibanaSavedObjectMeta.searchSourceJSON.index"


def _index_ref():
    return [{"name": INDEX_REF_NAME, "type": "index-pattern", "id": INDEX_PATTERN_ID}]


def viz(obj_id, title, vis_state, query="", uses_index=True):
    """Build a visualization saved object. `query` is a DQL/KQL string filter."""
    search_source = {"query": {"query": query, "language": "kuery"}, "filter": []}
    refs = []
    if uses_index:
        search_source["indexRefName"] = INDEX_REF_NAME
        refs = _index_ref()
    attrs = {
        "title": title,
        "visState": json.dumps(vis_state, separators=(",", ":")),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(search_source, separators=(",", ":"))
        },
    }
    return {
        "id": obj_id,
        "type": "visualization",
        "attributes": attrs,
        "references": refs,
        "migrationVersion": {"visualization": "7.9.3"},
    }


# ---- visState builders -----------------------------------------------------

def markdown_state(md):
    return {"title": "Aegis Header", "type": "markdown", "aggs": [],
            "params": {"fontSize": 12, "openLinksInNewTab": True, "markdown": md}}


def histogram_state(title, split_field, split_size=10):
    return {
        "title": title, "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "timestamp", "useNormalizedOpenSearchInterval": True,
                        "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                        "extended_bounds": {}}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "group",
             "params": {"field": split_field, "orderBy": "1", "order": "desc",
                        "size": split_size, "otherBucket": False, "missingBucket": False}},
        ],
        "params": {
            "type": "histogram", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                              "show": True, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                           "show": True, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right",
            "times": [], "addTimeMarker": False, "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
        },
    }


def pie_state(title, field, size=8):
    return {
        "title": title, "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                        "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
    }


def table_state(title, field, size=20):
    return {
        "title": title, "type": "table",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                        "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
    }


def metric_state(title, label):
    return {
        "title": title, "type": "metric",
        "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                  "params": {"customLabel": label}}],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                              "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                        "subText": "", "fontSize": 48}}},
    }


# ---- objects ---------------------------------------------------------------

HEADER_MD = (
    "### \U0001F6E1️ Aegis — Fleet Patching\n"
    "**One patch process for every machine.** Live from `rule.groups: aegis`. "
    "Errors panel spans 100103/100106/100109 (a 100109 escalation reclassifies its "
    "trigger event off 100106, so single-rule counts under-report)."
)

OBJECTS = [
    viz("aegis-header", "Aegis — Header", markdown_state(HEADER_MD), uses_index=False),
    viz("aegis-events-timeline", "Aegis — Events Over Time",
        histogram_state("Aegis — Events Over Time", "rule.id", 10),
        query='rule.groups : "aegis"'),
    viz("aegis-escalations-metric", "Aegis — Active Escalations",
        metric_state("Aegis — Active Escalations", "Repeated-failure escalations (100109)"),
        query='rule.id : "100109"'),
    viz("aegis-role-coverage", "Aegis — Fleet by Role",
        pie_state("Aegis — Fleet by Role", "data.role", 8),
        query='rule.id : "100101"'),
    # NB: filter on "has data.status", NOT rule.groups:patch_run -- error/success events
    # reclassify to child rules (100106/100105) that drop the patch_run group, so a
    # patch_run filter would miss them. data.status is present on every patch-log alert.
    viz("aegis-patch-outcome", "Aegis — Patch Outcome",
        pie_state("Aegis — Patch Outcome", "data.status", 6),
        query='rule.groups : "aegis" and data.status : *'),
    viz("aegis-hosts-attention", "Aegis — Hosts Needing Attention",
        table_state("Aegis — Hosts Needing Attention", "agent.name", 25),
        query='rule.groups : "error"'),
]

# dashboard layout on the 48-col grid
PANELS = [
    ("aegis-header",            {"x": 0,  "y": 0,  "w": 48, "h": 4}),
    ("aegis-events-timeline",   {"x": 0,  "y": 4,  "w": 32, "h": 15}),
    ("aegis-escalations-metric",{"x": 32, "y": 4,  "w": 16, "h": 7}),
    ("aegis-role-coverage",     {"x": 32, "y": 11, "w": 16, "h": 8}),
    ("aegis-patch-outcome",     {"x": 0,  "y": 19, "w": 16, "h": 15}),
    ("aegis-hosts-attention",   {"x": 16, "y": 19, "w": 32, "h": 15}),
]


def build_dashboard():
    panels_json, refs = [], []
    for i, (viz_id, grid) in enumerate(PANELS):
        ref_name = f"panel_{i}"
        grid = dict(grid, i=str(i))
        panels_json.append({"version": "7.9.3", "gridData": grid, "panelIndex": str(i),
                            "embeddableConfig": {}, "panelRefName": ref_name})
        refs.append({"name": ref_name, "type": "visualization", "id": viz_id})
    search_source = {"query": {"query": "", "language": "kuery"}, "filter": []}
    attrs = {
        "title": "Aegis — Fleet Patching",
        "hits": 0,
        "description": "Fleet patch status, outcomes, and repeated-failure escalations from the Aegis engine.",
        "panelsJSON": json.dumps(panels_json, separators=(",", ":")),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}, separators=(",", ":")),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-7d",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source, separators=(",", ":"))},
    }
    return {"id": "aegis-fleet-patching", "type": "dashboard", "attributes": attrs,
            "references": refs, "migrationVersion": {"dashboard": "7.9.3"}}


def main():
    objs = list(OBJECTS) + [build_dashboard()]
    out = "aegis-fleet-patching.ndjson"
    with open(out, "w", encoding="utf-8") as f:
        for o in objs:
            f.write(json.dumps(o, ensure_ascii=False))
            f.write("\n")
    print(f"wrote {len(objs)} saved objects -> {out}")


if __name__ == "__main__":
    main()
