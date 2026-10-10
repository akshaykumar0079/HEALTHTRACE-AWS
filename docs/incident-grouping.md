# Incident grouping, escalation and the Time Machine

## Grouping (explainable, no ML)
Every alert gets a **fingerprint** (kind + service/user/source key). An alert
with the fingerprint of an open incident is attached to it (deduplicated), never
a new incident. The incident view shows the fingerprint and the grouping reason
(`grouping` field).

| Concept | Meaning |
|---|---|
| Severity | Impact class (LOW..CRITICAL). Escalates, never silently drops while open. |
| Risk score | The detector's score; shown as "-" for rule-based kinds (`hipaa_*`, `auth_*`). |
| Risk trend | `rising`/`falling`/`steady`/`unknown` from the incident's recent risk values. |
| Evidence quality | How much supporting evidence is stored (count, sources); independent of severity. |

* **Cooldown / flood prevention** - repeated alerts on an open incident send no
  new notification; only a first HIGH/CRITICAL and each *escalation* notify.
  Tested in `test_email_flood.py`.
* **Reopen** - a matching alert within `reopen_window_minutes` of resolution
  reopens the incident (`reopen_count` increments); later it opens a new one.
  Operators can also reopen manually (`POST /api/incidents/{id}/reopen`).
* **Pinning** - a bookmark only; never changes severity, and retention skips pinned incidents.

## Time Machine
`GET /api/incidents/{id}/timeline?before_minutes=&after_minutes=` returns a
persisted, ordered timeline: window metrics (baseline vs observed), raw
synthetic evidence, alerts and incident lifecycle events, grouped into phases
(before / during / after). `.../timeline/{entry_id}` returns one entry with the
rule, threshold and reason. Replay in the UI is **read-only** and only moves a
cursor over already-stored data.

Missing or expired history is reported explicitly in `coverage` (for example
evidence removed by retention, or no metrics before the incident), never
silently filled in.
