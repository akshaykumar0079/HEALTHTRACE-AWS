# Correlation

Events from different sources are normalised to `NormalizedEvent` (time,
source, actor, request_id, host, resource, outcome) and joined by **rules that
require a shared key** - never by time alone.

| Rule | Shared key | Window |
|---|---|---|
| failed_then_successful_login | actor, ordered | 600 s |
| login_then_record_access | actor, ordered | 900 s |
| same_request | request_id | 120 s |
| app_error_on_host | host | 60 s |
| record_in_app_and_database | exact resource | 30 s |

* Masked patient ids (`P-****56`) are never join keys.
* Order-independent input; group ids are idempotent.
* Late events are flagged; events missing a rule's key are reported as skipped.
* The server and DB-audit adapters accept **synthetic formats only**. No real
  system integration exists. `GET /api/correlation/rules|demo`,
  `POST /api/correlation/analyze`, `GET /api/incidents/{id}/correlation`.
