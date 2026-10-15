# Canonical event schema (configured ingestion)

A configured source (see [ingestion.md](ingestion.md)) turns each JSON line into one of
three canonical events through an explicit mapping. Anything that cannot be mapped is
rejected with a [reason code](ingestion.md#rejection-reason-codes-stable); nothing is guessed.
All examples are synthetic.

## Fields by kind

`R` = required (mapped from the log or given a default), `O` = optional. Identifier fields
are replaced by keyed pseudonyms before the event object exists.

| Field | auth | audit | app | Canonical type / allowed values | Notes |
|---|---|---|---|---|---|
| `ts` | R | R | R | aware UTC datetime | must be **mapped from the log**; normalized (see Timestamps) |
| `event_id` | O | O | O | string | not stored raw; keyed digest used for de-duplication. Strongly recommended |
| `user_id` | R | R | - | string -> `U-<12 hex>` | must be mapped from the log |
| `outcome` | R | - | - | `success` \| `failure` | map source values with `values.outcome` |
| `method` | O | - | - | string, default `password` | |
| `source_region` | R | - | - | string | |
| `user_region` | R | R | - | string | |
| `source_ip` | O | - | - | string -> `ip-<12 hex>` | |
| `role` | - | R | - | string | not pseudonymized |
| `action` | - | R | - | `VIEW_RECORD` \| `EDIT_RECORD` \| `EXPORT_RECORDS` \| `SEARCH` | map with `values.action` |
| `patient_id` | - | R | O | string -> `P-<12 hex>` | |
| `patient_region` | - | R | - | string | |
| `service` | - | - | R | one of the configured services (`config.yaml: services`) | unknown service -> `unknown_service` |
| `level` | - | - | R | `INFO` \| `WARN` \| `ERROR` | map with `values.level` |
| `priority` | - | - | R | `urgent` \| `routine` | usually a `defaults` constant |
| `request_id` | - | - | R | string -> `req-<12 hex>` | |
| `status` | - | - | R | integer 100-599 | |
| `latency_ms` | - | - | R | integer >= 0 | |
| `msg` | - | - | **off by default** | string | see Free text |

## Mapping blocks (per source)

* `fields`: canonical field -> dotted path in the JSON line (`client.ip`). Missing path = field absent.
* `values`: per field, exact source value -> canonical value. An unmapped value is `bad_value`
  (or `unknown_service` for `service`). `ts` and `event_id` are never value-mapped.
* `defaults`: constants for fields the log does not carry. A default never replaces a value that is present.
* Unknown keys, unknown canonical fields for the kind, and unknown timezones fail at start-up.

## Timestamps

Accepted: ISO-8601 with an offset or `Z`; epoch seconds or milliseconds; offset-less ISO-8601 **only**
when the source sets `timezone` (IANA name) and the local time is unambiguous. Everything is stored as
UTC. Rejected: missing, unparseable, boolean, NaN/inf, outside 2000-2100, DST gap (`ts_invalid`), DST
overlap (`ts_ambiguous`), offset-less without a source timezone (`ts_no_tz`), further in the future than
`ingest.max_future_skew_seconds` (`ts_skew`).

## Free text (`msg`)

Free text is the main place identifiers hide, so in configured mode **it is not read**:

* `msg` may not appear under `fields` unless the source sets `include_msg: true`; otherwise
  start-up fails with an explanation. `include_msg: true` without a `msg` mapping also fails.
* Without opt-in the stored message is the constant `[free text omitted]`, or an operator-written
  `defaults.msg` string. Source text is never copied.
* With opt-in the text is pattern-redacted (emails, SSNs, phone numbers, card numbers, tokens), the
  event's own raw identifiers (user, patient, IP, request, event id) are removed literally, and it is cut
  to `max_msg_chars` (500). **Other people's names, MRNs and free-form identifiers that match no pattern
  still pass through.** `/api/security/status` shows the warning `free_text_ingest` while any source opts in.

## Example (synthetic)

```yaml
- id: claims_app
  path: claims.jsonl
  kind: app
  fields: {ts: ts, event_id: id, service: svc, level: lvl, request_id: req, patient_id: pt, status: http, latency_ms: ms}
  values:
    service: {rcm-claims: claims}
    level: {error: ERROR, info: INFO, warn: WARN}
  defaults: {priority: routine}
```

```json
{"ts":"2026-03-10T16:15:05Z","svc":"rcm-claims","lvl":"error","req":"r-1","http":503,"ms":120,"id":"evt-1"}
```

`generator_v1` sources (the project's synthetic files) keep their fixed schema; identifiers are still
pseudonymized and `msg` is replaced unless `include_msg: true`.
