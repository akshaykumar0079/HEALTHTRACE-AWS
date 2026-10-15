# HEALTHTRACE: Real-Hospital Implementation Plan

Companion to [REAL_HOSPITAL_READINESS_AUDIT.md](REAL_HOSPITAL_READINESS_AUDIT.md).
Status: **plan only; nothing in this plan has been implemented.**

## Principles

1. **Read-only.** HEALTHTRACE only reads authorized log files/streams. It never
   writes to, queries, or controls a hospital system.
2. **Preserve what works.** The synthetic generator, simulator, existing detectors,
   incident workflow, API and UI keep working. New code is additive; each change is
   gated by tests that already exist plus new ones.
3. **Local first, AWS optional.** No milestone requires AWS or any paid service.
4. **No connector without a target.** No hospital-specific connector is written
   until the source system, its log format, and an authorized integration method
   are known. Generic adapters (JSON lines, later syslog) come first.
5. **Minimum data.** Collect the fields detection needs; pseudonymize identifiers at
   the ingest boundary; never store raw patient identifiers.
6. **No production claim.** Every milestone ends with "validated on synthetic
   fixtures", never "production ready".

## Milestone map

| # | Milestone | Priority | Depends on |
|---|---|---|---|
| M1 | Secure read-only real-log ingestion pipeline | P0 | none |
| M2 | Privacy boundary: pseudonymization and redaction on every output path | P0 | M1 (schema) — **implemented on synthetic data; see status below** |
| M3 | Ingest health and monitoring of the monitor | P0 | M1 |
| M4 | Detection gaps: failed-only brute force, spraying, privilege change | P1 | M1 |
| M5 | Identity, sessions and audit trail | P1 | none |
| M6 | Operations: backups, CI, scanning, TLS guidance | P1 | none |
| M7 | Durable processing: persisted detector state and notification outbox | P2 | M1 |
| M8 | Source adapters (syslog, then IdP/EHR) after authorization | P2 | M1, M2, site info |
| M9 | Validation: replay of de-identified data, tuning, red-team exercise | gate | all above |

---

## M1. Secure read-only real-log ingestion (first milestone)

**Goal.** Ingest authorized local log files and structured JSON logs of an arbitrary
(configured) shape, normalize them into one documented schema, and feed the existing
detectors and incident workflow, without regressing the synthetic path.

### Design

* **Normalized event schema** (`docs/event-schema.md`, `app/ingest/schema.py`):
  `event_id`, `ts_utc`, `source_id`, `kind` (`auth` | `access` | `app` | `admin`),
  `actor` (pseudonym), `outcome`, `action`, `object_ref` (pseudonym),
  `src_ip` (optional, truncated or hashed per policy), `host`, `request_id`,
  `raw_ref` (source, offset), `schema_version`. Existing `AppEvent`, `AuditEvent`,
  `AuthEvent` stay; a converter maps normalized events to them so detectors are unchanged.
* **Source registry** (`config.yaml: ingest.sources[]`, validated at start):
  `id`, `path` (inside an allow-listed base dir), `format` (`json_lines`),
  `schema_mapping` (field and value mappings, e.g. `outcome: {Denied: failure}`),
  `timezone` (used only when a timestamp has no offset), `max_line_bytes`,
  `enabled`. Default config keeps today's three synthetic files so nothing changes.
* **Adapter interface** (`ingest/adapters/base.py`): `parse(raw_line, source) ->
  NormalizedEvent | Rejected(reason)`. First adapter: `json_lines` with mapping.
  `generator_v1` wraps the current parser, keeping the demo path intact.
* **Tailer hardening** (`ingest/tailer.py`, backward compatible):
  line cap (`max_line_bytes`, oversize line discarded and counted), drain old file
  before switching on rotation, regular-file and allow-listed-directory check
  (refuse symlinks that escape), supervised restart of a failed read with backoff,
  explicit `missing` / `stalled` source state.
* **Timestamps**: normalize to UTC at the boundary; naive timestamps use the
  source's configured timezone or are rejected with reason `ts_no_tz`; reject
  events beyond a configured clock-skew bound (reason `ts_skew`).
* **Deduplication**: `event_id` = source-provided id, else SHA-256 of normalized
  fields; bounded LRU per source; counter `duplicates_dropped`. Restart replay of the
  last un-persisted interval therefore does not double count.
* **Quarantine**: rejected lines recorded as `(source, offset, reason_code, sha256
  of line)`; the line body is **not stored by default** (optional redacted sample
  behind a flag). Counters per source and reason.
* **Redaction at ingest**: apply `Redactor` to free-text fields before any storage or
  broadcast; pseudonymize `actor`/`object_ref` (see M2).
* **Wiring**: the pipeline consumes `NormalizedEvent` from a single queue; detectors
  and incident logic are untouched. Settings flag `INGEST_MODE=legacy|configured`
  (default `legacy`), so the current behavior is the default and rollback is a
  config change.

### Affected files

New: `backend/app/ingest/{schema,registry,dedupe,quarantine}.py`,
`backend/app/ingest/adapters/{base,json_lines,generator_v1}.py`,
`docs/event-schema.md`, `docs/ingestion.md`, `backend/tests/fixtures/ingest/*.jsonl`.
Modified: `ingest/tailer.py`, `pipeline.py::start/_process_line`, `config.py`,
`config.yaml`, `parse/parser.py` (delegates to the `generator_v1` adapter),
`store/migrations.py` (m004: `ingest_sources`, `ingest_rejects`; additive, idempotent).

### Security controls

Read-only open (`"rb"`), allow-listed directory, no shell, no network in the
adapter, size caps, no raw line persisted, fail-closed on invalid source config at
start-up, secrets never in the source registry.

### Acceptance criteria (all must pass on synthetic fixtures)

1. Default install behaves identically to today (`INGEST_MODE=legacy`); existing
   suite unchanged and green.
2. A configured JSON source with a different field naming and outcome vocabulary
   produces the same alert as the synthetic equivalent.
3. Timestamps with offset, `Z`, epoch and (with configured tz) naive values all
   normalize to the same UTC instant; a naive timestamp with no configured tz is
   rejected with `ts_no_tz`, never raised as an exception.
4. Delivering the same 6-event batch twice yields the same incident and severity
   as once (regression for the audited HIGH to CRITICAL inflation).
5. A line exceeding `max_line_bytes` is discarded, counted, and memory stays bounded
   (regression for the 5 MB no-newline case).
6. Rotation by rename, by copy-truncate, and by deletion/recreate loses no
   complete line (regression for the audited lost `l3`).
7. Restart mid-stream resumes without loss or double count (kill between saves).
8. Malformed JSON, wrong types, unknown fields, binary garbage and very long lines
   never raise and are counted by reason; the pipeline keeps running.
9. A temporary read error (`PermissionError`, then recovery) pauses and resumes the
   source; it does not end the task.
10. No raw identifier from a fixture appears in the database, API responses,
    WebSocket frames or logs (assert by scanning outputs for planted canary strings).

### Tests

`tests/test_ingest_schema.py`, `test_ingest_adapters.py`, `test_ingest_dedupe.py`,
`test_tailer_rotation.py`, `test_ingest_restart.py`, `test_ingest_failures.py`,
`test_ingest_privacy_canary.py`, plus a fuzz test (hypothesis, or seeded random
bytes) on the adapter. Synthetic fixtures only.

---

## M2. Privacy boundary (P0, with M1)

* Replace display-time masking with **pseudonymization at ingest**: keyed HMAC
  (key from environment/secret store, never in the DB) for `actor`, `object_ref`,
  hostnames; truncate/hash IPs per policy. Responders re-identify through a
  controlled, audited lookup that runs outside this application (the application
  never stores the mapping).
* Close the two audited exposure paths: `Pipeline._remember_log` (`/api/events`, live
  WebSocket) and unredacted `incidents.user_id`, fingerprint and `alerts.explanation`
  (the fingerprint and explanation use the pseudonym).
* Existing redaction stays as defense in depth.
* Remove or confirm provenance of the four tracked dataset files (owner decision).
* **Acceptance:** canary test (M1 #10) covers `/api/events`, WebSocket, incident,
  alert, evidence, timeline, email and AWS payloads; migration test shows existing
  rows are handled (backfill pseudonymization or documented cutover).

### M2 status (implemented, uncommitted; evidence in [M2_PRIVACY_VERIFICATION.md](M2_PRIVACY_VERIFICATION.md))

**Completed (tested with synthetic data):** keyed-HMAC pseudonyms at the ingest boundary for user, patient, IP and
request id; event ids kept only as keyed digests; free text omitted by default; both audited exposure paths closed
(`/api/events` and WebSocket logs, `incidents.user_id`/fingerprint/`alerts.explanation`); exception text, SQL
parameters and recipient addresses kept out of logs and status; generic error bodies; key fingerprint guard
against silent key change; read-only historical-data scanner; cutover and key-rotation procedures
([privacy-boundary.md](privacy-boundary.md)). Ten acceptance criteria (C1-C10) have named tests; full backend
suites pass on SQLite (562 passed, 20 skipped) and PostgreSQL (582 passed).

**Partial / not done:** historical rows, backups, `-wal`/`-shm` files and old logs are not rewritten (documented
cutover, operator action); the scanner is SQLite-only; the controlled, audited re-identification path
is intentionally not built (needs M5 identities first); the four tracked dataset files still await an
owner decision; opt-in free text is pattern-based and keeps names; web-server access logs, host logs, core dumps,
swap and the browser are unverified; live provider (Brevo/SMTP/AWS) error text was not exercised.

**Skipped tests:** the PostgreSQL-parameterised cases are skipped when no PostgreSQL URL is set; they were run and passed separately.

**Remaining:** M3-M9 are not started.

---

## M3. Monitoring the monitor (P0)

* Per-source health: last event time, lag, malformed/dup/oversize rates, state
  (`ok|stalled|missing|error`); `/api/ingest/status`; dashboard panel.
* **Synthetic "ingestion stalled" and "malformed rate spike" incidents** raised
  through the normal incident workflow, so a blinded monitor is visible and notifies.
* `/metrics` (Prometheus text) behind the viewer role; documented external
  dead-man check (an uptime service that alerts when the heartbeat stops).
* **Acceptance:** stopping writes to a source raises a stalled incident within the
  configured interval; a format change raises a malformed-spike incident; no alert
  when a source is intentionally disabled.

## M4. Detection gaps (P1)

Each is a rule with documented thresholds, explainable evidence, and simulator
scenarios (including benign controls to measure false positives):
* repeated failures **without** success per user (brute force);
* one source across many users (password spraying), keyed on pseudonymized source;
* privilege/role change events (requires M1 `admin` kind and an authorized source);
* optional longer low-and-slow window with its own threshold.
* **Acceptance:** each scenario detected on fixed seeds; benign controls stay under a
  documented false-positive budget; benchmark added to `docs/simulator.md`. No claim
  of real-world accuracy.

## M5. Identity, sessions, audit (P1)

* OIDC login (authorization-code with PKCE) against an identity provider supplied
  by the site; group-to-role mapping; short-lived server sessions or JWT with expiry;
  `actor` becomes the individual's pseudonymous id. Static tokens remain for local
  development only and are refused when `ENVIRONMENT=production`.
* WebSocket auth via short-lived ticket, not a query-string token.
* Audit **reads** of incidents/evidence; tamper-evident chain (hash of previous row)
  and export; separate longer retention.
* **Acceptance:** authorization matrix test over every route and role; expired,
  malformed and replayed credentials rejected; read audit entries present; chain
  verification detects a modified row.

## M6. Operations (P1)

* GitHub Actions (or equivalent): backend tests on SQLite and Postgres, frontend
  typecheck/lint/test/build, `pip-audit`, `npm audit`, `bandit`, secret scan, container
  scan; failing checks block merge.
* Backup/restore runbook and scripts (SQLite online backup; `pg_dump`), restore
  drill documented with timings; encryption-at-rest guidance for volumes.
* TLS termination guidance and security headers (CSP, HSTS) in the app.
* **Acceptance:** CI green on a clean checkout; a restore drill produces a working
  system from backup in a fresh directory (scripted, tested).

## M7. Durable processing (P2)

* Persist detector state (auth failures, rolling access windows) at checkpoints so a
  restart does not forget a half-built pattern.
* Persisted notification outbox with retry and delivery status; an unacknowledged
  critical incident escalates to a second recipient.
* **Acceptance:** kill/restart test shows an attack pattern spanning a restart is
  still detected; queued notifications survive a crash and are sent once.

## M8. Source adapters (P2, requires site information)

Order, each only after the owner confirms the system and authorization:
1. RFC 5424/3164 syslog **file** adapter (read-only, from a collector's output file).
2. Identity-provider audit export adapter (format per vendor; file export first).
3. EHR audit-trail adapter (format per vendor; **needs the vendor's documented
   audit export and a data-use agreement**).
No network listeners are added without a threat-model review. Each adapter ships with
synthetic fixtures made from the vendor's public format documentation, never real logs.

## M9. Validation gate (before any pilot)

* Replay de-identified, authorized historical logs in an isolated environment;
  measure alert volume, precision on labelled events, detection delay.
* Tune thresholds with the site's security team; document residual false positives.
* Independent security review and penetration test; privacy/legal review (HIPAA or
  local law applies to the *site*, and this project makes no compliance claim).
* Shadow-mode period (alerts visible to analysts, no paging) with an exit criterion.

## Dependencies on you / the hospital

* The target systems and the **authorized** way to read their logs.
* A data-protection owner to approve fields collected, retention periods, and the
  pseudonymization/re-identification procedure.
* An identity provider for M5; a mail/paging channel for notifications.
* A security reviewer to sign off before any connection to a live environment.

## Recommended next action

Approve **M1 together with M2's ingest-boundary pseudonymization**, implemented on a
new branch from `a9d9e08`, default `INGEST_MODE=legacy`, no AWS, no real data. Before
that, confirm the provenance of the four tracked dataset files. Push the existing five
commits first so this work has a stable base.
