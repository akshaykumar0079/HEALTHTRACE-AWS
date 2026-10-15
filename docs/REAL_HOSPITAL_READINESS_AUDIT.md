# HEALTHTRACE: Real-Hospital Readiness Audit

Audited commit: `a9d9e08` on `main` (5 commits ahead of `origin/main`, not pushed).
Scope: backend, frontend, database, migrations, generator, detection, incidents,
notifications, WebSocket, configuration, tests, deployment.

**Bottom line.** HEALTHTRACE is a well-tested **synthetic-data prototype** with a
sound internal architecture. It is **not** suitable for real hospital logs or PHI
today. It reads three fixed JSON-lines files in one fixed schema, rejects anything
else as "malformed", has no event deduplication, mishandles timestamps without a
timezone, exposes unredacted identifiers through two read paths, and authenticates
with shared static tokens. Passing tests prove the synthetic scenarios behave as
specified; they do not prove real-world detection quality, security or availability.
**Hospital-specific integration, an independent security review and controlled
validation are required before any production use.**

## How each finding was established

* **Read** = I read the code at the path given.
* **Probed** = I ran the real `Parser` / `Pipeline._process_line` against crafted
  synthetic input in a throw-away database (`/tmp/probe.py`, `/tmp/probe2.py`;
  results quoted below). No `.env`, real database, network or real data was touched.
* **Not verified** = stated as a gap because nothing in the repository provides it.

Status values: **Implemented** (works, evidence given), **Partial**, **Simulated**
(works only on the project's own synthetic format/generator), **Missing**.

---

## 1. Log ingestion

### 1.1 Actual security-log ingestion: **Simulated**
* `backend/app/pipeline.py::Pipeline.start` hard-codes three tailers:
  `settings.log_dir / "app.log" | "audit.log" | "auth.log"`. There is no setting for
  other paths, globs, or sources.
* The only producers are `generator/generate.py` and `app/embedded_generator.py`
  (synthetic). `docker-compose.yml` runs the generator as a sidecar.
* Gaps: no configurable source list; no per-source identity/schema/timezone;
  no source health ("silent source" alert); a missing file is silently treated as
  "caught up" (`Tailer.run` catches `FileNotFoundError`).
* Required: configured source registry (path, format, schema version, tz), source
  health metrics, alert on stale/missing source. Tests: missing file, stale source.

### 1.2 File tailing: **Implemented (with gaps)**
* `backend/app/ingest/tailer.py::Tailer` (polling, byte offsets, inode rotation
  detection, truncation detection, partial-line buffering, bounded `asyncio.Queue(10000)`).
  Existing tests: `tests/test_tailer.py` (read).
* Gaps (read):
  * **No maximum line length.** `_buffer += chunk` grows without bound if a file has
    no newline (binary file, wrong path). Probed (`/tmp/probe3.py`): a 5 MB file with
    no newline left 5,000,000 bytes buffered and 0 lines queued. Memory-exhaustion risk.
  * Rotation detection uses inode only. Copy-truncate rotation that keeps the inode
    is caught only when size < offset; a rotated file that grows past the old offset
    before the next poll is **missed** (data loss, no signal).
  * On rotation the **tail of the old file is not drained** before switching: lines
    written between the last poll and the rotation are lost. Probed: `l1,l2` read,
    `l3` appended, file renamed and a new file started with `n1`; the queue received
    `['l1','l2','n1']`, so **`l3` was lost** with no signal.
  * `st_ino` is not stable on Windows/some network filesystems.
  * No check that the path is a regular file, not a symlink to elsewhere, and no
    allow-listed base directory (relevant once paths become configurable).
  * Decoding uses `errors="replace"`, so invalid bytes silently become U+FFFD.
* Required: line cap + counter, drain-before-rotate, path allow-list/symlink policy.

### 1.3 Structured JSON parsing: **Partial**
* `backend/app/parse/parser.py::Parser.parse_line`; models in `backend/app/models.py`.
* Works on the project's own three schemas. Everything else is counted in
  `malformed_lines` and **discarded with no record** (not even a quarantine sample).
* Probed (`/tmp/probe.py`):

| Input | Result |
|---|---|
| valid auth event | accepted |
| `type:"syslog"` / plain syslog text | rejected (counter only) |
| audit `patient_id:"MRN00123456"` | **rejected** (schema requires `^P-\d{6}$`) |
| audit `action:"READ"` | rejected (enum is 4 fixed values) |
| app `service:"radiology"` | rejected (enum of 5 fixed services) |
| auth `outcome:"denied"` | rejected |
| unknown extra field | accepted, field silently dropped |

* Consequence: real systems will have other services, action names, ID formats and
  outcome vocabularies. All of it is dropped as "malformed" with no visibility.
  `models.py` encodes synthetic assumptions (`PATIENT_ID_PATTERN`, `Service`
  literal, `AuditAction` literal).
* Required: a documented normalized schema (see plan, M1), a mapping layer from
  source field names/values to it, and a quarantine/dead-letter record with
  reason codes (content redacted).

### 1.4 Future integrations (syslog, identity provider, EHR, infrastructure): **Missing**
* Grep for `syslog|oidc|saml|ldap|hl7|fhir` across `backend/app`: no matches.
  `app/correlation/synthetic.py` contains **synthetic-format** adapters for
  "server" and "db_audit" logs only; they do not parse any real product's format.
* Not building any hospital-specific connector is deliberate until the target system
  and an authorized integration method are known. The plan defines the adapter
  interface so a connector can be added without touching detection.

### 1.5 Timestamp normalization: **Partial, with a verified defect**
* Pydantic parses ISO-8601 and epoch seconds. Probed:
  * `2026-03-10T21:30:00+05:30` accepted, kept with its own offset (not converted to UTC).
  * **`2026-03-10T16:00:00` (no timezone) accepted as a naive datetime.**
* Defect (probed): detectors and the window compare/subtract timestamps. A naive
  timestamp mixed with aware ones raises `TypeError`, caught by
  `Pipeline._consume`, which logs and **drops the event**:

| Scenario | Result |
|---|---|
| 5 naive-ts failures then aware success | `TypeError`; **no alert** (attack missed) |
| all naive | `TypeError` on later events; first alert still emitted |

  Real logs commonly omit or mislabel timezones, so this is a likely silent-miss path.
* Also: ordering uses event time with `_event_clock` high-water mark; a source with a
  skewed clock (future timestamps) would advance the clock and age out other data.
  No skew detection.
* Required: normalize every timestamp to UTC at the ingest boundary; reject or
  explicitly tag events with no timezone using a per-source configured tz; skew limit
  and counter. Tests for each.

### 1.6 Deduplication: **Missing (verified)**
* No event identity or dedupe anywhere in ingestion (grep found only alert-level
  fingerprinting in `incidents/engine.py`, which dedupes *incidents*, not *events*).
* Probed with the same 5 failures + 1 success:

| Delivery | Result |
|---|---|
| once | HIGH `auth_suspicious_login` |
| **whole batch delivered twice** | **CRITICAL** (failure count doubled, severity inflated) |
| success line replayed twice | one alert (success clears failures) |

* Duplicate delivery is normal in real pipelines (at-least-once forwarders, retries,
  restart replay). It would inflate counts and severity.
* Required: stable event id (source-provided, else content hash of normalized fields)
  with a bounded recent-id set per source; counter `duplicates_dropped`. Tests.

### 1.7 Malformed events: **Partial**
* Never crashes the pipeline (good, read + probed). Only a global counter is kept
  (`Parser.malformed_lines`, per-window `malformed_lines` metric). No reason codes,
  no per-source breakdown, no sample, no alert on a sudden malformed-rate rise
  (which, in real deployments, usually means a format change = blind monitoring).

### 1.8 Retries and temporary failures: **Partial**
* Email: bounded retry with backoff (`notify/mailer.py`, 3 attempts), non-retryable
  errors classified. Queue is **in-memory and unbounded**; queued alerts are lost on
  crash and there is no persisted outbox.
* Database write failures: `Pipeline._db_failed` counts and continues; no retry
  queue for evidence/alerts, so an outage window loses records (counted, not recovered).
* Tailer read errors other than `FileNotFoundError` propagate out of `run()` and
  **kill that tailer task** with no restart (`asyncio.create_task(tailer.run())`,
  no supervisor). Permission errors or a transient I/O error would stop ingestion silently.

### 1.9 Restart recovery: **Partial (at-least-once, stateful detectors lost)**
* `Pipeline._save_state` persists byte offsets + baselines every 60 s
  (`BASELINE_SAVE_INTERVAL_SECONDS`) and on clean `stop()`; offsets saved only when
  the queue is idle (read). Resume logic in `Tailer._initial_offset`.
* After a crash, up to 60 s of lines are **re-read and reprocessed**; with no
  dedupe (1.6) that double-counts.
* Detector state is **memory only**: `AuthDetector._failures`, `AccessDetector`
  rolling windows, `SlidingWindow`, `_hipaa_last_alert`. After a restart a
  half-completed attack pattern (e.g. 4 failures before restart, success after) is
  not detected. Incident state is restored (`_restore_incidents`).

---

## 2. Detection

| Capability | Status | Evidence / gap |
|---|---|---|
| Failed logins followed by success | **Implemented** (synthetic schema) | `detect/auth.py::AuthDetector.evaluate`; probed: 5 failures + success => HIGH |
| Repeated authentication failures **without** success | **Missing** | Probed: 20 failures for one user, no success => **0 alerts**. Brute force that fails is invisible. |
| Password spraying / one source IP many users | **Missing** | Probed: 8 users x 1 failure from one IP + 1 success => 0 alerts. `AuthDetector` keys only on `user_id`; `source_ip` is stored but never used for detection. |
| Low-and-slow guessing | **Missing** | Probed: 6 failures over 2 h then success => 0 alerts (10-minute window, `config.yaml: auth.window_minutes`). Acceptable as a tunable, but unmonitored. |
| Suspicious login (unfamiliar region) | **Partial** | Region comes from the log's own `source_region` vs `user_region` fields. No IP geolocation, impossible-travel, device or MFA signal. Real logs rarely supply `user_region`. |
| Privilege escalation | **Missing** | No event type, model or detector. Probed: an `iam`/`ROLE_GRANT` event is rejected as malformed. |
| Unusual access (off-hours, region mismatch, export) | **Simulated** | `detect/access.py::AccessDetector` (read). Depends on synthetic `patient_region`/`user_region`; thresholds tuned on generator traffic (see comment block in `config.yaml: hipaa`). |
| Potential bulk patient-record access | **Implemented** (synthetic schema) | `AccessDetector` per-user distinct-patient count vs learned baseline, with `bulk_min_threshold` floor. Real EHR audit logs differ (see 1.3). Alert quality unmeasured on real data. |
| Sliding-window metrics, baseline deviation | **Implemented** | `detect/window.py`, `detect/baseline.py`, `detect/anomaly.py` (EWMA, poisoning protection). Built for the 5 synthetic services. |
| Severity levels | **Implemented** | `detect/severity.py`, rules in `detect/access.py`/`detect/auth.py`. Weights are demo-calibrated. |
| Correlation | **Partial** | `app/correlation/` shared-key rules; works only with synthetic adapters; `pipeline.py` does not reference it (grep), so it runs on demand via the API, not on the live stream. |
| Alert/incident deduplication | **Implemented** | `incidents/engine.py` fingerprint grouping, cooldown, reopen; `tests/test_grouping.py`, `test_incidents.py`. |
| Detection quality on real data | **Missing / unknown** | Simulator benchmark (docs/simulator.md): 15/15 injected detected, mild degradation 1/3, control false positive 1/3 runs. Synthetic only; **no precision/recall claim is valid for real traffic**. |

---

## 3. Incidents, investigation, real time, notifications

| Item | Status | Evidence / gap |
|---|---|---|
| Persistent incident records | **Implemented** | `store/db.py` (`incidents`, `alerts`, `incident_events`), migrations `store/migrations.py` (m001-m003); restore on start `Pipeline._restore_incidents`. |
| Investigation history / timeline | **Implemented** | `incidents/timeline.py`, `/api/incidents/{id}/timeline`, `frontend/src/components/TimeMachine.tsx`; tests `test_timeline.py`, `TimeMachine.test.tsx`. Evidence is only retained for incidents; events that did not trigger one are not queryable later (only a 500-record in-memory buffer, `recent_logs`). |
| Real-time dashboard | **Implemented** | `api/ws.py` Broadcaster (bounded per-client queues, slow-client close), frontend WebSocket client. Single process, in-memory fan-out: no multi-instance support. |
| Reliable notifications | **Partial** | Email retry/backoff/flood tests (`test_email_flood.py`, `test_email.py`). No persisted outbox, no delivery receipt, no escalation if nobody acknowledges, no paging integration. Failure to notify is visible on a status page only. |
| Dead-man / self-monitoring | **Missing** | If ingestion stops (dead tailer, silent source) no alert is raised. For a security monitor this is the most important missing alert. |

---

## 4. Security controls

### 4.1 Authentication and RBAC: **Partial (demo-grade)**
* `backend/app/api/auth.py`: three shared static tokens (`VIEWER_TOKEN`,
  `OPERATOR_TOKEN`, `ADMIN_TOKEN`) compared in constant time. Roles enforced
  server-side (`require_role`), tested in `tests/test_auth.py`.
* Gaps (read):
  * **No individual identity.** The audit `actor` is the literal string `viewer`,
    `operator` or `admin`; every operator is the same person in the audit trail.
  * Default is **open** (auth disabled) unless `ENVIRONMENT=production` or
    `REQUIRE_OPERATOR_TOKEN` is set; the UI shows a banner but the server still runs.
  * Without `ADMIN_TOKEN` the operator token holds admin rights.
  * Tokens do not expire, cannot be revoked individually, and there is no
    brute-force throttling on token guesses (write rate limit only,
    `main.py::rate_limit`, keyed on `request.client.host`, which behind a proxy is
    one shared address).
  * WebSocket token is sent as a **query parameter** (`api/ws.py`), which ends up in
    proxy and access logs.
  * No MFA, SSO/OIDC, session management or CSRF model (token header, no cookies).
* Required: OIDC/SAML SSO with per-user identity and group-to-role mapping, session
  expiry, WebSocket auth by first message or short-lived ticket.

### 4.2 Secure sessions: **Missing** (no sessions; static bearer tokens).

### 4.3 Audit trail: **Partial**
* `audit_log` table (`store/migrations.py`) records state changes (acknowledge,
  resolve, settings, retention, simulate). Gaps:
  * **Reads are not audited** (who viewed which incident/evidence).
  * Not tamper-evident (plain table; the retention job deletes rows older than
    `RETENTION_AUDIT_DAYS`, default 365; no hash chain or write-once export).
  * Actor identity is weak (4.1).

### 4.4 Encryption: **Missing in application; depends on deployment**
* No application-level TLS (Uvicorn serves HTTP; `Dockerfile`), no encryption at
  rest for SQLite (`data/medguard.db` plaintext), no field-level encryption.
  Hosted docs assume provider TLS and Postgres `sslmode=require`
  (`docs/deployment.md`). `deploy/aws/healthtrace.yaml` provisions a Secrets Manager
  secret (read of the template only; not deployed or tested here).
* Security headers: only `nosniff`, `X-Frame-Options`, `Referrer-Policy`
  (`main.py`). No CSP, no HSTS.

### 4.5 Secrets management: **Partial**
* `.env` is git-ignored; `.env.example` has placeholders; secret-scan test in
  `tests/test_privacy.py`; no secrets in tracked files (checked).
* Gaps: tokens are plain environment variables; no rotation; the Brevo/SMTP key
  lives in `.env` on disk; no secret-manager integration in the app itself.

---

## 5. Privacy and data minimization

### 5.1 Log redaction: **Partial, with two verified exposure paths** (original finding at `a9d9e08`)

> **Update after M2 (uncommitted work, synthetic-data evidence only):** in `INGEST_MODE=configured` both exposure
> paths below are closed (keyed pseudonyms at the ingest boundary; see [privacy-boundary.md](privacy-boundary.md)
> and [M2_PRIVACY_VERIFICATION.md](M2_PRIVACY_VERIFICATION.md)). Legacy mode (the default) is unchanged and still
> exposes raw synthetic identifiers. Existing databases, backups and logs are not rewritten. Status: **Partial**
> until a cutover is performed, deployment-level items are in place and an independent review is done.

* `privacy/redaction.py::Redactor` (field names + regex: SSN, email, phone, Luhn card,
  MRN, bearer, API keys; patient ids masked to `P-****NN`). Applied to: stored
  evidence (`Pipeline._capture_evidence`), incident evidence/timeline API
  (`routes.py` `redact_value`), email and AWS payloads.
* **Not applied to** (verified):
  1. `Pipeline._remember_log` builds `recent_logs` records containing raw `user_id`
     and `source_ip` and a `msg` that embeds the raw `user_id`; these are served by
     `/api/events` (`routes.py:428`) and pushed on the live WebSocket.
  2. `incidents.user_id`, the incident **fingerprint**
     (`auth_suspicious_login:<user_id>`), and `alerts.explanation` are written to the
     database **unredacted**. Probed: with `user_id = "jane.doe@hospital.org"` the DB
     holds that email in `incidents.user_id`, `incidents.fingerprint` and
     `alerts.explanation`, while the evidence `msg` correctly shows `[EMAIL]`.
* Real log identifiers (usernames that are emails, IPs, workstation names) are
  personal data. Needs a **pseudonymization** decision (stable keyed hash for
  correlation, with a controlled re-identification path for responders) rather than
  display-time masking alone.

### 5.2 Patient-data minimization: **Partial**
* Ingestion keeps only the masked patient id in logs/evidence (good), but the parsed
  event in memory has the full id; detectors count distinct full ids. The schema is
  built around patient id presence (audit `patient_id` required). A real design should
  hash patient ids at the ingest boundary with a keyed hash and never retain the raw id.
* Four dataset files are tracked at the repository root
  (`cancer_patients_40_sample.csv`, `covid19_patient_risk_top50.csv`,
  `medical_dataset_40_patients_hackathon.xlsx`, `synthetic_medical_patient_dataset.xlsx`).
  They are referenced by no code, `Dockerfile` or docs. Their provenance is **not
  established here** (CSV headers show patient-level clinical columns). Confirm they
  are public or synthetic and remove them from the repository before any real-world
  use (I did not delete anything).

### 5.3 Retention: **Implemented** (`privacy/retention.py`, `tests/test_privacy.py`);
  defaults (evidence 30 d, resolved incidents 90 d, audit 365 d) are placeholders, not
  a policy derived from a hospital's requirements. No legal-hold flag.

---

## 6. Deployment, monitoring, backup, recovery, security testing

| Item | Status | Evidence / gap |
|---|---|---|
| Containerization | **Implemented** | `Dockerfile` (non-root uid 10001, healthcheck), `docker-compose.yml` (runs the synthetic generator sidecar). |
| Cloud template | **Simulated/untested** | `deploy/aws/healthtrace.yaml`, `docs/aws-deployment.md`; never deployed in this audit. AWS stays optional (`AWS_MODE=off|mock|live`). |
| App monitoring | **Partial** | `/api/health`, replay/heartbeat status, Notifications page. No metrics endpoint (Prometheus), no external uptime/dead-man check, no alert on ingestion stall. |
| Backups / recovery | **Missing** | No backup script, schedule or restore test; no `pg_dump`/snapshot automation (grep). Migrations are additive and idempotent (`test_migration_003.py`), which helps but is not a recovery plan. |
| High availability | **Missing** | Single process; in-memory state (queue, detectors, broadcaster). |
| CI | **Missing** | No `.github/` workflows; tests run only when someone runs them. |
| Dependency / SAST scanning | **Missing** | No `pip-audit`, `bandit`, SBOM or container scan configured. (`npm audit` was clean on 2026-10-10 after `npm audit fix`.) |
| Security tests | **Partial** | Auth/role tests, secret-leak scan, redaction tests, no-real-email guard (`conftest.py`). No fuzzing of the parser, no API authz matrix over every route, no pen-test. |
| Load / soak | **Missing** | No sustained-throughput or backpressure test beyond tailer unit tests. |

---

## 7. Test evidence (this audit)

Run on commit `a9d9e08` in this environment:

* Backend, SQLite: **403 passed, 14 skipped** (the skips are PostgreSQL-only tests).
* Backend, PostgreSQL 16 (earlier run, same code): **417 passed, 0 skipped**.
* Frontend: vitest **52 passed (5 files)**; `tsc -b` exit 0.
* The audit probes in this document are separate scripts, not part of the suite.

What these results do and do not show: they show the synthetic scenarios, the
migrations, the role checks and the redaction functions behave as written. They do
not show correct behavior on real logs, resistance to attack, availability, or
compliance.

---

## 8. Requirement matrix (summary)

| # | Requirement | Status | Key files |
|---|---|---|---|
| 1 | Real security-log ingestion | Simulated | `pipeline.py::start`, `ingest/tailer.py`, `generator/` |
| 2 | File tailing | Implemented (gaps) | `ingest/tailer.py` |
| 3 | Structured JSON parsing | Partial | `parse/parser.py`, `models.py` |
| 4 | Syslog / IdP / EHR / infra integration | Missing | (none) |
| 5 | Timestamp normalization | Partial (defect) | `models.py`, `detect/*` |
| 6 | Event deduplication | Missing | (none) |
| 7 | Malformed-event handling | Partial | `parse/parser.py` |
| 8 | Retries / temporary failures | Partial | `notify/mailer.py`, `pipeline.py` |
| 9 | Restart recovery | Partial | `pipeline.py::_save_state`, `ingest/tailer.py` |
| 10 | Suspicious login detection | Partial | `detect/auth.py` |
| 11 | Repeated failures (no success), spraying | Missing | `detect/auth.py` |
| 12 | Privilege escalation | Missing | (none) |
| 13 | Unusual access / bulk record access | Simulated | `detect/access.py` |
| 14 | Sliding window, baseline, severity | Implemented | `detect/*` |
| 15 | Correlation | Partial | `correlation/` |
| 16 | Alert / incident dedupe | Implemented | `incidents/engine.py` |
| 17 | Persistent incidents + history | Implemented | `store/`, `incidents/timeline.py` |
| 18 | Real-time dashboard | Implemented | `api/ws.py`, `frontend/` |
| 19 | Reliable notifications | Partial | `notify/mailer.py` |
| 20 | Authentication | Partial (shared tokens) | `api/auth.py` |
| 21 | RBAC | Implemented (coarse, 3 roles) | `api/auth.py` |
| 22 | Secure sessions | Missing | (none) |
| 23 | Audit trail | Partial | `store/migrations.py`, `routes.py` |
| 24 | Encryption (transit/rest) | Missing in app | `Dockerfile`, `main.py` |
| 25 | Secrets management | Partial | `.env.example`, `deploy/aws/healthtrace.yaml` |
| 26 | Log redaction | Partial (2 exposure paths in legacy mode; closed in configured mode by M2, see update in 5.1) | `privacy/redaction.py`, `pipeline.py::_remember_log` |
| 27 | Patient-data minimization | Partial | `models.py`, `pipeline.py` |
| 28 | Retention | Implemented | `privacy/retention.py` |
| 29 | Deployment | Partial | `Dockerfile`, `docker-compose.yml`, `deploy/` |
| 30 | Monitoring of the monitor | Missing | (none) |
| 31 | Backups and recovery | Missing | (none) |
| 32 | Security testing / CI | Partial / Missing | `tests/`, no CI |

## 9. Limitations of this audit

* Static reading plus targeted behavioural probes on synthetic input. No penetration
  test, no dependency CVE scan beyond `npm audit`, no load test, no review of any
  hospital environment.
* The Postgres and AWS paths were exercised only by the existing automated tests
  (Postgres) or not at all (AWS live).
* "Implemented" means implemented for the synthetic schema unless stated otherwise.
