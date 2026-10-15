# Privacy boundary (M2)

This page defines what HEALTHTRACE treats as sensitive, where each kind of value is allowed to
exist, every place it could be stored or shown, and what an operator must do about data that
predates the boundary. It describes what the code does and what automated tests demonstrate with
**synthetic** data. It does not make the system anonymous, compliant or production-ready;
see [Limits](#limits-and-what-is-not-verified).

## Policy in one paragraph

In **configured mode** (`INGEST_MODE=configured`), direct identifiers are replaced by keyed
pseudonyms *at the ingestion boundary, before an event object exists*, so detectors, the
database, the REST API, the WebSocket, logs, e-mail and AWS payloads only ever see pseudonyms.
Free text from sources is not read at all unless a source opts in. **Pseudonymization is not anonymization**: whoever holds the key (or a list of candidate identifiers plus the key) can
recompute the pseudonyms, quasi-identifiers remain, and the application keeps no lookup table and
offers no re-identification feature. **Legacy mode** (the default, for the synthetic demo)
keeps raw synthetic identifiers and is unsuitable for sensitive real-world data.

## Field inventory

| Class | Fields | Handling in configured mode | Why it exists |
|---|---|---|---|
| **Direct identifiers** | `user_id` (username, e-mail, account or employee id) | `U-` + 12 hex, HMAC-SHA256, domain `user` | group events per actor |
| | `patient_id` (MRN, claim id) | `P-` + 12 hex, domain `patient` | count distinct patients per actor |
| | `source_ip`, device identifiers | `ip-` + 12 hex, domain `ip` | detect logins from new origins |
| | `request_id` (correlation id; may embed an identifier) | `req-` + 12 hex, domain `request` | join events across sources |
| | `event_id` (source event id; often embeds a user or host) | never stored raw; keyed digest (`i:` + hex) | de-duplication |
| **Free text** | `msg`, exception text, stack traces, SQL parameters | `msg` omitted by default (`[free text omitted]`); opt-in text is pattern-redacted and the event's own identifiers removed; exception text is never logged (type and code location only); driver parameter logging is switched off | the main place identifiers hide |
| **Quasi-identifiers** | regions (`user_region`, `source_region`, `patient_region`), `role`, `service`, second-resolution timestamps, status, latency, counts such as "accessed 201 patients", `action`, `outcome` | kept as is | detection needs them; in a small facility a combination can single a person out |
| **Operational metadata** | reason codes, byte offsets and lengths, counters, source ids, tailer state, severity, incident state, migration versions, key fingerprint (8 hex shown) | kept | monitoring the monitor |
| **Secrets** | `PSEUDONYM_KEY`, SMTP password, Brevo API key, operator tokens | never stored in the database, never logged, never returned by an API; held as `SecretStr` | |
| **Operator-supplied contact data** | alert recipients (staff e-mail addresses) | stored in `notification_settings`; masked (`a***@domain`) in logs and error text | notifications |

## Where values can persist or be exposed

### Database tables (all of them; SQLite and PostgreSQL share the schema)

| Table | Contents | Raw identifiers possible? |
|---|---|---|
| `incidents` | fingerprint, kind, service, `user_id`, state, timestamps | pseudonym in configured mode; **raw if written by legacy mode** |
| `alerts` | explanation text, `user_id`, metrics JSON | same |
| `evidence_events` | per-incident evidence records (redacted JSON) | same |
| `incident_events` | state-change log | no source identifiers |
| `access_stats` | per-user access baselines keyed by `user_id` | pseudonym in configured mode; raw in legacy |
| `baselines`, `metrics` | numeric aggregates per service | no |
| `audit_log` | operator action, role label, target id | no source identifiers (operator actions carry no free text) |
| `notification_settings` | recipient addresses, thresholds | **yes, by design**: staff addresses |
| `notification_attempts` | channel, status, provider id, detail | detail is sanitized; no addresses |
| `simulation_runs` | synthetic scenario results | synthetic only |
| `tail_positions` | file path, inode, byte offset | file path (not a person) |
| `ingest_seen` | de-duplication window | keyed digests only |
| `ingest_rejects`, `ingest_reject_counts` | source, reason code, offset, length | **never the line** |
| `ingest_meta` | key fingerprint, cutover flags | non-secret facts only |
| `schema_migrations` | applied migration versions | no |

### Other outputs

| Path | Policy | Evidence |
|---|---|---|
| REST API (all `GET` routes, incident sub-resources, `/api/audit`, status and config endpoints) | pseudonyms only; no source lines, secrets, filesystem paths or stack traces | `test_c4_*` |
| API error bodies | 404 static text; 422 keeps `loc/msg/type` and drops the offending input; unhandled errors become a generic 500 | `test_c4_error_responses_*` |
| WebSocket (`snapshot`, `metric`, `alert`, `incident_update`, `logs`) | pseudonyms only | `test_c5_*` |
| Application logs | no event text, no exception messages, no SQL parameters, no recipient addresses | `test_c6_*`, `test_c3_driver_*` |
| E-mail subject and body, SMTP/Brevo error text | pseudonyms; recipients masked in logs/status | `test_c8_*` |
| AWS CloudWatch / SNS payloads and error text | pseudonyms; payload never logged on error | `test_c8_*` |
| Process memory | raw lines exist transiently in tailer buffers, the ingest queue and adapter locals (they must be read to be pseudonymized); the tailer keeps only a salted digest of a file's first bytes | `test_c1_no_raw_*` |
| The source log files | **outside the boundary**: HEALTHTRACE reads them read-only and does not alter them | not applicable |
| Exports | **none exist**; a test fails if an `export`/`download` style route is added without review | `test_c4_there_is_no_export_*` |

## Historical data

**Existing data is not rewritten.** Rows written before configured mode, or by legacy mode, can
contain raw identifiers in `incidents`, `alerts`, `evidence_events`, `access_stats` and (for
legacy lines) in text columns. SQLite `-wal`/`-shm` side files, backups, copies of the database
and exports made earlier carry the same content, and so do application and proxy logs written
before M2.

What the software does about it:

* On the first start in configured mode it records, in `ingest_meta`, whether the database already
  held incidents or alerts (`legacy_rows_at_cutover`). If so it logs a warning and
  `/api/security/status` shows `historical_raw_data`. Nothing is modified or deleted.
* `scripts/privacy_audit_db.py <sqlite-file>` scans an existing SQLite database **read-only** and prints
  counts per table/column of values that are not pseudonyms or that look like e-mail addresses, IPv4
  addresses, SSN-shaped numbers, legacy patient ids or MRNs. It never prints a value. Exit status 2
  means indicators were found. For PostgreSQL run equivalent `SELECT count(*)` queries over the same
  columns.

### Cutover procedure (recommended: a new database, not an in-place rewrite)

1. **Inventory.** Run the scanner on the old database and note the counts. List every copy: backups,
   volume snapshots, exported files, copied `.db` files, and the log files of the app, reverse proxy and
   host.
2. **Decide the fate of the old data** under your own records-retention rules. Options: keep it offline
   and access-restricted until its retention period ends; encrypt it; or destroy it by your normal
   process. HEALTHTRACE never deletes it for you.
3. **Create the new database.** Point `DB_PATH` (SQLite) or `DATABASE_URL` (PostgreSQL) at an empty
   location; set `INGEST_MODE=configured` and a fresh `PSEUDONYM_KEY` from a secret store.
4. **Rebuild history from the sources if needed.** Set `from_start: true` on a source so its files are
   replayed through the pseudonymizing adapter into the new database.
5. **Verify.** Run the scanner on the new database (expect no findings), check
   `/api/ingest/status` (`legacy_rows_at_cutover` must be `false`) and `/api/security/status`.
6. **Retire the old paths.** Remove access to the old database, and clear or age out old logs.

Running configured mode on the *same* database is possible, but the old rows stay as they were and
the warning above stays on. That is a conscious, visible choice, not a migration.

## Key rotation

* The key is the only thing tying a pseudonym to a person. Store it in a secret manager, never in the
  repository, `.env` committed to Git, a database or a log. There is no escrow: if the key is lost,
  old pseudonyms can no longer be recomputed from source logs.
* The application stores a one-way **fingerprint** of the key (`ingest_meta.pseudonym_key_fingerprint`,
  first 8 hex characters shown by `/api/ingest/status`). If the key later differs, start-up **stops**
  with an explanatory error, because every pseudonym would change and incidents for the same person
  would silently stop correlating.
* To rotate on purpose: (1) acknowledge or resolve open incidents, since the same person will appear
  under a new pseudonym and open a second incident; (2) set the new `PSEUDONYM_KEY` **and**
  `PSEUDONYM_KEY_ROTATION_ACK=true` for one start; (3) remove the flag again; (4) expect
  `/api/security/status` to show `pseudonym_key_rotated`.
* After rotation, history before and after the change does not link. Per-user baselines
  (`access_stats`) restart under the new pseudonyms.
* The alternative that keeps both worlds clean is a new database (see the cutover procedure).
* If a key may have been **exposed**, rotate it, and treat all earlier pseudonymized data as
  re-identifiable by whoever held the old key.

## What cannot be achieved by this software alone

These guarantees cannot be achieved without changes to deployment, access control or operations:

* **Access control.** Roles are shared tokens (`X-Operator-Token`). There are no per-user identities or
  sessions, so "who looked at what" is limited to a role label.
* **Transport and storage.** TLS termination, disk and backup encryption, key custody, host log
  retention and rotation, and swap/core-dump handling are the deployer's responsibility.
* **Web-server access logs.** The ASGI server and any reverse proxy log request URLs, including query
  strings that an operator typed (for example a search term or a `user_id` filter). Configure them to omit
  or truncate query strings.
* **The source systems.** The raw logs remain wherever the hospital keeps them.
* **Re-identification.** Authorized responders re-identify out of band with the key and the source logs.
  The application provides no lookup, and none should be added without an access-control design.
* **Small populations.** Quasi-identifiers (region, role, exact times, counts) can identify people in a
  small facility even when every pseudonym is perfect.

## Limits and what is not verified

* **Not verified:** PostgreSQL driver-level logging beyond the filter applied at connect time; the
  browser/frontend side (local storage, browser history); uvicorn/proxy access logs; operating-system
  logs, core dumps and swap; every data format other than the synthetic ones in the tests.
* **Free text** (opt-in only) is pattern-based. A person's name, or an identifier that matches no
  pattern, passes through; a test pins this so it cannot change silently.
* **Pseudonyms are 48 bits** of an HMAC. That is ample against accidental collision at hospital scale
  and is not a defence against someone who holds the key.
* **Legacy mode** keeps raw synthetic identifiers in every output path by design and says so in
  `/api/security/status` (`legacy_ingest`).
* **Passing tests is evidence about the paths tested, with synthetic data.** It does not establish
  production readiness; hospital-specific integration, an independent security review and controlled
  validation are still required. See [M2_PRIVACY_VERIFICATION.md](M2_PRIVACY_VERIFICATION.md).
