# M2 privacy boundary: verification record

Scope: milestone M2 ("Complete Privacy Boundary and Data Protection"), implemented on branch
`feature/m1-secure-ingestion` on top of `a9d9e08` with the M1 changes, uncommitted.
Everything below was exercised with **synthetic** data, local stubs and mocks. No real AWS service,
real e-mail, hospital system or patient data was used. Design and policy: [privacy-boundary.md](privacy-boundary.md).

**Verdict: all ten criteria are satisfied for the paths and data tested, with the gaps listed in the
last column and in [Known limitations](#known-limitations). This is not a claim of hospital-production
readiness, anonymity or regulatory compliance.**

## Criteria

All test names are in `backend/tests/test_m2_privacy.py` unless a file is named. The scenario fixture plants
canary values (user e-mail, employee id, IP, MRN, event id embedding a user, an unmapped field, malformed,
oversize and unknown-service lines, a free-text name, an SSN-shaped number) and every sink is scanned for
them; each scan has a **positive control** showing that the sink is non-empty and that the pseudonym that
should be there is present, so an empty sink cannot pass.

| Criterion | Implementation evidence | Test name/command | Result | Remaining gap |
|---|---|---|---|---|
| C1 Ingestion privacy boundary | Pseudonyms are applied in the adapter before an event object exists (`ingest/adapters.py`, `ingest/pseudonym.py`); `msg` is omitted by default; unmapped fields never copied; rejected lines are stored as reason + offset + length only; tailer first-bytes signature is a salted digest, not raw bytes | `test_c1_detectors_only_ever_receive_pseudonymized_event_objects`, `test_c1_no_raw_identifier_in_any_detection_state`, `test_c1_rejected_lines_are_not_retained_by_the_ingest_layer`; `test_ingest_privacy.py` | PASS | Raw lines exist transiently in tailer buffers, the queue and adapter locals (they must be read to be hashed). Not verifiable against core dumps or swap |
| C2 Pseudonymization correctness | HMAC-SHA256 over `domain\x00value`, 12 hex; domains `user`/`patient`/`ip`/`request`; event ids kept only as keyed digests; invalid or missing key refuses start-up; key only from environment/settings (`SecretStr`); one-way key fingerprint; key-change guard | `test_c2_pseudonyms_equal_an_independent_hmac_sha256_computation`, `test_c2_the_key_fingerprint_is_one_way_and_not_a_pseudonym`, `test_c2_missing_or_invalid_keys_refuse_configured_mode_without_fallback`, `test_c2_the_key_comes_from_the_environment_and_a_missing_env_var_refuses`, `test_c2_no_key_is_hard_coded_in_the_source_tree`, `test_c2_a_changed_key_on_an_existing_database_stops_start_up_unless_acknowledged`, `test_c2_enabling_configured_mode_on_a_database_with_old_rows_is_flagged_not_rewritten`; `test_ingest_configured.py` | PASS | Pseudonyms are 48 bits. Pseudonymization is not anonymization: the key holder can recompute them from candidate identifiers. Key custody is a deployment matter |
| C3 Database privacy | Only pseudonyms in `incidents`, `alerts`, `evidence_events`, `access_stats`; dedupe/quarantine hold digests and metadata; migration m005 adds `ingest_meta` (additive, idempotent); driver parameter logging suppressed | `test_c3_sqlite_rows_and_file_bytes_contain_no_raw_identifier_or_source_line` (12 tables, text and file bytes), `test_c3_dedupe_and_quarantine_tables_hold_only_digests_and_metadata`, `test_c3_unmapped_source_fields_are_never_copied_anywhere`, `test_c3_postgresql_tables_contain_no_raw_identifier`, `test_c3_driver_debug_logging_does_not_print_sql_parameters`, `test_c3_m005_is_additive_idempotent_and_keeps_existing_rows`, `test_c3_every_table_is_inventoried_in_the_privacy_boundary_document` | PASS (SQLite and PostgreSQL) | PostgreSQL check is pipeline-level, not through API/WS. Driver-level logging beyond the filter applied at connect time is not verified. `notification_settings` holds staff e-mail addresses by design |
| C4 REST API privacy | Every parameterless GET route (more than 55 paths) plus incident sub-resources, timeline, log context, audit and status/config endpoints swept; 422 handler drops echoed input; error boundary returns generic 500; `/api/config` shows file names, not paths; no export endpoint | `test_c4_every_get_endpoint_and_incident_sub_resource_is_free_of_raw_identifiers`, `test_c4_audit_trail_and_operator_actions_hold_no_source_identifiers`, `test_c4_search_terms_are_not_echoed_and_find_nothing`, `test_c4_error_responses_do_not_echo_input_secrets_or_internals`, `test_c4_there_is_no_export_or_download_endpoint`, `test_c4_configuration_and_status_endpoints_never_show_secrets_or_paths` | PASS | Sweep ran with open access; viewer/operator role variations not swept. POST/PUT routes other than acknowledge/investigate/pin were not swept. Routes with path parameters were reached only through the incident/log ids the scenario produced |
| C5 WebSocket privacy | Frames use the same pseudonymized records | `test_c5_websocket_frames_of_every_type_are_free_of_raw_identifiers` (snapshot, alert, incident_update, metric, logs), `test_c5_incident_creation_and_update_frames_carry_pseudonymous_users_and_policy_text`; `test_ws.py` | PASS | Browser side (local storage, history) not examined |
| C6 Application logs and exceptions | Exception messages never logged (`safe_exc`: type + file:line + function); notifier and mailer logs mask recipients; DEBUG capture over the whole scenario scanned; driver loggers held at WARNING | `test_c6_logs_captured_at_debug_level_during_the_whole_scenario_are_clean`, `test_c6_an_exception_raised_while_processing_a_line_is_logged_without_its_message`, `test_c6_a_database_error_is_logged_with_type_and_location_only`, `test_c6_malformed_oversize_and_non_json_input_never_reach_logs`, `test_c6_the_safe_log_helpers` | PASS | uvicorn/proxy access logs (request URLs and query strings), host logs, core dumps are outside the application and not verified. Capture excludes the test client's own `httpx`/`httpcore` loggers |
| C7 Incidents and detection explanations | Incident `user_id`, fingerprint, explanation and evidence carry pseudonyms; detection result is unchanged by pseudonymization; cross-source correlation joins on pseudonyms | `test_c7_incident_references_fingerprints_and_explanations_use_pseudonyms`, `test_c7_pseudonymization_does_not_change_what_is_detected` (two keys and legacy mode produce the same detections), `test_c7_correlation_across_sources_still_joins_on_pseudonyms` | PASS | Equivalence shown on the synthetic scenarios only; no claim about real-traffic precision/recall. Quasi-identifiers (region, role, timestamps, counts) remain by design |
| C8 E-mail and notification privacy | Subject/body/AWS payloads built from pseudonymized records; provider error text and recipient addresses masked in logs and status; AWS crash log omits the payload; notifications were not disabled | `test_c8_delivered_emails_and_aws_payloads_are_clean_and_not_empty` (fake SMTP, AWS mock log), `test_c8_a_transient_failure_was_retried_and_its_log_lines_do_not_expose_addresses`, `test_c8_a_permanent_delivery_failure_masks_recipients_in_logs_and_status`, `test_c8_provider_error_text_masks_addresses_for_every_provider_path`, `test_c8_an_aws_delivery_failure_is_logged_and_reported_without_the_payload`, `test_c8_notification_attempt_rows_are_metadata`; `test_email.py`, `test_notifier.py` | PASS | Stubs only: live Brevo/SMTP/AWS error text was not exercised. Recipient addresses are operator-configured and stored in `notification_settings`. Mail in transit and in the recipient mailbox is outside the application |
| C9 Historical data and operational boundaries | Nothing is rewritten or deleted; first configured start records `legacy_rows_at_cutover` and warns (`historical_raw_data` in security status); key-change guard; read-only scanner `scripts/privacy_audit_db.py`; documented cutover, rotation and non-software guarantees | `test_c9_the_scanner_finds_legacy_identifiers_without_printing_or_changing_them`, `test_c9_cutover_rehearsal_legacy_database_to_a_new_pseudonymized_database`, `test_c9_the_scanner_reports_a_configured_mode_database_clean`, `test_c9_the_documentation_covers_the_required_operational_topics`, `test_c9_legacy_mode_keeps_its_documented_raw_behaviour_and_says_so` | PASS for what software can do | Existing rows, `-wal`/`-shm` files, backups, exports and old logs keep raw identifiers until the operator retires them. Scanner supports SQLite only (PostgreSQL needs manual `SELECT count(*)`). Backups and log files cannot be verified by software |
| C10 End-to-end privacy regression | One scenario drives ingestion, quarantine, detection, persistence, API, WebSocket, logs, e-mail, AWS mock and in-memory state, with positive controls and a per-canary scan of every sink | `test_c10_end_to_end_every_output_path_was_exercised_and_is_clean`, `test_c10_known_limit_names_in_opted_in_free_text_are_not_removed` | PASS | The known-limit test pins that a person's name in opted-in free text is **not** removed |

## Commands run and results

Run from `backend/` with `../.venv/bin/python` unless noted; each under `timeout -s KILL`, output to a file.
Counts are from the final runs on the final tree.

| Command | Result |
|---|---|
| `python -m pytest tests/test_m2_privacy.py -q` (SQLite) | 55 passed, 2 skipped (the two PostgreSQL cases: no PostgreSQL URL set) |
| same with `HEALTHTRACE_TEST_DATABASE_URL=postgresql://ht@127.0.0.1:54329/healthtrace_test` (local PostgreSQL 16) | 57 passed, 0 skipped |
| `python -m pytest tests -q` (full backend, SQLite) | 562 passed, 20 skipped, 0 failed |
| same, with the PostgreSQL URL (full backend, PostgreSQL) | 582 passed, 0 skipped, 0 failed |
| `npx vitest run` (frontend) | 52 passed (52) |
| `npx tsc -b` | exit 0 |
| `npm run lint` | warnings only (`react(purity)`, `Date.now` in render, in files outside M2; present before M2) |
| `npm run build` | built successfully |
| `python ../scripts/bench_ingest.py` | pipeline median 18,526 lines/s, tailer median 711,017 lines/s (30,000 lines, 3 runs). Reference: baseline 19,999 and M1 21.4k pipeline lines/s, so pipeline throughput is within about 7-13% of earlier runs on this container; timing varies run to run |

The focused suites named in the task are contained in the full runs: privacy canary (`test_m2_privacy.py`,
`test_ingest_privacy.py`, `test_privacy.py`), ingestion/quarantine/dedupe (`test_ingest_configured.py`,
`test_ingest_quarantine_dedupe.py`, `test_tailer*.py`, `test_timestamps.py`), incidents (`test_incidents.py`,
`test_grouping.py`, `test_correlation.py`), API/WebSocket (`test_api.py`, `test_ws.py`), notifications
(`test_email.py`, `test_email_flood.py`, `test_notifier.py`).

Mutation check (13 deliberate regressions applied one at a time to the code under test): 12 were caught by the
M2 privacy tests; the 13th (the tailer comparing raw head bytes again) is a functional rather than a privacy
regression and is caught by `test_tailer_hardening.py`. This was a local, manual check and is not part of the suite.

## Skipped tests

* 20 skipped on the SQLite run: the PostgreSQL-parameterised cases, which run (and pass) when
  `HEALTHTRACE_TEST_DATABASE_URL` is set. Of those, 2 are in `test_m2_privacy.py`. No test was skipped by
  editing it; none is skipped on the PostgreSQL run.
* No `xfail`, no deleted tests.

## Test modifications (disclosed)

* `tests/test_hardening.py::test_interrupted_first_run_does_not_skip_history` was rewritten to be deterministic.
  It had a pre-existing race (a free-running tailer against database I/O): failed 4/120 isolated runs on
  baseline `a9d9e08`, 7/120 on the M1 tree, 4/60 on the M2 tree. The new version stops the tailers, performs
  explicit `poll_once()` calls and then joins the queue. **All assertions are unchanged.** Reintroducing the
  original bug makes the new version fail (`assert 12 <= 0`), and it passes 40/40 repeated runs.
* `tests/test_migration_003.py` asserts the migration list as `range(3, LATEST_VERSION + 1)` instead of the literal `[3]`, because
  later migrations (m004 from M1, m005 from M2) now also run on upgrade; the schema assertions are unchanged.
* The privacy tests from M1 (`test_ingest_privacy.py`, `test_ingest_quarantine_dedupe.py`) were updated when
  `msg` became omitted by default (M1 finalization); no assertion was relaxed to make them pass.

## Output paths inspected

Database (all 17 tables, SQLite and PostgreSQL), SQLite file bytes, REST GET routes, incident sub-resources,
timeline, log context, audit trail, status/config endpoints, 404/422/500 bodies, WebSocket frames (5 types),
application logs at DEBUG, exception logging, driver logging, e-mail subject/body, SMTP/Brevo error text,
AWS payloads and error text, notification-attempt rows, dedupe and quarantine stores, tailer state,
in-memory detector/queue state, legacy-database scan output, scanner exit codes.

Not inspected: uvicorn and proxy access logs, host/OS logs, core dumps, swap, browser storage, database
backups, filesystem snapshots, the source logs themselves, live provider responses.

## Known limitations

* **Pseudonymization is not anonymization.** Key holders can recompute pseudonyms; there is no escrow, so a
  lost key means old pseudonyms cannot be recomputed from source logs; an exposed key means earlier
  pseudonymized data should be treated as re-identifiable by whoever held it.
* Quasi-identifiers (region, role, exact times, counts) remain and can single out people in a small facility.
* Opt-in free text is pattern-based: names and identifiers matching no pattern pass through (pinned by a test).
* Raw lines exist transiently in process memory; detector state is memory-only, so a crash can replay a window
  of 60 seconds or more.
* No per-user identities: roles use shared tokens, so the audit trail records a role label only.
* Legacy mode (default) stores and shows raw synthetic identifiers by design and is labelled unsuitable for real data.
* Four tracked dataset files at the repository root still need an owner decision on provenance
  ([DATASET_PROVENANCE.md](DATASET_PROVENANCE.md)). They were not deleted, redistributed or read for contents.
* The scanner is pattern-based and SQLite-only; "no findings" is not proof of absence.

## Historical-data implications

Existing databases are not changed by M2 except for the additive `ingest_meta` table (migration m005).
Rows written by legacy mode keep raw identifiers, as do backups, `-wal`/`-shm` files and old logs. Enabling
configured mode on such a database is allowed but flagged (`historical_raw_data`). The recommended path is a
new database rebuilt from the sources (`from_start: true`); `test_c9_cutover_rehearsal_*` demonstrates that flow
with the old database left byte-identical. Steps: [privacy-boundary.md](privacy-boundary.md#cutover-procedure-recommended-a-new-database-not-an-in-place-rewrite).

## What remains (not done in M2)

M3 ingest health and monitoring of the monitor; M4 detection gaps; M5 identity, sessions and audit;
M6 operations (backups, CI, scanning, TLS guidance); M7 durable processing; M8 source adapters;
M9 validation gate. See [REAL_HOSPITAL_IMPLEMENTATION_PLAN.md](REAL_HOSPITAL_IMPLEMENTATION_PLAN.md).
Before any pilot: access control design for re-identification, an independent security review, deployment
hardening (TLS, encryption at rest, access-log configuration, key custody) and validation on de-identified data.
