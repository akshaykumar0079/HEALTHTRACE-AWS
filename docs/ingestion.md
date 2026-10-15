# Ingestion (Milestone 1)

HEALTHTRACE reads authorized log files, **read-only**. This page describes the
two ingest modes, how a configured source is declared, what is rejected and why,
and what is *not* protected. It makes no compliance claim and does not make the
project production-ready: hospital-specific integration, an independent security
review and controlled validation are still required.

## Modes (`INGEST_MODE`)

| Mode | Reads | Schema | Identifiers | Use |
|---|---|---|---|---|
| `legacy` (default) | `app.log`, `audit.log`, `auth.log` in `LOG_DIR` | the project's own synthetic schemas | **raw** | demos and tests only |
| `configured` | sources in `config.yaml` -> `ingest.sources` | explicit field mapping | **keyed pseudonyms** | the path toward real logs |

**Legacy mode is unsuitable for real logs.** It has no event ids (so it cannot
de-duplicate by default), keeps identifiers as written, and accepts only the
synthetic schemas. The server logs a warning at start and `/api/security/status`
reports `legacy_ingest`. It is kept so the existing generator, simulator, demo and
tests keep working unchanged.

Configured mode **refuses to start** unless: `PSEUDONYM_KEY` is a valid secret,
`ingest.sources` has at least one enabled source, every path is allowed, and every
mapping is complete. It never falls back to raw identifiers.

## Pseudonymization (`PSEUDONYM_KEY`)

* Generate once, outside the repository: `python -c "import secrets; print(secrets.token_hex(32))"`.
  Provide it through the environment or your secret store. It is a `SecretStr`: it is
  never logged, never written to the database, never returned by any API.
* At least 32 characters with real variety; placeholders such as `changeme` are refused.
* `user_id`, `patient_id`, `source_ip` and `request_id` become keyed HMAC-SHA256
  digests (`U-<12 hex>`, `P-<12 hex>`, `ip-<12 hex>`, `req-<12 hex>`) **before** an
  event object is created. Source event ids are stored only as keyed digests.
* The same value always gives the same pseudonym, so one actor is still one actor and a
  request id still joins across sources. Different keys give different pseudonyms.
* The application keeps **no lookup table**. A responder who needs the real person
  re-identifies out of band using the key and the original source logs. Pseudonyms are
  not anonymization: anyone with the key and a list of candidates can recompute them.
* Rotating the key changes every pseudonym; open incidents keep the old ones.

### What is not protected
* **Free text.** In configured mode `msg` is **omitted by default** (stored as
  `[free text omitted]`, or an operator-written `defaults.msg`). A source can opt in with
  `include_msg: true`; the text is then pattern-redacted (emails, SSNs, phone numbers, card
  numbers, tokens) and the event's own identifiers are removed, but anyone else's name or an
  identifier matching no pattern passes through. See [event-schema.md](event-schema.md#free-text-msg).
* Role, region and service names are kept as they are (needed by the detectors).
* Database debug logging: `aiosqlite`/`psycopg` debug logs include bound parameters.
  Do not enable DEBUG logging for them outside tests.
* Backups and anything outside HEALTHTRACE (the source logs themselves).

## Declaring a source

```yaml
# config.yaml  (all names below are examples; no real product format is implied)
ingest:
  max_future_skew_seconds: 300     # events more than this far in the future are rejected
  sources:
    - id: idp_export                 # [A-Za-z0-9._-], unique
      path: idp.jsonl                # relative to LOG_DIR, or absolute inside an allowed dir
      kind: auth                     # app | audit | auth
      timezone: Asia/Kolkata         # ONLY for timestamps with no offset; omit to reject those
      stalled_after_seconds: 600     # report "stalled" if no new data for this long
      fields:                        # canonical field -> dotted path in the JSON line
        ts: "@timestamp"
        event_id: event.id           # strongly recommended: enables safe de-duplication
        user_id: actor.name
        outcome: event.outcome
        source_region: client.geo
        user_region: actor.home_geo
        source_ip: client.ip
      values:                        # source value -> canonical value, exact match
        outcome: {Success: success, Failure: failure, Denied: failure}
      defaults: {}                   # constants for fields the log lacks
      # include_msg: false           # app sources: free text is omitted unless set true AND fields.msg is mapped
```

* Required canonical fields per kind: `auth` ts, user_id, outcome, source_region,
  user_region; `audit` ts, user_id, role, action, patient_id, patient_region,
  user_region; `app` ts, service, level, priority, request_id, status, latency_ms, msg.
  Each must have a mapping or a default; `ts` and `user_id` must be mapped from the log.
* Anything unmapped is **rejected with a reason code, never guessed**.
* `format: generator_v1` reads the project's own synthetic files as a configured
  source (identifiers are still pseudonymized).
* Unknown keys, unknown canonical fields and unknown timezones are start-up errors.

### Path safety
Paths are resolved (symlinks followed) and must lie inside `LOG_DIR` or a directory
listed in `INGEST_ALLOWED_DIRS` (absolute, comma-separated). `..`, absolute paths
elsewhere, symlinks that escape, directories, FIFOs and devices are refused at start.
Files are opened read-only.

## Rejection reason codes (stable)

`line_too_long`, `invalid_json`, `not_an_object`, `unknown_type`, `schema_invalid`,
`missing_field`, `bad_value`, `ts_invalid`, `ts_no_tz`, `ts_ambiguous`, `ts_skew`,
`unknown_service`, `pseudonym_unavailable`, `duplicate` (a drop, counted separately).

Quarantine keeps **source, reason, byte offset and length only**; never the line. Counts
persist across restarts; a bounded sample of recent rejections is kept. See
`GET /api/ingest/status`.

## Timestamps
Every event time is normalized to timezone-aware UTC. Accepted: ISO-8601 with an
offset or `Z`, epoch seconds or milliseconds, and offset-less ISO-8601 **only** when
the source has a `timezone` and the local time is unambiguous. Rejected: missing,
unparseable, NaN, boolean, outside 2000-2100, nonexistent (DST gap) or ambiguous (DST
overlap) local times, and times further in the future than `max_future_skew_seconds`.
Legacy mode assumes UTC for offset-less timestamps and counts them.

## De-duplication (`INGEST_DEDUPE`)
* `event_id` (default): an event is a duplicate if its source-provided id was already
  seen for that source. **Events without an id are never dropped.**
* `content` (opt-in): digest of the whole line. It collapses distinct events that
  serialize identically; use only for a source that retransmits and has fine timestamps.
* `off`.
Memory is bounded (200,000 ids per source). The newest 50,000 ids per source are saved at
checkpoints and reloaded at start, so a retransmission after a restart is still caught.
**Limit:** ids first seen after the last checkpoint are lost in a crash (clean shutdowns
checkpoint, and the interval is 60 s), so a crash can reprocess that window. Detector
state (failure windows, baselines in flight) is still in memory only.

## File tailing
Poll-based, byte offsets persisted per file. Lines longer than `INGEST_MAX_LINE_BYTES`
(1 MiB) are discarded as they arrive (memory stays bounded) and counted. On rotation the
old file is drained through the open descriptor before the new one starts (POSIX);
copy-truncate and in-place replacement are detected by size and a 64-byte head
signature. A read error (permissions, I/O) is retried with capped back-off and reported
as source state `error`; a missing file as `missing`; no new data for `stalled_after_seconds`
as `stalled`. A tailer task that dies is restarted and counted. Limits: drain-before-rotate
needs POSIX; a line cut by a restart inside an oversize line leaves a garbage tail that is
rejected; the head signature needs 64 bytes to exist.

## Known limitations and residual risks (read before any real-data use)

* **Crash replay window.** De-duplication ids and quarantine counts are saved at a 60-second
  checkpoint and on clean shutdown. After a crash or kill, events first seen since the last checkpoint
  are processed again (a regression test pins this). Source byte offsets are saved at the same checkpoint,
  but only when the queue is empty at the checkpoint, so under a sustained backlog the window can be longer than 60 s; downstream effects of a replay (a repeated alert) are possible.
* **Detector state is memory-only.** Failure windows, sliding windows and in-flight baselines are rebuilt
  from new events after a restart; an attack straddling a restart can be missed or detected late.
* **POSIX rotation.** Draining the old file before a rotation relies on holding the descriptor open
  (POSIX). On Windows the tail of a rotated file can be lost; copy-truncate is handled by size/head signature
  on all platforms. Rotation tested here is simulated with local files only.
* **Pseudonyms are reversible by the key holder** (and guessable from a candidate list): this is
  pseudonymization, not anonymization. There is no key-rotation or key-escrow procedure yet.
* **Free text** (opt-in only) is pattern-based; names and unusual identifiers can pass through.
* **Other fields keep their values**: roles, regions, service names, status codes and timestamps are
  not pseudonymized; combinations may be identifying in a small facility.
* **Debug logging** of database drivers prints bound parameters; never enable it outside tests.
* **Legacy mode** (the default) is unchanged: raw ids, no event-id de-duplication.
* **Not validated** against any real hospital log, volume, clock skew, character encoding or hostile input
  beyond the synthetic tests in this repository. Throughput figures are single-process, synthetic.
* No authentication of the log source, no TLS to sources (file reads only), no per-user identities or
  sessions on the dashboard, no persisted notification outbox, no backup/restore procedure.

## Not implemented in this milestone
Syslog, identity-provider, EHR or any hospital-specific connector; network listeners;
persisted detector state; a persisted notification outbox; user identities and sessions.
See [REAL_HOSPITAL_IMPLEMENTATION_PLAN.md](REAL_HOSPITAL_IMPLEMENTATION_PLAN.md).

See also: [Privacy boundary](privacy-boundary.md) (field inventory, historical data, key rotation) and [M2 verification](M2_PRIVACY_VERIFICATION.md).
