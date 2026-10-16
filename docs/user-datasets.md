# Evaluate your own dataset

The dashboard page **Your data** (Tools > Your data, `/app/research`) runs the detector on a CSV or JSON Lines file you
provide. It is part of the research evaluation features (see [evaluation.md](evaluation.md)); the synthetic scenarios
there remain the reproducible baseline.

> **Research prototype.** Upload only synthetic or properly de-identified data. This application is not
> HIPAA-certified, has not been security-reviewed for real patient data, and is not validated for clinical or
> production use. Nothing on this page changes that.

## What it does, and what it does not

* You upload a file, preview it, map your columns to the fields the detector uses, and validate the mapping.
* You run the detector (and, optionally, the fixed-threshold baselines from [evaluation.md](evaluation.md)).
* **No labels (the default):** the run is *descriptive*. It lists the incidents the detector raised, with
  timestamps, kinds, entities and severities. **Precision, recall and false-alarm rate are not computed**, and the
  result says so; the incidents have not been verified as true or false.
* **With labels:** if you map a label column and say which values mean "anomaly", the run also measures precision,
  recall, F1, false alarms per hour and detection delay against those labels (definitions below).
* The synthetic scenarios (`error_spike`, ...) are not injected into your data; they belong to the generator. You choose the *method(s)* and the *mode* (descriptive or labelled), not a scenario.
* Results are saved with the exact mapping so the experiment can be **repeated** (the result fingerprint must match)
  and **compared** with another one.
* Uploaded rows are not sent anywhere: no cloud service, no email, no external API is called. The run happens in a
  temporary database that is deleted afterwards.

## Supported files and limits

| | |
|---|---|
| Formats | `.csv` (delimiter `,` `;` tab or `\|`, detected from the header), `.jsonl` / `.ndjson` (one JSON object per line). Nested objects become dotted columns (`event.time`). Arrays are ignored. |
| Rejected | Anything else (`.xlsx`, `.json` arrays, `.txt`, no extension), binary files, files that are not UTF-8, files with empty or duplicate column names. |
| Size | 25 MB (`RESEARCH_MAX_UPLOAD_MB`) |
| Rows | 200,000 (`RESEARCH_MAX_ROWS`); further rows are ignored and the page says so |
| Columns | 100 (`RESEARCH_MAX_COLUMNS`) |
| Cell length | 2,000 characters; a row with a longer cell is rejected, not truncated |

A row that cannot be read is **rejected and counted**, never repaired. Rejections are reported by a stable reason
code and the row number only (for example `ts_invalid: rows 3, 17, 18`), never by content. More than half of the rows
rejected blocks the run, because that normally means the mapping is wrong.

## Dataset kinds and fields

Choose what the file is. Fields marked * must be mapped to a column.

**Service log** (`app`, the one the baselines and ablations apply to)

| Field | Notes |
|---|---|
| Timestamp * | ISO-8601 (with offset or `Z`), or epoch seconds / milliseconds. A timestamp without an offset uses the timezone you choose (default UTC). |
| Service * | Must resolve to `prior_auth`, `eligibility`, `pharmacy`, `claims` or `batch` (the services in `config.yaml`). Map your own names under *Value mapping* (`RX` to `pharmacy`), or pick one constant if the whole file is one service. `Prior-Auth` and `ELIGIBILITY` are matched automatically. |
| Event level / Status code | Map at least one. Level values `info/debug` -> INFO, `warn/warning` -> WARN, `error/fatal/critical` -> ERROR are matched automatically. If only one is mapped the other is derived (status >= 500 is an error). An event is an error when level is ERROR or status >= 500. |
| Latency (ms) | Optional. Not mapped: latency anomalies cannot be detected. |
| Priority | Optional (`urgent` / `routine`). Not mapped: everything is routine. |
| Patient identifier | Optional. Used only to count affected patients (the patient-impact part of severity). |
| Request identifier | Optional. The row number is used if absent. |

**Record access log** (`audit`): Timestamp *, User identifier *, Action * (`VIEW_RECORD`, `EDIT_RECORD`, `EXPORT_RECORDS`,
`SEARCH`; map yours), Patient identifier *, and optional Role and regions.
**Login log** (`auth`): Timestamp *, User identifier *, Outcome * (`success` / `failure`), and optional method, regions, source IP.
Only the `current` detector applies to these two kinds; the threshold baselines and ablations are service-log only.

Rows whose service, level, priority, action or outcome cannot be interpreted are rejected. Values are never guessed.
After *Validate*, the page lists the values it could not interpret so you can add them under *Value mapping*.

## Labels (optional ground truth)

Tick "My file has a column that says which rows are real anomalies", pick the **label column** (it must not also be
mapped as a detector input, otherwise the evaluation would be circular), tick the values that mean "anomaly", and choose:

* *An anomaly belongs to* its service/user (`entity`: a hit must be on the same service or user) or the whole dataset
  (`dataset`: any incident inside the interval counts);
* *Merge gap*: labelled rows closer together than this many seconds form one interval.

Definitions (also in the result):

* An **interval** is a run of labelled rows for one entity.
* A **hit (TP)**: the first incident of that entity whose first alert falls in `[interval start, interval end + 60 s]`
  (60 s because the detector looks at a 60-second window). Further incidents there are counted as *duplicates* and are not errors.
* A **miss (FN)**: an interval with no hit.
* A **false alarm (FP)**: every other incident. **Labels are treated as complete**: an incident outside every labelled
  interval counts against the detector, so incomplete labels make precision look worse than it is.
* `precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`, `F1` is their harmonic mean,
  `false alarms per hour = FP / hours spanned by the data`, `detection delay = first alert - interval start` (hits only).
  A metric with nothing to divide is shown as `n/a`, never as 0.
* The detector learns its baseline **from the same file** (in-sample), and needs about two minutes of data before it can
  alert. An interval that starts earlier is flagged "starts during detector warm-up".

Without a label mapping, none of this is computed, and the stored result contains no precision, recall or rate fields.

## Steps (Windows)

1. Start the app (three PowerShell windows, repository root; the first time also run `python -m venv .venv`,
   `.\.venv\Scripts\pip install -e "backend[dev]"` and `cd frontend; npm install`):

   ```powershell
   .\.venv\Scripts\python.exe -m generator.generate --backfill-hours 2   # once
   .\.venv\Scripts\python.exe -m generator.generate --rate 30            # window 1: live demo logs
   cd backend; ..\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8010   # window 2: API
   cd frontend; npm run dev                                                # window 3: http://localhost:5173
   ```

   Open `http://localhost:5173`. Without tokens configured you are the local administrator; with `OPERATOR_TOKEN` set,
   enter the token under Settings, API access (uploading needs the **operator** role). Restart the API after updating the code.
2. To try it with synthetic data, generate samples (PowerShell, repository root):

   ```powershell
   .\.venv\Scripts\python.exe scripts\make_sample_dataset.py
   ```

   This writes `data\samples\sample_labeled.csv` (with a `Flag` column) and `data\samples\sample_unlabeled.csv`.
3. Open **Your data** in the sidebar (Tools). Read the notice and tick the confirmation. Nothing can be selected before that.
4. **Choose a file.** The file is stored unchanged and a preview is shown.
5. **Preview.** Check the column names and types. Columns that look like identifiers or free text are masked.
6. **Map your columns.** Suggestions are filled in from common column names; correct them. For the samples: Time -> Timestamp,
   Component -> Service, Severity -> Event level, HTTP -> Status code, Duration_ms -> Latency, Urgency -> Priority,
   PatientRef -> Patient identifier, ReqID -> Request identifier. Under *Value mapping* set `RX` to `pharmacy`.
   For the labelled sample tick the label box, choose `Flag`, tick `1`.
7. **Validate.** Fix any error shown (missing required field, unknown column, invalid timestamps, unsupported values,
   rejected rows). Warnings tell you what a missing optional field costs.
8. **Run.** Choose *Descriptive only* or the labelled evaluation, tick the methods, press *Run evaluation*
   (about a minute for 100,000+ rows).
9. Press **Repeat** on the result to run the identical experiment again; the page says whether the result fingerprint
   matches. Tick two entries under *Saved experiments* and press *Compare selected* to compare them.

## API

All under `/api/research`. Reading experiments needs normal read access; anything that touches an uploaded file needs
the operator role; deleting an upload needs admin. The server re-validates and recomputes everything: a client cannot
submit a result.

| Call | Purpose |
|---|---|
| `GET /info` | limits, formats, field lists, methods, the warning text |
| `POST /uploads` | raw file as the request body; headers `X-Filename` (URL-encoded) and `X-Privacy-Ack: yes` (required); returns the id and the preview |
| `GET /uploads/{id}` | preview again |
| `POST /uploads/{id}/validate` `{mapping}` | validation report |
| `POST /experiments` `{upload_id, mapping, methods, mode, acknowledged_privacy_warning: true}` | run |
| `GET /experiments`, `GET /experiments/{id}` | list, fetch |
| `POST /experiments/{id}/rerun` | repeat with the stored upload and mapping |
| `GET /experiments/compare?a=&b=` | side-by-side |
| `DELETE /uploads/{id}` | admin: delete the upload and every experiment that used it |

## What is stored, and where

Under `research_dir` (default: a `research` folder next to the database, `data\research\`):

* `uploads\<sha256>.csv|jsonl` and `<sha256>.json`: the file **byte-for-byte as received**, marked read-only,
  named by its own SHA-256 and checked against it on every read (a changed file is refused). Uploading the same bytes twice stores one copy.
* `experiments\<id>.json`: the exact mapping, methods, mode, `config.yaml` hash, upload hash, the result and a result
  fingerprint (`results_sha256`). No raw row appears in it.
* `.pseudonym_key`: a random key created once for this installation (unless `PSEUDONYM_KEY` is set), so repeated runs
  produce the same pseudonyms. Treat it like a credential; deleting it changes every pseudonym, so older experiments
  would no longer reproduce bit-for-bit.

**Reproducibility:** an experiment is repeatable when the upload, mapping, methods, mode, `config.yaml` and the code are
the same. The result fingerprint is a hash of those inputs and the results; the Repeat button reports whether it matches.

## Privacy behaviour

* **Warning first.** The page requires an acknowledgement before the file chooser works, and the API refuses an upload
  or run without it (`X-Privacy-Ack`, `acknowledged_privacy_warning`).
* **Reuses the project's ingestion boundary.** Each row goes through the same adapter as configured ingestion
  ([ingestion.md](ingestion.md)): timestamps are normalized to UTC, user, patient, request and IP identifiers are replaced
  by keyed HMAC pseudonyms *before* an event object exists, free text is never copied (the message becomes a constant), and
  the model is validated. Mapped identifier columns therefore never reach the detector, the results or the logs.
* **Preview.** Shows the first five rows, pattern-redacted (SSN, e-mail, phone, card, MRN, patient ids) and shortened.
  Columns named like sensitive fields or that look like identifiers or free text (by name, or text with mostly unique values) are
  masked and their values are not listed. Redaction reduces accidental exposure; it does not prove a value is free of identifiers.
  Distinct values of low-variety columns (for example service names) are listed so you can map them; those are shown to you only.
* **No raw rows in logs or errors.** Messages carry reason codes, counts and row numbers only. Unexpected failures return a
  generic message and log only the exception type and code location. The audit log records ids (a hash prefix) and outcomes, not content.
* **Original filename** is shown to you after removing any path and scrubbing patterns; it is never used as a path.
* **Retention.** Experiments and uploads older than `RETENTION_RESEARCH_DAYS` (default 30; 0 = keep) are deleted by the
  existing retention job (Settings > Retention, dry run supported). An upload still used by a newer experiment is kept until
  that experiment expires. An admin can delete an upload and its experiments immediately.
* **Roles.** Operator to upload, preview, validate, run, repeat; admin to delete; viewers can read saved experiments.
* **No external calls.** The run uses the isolated simulator-style pipeline: AWS off, email disabled, no network.

### Caveats

* Uploaded data sits unencrypted on this server's disk (read-only, but not encrypted at rest) until it expires or is deleted.
* Pseudonyms are not anonymization: whoever has the key and a list of candidate identifiers can recompute them.
* Do not enable this on a public hosted deployment without authentication. Set `RESEARCH_ENABLED=false` to turn the feature off.
* Hosts with an ephemeral disk (some free tiers) lose uploads and experiments on restart.
* The detector, thresholds and severity weights in `config.yaml` were tuned on the project's synthetic generator. Results on
  other data show how this detector behaves there; they are not evidence of general accuracy.

## Settings

| Setting | Default | |
|---|---|---|
| `RESEARCH_ENABLED` | true | turn the feature off |
| `RESEARCH_DIR` | `<db folder>\research` | where uploads and experiments live |
| `RESEARCH_MAX_UPLOAD_MB` | 25 | |
| `RESEARCH_MAX_ROWS` | 200000 | |
| `RESEARCH_MAX_COLUMNS` | 100 | |
| `RETENTION_RESEARCH_DAYS` | 30 | 0 keeps forever |

## Limitations

* Single dataset kind per upload; no joins across files.
* Services must map onto the five configured services; other services cannot be monitored without editing `config.yaml`.
* No de-duplication of repeated rows; rows are sorted by timestamp, ties keep file order.
* Only the first 200 incidents per method are stored in the result.
* One evaluation at a time (a second request gets HTTP 409).
* The label scoring is incident-level and interval-based. It does not measure per-row classification, and it assumes complete labels.
* The baseline is learned from the same file, so the early part of the file cannot alert, and results describe in-sample behaviour.
