# Incident intelligence: related incidents, duplicate suggestions, trends (Phase 2)

Everything here is **read-only** and **rule-based**. It never merges, links, resolves, deletes or edits an incident, and a result is a lead for a person to check, not a diagnosis. No new table or migration is used: it reads the existing `incidents` and `evidence_events` tables.

## Endpoints

All three follow the existing read rules (`read_access`: open unless `VIEWER_TOKEN` / `REQUIRE_VIEW_AUTH` is set). Paths are under `/api`.

| Endpoint | Purpose |
|---|---|
| `GET /incidents/{id}/related?limit=10&min_score=0.4&window_hours=6` | Possibly related incidents with a score, reasons and a short summary. `limit` 1-25, `min_score` 0-1, `window_hours` 0.25-72. 404 for an unknown id, 422 for invalid parameters. |
| `GET /incidents/{id}/duplicates?limit=5&max_gap_minutes=30` | Conservative duplicate suggestions, always `requires_human_review: true`. `limit` 1-10, gap 0-240. |
| `GET /incidents/trends?days=30&since=&until=&bucket=auto&service=&kind=&severity=` | Counts of incidents opened in a range (default 30 days, max 366). `bucket` is `auto`, `day` or `hour` (hour needs <= 7 days). Unknown service, kind or severity is a 422. Declared before `/incidents/{id}` so `trends` is not parsed as an id. |

Each related or duplicate entry returns: source incident id, the other incident's id, `score`, `reasons` (plain sentences), `signals` (machine names), `time_gap_seconds`, and an `incident` summary with only: `id, title, kind, service, state, status_label, severity, alert_count, opened_at, last_seen_at, resolved_at`. It never returns `user_id`, the fingerprint (which can contain a user id), log text, or evidence content.

## Related-incident rules

Points are added per signal; the score is capped at 1.0.

| Signal | Points |
|---|---|
| Same service | 0.35 |
| Services linked in the configured dependency graph | 0.20 |
| Same anomaly type | 0.25 |
| Compatible type (same family: reliability, PHI access, access security) | 0.12 |
| Activity windows overlap / gap <= 15 min / <= 1 h / <= 6 h | 0.30 / 0.25 / 0.18 / 0.08 |
| Stored evidence from the same log sources and levels (Jaccard >= 0.5, both sides have evidence) | 0.10 |
| Same pseudonymous actor (**off by default**) | 0.15 |

A candidate is listed only if it has at least **two different kinds** of signal and a score of at least 0.40. Time alone can reach at most 0.30, so being close in time never links incidents. The current incident is excluded. Candidates come from a bounded SQL lookup of incidents whose activity overlaps the window around the source (at most 300, newest first; the response sets `candidates_truncated` when more existed and the UI says so), not from loading history into memory. Results are ordered by score, then smaller time gap, then newer id, so the output is deterministic.

Missing data is handled, not guessed: no service means no service signals; an inconsistent window (last seen before opened) is treated as a point in time; a naive timestamp is treated as UTC.

## Duplicate rules (stricter)

A duplicate suggestion needs the **same anomaly type and the same service** (both present) and activity within `max_gap_minutes`. It starts at 0.5 and gains for the shared grouping rule and for overlap or closeness; it loses points when peak severities differ by more than one level or when both incidents are already resolved (that looks like a recurrence). It is listed at 0.70 or more, and 0.90 or more is labelled `likely`, otherwise `possible`. Cautions are shown next to the reasons.

Person-scoped incidents (HIPAA and suspicious-login types) carry no service, so no duplicate is ever suggested for them, and the endpoint says why. Different types, different services, a missing service, or a gap of hours are never suggested. Duplicates are separate from relatedness on purpose: related means "look at these together", duplicate means "these may be the same event".

## Trends

All numbers are counts of stored incidents opened in `[since, until)`, computed with SQL `GROUP BY` (no full-history load): per day or hour by severity, by severity, by service, by anomaly type, open versus resolved, and recurring patterns (same type and service opened at least twice, with total `reopen_count`). Recurring patterns group by type and service only, never by user.

**Time to resolve** (median, p90, max) is shown only with at least 5 resolved incidents that have a valid duration (`mttr_seconds >= 0` and `resolved_at >= opened_at`). Otherwise it is `null` with the reason, and `resolved_without_valid_duration` says how many resolved incidents were left out. Nothing is estimated. Day and hour buckets use the UTC date of the stored timestamp. When the pipeline replays older history, the default end of the range follows the pipeline's event clock, as the other time-series endpoints do.

## Privacy

Signals are service, anomaly type, time, severity, the configured dependency graph and the coarse shape (log source, level) of stored evidence. Raw user ids, patient ids, request ids, IP addresses, e-mail addresses, fingerprints and log text are never used as signals and never returned. The only identity-based signal is "same pseudonymous actor", disabled unless `INCIDENT_INTEL_MATCH_ACTOR=true`; even when enabled only the fact of a match is reported, never the value. With it off, person-scoped incidents are still related by type and timing but not by person. Nothing is stored by these endpoints, so retention and the privacy audit are unaffected (no new table; `docs/privacy-boundary.md` is unchanged).

## Optional AI assistance

The deterministic results are the facts. The Phase 1 insight (`docs/ai-incident-intelligence.md`) now includes up to 3 top matches as facts `rel:<id>` (kind, service, state, severity, score, signal names, labelled `deterministic_match`; no actor, fingerprint or text). The built-in insight adds a next step that points at the top match and says it "may or may not share a cause". A local model, if configured, may only explain those facts: every claim still has to cite fact ids that exist in the bundle, and the existing validator rejects unknown ids, invented numbers and "action taken" claims. The prompt tells the model to say "may be related" and never that one incident caused another. With AI off or unavailable, the deterministic text is shown. If the related lookup fails the insight is built without it. The model is not asked to find relationships, only to explain computed ones.

## User interface

On the incident investigation page, below the AI insight panel: **Possibly related incidents** and **Possible duplicates** (two panels side by side on wide screens). Each shows the score, the reasons, severity, state, a link to the other incident, and loading, empty, error and retry states. The duplicate panel has no merge or delete action. On the Analytics page, an **Incident trends** panel with a 7d / 30d / 90d selector shows totals, open versus resolved, a stacked column chart by severity, breakdowns by service and type, recurring patterns, and the time-to-resolve figure only when it is available.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `INCIDENT_INTEL_MATCH_ACTOR` | `false` | Allow "same pseudonymous actor" as a related signal. |

## Limits

* Scores are rule weights, not probabilities. Thresholds were chosen by judgement and tested on synthetic data only; they have not been tuned on real incidents.
* Candidates and trends read persisted incidents. An incident that exists only in memory and has not been saved yet is not a candidate.
* Evidence similarity compares only log source and level, so it is weak; it adds 0.10 at most.
* Buckets are UTC days or hours. The first bucket of a range that does not start at midnight (or the hour) is partial.
* PostgreSQL and SQLite return the same results in the tests; large-volume performance has not been measured.
