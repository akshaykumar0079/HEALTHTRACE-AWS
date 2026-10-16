# Safe simulator

The simulator runs scenarios through the **real** detection pipeline, headless,
in a throw-away SQLite database in a temp directory. It cannot write to the
real store, send email, or call AWS (settings are built with `.env` ignored,
AWS off, email disabled, no `DATABASE_URL`). Notification decisions are counted,
not sent. One run at a time (HTTP 409 if busy).

Scenarios: `error_spike`, `failed_logins_then_success`, `bulk_record_access`,
`prior_auth_pipeline_failure`, `recovery_resolution`, `normal_control`, and
`mild_degradation` (a **known limit**: a small error-rate rise that the
detector sometimes misses; it is reported but does not gate tests).

Fixed seeds make runs reproducible. Each result reports expectations
(pass/fail per check), detection delay, false positives and isolation.

```
POST /api/simulations/run        {scenario, seed}   operator role
POST /api/simulations/benchmark  {seeds, scenarios} admin role
GET  /api/simulations/runs[/{id}]
```
UI: **Simulator** page in the dashboard.

## Benchmark (seeds 11, 22, 33; 7 scenarios; 21 runs)
| Metric | Result |
|---|---|
| Runs passing all checks | 17 / 21 |
| Injected incidents detected | 15 / 15 (gating scenarios) |
| Detection delay (simulated time) | median 10.1 s, max 216.4 s |
| Known-limit scenario (mild degradation) detected | 1 / 3 |
| Control (no incident injected) false positives | 1 / 3 runs (seed 33) |

These are synthetic results, not a claim about real-world accuracy. The control
false positive and the mild-degradation misses are real weaknesses of the
current thresholds.

The seed-33 control false positive is a LOW `batch` error-rate incident caused by 5 errors in one
100-event window passing all three guards at once; the analysis, a regression test and a larger
10-seed comparison with a threshold baseline and ablations are in [evaluation.md](evaluation.md).
