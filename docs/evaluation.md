# Evaluation (reproducible experiments)

This page describes the command that evaluates the detector on the project's
synthetic scenarios, how every number is defined, and what the results can and
cannot support. **Synthetic data only.** Nothing here is evidence about real
logs, real accuracy, clinical validity or HIPAA compliance.

It builds on the [safe simulator](simulator.md) (same scenarios, same seeded
generator, same labelled injection intervals) and does not replace it. The
simulator answers "did this run pass its expectations?"; the evaluation answers
"how does the detector compare with baselines and ablations over many seeds?".

## Run it

Setup (once, from the repository root, Windows PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e "backend[dev]"
```

If PowerShell blocks `Activate.ps1` (execution policy), skip activation and call
`..\.venv\Scripts\python.exe` instead of `python` below.

Run the evaluation (about 9-12 minutes for 10 seeds with 3 workers):

```powershell
cd backend
python -m app.evaluation --workers 3
```

Useful options:

```powershell
python -m app.evaluation --quick                    # seeds 11,22,33 only (about 2 minutes)
python -m app.evaluation --seeds 1,2,3,4,5,6,7,8    # your own seeds
python -m app.evaluation --scenarios error_spike,normal_control --methods current,threshold_10pct
python -m app.evaluation --out ..\results\run1      # output directory (default: data\evaluation)
python -m app.evaluation --list                     # scenarios and methods
```

`--workers` only changes speed; results are identical for any value. Output goes
to `data\evaluation\` (git-ignored) unless `--out` is given. `python -m pytest
backend/tests/test_evaluation.py` runs the tests for this module.

## What is compared

| Method id | What it is |
|---|---|
| `current` | The shipped detector, `config.yaml` unchanged. |
| `threshold_10pct` | **The baseline.** Alert when a service's 60 s error rate is >= 10% and the window has >= 5 errors. No learning, no severity, no latency check. |
| `threshold_5pct`, `threshold_20pct` | The same rule at 5% and 20%, reported as a sensitivity check so the baseline is not a single hand-picked number. |
| `no_time_aware` | Ablation: `baseline.time_aware: false`. Every window is judged against the service's all-hours baseline; the per-hour-of-day bucket is ignored. |
| `no_patient_impact` | Ablation: `criticality_weight=1`, `patient_factor_weight=0`. Severity = deviation x criticality; the patient-impact term is removed. |

The 10% threshold was chosen before the first run as a round, plausible alert
level (normal error rates in the generator are 0.5-3%); it was not tuned against
the results. The threshold baseline reuses the product's own 60 s / 5 s sliding
window and its minimum-evidence rule (>= 5 errors), so the only difference from
the detector is the decision rule. Consecutive flagged windows of one service
are one incident; it closes after 6 calm windows (the detector's
`service_auto_resolve_windows`), and a later flag opens a new incident.

Which methods apply to which scenarios: the HIPAA bulk-access and the
failed-login detectors are fixed rules that use no learned baseline and no
service severity, so the threshold baseline and both service ablations are
marked `n/a` for `bulk_record_access` and `failed_logins_then_success` rather
than scored as misses. The control run always applies (any method can raise a
false alarm). The headline comparison is therefore over the **service-metric
scenarios** (error spike, prior-auth failure, recovery, mild degradation, normal
control), where every method is scored on identical runs.

## Methodology

* Each scenario runs for 40 simulated minutes: 15 min of normal traffic (warm-up),
  the injection (3 or 5 min), 20 min of normal traffic. The injection interval
  is the ground-truth label.
* A run is a (scenario, seed) pair. The seed fully determines the synthetic
  stream; the same seed gives byte-identical input to every method. Default
  seeds are `11, 22, 33, 44, 55, 66, 77, 88, 99, 110` (the first three are the
  simulator benchmark's seeds).
* The `current` method and the two ablations run the real pipeline in the
  simulator's isolated, temporary SQLite database (no AWS, no email, nothing
  written to the real store).
* The unit of evaluation is the **incident** (grouped detections), not the alert.
* Time is event time (simulated), not wall-clock time.

## Metric definitions

Ground truth for a run is the injection interval `[inject_start, inject_end]` and
one expected `(kind, entity)` (for example `error_rate` on `eligibility`). A
control run (`normal_control`) has no expected incident.

Every incident the method raised is labelled by `app/evaluation/scoring.py`:

| Label | Rule |
|---|---|
| **TP** (true positive) | The first incident of the expected (kind, entity) whose first alert lies in `[inject_start, inject_end + 60 s]`. The 60 s grace exists because a 60 s sliding window still contains injected events that long after the injection stops. |
| **duplicate** | Further incidents of the expected (kind, entity) inside the same interval. Not a false alarm; counted and reported. |
| **collateral** | An incident listed in the scenario's `allowed_extra` (documented downstream effects, e.g. `prior_auth` errors while `eligibility` is down) starting at or after `inject_start`. Neither a hit nor a false alarm; counted and reported. |
| **FP** (false positive) | Every other incident: any incident in a control run; an incident before the injection; an unrelated service or user; or the expected target more than 60 s after the injection ended. |
| **FN** (false negative) | An injected run with no TP. |

Aggregates pool runs (sum the counts, then divide):

* `precision = TP / (TP + FP)`; `precision_strict = TP / (TP + FP + collateral + duplicates)`.
* `recall = TP / (TP + FN)`, over injected runs. `f1` is their harmonic mean.
* `false_alarms_per_hour = FP / simulated hours`, over all runs in the pool (including the injection windows).
* `detection delay = first alert time of the TP incident - inject_start`, in seconds of event time, **detected runs only**. A missed run has no delay; the miss is in recall. Reported as median, mean, min, max and n.
* `actionable delay` / `actionable_recall`: the same, but for the first alert at **HIGH or CRITICAL** (the severities that page or email staff in the product). A method without severity levels (the threshold) counts every alert as actionable.
* 95% Wilson intervals are shown for precision and recall.
* True negatives are not defined (there is no natural count of "non-events"), so accuracy and ROC-style metrics are not reported.

## Output format

Files written to the output directory:

| File | Content |
|---|---|
| `results.json` | Everything: `config` (seeds, scenarios, methods and their exact config overrides, full detector config, `config.yaml` sha256, scenario catalogue with labelled intervals), `runs` (one entry per method x scenario x seed with TP/FP/FN, delay, and every labelled incident), `per_scenario`, `aggregate_all_applicable`, `aggregate_service_metric_subset`, `results_sha256`, `run_info`. |
| `runs.csv` | One row per method x scenario x seed. |
| `per_scenario.csv` | Aggregates per method and scenario. |
| `aggregate.csv` | Aggregates per method for the two pools. |
| `summary.md` | The readable summary, generated from the JSON (nothing is typed by hand). |

`results_sha256` is a hash of `config` and `runs`. Two runs with the same code,
`config.yaml` and arguments have the same hash (tested, including across separate
processes with different `PYTHONHASHSEED`). `run_info` (time, machine, git commit,
whether the working tree was dirty) is recorded but excluded from the hash. To
reproduce a result, check out the recorded commit, keep `config.yaml`
(its hash is recorded) and run the same command.

## Results of the recorded run

Run on commit `6532b1b` plus the changes in this branch, 10 seeds, 7 scenarios,
6 methods (420 method-runs), `results_sha256` `9ecd906c8e1d…`. These are the
numbers from `summary.md`; regenerate it rather than trusting this copy.

Service-metric scenarios, all methods on the same runs (40 injected runs and
10 control runs per method; TP + FN = 40 in every row):

| Method | TP | FP | Distinct FP events | FN | Precision | Recall | False alarms / h | Median delay (s) |
|---|---|---|---|---|---|---|---|---|
| current | 37 | 11 | 5 | 3 | 77% | 92% | 0.333 | 5.3 |
| threshold_10pct | 40 | 0 | 0 | 0 | 100% | 100% | 0 | 12.8 |
| threshold_5pct | 40 | 34 | 14 | 0 | 54% | 100% | 1.03 | 5.4 |
| threshold_20pct | 30 | 0 | 0 | 10 | 100% | 75% | 0 | 15.4 |
| no_time_aware | 37 | 11 | 5 | 3 | 77% | 92% | 0.333 | 5.3 |
| no_patient_impact | 37 | 11 | 5 | 3 | 77% | 92% | 0.333 | 5.3 |

What the runs show, and what they do not:

* **The simple 10% threshold outperformed the current detector on this synthetic
  data**: no misses and no false alarms, versus 3 misses (all in `mild_degradation`)
  and 11 false-positive incidents. It is slower on abrupt spikes (median 12.8 s
  vs 5.3 s) because the learned z-score fires on the first abnormal window while
  a fixed 10% needs the error rate to climb. The result is sensitive to the
  threshold: 5% produces 34 false positives and 20% misses the mild degradation.
  The sweep shows a *sweet spot exists* for this generator, not that 10% is
  generally right. The learned baseline's expected advantage (adapting to a
  service's own normal level and to time of day) is not exercised by a generator
  whose normal error rates are fixed and similar across services.
* **Time-aware baselines: no measurable effect.** `no_time_aware` is identical to
  `current` on every run. This is expected, not a finding about the design: the
  generator has no time-of-day variation in error rates or latency, and every
  simulated run stays within one UTC hour, so the hourly bucket and the global
  bucket hold the same values. Testing this component needs synthetic data with a
  daily cycle (see "Decisions" below).
* **Patient-impact scoring: affects severity, not detection.** Detection (an
  incident being opened) does not depend on severity; `recall` is unchanged. HIGH+
  (actionable) recall changed from 75% to 90% when the term is removed, but that
  mixes two effects (the patient term is gone *and* criticality now has weight 1
  instead of 0.5, shifting scores up against unchanged thresholds), so it should not
  be read as "patient impact makes the system worse". A fair test needs
  re-tuned thresholds and a ground-truth notion of which incidents deserve to
  page.
* The detector's rule-based scenarios (`bulk_record_access`,
  `failed_logins_then_success`) were detected in 10/10 seeds with median delays
  of about 204 s and 203 s. These delays are dominated by when the scenario's
  pattern becomes *observable* (the 200th distinct patient / the successful login
  after the failures), not by detector latency. The detector is rule-based there,
  so "10/10" confirms the rule fires on its own scenario; it is not an accuracy
  estimate.
* `mild_degradation` (the documented known limit) was detected in 7/10 seeds, and
  never reached HIGH. It is reported as-is.

### False positives, and their independence

The `current` detector raised 16 false-positive incidents over 70 runs, but only
7 distinct events from 3 seeds (33, 66, 88). Runs with the same seed share the
same warm-up traffic, so one chance fluctuation recurs in several scenarios.
**Every one of them was LOW severity** (none would page or email staff), and all
were error-rate or latency series of `batch` and `eligibility`. Only the seed-33 `batch`
event was root-caused (next section); the other two were not individually analysed. Treat the effective sample size for false alarms as about the number
of seeds, not the number of runs, and note that the reported Wilson intervals
assume independent runs and are therefore too narrow.

## The simulator's documented false positive (seed 33)

`docs/simulator.md` reports 1 false positive in 3 control runs (seed 33). This
was investigated rather than suppressed:

* **What it is:** `normal_control`, seed 33, raises a single `error_rate` incident
  on `batch` at 16:30:00 UTC, peak severity LOW, resolved after 30 s. It also
  appears in the `failed_logins_then_success` run with the same seed (they share
  that stretch of traffic), which is why that simulator run also reports one false
  positive.
* **Cause (reproduced):** `batch` is the lowest-volume service (about 100-130
  events per 60 s window, normal error rate about 1%). In one window of 100 events
  5 were errors: 5.0%. That window clears all three guards at once: z = 3.95 (the
  standard deviation is floored at 0.01, so z >= 3 means only +3 percentage points
  over a 1.05% baseline), `errors >= 5`, and `error_rate >= 5%`. With about 1-1.3 expected
  errors per window, observing 5 or more has probability roughly 0.4-1% for a single window
  (Poisson tail; computed, not simulated). A 40-minute run contains about 480 overlapping
  windows for this service, so a chance event of this kind is plausible in a minority of
  seeds; it was seen in 1 of the 10 seeds here. It is small-sample noise passing a
  per-window rule, not a bug in the scenario or the evaluation code.
* **What severity does:** `batch` has criticality 0.3 and few patients involved, so the
  alert scored LOW. LOW and MEDIUM never email or page staff, so the false alarm is
  visible on the dashboard only.
* **Regression coverage:** `backend/tests/test_evaluation.py` pins both the
  mechanism (`test_false_positive_mechanism_...`: 5/100 fires, 4/100 does not) and
  the end-to-end outcome (`test_documented_false_positive_is_counted_not_hidden`:
  the seed-33 control run must report exactly one LOW `batch` false positive).
  If a detector change removes it, that test should be updated deliberately
  together with this page. The detector thresholds were **not** changed to hide it.
* **Options if you want it fixed (not done, because it changes the detector under
  test):** require a statistically meaningful count (for example a Poisson tail
  probability for the observed error count instead of a normal z-score), raise
  `error_rate_min_errors` for low-volume services, or require two consecutive
  anomalous windows. Each changes recall on `mild_degradation`, so it should be
  evaluated with this harness before adopting.

## Limitations

* One synthetic generator, authored with the detector; no real logs and no external
  data set. Results do not transfer to real traffic.
* Runs with the same seed are not independent (shared warm-up traffic). Confidence
  intervals are optimistic; report seeds as the sample size or use more seeds and
  a seed-level (cluster) analysis.
* The time-aware ablation cannot show a benefit on current data (see above).
* The patient-impact ablation changes the score scale and is not tuned.
* Large, abrupt injected anomalies dominate; slow drifts, bursty traffic, several
  simultaneous incidents and gradual baseline poisoning are not measured.
* The access and login detectors are fixed rules; there is no learned alternative
  to compare them against, and no ground truth beyond their own scenarios.
* Scenario labels are one expected (kind, entity) per scenario. Related incidents are
  reported as `collateral`, a judgement recorded in `allowed_extra`; `precision_strict`
  shows the effect of counting them as errors (52% pooled).
* Detection delay depends on the scenario shape (for example, when the 200th
  distinct patient is reached), not only on the detector.
* The product's real-time behaviour (queues, WebSocket, email, restart) is not part of
  this evaluation; it runs the detection logic headlessly.

## Decisions to make before writing a paper

1. **Time-of-day data.** To say anything about time-aware baselines, the generator
   needs a daily error-rate/latency cycle and runs spanning several hours. Decide
   whether to add that scenario family.
2. **Baselines.** The threshold baseline is simple but competitive here. Decide
   whether a stronger non-learned comparator (static z-score from a fixed training
   period, or a Poisson test) belongs in the comparison, and whether the fixed
   threshold is a fair "simple baseline" or a strawman in the other direction.
3. **Tuning protocol.** The detector's settings in `config.yaml` were tuned on the
   same generator (the file's comments say so). A paper needs separate tuning and
   test seeds, or a statement that all numbers are in-sample.
4. **False-positive fix.** Decide whether to change the detector (see options above)
   before final numbers are produced.
5. **Number of seeds** and whether to analyse by seed (cluster) rather than by run.

To run the detector on a dataset of your own, see [user-datasets.md](user-datasets.md).
