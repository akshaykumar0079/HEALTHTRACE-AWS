"""Ground-truth matching and metrics for the detector evaluation.

Pure functions: no pipeline, no I/O, no clock. Every definition here is the one
documented in docs/evaluation.md; change them together.

Unit of evaluation: the **incident** (one grouped detection, as the on-call
person would see it), not the individual alert or window.

Ground truth for one run is the labelled injection interval
``[inject_start, inject_end]`` plus the single (kind, entity) the scenario is
meant to trigger. A run with no expectation is a *control*: every incident in it
is a false alarm.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

ACTIONABLE = ("HIGH", "CRITICAL")   # severities that page/email staff in the product


@dataclass(frozen=True)
class Detection:
    """One incident-level detection from any method."""

    kind: str
    entity: str
    first_ts: datetime                         # event time of the first alert
    peak_severity: Optional[str] = None        # None for methods that have no severity
    first_actionable_ts: Optional[datetime] = None   # first alert at HIGH/CRITICAL (or first alert, if no severity)
    last_ts: Optional[datetime] = None               # last alert of the incident (descriptive output only)
    alert_count: int = 0


@dataclass(frozen=True)
class Truth:
    inject_start: datetime
    inject_end: datetime
    sim_hours: float
    kind: Optional[str] = None                 # None => control run (nothing was injected)
    entity: Optional[str] = None
    # (kind, entity) pairs that are documented, genuine downstream effects of the
    # injection (e.g. prior_auth errors while eligibility is down). Reported
    # separately; never silently counted as correct and never as false alarms.
    collateral: frozenset = frozenset()
    # A 60 s sliding window still contains injected events for up to 60 s after the
    # injection ends, so a first alert that late is still caused by the injection.
    grace_s: float = 60.0

    @property
    def injected(self) -> bool:
        return self.kind is not None


@dataclass
class RunScore:
    injected: bool
    tp: int = 0
    fp: int = 0
    fn: int = 0
    collateral: int = 0
    duplicates: int = 0
    delay_s: Optional[float] = None            # first alert of the TP incident - inject_start
    actionable_delay_s: Optional[float] = None  # same, but first HIGH/CRITICAL alert
    actionable_detected: Optional[bool] = None  # injected runs only
    sim_hours: float = 0.0
    labels: list[dict] = field(default_factory=list)   # one entry per detection, with the reason


def score_run(truth: Truth, detections: list[Detection]) -> RunScore:
    """Label every detection and derive TP/FP/FN for one run.

    * TP  - the first incident of the expected (kind, entity) whose first alert
            lies in [inject_start, inject_end + grace_s] (grace_s = 60).
    * duplicate - a further incident for the same (kind, entity) inside that
            interval (the problem was split across incidents). Not a false alarm,
            but counted and reported.
    * collateral - a documented downstream effect of the injection that starts at
            or after inject_start. Not a false alarm, not a hit.
    * FP  - everything else: any incident in a control run, an incident before the
            injection, an unrelated service/user, or the right kind/entity more than
            grace_s after the injection ended.
    * FN  - an injected run with no TP.
    """
    score = RunScore(injected=truth.injected, sim_hours=truth.sim_hours)
    tp_found = False
    for d in sorted(detections, key=lambda x: (x.first_ts, x.kind, x.entity)):
        in_window = truth.inject_start <= d.first_ts <= truth.inject_end + timedelta(seconds=truth.grace_s)
        is_target = truth.injected and d.kind == truth.kind and d.entity == truth.entity
        if is_target and in_window and not tp_found:
            tp_found = True
            score.tp = 1
            score.delay_s = round((d.first_ts - truth.inject_start).total_seconds(), 1)
            if d.first_actionable_ts is not None:
                score.actionable_delay_s = round((d.first_actionable_ts - truth.inject_start).total_seconds(), 1)
            score.actionable_detected = d.first_actionable_ts is not None
            label = "tp"
        elif is_target and in_window:
            score.duplicates += 1
            label = "duplicate"
        elif (d.kind, d.entity) in truth.collateral and d.first_ts >= truth.inject_start:
            score.collateral += 1
            label = "collateral"
        else:
            score.fp += 1
            label = "fp"
            if not truth.injected:
                reason = "control run: nothing was injected"
            elif d.first_ts < truth.inject_start:
                reason = "before the injection"
            elif is_target:
                reason = "after the injection ended"
            else:
                reason = "unrelated kind/entity"
            score.labels.append({"label": label, "reason": reason, **_det(d)})
            continue
        score.labels.append({"label": label, **_det(d)})
    if truth.injected and not tp_found:
        score.fn = 1
        score.actionable_detected = False
    return score


def _det(d: Detection) -> dict:
    return {"kind": d.kind, "entity": d.entity, "first_ts": d.first_ts.isoformat(),
            "peak_severity": d.peak_severity}


# -- aggregation -----------------------------------------------------------------------------


def wilson_interval(successes: int, n: int, z: float = 1.96) -> Optional[tuple[float, float]]:
    """95% Wilson score interval for a proportion; None when n == 0. Used because
    the number of runs is small and a bare percentage would overstate certainty."""
    if n <= 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)


def _ratio(num: int, den: int) -> Optional[float]:
    return round(num / den, 3) if den else None


def _stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "median": None, "mean": None, "min": None, "max": None}
    return {"n": len(values), "median": round(statistics.median(values), 1),
            "mean": round(statistics.fmean(values), 1), "min": min(values), "max": max(values)}


def aggregate(scores: list[RunScore]) -> dict:
    """Pool runs (micro-average: sum the counts, then divide).

    precision        = TP / (TP + FP)               collateral/duplicates in neither term
    precision_strict = TP / (TP + FP + collateral + duplicates)
    recall           = TP / (TP + FN)               over injected runs only
    f1               = harmonic mean of precision and recall
    false_alarms_per_hour = FP / simulated hours    over every run in the pool
    delay            = first-alert time - inject_start, detected runs only (a missed run has
                       no delay; the miss is in recall, not hidden in the delay)
    """
    tp = sum(s.tp for s in scores)
    fp = sum(s.fp for s in scores)
    fn = sum(s.fn for s in scores)
    collateral = sum(s.collateral for s in scores)
    duplicates = sum(s.duplicates for s in scores)
    injected = [s for s in scores if s.injected]
    hours = sum(s.sim_hours for s in scores)
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else (
        0.0 if precision is not None and recall is not None else None)
    actionable = sum(1 for s in injected if s.actionable_detected)
    return {
        "runs": len(scores), "injected_runs": len(injected),
        "control_runs": len(scores) - len(injected),
        "tp": tp, "fp": fp, "fn": fn, "collateral": collateral, "duplicates": duplicates,
        "precision": precision, "precision_ci95": wilson_interval(tp, tp + fp),
        "precision_strict": _ratio(tp, tp + fp + collateral + duplicates),
        "recall": recall, "recall_ci95": wilson_interval(tp, tp + fn),
        "f1": f1,
        "actionable_recall": _ratio(actionable, len(injected)),
        "simulated_hours": round(hours, 3),
        "false_alarms_per_hour": round(fp / hours, 3) if hours else None,
        "runs_with_false_alarm": sum(1 for s in scores if s.fp > 0),
        "delay_s": _stats([s.delay_s for s in scores if s.delay_s is not None]),
        "actionable_delay_s": _stats([s.actionable_delay_s for s in scores if s.actionable_delay_s is not None]),
    }
