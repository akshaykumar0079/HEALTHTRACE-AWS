"""Ground truth from a user's label column, and the metrics that follow from it.

Only used when the user maps a label column and says which values mean "anomaly". Without that, no
precision, recall or false-alarm rate is computed anywhere (see ``service.py``).

Definitions (docs/user-datasets.md):

* An **interval** is a run of rows labelled as anomalies for one entity (a service in a service log, a pseudonymous
  user in an audit/auth log; or the whole dataset when ``scope = dataset``). Rows closer together than
  ``merge_gap_seconds`` belong to the same interval.
* An incident is a **TP** when the first matching incident of an interval has its first alert in
  ``[interval start, interval end + 60 s]`` and the same entity. Further incidents of that entity in the interval
  are *duplicates* (not errors). Detection delay = first alert - interval start.
* An interval with no such incident is a **FN**. Every other incident is a **FP**: the labels are treated as
  exhaustive, so an incident outside every labelled interval counts as a false alarm.
* False-alarm rate = FP per hour of the dataset's time span.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from app.evaluation.scoring import Detection, RunScore, aggregate
from app.research.convert import Point

GRACE_SECONDS = 60.0     # a 60 s detection window still contains the anomaly this long after it ends
ANY = "*"


@dataclass(frozen=True)
class Interval:
    entity: str
    start: datetime
    end: datetime
    rows: int


def build_intervals(points: list[Point], *, scope: str, merge_gap_seconds: float) -> list[Interval]:
    groups: dict[str, list[datetime]] = {}
    for p in points:
        if p.positive:
            groups.setdefault(ANY if scope == "dataset" else p.entity, []).append(p.ts)
    out: list[Interval] = []
    for entity, stamps in groups.items():
        stamps.sort()
        start = prev = stamps[0]
        n = 1
        for ts in stamps[1:]:
            if (ts - prev).total_seconds() <= merge_gap_seconds:
                prev, n = ts, n + 1
            else:
                out.append(Interval(entity, start, prev, n))
                start = prev = ts
                n = 1
        out.append(Interval(entity, start, prev, n))
    return sorted(out, key=lambda i: (i.start, i.entity))


def score_intervals(intervals: list[Interval], detections: list[Detection], *, span_hours: float,
                    warmup_seconds: float, data_start: Optional[datetime]) -> dict[str, Any]:
    """Metrics plus a per-interval breakdown. ``span_hours`` is the time span of the data."""
    used: set[int] = set()
    scores: list[RunScore] = []
    details: list[dict[str, Any]] = []
    dets = sorted(enumerate(detections), key=lambda x: (x[1].first_ts, x[1].kind, x[1].entity))
    duplicates = 0
    for iv in intervals:
        limit = iv.end + timedelta(seconds=GRACE_SECONDS)
        hit: Optional[Detection] = None
        for idx, d in dets:
            if idx in used:
                continue
            if (iv.entity == ANY or d.entity == iv.entity) and iv.start <= d.first_ts <= limit:
                if hit is None:
                    hit = d
                    used.add(idx)
                else:
                    used.add(idx)
                    duplicates += 1
        s = RunScore(injected=True)
        if hit is not None:
            s.tp = 1
            s.delay_s = round((hit.first_ts - iv.start).total_seconds(), 1)
            s.actionable_delay_s = (round((hit.first_actionable_ts - iv.start).total_seconds(), 1)
                                    if hit.first_actionable_ts else None)
            s.actionable_detected = hit.first_actionable_ts is not None
        else:
            s.fn = 1
            s.actionable_detected = False
        scores.append(s)
        in_warmup = data_start is not None and (iv.start - data_start).total_seconds() < warmup_seconds
        details.append({
            "entity": iv.entity, "start": iv.start.isoformat(), "end": iv.end.isoformat(), "labelled_rows": iv.rows,
            "detected": hit is not None, "delay_s": s.delay_s,
            "detected_by": {"kind": hit.kind, "entity": hit.entity, "first_alert_at": hit.first_ts.isoformat(),
                            "peak_severity": hit.peak_severity} if hit else None,
            "starts_in_detector_warmup": in_warmup,
        })
    false_alarms = [d for idx, d in dets if idx not in used]
    tail = RunScore(injected=False, fp=len(false_alarms), sim_hours=span_hours)
    scores.append(tail)
    agg = aggregate(scores)
    keep = ("tp", "fp", "fn", "precision", "precision_ci95", "recall", "recall_ci95", "f1", "actionable_recall",
            "false_alarms_per_hour", "delay_s", "actionable_delay_s")
    metrics = {k: agg[k] for k in keep}
    metrics.update({"duplicates": duplicates, "intervals": len(intervals), "span_hours": round(span_hours, 4)})
    return {
        "metrics": metrics, "intervals": details,
        "false_alarms": [{"kind": d.kind, "entity": d.entity, "first_alert_at": d.first_ts.isoformat(),
                          "peak_severity": d.peak_severity} for d in false_alarms[:100]],
    }
