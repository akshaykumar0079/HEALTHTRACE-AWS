"""Read-only incident intelligence: related incidents, duplicate suggestions, trend helpers.

Everything here is deterministic and explainable. Nothing is written, merged,
resolved or deleted. A score says "worth a look", never "caused by".

Privacy: signals are service, anomaly kind, time, severity, the configured
service dependency graph and the *shape* of stored evidence (log source and
level). Raw user ids, fingerprints (which can embed a user id), log text and
request/patient ids are never used as signals and never returned. The only
identity-based signal is "same pseudonymous actor", it is OFF by default
(``INCIDENT_INTEL_MATCH_ACTOR``), and even when on only the fact of a match is
reported, never the value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from app.incidents.view import KIND_TITLE, STATUS_LABEL
from app.models import Incident

DISCLAIMER = "Suggested by deterministic rules. A match is a lead for a human to check, not proof of a shared cause."
DUPLICATE_DISCLAIMER = "A possible duplicate needs human review. Nothing is merged, resolved or deleted automatically."

MIN_RELATED_SCORE = 0.40
MIN_DUPLICATE_SCORE = 0.70
MAX_CANDIDATES = 300          # bounded lookup; the response says when more existed

# Kinds that describe one person's behaviour: the incident fingerprint contains
# an actor id, so two incidents of these kinds are only duplicates if the actor
# is the same, which we may only check when actor matching is switched on.
ACTOR_SCOPED = frozenset({
    "hipaa_bulk_access", "hipaa_off_hours", "hipaa_region_mismatch", "hipaa_bulk_export", "auth_suspicious_login",
})
_FAMILY = {
    "error_rate": "reliability", "latency_degradation": "reliability",
    "hipaa_bulk_access": "phi_access", "hipaa_bulk_export": "phi_access",
    "hipaa_off_hours": "phi_access", "hipaa_region_mismatch": "phi_access",
    "auth_suspicious_login": "access_security",
}
_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass(frozen=True)
class Match:
    candidate: Incident
    score: float
    reasons: list[str]
    signals: list[str]          # machine-readable signal names, for tests and the UI
    gap_seconds: Optional[float]


@dataclass
class Evidence:
    """Shape of an incident's stored evidence: a set of (log source, level) pairs."""
    shapes: frozenset = field(default_factory=frozenset)


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _window(i: Incident) -> Optional[tuple[datetime, datetime]]:
    """[opened, end] where end is the resolve/last-seen time; None if there is no usable start."""
    start = _utc(i.opened_at)
    if start is None:
        return None
    end = _utc(i.resolved_at) or _utc(i.last_seen_at) or start
    if end < start:      # inconsistent stored data: fall back to a point in time
        end = start
    return start, end


def gap_seconds(a: Incident, b: Incident) -> Optional[float]:
    """0 when the two activity windows overlap, else the distance between them."""
    wa, wb = _window(a), _window(b)
    if wa is None or wb is None:
        return None
    if wa[0] <= wb[1] and wb[0] <= wa[1]:
        return 0.0
    return (wb[0] - wa[1]).total_seconds() if wb[0] > wa[1] else (wa[0] - wb[1]).total_seconds()


def _human(seconds: float) -> str:
    if seconds < 90:
        return f"{round(seconds)} seconds"
    if seconds < 5400:
        return f"{round(seconds / 60)} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def _time_points(gap: Optional[float]) -> tuple[float, Optional[str]]:
    if gap is None:
        return 0.0, None
    if gap == 0:
        return 0.30, "Their activity windows overlap in time."
    if gap <= 900:
        return 0.25, f"Active within {_human(gap)} of each other."
    if gap <= 3600:
        return 0.18, f"Active within {_human(gap)} of each other."
    if gap <= 6 * 3600:
        return 0.08, f"Active within {_human(gap)} of each other."
    return 0.0, None


def _jaccard(a: frozenset, b: frozenset) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def score_related(
    source: Incident,
    cand: Incident,
    *,
    graph: Optional[dict[str, Iterable[str]]] = None,
    match_actor: bool = False,
    src_evidence: Optional[Evidence] = None,
    cand_evidence: Optional[Evidence] = None,
) -> Optional[Match]:
    """Score one candidate, or return None when it is not meaningful.

    A candidate qualifies only with at least two *different kinds* of signal and
    a score >= MIN_RELATED_SCORE, so closeness in time alone never links
    incidents. Max time-only score is 0.30, which is below the threshold.
    """
    if cand.id is None or cand.id == source.id:
        return None
    points = 0.0
    reasons: list[str] = []
    signals: list[str] = []

    same_service = bool(source.service) and source.service == cand.service
    if same_service:
        points += 0.35
        reasons.append(f"Same service ({source.service}).")
        signals.append("same_service")
    elif source.service and cand.service and graph is not None:
        sg, cg = set(graph.get(source.service, ())), set(graph.get(cand.service, ()))
        if cand.service in sg or source.service in cg:
            points += 0.20
            reasons.append(f"Services are linked in the configured dependency graph ({source.service} and {cand.service}).")
            signals.append("dependent_service")

    if source.kind == cand.kind:
        points += 0.25
        reasons.append(f"Same anomaly type ({KIND_TITLE.get(source.kind, source.kind)}).")
        signals.append("same_kind")
    elif _FAMILY.get(source.kind) and _FAMILY.get(source.kind) == _FAMILY.get(cand.kind):
        points += 0.12
        reasons.append("Compatible anomaly types (same family: " + _FAMILY[source.kind].replace("_", " ") + ").")
        signals.append("compatible_kind")

    gap = gap_seconds(source, cand)
    t_points, t_reason = _time_points(gap)
    if t_points:
        points += t_points
        reasons.append(t_reason or "")
        signals.append("time_proximity")

    if match_actor and source.user_id and source.user_id == cand.user_id:
        points += 0.15
        reasons.append("Involves the same (pseudonymous) actor.")
        signals.append("same_actor")

    if src_evidence and cand_evidence and src_evidence.shapes and cand_evidence.shapes:
        overlap = _jaccard(src_evidence.shapes, cand_evidence.shapes)
        if overlap >= 0.5:
            points += 0.10
            reasons.append("Stored evidence comes from the same log sources and levels.")
            signals.append("evidence_shape")

    distinct = len({"service" if s in ("same_service", "dependent_service") else
                    "kind" if s in ("same_kind", "compatible_kind") else s for s in signals})
    score = round(min(points, 1.0), 2)
    if distinct < 2 or score < MIN_RELATED_SCORE:
        return None
    return Match(cand, score, [r for r in reasons if r], signals, gap)


def rank_related(
    source: Incident, candidates: Iterable[Incident], *, limit: int = 10, min_score: float = MIN_RELATED_SCORE, **kw: Any
) -> list[Match]:
    ev = kw.pop("evidence", {}) or {}
    matches: list[Match] = []
    for cand in candidates:
        m = score_related(source, cand, src_evidence=ev.get(source.id), cand_evidence=ev.get(cand.id), **kw)
        if m and m.score >= min_score:
            matches.append(m)
    matches.sort(key=lambda m: (-m.score, m.gap_seconds if m.gap_seconds is not None else 9e18, -(m.candidate.id or 0)))
    return matches[:limit]


# -- duplicate suggestions --------------------------------------------------------


@dataclass(frozen=True)
class DuplicateMatch:
    candidate: Incident
    confidence: str            # "likely" | "possible"
    score: float
    reasons: list[str]
    cautions: list[str]
    gap_seconds: Optional[float]


def score_duplicate(
    source: Incident, cand: Incident, *, match_actor: bool = False, max_gap_seconds: float = 1800.0
) -> Optional[DuplicateMatch]:
    """Conservative: same anomaly type AND same service AND (nearly) the same time.

    Never a duplicate: different kind, a missing service or timestamp, a gap
    larger than ``max_gap_seconds``. Actor-scoped kinds (whose grouping key is a
    person) are only compared when actor matching is on, and then only when the
    actor is the same; otherwise they are skipped, not guessed.
    """
    if cand.id is None or cand.id == source.id:
        return None
    if source.kind != cand.kind or not source.service or source.service != cand.service:
        return None
    gap = gap_seconds(source, cand)
    if gap is None or gap > max_gap_seconds:
        return None
    reasons = [f"Same anomaly type ({KIND_TITLE.get(source.kind, source.kind)}) on the same service ({source.service})."]
    points = 0.5
    cautions: list[str] = []
    if source.kind in ACTOR_SCOPED:
        if not match_actor or not source.user_id or source.user_id != cand.user_id:
            return None
        points += 0.2
        reasons.append("Involves the same (pseudonymous) actor.")
    else:
        points += 0.1
        reasons.append("Both use the same grouping rule for this service (anomaly type + service).")
    if gap == 0:
        points += 0.2
        reasons.append("Their activity windows overlap in time.")
    else:
        points += 0.1 if gap <= 600 else 0.05
        reasons.append(f"Active within {_human(gap)} of each other.")
    sa, sb = _SEV_RANK.get(source.peak_severity, -1), _SEV_RANK.get(cand.peak_severity, -1)
    if abs(sa - sb) <= 1:
        points += 0.05
    else:
        cautions.append("Peak severities differ by more than one level.")
        points -= 0.1
    if source.state == "RESOLVED" and cand.state == "RESOLVED":
        cautions.append("Both are already resolved; this may be a recurrence rather than a duplicate.")
        points -= 0.1
    score = round(max(0.0, min(points, 1.0)), 2)
    if score < MIN_DUPLICATE_SCORE:
        return None
    return DuplicateMatch(cand, "likely" if score >= 0.9 else "possible", score, reasons, cautions, gap)


def rank_duplicates(source: Incident, candidates: Iterable[Incident], *, limit: int = 5, **kw: Any) -> list[DuplicateMatch]:
    out = [m for c in candidates if (m := score_duplicate(source, c, **kw))]
    out.sort(key=lambda m: (-m.score, m.gap_seconds if m.gap_seconds is not None else 9e18, -(m.candidate.id or 0)))
    return out[:limit]


# -- response shapes (an allow-list: no user_id, fingerprint or evidence text) ----------


def summary(i: Incident) -> dict[str, Any]:
    end = _utc(i.last_seen_at) or _utc(i.opened_at)
    return {
        "id": i.id,
        "title": f"{KIND_TITLE.get(i.kind, i.kind)}: {i.service or 'no service'}",
        "kind": i.kind,
        "service": i.service,
        "state": i.state,
        "status_label": STATUS_LABEL.get(i.state, i.state),
        "severity": i.peak_severity,
        "alert_count": i.alert_count,
        "opened_at": i.opened_at.isoformat() if i.opened_at else None,
        "last_seen_at": end.isoformat() if end else None,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
    }


def related_view(source_id: int, m: Match) -> dict[str, Any]:
    return {
        "source_incident_id": source_id,
        "related_incident_id": m.candidate.id,
        "score": m.score,
        "reasons": m.reasons,
        "signals": m.signals,
        "time_gap_seconds": None if m.gap_seconds is None else round(m.gap_seconds),
        "incident": summary(m.candidate),
        "basis": "deterministic_match",
    }


def duplicate_view(source_id: int, m: DuplicateMatch) -> dict[str, Any]:
    return {
        "source_incident_id": source_id,
        "candidate_incident_id": m.candidate.id,
        "confidence": m.confidence,
        "score": m.score,
        "reasons": m.reasons,
        "cautions": m.cautions,
        "time_gap_seconds": None if m.gap_seconds is None else round(m.gap_seconds),
        "incident": summary(m.candidate),
        "requires_human_review": True,
        "basis": "deterministic_match",
    }


async def find_related(
    store: Any, source: Incident, *, graph: Optional[dict[str, Iterable[str]]], match_actor: bool, limit: int = 10,
    min_score: float = MIN_RELATED_SCORE, window_hours: float = 6.0,
) -> tuple[list[Match], int, bool]:
    """Look up candidates in the store (bounded SQL) and rank them. Returns (matches, candidates considered, whether more candidates existed than the cap)."""
    start, end = candidate_window(source, hours=window_hours)
    found = await store.incidents_overlapping(start, end, exclude_id=source.id, limit=MAX_CANDIDATES + 1)
    truncated = len(found) > MAX_CANDIDATES
    candidates = found[:MAX_CANDIDATES]
    shapes = await store.evidence_shapes([i for i in [source.id, *[c.id for c in candidates]] if i is not None])
    matches = rank_related(source, candidates, limit=limit, min_score=min_score, graph=graph,
                           match_actor=match_actor, evidence={k: Evidence(v) for k, v in shapes.items()})
    return matches, len(candidates), truncated


def candidate_window(source: Incident, *, hours: float) -> tuple[datetime, datetime]:
    """Time range in which candidates are looked up (bounded: the SQL, not Python, filters history)."""
    w = _window(source) or (_utc(source.opened_at) or datetime.now(timezone.utc),) * 2
    pad = timedelta(hours=hours)
    return w[0] - pad, w[1] + pad


# -- trends -------------------------------------------------------------------------

MIN_RESOLUTION_SAMPLE = 5


def _percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile of a non-empty sorted list."""
    import math
    idx = max(0, min(len(sorted_values) - 1, math.ceil(q * len(sorted_values)) - 1))
    return sorted_values[idx]


def _bucket_keys(since: datetime, until: datetime, bucket: str) -> list[str]:
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    t = since.replace(minute=0, second=0, microsecond=0) if bucket == "hour" else since.replace(
        hour=0, minute=0, second=0, microsecond=0)
    keys: list[str] = []
    while t < until and len(keys) < 4000:
        keys.append(t.strftime("%Y-%m-%dT%H") if bucket == "hour" else t.strftime("%Y-%m-%d"))
        t += step
    return keys


def build_trends(raw: dict[str, Any], *, since: datetime, until: datetime, bucket: str) -> dict[str, Any]:
    """Shape SQL aggregates for the API. Every number is a count from stored rows. Resolution statistics are
    reported only when at least MIN_RESOLUTION_SAMPLE valid durations exist; otherwise they are null with the
    reason, never an estimate."""
    sev_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    cells: dict[str, dict[str, int]] = {}
    for b, sev, n in raw["series"]:
        cells.setdefault(b, {})[sev] = cells.get(b, {}).get(sev, 0) + n
    keys = _bucket_keys(since, until, bucket)
    series = []
    for k in keys:
        row = cells.get(k, {})
        series.append({"bucket": k, "total": sum(row.values()), **{s: row.get(s, 0) for s in sev_order}})
    total = sum(n for _, n in raw["by_severity"])
    state = dict(raw["by_state"])
    open_n = sum(state.get(s, 0) for s in ("OPEN", "ACKNOWLEDGED", "INVESTIGATING"))
    durations = sorted(raw["durations"])
    if len(durations) >= MIN_RESOLUTION_SAMPLE:
        resolution: dict[str, Any] = {
            "available": True, "sample_size": len(durations), "median_seconds": round(_percentile(durations, 0.5)),
            "p90_seconds": round(_percentile(durations, 0.9)), "max_seconds": round(durations[-1]), "reason": None,
        }
    else:
        resolution = {
            "available": False, "sample_size": len(durations), "median_seconds": None, "p90_seconds": None,
            "max_seconds": None,
            "reason": f"Only {len(durations)} resolved incident(s) with valid timestamps; at least "
                      f"{MIN_RESOLUTION_SAMPLE} are needed.",
        }
    return {
        "range": {"since": since.isoformat(), "until": until.isoformat(), "bucket": bucket},
        "total": total,
        "series": series,
        "by_severity": [{"key": s, "count": dict(raw["by_severity"]).get(s, 0)} for s in sev_order],
        "by_service": [{"key": k, "label": k or "No service", "count": n} for k, n in raw["by_service"]],
        "by_kind": [{"key": k, "label": KIND_TITLE.get(k, k), "count": n} for k, n in raw["by_kind"]],
        "status": {"open": open_n, "resolved": state.get("RESOLVED", 0), "by_state": state},
        "recurring": [
            {"kind": k, "label": KIND_TITLE.get(k, k), "service": svc, "count": n, "first_opened_at": first,
             "last_opened_at": last, "reopen_count": reopens}
            for k, svc, n, first, last, reopens in raw["recurring"]
        ],
        "resolution": resolution,
        "resolved_without_valid_duration": max(0, raw["resolved_total"] - len(raw["durations"])),
        "basis": "Counts of stored incidents opened in the range. Nothing is estimated or simulated by this view.",
    }
