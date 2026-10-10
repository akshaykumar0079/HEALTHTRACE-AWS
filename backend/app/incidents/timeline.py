"""Incident Time Machine: a read-only timeline assembled from persisted data.

Sources (nothing here is fabricated, and nothing is ever written):

* ``metrics``   persisted 60s-window metrics of the incident's service
                (observed vs baseline), when they were stored;
* ``alerts``    alerts attached to the incident, plus other alerts for the
                same service/user in the window ("related");
* ``lifecycle`` the incident's own events (opened, escalated, acknowledged ...);
* ``evidence``  the masked log records stored as evidence.

Raw application/audit logs are not retained after processing, so context
*before* an incident comes from window metrics and related alerts only. The
``coverage`` block states exactly what existed, what is missing and why
(never stored, throttled, or deleted by retention) so an investigator is never
shown a silently empty or invented history.

Phases are relative to the incident: ``before`` (< opened_at), ``during``
(opened_at .. end) and ``after`` (> end), where end is resolved_at, else now.
Both ends of every window are inclusive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Callable, Optional

from app.config import AppConfig
from app.incidents.explain import explain_detection
from app.models import Alert, Incident, IncidentEvent, WindowMetrics

MAX_WINDOW_MINUTES = 24 * 60
DEFAULT_WINDOW_MINUTES = 15.0
ALL_SOURCES = ("metrics", "alerts", "lifecycle", "evidence")
EVIDENCE_CAP = 200


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _parse(value: Any) -> Optional[datetime]:
    try:
        return _aware(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except (TypeError, ValueError):
        return None


@dataclass
class TimelineQuery:
    before_minutes: float = DEFAULT_WINDOW_MINUTES
    after_minutes: float = DEFAULT_WINDOW_MINUTES
    max_metric_points: int = 240
    sources: tuple[str, ...] = ALL_SOURCES
    as_of: Optional[datetime] = None

    def clamp(self) -> "TimelineQuery":
        self.before_minutes = max(0.0, min(float(self.before_minutes), MAX_WINDOW_MINUTES))
        self.after_minutes = max(0.0, min(float(self.after_minutes), MAX_WINDOW_MINUTES))
        self.max_metric_points = max(10, min(int(self.max_metric_points), 2000))
        return self


@dataclass
class TimelineData:
    """What the store returned. Kept separate so assembly is a pure function."""

    incident: Incident
    events: list[IncidentEvent] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)            # attached to the incident
    related_alerts: list[Alert] = field(default_factory=list)    # same source, other incidents, in the window
    evidence: list[dict[str, Any]] = field(default_factory=list)
    metrics: list[WindowMetrics] = field(default_factory=list)
    earliest_metric: Optional[datetime] = None
    metrics_total_for_service: int = 0


def incident_bounds(incident: Incident, now: datetime) -> tuple[datetime, datetime]:
    start = _aware(incident.opened_at)
    end = _aware(incident.resolved_at) if incident.resolved_at else now
    return start, max(end, start)


def window_for(incident: Incident, query: TimelineQuery, now: datetime) -> tuple[datetime, datetime]:
    start, end = incident_bounds(incident, now)
    return start - timedelta(minutes=query.before_minutes), end + timedelta(minutes=query.after_minutes)


def phase_of(ts: datetime, start: datetime, end: datetime) -> str:
    if ts < start:
        return "before"
    if ts > end:
        return "after"
    return "during"


# -- entries ------------------------------------------------------------------

_COMPONENT = {"metrics": None, "alerts": "detector", "lifecycle": "incident workflow"}


def _evidence_component(record: dict[str, Any]) -> str:
    kind = record.get("type")
    if kind == "audit":
        return "patient record access"
    if kind == "auth":
        return "authentication"
    return str(record.get("service") or "application")


def metric_entry(m: WindowMetrics, incident: Incident, config: AppConfig) -> dict[str, Any]:
    a = config.anomaly
    std = m.baseline_std
    z = None
    breach = None
    if m.baseline_mean is not None:
        eff = max(std if std is not None else 0.0, a.min_std)
        z = (m.error_rate - m.baseline_mean) / eff
        breach = bool(z >= a.error_rate_z_threshold and m.errors >= a.error_rate_min_errors
                      and m.error_rate >= a.error_rate_min_rate)
    return {
        "id": f"metric:{_aware(m.window_end).isoformat()}",
        "ts": _aware(m.window_end).isoformat(), "source": "metrics", "event_type": "window_metric",
        "service": m.service, "component": m.service, "severity": None,
        "summary": f"{m.service}: {m.errors}/{m.total} errors ({m.error_rate:.1%}), p95 {m.p95_latency_ms:.0f} ms",
        "observed": {"error_rate": m.error_rate, "errors": m.errors, "total": m.total, "p95_latency_ms": m.p95_latency_ms},
        "baseline": None if m.baseline_mean is None else {"error_rate_mean": m.baseline_mean, "error_rate_std": std},
        "z": z, "breaches_threshold": breach,
    }


def alert_entry(alert: Alert, incident: Incident, related: bool) -> dict[str, Any]:
    return {
        "id": f"alert:{alert.id}", "ts": _aware(alert.ts).isoformat(), "source": "alerts",
        "event_type": "related_alert" if related else "alert", "service": alert.service,
        "component": _COMPONENT["alerts"], "severity": alert.severity, "summary": alert.explanation,
        "alert_kind": alert.kind, "incident_id": alert.incident_id, "related": related,
    }


def lifecycle_entry(event: IncidentEvent) -> dict[str, Any]:
    labels = {"opened": "Incident opened", "alert_attached": "Another alert attached", "escalated": "Severity escalated",
              "acknowledged": "Acknowledged", "investigating": "Investigation started", "resolved": "Resolved",
              "auto_resolved": "Auto-resolved", "muted": "Notifications muted", "pinned": "Pinned", "unpinned": "Unpinned",
              "reopened": "Reopened"}
    summary = labels.get(event.event_type, event.event_type)
    if event.detail:
        summary = f"{summary}: {event.detail}"
    return {
        "id": f"lifecycle:{event.id}", "ts": _aware(event.ts).isoformat(), "source": "lifecycle",
        "event_type": event.event_type, "service": None, "component": _COMPONENT["lifecycle"],
        "severity": event.severity, "summary": summary,
    }


def evidence_entry(row: dict[str, Any]) -> dict[str, Any]:
    record = row["record"]
    return {
        "id": f"evidence:{row['id']}", "ts": row["ts"], "source": "evidence",
        "event_type": f"{record.get('type', 'app')}_log", "service": record.get("service"),
        "component": _evidence_component(record), "severity": None, "level": _level_to_severity(record.get("level")),
        "summary": str(record.get("msg") or record.get("action") or "log record")[:300], "alert_id": row.get("alert_id"),
    }


def _level_to_severity(level: Optional[str]) -> Optional[str]:
    # A log *level*, kept in its own field so it is never mistaken for incident severity.
    return {"ERROR": "ERROR", "WARN": "WARN", "INFO": "INFO"}.get(str(level or "").upper())


# -- coverage -----------------------------------------------------------------


def _gaps(points: list[datetime], expected: float) -> list[dict[str, Any]]:
    out = []
    for a, b in zip(points, points[1:]):
        delta = (b - a).total_seconds()
        if delta > max(expected * 3, 30.0):
            out.append({"from": a.isoformat(), "to": b.isoformat(), "seconds": round(delta, 1)})
    return out


def metrics_coverage(
    data: TimelineData, win_from: datetime, win_to: datetime, now: datetime, retention_hours: int
) -> dict[str, Any]:
    incident = data.incident
    horizon = now - timedelta(hours=retention_hours) if retention_hours else None
    if incident.service is None:
        return {"applicable": False, "status": "not_applicable", "points": 0, "gaps": [],
                "message": "This incident is user-based (access or login rules); it has no per-service window metrics."}
    effective_to = min(win_to, now)
    points = sorted(_aware(m.window_end) for m in data.metrics)
    if not points:
        expired = horizon is not None and win_from < horizon
        if expired and (data.earliest_metric is None or data.earliest_metric > win_from):
            return {"applicable": True, "status": "expired", "points": 0, "gaps": [],
                    "message": f"Window metrics older than {retention_hours} h are deleted by the retention policy, "
                               "so none exist for this period."}
        return {"applicable": True, "status": "none", "points": 0, "gaps": [],
                "message": "No window metrics were stored for this period (collection may have been stopped, "
                           "or persistence is throttled)."}
    spacings = [(b - a).total_seconds() for a, b in zip(points, points[1:]) if b > a]
    expected = median(spacings) if spacings else 60.0
    gaps = _gaps(points, expected)
    lead_missing = (points[0] - win_from).total_seconds() > max(expected * 3, 30.0)
    tail_missing = (effective_to - points[-1]).total_seconds() > max(expected * 3, 30.0)
    expired_lead = lead_missing and horizon is not None and win_from < horizon
    partial = bool(gaps) or lead_missing or tail_missing
    notes = []
    if expired_lead:
        notes.append(f"History before {horizon.isoformat()} was removed by retention ({retention_hours} h).")
    elif lead_missing:
        notes.append("No metrics exist before the first stored point.")
    if tail_missing:
        notes.append("No metrics exist after the last stored point.")
    if gaps:
        notes.append(f"{len(gaps)} gap(s) in stored metrics.")
    return {"applicable": True, "status": "partial" if partial else "complete", "points": len(points),
            "first": points[0].isoformat(), "last": points[-1].isoformat(),
            "expected_interval_seconds": round(expected, 1), "gaps": gaps[:20],
            "message": " ".join(notes) or "Window metrics cover the requested range."}


# -- reconstruction -----------------------------------------------------------


def reconstruct_state(
    incident: Incident, events: list[IncidentEvent], alerts: list[Alert], as_of: datetime
) -> dict[str, Any]:
    """The incident as it was at ``as_of``, replayed from its stored events.
    Pure: the stored records are never modified."""
    as_of = _aware(as_of)
    seen = [e for e in events if _aware(e.ts) <= as_of]
    status = "NOT_YET_OPENED" if _aware(incident.opened_at) > as_of and not seen else "OPEN"
    severity: Optional[str] = None
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for e in seen:
        if e.event_type in ("opened", "alert_attached", "escalated", "reopened") and e.severity:
            if severity is None or order[e.severity] > order[severity]:
                severity = e.severity
        if e.event_type in ("opened", "reopened"):
            status = "OPEN"
        elif e.event_type == "acknowledged":
            status = "ACKNOWLEDGED"
        elif e.event_type == "investigating":
            status = "INVESTIGATING"
        elif e.event_type in ("resolved", "auto_resolved"):
            status = "RESOLVED"
    attached = [a for a in alerts if _aware(a.ts) <= as_of]
    return {
        "as_of": as_of.isoformat(), "status": status, "severity": severity, "occurrences": len(attached),
        "events_applied": len(seen),
        "last_alert_ts": max((_aware(a.ts) for a in attached), default=None).isoformat() if attached else None,
    }


# -- assembly -----------------------------------------------------------------


def _downsample(items: list[Any], limit: int) -> tuple[list[Any], int]:
    if len(items) <= limit:
        return items, 1
    stride = -(-len(items) // limit)
    kept = items[::stride]
    if items[-1] is not kept[-1]:
        kept.append(items[-1])
    return kept, stride


def build_timeline(
    data: TimelineData, query: TimelineQuery, config: AppConfig, *, now: Optional[datetime] = None,
    retention_hours: int = 24, redact: Optional[Callable[[Any], Any]] = None,
) -> dict[str, Any]:
    now = _aware(now or datetime.now(timezone.utc))
    query.clamp()
    incident = data.incident
    start, end = incident_bounds(incident, now)
    win_from, win_to = window_for(incident, query, now)
    cutoff = _aware(query.as_of) if query.as_of else None
    notes: list[str] = []

    def inside(ts: datetime) -> bool:
        ts = _aware(ts)
        return win_from <= ts <= win_to and (cutoff is None or ts <= cutoff)

    entries: list[dict[str, Any]] = []
    downsample = {"applied": False, "stride": 1, "metric_points_in_window": 0}

    if "metrics" in query.sources:
        in_win = [m for m in data.metrics if inside(m.window_end)]
        kept, stride = _downsample(in_win, query.max_metric_points)
        downsample = {"applied": stride > 1, "stride": stride, "metric_points_in_window": len(in_win)}
        entries += [metric_entry(m, incident, config) for m in kept]
    if "alerts" in query.sources:
        entries += [alert_entry(a, incident, False) for a in data.alerts if inside(a.ts)]
        attached_ids = {a.id for a in data.alerts}
        entries += [alert_entry(a, incident, True) for a in data.related_alerts
                    if a.id not in attached_ids and inside(a.ts)]
    if "lifecycle" in query.sources:
        entries += [lifecycle_entry(e) for e in data.events if inside(e.ts)]
    if "evidence" in query.sources:
        for row in data.evidence:
            ts = _parse(row.get("ts"))
            if ts is not None and inside(ts):
                entries.append(evidence_entry(row))

    for entry in entries:
        ts = _parse(entry["ts"]) or start
        entry["phase"] = phase_of(ts, start, end)
        entry["_sort"] = ts
    # Chronological; ties keep a stable, explainable order (lifecycle, alert, evidence, metric).
    rank = {"lifecycle": 0, "alerts": 1, "evidence": 2, "metrics": 3}
    entries.sort(key=lambda e: (e["_sort"], rank.get(e["source"], 9), e["id"]))
    for entry in entries:
        entry.pop("_sort", None)
    if redact:
        for entry in entries:
            entry["summary"] = redact(entry["summary"])

    cov_metrics = metrics_coverage(data, win_from, win_to, now, retention_hours)
    evidence_count = len(data.evidence)
    coverage = {
        "window": {"from": win_from.isoformat(), "to": win_to.isoformat()},
        "metrics": cov_metrics,
        "evidence": {
            "stored": evidence_count, "cap": EVIDENCE_CAP,
            "status": "none" if evidence_count == 0 else ("capped" if evidence_count >= EVIDENCE_CAP else "available"),
            "message": ("No evidence records were stored for this incident." if evidence_count == 0 else
                        f"{evidence_count} masked log record(s) stored" + (" (cap reached; later records were not kept)." if evidence_count >= EVIDENCE_CAP else ".")),
        },
        "raw_logs": "Raw application and audit logs are not retained after processing; only evidence records, "
                    "window metrics, alerts and lifecycle events are stored.",
        "retention": {"metrics_hours": retention_hours,
                      "metrics_horizon": (now - timedelta(hours=retention_hours)).isoformat() if retention_hours else None},
    }
    if not entries:
        notes.append("No stored events fall inside this window. Nothing has been inferred or generated.")
    if cov_metrics["status"] in ("expired", "none") and cov_metrics.get("applicable"):
        notes.append(cov_metrics["message"])
    if downsample["applied"]:
        notes.append(f"Window metrics were thinned to every {downsample['stride']}th point for display "
                     f"({downsample['metric_points_in_window']} stored).")
    if incident.resolved_at is None:
        notes.append("The incident is still active; 'during' extends to now.")

    out: dict[str, Any] = {
        "incident_id": incident.id,
        "anchor": {"opened_at": start.isoformat(), "end": end.isoformat(), "resolved": incident.resolved_at is not None},
        "query": {"before_minutes": query.before_minutes, "after_minutes": query.after_minutes,
                  "sources": list(query.sources), "as_of": cutoff.isoformat() if cutoff else None},
        "entries": entries, "count": len(entries), "coverage": coverage, "downsampling": downsample,
        "explanation": explain_detection(config, incident, data.alerts), "notes": notes,
        "read_only": True,
    }
    if cutoff:
        out["state_as_of"] = reconstruct_state(incident, data.events, data.alerts, cutoff)
    return out


def entry_detail(kind: str, payload: Any, redact: Optional[Callable[[Any], Any]] = None) -> dict[str, Any]:
    """Raw, log-safe details of one selected entry."""
    if kind == "metric":
        raw = payload.model_dump(mode="json")
    elif kind == "alert":
        raw = payload.model_dump(mode="json")
    elif kind == "lifecycle":
        raw = payload.model_dump(mode="json")
    else:
        raw = payload
    return {"kind": kind, "raw": redact(raw) if redact else raw,
            "note": "Synthetic, masked, log-safe record. Identifiers are masked before storage and display."}


async def load_timeline_data(store: Any, incident: Incident, query: TimelineQuery, now: datetime) -> TimelineData:
    """Read everything the timeline needs from the store (read-only)."""
    query.clamp()
    win_from, win_to = window_for(incident, query, now)
    iid = incident.id
    events = await store.list_incident_events(iid) if iid is not None else []
    alerts = await store.list_alerts(limit=1000, incident_id=iid) if iid is not None else []
    alerts = sorted(alerts, key=lambda a: (a.ts, a.id or 0))
    evidence = await store.list_evidence(iid, limit=EVIDENCE_CAP + 50) if iid is not None else []
    related: list[Alert] = []
    if incident.service is not None:
        related = await store.list_alerts_between(start=win_from, end=win_to, service=incident.service)
    elif incident.user_id is not None:
        related = await store.list_alerts_between(start=win_from, end=win_to, user_id=incident.user_id)
    metrics: list[WindowMetrics] = []
    earliest = None
    if incident.service is not None:
        metrics = await store.list_metrics_between(service=incident.service, start=win_from, end=min(win_to, now))
        earliest = await store.earliest_metric_ts(incident.service)
    return TimelineData(incident=incident, events=events, alerts=alerts, related_alerts=related, evidence=evidence,
                        metrics=metrics, earliest_metric=earliest)
