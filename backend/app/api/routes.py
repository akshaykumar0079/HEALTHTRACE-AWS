"""REST API (SPEC.md section 6.11), plus the read models the dashboard needs."""

from __future__ import annotations

import asyncio
import hmac
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.api.auth import PERMISSIONS, caller_for, configured_tokens, read_requires_auth, require_admin, require_operator
from app.api.auth import read_access
from app.correlation.engine import RULES as CORRELATION_RULES, CorrelationEngine, correlate
from app.correlation.events import ADAPTER_STATUS, normalize_all
from app.correlation.synthetic import demo_records
from app.demo import MAX_DURATION_S, MIN_DURATION_S, SCENARIO_NAMES, SCENARIOS
from app.incidents.timeline import (
    TimelineQuery, build_timeline, entry_detail, load_timeline_data, ALL_SOURCES,
)
from app.ai.service import InsightService, TooSoon
from app.incidents import related as intel
from app.incidents.explain import detection_rule
from app.incidents.view import KIND_TITLE, STATUS_LABEL, incident_view
from app.models import Incident, IncidentEvent
from app.notify.mailer import ALLOWED_MIN_SEVERITIES, parse_recipients
from app.pipeline import Pipeline
from app.simulation.runner import run_benchmark, run_scenario_threaded
from app.simulation.scenarios import DEFAULT_BENCHMARK_SEEDS, SCENARIOS as SIM_SCENARIOS
from app.simulation.scenarios import list_scenarios as list_sim_scenarios

router = APIRouter(dependencies=[Depends(read_access)])

_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_STATES = {"OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"}
_ACTIVE = ("OPEN", "ACKNOWLEDGED", "INVESTIGATING")
_SOURCE_KINDS = {
    "app": ("error_rate", "latency_degradation"),
    "audit": ("hipaa_bulk_access", "hipaa_bulk_export", "hipaa_off_hours", "hipaa_region_mismatch"),
    "auth": ("auth_suspicious_login",),
}
_SORTS = {"priority", "recent", "opened", "severity", "risk", "occurrences"}

logger = logging.getLogger(__name__)


def _pipeline(request: Request) -> Pipeline:
    return request.app.state.pipeline



# -- health / services -------------------------------------------------------


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    return _pipeline(request).health_snapshot()


@router.get("/services")
async def services(request: Request) -> list[dict[str, Any]]:
    return _pipeline(request).services_snapshot()


@router.get("/services/{service}")
async def service_detail(service: str, request: Request) -> dict[str, Any]:
    pipeline = _pipeline(request)
    if service not in pipeline.config.services:
        raise HTTPException(status_code=404, detail=f"unknown service: {service}")
    state = next(s for s in pipeline.services_snapshot() if s["service"] == service)
    incidents = [i for i in await _all_incidents(pipeline) if i.service == service][:50]
    alerts = await pipeline.store.list_alerts(limit=50, service=service)
    return {
        **state,
        "baselines": {
            "error_rate": pipeline.baseline.cells_for(service, "error_rate"),
            "p95_latency_ms": pipeline.baseline.cells_for(service, "p95_latency_ms"),
        },
        "incidents": [i.model_dump(mode="json") for i in incidents],
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }


@router.get("/metrics")
async def metrics(
    request: Request, service: str, minutes: int = Query(default=15, ge=1, le=1440)
) -> list[dict[str, Any]]:
    pipeline = _pipeline(request)
    if service not in pipeline.config.services:
        raise HTTPException(status_code=404, detail=f"unknown service: {service}")
    rows = await pipeline.store.list_metrics(service=service, minutes=minutes, before=_metrics_anchor(pipeline))
    return [r.model_dump(mode="json") for r in rows]


def _metrics_anchor(pipeline: Pipeline) -> Optional[datetime]:
    """Time-series windows are anchored to the pipeline's event clock when it
    runs behind the wall clock (replayed history), else to now."""
    clock = pipeline._event_clock  # noqa: SLF001
    now = datetime.now(timezone.utc)
    if clock is not None and now - clock > timedelta(minutes=5):
        return clock
    return None


# -- alerts / incidents ------------------------------------------------------


@router.get("/alerts")
async def alerts(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    severity: Optional[str] = None,
    service: Optional[str] = None,
    kind: Optional[str] = None,
    incident_id: Optional[int] = None,
    user_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    pipeline = _pipeline(request)
    rows = await pipeline.store.list_alerts(
        limit=limit, severity=severity, service=service, kind=kind, incident_id=incident_id, user_id=user_id
    )
    return [a.model_dump(mode="json") for a in rows]


async def _all_incidents(pipeline: Pipeline, state: Optional[str] = None, limit: int = 500) -> list[Incident]:
    """Persisted history merged with the engine's live view (the engine is
    authoritative for any incident it currently tracks)."""
    merged: dict[int, Incident] = {i.id: i for i in await pipeline.store.list_incidents(state=state, limit=limit)}
    for incident in pipeline.incidents.list_incidents(state=state):
        if incident.id is not None:
            merged[incident.id] = incident
    return sorted(merged.values(), key=lambda i: (i.opened_at, i.id or 0), reverse=True)[:limit]


@router.get("/incidents")
async def incidents(
    request: Request, state: Optional[str] = None, limit: int = Query(default=500, ge=1, le=2000)
) -> list[dict[str, Any]]:
    if state is not None and state not in _STATES:
        raise HTTPException(status_code=422, detail=f"state must be one of {sorted(_STATES)}")
    return [incident_view(i) for i in await _all_incidents(_pipeline(request), state, limit)]


def _csv(value: Optional[str], allowed: Optional[set[str]], name: str) -> list[str]:
    items = [v.strip().upper() if allowed else v.strip() for v in (value or "").split(",") if v.strip()]
    bad = [v for v in items if allowed is not None and v not in allowed]
    if bad:
        raise HTTPException(status_code=422, detail=f"{name} must be from {sorted(allowed or [])}")
    return items


def _text_match(i: Incident, text: str) -> bool:
    """Case-insensitive match on id (#12), title, source, kind code and fingerprint."""
    view = incident_view(i)
    haystack = " ".join(str(v) for v in (view["title"], i.service or "", i.user_id or "", i.kind, i.fingerprint,
                                         view["status_label"], view["severity"])).lower()
    return text.lstrip("#") == str(i.id) or text in haystack


def _sort_key(sort: str):
    def last_seen(i: Incident) -> float:
        return (i.last_seen_at or i.opened_at).timestamp()

    def risk(i: Incident) -> float:
        return -1.0 if i.peak_score is None else i.peak_score

    if sort == "recent":
        return lambda i: (last_seen(i), i.id or 0)
    if sort == "opened":
        return lambda i: (i.opened_at.timestamp(), i.id or 0)
    if sort == "severity":
        return lambda i: (_SEVERITY_RANK[i.peak_severity], risk(i), last_seen(i))
    if sort == "risk":
        return lambda i: (risk(i), _SEVERITY_RANK[i.peak_severity], last_seen(i))
    if sort == "occurrences":
        return lambda i: (i.alert_count, last_seen(i))
    # priority (default): severity, then risk score, then recency
    return lambda i: (_SEVERITY_RANK[i.peak_severity], risk(i), last_seen(i), i.id or 0)


@router.get("/incidents/search")
async def search_incidents(
    request: Request,
    status: Optional[str] = Query(default=None, description="comma list of OPEN,ACKNOWLEDGED,INVESTIGATING,RESOLVED"),
    severity: Optional[str] = Query(default=None, description="comma list of LOW,MEDIUM,HIGH,CRITICAL"),
    pinned: Optional[bool] = None,
    service: Optional[str] = Query(default=None, max_length=64),
    source: Optional[Literal["app", "audit", "auth"]] = Query(default=None, description="log source the detection reads"),
    q: Optional[str] = Query(default=None, max_length=100),
    since_hours: Optional[int] = Query(default=None, ge=1, le=24 * 365, description="only incidents seen/resolved within this many hours"),
    sort: str = "priority",
    order: str = "desc",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
) -> dict[str, Any]:
    """Filtered, sorted, paged incident list (active work and history)."""
    pipeline = _pipeline(request)
    if sort not in _SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of {sorted(_SORTS)}")
    if order not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="order must be asc or desc")
    states = _csv(status, _STATES, "status")
    severities = _csv(severity, _SEVERITIES, "severity")
    text = (q or "").strip().lower()
    rows = await pipeline.store.query_incidents(
        states=states or None, severities=severities or None, service=service or None, pinned=pinned, limit=5000,
        kinds=list(_SOURCE_KINDS[source]) if source else None,
    )
    # The engine's in-memory copy is authoritative for incidents it tracks (and
    # may not be persisted yet); every filter is then applied once, here.
    merged: dict[int, Incident] = {i.id: i for i in rows if i.id is not None}
    for live in pipeline.incidents.list_incidents():
        if live.id is not None:
            merged[live.id] = live
    items = list(merged.values())
    if states:
        items = [i for i in items if i.state in states]
    if severities:
        items = [i for i in items if i.peak_severity in severities]
    if pinned is not None:
        items = [i for i in items if i.pinned == pinned]
    if service:
        items = [i for i in items if i.service == service]
    if source:
        items = [i for i in items if i.kind in _SOURCE_KINDS[source]]
    if since_hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        items = [i for i in items if (i.resolved_at or i.last_seen_at or i.opened_at) >= cutoff]
    if text:
        items = [i for i in items if _text_match(i, text)]
    items.sort(key=_sort_key(sort), reverse=(order == "desc"))
    total = len(items)
    page = items[offset: offset + limit]
    return {"items": [incident_view(i) for i in page], "total": total, "limit": limit, "offset": offset,
            "sort": sort, "order": order}


@router.get("/incidents/summary")
async def incidents_summary(request: Request) -> dict[str, Any]:
    """Counts for the Overview cards, computed from the stored incidents."""
    pipeline = _pipeline(request)
    rows = await _all_incidents(pipeline, limit=5000)
    active = [i for i in rows if i.state in _ACTIVE]
    resolved = [i for i in rows if i.state == "RESOLVED"]
    now = datetime.now(timezone.utc)
    mttrs = [i.mttr_seconds for i in resolved if i.mttr_seconds is not None]
    return {
        "active": len(active),
        "pinned": sum(1 for i in rows if i.pinned),
        "resolved": len(resolved),
        "total": len(rows),
        "by_severity": {s: sum(1 for i in active if i.peak_severity == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "by_status": {s: sum(1 for i in rows if i.state == s) for s in ("OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED")},
        "unacknowledged_high": sum(1 for i in active if i.state == "OPEN" and i.peak_severity in ("HIGH", "CRITICAL")),
        "resolved_last_24h": sum(1 for i in resolved if i.resolved_at and now - i.resolved_at <= timedelta(hours=24)),
        "mean_time_to_resolve_seconds": (sum(mttrs) / len(mttrs)) if mttrs else None,
        "generated_at": now.isoformat(),
    }


@router.get("/activity")
async def recent_activity(request: Request, limit: int = Query(default=15, ge=1, le=100)) -> list[dict[str, Any]]:
    """Newest incident lifecycle events (opened, escalated, pinned, resolved...), for the Overview."""
    rows = await _pipeline(request).store.recent_incident_events(limit)
    for row in rows:
        source = row["service"] or row["user_id"] or "unknown"
        row["title"] = f"{KIND_TITLE.get(row['kind'], row['kind'] or 'incident')}: {source}"
    return rows


# -- incident intelligence (read-only; see docs/incident-intelligence.md) -------------


def _as_utc(value: datetime) -> datetime:
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


# Declared before ``/incidents/{incident_id}`` so "trends" is not parsed as an id.
@router.get("/incidents/trends")
async def incident_trends(
    request: Request,
    since: Optional[datetime] = Query(default=None, description="start of range (UTC if no offset); default until - days"),
    until: Optional[datetime] = Query(default=None, description="end of range, exclusive; default now"),
    days: int = Query(default=30, ge=1, le=366, description="range length when `since` is not given"),
    bucket: Literal["auto", "day", "hour"] = "auto",
    service: Optional[str] = None,
    kind: Optional[str] = None,
    severity: Optional[str] = None,
) -> dict[str, Any]:
    """Counts of stored incidents opened in a range: over time, by severity/service/type, open vs resolved,
    recurring patterns and (only with enough valid timestamps) time to resolution."""
    pipeline = _pipeline(request)
    end = _as_utc(until) if until else (_metrics_anchor(pipeline) or datetime.now(timezone.utc))
    start = _as_utc(since) if since else end - timedelta(days=days)
    if start >= end:
        raise HTTPException(status_code=422, detail="since must be earlier than until")
    if end - start > timedelta(days=366):
        raise HTTPException(status_code=422, detail="range may not exceed 366 days")
    if bucket == "auto":
        bucket = "hour" if end - start <= timedelta(days=3) else "day"
    elif bucket == "hour" and end - start > timedelta(days=7):
        raise HTTPException(status_code=422, detail="hourly buckets need a range of 7 days or less")
    if service is not None and service not in pipeline.config.services:
        raise HTTPException(status_code=422, detail=f"unknown service: {service}")
    if kind is not None and kind not in KIND_TITLE:
        raise HTTPException(status_code=422, detail=f"kind must be one of {sorted(KIND_TITLE)}")
    if severity is not None and severity not in _SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(_SEVERITIES)}")
    raw = await pipeline.store.incident_trends(
        since=start, until=end, bucket=bucket, service=service, kind=kind, severity=severity)
    out = intel.build_trends(raw, since=start, until=end, bucket=bucket)
    out["filters"] = {"service": service, "kind": kind, "severity": severity}
    return out


@router.get("/incidents/{incident_id}")
async def incident_detail(incident_id: int, request: Request) -> dict[str, Any]:
    pipeline = _pipeline(request)
    incident = pipeline.incidents.get(incident_id) or await pipeline.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    events = await pipeline.store.list_incident_events(incident_id)
    alerts_ = await pipeline.store.list_alerts(limit=200, incident_id=incident_id)
    evidence = pipeline.redactor.redact_value(await pipeline.store.list_evidence(incident_id, limit=100))
    return {
        "incident": incident_view(incident),
        "events": [e.model_dump(mode="json") for e in events],
        "alerts": [a.model_dump(mode="json") for a in alerts_],
        "evidence": evidence,
        "detection": detection_rule(pipeline.config, incident.kind),
    }


def _insights(request: Request) -> InsightService:
    """The AI insight service, created on first use so the rest of the app is untouched when it is never called."""
    service = getattr(request.app.state, "ai_insights", None)
    if service is None:
        p = _pipeline(request)
        service = InsightService(p.settings, p.config, p.store, p.redactor)
        request.app.state.ai_insights = service
    return service


async def _load_incident(request: Request, incident_id: int) -> Incident:
    pipeline = _pipeline(request)
    incident = pipeline.incidents.get(incident_id) or await pipeline.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.get("/ai/status")
async def ai_status(request: Request) -> dict[str, Any]:
    """Whether a local model is configured. The deterministic insight is always available."""
    return _insights(request).status()


@router.get("/incidents/{incident_id}/insight")
async def incident_insight(incident_id: int, request: Request) -> dict[str, Any]:
    """Summary, severity rationale, hypotheses and next steps, each citing evidence ids. Recommendations only."""
    incident = await _load_incident(request, incident_id)
    out = await _insights(request).current(incident)
    return {"insight": out["insight"].model_dump(mode="json"), "stale_ai_available": out["stale_ai_available"],
            "ai": out["ai"]}


@router.post("/incidents/{incident_id}/insight/generate")
async def generate_incident_insight(incident_id: int, request: Request,
                                    actor: str = Depends(require_operator)) -> dict[str, Any]:
    """Ask the configured local model (if any) and validate its answer; otherwise the deterministic insight."""
    pipeline = _pipeline(request)
    incident = await _load_incident(request, incident_id)
    service = _insights(request)
    try:
        insight = await service.generate(incident)
    except TooSoon:
        raise HTTPException(status_code=429, detail="an insight was requested for this incident a moment ago")
    await pipeline.audit(actor, "ai_insight", "incident", incident_id,
                         detail=f"{insight.generated_by}:{insight.fallback_reason or 'ok'}",
                         outcome="ok" if insight.status == "ok" else "fallback")
    return {"insight": insight.model_dump(mode="json"), "stale_ai_available": False, "ai": service.status()}


async def _lifecycle(request: Request, incident_id: int, actor: str, action: str, apply, not_found: str) -> dict[str, Any]:
    pipeline = _pipeline(request)
    update = apply(pipeline.incidents, datetime.now(timezone.utc))
    if update is None:
        await pipeline.audit(actor, action, "incident", incident_id, outcome="rejected")
        raise HTTPException(status_code=404, detail=not_found)
    await pipeline.apply_incident_update(update)
    await pipeline.audit(actor, action, "incident", incident_id)
    return incident_view(update.incident)


@router.post("/incidents/{incident_id}/ack")
async def ack_incident(incident_id: int, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    return await _lifecycle(request, incident_id, actor, "acknowledge",
                            lambda eng, now: eng.acknowledge(incident_id, now), "incident not found, or not New")


@router.post("/incidents/{incident_id}/investigate")
async def investigate_incident(incident_id: int, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    return await _lifecycle(request, incident_id, actor, "investigate",
                            lambda eng, now: eng.investigate(incident_id, now),
                            "incident not found, or not New/Acknowledged")


@router.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: int, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    return await _lifecycle(request, incident_id, actor, "resolve",
                            lambda eng, now: eng.resolve(incident_id, now), "incident not found, or already Resolved")


class MuteRequest(BaseModel):
    minutes: float = Field(default=30, ge=0, le=24 * 60)


@router.post("/incidents/{incident_id}/mute")
async def mute_incident(
    incident_id: int, request: Request, payload: MuteRequest, actor: str = Depends(require_operator)
) -> dict[str, Any]:
    return await _lifecycle(request, incident_id, actor, "mute" if payload.minutes else "unmute",
                            lambda eng, now: eng.mute(incident_id, now, payload.minutes), "incident not found")


@router.post("/incidents/{incident_id}/reopen")
async def reopen_incident(incident_id: int, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    return await _lifecycle(request, incident_id, actor, "reopen",
                            lambda engine, now: engine.reopen(incident_id, now),
                            "incident not found, not resolved, or superseded by a newer incident")


async def _set_pinned(request: Request, incident_id: int, pinned: bool, actor: str) -> dict[str, Any]:
    """Pin/unpin works on any incident, including resolved history that the
    live engine no longer tracks. It changes only the pinned flag."""
    pipeline = _pipeline(request)
    now = datetime.now(timezone.utc)
    update = pipeline.incidents.set_pinned(incident_id, pinned, now)
    if update is None:
        stored = await pipeline.store.get_incident(incident_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="incident not found")
        if stored.pinned != pinned:
            stored.pinned, stored.pinned_at = pinned, (now if pinned else None)
            await pipeline.store.upsert_incident(stored)
            await pipeline.store.save_incident_event(
                IncidentEvent(incident_id=incident_id, ts=now, event_type="pinned" if pinned else "unpinned"))
        incident = stored
    else:
        await pipeline.apply_incident_update(update)
        incident = update.incident
    await pipeline.audit(actor, "pin" if pinned else "unpin", "incident", incident_id)
    return incident_view(incident)


@router.post("/incidents/{incident_id}/pin")
async def pin_incident(incident_id: int, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    return await _set_pinned(request, incident_id, True, actor)


@router.post("/incidents/{incident_id}/unpin")
async def unpin_incident(incident_id: int, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    return await _set_pinned(request, incident_id, False, actor)


@router.get("/audit", dependencies=[Depends(require_operator)])
async def audit_log(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    target_type: Optional[str] = Query(default=None, max_length=32),
    target_id: Optional[str] = Query(default=None, max_length=64),
    action: Optional[str] = Query(default=None, max_length=32),
) -> list[dict[str, Any]]:
    return await _pipeline(request).store.list_audit(
        limit=limit, target_type=target_type, target_id=target_id, action=action)


# -- logs ---------------------------------------------------------------------

_FIELD_TERM = re.compile(r'^(\w+):(.+)$')
_LOG_FIELDS = {"service", "level", "status", "priority", "type", "user", "user_id", "action", "request_id",
               "role", "region"}


def _match_log(record: dict[str, Any], terms: list[str]) -> bool:
    haystack = None
    for term in terms:
        m = _FIELD_TERM.match(term)
        if m and m.group(1).lower() in _LOG_FIELDS:
            key, value = m.group(1).lower(), m.group(2).lower()
            if key == "user":
                key = "user_id"
            if key == "region":
                candidates = [record.get("patient_region"), record.get("user_region")]
            else:
                candidates = [record.get(key)]
            if not any(c is not None and str(c).lower() == value for c in candidates):
                return False
            continue
        if haystack is None:
            haystack = " ".join(str(v) for v in record.values() if v is not None).lower()
        if term.lower() not in haystack:
            return False
    return True


@router.get("/logs")
async def logs(
    request: Request,
    q: str = "",
    limit: int = Query(default=200, ge=1, le=2000),
    before_seq: Optional[int] = None,
) -> dict[str, Any]:
    """Search the in-memory buffer of recent events. ``q`` is space-separated
    terms, all of which must match (the word AND is accepted and ignored):
    ``field:value`` for service/level/status/priority/type/user/action/
    request_id/role/region, anything else is a case-insensitive substring."""
    pipeline = _pipeline(request)
    terms = [t for t in q.split() if t.upper() != "AND"]
    results = []
    for record in reversed(pipeline.recent_logs):
        if before_seq is not None and record["seq"] >= before_seq:
            continue
        if _match_log(record, terms):
            results.append(record)
            if len(results) >= limit:
                break
    return {"events": results, "buffer_size": len(pipeline.recent_logs),
            "buffer_capacity": pipeline.recent_logs.maxlen}


@router.get("/logs/{seq}/context")
async def log_context(seq: int, request: Request, around: int = Query(default=10, ge=1, le=100)) -> dict[str, Any]:
    pipeline = _pipeline(request)
    records = list(pipeline.recent_logs)
    idx = next((i for i, r in enumerate(records) if r["seq"] == seq), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="log event is no longer in the recent buffer")
    target = records[idx]
    related = [a.model_dump(mode="json") for a in pipeline.recent_alerts
               if target.get("service") and a.service == target.get("service")
               and abs((a.ts - datetime.fromisoformat(target["ts"])).total_seconds()) <= 120]
    return {"event": target, "before": records[max(0, idx - around):idx], "after": records[idx + 1:idx + 1 + around],
            "related_alerts": related[-5:]}


# -- HIPAA ------------------------------------------------------------------


@router.get("/hipaa/users")
async def hipaa_users(request: Request, limit: int = Query(default=50, ge=1, le=500)) -> list[dict[str, Any]]:
    return _pipeline(request).access_detector.user_summaries()[:limit]


# -- analytics ----------------------------------------------------------------


@router.get("/analytics")
async def analytics(request: Request, hours: int = Query(default=24, ge=1, le=168)) -> dict[str, Any]:
    pipeline = _pipeline(request)
    anchor = _metrics_anchor(pipeline) or datetime.now(timezone.utc)
    since = anchor - timedelta(hours=hours)

    per_hour: dict[str, dict[str, Any]] = {}
    by_service: dict[str, dict[str, int]] = {}
    for hour, severity, svc, count in await pipeline.store.alert_counts(since=since):
        bucket = per_hour.setdefault(hour, {"hour": hour, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0})
        bucket[severity] = bucket.get(severity, 0) + count
        by_service.setdefault(svc, {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0})[severity] += count

    step_factor = pipeline.config.window.size_seconds / pipeline.config.window.step_seconds
    volume: dict[str, dict[str, Any]] = {}
    for hour, svc, total, errors, p95 in await pipeline.store.metrics_hourly(since=since):
        row = volume.setdefault(hour, {"hour": hour, "events": 0, "errors": 0, "services": {}})
        events, errs = total / step_factor, errors / step_factor
        row["events"] += events
        row["errors"] += errs
        row["services"][svc] = {"events": round(events), "errors": round(errs),
                                "error_rate": errs / events if events else 0.0, "p95_latency_ms": p95}
    for row in volume.values():
        row["error_rate"] = row["errors"] / row["events"] if row["events"] else 0.0
        row["events"], row["errors"] = round(row["events"]), round(row["errors"])

    incidents_ = [i for i in await _all_incidents(pipeline, limit=2000) if i.opened_at >= since]
    mttr: dict[str, list[float]] = {}
    for i in incidents_:
        if i.mttr_seconds is not None:
            mttr.setdefault(i.service or "hipaa", []).append(i.mttr_seconds)
    recurring: dict[str, int] = {}
    for i in incidents_:
        recurring[i.fingerprint] = recurring.get(i.fingerprint, 0) + 1

    return {
        "hours": hours,
        "since": since.isoformat(),
        "alerts_per_hour": sorted(per_hour.values(), key=lambda r: r["hour"]),
        "alerts_by_service": by_service,
        "alerts_by_kind": dict(await pipeline.store.alert_kind_counts(since=since)),
        "volume_per_hour": sorted(volume.values(), key=lambda r: r["hour"]),
        "incidents": {
            "total": len(incidents_),
            "active": sum(1 for i in incidents_ if i.state != "RESOLVED"),
            "resolved": sum(1 for i in incidents_ if i.state == "RESOLVED"),
            "by_severity": {s: sum(1 for i in incidents_ if i.peak_severity == s) for s in _SEVERITIES},
        },
        "mttr_seconds": {k: {"mean": sum(v) / len(v), "count": len(v), "max": max(v)} for k, v in mttr.items()},
        "recurring": sorted(
            ({"fingerprint": fp, "count": n} for fp, n in recurring.items() if n > 1),
            key=lambda r: r["count"], reverse=True,
        )[:10],
        "detection_lag_seconds": pipeline.health_snapshot()["event_lag_seconds"],
    }


# -- config / AWS -------------------------------------------------------------


@router.get("/config")
async def config(request: Request) -> dict[str, Any]:
    """Effective detection configuration (read-only: edit config.yaml and
    restart to change it) and non-secret deployment settings."""
    pipeline = _pipeline(request)
    s = pipeline.settings
    return {
        "detection": pipeline.config.model_dump(),
        "deployment": {
            "project_name": s.project_name,
            "environment": s.environment,
            "demo_mode": s.demo_mode,
            "aws_mode": s.aws_mode,
            "log_sources": [
                {"name": t.path.name, "path": t.path.name, "size_bytes": t.file_size, "offset": t.committed_offset}
                for t in pipeline._tailers  # noqa: SLF001
            ],
            "operator_token_required": bool(s.operator_token),
            "email_enabled": s.email_enabled,
        },
    }


@router.get("/aws/status")
async def aws_status(request: Request) -> dict[str, Any]:
    pipeline = _pipeline(request)
    n = pipeline.notifier
    return {
        "integration": n.integration_status(),
        "mode": n.mode,
        "region": n.region,
        "cloudwatch": {"log_group": n.log_group, "log_stream": n.log_stream or "daily (YYYY-MM-DD)",
                       **n.status["cloudwatch"].to_dict()},
        "sns": {"topic_arn": n.sns_topic_arn or None, "configured": n.sns_configured, **n.status["sns"].to_dict()},
        "queue_depth": n.queue_depth,
        "config_warnings": n.config_warnings(),
        "credentials_source": n.credentials_source(),
        "requirement_note": ("The Acentra brief asks for alerts pushed to AWS CloudWatch Logs/SNS. That needs "
                             "AWS_MODE=live plus resources and credentials. Email via Brevo is a separate, "
                             "additional channel and does not satisfy it."),
    }


@router.get("/notifications/email")
async def email_status(request: Request) -> dict[str, Any]:
    """Email alert channel status. Never includes SMTP_PASSWORD."""
    return _pipeline(request).email.status_dict()


@router.post("/aws/test-connection", dependencies=[Depends(require_admin)])
async def aws_test_connection(request: Request) -> dict[str, Any]:
    return await _pipeline(request).notifier.test_connection()


@router.post("/aws/test-alert", dependencies=[Depends(require_admin)])
async def aws_test_alert(request: Request) -> dict[str, Any]:
    return await _pipeline(request).notifier.send_test_alert()


# -- system status -----------------------------------------------------------


@router.get("/status")
async def system_status(request: Request) -> dict[str, Any]:
    """One call for the connection/health strip: backend, database, stream,
    data source. Never includes secrets or the database URL."""
    pipeline = _pipeline(request)
    health_ = pipeline.health_snapshot()
    db_ok, db_error = True, None
    try:
        await pipeline.store.ping()
    except Exception as exc:
        db_ok, db_error = False, type(exc).__name__
    lag = health_["event_lag_seconds"]
    tailers = health_["tailers"]
    # "live" only when events are actually flowing; a quiet or stalled source is "stale".
    stream = "replaying" if pipeline.replay_active else ("live" if lag is not None and lag < 30 else "stale")
    return {
        "backend": "ok",
        "environment": pipeline.settings.environment,
        "database": {"dialect": pipeline.store.dialect, "ok": db_ok, "error": db_error,
                     "write_errors": pipeline.db_errors, "last_write_error": pipeline.last_db_error},
        "stream": {"state": stream, "event_lag_seconds": lag, "sources": tailers,
                   "ws_clients": health_["ws_clients"]},
        "data_source": pipeline.settings.data_source,
        "simulated_data": pipeline.settings.data_source == "simulated",
        "operator_auth": {"required": pipeline.settings.auth_required, "configured": bool(pipeline.settings.operator_token)},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# -- notification settings (Settings -> Notifications) ------------------------

_TEST_EMAIL_MIN_INTERVAL = timedelta(seconds=30)


class NotificationSettingsIn(BaseModel):
    enabled: bool
    recipients: list[str] = Field(min_length=1, max_length=5)
    min_severity: Literal["HIGH", "CRITICAL"] = "HIGH"
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)


async def _notification_view(pipeline: Pipeline) -> dict[str, Any]:
    email = pipeline.email
    saved = await pipeline.store.get_notification_settings()
    status = email.status_dict()
    attempts = await pipeline.store.list_notification_attempts(limit=10)
    return {
        "settings": {
            "enabled": email.settings.enabled,
            "recipients": email.settings.recipients,
            "min_severity": email.settings.min_severity,
            "cooldown_seconds": email.settings.cooldown_seconds,
            "updated_at": saved["updated_at"] if saved else None,
            "updated_by": saved["updated_by"] if saved else None,
        },
        "provider": {
            "name": email.settings.provider,
            "configured": email.configured,
            "missing": email.missing_settings(),        # variable names only, never values
            "sender": email.settings.sender or None,
            "secret_configured": bool(email.settings.api_key.get_secret_value() or email.settings.password.get_secret_value()),
        },
        "status": {k: status[k] for k in ("sent", "failed", "skipped", "retries", "last_success_at", "last_failure_at",
                                          "last_error", "queue_depth", "sent_last_hour", "max_per_hour",
                                          "last_provider_message_id", "delivery_confirmed", "delivery_note",
                                          "config_warnings")},
        "attempts": attempts,
        "allowed_min_severities": list(ALLOWED_MIN_SEVERITIES),
    }


@router.get("/settings/notifications")
async def get_notification_settings(request: Request) -> dict[str, Any]:
    return await _notification_view(_pipeline(request))


@router.put("/settings/notifications")
async def put_notification_settings(
    request: Request, payload: NotificationSettingsIn, actor: str = Depends(require_admin)
) -> dict[str, Any]:
    pipeline = _pipeline(request)
    try:
        recipients = parse_recipients(payload.recipients)
        pipeline.email.apply_prefs(enabled=payload.enabled, recipients=recipients,
                                   min_severity=payload.min_severity, cooldown_seconds=payload.cooldown_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    await pipeline.store.save_notification_settings(
        enabled=payload.enabled, recipients=recipients, min_severity=payload.min_severity,
        cooldown_seconds=payload.cooldown_seconds, updated_by=actor)
    await pipeline.audit(actor, "update_notification_settings", "settings", "notifications",
                         detail=f"enabled={payload.enabled} min_severity={payload.min_severity} "
                                f"cooldown={payload.cooldown_seconds}s recipients={len(recipients)}")
    view = await _notification_view(pipeline)
    view["warnings"] = pipeline.email.config_warnings() if payload.enabled else []
    return view


@router.post("/settings/notifications/test")
async def send_test_notification(request: Request, actor: str = Depends(require_admin)) -> dict[str, Any]:
    """Send one test email to the saved recipients. Reports whether the PROVIDER
    ACCEPTED it; inbox delivery is not observable from here."""
    pipeline = _pipeline(request)
    email = pipeline.email
    if not email.configured:
        raise HTTPException(status_code=409, detail={
            "message": "email provider is not configured", "missing": email.missing_settings()})
    now = datetime.now(timezone.utc)
    if email.last_test_at and now - email.last_test_at < _TEST_EMAIL_MIN_INTERVAL:
        raise HTTPException(status_code=429, detail="a test email was sent a moment ago; wait 30 seconds")
    ok, error = await email.send_test_email()
    await pipeline.audit(actor, "send_test_email", "settings", "notifications",
                         detail="accepted by provider" if ok else (error or "failed")[:200],
                         outcome="ok" if ok else "failed")
    return {
        "ok": ok,
        "result": "accepted_by_provider" if ok else "failed",
        "provider": email.settings.provider,
        "provider_message_id": email.last_provider_message_id if ok else None,
        "error": None if ok else error,
        "note": "Accepted means the provider took the message for sending; it does not confirm inbox delivery."
                if ok else None,
    }


# -- demo ---------------------------------------------------------------------


class InjectRequest(BaseModel):
    scenario: str
    duration_s: float = Field(default=60, ge=MIN_DURATION_S, le=MAX_DURATION_S)


@router.get("/demo/scenarios")
async def demo_scenarios(request: Request) -> dict[str, Any]:
    return {"enabled": _pipeline(request).settings.demo_mode, "scenarios": SCENARIOS}


@router.post("/demo/inject", dependencies=[Depends(require_operator)])
async def demo_inject(request: Request, payload: InjectRequest) -> dict[str, Any]:
    pipeline = _pipeline(request)
    if not pipeline.settings.demo_mode:
        raise HTTPException(status_code=403, detail="DEMO_MODE is disabled")
    if payload.scenario not in SCENARIO_NAMES:
        raise HTTPException(status_code=422, detail=f"unknown scenario: {payload.scenario}")
    pipeline.write_control_file(payload.scenario, payload.duration_s)
    return {"scenario": payload.scenario, "duration_s": payload.duration_s}


# -- who am I / security posture / retention ---------------------------------


@router.get("/me")
async def me(request: Request, x_operator_token: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """The caller's role, so the UI can show only the controls that will work."""
    caller = caller_for(request, x_operator_token)
    return {
        "role": caller.role, "actor": caller.actor, "authenticated": caller.authenticated,
        "open_access": caller.open_access,
        "can": {"operate": caller.role in ("operator", "admin"), "admin": caller.role == "admin"},
    }


def _security_warnings(pipeline: Pipeline) -> list[dict[str, str]]:
    s = pipeline.settings
    out: list[dict[str, str]] = []

    def warn(code: str, level: str, message: str) -> None:
        out.append({"code": code, "level": level, "message": message})

    if not configured_tokens(s):
        if s.auth_required:
            warn("controls_locked", "info", "No operator token is configured, so state-changing actions are refused.")
        else:
            warn("auth_disabled", "critical",
                 "Authentication is DISABLED: anyone who can reach this server can acknowledge, resolve, change "
                 "settings and run cleanup. Set OPERATOR_TOKEN (and ADMIN_TOKEN) before exposing it.")
    elif s.operator_token and not s.admin_token:
        warn("roles_collapsed", "warning",
             "ADMIN_TOKEN is not set, so the operator token also holds admin rights (settings, retention).")
    if not read_requires_auth(s):
        warn("view_open", "warning" if configured_tokens(s) else "info",
             "Incidents and events can be read without a token. Set VIEWER_TOKEN or REQUIRE_VIEW_AUTH=true to restrict.")
    if not s.redaction_enabled:
        warn("redaction_disabled", "critical", "Sensitive-field redaction is OFF (REDACTION_ENABLED=false).")
    if pipeline.retention.all_disabled:
        warn("retention_disabled", "warning", "Every retention rule is disabled: data is kept forever.")
    if "*" in [o.strip() for o in s.cors_origins.split(",")]:
        warn("cors_wildcard", "warning", "CORS allows every origin.")
    if s.environment.lower() in ("production", "prod") and pipeline.store.dialect == "sqlite":
        warn("sqlite_in_production", "warning", "Production is using local SQLite instead of PostgreSQL.")
    if s.ingest_mode == "legacy":
        warn("legacy_ingest", "warning",
             "INGEST_MODE=legacy reads synthetic files with raw identifiers and no event-id de-duplication. "
             "It is for demos and tests and is NOT suitable for real logs. Use INGEST_MODE=configured.")
    elif pipeline.registry is not None and any(
            src.cfg.include_msg for src in pipeline.registry.sources.values()
        ):
        warn("free_text_ingest", "warning",
             "A source opts in to free-text messages (include_msg). Text is only pattern-redacted and the event's "
             "own identifiers are removed; other identifiers in free text pass through. Prefer omitting it.")
    if s.ingest_mode != "legacy" and pipeline.key_state.get("legacy_rows_at_cutover"):
        warn("historical_raw_data", "warning",
             "This database already held incidents or alerts when pseudonymization was enabled. Those rows were "
             "written before the privacy boundary and may contain raw identifiers. They are not rewritten; follow the "
             "cutover procedure in docs/privacy-boundary.md (new database, retention, or an offline copy).")
    if pipeline.key_state.get("rotated_at"):
        warn("pseudonym_key_rotated", "info",
             "The pseudonymization key was rotated on this database: incidents before and after the rotation use "
             "different pseudonyms for the same person and do not correlate.")
    if s.ingest_mode != "legacy" and s.ingest_dedupe == "content":
        warn("content_dedupe", "info",
             "Content-hash de-duplication is on: genuinely distinct events that serialize identically are collapsed.")
    if s.data_source == "simulated":
        warn("simulated_data", "info", "Data is synthetic. No real patient data should be connected without a security review.")
    return out


@router.get("/ingest/status")
async def ingest_status(request: Request) -> dict[str, Any]:
    """Per-source state, counters and reject reasons. Metadata only: no line
    content, no raw identifiers, no file system paths beyond the file name."""
    pipeline = _pipeline(request)
    return {
        "mode": pipeline.settings.ingest_mode,
        "dedupe": pipeline.deduper.stats(),
        "pseudonymization": {"enabled": pipeline.pseudonymizer is not None, **pipeline.key_state},
        "sources": [t.status() | {"source": t.source} for t in pipeline._tailers],  # noqa: SLF001
        "rejects": pipeline.quarantine.summary(),
        "naive_timestamps_assumed_utc": pipeline.parser.naive_assumed_utc,
        "tailer_restarts": pipeline.tailer_restarts,
    }


@router.get("/security/status")
async def security_status(request: Request) -> dict[str, Any]:
    pipeline = _pipeline(request)
    s = pipeline.settings
    return {
        "warnings": _security_warnings(pipeline),
        "auth": {
            "operator_token_configured": bool(s.operator_token), "admin_token_configured": bool(s.admin_token),
            "viewer_token_configured": bool(s.viewer_token), "read_requires_auth": read_requires_auth(s),
            "required_in_this_environment": s.auth_required,
        },
        "roles": PERMISSIONS,
        "redaction": {"enabled": s.redaction_enabled},
        "retention": {"policy": pipeline.retention.describe(), "last_run": pipeline.last_retention_run,
                      "interval_hours": s.retention_interval_hours},
        "processing": {"data_source": s.data_source, "database": pipeline.store.dialect,
                       "cloud_integrations": {"aws_mode": s.aws_mode, "email_enabled": s.email_enabled}},
        "not_verified": [
            "No regulatory compliance (HIPAA, SOC 2, HITRUST) is claimed or has been assessed.",
            "Token roles are a basic control, not per-user identity or SSO; use a gateway or identity provider in production.",
            "Redaction is pattern/field based and cannot prove a log line contains no identifiers.",
            "A penetration test, threat model and professional security review have not been done.",
        ],
    }


@router.get("/admin/retention")
async def retention_status(request: Request) -> dict[str, Any]:
    """The policy and what a cleanup would delete right now (dry run)."""
    pipeline = _pipeline(request)
    preview = await pipeline.run_retention(dry_run=True)
    return {"policy": pipeline.retention.describe(), "would_delete": preview["deleted"],
            "last_run": pipeline.last_retention_run}


@router.post("/admin/retention/run")
async def retention_run(request: Request, actor: str = Depends(require_admin)) -> dict[str, Any]:
    return await _pipeline(request).run_retention(actor=actor)


# -- Incident Time Machine (read-only) ---------------------------------------


async def _incident_or_404(pipeline: Pipeline, incident_id: int) -> Incident:
    incident = pipeline.incidents.get(incident_id) or await pipeline.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


def _service_graph(pipeline: Pipeline) -> dict[str, list[str]]:
    return {name: list(cfg.depends_on) for name, cfg in pipeline.config.services.items()}


@router.get("/incidents/{incident_id}/related")
async def related_incidents(
    incident_id: int, request: Request,
    limit: int = Query(default=10, ge=1, le=25),
    min_score: float = Query(default=intel.MIN_RELATED_SCORE, ge=0.0, le=1.0),
    window_hours: float = Query(default=6.0, ge=0.25, le=72.0, description="how far around the incident to look"),
) -> dict[str, Any]:
    """Incidents that may be related to this one, each with a score and the reasons for it. Read-only: nothing is
    linked, merged or changed, and a match is a lead, not proof of a shared cause."""
    pipeline = _pipeline(request)
    source = await _incident_or_404(pipeline, incident_id)
    match_actor = bool(pipeline.settings.incident_intel_match_actor)
    matches, considered, truncated = await intel.find_related(
        pipeline.store, source, graph=_service_graph(pipeline), match_actor=match_actor, limit=limit,
        min_score=min_score, window_hours=window_hours)
    return {
        "source_incident_id": source.id,
        "related": [intel.related_view(source.id, m) for m in matches],
        "count": len(matches),
        "candidates_considered": considered,
        "candidates_truncated": truncated,
        "criteria": {"min_score": min_score, "window_hours": window_hours, "actor_matching": match_actor},
        "disclaimer": intel.DISCLAIMER,
    }


@router.get("/incidents/{incident_id}/duplicates")
async def duplicate_incidents(
    incident_id: int, request: Request,
    limit: int = Query(default=5, ge=1, le=10),
    max_gap_minutes: float = Query(default=30.0, ge=0.0, le=240.0),
) -> dict[str, Any]:
    """Conservative duplicate suggestions (same type, same service, nearly the same time). For human review only:
    nothing is merged, resolved or deleted."""
    pipeline = _pipeline(request)
    source = await _incident_or_404(pipeline, incident_id)
    match_actor = bool(pipeline.settings.incident_intel_match_actor)
    skipped: Optional[str] = None
    duplicates: list[dict[str, Any]] = []
    if source.kind in intel.ACTOR_SCOPED and not match_actor:
        skipped = ("This anomaly type is grouped per person. Duplicate suggestions would need to compare the actor, "
                   "which is disabled (INCIDENT_INTEL_MATCH_ACTOR), so none are made.")
    elif not source.service:
        skipped = "The incident has no service, so there is nothing safe to compare."
    else:
        start, end = intel.candidate_window(source, hours=max_gap_minutes / 60.0)
        candidates = await pipeline.store.incidents_overlapping(start, end, exclude_id=source.id)
        found = intel.rank_duplicates(source, candidates, limit=limit, match_actor=match_actor,
                                      max_gap_seconds=max_gap_minutes * 60.0)
        duplicates = [intel.duplicate_view(source.id, m) for m in found]
    return {
        "source_incident_id": source.id,
        "duplicates": duplicates,
        "count": len(duplicates),
        "skipped_reason": skipped,
        "criteria": {"max_gap_minutes": max_gap_minutes, "actor_matching": match_actor},
        "disclaimer": intel.DUPLICATE_DISCLAIMER,
    }


@router.get("/incidents/{incident_id}/timeline")
async def incident_timeline(
    incident_id: int, request: Request,
    before_minutes: float = Query(default=15, ge=0, le=1440),
    after_minutes: float = Query(default=15, ge=0, le=1440),
    sources: Optional[str] = Query(default=None, description="comma list of metrics,alerts,lifecycle,evidence"),
    as_of: Optional[datetime] = Query(default=None, description="replay: the state and events up to this time"),
    max_points: int = Query(default=240, ge=10, le=2000),
) -> dict[str, Any]:
    """Events before, during and after the incident with explicit coverage.
    GET-only and read-only: replaying never modifies stored records."""
    pipeline = _pipeline(request)
    incident = await _incident_or_404(pipeline, incident_id)
    chosen = tuple(v.strip().lower() for v in (sources or "").split(",") if v.strip()) or ALL_SOURCES
    if any(v not in ALL_SOURCES for v in chosen):
        raise HTTPException(status_code=422, detail=f"sources must be from {list(ALL_SOURCES)}")
    query = TimelineQuery(before_minutes=before_minutes, after_minutes=after_minutes,
                          max_metric_points=max_points, sources=chosen, as_of=as_of)
    now = datetime.now(timezone.utc)
    data = await load_timeline_data(pipeline.store, incident, query, now)
    return build_timeline(data, query, pipeline.config, now=now, retention_hours=pipeline.retention.metrics_hours,
                          redact=pipeline.redactor.redact_value)


@router.get("/incidents/{incident_id}/timeline/{entry_id:path}")
async def incident_timeline_entry(incident_id: int, entry_id: str, request: Request) -> dict[str, Any]:
    """Raw, log-safe details of one timeline entry (metric, alert, lifecycle or evidence)."""
    pipeline = _pipeline(request)
    incident = await _incident_or_404(pipeline, incident_id)
    kind, _, ref = entry_id.partition(":")
    redact = pipeline.redactor.redact_value
    store = pipeline.store
    if kind == "metric" and incident.service:
        ts = _parse_ts(ref)
        rows = await store.list_metrics_between(service=incident.service, start=ts, end=ts, limit=1)
        if rows:
            return entry_detail("metric", rows[0], redact)
    elif kind == "alert" and ref.isdigit():
        alert = await store.get_alert(int(ref))
        if alert is not None and (alert.incident_id == incident_id or alert.service == incident.service
                                  or (alert.user_id is not None and alert.user_id == incident.user_id)):
            return entry_detail("alert", alert, redact)
    elif kind == "lifecycle" and ref.isdigit():
        event = await store.get_incident_event(incident_id, int(ref))
        if event is not None:
            return entry_detail("lifecycle", event, redact)
    elif kind == "evidence" and ref.isdigit():
        row = await store.get_evidence(incident_id, int(ref))
        if row is not None:
            return entry_detail("evidence", row, redact)
    raise HTTPException(status_code=404, detail="timeline entry not found (it may have expired under the retention policy)")


def _parse_ts(value: str) -> datetime:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid timestamp in entry id") from None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


# -- synthetic incident simulator ----------------------------------------------------------
# Runs the real detection pipeline on generated data in an isolated temporary
# database. See app/simulation/runner.py for the safety properties.

_sim_lock = asyncio.Lock()


class SimulationRequest(BaseModel):
    scenario_id: str
    seed: Optional[int] = Field(default=None, ge=0, le=2**31 - 1)


class BenchmarkRequest(BaseModel):
    seeds: list[int] = Field(default_factory=lambda: list(DEFAULT_BENCHMARK_SEEDS), min_length=1, max_length=3)
    scenario_ids: Optional[list[str]] = Field(default=None, max_length=10)


@router.get("/simulations/scenarios")
async def simulation_scenarios() -> dict[str, Any]:
    return {"scenarios": list_sim_scenarios(), "synthetic_only": True,
            "note": "Simulations use generated data in a temporary database. They never touch real systems, "
                    "this dashboard's incidents, or any notification channel."}


@router.post("/simulations/run")
async def run_simulation(payload: SimulationRequest, request: Request,
                         actor: str = Depends(require_operator)) -> dict[str, Any]:
    if payload.scenario_id not in SIM_SCENARIOS:
        raise HTTPException(status_code=404, detail="unknown scenario")
    if _sim_lock.locked():
        raise HTTPException(status_code=409, detail="a simulation is already running")
    pipeline = _pipeline(request)
    async with _sim_lock:
        result = await run_scenario_threaded(payload.scenario_id, payload.seed)
        run_id = await pipeline.store.save_simulation_run(
            created_at=datetime.now(timezone.utc), scenario_id=result["scenario_id"], seed=result["seed"],
            passed=result["passed"], summary=result["summary"], result=result, requested_by=actor)
    await pipeline.audit(actor, "simulate", "simulation", run_id)
    return {"id": run_id, **result}


@router.post("/simulations/benchmark")
async def run_simulation_benchmark(payload: BenchmarkRequest, request: Request,
                                   actor: str = Depends(require_admin)) -> dict[str, Any]:
    ids = payload.scenario_ids or list(SIM_SCENARIOS)
    unknown = [i for i in ids if i not in SIM_SCENARIOS]
    if unknown:
        raise HTTPException(status_code=404, detail=f"unknown scenario: {unknown[0]}")
    if _sim_lock.locked():
        raise HTTPException(status_code=409, detail="a simulation is already running")
    pipeline = _pipeline(request)
    async with _sim_lock:
        result = await asyncio.to_thread(run_benchmark, tuple(payload.seeds), ids)
        s = result["summary"]
        summary = (f"{s['detected']}/{s['injected_runs']} detected, "
                   f"{s['control_false_positives']} control false positives")
        run_id = await pipeline.store.save_simulation_run(
            created_at=datetime.now(timezone.utc), scenario_id="benchmark", seed=payload.seeds[0],
            passed=s["passed"] == s["runs"], summary=summary, result=result, requested_by=actor)
    await pipeline.audit(actor, "simulate", "simulation", run_id)
    return {"id": run_id, **result}


@router.get("/simulations/runs")
async def simulation_runs(request: Request, limit: int = Query(20, ge=1, le=100),
                          scenario_id: Optional[str] = None) -> dict[str, Any]:
    return {"items": await _pipeline(request).store.list_simulation_runs(limit=limit, scenario_id=scenario_id)}


@router.get("/simulations/runs/{run_id}")
async def simulation_run(run_id: int, request: Request) -> dict[str, Any]:
    row = await _pipeline(request).store.get_simulation_run(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="simulation run not found")
    return row


# -- cross-system correlation ----------------------------------------------------------------


class CorrelationRecord(BaseModel):
    source: Literal["app", "auth", "audit", "server", "db_audit"]
    record: dict[str, Any]


class CorrelationRequest(BaseModel):
    events: list[CorrelationRecord] = Field(max_length=500)


def _correlation_view(pipeline: Pipeline, result: dict[str, Any]) -> dict[str, Any]:
    return pipeline.redactor.redact_value(result)


@router.get("/correlation/rules")
async def correlation_rules() -> dict[str, Any]:
    return {"rules": [r.describe() for r in CORRELATION_RULES], "adapters": ADAPTER_STATUS,
            "note": "server and db_audit adapters use a documented synthetic format and are not validated "
                    "against any real product."}


@router.get("/correlation/demo")
async def correlation_demo(request: Request) -> dict[str, Any]:
    events, skipped = normalize_all(demo_records())
    return {"synthetic": True, **_correlation_view(_pipeline(request), correlate(events, adapter_skipped=skipped))}


@router.post("/correlation/analyze")
async def correlation_analyze(payload: CorrelationRequest, request: Request) -> dict[str, Any]:
    """Correlate caller-supplied records. Computation only: nothing is stored."""
    events, skipped = normalize_all([(e.source, e.record) for e in payload.events])
    return _correlation_view(_pipeline(request), correlate(events, adapter_skipped=skipped))


@router.get("/incidents/{incident_id}/correlation")
async def incident_correlation(
    incident_id: int, request: Request, window_minutes: float = Query(default=15, ge=1, le=240),
) -> dict[str, Any]:
    """Which other events, from which other systems, belong with this incident
    and why. Uses the incident's captured evidence plus recent logs in memory;
    groups that do not involve this incident's actor or service are dropped."""
    pipeline = _pipeline(request)
    incident = await _incident_or_404(pipeline, incident_id)
    now = datetime.now(timezone.utc)
    start = incident.opened_at - timedelta(minutes=window_minutes)
    end = (incident.resolved_at or now) + timedelta(minutes=window_minutes)
    records: list[tuple[str, dict[str, Any]]] = []
    for row in await pipeline.store.list_evidence(incident_id, limit=200):
        rec = row["record"]
        if rec.get("type") in ("app", "auth", "audit"):
            records.append((rec["type"], rec))
    for rec in list(pipeline.recent_logs):
        try:
            ts = datetime.fromisoformat(rec["ts"])
        except (KeyError, ValueError):
            continue
        if start <= ts <= end and rec.get("type") in ("app", "auth", "audit"):
            records.append((rec["type"], rec))
    events, skipped = normalize_all(records)
    engine = CorrelationEngine()
    engine.add_all(events)
    result = engine.result(adapter_skipped=skipped)

    def relevant(group: dict[str, Any]) -> bool:
        return any((e["actor"] and e["actor"] == incident.user_id) or (e["service"] and e["service"] == incident.service)
                   for e in group["events"])

    result["groups"] = [g for g in result["groups"] if relevant(g)]
    result.update({"incident_id": incident_id, "window": {"start": start.isoformat(), "end": end.isoformat()},
                   "inputs": {"evidence_and_recent_logs": len(records)},
                   "limits": "Only the application, authentication and audit logs this system ingests are "
                             "available here; server and database audit sources need an adapter."})
    return _correlation_view(pipeline, result)
