"""Smart alert grouping and escalation: explainable grouping, dedupe, cooldown
flood prevention, escalation on new evidence, reopening, risk trend, and
concurrent updates."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import IncidentConfig
from app.incidents.engine import IncidentEngine, compute_trend
from app.incidents.view import evidence_quality, incident_view
from app.models import Alert, Anomaly
from tests.test_workflow import _build

T0 = datetime(2026, 3, 10, 16, 0, 0, tzinfo=timezone.utc)
CFG = IncidentConfig(cooldown_minutes=5, service_auto_resolve_windows=6, hipaa_auto_resolve_minutes=10,
                     reopen_window_minutes=3)


def svc(offset_s=0, service="claims", kind="error_rate") -> Anomaly:
    return Anomaly(kind=kind, ts=T0 + timedelta(seconds=offset_s), service=service, z=5.0)


def usr(offset_s=0, user="U-117", kind="hipaa_bulk_access") -> Anomaly:
    return Anomaly(kind=kind, ts=T0 + timedelta(seconds=offset_s), user_id=user)


def alert(a: Anomaly, severity="HIGH", score=0.6) -> Alert:
    rule = a.kind.startswith(("hipaa_", "auth_"))
    return Alert(ts=a.ts, kind=a.kind, service=a.service, user_id=a.user_id, severity=severity,
                 score=0.0 if rule else score, explanation="because", metrics={})


# -- grouping rules ----------------------------------------------------------------------------


def test_repeats_group_into_one_incident_with_counts_and_first_last_seen():
    e = IncidentEngine(CFG)
    first = e.record_alert(svc(0), alert(svc(0)))
    for i in range(1, 10):
        u = e.record_alert(svc(i * 10), alert(svc(i * 10)))
    inc = u.incident
    assert inc.id == first.incident.id and inc.alert_count == 10
    assert inc.opened_at == T0 and inc.last_seen_at == T0 + timedelta(seconds=90)
    assert len(e.list_incidents()) == 1


def test_different_service_or_kind_or_user_do_not_group():
    e = IncidentEngine(CFG)
    ids = {
        e.record_alert(svc(0, "claims"), alert(svc(0, "claims"))).incident.id,
        e.record_alert(svc(1, "pharmacy"), alert(svc(1, "pharmacy"))).incident.id,
        e.record_alert(svc(2, "claims", "latency_degradation"), alert(svc(2, "claims", "latency_degradation"))).incident.id,
        e.record_alert(usr(3, "U-1"), alert(usr(3, "U-1"))).incident.id,
        e.record_alert(usr(4, "U-2"), alert(usr(4, "U-2"))).incident.id,
    }
    assert len(ids) == 5


def test_grouping_is_explained_in_the_view():
    e = IncidentEngine(CFG)
    inc = e.record_alert(svc(), alert(svc())).incident
    g = incident_view(inc)["grouping"]
    assert g["key"] == "error_rate:claims" and "same detection kind and same service" in g["rule"]
    uinc = e.record_alert(usr(), alert(usr())).incident
    assert "same user" in incident_view(uinc)["grouping"]["rule"]


# -- severity vs risk vs evidence quality ------------------------------------------------------


def test_severity_risk_score_and_evidence_quality_are_independent():
    e = IncidentEngine(CFG)
    inc = e.record_alert(svc(), alert(svc(), severity="LOW", score=0.9)).incident
    view = incident_view(inc)
    assert view["severity"] == "LOW" and view["risk_score"] == 90 and view["evidence_quality"] == "none"
    inc.evidence_count = 20
    assert incident_view(inc)["evidence_quality"] == "strong"
    assert [evidence_quality(n) for n in (0, 1, 4, 5, 14, 15)] == ["none", "limited", "limited", "moderate", "moderate", "strong"]


# -- escalation -------------------------------------------------------------------------------


def test_escalation_on_new_evidence_notifies_once_and_records_why():
    e = IncidentEngine(CFG)
    e.record_alert(svc(0), alert(svc(0), severity="LOW"))
    up = e.record_alert(svc(10), alert(svc(10), severity="HIGH"))
    assert up.is_escalation and up.should_notify
    assert up.events[0].event_type == "escalated" and "LOW -> HIGH" in up.events[0].detail
    again = e.record_alert(svc(20), alert(svc(20), severity="HIGH"))
    assert not again.is_escalation and not again.should_notify


def test_a_lower_severity_later_never_downgrades_peak():
    e = IncidentEngine(CFG)
    e.record_alert(svc(0), alert(svc(0), severity="CRITICAL"))
    up = e.record_alert(svc(5), alert(svc(5), severity="LOW"))
    assert up.incident.peak_severity == "CRITICAL" and not up.is_escalation


def test_escalation_inside_cooldown_after_resolve_is_suppressed():
    e = IncidentEngine(CFG)
    first = e.record_alert(svc(0), alert(svc(0), severity="LOW")).incident
    e.resolve(first.id, T0 + timedelta(seconds=10))
    up = e.record_alert(svc(60), alert(svc(60), severity="CRITICAL"))
    assert up.is_reopen and not up.should_notify  # still inside the 5 minute cooldown


# -- flood prevention ---------------------------------------------------------------------------


def test_hundreds_of_repeats_produce_a_single_notification_hint():
    e = IncidentEngine(CFG)
    hints = [e.record_alert(svc(i), alert(svc(i))).should_notify for i in range(300)]
    assert hints.count(True) == 1 and e.list_incidents()[0].alert_count == 300


def test_pipeline_notifies_once_for_a_burst_and_again_only_on_escalation(tmp_path: Path):
    app, pipeline = _build(tmp_path)
    sent: list[tuple[int, bool]] = []
    pipeline.email.notify_incident = lambda incident, alert_, escalated=False: sent.append((incident.id, escalated))
    with TestClient(app) as c:
        now = datetime.now(timezone.utc)

        async def go():
            for i in range(150):
                a = Anomaly(kind="error_rate", ts=now, service="claims", z=5.0)
                await pipeline._handle_alert(a, Alert(ts=now, kind="error_rate", service="claims",
                                                      severity="HIGH", score=0.6, explanation="x"))
            a = Anomaly(kind="error_rate", ts=now, service="claims", z=9.0)
            await pipeline._handle_alert(a, Alert(ts=now, kind="error_rate", service="claims",
                                                  severity="CRITICAL", score=0.9, explanation="x"))

        c.portal.call(go)
    assert sent == [(1, False), (1, True)]


# -- reopening ------------------------------------------------------------------------------------


def test_recurrence_inside_the_window_reopens_the_same_incident():
    e = IncidentEngine(CFG)
    inc = e.record_alert(svc(0), alert(svc(0))).incident
    e.acknowledge(inc.id, T0 + timedelta(seconds=5))
    e.resolve(inc.id, T0 + timedelta(seconds=10))
    up = e.record_alert(svc(100), alert(svc(100)))        # 90s after resolution, window is 3 min
    assert up.is_reopen and not up.is_new and up.incident.id == inc.id
    assert up.incident.state == "OPEN" and up.incident.resolved_at is None and up.incident.mttr_seconds is None
    assert up.incident.reopen_count == 1 and up.incident.acknowledged_at is None
    assert up.events[0].event_type == "reopened" and "90s" in up.events[0].detail
    assert up.incident.alert_count == 2 and len(e.list_incidents()) == 1


def test_recurrence_after_the_window_opens_a_new_incident():
    e = IncidentEngine(CFG)
    inc = e.record_alert(svc(0), alert(svc(0))).incident
    e.resolve(inc.id, T0 + timedelta(seconds=10))
    up = e.record_alert(svc(10 + 4 * 60), alert(svc(10 + 4 * 60)))   # 4 min later, window is 3
    assert up.is_new and up.incident.id != inc.id and not up.is_reopen


def test_reopen_window_zero_disables_reopening():
    e = IncidentEngine(IncidentConfig(cooldown_minutes=5, service_auto_resolve_windows=6, hipaa_auto_resolve_minutes=10))
    inc = e.record_alert(svc(0), alert(svc(0))).incident
    e.resolve(inc.id, T0 + timedelta(seconds=10))
    assert e.record_alert(svc(30), alert(svc(30))).is_new


def test_reopen_after_cooldown_with_higher_severity_notifies():
    cfg = IncidentConfig(cooldown_minutes=1, service_auto_resolve_windows=6, hipaa_auto_resolve_minutes=10,
                         reopen_window_minutes=10)
    e = IncidentEngine(cfg)
    inc = e.record_alert(svc(0), alert(svc(0), severity="MEDIUM")).incident
    e.resolve(inc.id, T0 + timedelta(seconds=10))
    up = e.record_alert(svc(10 + 120), alert(svc(130), severity="CRITICAL"))
    assert up.is_reopen and up.is_escalation and up.should_notify


def test_manual_reopen_only_for_the_newest_resolved_incident():
    e = IncidentEngine(CFG)
    old = e.record_alert(svc(0), alert(svc(0))).incident
    e.resolve(old.id, T0 + timedelta(seconds=10))
    new = e.record_alert(svc(10 + 600), alert(svc(610))).incident       # past the window: a new incident
    assert new.id != old.id
    assert e.reopen(old.id, T0 + timedelta(hours=1)) is None             # superseded
    assert e.reopen(new.id, T0 + timedelta(hours=1)) is None             # not resolved
    e.resolve(new.id, T0 + timedelta(seconds=700))
    up = e.reopen(new.id, T0 + timedelta(hours=1))
    assert up.incident.state == "OPEN" and up.events[0].detail.startswith("manually reopened")


def test_pinned_flag_survives_reopen_and_never_changes_severity():
    e = IncidentEngine(CFG)
    inc = e.record_alert(svc(0), alert(svc(0), severity="MEDIUM")).incident
    e.set_pinned(inc.id, True, T0)
    e.resolve(inc.id, T0 + timedelta(seconds=5))
    up = e.record_alert(svc(30), alert(svc(30), severity="MEDIUM"))
    assert up.incident.pinned and up.incident.peak_severity == "MEDIUM"


def test_hipaa_and_auth_incidents_reopen_too():
    e = IncidentEngine(CFG)
    inc = e.record_alert(usr(0, kind="auth_suspicious_login"), alert(usr(0, kind="auth_suspicious_login"))).incident
    e.resolve(inc.id, T0 + timedelta(seconds=5))
    assert e.record_alert(usr(40, kind="auth_suspicious_login"), alert(usr(40, kind="auth_suspicious_login"))).is_reopen


# -- risk trend ------------------------------------------------------------------------------------


def test_trend_rising_falling_stable_and_unknown():
    assert compute_trend([0.3], rule_based=False) == "unknown"
    assert compute_trend([0.3, 0.4, 0.6, 0.8], rule_based=False) == "rising"
    assert compute_trend([0.8, 0.7, 0.4, 0.3], rule_based=False) == "falling"
    assert compute_trend([0.5, 0.51, 0.5, 0.52], rule_based=False) == "stable"


def test_trend_is_tracked_on_the_incident_and_is_severity_based_for_rules():
    e = IncidentEngine(CFG)
    for i, s in enumerate((0.2, 0.3, 0.6, 0.8)):
        inc = e.record_alert(svc(i), alert(svc(i), score=s)).incident
    assert inc.risk_trend == "rising" and inc.latest_score == 0.8 and incident_view(inc)["risk_trend_basis"] == "alert score"
    u = e.record_alert(usr(0), alert(usr(0), severity="MEDIUM")).incident
    for i, s in enumerate(("MEDIUM", "HIGH", "CRITICAL"), start=1):
        u = e.record_alert(usr(i), alert(usr(i), severity=s)).incident
    assert u.risk_trend == "rising" and u.latest_score is None                  # no score is invented
    assert "severity" in incident_view(u)["risk_trend_basis"]


# -- concurrency ---------------------------------------------------------------------------------------


def test_concurrent_duplicate_alerts_create_exactly_one_incident(tmp_path: Path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        now = datetime.now(timezone.utc)

        async def go():
            async def one(i):
                a = Anomaly(kind="error_rate", ts=now + timedelta(milliseconds=i), service="claims", z=5.0)
                await pipeline._handle_alert(a, Alert(ts=a.ts, kind="error_rate", service="claims",
                                                      severity="HIGH", score=0.5, explanation="x"))
            await asyncio.gather(*(one(i) for i in range(60)))
            rows = await pipeline.store.list_incidents()
            return rows

        rows = c.portal.call(go)
        assert len(rows) == 1 and rows[0].alert_count == 60 and rows[0].evidence_count >= 0
        assert len(pipeline.incidents.list_incidents()) == 1


def test_concurrent_api_actions_leave_a_consistent_state_and_audit_trail(tmp_path: Path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        now = datetime.now(timezone.utc)

        async def go():
            a = Anomaly(kind="error_rate", ts=now, service="claims", z=5.0)
            await pipeline._handle_alert(a, Alert(ts=now, kind="error_rate", service="claims", severity="HIGH",
                                                  score=0.5, explanation="x"))
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                calls = [client.post("/api/incidents/1/ack") for _ in range(10)]
                calls += [client.post("/api/incidents/1/resolve") for _ in range(10)]
                calls += [client.post("/api/incidents/1/pin") for _ in range(5)]
                responses = await asyncio.gather(*calls)
            return [r.status_code for r in responses]

        codes = c.portal.call(go)
        assert set(codes) <= {200, 404}                     # never a 500 or a half-applied state
        incident = pipeline.incidents.get(1)
        assert incident.state == "RESOLVED" and incident.pinned
        audit = c.get("/api/audit").json()
        assert sum(1 for r in audit if r["action"] == "resolve" and r["outcome"] == "ok") == 1
