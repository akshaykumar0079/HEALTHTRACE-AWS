"""Incident Time Machine: ordering, window boundaries, empty/expired history,
event selection, replay (as_of) and read-only behaviour."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import load_config
from app.incidents.timeline import (
    TimelineData, TimelineQuery, build_timeline, metrics_coverage, phase_of, reconstruct_state,
)
from app.models import Alert, Incident, IncidentEvent, WindowMetrics
from tests.test_workflow import _build

CONFIG = load_config()
T0 = datetime(2026, 3, 10, 16, 0, 0, tzinfo=timezone.utc)
NOW = T0 + timedelta(hours=1)


def mins(n: float) -> datetime:
    return T0 + timedelta(minutes=n)


def incident(**kw) -> Incident:
    base = dict(id=1, fingerprint="error_rate:claims", kind="error_rate", service="claims", state="RESOLVED",
                peak_severity="HIGH", alert_count=2, opened_at=T0, resolved_at=mins(10), last_seen_at=mins(8),
                peak_score=0.7, latest_score=0.7, evidence_count=2)
    base.update(kw)
    return Incident(**base)


def metric(minute: float, errors=3, total=100, **kw) -> WindowMetrics:
    base = dict(service="claims", window_end=mins(minute), total=total, errors=errors, error_rate=errors / total,
                p95_latency_ms=200.0, urgent_errors=0, affected_patients_urgent=0, affected_patients_routine=2,
                baseline_mean=0.02, baseline_std=0.01)
    base.update(kw)
    return WindowMetrics(**base)


def alert(aid: int, minute: float, incident_id=1, severity="HIGH", **kw) -> Alert:
    base = dict(id=aid, ts=mins(minute), kind="error_rate", service="claims", severity=severity, score=0.7,
                explanation="claims error rate 30% vs baseline 2%", incident_id=incident_id,
                metrics={"error_rate": 0.3, "errors": 30, "total": 100, "baseline_mean": 0.02,
                         "baseline_std": 0.01, "z": 28.0})
    base.update(kw)
    return Alert(**base)


def event(eid: int, minute: float, etype: str, severity=None) -> IncidentEvent:
    return IncidentEvent(id=eid, incident_id=1, ts=mins(minute), event_type=etype, severity=severity)


def evidence(eid: int, minute: float, **record) -> dict:
    rec = {"ts": mins(minute).isoformat(), "type": "app", "service": "claims", "level": "ERROR", "msg": "Claim failed"}
    rec.update(record)
    return {"id": eid, "alert_id": 1, "ts": rec["ts"], "record": rec}


def data(**kw) -> TimelineData:
    base = dict(incident=incident(), events=[event(1, 0, "opened", "HIGH"), event(2, 10, "resolved")],
                alerts=[alert(1, 0), alert(2, 8)], evidence=[evidence(1, 1), evidence(2, 2)],
                metrics=[metric(m) for m in (-5, -2, 0, 2, 4, 6, 8, 10, 12)])
    base.update(kw)
    return TimelineData(**base)


def build(d: TimelineData, **q):
    return build_timeline(d, TimelineQuery(**q), CONFIG, now=NOW)


# -- ordering ---------------------------------------------------------------------------------


def test_entries_are_chronological_with_a_stable_tiebreak():
    out = build(data())
    stamps = [e["ts"] for e in out["entries"]]
    assert stamps == sorted(stamps)
    at_zero = [e["source"] for e in out["entries"] if e["ts"] == T0.isoformat()]
    assert at_zero == ["lifecycle", "alerts", "metrics"]  # same instant: lifecycle, alert, then metric


def test_out_of_order_input_is_sorted():
    shuffled = data(metrics=list(reversed(data().metrics)), alerts=[alert(2, 8), alert(1, 0)])
    stamps = [e["ts"] for e in build(shuffled)["entries"]]
    assert stamps == sorted(stamps)


def test_phases_before_during_after():
    out = build(data())
    by_ts = {e["ts"]: e["phase"] for e in out["entries"] if e["source"] == "metrics"}
    assert by_ts[mins(-5).isoformat()] == "before"
    assert by_ts[mins(0).isoformat()] == "during"       # opened_at is inclusive
    assert by_ts[mins(10).isoformat()] == "during"      # resolved_at is inclusive
    assert by_ts[mins(12).isoformat()] == "after"
    assert phase_of(mins(10) + timedelta(microseconds=1), T0, mins(10)) == "after"


# -- time boundaries --------------------------------------------------------------------------


def test_window_edges_are_inclusive_and_outside_is_excluded():
    d = data(metrics=[metric(-5), metric(-5.0001), metric(15), metric(15.0001)])
    out = build(d, before_minutes=5, after_minutes=5, sources=("metrics",))
    stamps = {e["ts"] for e in out["entries"]}
    assert mins(-5).isoformat() in stamps and mins(15).isoformat() in stamps
    assert mins(-5.0001).isoformat() not in stamps and mins(15.0001).isoformat() not in stamps


def test_zero_windows_show_only_the_incident_itself():
    out = build(data(), before_minutes=0, after_minutes=0)
    assert {e["phase"] for e in out["entries"]} == {"during"}


def test_window_is_clamped_to_24_hours():
    out = build(data(), before_minutes=99999, after_minutes=-4)
    assert out["query"]["before_minutes"] == 1440 and out["query"]["after_minutes"] == 0


def test_active_incident_during_extends_to_now():
    d = data(incident=incident(state="OPEN", resolved_at=None))
    out = build(d)
    assert out["anchor"]["resolved"] is False and out["anchor"]["end"] == NOW.isoformat()
    assert any("still active" in n for n in out["notes"])


# -- empty / expired / partial history --------------------------------------------------------


def test_empty_history_is_explicit_and_nothing_is_fabricated():
    d = TimelineData(incident=incident(evidence_count=0), events=[], alerts=[], evidence=[], metrics=[])
    out = build(d)
    assert out["entries"] == [] and out["count"] == 0
    assert out["coverage"]["metrics"]["status"] == "none"
    assert out["coverage"]["evidence"]["status"] == "none"
    assert any("No stored events" in n for n in out["notes"])
    assert out["explanation"]["available"] is False


def test_metrics_older_than_retention_are_reported_as_expired():
    old = incident(opened_at=T0 - timedelta(days=3), resolved_at=T0 - timedelta(days=3) + timedelta(minutes=5))
    d = TimelineData(incident=old, events=[], alerts=[], evidence=[], metrics=[])
    out = build_timeline(d, TimelineQuery(), CONFIG, now=NOW, retention_hours=24)
    cov = out["coverage"]["metrics"]
    assert cov["status"] == "expired" and "retention" in cov["message"]


def test_gaps_make_coverage_partial():
    d = data(metrics=[metric(-5), metric(-4), metric(-3), metric(6), metric(7), metric(8)])
    cov = build(d)["coverage"]["metrics"]
    assert cov["status"] == "partial" and cov["gaps"] and cov["gaps"][0]["seconds"] > 300


def test_user_based_incident_has_no_metric_coverage_claim():
    inc = incident(kind="hipaa_bulk_access", service=None, user_id="U-117", fingerprint="hipaa_bulk_access:U-117")
    out = build(TimelineData(incident=inc, events=[event(1, 0, "opened", "HIGH")], alerts=[], evidence=[], metrics=[]))
    assert out["coverage"]["metrics"]["status"] == "not_applicable"


def test_metric_downsampling_is_flagged():
    many = [metric(i * 0.1) for i in range(-30, 120)]
    out = build(data(metrics=many), sources=("metrics",), max_metric_points=20)
    assert out["downsampling"]["applied"] and out["count"] <= 22
    assert any("thinned" in n for n in out["notes"])


# -- baseline vs observed, rule, reason ------------------------------------------------------


def test_entries_carry_baseline_vs_observed_and_breach_flag():
    out = build(data(metrics=[metric(1, errors=30), metric(2, errors=1)]), sources=("metrics",))
    hot, calm = out["entries"]
    assert hot["observed"]["error_rate"] == 0.3 and hot["baseline"]["error_rate_mean"] == 0.02
    assert hot["breaches_threshold"] is True and calm["breaches_threshold"] is False


def test_metric_without_baseline_does_not_invent_one():
    out = build(data(metrics=[metric(1, baseline_mean=None, baseline_std=None)]), sources=("metrics",))
    e = out["entries"][0]
    assert e["baseline"] is None and e["z"] is None and e["breaches_threshold"] is None


def test_explanation_has_rule_threshold_observed_and_reason():
    ex = build(data())["explanation"]
    assert ex["available"] and ex["observed"]["error_rate"] == 0.3
    assert ex["baseline"]["mean"] == 0.02 and ex["threshold"]["z"] == CONFIG.anomaly.error_rate_z_threshold
    assert "baseline" in ex["reason"] and "standard deviations" in ex["rule_text"]


# -- replay / as_of ---------------------------------------------------------------------------


def test_as_of_replays_state_and_hides_the_future_without_changing_data():
    d = data(events=[event(1, 0, "opened", "MEDIUM"), event(2, 4, "escalated", "HIGH"), event(3, 6, "acknowledged"),
                     event(4, 10, "resolved")])
    snapshot = copy.deepcopy(d)
    early = build(d, as_of=mins(1))
    assert early["state_as_of"]["status"] == "OPEN" and early["state_as_of"]["severity"] == "MEDIUM"
    assert early["state_as_of"]["occurrences"] == 1
    assert all(e["ts"] <= mins(1).isoformat() for e in early["entries"])
    mid = build(d, as_of=mins(7))
    assert mid["state_as_of"]["status"] == "ACKNOWLEDGED" and mid["state_as_of"]["severity"] == "HIGH"
    end = build(d, as_of=mins(11))
    assert end["state_as_of"]["status"] == "RESOLVED" and end["state_as_of"]["occurrences"] == 2
    assert d.events == snapshot.events and d.alerts == snapshot.alerts and d.metrics == snapshot.metrics


def test_reconstruct_state_before_the_incident_exists():
    state = reconstruct_state(incident(), [event(1, 0, "opened", "HIGH")], [alert(1, 0)], mins(-1))
    assert state["status"] == "NOT_YET_OPENED" and state["occurrences"] == 0 and state["events_applied"] == 0


def test_reopened_state_is_replayed():
    evs = [event(1, 0, "opened", "HIGH"), event(2, 5, "resolved"), event(3, 6, "reopened", "HIGH")]
    assert reconstruct_state(incident(), evs, [], mins(7))["status"] == "OPEN"
    assert reconstruct_state(incident(), evs, [], mins(5.5))["status"] == "RESOLVED"


# -- selection ids and redaction ---------------------------------------------------------------


def test_every_entry_has_a_unique_selectable_id():
    entries = build(data())["entries"]
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))
    prefixes = {i.split(":")[0] for i in ids}
    assert prefixes == {"metric", "alert", "lifecycle", "evidence"}


def test_summaries_are_redacted_on_the_way_out():
    from app.privacy.redaction import Redactor

    r = Redactor.build()
    d = data(evidence=[evidence(1, 1, msg="user jane@example.org called 615-555-0100")])
    out = build_timeline(d, TimelineQuery(), CONFIG, now=NOW, redact=r.redact_value)
    text = " ".join(e["summary"] for e in out["entries"])
    assert "jane@example.org" not in text and "615-555-0100" not in text


def test_metrics_coverage_function_handles_no_service():
    d = data(incident=incident(service=None, user_id="U-1", kind="hipaa_bulk_access"))
    assert metrics_coverage(d, T0, NOW, NOW, 24)["status"] == "not_applicable"


# -- API: persisted data, selection, read-only ---------------------------------------------------


def _seed_store(client, pipeline):
    """Persist an incident with its alert, events, evidence and metrics, inside the app's event loop."""
    from app.models import Anomaly

    async def go():
        anomaly = Anomaly(kind="error_rate", ts=T0, service="claims", z=5.0)
        alert_ = Alert(ts=T0, kind="error_rate", service="claims", severity="HIGH", score=0.7,
                       explanation="claims error rate 30% vs baseline 2%",
                       metrics={"error_rate": 0.3, "errors": 30, "total": 100, "baseline_mean": 0.02,
                                "baseline_std": 0.01, "z": 28.0})
        update = pipeline.incidents.record_alert(anomaly, alert_)
        alert_.incident_id = update.incident.id
        alert_.id = await pipeline.store.save_alert(alert_)
        await pipeline.apply_incident_update(update)
        await pipeline.store.save_evidence(update.incident.id, alert_.id, [
            {"ts": T0.isoformat(), "type": "app", "service": "claims", "level": "ERROR", "msg": "Claim failed",
             "request_id": "CLM-1", "email": "jane@example.org"}])
        for minute in (-3, -1, 0, 2):
            await pipeline.store.save_metrics(metric(minute))
        return update.incident.id

    return client.portal.call(go)


def _counts(client, pipeline):
    async def go():
        out = {}
        for table in ("metrics", "alerts", "incidents", "incident_events", "evidence_events", "audit_log"):
            row = await (await pipeline.store.conn.execute(f"SELECT COUNT(*) FROM {table}")).fetchone()
            out[table] = row[0]
        return out

    return client.portal.call(go)


def test_api_timeline_selection_and_read_only(tmp_path: Path):
    app, pipeline = _build(tmp_path, operator_token="s3cret", retention_metrics_hours=0)
    with TestClient(app) as c:
        iid = _seed_store(c, pipeline)
        before = _counts(c, pipeline)
        body = c.get(f"/api/incidents/{iid}/timeline", params={"before_minutes": 10, "after_minutes": 10}).json()
        assert body["read_only"] is True and body["count"] == 7  # 4 metrics, alert, opened event, evidence
        sources = {e["source"] for e in body["entries"]}
        assert sources == {"metrics", "alerts", "lifecycle", "evidence"}
        assert body["explanation"]["available"] and body["explanation"]["observed"]["error_rate"] == 0.3
        # select every entry and read its raw details
        for entry in body["entries"]:
            detail = c.get(f"/api/incidents/{iid}/timeline/{entry['id']}")
            assert detail.status_code == 200, entry["id"]
            assert detail.json()["raw"]
        ev = next(e for e in body["entries"] if e["source"] == "evidence")
        raw = c.get(f"/api/incidents/{iid}/timeline/{ev['id']}").json()["raw"]
        assert raw["record"]["email"] == "[REDACTED]"                 # redacted before display
        # replay never writes
        c.get(f"/api/incidents/{iid}/timeline", params={"as_of": (T0 + timedelta(seconds=1)).isoformat()})
        assert _counts(c, pipeline) == before


def test_api_timeline_errors(tmp_path: Path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        iid = _seed_store(c, pipeline)
        assert c.get("/api/incidents/9999/timeline").status_code == 404
        assert c.get(f"/api/incidents/{iid}/timeline", params={"sources": "bogus"}).status_code == 422
        assert c.get(f"/api/incidents/{iid}/timeline", params={"before_minutes": -1}).status_code == 422
        assert c.get(f"/api/incidents/{iid}/timeline/alert:99999").status_code == 404
        assert c.get(f"/api/incidents/{iid}/timeline/nonsense:1").status_code == 404
        assert c.get(f"/api/incidents/{iid}/timeline/metric:not-a-time").status_code == 422


def test_api_empty_history_for_incident_without_metrics(tmp_path: Path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        iid = _seed_store(c, pipeline)
        body = c.get(f"/api/incidents/{iid}/timeline", params={"sources": "metrics"}).json()
        assert body["count"] == 4  # only the stored points; no padding
        far = c.get(f"/api/incidents/{iid}/timeline", params={"sources": "evidence", "before_minutes": 0,
                                                             "after_minutes": 0, "as_of": (T0 - timedelta(days=1)).isoformat()}).json()
        assert far["count"] == 0 and far["notes"]
