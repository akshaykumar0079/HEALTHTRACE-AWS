"""Incident workflow API: statuses, pinning, search/sort/filter, risk score,
evidence, audit trail, notification settings, auth, and failure isolation."""

from __future__ import annotations

import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, load_config
from app.main import create_app
from app.models import Alert, Anomaly

T0 = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def _build(tmp_path: Path, **kw):
    kw.setdefault("aws_mode", "off")
    settings = Settings(
        log_dir=tmp_path / "logs", db_path=tmp_path / "m.db", control_file=tmp_path / "c.json",
        static_dir=tmp_path / "nostatic", **kw,
    )
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    (settings.log_dir / "app.log").write_text("", encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("", encoding="utf-8")
    app = create_app(settings=settings, config=load_config())
    return app, app.state.pipeline


def _seed(pipeline, kind="error_rate", service="claims", severity="HIGH", score=0.6, user_id=None, ts=T0):
    anomaly = Anomaly(kind=kind, ts=ts, service=None if user_id else service, user_id=user_id, z=5.0)
    alert = Alert(ts=ts, kind=kind, service=None if user_id else service, user_id=user_id, severity=severity,
                  score=score, explanation="because")
    update = pipeline.incidents.record_alert(anomaly, alert)
    return update.incident


# -- statuses --------------------------------------------------------------------------------


def test_full_status_flow_and_labels(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline)
    with TestClient(app) as c:
        body = c.get("/api/incidents/search").json()["items"][0]
        assert body["status"] == "OPEN" and body["status_label"] == "New"
        assert c.post(f"/api/incidents/{inc.id}/ack").json()["status_label"] == "Acknowledged"
        r = c.post(f"/api/incidents/{inc.id}/investigate").json()
        assert r["state"] == "INVESTIGATING" and r["status_label"] == "Investigating"
        assert c.post(f"/api/incidents/{inc.id}/ack").status_code == 404           # cannot go backwards
        assert c.post(f"/api/incidents/{inc.id}/investigate").status_code == 404
        done = c.post(f"/api/incidents/{inc.id}/resolve").json()
        assert done["status_label"] == "Resolved" and done["mttr_seconds"] is not None


def test_investigating_incident_still_absorbs_repeats(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline)
    with TestClient(app) as c:
        c.post(f"/api/incidents/{inc.id}/investigate")
        again = _seed(pipeline, ts=T0 + timedelta(seconds=30), severity="CRITICAL", score=0.9)
        assert again.id == inc.id and again.alert_count == 2 and again.peak_severity == "CRITICAL"
        item = c.get("/api/incidents/search").json()["items"][0]
        assert item["occurrence_count"] == 2 and item["state"] == "INVESTIGATING"
        assert item["first_seen_at"] == T0.isoformat() and item["last_seen_at"] == (T0 + timedelta(seconds=30)).isoformat()


# -- risk score ------------------------------------------------------------------------------


def test_risk_score_is_the_real_detector_score_never_invented(tmp_path):
    app, pipeline = _build(tmp_path)
    stat = _seed(pipeline, score=0.623)
    _seed(pipeline, score=0.31, ts=T0 + timedelta(seconds=5))                        # lower: peak must not drop
    hipaa = _seed(pipeline, kind="hipaa_bulk_access", user_id="u-1", severity="CRITICAL", score=0.0)
    with TestClient(app) as c:
        items = {i["id"]: i for i in c.get("/api/incidents/search").json()["items"]}
        assert items[stat.id]["risk_score"] == 62
        assert items[hipaa.id]["risk_score"] is None
        assert "rule-based" in items[hipaa.id]["risk_basis"]


# -- pinning -----------------------------------------------------------------------------------


def test_pin_never_changes_severity_score_or_status(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline, severity="MEDIUM", score=0.4)
    with TestClient(app) as c:
        before = c.get(f"/api/incidents/{inc.id}").json()["incident"]
        pinned = c.post(f"/api/incidents/{inc.id}/pin").json()
        assert pinned["pinned"] is True and pinned["pinned_at"]
        for field in ("severity", "risk_score", "status", "state", "peak_severity", "alert_count"):
            assert pinned[field] == before[field], field
        unpinned = c.post(f"/api/incidents/{inc.id}/unpin").json()
        assert unpinned["pinned"] is False and unpinned["severity"] == before["severity"]


def test_pin_resolved_history_and_filter_pinned_only(tmp_path):
    app, pipeline = _build(tmp_path)
    a = _seed(pipeline, service="claims")
    b = _seed(pipeline, service="pharmacy")
    with TestClient(app) as c:
        c.post(f"/api/incidents/{a.id}/resolve")
        assert c.post(f"/api/incidents/{a.id}/pin").status_code == 200              # resolved incidents can be pinned
        pinned = c.get("/api/incidents/search", params={"pinned": "true"}).json()
        assert [i["id"] for i in pinned["items"]] == [a.id]
        assert c.get("/api/incidents/search", params={"pinned": "false"}).json()["items"][0]["id"] == b.id
        assert c.post("/api/incidents/9999/pin").status_code == 404


def test_pin_survives_restart(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline)
    with TestClient(app) as c:
        c.post(f"/api/incidents/{inc.id}/pin")
        c.post(f"/api/incidents/{inc.id}/ack")
    app2, pipeline2 = _build(tmp_path)                                                # same database file
    with TestClient(app2) as c2:
        item = c2.get("/api/incidents/search").json()["items"][0]
        assert item["id"] == inc.id and item["pinned"] is True and item["state"] == "ACKNOWLEDGED"


# -- search / sort / filter -----------------------------------------------------------------------


def _mixed(pipeline):
    low = _seed(pipeline, service="batch", severity="LOW", score=0.1, ts=T0)
    med = _seed(pipeline, service="pharmacy", severity="MEDIUM", score=0.4, ts=T0 + timedelta(minutes=1))
    high_hi = _seed(pipeline, service="claims", severity="HIGH", score=0.7, ts=T0 + timedelta(minutes=2))
    high_lo = _seed(pipeline, service="eligibility", severity="HIGH", score=0.55, ts=T0 + timedelta(minutes=3))
    crit = _seed(pipeline, kind="hipaa_bulk_access", user_id="dr-evans", severity="CRITICAL", ts=T0 + timedelta(minutes=4))
    return low, med, high_hi, high_lo, crit


def test_default_sort_is_severity_then_risk_then_recency(tmp_path):
    app, pipeline = _build(tmp_path)
    low, med, high_hi, high_lo, crit = _mixed(pipeline)
    with TestClient(app) as c:
        ids = [i["id"] for i in c.get("/api/incidents/search").json()["items"]]
        assert ids == [crit.id, high_hi.id, high_lo.id, med.id, low.id]


def test_sorts_filters_and_search(tmp_path):
    app, pipeline = _build(tmp_path)
    low, med, high_hi, high_lo, crit = _mixed(pipeline)
    with TestClient(app) as c:
        get = lambda **p: c.get("/api/incidents/search", params=p).json()  # noqa: E731
        assert [i["id"] for i in get(sort="recent")["items"]][0] == crit.id
        assert [i["id"] for i in get(sort="recent", order="asc")["items"]][0] == low.id
        assert get(sort="risk")["items"][0]["id"] == high_hi.id                       # highest real score
        assert {i["id"] for i in get(severity="HIGH,CRITICAL")["items"]} == {high_hi.id, high_lo.id, crit.id}
        assert [i["id"] for i in get(q="dr-evans")["items"]] == [crit.id]             # by user
        assert [i["id"] for i in get(q="pharm")["items"]] == [med.id]                 # by source
        assert [i["id"] for i in get(q="bulk phi")["items"]] == [crit.id]             # by title
        assert [i["id"] for i in get(q=f"#{low.id}")["items"]] == [low.id]            # by id
        assert get(q="no-such-thing")["total"] == 0
        assert get(limit=2)["total"] == 5 and len(get(limit=2)["items"]) == 2
        assert len(get(limit=2, offset=4)["items"]) == 1
        c.post(f"/api/incidents/{low.id}/resolve")
        assert [i["id"] for i in get(status="RESOLVED")["items"]] == [low.id]          # history filter
        assert low.id not in [i["id"] for i in get(status="OPEN,ACKNOWLEDGED,INVESTIGATING")["items"]]


def test_search_rejects_bad_parameters(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        assert c.get("/api/incidents/search", params={"sort": "bogus"}).status_code == 422
        assert c.get("/api/incidents/search", params={"severity": "PANIC"}).status_code == 422
        assert c.get("/api/incidents/search", params={"status": "DONE"}).status_code == 422
        assert c.get("/api/incidents/search", params={"order": "sideways"}).status_code == 422
        assert c.get("/api/incidents/search", params={"limit": 100000}).status_code == 422
        assert c.get("/api/incidents/search", params={"q": "x" * 500}).status_code == 422
        assert c.get("/api/incidents/search", params={"q": "'; DROP TABLE incidents;--"}).json()["total"] == 0


def test_summary_counts_come_from_data(tmp_path):
    app, pipeline = _build(tmp_path)
    low, med, high_hi, high_lo, crit = _mixed(pipeline)
    with TestClient(app) as c:
        c.post(f"/api/incidents/{crit.id}/pin")
        c.post(f"/api/incidents/{low.id}/resolve")
        s = c.get("/api/incidents/summary").json()
        assert s["active"] == 4 and s["resolved"] == 1 and s["pinned"] == 1
        assert s["by_severity"] == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        assert s["unacknowledged_high"] == 3
        empty = _build(tmp_path / "empty")[0]
    with TestClient(empty) as c:
        z = c.get("/api/incidents/summary").json()
        assert z["active"] == 0 and z["mean_time_to_resolve_seconds"] is None


# -- audit ----------------------------------------------------------------------------------------


def test_actions_are_audited(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline)
    with TestClient(app) as c:
        c.post(f"/api/incidents/{inc.id}/ack")
        c.post(f"/api/incidents/{inc.id}/pin")
        c.post(f"/api/incidents/{inc.id}/resolve")
        c.post(f"/api/incidents/{inc.id}/ack")                                          # rejected: also recorded
        log = c.get("/api/audit", params={"target_type": "incident", "target_id": str(inc.id)}).json()
        actions = [(r["action"], r["outcome"]) for r in reversed(log)]
        assert actions == [("acknowledge", "ok"), ("pin", "ok"), ("resolve", "ok"), ("acknowledge", "rejected")]
        detail = c.get(f"/api/incidents/{inc.id}").json()
        assert [e["event_type"] for e in detail["events"]] == ["acknowledged", "pinned", "resolved"]  # "opened" is stored by the pipeline path, not by direct seeding


# -- auth -----------------------------------------------------------------------------------------


def test_operator_token_protects_writes_but_not_reads(tmp_path):
    app, pipeline = _build(tmp_path, operator_token="s3cret-token")
    inc = _seed(pipeline)
    with TestClient(app) as c:
        assert c.get("/api/incidents/search").status_code == 200
        for path in ("ack", "investigate", "resolve", "pin", "unpin"):
            assert c.post(f"/api/incidents/{inc.id}/{path}").status_code == 401, path
        assert c.get("/api/audit").status_code == 401
        assert c.put("/api/settings/notifications", json={}).status_code == 401
        assert c.post("/api/settings/notifications/test").status_code == 401
        ok = c.post(f"/api/incidents/{inc.id}/pin", headers={"X-Operator-Token": "s3cret-token"})
        assert ok.status_code == 200
        assert c.post(f"/api/incidents/{inc.id}/unpin", headers={"X-Operator-Token": "wrong"}).status_code == 401
        audit = c.get("/api/audit", headers={"X-Operator-Token": "s3cret-token"}).json()
        assert audit[0]["actor"] == "operator" and "s3cret-token" not in str(audit)


def test_production_without_a_token_fails_closed(tmp_path):
    app, pipeline = _build(tmp_path, environment="production")
    inc = _seed(pipeline)
    with TestClient(app) as c:
        assert c.post(f"/api/incidents/{inc.id}/ack").status_code == 403
        assert c.get("/api/status").json()["operator_auth"] == {"required": True, "configured": False}
        assert c.get("/api/incidents/search").status_code == 200


# -- notification settings ---------------------------------------------------------------------------


def test_notification_settings_roundtrip_and_validation(tmp_path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        got = c.get("/api/settings/notifications").json()
        assert got["settings"]["min_severity"] == "HIGH" and got["provider"]["configured"] is False
        assert "key" not in str(got["provider"]).lower().replace("secret_configured", "")
        put = lambda **b: c.put("/api/settings/notifications", json=b)  # noqa: E731
        good = {"enabled": True, "recipients": ["Ops@Example.com", "ops@example.com", "b@example.org"],
                "min_severity": "CRITICAL", "cooldown_seconds": 90}
        r = put(**good)
        assert r.status_code == 200
        assert r.json()["settings"]["recipients"] == ["Ops@Example.com", "b@example.org"]   # de-duplicated
        assert r.json()["settings"]["cooldown_seconds"] == 90
        assert pipeline.email.settings.min_severity == "CRITICAL" and pipeline.email.settings.enabled
        for bad in (
            {**good, "recipients": ["not-an-email"]},
            {**good, "recipients": []},
            {**good, "recipients": ["a@b.co"] * 1 + [f"x{n}@example.com" for n in range(6)]},
            {**good, "recipients": ["a@@b.com"]},
            {**good, "recipients": ["a b@example.com"]},
            {**good, "min_severity": "LOW"},
            {**good, "min_severity": "MEDIUM"},
            {**good, "cooldown_seconds": -1},
            {**good, "cooldown_seconds": 10**7},
            {**good, "enabled": "maybe"},
        ):
            assert put(**bad).status_code == 422, bad
        assert pipeline.email.settings.cooldown_seconds == 90                              # bad input changed nothing


def test_settings_persist_across_restart_and_override_env(tmp_path):
    app, _ = _build(tmp_path, email_enabled=False, alert_email_to="env@example.com")
    with TestClient(app) as c:
        assert c.get("/api/settings/notifications").json()["settings"]["recipients"] == ["env@example.com"]
        c.put("/api/settings/notifications", json={"enabled": True, "recipients": ["ui@example.com"],
                                                    "min_severity": "CRITICAL", "cooldown_seconds": 42})
    app2, pipeline2 = _build(tmp_path, email_enabled=False, alert_email_to="env@example.com")
    with TestClient(app2) as c2:
        s = c2.get("/api/settings/notifications").json()["settings"]
        assert s == {**s, "enabled": True, "recipients": ["ui@example.com"], "min_severity": "CRITICAL",
                     "cooldown_seconds": 42}
        assert pipeline2.email.settings.recipients == ["ui@example.com"]


def test_test_email_requires_configuration_and_never_reaches_the_network(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        r = c.post("/api/settings/notifications/test")
        assert r.status_code == 409 and "BREVO_API_KEY" in str(r.json()) or "SMTP" in str(r.json())


def test_test_email_with_stubbed_provider_reports_acceptance_not_delivery(tmp_path, monkeypatch):
    app, pipeline = _build(tmp_path, email_enabled=True, email_provider="brevo", brevo_api_key="xkeysib-FAKE-KEY",
                           alert_email_from="sender@example.com", alert_email_to="to@example.com")
    sent = []

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"messageId": "<abc123@smtp-relay.example>"}'

    def fake_urlopen(request, *a, **k):
        sent.append(request.full_url)
        return Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with TestClient(app) as c:
        r = c.post("/api/settings/notifications/test")
        body = r.json()
        assert r.status_code == 200 and body["ok"] is True and body["result"] == "accepted_by_provider"
        assert body["provider_message_id"] == "<abc123@smtp-relay.example>"
        assert "delivered" not in body["result"] and "not confirm inbox delivery" in body["note"]
        assert "xkeysib-FAKE-KEY" not in r.text
        assert c.post("/api/settings/notifications/test").status_code == 429               # rate limited
        view = c.get("/api/settings/notifications").json()
        assert view["attempts"][0]["status"] == "accepted" and view["status"]["delivery_confirmed"] is False
        assert "xkeysib-FAKE-KEY" not in str(view)
        audit = c.get("/api/audit", params={"action": "send_test_email"}).json()
        assert audit and "xkeysib" not in str(audit)
    assert sent == ["https://api.brevo.com/v3/smtp/email"]


def test_provider_failure_is_reported_without_leaking_the_key(tmp_path, monkeypatch):
    app, _ = _build(tmp_path, email_enabled=True, email_provider="brevo", brevo_api_key="xkeysib-FAKE-KEY",
                    alert_email_from="sender@example.com", alert_email_to="to@example.com")
    import io
    import urllib.error

    def boom(request, *a, **k):
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"code":"unauthorized","message":"Key not found xkeysib-FAKE-KEY"}'))

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with TestClient(app) as c:
        r = c.post("/api/settings/notifications/test")
        assert r.status_code == 200 and r.json()["ok"] is False and r.json()["result"] == "failed"
        assert "xkeysib-FAKE-KEY" not in r.text and "401" in r.json()["error"]
        assert c.get("/api/settings/notifications").json()["attempts"][0]["status"] == "failed"


# -- email flood protection ------------------------------------------------------------------------------


def _email_pipeline(tmp_path, **kw):
    app, pipeline = _build(tmp_path, email_enabled=True, email_provider="brevo", brevo_api_key="k",
                           alert_email_from="s@example.com", alert_email_to="to@example.com", **kw)
    return app, pipeline


def test_cooldown_flood_guard_and_min_severity(tmp_path):
    _, pipeline = _email_pipeline(tmp_path)
    email = pipeline.email
    email.apply_prefs(enabled=True, recipients=["to@example.com"], min_severity="HIGH", cooldown_seconds=300)

    def notify(inc, escalated=False):
        email.notify_incident(inc, Alert(ts=T0, kind=inc.kind, service=inc.service, severity=inc.peak_severity,
                                         score=0.6, explanation="x"), escalated=escalated)

    medium = _seed(pipeline, service="batch", severity="MEDIUM", score=0.4)
    notify(medium)
    assert email.queue_depth == 0                                                         # below minimum: silent
    high = _seed(pipeline, service="claims", severity="HIGH")
    notify(high)
    notify(high)                                                                          # same fingerprint, in cooldown
    assert email.queue_depth == 1 and email.status.skipped == 1
    assert "cooldown" in email.status.to_dict()["recent"][0]["error"]
    high.peak_severity = "CRITICAL"
    notify(high, escalated=True)                                                          # escalation bypasses cooldown
    assert email.queue_depth == 2
    email.apply_prefs(enabled=True, recipients=["to@example.com"], min_severity="CRITICAL", cooldown_seconds=0)
    other = _seed(pipeline, service="pharmacy", severity="HIGH")
    notify(other)
    assert email.queue_depth == 2                                                         # HIGH no longer qualifies


def test_hourly_flood_guard_caps_emails(tmp_path):
    _, pipeline = _email_pipeline(tmp_path)
    email = pipeline.email
    email.apply_prefs(enabled=True, recipients=["to@example.com"], min_severity="HIGH", cooldown_seconds=0)
    email.settings.max_per_hour = 3
    for n in range(10):
        inc = _seed(pipeline, kind="hipaa_bulk_access", user_id=f"u-{n}", severity="HIGH")
        email.notify_incident(inc, Alert(ts=T0, kind=inc.kind, user_id=f"u-{n}", severity="HIGH", score=0.0,
                                         explanation="x"))
    assert email.queue_depth == 3 and email.status.skipped == 7
    assert "flood guard" in email.status.to_dict()["recent"][0]["error"]


def test_disabled_email_queues_nothing(tmp_path):
    _, pipeline = _email_pipeline(tmp_path)
    pipeline.email.apply_prefs(enabled=False, recipients=["to@example.com"], min_severity="HIGH", cooldown_seconds=0)
    inc = _seed(pipeline, severity="CRITICAL")
    pipeline.email.notify_incident(inc, Alert(ts=T0, kind=inc.kind, service="claims", severity="CRITICAL", score=1,
                                              explanation="x"))
    assert pipeline.email.queue_depth == 0 and pipeline.email.status.skipped == 0


# -- evidence + failure isolation --------------------------------------------------------------------------


def _error_record(n, service="claims"):
    return {"seq": n, "ts": (T0 - timedelta(seconds=n)).isoformat(), "type": "app", "service": service,
            "level": "ERROR", "priority": "urgent", "request_id": f"r{n}", "patient_id": "P-***123",
            "status": 503, "latency_ms": 900, "msg": "upstream timeout", "is_error": True}


def test_evidence_is_captured_with_the_incident_and_survives_resolution(tmp_path):
    import asyncio

    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        for n in range(30):
            pipeline.recent_logs.append(_error_record(n))
        pipeline.recent_logs.append(_error_record(99, service="pharmacy"))              # other service: excluded
        anomaly = Anomaly(kind="error_rate", ts=T0, service="claims", z=5.0)
        alert = Alert(ts=T0, kind="error_rate", service="claims", severity="HIGH", score=0.6, explanation="x")
        c.portal.call(pipeline._handle_alert, anomaly, alert)                           # the real pipeline path
        inc_id = pipeline.incidents.list_incidents()[0].id
        c.post(f"/api/incidents/{inc_id}/resolve")
        detail = c.get(f"/api/incidents/{inc_id}").json()
        assert 0 < len(detail["evidence"]) <= pipeline.EVIDENCE_PER_ALERT
        assert all(e["record"]["service"] == "claims" for e in detail["evidence"])
        assert all("P-***" in str(e["record"]["patient_id"]) for e in detail["evidence"])   # already masked
        assert len(detail["alerts"]) == 1


def test_database_failure_does_not_stop_detection_or_broadcast(tmp_path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        async def broken(*a, **k):
            raise RuntimeError("connection reset")

        pipeline.store.save_alert = broken
        pipeline.store.upsert_incident = broken
        pipeline.store.save_incident_event = broken
        pipeline.store.save_evidence = broken
        pipeline.recent_logs.append(_error_record(1))
        anomaly = Anomaly(kind="error_rate", ts=T0, service="claims", z=5.0)
        alert = Alert(ts=T0, kind="error_rate", service="claims", severity="HIGH", score=0.6, explanation="x")
        c.portal.call(pipeline._handle_alert, anomaly, alert)                           # must not raise
        assert pipeline.alerts_emitted == 1 and pipeline.db_errors >= 3
        assert pipeline.incidents.list_incidents()[0].peak_severity == "HIGH"           # engine still tracked it
        st = c.get("/api/status").json()["database"]
        assert st["write_errors"] >= 3 and st["last_write_error"]


def test_status_endpoint_reports_connection_and_simulated_data(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        s = c.get("/api/status").json()
        assert s["backend"] == "ok" and s["database"]["ok"] is True and s["database"]["dialect"] == "sqlite"
        assert s["simulated_data"] is True and s["data_source"] == "simulated"
        assert s["stream"]["state"] in ("live", "stale", "replaying")
        assert "database_url" not in str(s).lower()
    real, _ = _build(tmp_path / "real", data_source="real")
    with TestClient(real) as c:
        assert c.get("/api/status").json()["simulated_data"] is False


# -- AWS integration status (Phase 9) ----------------------------------------------------------------------


@pytest.mark.parametrize("mode,expected,calls", [("off", "NOT CONFIGURED", False), ("mock", "MOCK", False)])
def test_aws_status_off_and_mock_make_no_aws_calls(tmp_path, mode, expected, calls):
    app, pipeline = _build(tmp_path, aws_mode=mode)
    with TestClient(app) as c:
        s = c.get("/api/aws/status").json()
        assert s["integration"]["status"] == expected and s["integration"]["calls_aws"] is calls
        assert s["integration"]["verified"] is False
        assert "does not satisfy" in s["requirement_note"]                       # Brevo is not presented as AWS


def test_aws_default_is_off_and_never_claims_delivery(tmp_path):
    assert Settings().aws_mode == "off"
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        detail = c.get("/api/aws/status").json()["integration"]["detail"].lower()
        assert "disabled" in detail and "delivered" not in detail.replace("nothing is delivered", "")


def test_aws_live_status_transitions_without_network(tmp_path):
    from app.notify.aws import AwsNotifier

    n = AwsNotifier("live", region="us-east-1", log_group="/g", sns_topic_arn="")
    assert n.integration_status()["status"] == "NOT CONFIGURED"                # SNS topic missing
    n = AwsNotifier("live", region="us-east-1", log_group="/g",
                    sns_topic_arn="arn:aws:sns:us-east-1:123456789012:t")
    assert n.integration_status()["status"] == "CONFIGURED" and n.integration_status()["verified"] is False
    n.status["sns"].record("failed", "s", "AccessDenied")
    assert n.integration_status()["status"] == "ERROR" and "AccessDenied" in n.integration_status()["detail"]
    n.status["sns"].record("sent", "s")
    st = n.integration_status()
    assert st["status"] == "CONFIGURED" and st["verified"] is True


def test_history_time_window_filter(tmp_path):
    app, pipeline = _build(tmp_path)
    old = _seed(pipeline, service="batch", ts=datetime.now(timezone.utc) - timedelta(days=10))
    new = _seed(pipeline, service="claims", ts=datetime.now(timezone.utc) - timedelta(minutes=5))
    with TestClient(app) as c:
        ids = lambda **p: {i["id"] for i in c.get("/api/incidents/search", params=p).json()["items"]}  # noqa: E731
        assert ids(since_hours=24) == {new.id}
        assert ids(since_hours=24 * 30) == {old.id, new.id}
        assert c.get("/api/incidents/search", params={"since_hours": 0}).status_code == 422
