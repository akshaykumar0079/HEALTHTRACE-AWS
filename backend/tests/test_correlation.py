"""Cross-system correlation: valid links, unrelated events, missing fields,
window boundaries, late arrivals, and the reasons shown for each link."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.correlation.engine import CorrelationEngine, RULES, correlate
from app.correlation.events import AdapterError, normalize, normalize_all
from app.correlation.synthetic import demo_records
from tests.test_workflow import _build, _seed

T0 = datetime(2026, 3, 10, 16, 0, 0, tzinfo=timezone.utc)


def iso(sec: float) -> str:
    return (T0 + timedelta(seconds=sec)).isoformat()


def ev(source, sec, **raw):
    return normalize(source, {"ts": iso(sec), **raw})


def group_ids(result):
    return [sorted(e["id"] for e in g["events"]) for g in result["groups"]]


# -- adapters ------------------------------------------------------------------------------


def test_every_source_normalises_to_the_same_interface():
    cases = {
        "app": {"ts": iso(0), "service": "claims", "level": "ERROR", "status": 500, "request_id": "r1", "msg": "x"},
        "auth": {"ts": iso(0), "user_id": "U-1", "outcome": "failure"},
        "audit": {"ts": iso(0), "user_id": "U-1", "action": "VIEW_RECORD", "patient_id": "P-1"},
        "server": {"ts": iso(0), "host": "h1", "process": "worker", "level": "ERROR", "message": "boom"},
        "db_audit": {"ts": iso(0), "db_user": "U-1", "statement_type": "SELECT", "object": "patients"},
    }
    for source, raw in cases.items():
        e = normalize(source, raw)
        assert e.source == source and e.ts == T0 and e.id.startswith(source + ":")
    assert normalize("app", cases["app"]).outcome == "error"
    assert normalize("server", cases["server"]).outcome == "error"
    assert normalize("db_audit", cases["db_audit"]).actor == "U-1"


def test_event_ids_are_deterministic():
    raw = {"ts": iso(0), "user_id": "U-1", "outcome": "success"}
    assert normalize("auth", raw).id == normalize("auth", dict(raw)).id


def test_records_without_a_usable_timestamp_are_reported_not_invented():
    events, skipped = normalize_all([
        ("auth", {"user_id": "U-1", "outcome": "success"}),
        ("auth", {"ts": "not a time", "user_id": "U-1"}),
        ("nope", {"ts": iso(0)}),
        ("auth", {"ts": iso(0), "user_id": "U-1", "outcome": "success"}),
    ])
    assert len(events) == 1
    assert [s["reason"] for s in skipped] == ["missing_timestamp", "bad_timestamp", "unknown_source"]
    with pytest.raises(AdapterError):
        normalize("auth", {})


def test_naive_timestamps_are_treated_as_utc():
    e = normalize("auth", {"ts": "2026-03-10T16:00:00", "user_id": "U-1"})
    assert e.ts == T0


def test_masked_patient_ids_are_never_a_join_key():
    e = normalize("app", {"ts": iso(0), "patient_id": "P-****42", "service": "claims"})
    assert e.resource is None
    a = normalize("app", {"ts": iso(0), "patient_id": "P-****42", "service": "claims"})
    b = normalize("db_audit", {"ts": iso(1), "object": "P-****42"})
    assert correlate([a, b])["groups"] == []


# -- valid correlations --------------------------------------------------------------------


def test_login_chain_links_by_actor_and_explains_why():
    result = correlate([
        ev("auth", 0, id="1", user_id="U-1", outcome="failure"),
        ev("auth", 60, id="2", user_id="U-1", outcome="success"),
        ev("db_audit", 120, id="3", db_user="U-1", statement_type="SELECT", object="patients"),
    ])
    assert group_ids(result) == [["auth:1", "auth:2", "db_audit:3"]]
    why = " ".join(result["groups"][0]["why"])
    assert "same actor (U-1)" in why and "after auth event" in why
    assert {l["rule"] for l in result["groups"][0]["links"]} == {"failed_then_successful_login", "login_then_record_access"}


def test_request_id_links_across_systems():
    result = correlate([
        ev("app", 0, id="a", service="claims", level="ERROR", status=500, request_id="rq-1"),
        ev("server", 20, id="s", host="h1", process="w", level="INFO", message="m", request_id="rq-1"),
    ])
    assert group_ids(result) == [["app:a", "server:s"]]
    assert "same request id (rq-1)" in result["groups"][0]["why"][0]


def test_app_error_and_server_fault_link_on_host():
    result = correlate([
        ev("app", 0, id="a", service="claims", level="ERROR", status=500, host="h1"),
        ev("server", 10, id="s", host="h1", process="w", level="ERROR", message="m"),
    ])
    assert group_ids(result) == [["app:a", "server:s"]]


def test_same_exact_record_links_app_and_db_audit():
    result = correlate([
        ev("app", 0, id="a", service="claims", level="INFO", status=200, patient_id="P-777"),
        ev("db_audit", 5, id="d", db_user="svc", statement_type="SELECT", object="P-777"),
    ])
    assert group_ids(result) == [["app:a", "db_audit:d"]]


# -- unrelated events, coincidence in time --------------------------------------------------


def test_events_in_the_same_second_with_nothing_in_common_are_not_linked():
    result = correlate([
        ev("auth", 0, id="1", user_id="U-1", outcome="success"),
        ev("audit", 0, id="2", user_id="U-2", action="VIEW_RECORD", patient_id="P-1"),
        ev("server", 0, id="3", host="h1", process="w", level="ERROR", message="m"),
        ev("app", 0, id="4", service="claims", level="ERROR", status=500, host="h2", request_id="r9"),
        ev("db_audit", 0, id="5", db_user="U-3", statement_type="SELECT", object="P-9"),
    ])
    assert result["groups"] == [] and result["unlinked_event_count"] == 5


def test_same_actor_but_wrong_direction_or_filter_is_not_linked():
    # record access BEFORE the login does not follow the login
    before = correlate([
        ev("db_audit", 0, id="d", db_user="U-1", statement_type="SELECT", object="t"),
        ev("auth", 60, id="a", user_id="U-1", outcome="success"),
    ])
    assert before["groups"] == []
    # a FAILED login is not followed by "record access" (only a successful one is)
    failed = correlate([
        ev("auth", 0, id="a", user_id="U-1", outcome="failure"),
        ev("db_audit", 60, id="d", db_user="U-1", statement_type="SELECT", object="t"),
    ])
    assert failed["groups"] == []


def test_matching_keys_with_different_values_do_not_link():
    result = correlate([
        ev("auth", 0, id="1", user_id="U-1", outcome="failure"),
        ev("auth", 5, id="2", user_id="U-2", outcome="success"),
        ev("app", 0, id="3", service="claims", level="ERROR", status=500, request_id="r1"),
        ev("server", 1, id="4", host="h", process="w", level="ERROR", message="m", request_id="r2"),
    ])
    assert result["groups"] == []


# -- window boundaries ----------------------------------------------------------------------


@pytest.mark.parametrize("gap,linked", [(0, True), (899, True), (900, True), (900.001, False), (-1, False)])
def test_ordered_window_boundary_login_then_access(gap, linked):
    result = correlate([
        ev("auth", 0, id="a", user_id="U-1", outcome="success"),
        ev("db_audit", gap, id="d", db_user="U-1", statement_type="SELECT", object="t"),
    ])
    assert bool(result["groups"]) is linked


@pytest.mark.parametrize("gap,linked", [(60, True), (-60, True), (61, False), (-61, False)])
def test_symmetric_window_boundary_app_error_and_server(gap, linked):
    result = correlate([
        ev("app", 100, id="a", service="claims", level="ERROR", status=500, host="h1"),
        ev("server", 100 + gap, id="s", host="h1", process="w", level="ERROR", message="m"),
    ])
    assert bool(result["groups"]) is linked


# -- missing fields --------------------------------------------------------------------------


def test_missing_fields_are_reported_and_never_matched_on_a_guess():
    result = correlate([
        ev("auth", 0, id="a", outcome="success"),                                   # no actor
        ev("db_audit", 5, id="d", statement_type="SELECT"),                         # no actor, no object
        ev("server", 5, id="s", level="ERROR", message="m"),                        # no host
    ])
    assert result["groups"] == []
    skipped = {s["event_id"]: s for s in result["skipped_for_missing_fields"]}
    assert set(skipped) == {"auth:a", "db_audit:d", "server:s"}
    assert "actor" in skipped["auth:a"]["missing_by_rule"]["login_then_record_access"]


def test_an_event_missing_an_optional_key_still_links_by_another():
    result = correlate([
        ev("auth", 0, id="a", user_id="U-1", outcome="success"),                    # no request id
        ev("audit", 30, id="u", user_id="U-1", action="VIEW_RECORD", patient_id="P-1"),
    ])
    assert group_ids(result) == [["audit:u", "auth:a"]]
    assert result["skipped_for_missing_fields"] == []


# -- late arrival and ordering ---------------------------------------------------------------


def test_late_arriving_event_links_retroactively_and_is_flagged():
    engine = CorrelationEngine()
    engine.add(ev("auth", 0, id="a", user_id="U-1", outcome="success"))
    assert engine.groups() == []
    created = engine.add(ev("db_audit", 200, received_at=iso(5000), id="d", db_user="U-1",
                            statement_type="EXPORT", object="t"))
    assert len(created) == 1 and created[0]["involves_late_event"] is True
    group = engine.groups()[0]
    assert group["has_late_events"] and [e["late"] for e in group["events"]] == [False, True]
    assert engine.result()["late_event_ids"] == ["db_audit:d"]


def test_on_time_arrival_is_not_flagged_late():
    engine = CorrelationEngine()
    engine.add(ev("auth", 0, id="a", user_id="U-1", outcome="success", received_at=iso(1)))
    assert engine.result()["late_event_ids"] == []


def test_result_does_not_depend_on_arrival_order():
    events, _ = normalize_all(demo_records())
    baseline = correlate(events)
    for seed in range(5):
        shuffled = events[:]
        random.Random(seed).shuffle(shuffled)
        again = correlate(shuffled)
        assert group_ids(again) == group_ids(baseline)
        assert [g["group_id"] for g in again["groups"]] == [g["group_id"] for g in baseline["groups"]]


def test_adding_an_event_twice_is_a_no_op():
    engine = CorrelationEngine()
    e = ev("auth", 0, id="a", user_id="U-1", outcome="success")
    engine.add(e)
    assert engine.add(e) == [] and len(engine.events) == 1


def test_event_cap_evicts_oldest_with_its_links():
    engine = CorrelationEngine(max_events=2)
    engine.add(ev("auth", 0, id="a", user_id="U-1", outcome="success"))
    engine.add(ev("audit", 10, id="b", user_id="U-1", action="VIEW_RECORD", patient_id="P-1"))
    assert len(engine.groups()) == 1
    engine.add(ev("audit", 20, id="c", user_id="U-9", action="VIEW_RECORD", patient_id="P-2"))
    assert "auth:a" not in engine.events and engine.groups() == []


# -- the demo data set ------------------------------------------------------------------------


def test_demo_dataset_has_the_documented_outcome():
    events, skipped = normalize_all(demo_records())
    result = correlate(events, adapter_skipped=skipped)
    ids = group_ids(result)
    assert ["audit:u1", "auth:a1", "auth:a2", "auth:a3", "db_audit:d1", "db_audit:d3"] in ids
    assert ["app:p1", "db_audit:d2", "server:s1"] in ids
    linked = {i for g in ids for i in g}
    assert not linked & {"auth:a9", "server:s9", "app:p9"}                       # unrelated noise stays apart
    assert [s["event_id"] for s in result["skipped_for_missing_fields"]] == ["auth:a8"]
    assert result["late_event_ids"] == ["db_audit:d3"]
    assert len(RULES) == len(result["rules"])


# -- API ---------------------------------------------------------------------------------------


def test_api_rules_demo_and_analyze(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        rules = c.get("/api/correlation/rules").json()
        assert len(rules["rules"]) == len(RULES) and "synthetic" in rules["adapters"]["server"]
        demo = c.get("/api/correlation/demo").json()
        assert demo["synthetic"] is True and len(demo["groups"]) == 2
        body = {"events": [
            {"source": "auth", "record": {"ts": iso(0), "user_id": "U-1", "outcome": "success"}},
            {"source": "audit", "record": {"ts": iso(30), "user_id": "U-1", "action": "VIEW_RECORD", "patient_id": "P-1"}},
            {"source": "auth", "record": {"user_id": "U-1"}},
        ]}
        out = c.post("/api/correlation/analyze", json=body).json()
        assert len(out["groups"]) == 1 and out["adapter_skipped"][0]["reason"] == "missing_timestamp"
        assert c.post("/api/correlation/analyze", json={"events": [{"source": "x", "record": {}}]}).status_code == 422
        assert c.post("/api/correlation/analyze", json={"events": [{"source": "auth", "record": {}}] * 501}).status_code == 422


def test_api_output_is_redacted(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        body = {"events": [{"source": "server", "record": {
            "ts": iso(0), "host": "h", "process": "w", "level": "ERROR",
            "message": "failed for jane.doe@example.com ssn 123-45-6789"}}]}
        text = c.post("/api/correlation/analyze", json=body).text
        assert "jane.doe@example.com" not in text and "123-45-6789" not in text


def test_incident_correlation_links_the_actors_other_activity(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline, kind="auth_suspicious_login", user_id="U-064", severity="HIGH", score=0.0)
    now = datetime.now(timezone.utc)

    def stamp(offset):
        return (now - timedelta(seconds=offset)).isoformat()

    pipeline.recent_logs.extend([
        {"seq": 1, "ts": stamp(100), "type": "auth", "user_id": "U-064", "outcome": "success", "msg": "login success"},
        {"seq": 2, "ts": stamp(60), "type": "audit", "user_id": "U-064", "action": "EXPORT_RECORDS",
         "patient_id": "P-****11", "msg": "export"},
        {"seq": 3, "ts": stamp(60), "type": "audit", "user_id": "U-777", "action": "VIEW_RECORD",
         "patient_id": "P-****11", "msg": "unrelated"},
    ])
    inc.opened_at = now - timedelta(minutes=3)
    pipeline.incidents.get(inc.id).opened_at = inc.opened_at
    with TestClient(app) as c:
        c.portal.call(pipeline.store.upsert_incident, inc)
        out = c.get(f"/api/incidents/{inc.id}/correlation").json()
        assert out["incident_id"] == inc.id
        assert len(out["groups"]) == 1
        actors = {e["actor"] for e in out["groups"][0]["events"]}
        assert actors == {"U-064"}
        assert any("same actor (U-064)" in w for w in out["groups"][0]["why"])
        assert c.get("/api/incidents/9999/correlation").status_code == 404
        assert c.get(f"/api/incidents/{inc.id}/correlation?window_minutes=0").status_code == 422
