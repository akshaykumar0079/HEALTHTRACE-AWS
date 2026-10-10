"""Safe synthetic incident simulator: repeatability, expectations, labelled
metrics, isolation from real systems, and the API around it."""

from __future__ import annotations

import dataclasses
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import routes
from app.simulation import runner
from app.simulation.runner import _isolated_settings, build_stream, run_benchmark, run_scenario, summarize_benchmark
from app.simulation.scenarios import SCENARIOS, list_scenarios
from generator.scenarios import ALL_SCENARIO_NAMES
from tests.test_workflow import _build

GATED = [sid for sid, s in SCENARIOS.items() if not s.known_limit]


# -- catalogue -------------------------------------------------------------------------------


def test_every_scenario_maps_to_a_real_generator_scenario():
    for scn in SCENARIOS.values():
        if scn.generator_scenario is not None:
            assert scn.generator_scenario in ALL_SCENARIO_NAMES, scn.id


def test_catalogue_covers_the_required_scenarios():
    kinds = {s.expectation.kind for s in SCENARIOS.values() if s.expectation}
    assert {"error_rate", "auth_suspicious_login", "hipaa_bulk_access"} <= kinds
    assert any(s.id == "prior_auth_pipeline_failure" for s in SCENARIOS.values())
    assert any(s.must_resolve for s in SCENARIOS.values())            # recovery / resolution
    assert any(s.labelled_normal for s in SCENARIOS.values())         # false-positive control


def test_listing_states_expected_alerts_severity_and_evidence():
    for item in list_scenarios():
        assert item["synthetic"] is True and item["expected_alerts"]
        if item["expected_kind"]:
            assert item["expected_severity"] and item["min_evidence"] > 0 and item["max_detection_delay_s"] > 0


# -- repeatability ---------------------------------------------------------------------------


def test_same_seed_gives_identical_stream_and_different_seed_does_not():
    scn = SCENARIOS["error_spike"]
    a, labels_a = build_stream(scn, 7)
    b, labels_b = build_stream(scn, 7)
    c, _ = build_stream(scn, 8)
    assert a == b and labels_a == labels_b
    assert a != c


def test_same_seed_gives_identical_results():
    r1, r2 = run_scenario("bulk_record_access"), run_scenario("bulk_record_access")
    for r in (r1, r2):
        r.pop("isolation", None)
    assert r1["incidents"] == r2["incidents"]
    assert r1["metrics"] == r2["metrics"]
    assert r1["notification_decisions"] == r2["notification_decisions"]


def test_stream_is_ordered_and_synthetic_only():
    import json

    lines, _ = build_stream(SCENARIOS["failed_logins_then_success"], 1)
    events = [json.loads(line) for line in lines]
    assert [e["ts"] for e in events] == sorted(e["ts"] for e in events)
    for e in events:
        if e["type"] == "auth":
            assert e["source_ip"].startswith("192.0.2.")                 # RFC 5737 documentation range
        if e["type"] == "audit":
            assert e["patient_id"].startswith("P-")


# -- expectations, delay, false positives -------------------------------------------------


@pytest.mark.parametrize("scenario_id", GATED)
def test_gated_scenarios_pass_with_their_default_seed(scenario_id):
    result = run_scenario(scenario_id)
    failed = [c for c in result["checks"] if not c["passed"]]
    assert result["passed"], failed
    assert result["synthetic"] is True
    if SCENARIOS[scenario_id].expectation:
        m = result["metrics"]
        assert m["detection_delay_s"] is not None and m["detection_delay_s"] >= 0
    assert result["metrics"]["false_positive_incidents"] == 0


def test_recovery_scenario_resolves_the_incident_and_reports_time_to_resolve():
    result = run_scenario("recovery_resolution")
    expected = [i for i in result["incidents"] if i["label"] == "expected"]
    assert expected and expected[0]["state"] == "RESOLVED"
    assert result["metrics"]["time_to_resolve_s"] is not None and result["metrics"]["time_to_resolve_s"] >= 0


def test_control_run_has_no_incidents():
    result = run_scenario("normal_control")
    assert result["incidents"] == [] and result["metrics"]["false_positives_per_hour"] == 0


def test_a_wrong_expectation_fails_the_run_instead_of_passing_silently(monkeypatch):
    scn = SCENARIOS["error_spike"]
    wrong = dataclasses.replace(scn, expectation=dataclasses.replace(scn.expectation, entity="claims"))
    monkeypatch.setitem(SCENARIOS, "error_spike", wrong)
    result = run_scenario("error_spike")
    assert result["passed"] is False
    assert "detected" in [c["name"] for c in result["checks"] if not c["passed"]]


def test_unexpected_incidents_are_counted_as_false_positives(monkeypatch):
    scn = SCENARIOS["error_spike"]
    monkeypatch.setitem(SCENARIOS, "error_spike", dataclasses.replace(scn, allowed_extra=()))
    result = run_scenario("error_spike")
    assert result["metrics"]["false_positive_incidents"] >= 1
    assert result["passed"] is False
    assert result["metrics"]["false_positives_per_hour"] > 0


def test_severity_and_evidence_expectations_are_enforced(monkeypatch):
    scn = SCENARIOS["error_spike"]
    strict = dataclasses.replace(scn, expectation=dataclasses.replace(
        scn.expectation, severities=("LOW",), min_evidence=10_000, max_delay_s=1))
    monkeypatch.setitem(SCENARIOS, "error_spike", strict)
    failed = {c["name"] for c in run_scenario("error_spike")["checks"] if not c["passed"]}
    assert {"severity", "evidence_count", "detection_delay"} <= failed


def test_notification_flood_check_counts_staff_notifications(monkeypatch):
    scn = SCENARIOS["error_spike"]
    monkeypatch.setitem(SCENARIOS, "error_spike", dataclasses.replace(scn, max_notifications=0))
    result = run_scenario("error_spike")
    assert "notification_flood" in [c["name"] for c in result["checks"] if not c["passed"]]
    assert result["metrics"]["staff_notifications"] > 0


def test_benchmark_summary_math():
    def res(sid, delay, fp, hours=1.0, limit=False):
        return {"scenario_id": sid, "passed": fp == 0, "known_limit": limit,
                "metrics": {"detection_delay_s": delay, "false_positive_incidents": fp, "simulated_hours": hours}}

    summary = summarize_benchmark([
        res("a", 10, 0), res("b", 30, 0), res("c", None, 0),
        res("m", None, 0, limit=True), res("normal_control", None, 1, hours=0.5),
    ])
    assert summary["injected_runs"] == 3 and summary["detected"] == 2
    assert summary["detection_rate"] == pytest.approx(0.667, abs=0.001)
    assert summary["detection_delay_s"] == {"median": 20.0, "max": 30}
    assert summary["known_limit_runs"] == 1 and summary["known_limit_detected"] == 0
    assert summary["control_false_positives"] == 1 and summary["control_false_positives_per_hour"] == 2.0


def test_benchmark_runs_selected_scenarios_across_seeds():
    out = run_benchmark(seeds=(5,), scenario_ids=["normal_control", "bulk_record_access"])
    assert out["seeds"] == [5] and len(out["runs"]) == 2
    assert out["summary"]["runs"] == 2 and out["summary"]["control_runs"] == 1


# -- isolation: it cannot touch real systems ------------------------------------------------


def test_settings_ignore_environment_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("EMAIL_ENABLED", "true")
    monkeypatch.setenv("AWS_MODE", "live")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pw@example.invalid/db")
    monkeypatch.setenv("BREVO_API_KEY", "xkeysib-not-a-real-key")
    s = _isolated_settings(tmp_path)
    assert s.email_enabled is False and s.aws_mode == "off" and s.database_url == ""
    assert Path(s.db_path).parent == tmp_path


def test_run_uses_a_temporary_database_and_cleans_it_up(monkeypatch):
    seen: list[Path] = []
    real = runner._isolated_settings

    def spy(workdir):
        seen.append(workdir)
        return real(workdir)

    monkeypatch.setattr(runner, "_isolated_settings", spy)
    run_scenario("normal_control")
    assert len(seen) == 1
    assert seen[0].name.startswith("healthtrace-sim-") and not seen[0].exists()
    assert Path(tempfile.gettempdir()) in seen[0].parents


def test_simulation_never_touches_the_real_database_or_sends_anything(tmp_path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        before = c.get("/api/incidents/search").json()["total"]
        r = c.post("/api/simulations/run", json={"scenario_id": "error_spike"})
        assert r.status_code == 200 and r.json()["passed"] is True
        assert c.get("/api/incidents/search").json()["total"] == before
        assert pipeline.alerts_emitted == 0
    # the conftest autouse fixture fails the test if SMTP / the mail API was contacted


# -- API ---------------------------------------------------------------------------------------


def test_api_lists_scenarios_and_persists_runs(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        listing = c.get("/api/simulations/scenarios").json()
        assert listing["synthetic_only"] is True and len(listing["scenarios"]) == len(SCENARIOS)
        assert c.get("/api/simulations/runs").json()["items"] == []
        run = c.post("/api/simulations/run", json={"scenario_id": "normal_control"}).json()
        assert run["id"] >= 1 and run["scenario_id"] == "normal_control" and run["seed"] == SCENARIOS["normal_control"].seed
        items = c.get("/api/simulations/runs").json()["items"]
        assert [i["id"] for i in items] == [run["id"]] and items[0]["passed"] is True
        detail = c.get(f"/api/simulations/runs/{run['id']}").json()
        assert detail["result"]["checks"] == run["checks"]
        assert c.get("/api/simulations/runs/9999").status_code == 404
        actions = [a["action"] for a in c.get("/api/audit").json()]
        assert "simulate" in actions


def test_api_validation(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        assert c.post("/api/simulations/run", json={"scenario_id": "nope"}).status_code == 404
        assert c.post("/api/simulations/run", json={"scenario_id": "normal_control", "seed": -1}).status_code == 422
        assert c.post("/api/simulations/benchmark", json={"seeds": [1, 2, 3, 4]}).status_code == 422
        assert c.post("/api/simulations/benchmark", json={"scenario_ids": ["nope"]}).status_code == 404


def test_api_runs_one_simulation_at_a_time(tmp_path):
    app, _ = _build(tmp_path)
    with TestClient(app) as c:
        async def hold():
            await routes._sim_lock.acquire()

        c.portal.call(hold)
        try:
            assert c.post("/api/simulations/run", json={"scenario_id": "normal_control"}).status_code == 409
        finally:
            routes._sim_lock.release()


def test_api_roles(tmp_path):
    app, _ = _build(tmp_path, operator_token="op-token", viewer_token="view-token", admin_token="adm-token")
    body = {"scenario_id": "normal_control"}
    with TestClient(app) as c:
        assert c.post("/api/simulations/run", json=body).status_code == 401
        assert c.post("/api/simulations/run", json=body, headers={"X-Operator-Token": "view-token"}).status_code == 403
        assert c.post("/api/simulations/run", json=body, headers={"X-Operator-Token": "op-token"}).status_code == 200
        bench = {"seeds": [3], "scenario_ids": ["normal_control"]}
        assert c.post("/api/simulations/benchmark", json=bench,
                      headers={"X-Operator-Token": "op-token"}).status_code == 403
        ok = c.post("/api/simulations/benchmark", json=bench, headers={"X-Operator-Token": "adm-token"})
        assert ok.status_code == 200 and ok.json()["summary"]["control_runs"] == 1
