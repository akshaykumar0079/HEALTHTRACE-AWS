"""Failed logins followed by an unusual successful login: detector rules,
synthetic auth traffic, parser, and end-to-end incident creation."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import AuthConfig
from app.detect.auth import AuthDetector, score_auth_anomaly
from app.models import AuthEvent
from app.parse.parser import Parser
from generator.generate import generate_batch, generate_events
from tests.test_workflow import _build

T0 = datetime(2026, 3, 10, 16, 0, 0, tzinfo=timezone.utc)
CFG = AuthConfig()


def ev(offset_s: float, outcome: str, user="U-1", src="TN-North", home="TN-North") -> AuthEvent:
    return AuthEvent(ts=T0 + timedelta(seconds=offset_s), user_id=user, outcome=outcome, source_region=src,
                     user_region=home, source_ip="192.0.2.7")


def run(events):
    det = AuthDetector(CFG)
    out = []
    for e in events:
        out += det.evaluate(e)
    return out


# -- detector rules --------------------------------------------------------------------------------


def test_below_threshold_is_not_suspicious():
    assert run([ev(i, "failure") for i in range(4)] + [ev(10, "success")]) == []


def test_threshold_failures_then_success_alerts_medium_for_a_familiar_region():
    found = run([ev(i, "failure") for i in range(5)] + [ev(10, "success")])
    assert len(found) == 1 and found[0].kind == "auth_suspicious_login"
    assert score_auth_anomaly(found[0], CFG).severity == "MEDIUM"


def test_unfamiliar_region_raises_to_high_and_many_failures_too():
    unfamiliar = run([ev(i, "failure", src="EXT-VPN") for i in range(5)] + [ev(10, "success", src="EXT-VPN")])
    assert score_auth_anomaly(unfamiliar[0], CFG).severity == "HIGH"
    many = run([ev(i, "failure") for i in range(10)] + [ev(20, "success")])
    assert score_auth_anomaly(many[0], CFG).severity == "HIGH"


def test_both_conditions_make_it_critical():
    found = run([ev(i, "failure", src="EXT-VPN") for i in range(10)] + [ev(20, "success", src="EXT-VPN")])
    assert score_auth_anomaly(found[0], CFG).severity == "CRITICAL"


def test_failures_expire_outside_the_window():
    assert run([ev(i, "failure") for i in range(5)] + [ev(11 * 60, "success")]) == []


def test_burst_cannot_alert_twice_and_a_new_burst_can():
    events = [ev(i, "failure") for i in range(6)] + [ev(10, "success"), ev(11, "success")]
    assert len(run(events)) == 1
    again = events + [ev(100 + i, "failure") for i in range(5)] + [ev(120, "success")]
    assert len(run(again)) == 2


def test_users_are_independent():
    events = [ev(i, "failure", user="U-1") for i in range(3)] + [ev(i + 3, "failure", user="U-2") for i in range(3)]
    assert run(events + [ev(20, "success", user="U-1")]) == []


def test_alert_has_no_invented_score_and_explains_itself():
    found = run([ev(i, "failure") for i in range(5)] + [ev(10, "success")])
    alert = score_auth_anomaly(found[0], CFG)
    assert alert.score == 0.0 and "5 failed logins" in alert.explanation
    assert alert.metrics["failures"] == 5 and alert.metrics["first_failure_ts"] < alert.metrics["last_failure_ts"]


def test_late_arriving_event_does_not_crash_or_wipe_history():
    det = AuthDetector(CFG)
    for i in range(5):
        det.evaluate(ev(100 + i, "failure"))
    assert det.evaluate(ev(50, "failure")) == []              # older than what we hold: ignored, no error
    assert len(det.evaluate(ev(200, "success"))) == 1


# -- parser ----------------------------------------------------------------------------------------------


def test_parser_reads_auth_lines_and_counts_bad_ones():
    p = Parser()
    good = json.dumps({"ts": "2026-03-10T16:00:00Z", "type": "auth", "user_id": "U-1", "outcome": "failure",
                       "source_region": "EXT", "user_region": "TN-North"})
    assert isinstance(p.parse_line(good), AuthEvent)
    assert p.parse_line(good.replace("failure", "maybe")) is None
    assert p.malformed_lines == 1


# -- synthetic traffic ---------------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(8))
def test_normal_traffic_never_triggers_the_login_rule(seed):
    _, _, auth = generate_events(None, 3600, 30, T0, random.Random(seed))
    assert auth, "normal traffic includes logins"
    det = AuthDetector(CFG)
    hits = [a for e in auth for a in det.evaluate(AuthEvent.model_validate(e))]
    assert hits == []


def test_scenario_produces_exactly_one_alert_for_its_user():
    _, _, auth = generate_events("suspicious_login", 60, 10, T0, random.Random(3))
    det = AuthDetector(CFG)
    hits = [a for e in auth for a in det.evaluate(AuthEvent.model_validate(e))]
    assert [h.user_id for h in hits] == ["U-064"]
    assert score_auth_anomaly(hits[0], CFG).severity == "HIGH"


def test_auth_generation_does_not_change_app_or_audit_output():
    a1, b1 = generate_batch("eligibility_outage", 90, 20, T0, random.Random(11))
    a2, b2, _ = generate_events("eligibility_outage", 90, 20, T0, random.Random(11))
    assert a1 == a2 and b1 == b2


def test_synthetic_source_ips_are_in_the_documentation_range():
    _, _, auth = generate_events("suspicious_login", 60, 10, T0, random.Random(1))
    assert all(e["source_ip"].startswith("192.0.2.") for e in auth)


def test_same_seed_is_repeatable():
    one = generate_events("suspicious_login", 60, 10, T0, random.Random(5))
    two = generate_events("suspicious_login", 60, 10, T0, random.Random(5))
    assert one == two


# -- end to end ---------------------------------------------------------------------------------------------


def test_pipeline_turns_a_login_burst_into_an_incident_with_auth_evidence(tmp_path: Path):
    app, pipeline = _build(tmp_path)
    with TestClient(app) as c:
        now = datetime.now(timezone.utc)
        lines = []
        for i in range(8):
            lines.append(json.dumps({"ts": (now + timedelta(seconds=i)).isoformat(), "type": "auth", "user_id": "U-064",
                                     "outcome": "failure", "source_region": "EXT-VPN", "user_region": "TN-North",
                                     "source_ip": "192.0.2.9"}))
        lines.append(json.dumps({"ts": (now + timedelta(seconds=9)).isoformat(), "type": "auth", "user_id": "U-064",
                                 "outcome": "success", "source_region": "EXT-VPN", "user_region": "TN-North",
                                 "source_ip": "192.0.2.9"}))

        async def go():
            for line in lines:
                await pipeline._process_line(line)

        c.portal.call(go)
        items = c.get("/api/incidents/search").json()["items"]
        assert len(items) == 1
        inc = items[0]
        assert inc["kind"] == "auth_suspicious_login" and inc["severity"] == "HIGH" and inc["risk_score"] is None
        assert inc["title"].startswith("Suspicious login")
        detail = c.get(f"/api/incidents/{inc['id']}").json()
        assert detail["evidence"] and all(e["record"]["type"] == "auth" for e in detail["evidence"])
        assert c.get("/api/health").json()["events_processed"]["auth"] == 9
