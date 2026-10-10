"""Redaction (storage / display / outbound), retention, roles, audit trail,
security warnings, and "secrets never leak" checks."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.models import Alert, Incident
from app.privacy.redaction import REDACTED, Redactor
from app.privacy.retention import RetentionPolicy, apply_retention
from tests.test_workflow import _build, _seed

REPO = Path(__file__).resolve().parents[2]
NOW = datetime.now(timezone.utc)


# -- redaction: unit -------------------------------------------------------------------------


def test_default_patterns_mask_common_identifiers():
    r = Redactor.build()
    text = ("jane.doe@example.com called (615) 555-0142, SSN 123-45-6789, card 4111 1111 1111 1111, MRN: 00481516, "
            "Authorization: Bearer abcdef1234567890, key xkeysib-" + "a" * 20)
    out = r.redact_text(text)
    for leaked in ("jane.doe@example.com", "555-0142", "123-45-6789", "4111 1111 1111 1111", "00481516",
                   "abcdef1234567890", "xkeysib-" + "a" * 20):
        assert leaked not in out
    for marker in ("[EMAIL]", "[PHONE]", "[SSN]", "[CARD]", "[MRN]", "[KEY]"):
        assert marker in out


def test_card_pattern_requires_a_valid_card_number():
    r = Redactor.build()
    assert r.redact_text("order 1234 5678 9012 3456 shipped") == "order 1234 5678 9012 3456 shipped"   # fails Luhn
    assert r.redact_text("ts 20260310160000 ok") == "ts 20260310160000 ok"
    assert "[CARD]" in r.redact_text("4111-1111-1111-1111")


def test_patient_ids_are_masked_wherever_they_appear():
    assert Redactor.build().redact_text("viewed P-123456 and P-000042") == "viewed P-****56 and P-****42"


def test_sensitive_keys_are_replaced_whatever_the_value():
    r = Redactor.build()
    out = r.redact_value({"name": "Jane", "SSN": "x", "nested": {"password": "hunter2", "ok": "fine"},
                          "list": [{"email": "a@b.co"}], "count": 3, "dob": ""})
    assert out["name"] == out["SSN"] == out["nested"]["password"] == out["list"][0]["email"] == REDACTED
    assert out["nested"]["ok"] == "fine" and out["count"] == 3 and out["dob"] == ""


def test_redaction_does_not_mutate_its_input():
    original = {"name": "Jane", "msg": "a@b.co"}
    Redactor.build().redact_value(original)
    assert original == {"name": "Jane", "msg": "a@b.co"}


def test_extra_fields_and_patterns_are_configurable_and_validated():
    r = Redactor.build(extra_fields=["Badge"], extra_patterns=[r"TICKET-\d+"])
    assert r.redact_value({"badge": "B-1"})["badge"] == REDACTED
    assert "TICKET-" not in r.redact_text("see TICKET-991")
    with pytest.raises(ValueError):
        Redactor.build(extra_patterns=["(unclosed"])


def test_disabled_redactor_passes_everything_through():
    r = Redactor.build(enabled=False)
    sample = {"name": "Jane", "msg": "a@b.co P-123456"}
    assert r.redact_value(sample) == sample and r.redact_text("a@b.co") == "a@b.co"


# -- redaction: storage, display, outbound ------------------------------------------------------


def _insert_raw_evidence(pipeline, incident_id, record):
    async def go():
        await pipeline.store.save_evidence(incident_id, None, [record])
    return go


def test_evidence_is_redacted_before_storage(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline)
    record = {"seq": 1, "ts": NOW.isoformat(), "type": "app", "service": "claims", "is_error": True,
              "msg": "failed for jane.doe@example.com", "level": "ERROR", "request_id": "r1"}
    pipeline.recent_logs.append(record)
    alert = Alert(ts=NOW, kind="error_rate", service="claims", severity="HIGH", score=0.6, explanation="x")
    with TestClient(app) as c:
        c.portal.call(pipeline._capture_evidence, inc, alert)
        rows = c.portal.call(pipeline.store.list_evidence, inc.id)
        assert rows and "jane.doe@example.com" not in json.dumps(rows) and "[EMAIL]" in json.dumps(rows)


def test_rows_stored_unredacted_are_masked_on_display(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline)
    legacy = {"seq": 2, "ts": NOW.isoformat(), "type": "app", "service": "claims", "msg": "ssn 123-45-6789"}
    with TestClient(app) as c:
        c.portal.call(_insert_raw_evidence(pipeline, inc.id, legacy))
        body = c.get(f"/api/incidents/{inc.id}").text
        assert "123-45-6789" not in body and "[SSN]" in body


def test_redaction_can_be_disabled_and_the_status_says_so(tmp_path):
    app, pipeline = _build(tmp_path, redaction_enabled=False)
    inc = _seed(pipeline)
    with TestClient(app) as c:
        c.portal.call(_insert_raw_evidence(pipeline, inc.id, {"seq": 3, "ts": NOW.isoformat(), "type": "app",
                                                              "service": "claims", "msg": "mail a@b.co"}))
        assert "a@b.co" in c.get(f"/api/incidents/{inc.id}").text
        status = c.get("/api/security/status").json()
        assert status["redaction"]["enabled"] is False
        assert "redaction_disabled" in {w["code"] for w in status["warnings"]}


def test_outbound_email_and_cloud_text_are_redacted(tmp_path):
    app, pipeline = _build(tmp_path, email_enabled=True, email_provider="brevo", brevo_api_key="k",
                           alert_email_from="a@example.org", alert_email_to="b@example.org")
    inc = _seed(pipeline)
    alert = Alert(ts=NOW, kind="error_rate", service="claims", severity="HIGH", score=0.6,
                  explanation="contact jane.doe@example.com about P-123456 ssn 123-45-6789")
    msg = pipeline.email.build_message(inc, alert)
    body = msg.get_body(("plain",)).get_content() + msg.get_body(("html",)).get_content()
    assert "jane.doe@example.com" not in body and "123-45-6789" not in body and "P-123456" not in body
    assert pipeline.notifier.redact("a@b.co P-123456") == "[EMAIL] P-****56"
    mock_payload = pipeline.notifier.redact(alert.model_dump(mode="json"))
    assert "jane.doe@example.com" not in json.dumps(mock_payload)


def test_bad_redaction_pattern_fails_at_startup(tmp_path):
    with pytest.raises(ValueError):
        _build(tmp_path, redact_extra_patterns="(unclosed")


# -- retention -----------------------------------------------------------------------------------


def _incident(state="RESOLVED", resolved_days_ago=120, pinned=False, fp="e:claims") -> Incident:
    opened = NOW - timedelta(days=resolved_days_ago + 1)
    return Incident(fingerprint=fp, kind="error_rate", service="claims", state=state, peak_severity="HIGH",
                    opened_at=opened, resolved_at=(NOW - timedelta(days=resolved_days_ago)) if state == "RESOLVED" else None,
                    pinned=pinned, last_seen_at=opened)


async def _count(store, table):
    return (await (await store.conn.execute(f"SELECT COUNT(*) FROM {table}")).fetchone())[0]


def test_policy_reads_settings_and_describes_itself(tmp_path):
    _, pipeline = _build(tmp_path, retention_alerts_days=7, retention_audit_days=0)
    p = pipeline.retention
    assert p.alerts_days == 7 and p.audit_days == 0
    rows = {r["data"]: r for r in p.describe()}
    assert rows["Alerts"]["keep"] == "7 days" and rows["Audit log"]["keep"] == "forever"
    assert not p.all_disabled and RetentionPolicy(0, 0, 0, 0, 0, 0, 0).all_disabled


def test_retention_deletes_old_resolved_incidents_only(tmp_path):
    app, pipeline = _build(tmp_path)
    store = pipeline.store

    async def seed():
        ids = {}
        for name, inc in {
            "old_resolved": _incident(fp="a:1"),
            "recent_resolved": _incident(resolved_days_ago=5, fp="a:2"),
            "old_pinned": _incident(pinned=True, fp="a:3"),
            "open": _incident(state="OPEN", fp="a:4"),
        }.items():
            await store.upsert_incident(inc)
            row = await (await store.conn.execute("SELECT id FROM incidents WHERE fingerprint = ?", (inc.fingerprint,))).fetchone()
            ids[name] = row[0]
            await store.save_alert(Alert(ts=NOW - timedelta(days=200), kind="error_rate", service="claims", severity="HIGH",
                                         score=0.5, explanation="x", incident_id=ids[name]))
            await store.save_evidence(ids[name], None, [{"ts": (NOW - timedelta(days=200)).isoformat(), "type": "app"}])
        return ids

    with TestClient(app) as c:
        ids = c.portal.call(seed)
        policy = RetentionPolicy(metrics_hours=0, evidence_days=0, alerts_days=0, resolved_incidents_days=90,
                                 notification_attempts_days=0, simulation_runs_days=0, audit_days=0)

        dry = c.portal.call(lambda: apply_retention(store, policy, now=NOW, dry_run=True))
        assert dry == {"resolved_incidents": 1} and c.portal.call(_count, store, "incidents") == 4

        done = c.portal.call(lambda: apply_retention(store, policy, now=NOW))
        assert done == {"resolved_incidents": 1}
        left = {r[0] for r in c.portal.call(lambda: _fetch(store, "SELECT id FROM incidents"))}
        assert left == {ids["recent_resolved"], ids["old_pinned"], ids["open"]}
        # the purged incident's alerts and evidence went with it; the others are untouched
        assert c.portal.call(_count, store, "alerts") == 3 and c.portal.call(_count, store, "evidence_events") == 3


async def _fetch(store, sql):
    return await (await store.conn.execute(sql)).fetchall()


def test_age_rules_spare_unresolved_incidents_and_zero_disables(tmp_path):
    app, pipeline = _build(tmp_path)
    store = pipeline.store

    async def seed():
        await store.upsert_incident(_incident(state="OPEN", fp="b:1"))
        open_id = (await _fetch(store, "SELECT id FROM incidents"))[0][0]
        old = (NOW - timedelta(days=400)).isoformat()
        await store.save_evidence(open_id, None, [{"ts": old, "type": "app"}])
        await store.save_alert(Alert(ts=NOW - timedelta(days=400), kind="error_rate", service="claims",
                                     severity="HIGH", score=0.5, explanation="x", incident_id=open_id))
        await store.save_alert(Alert(ts=NOW - timedelta(days=400), kind="error_rate", service="claims",
                                     severity="HIGH", score=0.5, explanation="orphan", incident_id=None))
        await store.add_audit(actor="x", action="old", target_type="t", ts=NOW - timedelta(days=500))
        await store.add_audit(actor="x", action="new", target_type="t")
        await store.save_simulation_run(created_at=NOW - timedelta(days=40), scenario_id="s", seed=1, passed=True,
                                        summary="s", result={})

    with TestClient(app) as c:
        c.portal.call(seed)
        everything = RetentionPolicy(24, 30, 90, 90, 30, 30, 365)
        out = c.portal.call(lambda: apply_retention(store, everything, now=NOW))
        assert out["evidence"] == 0                       # open incident keeps its evidence
        assert out["alerts"] == 1                         # only the orphan alert goes
        assert out["audit"] == 1 and out["simulation_runs"] == 1
        remaining = [r[0] for r in c.portal.call(lambda: _fetch(store, "SELECT action FROM audit_log"))]
        assert "old" not in remaining and "new" in remaining
        off = RetentionPolicy(0, 0, 0, 0, 0, 0, 0)
        assert c.portal.call(lambda: apply_retention(store, off, now=NOW)) == {}


def test_retention_api_preview_run_and_audit(tmp_path):
    app, pipeline = _build(tmp_path, operator_token="op", admin_token="adm")
    with TestClient(app) as c:
        h_op, h_adm = {"X-Operator-Token": "op"}, {"X-Operator-Token": "adm"}
        assert c.post("/api/admin/retention/run").status_code == 401
        assert c.post("/api/admin/retention/run", headers=h_op).status_code == 403
        out = c.post("/api/admin/retention/run", headers=h_adm).json()
        assert out["error"] is None and out["dry_run"] is False
        preview = c.get("/api/admin/retention", headers=h_adm).json()
        assert preview["last_run"]["ran_at"] == out["ran_at"] and preview["policy"]
        actions = [a["action"] for a in c.get("/api/audit", headers=h_adm).json()]
        assert "retention.run" in actions


# -- roles ---------------------------------------------------------------------------------------


def test_local_development_is_open_but_loudly_warned(tmp_path):
    app, pipeline = _build(tmp_path)
    inc = _seed(pipeline)
    with TestClient(app) as c:
        assert c.post(f"/api/incidents/{inc.id}/ack").status_code == 200
        me = c.get("/api/me").json()
        assert me["open_access"] is True and me["can"] == {"operate": True, "admin": True}
        warnings = {w["code"]: w for w in c.get("/api/security/status").json()["warnings"]}
        assert warnings["auth_disabled"]["level"] == "critical" and "DISABLED" in warnings["auth_disabled"]["message"]


def test_production_without_tokens_refuses_state_changes(tmp_path):
    app, pipeline = _build(tmp_path, environment="production")
    inc = _seed(pipeline)
    with TestClient(app) as c:
        assert c.post(f"/api/incidents/{inc.id}/ack").status_code == 403
        assert c.put("/api/settings/notifications", json={"enabled": False, "recipients": ["a@b.co"],
                                                          "min_severity": "HIGH", "cooldown_seconds": 300}).status_code == 403
        codes = {w["code"] for w in c.get("/api/security/status").json()["warnings"]}
        assert "controls_locked" in codes and "auth_disabled" not in codes


def test_role_matrix(tmp_path):
    app, pipeline = _build(tmp_path, viewer_token="v-tok", operator_token="o-tok", admin_token="a-tok")
    inc = _seed(pipeline)
    settings_body = {"enabled": False, "recipients": ["a@b.co"], "min_severity": "HIGH", "cooldown_seconds": 300}
    H = lambda t: {"X-Operator-Token": t} if t else {}
    with TestClient(app) as c:
        # reads: a viewer token is required once one is configured
        assert c.get("/api/incidents/search").status_code == 401
        assert c.get("/api/incidents/search", headers=H("wrong")).status_code == 401
        for tok in ("v-tok", "o-tok", "a-tok"):
            assert c.get("/api/incidents/search", headers=H(tok)).status_code == 200
        assert c.get("/api/health").status_code == 200                                    # liveness stays open
        # acknowledge / resolve: operator and above
        assert c.post(f"/api/incidents/{inc.id}/ack").status_code == 401
        assert c.post(f"/api/incidents/{inc.id}/ack", headers=H("v-tok")).status_code == 403
        assert c.post(f"/api/incidents/{inc.id}/ack", headers=H("o-tok")).status_code == 200
        assert c.post(f"/api/incidents/{inc.id}/resolve", headers=H("v-tok")).status_code == 403
        assert c.post(f"/api/incidents/{inc.id}/resolve", headers=H("a-tok")).status_code == 200
        # settings: admin only
        assert c.put("/api/settings/notifications", json=settings_body, headers=H("v-tok")).status_code == 403
        assert c.put("/api/settings/notifications", json=settings_body, headers=H("o-tok")).status_code == 403
        assert c.put("/api/settings/notifications", json=settings_body, headers=H("a-tok")).status_code == 200
        # /me reflects the role
        assert c.get("/api/me", headers=H("v-tok")).json()["can"] == {"operate": False, "admin": False}
        assert c.get("/api/me", headers=H("o-tok")).json()["can"] == {"operate": True, "admin": False}
        assert c.get("/api/me", headers=H("a-tok")).json()["can"] == {"operate": True, "admin": True}


def test_operator_token_alone_holds_admin_rights_and_warns(tmp_path):
    app, pipeline = _build(tmp_path, operator_token="o-tok")
    with TestClient(app) as c:
        assert c.get("/api/me", headers={"X-Operator-Token": "o-tok"}).json()["can"]["admin"] is True
        codes = {w["code"] for w in c.get("/api/security/status").json()["warnings"]}
        assert "roles_collapsed" in codes and "view_open" in codes


def test_require_view_auth_closes_reads_for_everyone_without_a_token(tmp_path):
    app, _ = _build(tmp_path, operator_token="o-tok", require_view_auth=True)
    with TestClient(app) as c:
        assert c.get("/api/incidents/search").status_code == 401
        assert c.get("/api/incidents/search", headers={"X-Operator-Token": "o-tok"}).status_code == 200


def test_websocket_requires_a_token_when_reads_are_restricted(tmp_path):
    app, _ = _build(tmp_path, viewer_token="v-tok")
    with TestClient(app) as c:
        with pytest.raises(Exception):
            with c.websocket_connect("/ws") as ws:
                ws.receive_json()
        with pytest.raises(Exception):
            with c.websocket_connect("/ws?token=wrong") as ws:
                ws.receive_json()
        with c.websocket_connect("/ws?token=v-tok") as ws:
            assert ws.receive_json()["type"] == "snapshot"


def test_audit_trail_names_the_acting_role_and_never_contains_tokens(tmp_path):
    app, pipeline = _build(tmp_path, operator_token="o-secret-123", admin_token="a-secret-456")
    inc = _seed(pipeline)
    with TestClient(app) as c:
        H = {"X-Operator-Token": "o-secret-123"}
        c.post(f"/api/incidents/{inc.id}/ack", headers=H)
        c.put("/api/settings/notifications", headers={"X-Operator-Token": "a-secret-456"},
              json={"enabled": False, "recipients": ["a@b.co"], "min_severity": "HIGH", "cooldown_seconds": 300})
        log = c.get("/api/audit", headers=H).json()
        by_action = {a["action"]: a for a in log}
        assert by_action["acknowledge"]["actor"] == "operator"
        assert by_action["update_notification_settings"]["actor"] == "admin"
        assert "secret" not in json.dumps(log)


# -- secrets -------------------------------------------------------------------------------------


def test_status_endpoint_and_logs_never_contain_secret_values(tmp_path, caplog):
    secrets = ["op-SECRET-aaaa1111", "adm-SECRET-bbbb2222", "view-SECRET-cccc3333", "pg-SECRET-pass-dddd4444",
               "brevo-SECRET-key-eeee5555"]
    app, pipeline = _build(tmp_path, operator_token=secrets[0], admin_token=secrets[1], viewer_token=secrets[2],
                           brevo_api_key=secrets[4])
    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as c:
            c.get("/api/incidents/search", headers={"X-Operator-Token": "wrong-" + secrets[0]})
            c.post("/api/incidents/1/ack", headers={"X-Operator-Token": secrets[2]})
            texts = [c.get("/api/security/status", headers={"X-Operator-Token": secrets[2]}).text,
                     c.get("/api/settings/notifications", headers={"X-Operator-Token": secrets[2]}).text,
                     c.get("/api/health", headers={"X-Operator-Token": secrets[2]}).text]
    blob = "\n".join(texts) + "\n" + caplog.text
    for secret in secrets:
        assert secret not in blob, f"{secret[:6]}… leaked"


def test_comparison_of_tokens_is_constant_time():
    import inspect
    from app.api import auth

    assert "compare_digest" in inspect.getsource(auth._match)


_SECRET_SHAPES = {
    "brevo key": re.compile(r"xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}"),
    "aws access key": re.compile(r"\bAKIA(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "google app password": re.compile(r"(?i)(?:SMTP_PASSWORD|APP_PASSWORD)\s*[:=]\s*[\"']?(?!abcd efgh ijkl mnop)[a-z]{4}(?: ?[a-z]{4}){3}\b"),
}


def _git(*args):
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)


@pytest.mark.skipif(not (REPO / ".git").exists(), reason="not a git checkout")
def test_no_secrets_in_tracked_or_untracked_files_and_env_is_ignored():
    files = _git("ls-files", "-co", "--exclude-standard").stdout.split("\n")
    files = [f for f in files if f]
    assert files, "git returned no files"
    assert ".env" not in files and not [f for f in files if re.search(r"(^|/)\.env\.(?!example$)", f)]
    assert not [f for f in files if f.endswith((".db", ".sqlite", ".pem", ".key")) or f.startswith("data/")]
    hits = []
    for rel in files:
        path = REPO / rel
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name, rx in _SECRET_SHAPES.items():
            if rx.search(text):
                hits.append((rel, name))
    assert not hits, hits
    # the template must carry no values for secret settings
    template = (REPO / ".env.example").read_text(encoding="utf-8")
    for key in ("BREVO_API_KEY", "SMTP_PASSWORD", "OPERATOR_TOKEN", "ADMIN_TOKEN", "VIEWER_TOKEN", "DATABASE_URL"):
        for line in template.splitlines():
            if line.startswith(f"{key}="):
                assert line.strip() == f"{key}=", f"{key} has a value in .env.example"
