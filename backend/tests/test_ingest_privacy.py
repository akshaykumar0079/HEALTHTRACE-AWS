"""Stage E tests: keyed pseudonymization at the configured boundary and canary
leak checks. Synthetic canary identifiers are planted in every input; none may
appear in the database file, API responses, WebSocket frames, application logs or
notification payloads in configured mode. All fake; no real service is contacted."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings, SourceConfig
from app.ingest import reasons
from app.ingest.pseudonym import IngestConfigError, Pseudonymizer, load_key
from app.main import create_app
from app.notify.mailer import EmailNotifier
from app.pipeline import Pipeline
from tests.ingest_helpers import (
    APP_SRC, APP_SRC_MSG, AUDIT_SRC, AUTH_SRC, KEY, OTHER_KEY, claims, config_for, ehr, failures_then_success, idp, make_pipeline,
    now, settings_for,
)
from tests.test_email import FakeSMTP, email_settings

CANARY_USER = "jane.canary@hospital.test"
CANARY_USER2 = "dr.canary.smith"
CANARY_IP = "198.51.100.231"
CANARY_PATIENT = "MRN-CANARY-"
CANARY_EVENT = "evt-jane.canary@hospital.test-"
RAW_NEEDLES = ["jane.canary", "dr.canary", "hospital.test", CANARY_IP, "198.51.100", "mrn-canary", "evt-jane"]


# -- key handling: externally configured, validated, no fallback --------------------------------------

@pytest.mark.parametrize("bad", [None, "", "   ", "Sh0rtK3y!", "a" * 31, "a" * 40, "ab" * 20, "changeme" + "x1" * 20,
                                 "your-key-" + "Zq3" * 10])
def test_invalid_keys_are_refused(bad):
    with pytest.raises(IngestConfigError) as e:
        load_key(bad)
    assert not (bad and bad.strip()) or bad.strip() not in str(e.value)                       # message never echoes the key


def test_a_generated_key_is_accepted_and_hidden():
    import secrets

    k = secrets.token_hex(32)
    assert load_key(k) == k.encode()
    ps = Pseudonymizer.from_setting(k)
    assert k not in repr(ps) and "hidden" in repr(ps)


def test_pseudonyms_are_stable_keyed_and_domain_separated():
    a, b = Pseudonymizer.from_setting(KEY), Pseudonymizer.from_setting(OTHER_KEY)
    assert a.user(CANARY_USER) == a.user(f"  {CANARY_USER} ")                                 # stable, whitespace-insensitive
    assert a.user(CANARY_USER) != b.user(CANARY_USER)                                         # key changes the mapping
    assert a.user("x") != a.patient("x") != a.ip("x")                                          # domains do not cross-link
    assert a.user("x").startswith("U-") and len(a.user("x")) == 14
    assert a.patient("x").startswith("P-") and a.ip("x").startswith("ip-")
    assert CANARY_USER not in a.user(CANARY_USER)
    with pytest.raises(ValueError):
        a.user("   ")


async def test_configured_mode_without_a_valid_key_refuses_to_start_and_never_falls_back(tmp_path):
    for key in ("", "Sh0rtK3y!"):
        s = settings_for(tmp_path, pseudonym_key=SecretStr(key))
        with pytest.raises(IngestConfigError):
            Pipeline(s, config_for(AUTH_SRC))
        with pytest.raises(IngestConfigError):
            create_app(settings=s, config=config_for(AUTH_SRC))                                # the application does not come up


def test_the_key_is_not_in_settings_repr_or_dump(tmp_path):
    s = settings_for(tmp_path)
    assert KEY not in repr(s) and KEY not in str(s) and KEY not in json.dumps(s.model_dump(mode="json"), default=str)


# -- identifiers never reach event objects -------------------------------------------------------------

async def test_pseudonymization_happens_before_any_event_object_exists():
    p = await make_pipeline()
    base = now() - timedelta(minutes=5)
    for line in failures_then_success(base, user=CANARY_USER, ip=CANARY_IP):
        await p._process_line(line, "idp_fixture")
    await p._process_line(ehr(base, CANARY_USER2, "READ", CANARY_PATIENT + "000001", eid="e1"), "ehr_audit_fixture")
    await p._process_line(claims(base, eid="c1", patient=CANARY_PATIENT + "000002"), "claims_app_fixture")
    ps = Pseudonymizer.from_setting(KEY)
    seen = json.dumps(list(p.recent_logs), default=str).lower()
    for needle in RAW_NEEDLES:
        assert needle not in seen, needle
    assert ps.user(CANARY_USER) in json.dumps(list(p.recent_logs)) and ps.ip(CANARY_IP) in json.dumps(list(p.recent_logs))
    inc = p.incidents.list_incidents()[0]
    assert inc.user_id == ps.user(CANARY_USER) and inc.fingerprint == f"auth_suspicious_login:{ps.user(CANARY_USER)}"
    await p.store.close()


async def test_free_text_is_omitted_by_default_in_configured_mode():
    p = await make_pipeline()          # APP_SRC does not opt in
    t = now() - timedelta(minutes=1)
    await p._process_line(claims(t, eid="c1", message=f"{CANARY_USER} ssn 123-45-6789 SECRET free text"), "claims_app_fixture")
    msg = [r for r in p.recent_logs if r["type"] == "app"][0]["msg"]
    assert msg == "[free text omitted]"
    assert "SECRET" not in json.dumps(list(p.recent_logs)) and CANARY_USER not in json.dumps(list(p.recent_logs))
    await p.store.close()


async def test_operator_constant_may_replace_omitted_text_but_source_text_never_wins():
    const = dict(APP_SRC, defaults={"priority": "routine", "msg": "claims event"})
    p = await make_pipeline(srcs=[const])
    await p._process_line(claims(now() - timedelta(minutes=1), eid="c2", message="SECRET free text"), "claims_app_fixture")
    assert [r for r in p.recent_logs if r["type"] == "app"][0]["msg"] == "claims event"
    await p.store.close()


def test_mapping_msg_without_opt_in_is_a_startup_error_and_opt_in_needs_a_mapping():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="include_msg"):
        SourceConfig(**dict(APP_SRC, fields={**APP_SRC["fields"], "msg": "message"}))
    with pytest.raises(ValidationError, match="include_msg"):
        SourceConfig(**dict(APP_SRC, include_msg=True))


async def test_opt_in_free_text_is_redacted_and_scrubs_the_events_own_identifiers():
    p = await make_pipeline(srcs=[APP_SRC_MSG])
    t = now() - timedelta(minutes=1)
    await p._process_line(
        claims(t, eid="c1", patient=CANARY_PATIENT + "000001",
               message=f"call jane.canary@hospital.test re {CANARY_PATIENT}000001 and 123-45-6789 req r-c1"),
        "claims_app_fixture")
    msg = [r for r in p.recent_logs if r["type"] == "app"][0]["msg"]
    for needle in ("jane.canary", CANARY_PATIENT, "123-45-6789", "r-c1"):
        assert needle.lower() not in msg.lower(), needle
    # Documented limit: an identifier of another person that matches no pattern passes through.
    await p._process_line(claims(t, eid="c2", message="see zed.unlisted.person"), "claims_app_fixture")
    assert "zed.unlisted.person" in [r for r in p.recent_logs if r["type"] == "app"][-1]["msg"]
    await p.store.close()


async def test_event_ids_are_stored_as_keyed_digests_not_raw():
    p = await make_pipeline()
    for line in failures_then_success(now() - timedelta(minutes=5), user="u", ip="203.0.113.9"):
        await p._process_line(line, "idp_fixture")
    await p._save_state()
    cur = await p.store.conn.execute("SELECT event_id FROM ingest_seen")
    stored = [r[0] for r in await cur.fetchall()]
    assert stored and all(s.startswith("i:") and len(s) == 66 for s in stored)            # i: + 64 hex (HMAC-SHA256)
    assert not any(raw in s for s in stored for raw in ("f0", "s1"))
    await p.store.close()


# -- the canary run: database, API, WebSocket, logs, notifications ------------------------------------------

def _all_text_in_db(db_path: Path) -> str:
    con = sqlite3.connect(db_path)
    parts: list[str] = []
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        for row in con.execute(f'SELECT * FROM "{name}"').fetchall():
            parts.append(json.dumps(row, default=str))
    con.close()
    return "\n".join(parts).lower()


def test_canary_identifiers_do_not_leak_anywhere_in_configured_mode(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    s = settings_for(tmp_path, aws_mode="mock", demo_mode=False)
    cfg = config_for(AUTH_SRC, AUDIT_SRC, APP_SRC_MSG)  # strictest: free text opted in
    for name in ("idp.jsonl", "ehr.jsonl", "claims.jsonl"):
        (s.log_dir / name).write_text("")
    app = create_app(settings=s, config=cfg)
    pipeline = app.state.pipeline
    mailer = EmailNotifier(email_settings(), app_config=cfg, smtp_factory=FakeSMTP, base_backoff=0.01)
    mailer.redact = pipeline.redactor.redact_value
    pipeline.email = mailer

    base = now() - timedelta(minutes=8)
    ps = Pseudonymizer.from_setting(KEY)
    frames: list[dict] = []

    def append(path: str, lines: list[str]) -> None:
        with (s.log_dir / path).open("a") as f:
            f.write("\n".join(lines) + "\n")

    def wait(cond, seconds=20.0):
        end = time.time() + seconds
        while time.time() < end:
            if cond():
                return
            time.sleep(0.05)
        raise AssertionError("condition not reached")

    with TestClient(app) as client:
        # Phase 1: history, containing every canary shape.
        append("idp.jsonl", failures_then_success(base, user=CANARY_USER, ip=CANARY_IP, ids=False)[:3])
        append("claims.jsonl", [claims(base + timedelta(seconds=i), eid=f"{CANARY_EVENT}{i}", lvl="error", http=503,
                                       message=f"login for {CANARY_USER} ssn 123-45-6789", patient=f"{CANARY_PATIENT}{i:06d}")
                                for i in range(5)])
        wait(lambda: pipeline.events_processed["auth"] >= 3 and pipeline.events_processed["app"] >= 5
             and all(t.caught_up for t in pipeline._tailers) and pipeline.queue._unfinished_tasks == 0)

        # Phase 2: live events after a WebSocket client connected.
        with client.websocket_connect("/ws") as ws:
            guard = threading.Timer(25, ws.close)
            guard.start()
            frames.append(ws.receive_json())                                               # snapshot
            live_base = now() - timedelta(minutes=2)
            append("idp.jsonl", [idp(live_base + timedelta(seconds=i), CANARY_USER, "Failure", eid=f"{CANARY_EVENT}auth{i}",
                                     ip=CANARY_IP) for i in range(5)]
                   + [idp(live_base + timedelta(seconds=9), CANARY_USER, "Success", eid=f"{CANARY_EVENT}ok", ip=CANARY_IP)])
            append("ehr.jsonl", [ehr(live_base + timedelta(seconds=i * 0.2), CANARY_USER2, "READ", f"{CANARY_PATIENT}{i:06d}",
                                     eid=f"{CANARY_EVENT}ehr{i}") for i in range(260)])
            seen_alert = seen_logs = False
            for _ in range(40):
                f = ws.receive_json()
                frames.append(f)
                seen_alert |= f.get("type") == "alert"
                seen_logs |= f.get("type") == "logs"
                if seen_alert and seen_logs:
                    break
            guard.cancel()
            assert seen_alert and seen_logs
        wait(lambda: pipeline.events_processed["audit"] >= 260 and pipeline.queue._unfinished_tasks == 0)
        wait(lambda: len(FakeSMTP.all_sent()) >= 1, 10)

        incidents = client.get("/api/incidents").json()
        kinds = {i["kind"] for i in incidents}
        assert "auth_suspicious_login" in kinds and any(k.startswith("hipaa_") for k in kinds)
        api_text = [json.dumps(incidents)]
        for path in ("/api/incidents/search", "/api/incidents/summary", "/api/alerts", "/api/activity", "/api/logs?limit=500",
                     "/api/hipaa/users", "/api/analytics", "/api/config", "/api/status", "/api/health", "/api/services",
                     "/api/ingest/status", "/api/security/status", "/api/aws/status", "/api/notifications/email",
                     "/api/settings/notifications", "/api/audit", "/api/metrics?service=claims", "/api/services/claims"):
            r = client.get(path)
            assert r.status_code in (200, 404), (path, r.status_code)
            api_text.append(r.text)
        for inc in incidents:
            for sub in ("", "/timeline", "/correlation"):
                r = client.get(f"/api/incidents/{inc['id']}{sub}")
                assert r.status_code == 200, (sub, r.status_code)
                api_text.append(r.text)
        auth_inc = next(i for i in incidents if i["kind"] == "auth_suspicious_login")
        assert auth_inc["user_id"] == ps.user(CANARY_USER)                                  # positive control: pseudonym present
        status = client.get("/api/ingest/status").json()
        assert status["mode"] == "configured" and status["pseudonymization"]["enabled"] is True
        assert KEY not in json.dumps(status) and "/" not in json.dumps([x["path"] for x in status["sources"]])

    # --- assertions across every sink ---
    def assert_clean(label: str, text: str) -> None:
        low = text.lower()
        for needle in RAW_NEEDLES:
            assert needle not in low, f"{label} leaked {needle!r}"
        assert "123-45-6789" not in low, f"{label} leaked an SSN"
        assert KEY.lower() not in low, f"{label} leaked the pseudonym key"

    assert_clean("API", "\n".join(api_text))
    assert_clean("WebSocket", json.dumps(frames, default=str))
    assert_clean("application logs", caplog.text)
    assert_clean("database rows", _all_text_in_db(s.db_path))
    raw_bytes = b"".join(p.read_bytes() for p in (s.db_path, Path(str(s.db_path) + "-wal")) if p.exists()).lower()
    for needle in RAW_NEEDLES:
        assert needle.encode() not in raw_bytes, f"database file bytes contain {needle!r}"
    sent = "\n".join(m.as_string() for m in FakeSMTP.all_sent()) if hasattr(FakeSMTP, "all_sent") else ""
    assert sent, "expected the fake mailer to have received a notification"
    assert_clean("email payload", sent)
    aws_log = tmp_path / "aws_mock.log"
    assert aws_log.exists() and aws_log.stat().st_size > 0, "expected mock AWS notifications"
    assert_clean("AWS notification payload", aws_log.read_text())


# -- legacy mode: unchanged behaviour, explicit warning -------------------------------------------------------

def test_legacy_mode_keeps_raw_synthetic_ids_and_warns_it_is_unsuitable(tmp_path):
    s = Settings(_env_file=None, aws_mode="off", email_enabled=False, database_url="", log_dir=tmp_path / "logs",
                 db_path=tmp_path / "l.db", control_file=tmp_path / "c.json", static_dir=tmp_path / "nostatic",
                 embedded_generator=False)
    s.log_dir.mkdir()
    for n in ("app.log", "audit.log", "auth.log"):
        (s.log_dir / n).write_text("")
    assert s.ingest_mode == "legacy"
    app = create_app(settings=s, config=config_for(AUTH_SRC))
    with TestClient(app) as client:
        warnings = {w["code"]: w for w in client.get("/api/security/status").json()["warnings"]}
        assert "legacy_ingest" in warnings and "NOT suitable for real logs" in warnings["legacy_ingest"]["message"]
        st = client.get("/api/ingest/status").json()
        assert st["mode"] == "legacy" and st["pseudonymization"]["enabled"] is False


def test_configured_mode_does_not_show_the_legacy_warning(tmp_path):
    s = settings_for(tmp_path)
    (s.log_dir / "idp.jsonl").write_text("")
    app = create_app(settings=s, config=config_for(AUTH_SRC))
    with TestClient(app) as client:
        codes = {w["code"] for w in client.get("/api/security/status").json()["warnings"]}
        assert "legacy_ingest" not in codes
