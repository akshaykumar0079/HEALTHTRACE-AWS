"""M2 acceptance tests: one consistent privacy boundary (docs/M2_PRIVACY_VERIFICATION.md).

Criteria are tagged C1..C10 in the test names. Every "nothing leaked" assertion is paired
with a positive control proving the path under test actually carried data. Synthetic data
and local mocks only: FakeSMTP, the file-backed AWS mock, SQLite (and PostgreSQL when
HEALTHTRACE_TEST_DATABASE_URL is set). No network, no real service."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import smtplib
import sqlite3
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings
from app.ingest.pseudonym import IngestConfigError, Pseudonymizer, load_key
from app.main import create_app
from app.notify.aws import AwsNotifier
from app.notify.mailer import EmailNotifier
from app.pipeline import Pipeline
from app.privacy import safe_log
from tests.ingest_helpers import (
    APP_SRC, APP_SRC_MSG, AUDIT_SRC, AUTH_SRC, KEY, OTHER_KEY, claims, config_for, ehr, failures_then_success, idp,
    make_pipeline, now, settings_for,
)
from tests.privacy_harness import (
    CANARY_BAD_USER, CANARY_EVENT, CANARY_GARBAGE, CANARY_IP, CANARY_MSG_NAME, CANARY_OVERSIZE, CANARY_PATIENT,
    CANARY_UNKNOWN_SERVICE, CANARY_UNMAPPED, CANARY_USER, CANARY_USER2, RAW_NEEDLES, SSN, capture_logs, db_text_sqlite,
    run_scenario, scan,
)
from tests.test_email import FakeSMTP, bulk_access, email_settings
from tests.test_notifier import make_alert, make_incident

PG_URL = os.environ.get("HEALTHTRACE_TEST_DATABASE_URL", "")
REPO = Path(__file__).resolve().parents[2]
RECIPIENT = "vasan.akxy@gmail.com"  # operator-configured notification address used by the e-mail fixtures


@pytest.fixture(scope="module")
def out(tmp_path_factory):
    """The end-to-end scenario runs once; criteria tests inspect what it emitted."""
    return run_scenario(tmp_path_factory.mktemp("m2_scenario"))


# =====================================================================================================
# C1 - ingestion privacy boundary
# =====================================================================================================

async def test_c1_detectors_only_ever_receive_pseudonymized_event_objects(monkeypatch):
    p = await make_pipeline(srcs=[AUTH_SRC, AUDIT_SRC, APP_SRC_MSG])
    seen: dict[str, list[str]] = {"auth": [], "audit": [], "app": []}
    for kind, name in (("auth", "_process_auth_event"), ("audit", "_process_audit_event"), ("app", "_process_app_event")):
        original = getattr(p, name)

        async def spy(event, _orig=original, _kind=kind):
            seen[_kind].append(event.model_dump_json())
            return await _orig(event)

        monkeypatch.setattr(p, name, spy)
    base = now() - timedelta(minutes=5)
    for line in failures_then_success(base, user=CANARY_USER, ip=CANARY_IP):
        await p._process_line(line, "idp_fixture")
    await p._process_line(ehr(base, CANARY_USER2, "READ", CANARY_PATIENT + "000001", eid="e1"), "ehr_audit_fixture")
    await p._process_line(claims(base, eid=CANARY_EVENT + "1", patient=CANARY_PATIENT + "000002",
                                 message=f"{CANARY_USER} {CANARY_IP} {SSN}"), "claims_app_fixture")
    # positive control: the detectors really received events of all three kinds
    assert len(seen["auth"]) == 6 and len(seen["audit"]) == 1 and len(seen["app"]) == 1
    for kind, payloads in seen.items():
        scan(f"{kind} event object", "\n".join(payloads))
    ps = Pseudonymizer.from_setting(KEY)
    assert ps.user(CANARY_USER) in seen["auth"][0] and ps.ip(CANARY_IP) in seen["auth"][0]
    assert ps.patient(CANARY_PATIENT + "000001") in seen["audit"][0]
    await p.store.close()


def test_c1_no_raw_identifier_in_any_detection_state(out):
    # positive control: the walk reached real detector state (pseudonyms are there), and a lot of it
    assert out.state_nodes > 1000
    assert out.ps.user(CANARY_USER) in out.state_text and out.ps.user(CANARY_USER2) in out.state_text
    assert out.ps.ip(CANARY_IP) in out.state_text
    # the dedupe component legitimately holds the HMAC key, so the key itself is excluded from this one scan
    scan("pipeline in-memory state (detectors, windows, incidents, buffers, queue, dedupe, quarantine)", out.state_text, check_key=False)


async def test_c1_rejected_lines_are_not_retained_by_the_ingest_layer():
    p = await make_pipeline()
    bad = [f"{CANARY_GARBAGE} {CANARY_USER}", json.dumps({"@timestamp": "nonsense", "actor": {"name": CANARY_BAD_USER}})]
    for line in bad:
        await p._process_line(line, "idp_fixture", 0)
    assert p.quarantine.total() == 2                                                  # positive control
    from tests.privacy_harness import graph_text
    text, nodes = graph_text(p)
    assert nodes > 50
    scan("state after rejects", text, check_key=False)   # the dedupe component holds the HMAC key by design
    await p.store.close()


# =====================================================================================================
# C2 - pseudonymization correctness and safe failure
# =====================================================================================================

def test_c2_pseudonyms_equal_an_independent_hmac_sha256_computation():
    ps = Pseudonymizer.from_setting(KEY)
    for domain, fn, prefix in (("user", ps.user, "U-"), ("patient", ps.patient, "P-"),
                               ("ip", ps.ip, "ip-"), ("request", ps.request, "req-")):
        expected = hmac.new(KEY.encode(), f"{domain}\x00{CANARY_USER}".encode(), hashlib.sha256).hexdigest()[:12]
        assert fn(CANARY_USER) == prefix + expected
        assert fn(CANARY_USER) == fn(CANARY_USER)                                    # stable
    outputs = {ps.user("x"), ps.patient("x"), ps.ip("x"), ps.request("x")}
    assert len({o.split("-", 1)[1] for o in outputs}) == 4                            # domain separated: same text, 4 digests


def test_c2_the_key_fingerprint_is_one_way_and_not_a_pseudonym():
    a, b = Pseudonymizer.from_setting(KEY), Pseudonymizer.from_setting(OTHER_KEY)
    assert a.fingerprint() == Pseudonymizer.from_setting(KEY).fingerprint() != b.fingerprint()
    assert KEY not in a.fingerprint() and len(a.fingerprint()) == 16
    label = "healthtrace:key-fingerprint:v1"
    assert a.fingerprint() not in {a.user(label)[2:], a.patient(label)[2:], a.ip(label)[3:], a.request(label)[4:]}   # not a pseudonym
    assert KEY not in repr(a)


@pytest.mark.parametrize("bad", [None, "", "   ", "\t\n", "short-key", "a" * 31, "z" * 64, "ab" * 20, "changeme" + "x7" * 20,
                                 "example-" + "Qw9" * 12, "placeholder-" + "Lm4" * 10])
def test_c2_missing_or_invalid_keys_refuse_configured_mode_without_fallback(tmp_path, bad):
    with pytest.raises(IngestConfigError) as e:
        load_key(bad)
    if bad and bad.strip():
        assert bad.strip() not in str(e.value)
    s = settings_for(tmp_path, pseudonym_key=SecretStr(bad or ""))
    with pytest.raises(IngestConfigError):
        Pipeline(s, config_for(AUTH_SRC))                                           # the pipeline is never built...
    with pytest.raises(IngestConfigError):
        create_app(settings=s, config=config_for(AUTH_SRC))                         # ...and neither is the app
    assert not (s.log_dir / "idp.jsonl").exists()                                    # nothing was read or created


def test_c2_the_key_comes_from_the_environment_and_a_missing_env_var_refuses(monkeypatch, tmp_path):
    monkeypatch.setenv("INGEST_MODE", "configured")
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.delenv("PSEUDONYM_KEY", raising=False)
    (tmp_path / "logs").mkdir()
    s = Settings(_env_file=None, database_url="", db_path=tmp_path / "x.db", aws_mode="off")
    assert s.ingest_mode == "configured" and s.pseudonym_key.get_secret_value() == ""
    with pytest.raises(IngestConfigError):
        Pipeline(s, config_for(AUTH_SRC))
    monkeypatch.setenv("PSEUDONYM_KEY", KEY)
    s2 = Settings(_env_file=None, database_url="", db_path=tmp_path / "x.db", aws_mode="off", log_dir=tmp_path / "logs")
    assert s2.pseudonym_key.get_secret_value() == KEY
    assert KEY not in repr(s2) and KEY not in json.dumps(s2.model_dump(mode="json"), default=str)


def test_c2_no_key_is_hard_coded_in_the_source_tree():
    hits = []
    for path in list((REPO / "backend" / "app").rglob("*.py")) + [REPO / "config.yaml", REPO / ".env.example"]:
        text = path.read_text(errors="ignore")
        for m in re.finditer(r"PSEUDONYM_KEY\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,})", text):
            hits.append((path.name, m.group(0)[:20]))
    assert hits == []


async def _start_and_stop(settings, cfg) -> Pipeline:
    p = Pipeline(settings, cfg)
    await p.start()
    state = dict(p.key_state)
    await p.stop()
    p.key_state_snapshot = state
    return p


async def test_c2_a_changed_key_on_an_existing_database_stops_start_up_unless_acknowledged(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    cfg = config_for(AUTH_SRC)
    first = await _start_and_stop(settings_for(tmp_path), cfg)
    fp = first.pseudonymizer.fingerprint()[:8]
    assert first.key_state_snapshot["fingerprint"] == fp and first.key_state_snapshot["legacy_rows_at_cutover"] is False
    again = await _start_and_stop(settings_for(tmp_path), cfg)                      # same key: fine
    assert again.key_state_snapshot["fingerprint"] == fp

    other = settings_for(tmp_path, pseudonym_key=SecretStr(OTHER_KEY))
    with pytest.raises(IngestConfigError) as e:
        await Pipeline(other, cfg).start()
    assert "PSEUDONYM_KEY_ROTATION_ACK" in str(e.value) and OTHER_KEY not in str(e.value) and KEY not in str(e.value)

    acked = settings_for(tmp_path, pseudonym_key=SecretStr(OTHER_KEY), pseudonym_key_rotation_ack=True)
    rotated = await _start_and_stop(acked, cfg)
    assert rotated.key_state_snapshot["rotated_at"] and rotated.key_state_snapshot["fingerprint"] != fp
    assert "PSEUDONYM_KEY changed (acknowledged)" in caplog.text
    # after the acknowledged start the new key is simply the key; the old one now needs acknowledgement
    with pytest.raises(IngestConfigError):
        await Pipeline(settings_for(tmp_path), cfg).start()
    for secret in (KEY, OTHER_KEY):
        assert secret not in caplog.text


async def test_c2_enabling_configured_mode_on_a_database_with_old_rows_is_flagged_not_rewritten(tmp_path):
    legacy_settings = Settings(_env_file=None, aws_mode="off", email_enabled=False, database_url="", log_dir=tmp_path / "logs",
                               db_path=tmp_path / "t.db", control_file=tmp_path / "c.json", static_dir=tmp_path / "ns",
                               embedded_generator=False, retention_interval_hours=0)
    legacy_settings.log_dir.mkdir()
    for n in ("app.log", "audit.log", "auth.log"):
        (legacy_settings.log_dir / n).write_text("")
    lp = Pipeline(legacy_settings, config_for(AUTH_SRC))
    await lp.start()
    base = now() - timedelta(minutes=5)
    for i in range(6):
        await lp._process_line(json.dumps({"ts": (base + timedelta(seconds=i)).isoformat(), "type": "auth", "user_id": "legacy.raw.user",
                                           "outcome": "failure" if i < 5 else "success", "source_region": "RU", "user_region": "IN",
                                           "source_ip": "192.0.2.77"}))
    await lp.stop()
    before = db_text_sqlite(legacy_settings.db_path)
    assert "legacy.raw.user" in before                                               # legacy mode keeps raw ids (documented)

    cp = await _start_and_stop(settings_for(tmp_path, db_path=legacy_settings.db_path), config_for(AUTH_SRC))
    assert cp.key_state_snapshot["legacy_rows_at_cutover"] is True
    assert "legacy.raw.user" in db_text_sqlite(legacy_settings.db_path)              # NOT silently rewritten or deleted
    s = settings_for(tmp_path, db_path=legacy_settings.db_path)
    (s.log_dir / "idp.jsonl").write_text("")
    with TestClient(create_app(settings=s, config=config_for(AUTH_SRC))) as client:
        codes = {w["code"] for w in client.get("/api/security/status").json()["warnings"]}
        assert "historical_raw_data" in codes
        st = client.get("/api/ingest/status").json()["pseudonymization"]
        assert st["legacy_rows_at_cutover"] is True and KEY not in json.dumps(st)


# =====================================================================================================
# C3 - database privacy
# =====================================================================================================

def test_c3_sqlite_rows_and_file_bytes_contain_no_raw_identifier_or_source_line(out):
    t = out.db_tables
    for table in ("incidents", "alerts", "evidence_events", "incident_events", "audit_log", "ingest_seen", "ingest_rejects",
                  "ingest_reject_counts", "notification_attempts", "tail_positions", "metrics", "baselines"):
        assert t.get(table, 0) > 0, f"positive control: {table} has no rows, so it was not exercised"
    assert out.ps.user(CANARY_USER) in out.db_text and out.ps.user(CANARY_USER2) in out.db_text
    scan("database rows", out.db_text)
    low = out.db_bytes.lower()
    for needle in (*RAW_NEEDLES, SSN, KEY.lower()):
        assert needle.encode() not in low, f"database file bytes contain {needle!r}"


def test_c3_dedupe_and_quarantine_tables_hold_only_digests_and_metadata(out):
    con = sqlite3.connect(out.settings.db_path)
    ids = [r[0] for r in con.execute("SELECT event_id FROM ingest_seen")]
    assert len(ids) > 100 and all(re.fullmatch(r"[ic]:[0-9a-f]{20,}", i) for i in ids)       # keyed digests only
    reasons_seen = {r[0] for r in con.execute("SELECT reason FROM ingest_reject_counts")}
    assert {"line_too_long", "invalid_json", "ts_invalid", "bad_value", "unknown_service"} <= reasons_seen   # positive control
    cols = [r[1] for r in con.execute("PRAGMA table_info(ingest_rejects)")]
    assert set(cols) == {"id", "ts", "source", "reason", "line_offset", "line_length"}        # no column that could hold a line
    meta = dict(con.execute("SELECT key, value FROM ingest_meta").fetchall())
    assert set(meta) <= {"pseudonym_key_fingerprint", "legacy_rows_at_cutover", "key_rotated_at"}
    assert meta["pseudonym_key_fingerprint"] == out.ps.fingerprint() and KEY not in "".join(meta.values())
    con.close()


def test_c3_unmapped_source_fields_are_never_copied_anywhere(out):
    assert out.pipeline_counts["auth"] >= 3                                         # the lines carrying the unmapped note were processed
    for label, text in (("db", out.db_text), ("api", out.api_text), ("ws", json.dumps(out.ws_frames, default=str)),
                        ("state", out.state_text), ("logs", out.logs.text)):
        assert CANARY_UNMAPPED not in text.lower(), label


@pytest.mark.skipif(not PG_URL, reason="needs HEALTHTRACE_TEST_DATABASE_URL (PostgreSQL)")
async def test_c3_postgresql_tables_contain_no_raw_identifier():
    from app.store.database import PostgresDatabase

    db = PostgresDatabase(PG_URL)
    await db.connect()
    await db.execute("DROP SCHEMA public CASCADE")
    await db.execute("CREATE SCHEMA public")
    await db.close()
    work = Path(tempfile.mkdtemp())
    p = Pipeline(settings_for(work, database_url=PG_URL), config_for(AUTH_SRC, AUDIT_SRC, APP_SRC_MSG))
    await p.start()
    base = now() - timedelta(minutes=5)
    for line in failures_then_success(base, user=CANARY_USER, ip=CANARY_IP):
        await p._process_line(line, "idp_fixture")
    for i in range(3):
        await p._process_line(claims(base + timedelta(seconds=i), eid=f"{CANARY_EVENT}{i}", lvl="error", http=503,
                                     message=f"{CANARY_USER} {CANARY_IP} {SSN}", patient=f"{CANARY_PATIENT}{i:06d}"), "claims_app_fixture")
    await p._process_line(f"{CANARY_GARBAGE} {CANARY_USER}", "idp_fixture", 0)
    await p._save_state()
    await p.audit("operator", "acknowledge", "incident", 1)                           # audit_log row
    await p._record_email_attempt({"kind": "incident", "status": "accepted", "incident_id": 1, "severity": "HIGH",
                                   "provider": "smtp", "detail": "accepted by smtp (not a delivery confirmation)"})
    await p.store.save_tail_position("auth.log", 1, 128)                              # tailers are not run at pipeline level
    await asyncio.sleep(0.2)                                                          # the hook persists asynchronously
    names = [r[0] for r in await (await p.store.conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).fetchall()]
    text, populated = [], set()
    for n in names:
        rows = await (await p.store.conn.execute(f'SELECT * FROM "{n}"')).fetchall()
        if rows:
            populated.add(n)
        text.extend(json.dumps(r, default=str) for r in rows)
    assert {"incidents", "alerts", "evidence_events", "ingest_seen", "ingest_rejects", "ingest_reject_counts", "ingest_meta",
            "audit_log", "notification_attempts", "tail_positions"} <= populated      # positive control
    scan("PostgreSQL rows", "\n".join(text))
    assert Pseudonymizer.from_setting(KEY).user(CANARY_USER) in "\n".join(text)
    await p.stop()


def test_c3_driver_debug_logging_does_not_print_sql_parameters(tmp_path, monkeypatch):
    from app.store.db import Store

    async def run(store_path: Path) -> str:
        with capture_logs() as logs:
            store = Store(store_path)
            await store.connect()
            await store.add_audit(actor="operator", action="ack", target_type="incident", target_id=CANARY_USER,
                                  detail=f"param {CANARY_USER2} {CANARY_IP}", outcome="ok")
            await store.close()
        return logs.text

    guarded = asyncio.run(run(tmp_path / "a.db"))
    assert "INSERT INTO audit_log" not in guarded                                    # statements are not logged at all...
    scan("driver logs (guarded)", guarded)

    # positive control: remove the guard and the same operation DOES print the parameters
    drivers = [logging.getLogger(n) for n in ("aiosqlite",)]
    saved = [(lg, lg.level, list(lg.filters)) for lg in drivers]
    monkeypatch.setattr("app.store.database.quiet_driver_logs", lambda: None)       # connect() no longer applies the guard
    try:
        for lg in drivers:
            lg.setLevel(logging.DEBUG)
            lg.filters.clear()
        unguarded = asyncio.run(run(tmp_path / "b.db"))
    finally:
        for lg, level, filters in saved:
            lg.setLevel(level)
            lg.filters[:] = filters
    assert CANARY_USER2 in unguarded and "INSERT INTO audit_log" in unguarded        # the control: the leak is real without the guard
    assert logging.getLogger("aiosqlite").level == logging.WARNING                    # and the guard is back in place


BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG_URL, reason="needs HEALTHTRACE_TEST_DATABASE_URL"))]


@pytest.mark.parametrize("kind", BACKENDS)
async def test_c3_m005_is_additive_idempotent_and_keeps_existing_rows(kind, tmp_path, monkeypatch):
    """Migration compatibility on SQLite and PostgreSQL: the new table is additive and existing data is untouched."""
    from app.store import migrations
    from app.store.database import PostgresDatabase, create_database
    from app.store.db import Store
    from app.store.migrations import LATEST_VERSION, applied_versions, migrate

    if kind == "postgres":
        db = PostgresDatabase(PG_URL)
        await db.connect()
        await db.execute("DROP SCHEMA public CASCADE")
        await db.execute("CREATE SCHEMA public")
        await db.close()
        db = create_database(tmp_path / "x.db", PG_URL)
    else:
        db = create_database(tmp_path / "m.db")
    await db.connect()
    monkeypatch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS[:4])
    assert await migrate(db) == [1, 2, 3, 4]
    monkeypatch.undo()
    await db.execute("INSERT INTO audit_log (ts, actor, action, target_type, outcome) VALUES ('2026-01-01T00:00:00+00:00','a','x','t','ok')")
    await db.commit()
    assert not await db.table_exists("ingest_meta")
    assert await migrate(db) == list(range(5, LATEST_VERSION + 1)) and await db.table_exists("ingest_meta")
    assert await migrate(db) == []                                                    # idempotent
    assert sorted(await applied_versions(db)) == list(range(1, LATEST_VERSION + 1))
    assert (await (await db.execute("SELECT COUNT(*) FROM audit_log")).fetchone())[0] == 1
    await db.close()

    store = Store(tmp_path / "unused.db", PG_URL) if kind == "postgres" else Store(tmp_path / "s.db")
    await store.connect()
    assert await store.get_ingest_meta("k") is None
    await store.set_ingest_meta("k", "v1")
    await store.set_ingest_meta("k", "v2")                                           # upsert works on both dialects
    assert await store.get_ingest_meta("k") == "v2"
    await store.close()


def test_c3_every_table_is_inventoried_in_the_privacy_boundary_document(out):
    doc = (REPO / "docs" / "privacy-boundary.md").read_text()
    missing = [t for t in out.db_tables if t != "sqlite_sequence" and f"`{t}`" not in doc]
    assert missing == [], f"tables missing from docs/privacy-boundary.md: {missing}"


# =====================================================================================================
# C4 - REST API
# =====================================================================================================

def test_c4_every_get_endpoint_and_incident_sub_resource_is_free_of_raw_identifiers(out):
    assert len(out.api) > 55                                                         # positive control: the sweep was broad
    assert all(code < 500 for code in out.api_status.values()), {k: v for k, v in out.api_status.items() if v >= 500}
    for path, text in out.api.items():
        scan(f"GET {path}", text)
    joined = out.api_text
    for must in (out.ps.user(CANARY_USER), out.ps.user(CANARY_USER2)):               # pseudonyms are what the API shows
        assert must in joined
    assert "/api/incidents/1/timeline" in out.api and any("/timeline/" in k for k in out.api)   # entry-level evidence was fetched
    assert any(k.endswith("/context") for k in out.api)                               # log context was fetched
    assert "POST ack" in out.api and "POST pin" in out.api                            # operator actions were exercised


def test_c4_audit_trail_and_operator_actions_hold_no_source_identifiers(out):
    audit = out.api["/api/audit"]
    rows = json.loads(audit)
    assert {r["action"] for r in rows} >= {"acknowledge", "investigate", "pin"}      # positive control
    scan("/api/audit", audit)


def test_c4_search_terms_are_not_echoed_and_find_nothing(out):
    for q in (CANARY_USER, CANARY_USER2, CANARY_IP):
        body = json.loads(out.api[f"/api/logs?q={q}"])
        assert body["events"] == []                                                   # raw values match nothing: they are not stored
        assert q.lower() not in out.api[f"/api/logs?q={q}"].lower()
    positive = json.loads(out.api.get("/api/logs", "{}"))
    assert positive["events"], "positive control: the unfiltered buffer has events"


def test_c4_error_responses_do_not_echo_input_secrets_or_internals(tmp_path, monkeypatch):
    s = settings_for(tmp_path)
    (s.log_dir / "idp.jsonl").write_text("")
    app = create_app(settings=s, config=config_for(AUTH_SRC))
    pipeline = app.state.pipeline
    with capture_logs() as logs, TestClient(app, raise_server_exceptions=False) as client:
        r404 = client.get("/api/incidents/999999")
        assert r404.status_code == 404
        r422 = client.get(f"/api/logs?limit={CANARY_USER}")
        assert r422.status_code == 422 and isinstance(r422.json()["detail"], list)
        assert all(set(d) == {"loc", "msg", "type"} for d in r422.json()["detail"])  # no "input" echo
        r422b = client.post("/api/incidents/1/mute", json={"minutes": CANARY_USER2})
        assert r422b.status_code == 422

        async def boom(*a, **k):
            raise RuntimeError(f"explode for {CANARY_USER} from {CANARY_IP} in {tmp_path}")

        monkeypatch.setattr(pipeline.store, "list_alerts", boom)
        r500 = client.get("/api/alerts")
        assert r500.status_code == 500 and r500.json() == {"detail": "Internal server error"}
        for name, r in (("404", r404), ("422", r422), ("422b", r422b), ("500", r500)):
            scan(f"error response {name}", r.text)
            assert str(tmp_path) not in r.text and "Traceback" not in r.text
    assert logs.has("unhandled error on GET /api/alerts: RuntimeError")              # positive control: the failure was logged, safely
    scan("logs after a forced 500", logs.text)
    assert "Traceback" not in logs.text and str(tmp_path / "x") not in logs.text


def test_c4_there_is_no_export_or_download_endpoint():
    from app.api.routes import router

    paths = [r.path for r in router.routes if isinstance(r, APIRoute)]
    assert paths, "router has routes"
    assert not [p for p in paths if re.search(r"export|download|dump|backup", p)], \
        "an export-style endpoint was added: it needs its own privacy review and canary test"


def test_c4_configuration_and_status_endpoints_never_show_secrets_or_paths(out):
    for path in ("/api/config", "/api/status", "/api/security/status", "/api/ingest/status", "/api/aws/status",
                 "/api/notifications/email", "/api/settings/notifications"):
        text = out.api[path]
        assert KEY not in text and "PSEUDONYM_KEY" not in text.replace("PSEUDONYM_KEY_ROTATION_ACK", "")
        assert str(out.settings.log_dir) not in text and str(out.settings.db_path) not in text, path
        from tests.test_email import APP_PASSWORD
        assert APP_PASSWORD not in text, path


# =====================================================================================================
# C5 - WebSocket
# =====================================================================================================

def test_c5_websocket_frames_of_every_type_are_free_of_raw_identifiers(out):
    assert {"snapshot", "alert", "incident_update", "metric", "logs"} <= out.ws_types, out.ws_types     # positive control
    assert len(out.ws_frames) > 20
    scan("WebSocket frames", json.dumps(out.ws_frames, default=str))
    text = json.dumps(out.ws_frames)
    assert out.ps.user(CANARY_USER) in text                                           # live frames carried the pseudonym
    live_logs = [e for f in out.ws_frames if f.get("type") == "logs" for e in f["events"]]
    assert any(e.get("type") == "audit" for e in live_logs) or any(e.get("type") == "app" for e in live_logs)


def test_c5_incident_creation_and_update_frames_carry_pseudonymous_users_and_policy_text(out):
    updates = [f for f in out.ws_frames if f.get("type") == "incident_update"]
    assert updates
    users = {u["incident"].get("user_id") for u in updates if u["incident"].get("user_id")}
    assert users and all(re.fullmatch(r"U-[0-9a-f]{12}", x) for x in users), users
    for u in updates:
        inc = u["incident"]
        if inc.get("user_id"):
            assert inc["fingerprint"] == f"{inc['kind']}:{inc['user_id']}"             # fingerprint uses the pseudonym
        scan("incident_update frame", json.dumps(u, default=str))


# =====================================================================================================
# C6 - application logs and exceptions
# =====================================================================================================

def test_c6_logs_captured_at_debug_level_during_the_whole_scenario_are_clean(out):
    text = out.logs.text
    assert len(out.logs.records) > 50                                                 # positive control: a lot was captured
    assert out.logs.from_loggers("app.pipeline", "app.notify", "app.ingest")          # ...including the application's own loggers
    assert not out.logs.from_loggers("aiosqlite")                                     # driver statements/parameters are not logged
    scan("application logs (DEBUG, malformed input, retries)", text)
    from tests.test_email import APP_PASSWORD
    assert APP_PASSWORD not in text


async def test_c6_an_exception_raised_while_processing_a_line_is_logged_without_its_message(monkeypatch):
    p = await make_pipeline()

    async def explode(event):
        raise ValueError(f"cannot process {CANARY_USER} {CANARY_IP} {event!r}")

    monkeypatch.setattr(p, "_process_auth_event", explode)
    from app.ingest.tailer import SourceLine

    with capture_logs() as logs:
        p.queue.put_nowait(SourceLine("idp_fixture", idp(now() - timedelta(minutes=1), CANARY_USER, "Failure", eid="e2",
                                                         ip=CANARY_IP), 0))
        consumer = asyncio.create_task(p._consume())
        await asyncio.wait_for(p.queue.join(), 5)
        consumer.cancel()
    assert logs.has("pipeline: error processing a line: ValueError")                  # positive control
    scan("logs after a processing exception", logs.text)
    assert "Traceback" not in logs.text
    await p.store.close()


async def test_c6_a_database_error_is_logged_with_type_and_location_only():
    p = await make_pipeline()
    with capture_logs() as logs:
        p._db_failed("write incident", sqlite3.IntegrityError(f"UNIQUE failed for {CANARY_USER} {CANARY_IP} {SSN}"))
    assert logs.has("database error during write incident (IntegrityError")
    scan("db error log", logs.text)
    await p.store.close()


async def test_c6_malformed_oversize_and_non_json_input_never_reach_logs(tmp_path):
    p = await make_pipeline(work=tmp_path)
    with capture_logs() as logs:
        for line in (f"{CANARY_GARBAGE} {CANARY_USER}", "{" + CANARY_OVERSIZE, json.dumps({"x": CANARY_USER}),
                     json.dumps([CANARY_USER]), json.dumps({"@timestamp": "bad", "actor": {"name": CANARY_USER}})):
            await p._process_line(line, "idp_fixture", 7)
    assert p.quarantine.total() == 5                                                    # positive control
    scan("logs from malformed input", logs.text)
    await p.store.close()


def test_c6_the_safe_log_helpers():
    assert safe_log.scrub_text(f"a {CANARY_USER} b {CANARY_IP} c {SSN} d 2001:db8:85a3::8a2e:370:7334") == \
        "a [EMAIL] b [IP] c [SSN] d [IP]"
    assert safe_log.mask_email(RECIPIENT) == "v***@gmail.com" and safe_log.mask_email("nonsense") == "[address]"
    try:
        raise KeyError(CANARY_USER)
    except KeyError as exc:
        described = safe_log.safe_exc(exc)
    assert described.startswith("KeyError at test_m2_privacy.py:") and CANARY_USER not in described
    assert CANARY_USER not in safe_log.sanitize_error(ValueError(f"x {CANARY_USER}"))
    assert len(safe_log.sanitize_error("z" * 1000)) <= 204


# =====================================================================================================
# C7 - incidents, fingerprints, explanations; detection still works
# =====================================================================================================

def test_c7_incident_references_fingerprints_and_explanations_use_pseudonyms(out):
    by_kind = {i["kind"]: i for i in out.incidents}
    assert {"auth_suspicious_login", "error_rate"} <= set(by_kind) and any(k.startswith("hipaa_") for k in by_kind)   # detection works
    auth = by_kind["auth_suspicious_login"]
    pseud = out.ps.user(CANARY_USER)
    assert auth["user_id"] == pseud and auth["fingerprint"] == f"auth_suspicious_login:{pseud}"
    alerts = json.loads(out.api["/api/alerts"])
    auth_alert = next(a for a in alerts if a["kind"] == "auth_suspicious_login")
    assert pseud in auth_alert["explanation"] and CANARY_USER.lower() not in auth_alert["explanation"].lower()
    hipaa = next(i for k, i in by_kind.items() if k.startswith("hipaa_"))
    assert hipaa["user_id"] == out.ps.user(CANARY_USER2)
    for i in out.incidents:
        scan(f"incident {i['id']}", json.dumps(i))
    # evidence + timeline + correlation views of those incidents
    for k in out.api:
        if re.fullmatch(r"/api/incidents/\d+/(timeline|correlation)", k):
            scan(k, out.api[k])


async def _incident_signature(p) -> list[tuple[str, str]]:
    return sorted((i.kind, i.peak_severity) for i in p.incidents.list_incidents())


async def test_c7_pseudonymization_does_not_change_what_is_detected():
    """Same behaviour in two configured deployments with different keys, and the same as legacy parsing of the same story."""
    base = now() - timedelta(minutes=6)
    sigs = []
    for key in (KEY, OTHER_KEY):
        p = await make_pipeline(pseudonym_key=SecretStr(key))
        for line in failures_then_success(base, user="svc.account", ip="203.0.113.50"):
            await p._process_line(line, "idp_fixture")
        for i in range(260):
            await p._process_line(ehr(base + timedelta(seconds=i * 0.2), "dr.x", "READ", f"MRN-{i:06d}", eid=f"e{i}"), "ehr_audit_fixture")
        sigs.append(await _incident_signature(p))
        await p.store.close()
    assert sigs[0] == sigs[1] and sigs[0], sigs                                       # positive control: something was detected
    # the legacy parser sees the same auth story and raises the same auth incident
    work = Path(tempfile.mkdtemp())
    s = Settings(_env_file=None, aws_mode="off", email_enabled=False, database_url="", log_dir=work / "logs", db_path=work / "l.db",
                 control_file=work / "c.json", static_dir=work / "ns", embedded_generator=False)
    s.log_dir.mkdir()
    lp = Pipeline(s, config_for(AUTH_SRC))
    await lp.store.connect()
    await lp.baseline.load(lp.store)
    for i in range(6):
        await lp._process_line(json.dumps({"ts": (base + timedelta(seconds=i)).isoformat(), "type": "auth", "user_id": "svc.account",
                                           "outcome": "failure" if i < 5 else "success", "source_region": "RU",
                                           "user_region": "IN", "source_ip": "203.0.113.50"}))
    legacy_auth = [x for x in await _incident_signature(lp) if x[0] == "auth_suspicious_login"]
    assert legacy_auth and legacy_auth == [x for x in sigs[0] if x[0] == "auth_suspicious_login"]
    await lp.store.close()


async def test_c7_correlation_across_sources_still_joins_on_pseudonyms():
    p = await make_pipeline()
    ps = p.pseudonymizer
    t = now() - timedelta(minutes=3)
    # the same person appears in the identity source and in the EHR audit source
    await p._process_line(idp(t, CANARY_USER, "Failure", eid="a1"), "idp_fixture")
    await p._process_line(ehr(t, CANARY_USER, "READ", "MRN-1", eid="b1"), "ehr_audit_fixture")
    users = {r["user_id"] for r in p.recent_logs if r["type"] in ("auth", "audit")}
    assert users == {ps.user(CANARY_USER)}                                            # one actor, one pseudonym, across sources
    await p.store.close()


# =====================================================================================================
# C8 - e-mail and notifications
# =====================================================================================================

def test_c8_delivered_emails_and_aws_payloads_are_clean_and_not_empty(out):
    assert len(out.emails) >= 2                                                       # positive control (HIGH and CRITICAL incidents)
    for n, mail in enumerate(out.emails):
        scan(f"e-mail #{n}", mail)
        assert "[HEALTHTRACE]" in mail and "U-" in mail                               # severity subject + pseudonymous target kept
    assert out.aws_log.count("\n") >= 5 and out.ps.user(CANARY_USER) in out.aws_log
    scan("AWS mock payloads (CloudWatch + SNS)", out.aws_log)


def test_c8_a_transient_failure_was_retried_and_its_log_lines_do_not_expose_addresses(out):
    lines = out.logs.from_loggers("app.notify.mailer")
    assert any("attempt 1 failed" in l and "retrying" in l for l in lines), lines     # the failure path really ran
    assert any(" sent " in l for l in lines)                                          # and delivery then succeeded (behaviour kept)
    assert RECIPIENT not in "\n".join(lines) and "vasan.akxy" not in "\n".join(lines)
    assert "v***@gmail.com" in "\n".join(lines)
    status = out.api["/api/notifications/email"]
    scan("/api/notifications/email", status)
    assert "attempt 1 failed" not in status or RECIPIENT not in status.split("attempt 1 failed", 1)[1][:200]


async def test_c8_a_permanent_delivery_failure_masks_recipients_in_logs_and_status():
    FakeSMTP.instances, FakeSMTP.fail_with = [], [smtplib.SMTPRecipientsRefused({RECIPIENT: (550, b"no such user")})]
    notifier = EmailNotifier(email_settings(), app_config=config_for(AUTH_SRC), smtp_factory=FakeSMTP, base_backoff=0.01)
    inc, alert = bulk_access()
    inc.user_id = alert.user_id = Pseudonymizer.from_setting(KEY).user(CANARY_USER)
    with capture_logs() as logs:
        await notifier.start()
        notifier.notify_incident(inc, alert)
        await notifier.stop()
    lines = "\n".join(logs.from_loggers("app.notify.mailer"))
    assert "failed to send" in lines                                                  # positive control: the failure was logged
    status_json = json.dumps(notifier.status.to_dict(), default=str)
    assert "refused" in status_json                                                   # positive control: the error is reported...
    assert RECIPIENT not in lines and RECIPIENT not in status_json                    # ...with the address masked
    assert "v***@gmail.com" in lines
    scan("failed-delivery logs", lines)


def test_c8_provider_error_text_masks_addresses_for_every_provider_path():
    from app.notify.mailer import BrevoApiError

    notifier = EmailNotifier(email_settings(), app_config=config_for(AUTH_SRC), smtp_factory=FakeSMTP)
    cases = [
        BrevoApiError(400, f"invalid recipient {RECIPIENT} and {CANARY_USER}"),
        smtplib.SMTPRecipientsRefused({RECIPIENT: (550, b"no such user"), CANARY_USER: (550, b"no")}),
        smtplib.SMTPResponseException(550, f"mailbox {RECIPIENT} unavailable".encode()),
        RuntimeError(f"unexpected {RECIPIENT}"),
    ]
    for exc in cases:
        text = notifier._describe_error(exc)
        assert "@" in text and RECIPIENT not in text and CANARY_USER not in text and "***@" in text, text   # masked, still diagnosable


async def test_c8_an_aws_delivery_failure_is_logged_and_reported_without_the_payload(monkeypatch):
    notifier = AwsNotifier("mock", max_attempts=2, base_backoff=0.01)

    async def always_fails(alert):
        raise RuntimeError(f"AccessDenied for {CANARY_USER} from {CANARY_IP}: {alert!r}")

    monkeypatch.setattr(notifier, "_send_cloudwatch", always_fails)
    with capture_logs() as logs:
        await notifier.start()
        notifier.notify_alert(make_alert())
        await notifier.stop()
    assert logs.has("notifier: giving up after 2 attempts")                           # positive control
    scan("AWS failure log", logs.text)
    channel_status = json.dumps({c: st.to_dict() for c, st in notifier.status.items()}, default=str)
    assert "RuntimeError" in channel_status                                           # positive control: failure recorded
    scan("AWS channel status", channel_status)

    async def crash(item):
        raise RuntimeError(f"unexpected {CANARY_USER} {item!r}")

    monkeypatch.setattr(notifier, "_process_with_retry", crash)
    with capture_logs() as logs2:
        n2 = AwsNotifier("mock")
        monkeypatch.setattr(n2, "_process_with_retry", crash)
        await n2.start()
        n2.notify_alert(make_alert())
        await n2.stop()
    assert logs2.has("notifier: unexpected error processing a cloudwatch item: RuntimeError")
    scan("AWS unexpected-error log", logs2.text)


def test_c8_notification_attempt_rows_are_metadata(out):
    con = sqlite3.connect(out.settings.db_path)
    rows = con.execute("SELECT channel, kind, provider, status, detail FROM notification_attempts").fetchall()
    con.close()
    assert rows and {r[3] for r in rows} <= {"accepted", "failed", "skipped", "queued"}
    scan("notification_attempts", json.dumps(rows))


# =====================================================================================================
# C9 - historical data and operational boundaries
# =====================================================================================================

def _run_audit(db: Path) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "privacy_audit_db.py"), str(db), "--json"],
                       capture_output=True, text=True, cwd=REPO / "backend")
    return r.returncode, r.stdout


async def test_c9_the_scanner_finds_legacy_identifiers_without_printing_or_changing_them(tmp_path):
    s = Settings(_env_file=None, aws_mode="off", email_enabled=False, database_url="", log_dir=tmp_path / "logs", db_path=tmp_path / "legacy.db",
                 control_file=tmp_path / "c.json", static_dir=tmp_path / "ns", embedded_generator=False)
    s.log_dir.mkdir()
    p = Pipeline(s, config_for(AUTH_SRC))
    await p.store.connect()
    await p.baseline.load(p.store)
    base = now() - timedelta(minutes=5)
    for i in range(6):
        await p._process_line(json.dumps({"ts": (base + timedelta(seconds=i)).isoformat(), "type": "auth", "user_id": "legacy.raw.user",
                                          "outcome": "failure" if i < 5 else "success", "source_region": "RU", "user_region": "IN",
                                          "source_ip": "192.0.2.77"}))
    await p._save_state()
    await p.store.close()
    before = hashlib.sha256(s.db_path.read_bytes()).hexdigest()
    code, report = _run_audit(s.db_path)
    assert code == 2                                                                  # indicators found
    data = json.loads(report)
    kinds = {(f["table"], f["column"], f["kind"]) for f in data["findings"]}
    assert ("incidents", "user_id", "non_pseudonym_identifier") in kinds and ("alerts", "user_id", "non_pseudonym_identifier") in kinds
    assert "legacy.raw.user" not in report and "192.0.2.77" not in report              # counts only
    assert hashlib.sha256(s.db_path.read_bytes()).hexdigest() == before                # read-only: file unchanged


async def test_c9_cutover_rehearsal_legacy_database_to_a_new_pseudonymized_database(tmp_path):
    """The documented procedure end to end: scan the old database, start configured mode on a NEW database,
    rebuild history from the same source file, scan again. The old database is left exactly as it was."""
    import time

    logs = tmp_path / "logs"
    logs.mkdir()
    base = now() - timedelta(minutes=5)
    story = [json.dumps({"ts": (base + timedelta(seconds=i)).isoformat(), "type": "auth", "user_id": "legacy.raw.user",
                         "outcome": "failure" if i < 5 else "success", "source_region": "RU", "user_region": "IN",
                         "source_ip": "192.0.2.77"}) for i in range(6)]
    (logs / "auth.log").write_text("\n".join(story) + "\n")
    for n in ("app.log", "audit.log"):
        (logs / n).write_text("")

    def make_legacy_settings():
        return Settings(_env_file=None, aws_mode="off", email_enabled=False, database_url="", log_dir=logs, db_path=tmp_path / "old.db",
                        control_file=tmp_path / "c.json", static_dir=tmp_path / "ns", embedded_generator=False, retention_interval_hours=0)

    # 1) the old world: legacy mode reads the file and stores raw ids
    with TestClient(create_app(settings=make_legacy_settings(), config=config_for(AUTH_SRC))) as client:
        end = time.time() + 20
        while time.time() < end and not client.get("/api/incidents").json():
            time.sleep(0.1)
        assert client.get("/api/incidents").json()[0]["user_id"] == "legacy.raw.user"
    old_db = tmp_path / "old.db"
    old_hash = hashlib.sha256(old_db.read_bytes()).hexdigest()
    code, report = _run_audit(old_db)
    assert code == 2 and "legacy.raw.user" not in report                               # step 1: inventory finds it, prints no values

    # 2-4) the new world: a NEW database, configured mode, history rebuilt from the same source file
    gen = dict(id="synthetic_auth", path="auth.log", format="generator_v1", from_start=True)
    new_settings = settings_for(tmp_path, db_path=tmp_path / "new.db", log_dir=logs)
    with TestClient(create_app(settings=new_settings, config=config_for(gen))) as client:
        end = time.time() + 20
        while time.time() < end and not client.get("/api/incidents").json():
            time.sleep(0.1)
        inc = client.get("/api/incidents").json()
        assert inc and inc[0]["kind"] == "auth_suspicious_login"                       # detection survives the cutover
        assert inc[0]["user_id"] == Pseudonymizer.from_setting(KEY).user("legacy.raw.user")
        status = client.get("/api/ingest/status").json()["pseudonymization"]
        assert status["legacy_rows_at_cutover"] is False                               # step 5: verified clean start
        assert "historical_raw_data" not in {w["code"] for w in client.get("/api/security/status").json()["warnings"]}
    code2, report2 = _run_audit(tmp_path / "new.db")
    assert code2 == 0 and json.loads(report2)["findings"] == []                         # step 5: scanner finds nothing
    scan("new database", db_text_sqlite(tmp_path / "new.db"), extra=("legacy.raw.user", "192.0.2.77"))
    assert hashlib.sha256(old_db.read_bytes()).hexdigest() == old_hash                 # the old database was never touched


def test_c9_the_scanner_reports_a_configured_mode_database_clean(out):
    code, report = _run_audit(out.settings.db_path)
    data = json.loads(report)
    assert code == 0 and data["findings"] == [], data["findings"]
    assert data["tables"]["incidents"] > 0 and data["tables"]["alerts"] > 0           # positive control: there was data to inspect
    assert data["configured_mode_recorded"] is True


def test_c9_the_documentation_covers_the_required_operational_topics():
    text = (REPO / "docs" / "privacy-boundary.md").read_text().lower()
    for topic in ("historical data", "cutover", "key rotation", "backups", "exported", "legacy mode", "not anonymi",
                  "re-identif", "quasi-identifier", "privacy_audit_db.py", "pseudonym_key_rotation_ack",
                  "cannot be achieved", "not verified"):
        assert topic in text, f"docs/privacy-boundary.md does not cover {topic!r}"


def test_c9_legacy_mode_keeps_its_documented_raw_behaviour_and_says_so(tmp_path):
    s = Settings(_env_file=None, aws_mode="off", email_enabled=False, database_url="", log_dir=tmp_path / "logs", db_path=tmp_path / "l.db",
                 control_file=tmp_path / "c.json", static_dir=tmp_path / "ns", embedded_generator=False)
    s.log_dir.mkdir()
    for n in ("app.log", "audit.log", "auth.log"):
        (s.log_dir / n).write_text("")
    base = now() - timedelta(minutes=4)
    lines = [json.dumps({"ts": (base + timedelta(seconds=i)).isoformat(), "type": "auth", "user_id": "legacy.raw.user",
                         "outcome": "failure" if i < 5 else "success", "source_region": "RU", "user_region": "IN",
                         "source_ip": "192.0.2.77"}) for i in range(6)]
    with TestClient(create_app(settings=s, config=config_for(AUTH_SRC))) as client:
        with (s.log_dir / "auth.log").open("a") as f:
            f.write("\n".join(lines) + "\n")
        import time
        end = time.time() + 15
        while time.time() < end and not client.get("/api/incidents").json():
            time.sleep(0.1)
        inc = client.get("/api/incidents").json()
        assert inc and inc[0]["user_id"] == "legacy.raw.user"                         # documented legacy behaviour: raw id kept
        warnings = {w["code"]: w for w in client.get("/api/security/status").json()["warnings"]}
        assert "legacy_ingest" in warnings and "NOT suitable for real logs" in warnings["legacy_ingest"]["message"]


# =====================================================================================================
# C10 - end to end
# =====================================================================================================

def test_c10_end_to_end_every_output_path_was_exercised_and_is_clean(out):
    """One synthetic canary set, through ingestion, detection, persistence, API, WebSocket, logs and
    mocked notifications. Each path has a positive control; every planted canary is scanned for."""
    controls = {
        "ingestion": out.pipeline_counts["auth"] >= 8 and out.pipeline_counts["audit"] >= 260 and out.pipeline_counts["app"] >= 13,
        "quarantine": out.ingest_status["rejects"]["total"] >= 5,
        "detection": {"auth_suspicious_login", "error_rate"} <= {i["kind"] for i in out.incidents},
        "persistence": all(out.db_tables.get(t, 0) > 0 for t in ("incidents", "alerts", "evidence_events", "ingest_seen", "audit_log")),
        "api": len(out.api) > 55,
        "websocket": {"snapshot", "alert", "incident_update", "logs"} <= out.ws_types,
        "logs": len(out.logs.records) > 50,
        "email": len(out.emails) >= 2,
        "aws": out.aws_log.count("\n") >= 5,
        "state": out.state_nodes > 1000,
    }
    assert all(controls.values()), controls
    sinks = {
        "database rows": out.db_text, "database bytes": out.db_bytes.decode("latin-1"), "REST API": out.api_text,
        "WebSocket": json.dumps(out.ws_frames, default=str), "application logs": out.logs.text,
        "e-mail": "\n".join(out.emails), "AWS payloads": out.aws_log, "in-memory state": out.state_text,
    }
    for label, text in sinks.items():
        scan(label, text, check_key=(label != "in-memory state"))   # the pseudonymizer/deduper hold the key in memory
    # every individual canary, by name (so a failure names the value that leaked, not just a position)
    named = {"username/e-mail": CANARY_USER, "employee id": CANARY_USER2, "ip": CANARY_IP, "mrn": CANARY_PATIENT,
             "event id": CANARY_EVENT, "unmapped field": CANARY_UNMAPPED, "rejected user": CANARY_BAD_USER,
             "garbage line": CANARY_GARBAGE, "oversize line": CANARY_OVERSIZE, "unknown service": CANARY_UNKNOWN_SERVICE}
    for label, text in sinks.items():
        for what, value in named.items():
            assert value.lower() not in text.lower(), f"{what} ({value}) leaked into {label}"


def test_c10_known_limit_names_in_opted_in_free_text_are_not_removed(out):
    """Documented limitation, pinned so it cannot silently change: a person's NAME inside opted-in
    free text matches no pattern and is kept. (The source that opts in is a deliberate choice.)"""
    found = json.loads(out.api["/api/logs?q=canaryson"])["events"]
    assert found and all("canaryson" in e["msg"].lower() for e in found)                 # the name is kept and searchable
    assert CANARY_USER.lower() not in json.dumps(found).lower() and CANARY_IP not in json.dumps(found)   # but the rest was scrubbed
