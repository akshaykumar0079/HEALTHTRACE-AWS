"""Database layer: migrations and Store behaviour on SQLite, and on PostgreSQL
when HEALTHTRACE_TEST_DATABASE_URL points at a disposable database.

    HEALTHTRACE_TEST_DATABASE_URL=postgresql://user@127.0.0.1:5432/healthtrace_test pytest tests/test_database.py

The PostgreSQL cases DROP the public schema of that database, so never point
it at real data. Without the variable they are skipped, not faked.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.models import Alert, Incident, IncidentEvent
from app.store.database import (
    PostgresDatabase, create_database, is_postgres_url, normalize_database_url, redact_database_url,
)
from app.store.db import BaselineRow, Store
from app.store.migrations import LATEST_VERSION, applied_versions, migrate

PG_URL = os.environ.get("HEALTHTRACE_TEST_DATABASE_URL", "")
NOW = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


def _backends():
    params = ["sqlite"]
    params.append(pytest.param("postgres", marks=pytest.mark.skipif(
        not PG_URL, reason="set HEALTHTRACE_TEST_DATABASE_URL to run the PostgreSQL cases")))
    return params


async def _reset_postgres() -> None:
    db = PostgresDatabase(PG_URL)
    await db.connect()
    await db.execute("DROP SCHEMA public CASCADE")
    await db.execute("CREATE SCHEMA public")
    await db.close()


@pytest.fixture(params=_backends())
async def store(request, tmp_path):
    if request.param == "postgres":
        await _reset_postgres()
        s = Store(tmp_path / "unused.db", PG_URL)
    else:
        s = Store(tmp_path / "t.db")
    await s.connect()
    yield s
    await s.close()


def _incident(i: int = 1, **kw) -> Incident:
    base = dict(id=i, fingerprint=f"error_rate:claims{i}", kind="error_rate", service="claims", state="OPEN",
                peak_severity="HIGH", alert_count=1, opened_at=NOW, last_seen_at=NOW, peak_score=0.62)
    base.update(kw)
    return Incident(**base)


def _alert(**kw) -> Alert:
    base = dict(ts=NOW, kind="error_rate", service="claims", severity="HIGH", score=0.6, explanation="x",
                metrics={"a": 1}, incident_id=1)
    base.update(kw)
    return Alert(**base)


# -- url helpers -------------------------------------------------------------------------


def test_url_helpers():
    assert normalize_database_url("postgres://u:p@h/db") == "postgresql://u:p@h/db"
    assert normalize_database_url("postgresql+psycopg://u:p@h/db") == "postgresql://u:p@h/db"
    assert is_postgres_url("postgres://x") and not is_postgres_url("") and not is_postgres_url("sqlite:///a.db")
    assert redact_database_url("postgresql://user:s3cret@host/db") == "postgresql://user:***@host/db"
    assert "s3cret" not in redact_database_url("postgres://user:s3cret@host:5432/db?sslmode=require")


def test_create_database_rejects_unknown_scheme(tmp_path):
    with pytest.raises(ValueError):
        create_database(tmp_path / "x.db", "mysql://u:p@h/db")


# -- migrations ---------------------------------------------------------------------------


async def test_migrations_apply_once_and_are_idempotent(store):
    versions = await applied_versions(store.conn)
    assert sorted(versions) == list(range(1, LATEST_VERSION + 1))
    assert await migrate(store.conn) == []  # second run is a no-op
    for table in ("incidents", "alerts", "evidence_events", "audit_log", "notification_settings",
                  "notification_attempts", "schema_migrations"):
        assert await store.conn.table_exists(table), table
    cols = await store.conn.column_names("incidents")
    assert {"pinned", "pinned_at", "investigating_at", "last_seen_at", "peak_score", "muted_until"} <= cols


async def test_migration_preserves_existing_sqlite_data(tmp_path):
    """A database written by the previous build (no pinned/peak_score columns,
    no migrations table) keeps every row when the new code opens it."""
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.executescript(
        """
        CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, kind TEXT NOT NULL,
            service TEXT, user_id TEXT, state TEXT NOT NULL, peak_severity TEXT NOT NULL,
            alert_count INTEGER NOT NULL DEFAULT 1, opened_at TEXT NOT NULL, acknowledged_at TEXT,
            resolved_at TEXT, mttr_seconds REAL);
        CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, kind TEXT NOT NULL, service TEXT,
            user_id TEXT, severity TEXT NOT NULL, score REAL NOT NULL, explanation TEXT NOT NULL,
            metrics_json TEXT NOT NULL DEFAULT '{}', incident_id INTEGER);
        CREATE TABLE metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL, window_end TEXT NOT NULL,
            total INTEGER NOT NULL, errors INTEGER NOT NULL, error_rate REAL NOT NULL, p95_latency_ms REAL NOT NULL,
            urgent_errors INTEGER NOT NULL, affected_patients_urgent INTEGER NOT NULL,
            affected_patients_routine INTEGER NOT NULL, malformed_lines INTEGER NOT NULL DEFAULT 0);
        INSERT INTO incidents (fingerprint, kind, service, state, peak_severity, alert_count, opened_at)
            VALUES ('error_rate:claims', 'error_rate', 'claims', 'ACKNOWLEDGED', 'CRITICAL', 7, '2026-05-01T12:00:00+00:00');
        INSERT INTO alerts (ts, kind, service, severity, score, explanation, incident_id)
            VALUES ('2026-05-01T12:00:00+00:00', 'error_rate', 'claims', 'CRITICAL', 0.9, 'old alert', 1);
        INSERT INTO metrics (service, window_end, total, errors, error_rate, p95_latency_ms, urgent_errors,
            affected_patients_urgent, affected_patients_routine)
            VALUES ('claims', '2026-05-01T12:00:00+00:00', 10, 5, 0.5, 100, 1, 1, 1);
        """
    )
    raw.commit()
    raw.close()

    s = Store(path)
    await s.connect()
    try:
        inc = await s.get_incident(1)
        assert inc is not None and inc.state == "ACKNOWLEDGED" and inc.alert_count == 7
        assert inc.pinned is False and inc.peak_score is None
        assert [a.explanation for a in await s.list_alerts()] == ["old alert"]
        assert len(await s.list_metrics(service="claims", minutes=10, before=NOW + timedelta(minutes=1))) == 1
        cols = await s.conn.column_names("metrics")
        assert {"baseline_mean", "baseline_std"} <= cols
    finally:
        await s.close()


# -- store round trips ---------------------------------------------------------------------


async def test_incident_roundtrip_with_workflow_fields(store):
    inc = _incident(pinned=True, pinned_at=NOW, investigating_at=NOW, muted_until=NOW + timedelta(minutes=5),
                    state="INVESTIGATING")
    await store.upsert_incident(inc)
    got = await store.get_incident(1)
    assert got is not None
    assert got.pinned is True and got.state == "INVESTIGATING" and got.peak_score == pytest.approx(0.62)
    assert got.pinned_at == NOW and got.muted_until == NOW + timedelta(minutes=5)
    inc.pinned, inc.pinned_at = False, None
    await store.upsert_incident(inc)
    assert (await store.get_incident(1)).pinned is False
    assert await store.max_incident_id() == 1


async def test_inserts_return_ids(store):
    a1 = await store.save_alert(_alert())
    a2 = await store.save_alert(_alert())
    assert a2 == a1 + 1
    e = await store.save_incident_event(IncidentEvent(incident_id=1, ts=NOW, event_type="pinned"))
    assert isinstance(e, int) and e >= 1
    assert (await store.list_incident_events(1))[0].event_type == "pinned"


async def test_query_incidents_filters_and_is_injection_safe(store):
    await store.upsert_incident(_incident(1, peak_severity="CRITICAL", state="OPEN", pinned=True))
    await store.upsert_incident(_incident(2, peak_severity="LOW", state="RESOLVED", service="pharmacy",
                                          fingerprint="latency_degradation:pharmacy", kind="latency_degradation"))
    await store.upsert_incident(_incident(3, kind="hipaa_bulk_access", service=None, user_id="u-77",
                                          fingerprint="hipaa_bulk_access:u-77"))
    assert [i.id for i in await store.query_incidents(states=["RESOLVED"])] == [2]
    assert [i.id for i in await store.query_incidents(pinned=True)] == [1]
    assert {i.id for i in await store.query_incidents(severities=["HIGH", "CRITICAL"])} == {1, 3}
    assert [i.id for i in await store.query_incidents(text="U-77")] == [3]            # case-insensitive
    assert [i.id for i in await store.query_incidents(text="pharm")] == [2]
    assert [i.id for i in await store.query_incidents(text="x", text_kinds=["hipaa_bulk_access"])] == [3]
    assert await store.query_incidents(text="'; DROP TABLE incidents; --") == []
    assert await store.query_incidents(text="100%") == []                              # % is literal, not a wildcard
    assert await store.query_incidents(text="c_a") == []                               # _ is literal: no "cla" match
    assert len(await store.list_incidents()) == 3                                      # table intact


async def test_evidence_is_deduplicated_and_capped(store):
    await store.upsert_incident(_incident(1))
    recs = [{"seq": n, "ts": f"2026-05-01T12:00:{n:02d}+00:00", "type": "app", "service": "claims",
             "level": "ERROR", "msg": f"boom {n}"} for n in range(10)]
    assert await store.save_evidence(1, None, recs) == 10
    await store.save_evidence(1, None, recs)                                           # same records again
    assert await store.count_evidence(1) == 10
    # seq differs between runs but the content is the same: still one row
    again = [{**recs[0], "seq": 999}]
    await store.save_evidence(1, None, again)
    assert await store.count_evidence(1) == 10
    many = [{"ts": f"2026-05-01T13:{n // 60:02d}:{n % 60:02d}+00:00", "type": "app", "msg": f"m{n}"} for n in range(300)]
    await store.save_evidence(1, None, many, max_per_incident=50)
    assert await store.count_evidence(1) == 50
    ev = await store.list_evidence(1, limit=5)
    assert len(ev) == 5 and "record" in ev[0]


async def test_audit_log_roundtrip(store):
    await store.add_audit(actor="operator", action="pin", target_type="incident", target_id="4", detail="d")
    await store.add_audit(actor="operator", action="resolve", target_type="incident", target_id="5")
    rows = await store.list_audit(target_type="incident", target_id="4")
    assert len(rows) == 1 and rows[0]["action"] == "pin" and rows[0]["outcome"] == "ok"
    assert len(await store.list_audit()) == 2


async def test_notification_settings_persist_and_validate(store):
    assert await store.get_notification_settings() is None
    await store.save_notification_settings(enabled=True, recipients=["a@example.com", "b@example.com"],
                                           min_severity="CRITICAL", cooldown_seconds=120, updated_by="operator")
    got = await store.get_notification_settings()
    assert got == {**got, "enabled": True, "recipients": ["a@example.com", "b@example.com"],
                   "min_severity": "CRITICAL", "cooldown_seconds": 120}
    await store.save_notification_settings(enabled=False, recipients=["a@example.com"], min_severity="HIGH",
                                           cooldown_seconds=0, updated_by="operator")
    assert (await store.get_notification_settings())["enabled"] is False
    with pytest.raises(Exception):                                                     # DB-level CHECK constraint
        await store.save_notification_settings(enabled=True, recipients=["a@example.com"], min_severity="BOGUS",
                                               cooldown_seconds=1, updated_by="x")
    with pytest.raises(Exception):
        await store.save_notification_settings(enabled=True, recipients=["a@example.com"], min_severity="HIGH",
                                               cooldown_seconds=-5, updated_by="x")


async def test_notification_attempts_never_hold_a_key(store):
    await store.add_notification_attempt(channel="email", kind="test", provider="brevo", status="accepted",
                                         provider_message_id="<abc@brevo>", detail="accepted")
    rows = await store.list_notification_attempts()
    assert rows[0]["status"] == "accepted" and rows[0]["provider_message_id"] == "<abc@brevo>"
    with pytest.raises(Exception):
        await store.add_notification_attempt(channel="email", kind="test", provider="brevo", status="delivered")


async def test_existing_store_features_still_work(store):
    await store.save_baselines([BaselineRow("claims", 3, "error_rate", 0.01, 0.0001, 10)])
    assert (await store.load_baselines())[0].mean == pytest.approx(0.01)
    await store.save_tail_position("/tmp/app.log", 12345, 4_000_000_000)             # > 2^31: needs BIGINT on Postgres
    assert (await store.load_tail_positions())["/tmp/app.log"] == (12345, 4_000_000_000)
    await store.save_alert(_alert())
    assert (await store.alert_counts(since=NOW - timedelta(hours=1)))[0][1:] == ("HIGH", "claims", 1)
    assert (await store.alert_kind_counts(since=NOW - timedelta(hours=1))) == [("error_rate", 1)]
    await store.save_access_stat("u1", "reads", 1.0, 2.0, 3)
    assert (await store.load_access_stats())[0][0] == "u1"


async def test_data_survives_reconnect(tmp_path):
    if PG_URL:
        await _reset_postgres()
        make = lambda: Store(tmp_path / "x.db", PG_URL)  # noqa: E731
    else:
        make = lambda: Store(tmp_path / "x.db")  # noqa: E731
    s = make()
    await s.connect()
    await s.upsert_incident(_incident(1, pinned=True, pinned_at=NOW))
    await s.add_audit(actor="a", action="pin", target_type="incident", target_id="1")
    await s.close()
    s2 = make()
    await s2.connect()                                                                 # migrations run again: no-op
    try:
        assert (await s2.get_incident(1)).pinned is True
        assert len(await s2.list_audit()) == 1
    finally:
        await s2.close()


@pytest.mark.skipif(not PG_URL, reason="needs HEALTHTRACE_TEST_DATABASE_URL")
async def test_postgres_reconnects_after_connection_loss(tmp_path):
    await _reset_postgres()
    s = Store(tmp_path / "x.db", PG_URL)
    await s.connect()
    try:
        await s.upsert_incident(_incident(1))
        await s.conn._conn.close()                                                     # simulate an idle-killed connection
        assert (await s.get_incident(1)) is not None                                   # transparently reconnects
    finally:
        await s.close()
