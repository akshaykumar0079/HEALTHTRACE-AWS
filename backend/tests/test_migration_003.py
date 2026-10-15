"""Migration 003 (time machine / grouping / simulator): upgrade, idempotency,
data preservation and persistence, on SQLite and (when configured) PostgreSQL."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from app.models import Alert, Incident
from app.store import migrations
from app.store.database import PostgresDatabase, create_database
from app.store.db import Store
from app.store.migrations import LATEST_VERSION, applied_versions, migrate

PG_URL = os.environ.get("HEALTHTRACE_TEST_DATABASE_URL", "")
NOW = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG_URL, reason="needs HEALTHTRACE_TEST_DATABASE_URL"))]


async def _fresh_db(kind, tmp_path):
    if kind == "postgres":
        db = PostgresDatabase(PG_URL)
        await db.connect()
        await db.execute("DROP SCHEMA public CASCADE")
        await db.execute("CREATE SCHEMA public")
        await db.close()
        return create_database(tmp_path / "unused.db", PG_URL)
    return create_database(tmp_path / "m.db")


def _store(kind, tmp_path):
    return Store(tmp_path / "m.db", PG_URL if kind == "postgres" else None)


@pytest.mark.parametrize("kind", BACKENDS)
async def test_upgrade_from_version_2_keeps_data_and_backfills(kind, tmp_path, monkeypatch):
    db = await _fresh_db(kind, tmp_path)
    await db.connect()
    monkeypatch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS[:2])
    assert await migrate(db) == [1, 2]
    monkeypatch.undo()

    await db.execute(
        "INSERT INTO incidents (fingerprint, kind, service, state, peak_severity, alert_count, opened_at) "
        "VALUES ('error_rate:claims', 'error_rate', 'claims', 'OPEN', 'HIGH', 2, '2026-05-01T12:00:00+00:00')")
    for i in range(3):
        await db.execute("INSERT INTO evidence_events (incident_id, alert_id, ts, source, summary, record_json, digest, created_at) "
                         "VALUES (1, NULL, '2026-05-01T12:00:0%d+00:00', 'app', 's', '{}', 'f%d', '2026-05-01T12:00:00+00:00')" % (i, i))
    await db.commit()
    old_cols = await db.column_names("incidents")
    assert "risk_trend" not in old_cols and not await db.table_exists("simulation_runs")

    assert await migrate(db) == list(range(3, LATEST_VERSION + 1))
    cols = await db.column_names("incidents")
    assert {"latest_score", "risk_trend", "reopen_count", "evidence_count"} <= cols
    assert await db.table_exists("simulation_runs")
    await db.close()

    store = _store(kind, tmp_path)
    await store.connect()
    try:
        inc = await store.get_incident(1)
        assert inc.alert_count == 2 and inc.state == "OPEN"
        assert inc.evidence_count == 3                      # backfilled from the stored evidence
        assert inc.risk_trend == "unknown" and inc.reopen_count == 0 and inc.latest_score is None
    finally:
        await store.close()


@pytest.mark.parametrize("kind", BACKENDS)
async def test_migration_003_is_idempotent(kind, tmp_path):
    db = await _fresh_db(kind, tmp_path)
    await db.connect()
    try:
        assert await migrate(db) == list(range(1, LATEST_VERSION + 1))
        again = migrations.MIGRATIONS[2]
        assert again.version == 3
        await again.apply(db)                               # applying the body twice must not fail
        assert await migrate(db) == []
        assert sorted(await applied_versions(db)) == list(range(1, LATEST_VERSION + 1))
    finally:
        await db.close()


@pytest.mark.parametrize("kind", BACKENDS)
async def test_new_fields_and_simulation_runs_persist_across_reconnect(kind, tmp_path):
    await _fresh_db(kind, tmp_path)
    store = _store(kind, tmp_path)
    await store.connect()
    inc = Incident(id=1, fingerprint="error_rate:claims", kind="error_rate", service="claims", peak_severity="HIGH",
                   opened_at=NOW, latest_score=0.42, risk_trend="rising", reopen_count=2, evidence_count=9)
    await store.upsert_incident(inc)
    run_id = await store.save_simulation_run(created_at=NOW, scenario_id="error_spike", seed=7, passed=True,
                                             summary="PASS", result={"checks": [1, 2]}, requested_by="operator")
    await store.close()

    again = _store(kind, tmp_path)
    await again.connect()
    try:
        got = (await again.list_incidents())[0]
        assert (got.latest_score, got.risk_trend, got.reopen_count, got.evidence_count) == (0.42, "rising", 2, 9)
        run = await again.get_simulation_run(run_id)
        assert run["result"] == {"checks": [1, 2]} and run["seed"] == 7 and run["passed"] is True
        assert [r["id"] for r in await again.list_simulation_runs(scenario_id="error_spike")] == [run_id]
        assert await again.list_simulation_runs(scenario_id="other") == []
        assert await again.get_simulation_run(999) is None
    finally:
        await again.close()


@pytest.mark.parametrize("kind", BACKENDS)
async def test_timeline_queries_work_on_this_backend(kind, tmp_path):
    await _fresh_db(kind, tmp_path)
    store = _store(kind, tmp_path)
    await store.connect()
    try:
        await store.upsert_incident(Incident(id=1, fingerprint="f", kind="error_rate", service="claims",
                                             peak_severity="HIGH", opened_at=NOW))
        await store.save_alert(Alert(ts=NOW, kind="error_rate", service="claims", severity="HIGH", score=0.5,
                                     explanation="x", incident_id=1))
        found = await store.list_alerts_between(start=NOW - timedelta(minutes=1), end=NOW + timedelta(minutes=1),
                                                service="claims")
        assert len(found) == 1
        assert await store.earliest_metric_ts("claims") is None
    finally:
        await store.close()
