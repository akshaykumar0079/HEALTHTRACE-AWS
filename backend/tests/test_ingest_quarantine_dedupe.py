"""Stage C regression tests: reason codes, metadata-only quarantine, event-id
de-duplication (opt-in content mode), restart durability, migration m004.
Runs on SQLite and, when HEALTHTRACE_TEST_DATABASE_URL is set, PostgreSQL."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path

import pytest

from app.config import load_config
from app.ingest import reasons
from app.ingest.dedupe import Deduper
from app.ingest.quarantine import Quarantine
from app.pipeline import Pipeline
from app.simulation.runner import _isolated_settings
from app.store import migrations
from app.store.database import PostgresDatabase, create_database
from app.store.db import Store
from app.store.migrations import LATEST_VERSION, applied_versions, migrate

PG_URL = os.environ.get("HEALTHTRACE_TEST_DATABASE_URL", "")
BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG_URL, reason="needs HEALTHTRACE_TEST_DATABASE_URL"))]
CANARY = "CANARY-SSN-123-45-6789"


async def _store(kind, tmp_path) -> Store:
    if kind == "postgres":
        db = PostgresDatabase(PG_URL)
        await db.connect()
        await db.execute("DROP SCHEMA public CASCADE")
        await db.execute("CREATE SCHEMA public")
        await db.close()
        store = Store(tmp_path / "unused.db", PG_URL)
    else:
        store = Store(tmp_path / "s.db")
    await store.connect()
    return store


# -- reason codes -------------------------------------------------------------------------

def test_reason_codes_are_stable_strings():
    assert reasons.LINE_TOO_LONG == "line_too_long" and reasons.TS_NO_TZ == "ts_no_tz"
    assert reasons.UNKNOWN_SERVICE == "unknown_service" and reasons.DUPLICATE == "duplicate"
    assert all(c == c.lower() and " " not in c for c in reasons.ALL_CODES)


# -- migration m004 -----------------------------------------------------------------------

@pytest.mark.parametrize("kind", BACKENDS)
async def test_m004_is_additive_idempotent_and_recorded(kind, tmp_path, monkeypatch):
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
    monkeypatch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS[:3])
    assert await migrate(db) == [1, 2, 3]
    monkeypatch.undo()
    await db.execute("INSERT INTO audit_log (ts, actor, action, target_type, outcome) VALUES ('2026-01-01T00:00:00+00:00','a','x','t','ok')")
    await db.commit()
    for t in ("ingest_reject_counts", "ingest_rejects", "ingest_seen"):
        assert not await db.table_exists(t)
    assert await migrate(db) == list(range(4, LATEST_VERSION + 1))
    for t in ("ingest_reject_counts", "ingest_rejects", "ingest_seen"):
        assert await db.table_exists(t)
    assert await migrate(db) == []                                       # idempotent
    assert sorted(await applied_versions(db)) == list(range(1, LATEST_VERSION + 1))
    n = await (await db.execute("SELECT COUNT(*) FROM audit_log")).fetchone()
    assert n[0] == 1                                                     # existing data untouched
    await db.close()


# -- quarantine ---------------------------------------------------------------------------

def test_quarantine_counts_and_coerces_unknown_codes():
    q = Quarantine()
    q.record("app.log", reasons.LINE_TOO_LONG, 10, 99)
    q.record("app.log", reasons.LINE_TOO_LONG, 200, 99)
    q.record("auth.log", reasons.TS_NO_TZ)
    q.record("auth.log", "made-up-code")
    assert q.by_reason() == {"line_too_long": 2, "ts_no_tz": 1, "schema_invalid": 1}
    assert q.total("app.log") == 2 and q.total() == 4
    assert set(q.recent[0]) == {"ts", "source", "reason", "offset", "length"}   # metadata only


@pytest.mark.parametrize("kind", BACKENDS)
async def test_quarantine_persists_counts_and_bounded_sample(kind, tmp_path):
    store = await _store(kind, tmp_path)
    q = Quarantine()
    for i in range(30):
        q.record("a.log", reasons.INVALID_JSON, i, 5)
    await q.flush(store)
    q.record("a.log", reasons.INVALID_JSON, 99, 5)
    await q.flush(store)
    q2 = Quarantine()
    await q2.load(store)
    assert q2.by_reason() == {"invalid_json": 31}                          # counters accumulate across flushes
    await store.save_ingest_rejects({}, {}, [{"ts": "2026-01-01T00:00:00+00:00", "source": "a.log", "reason": "x",
                                             "offset": i, "length": 1} for i in range(10)], keep_rows=5)
    rows = await store.list_ingest_rejects(limit=1000)
    assert len(rows) <= 6                                                  # trimmed to the newest rows
    assert all(set(r) == {"ts", "source", "reason", "offset", "length"} for r in rows)
    await store.close()


# -- de-duplication -----------------------------------------------------------------------

def test_event_id_mode_is_the_default_and_never_uses_content():
    d = Deduper()
    assert d.mode == "event_id"
    assert d.is_duplicate("s", "evt-1", "line A") is False
    assert d.is_duplicate("s", "evt-1", "line B") is True                  # same id, different content: duplicate
    assert d.is_duplicate("s", "evt-2", "line A") is False                 # same content, different id: kept
    assert d.is_duplicate("other", "evt-1") is False                        # ids are per source
    assert d.duplicates["s"] == 1


def test_events_without_an_id_are_never_dropped_in_default_mode():
    d = Deduper()
    for _ in range(5):
        assert d.is_duplicate("s", None, "identical raw line") is False
        assert d.is_duplicate("s", "  ", "identical raw line") is False
    assert d.no_event_id["s"] == 10 and d.duplicates["s"] == 0


def test_content_mode_is_opt_in_and_off_disables():
    c = Deduper("content")
    assert c.is_duplicate("s", None, "same") is False and c.is_duplicate("s", None, "same") is True
    assert c.is_duplicate("s", "evt-1", "different") is False               # ids ignored in content mode
    assert Deduper("off").is_duplicate("s", "evt-1", "x") is False and Deduper("off").is_duplicate("s", "evt-1", "x") is False
    with pytest.raises(ValueError):
        Deduper("hash-everything")


def test_content_mode_with_key_stores_no_plain_digest():
    a, b = Deduper("content", key=b"k1"), Deduper("content", key=b"k2")
    a.is_duplicate("s", None, "line"); b.is_duplicate("s", None, "line")
    assert a._pending[0][1] != b._pending[0][1]                              # keyed: not a bare SHA-256 of the line


def test_lru_is_bounded():
    d = Deduper(capacity=3)
    for i in range(10):
        d.is_duplicate("s", f"e{i}")
    assert d.stats()["tracked"]["s"] == 3
    assert d.is_duplicate("s", "e9") is True and d.is_duplicate("s", "e0") is False   # oldest forgotten


@pytest.mark.parametrize("kind", BACKENDS)
async def test_dedupe_window_survives_a_restart(kind, tmp_path):
    store = await _store(kind, tmp_path)
    d1 = Deduper()
    for i in range(20):
        d1.is_duplicate("app.log", f"evt-{i}")
    await d1.flush(store)
    await d1.flush(store)                                                    # nothing new: no-op
    d2 = Deduper()                                                            # "restart"
    await d2.load(store)
    assert all(d2.is_duplicate("app.log", f"evt-{i}") for i in range(20))     # retransmission after restart is recognized
    assert d2.is_duplicate("app.log", "evt-new") is False
    await store.save_ingest_seen([("app.log", f"x{i}") for i in range(30)], keep_per_source=10)
    kept = await store.load_ingest_seen()
    assert len(kept["app.log"]) <= 11                                         # persisted window is bounded
    await store.close()


@pytest.mark.parametrize("kind", BACKENDS)
async def test_documented_crash_window_ids_after_last_checkpoint_are_reprocessed(kind, tmp_path):
    """docs/ingestion.md: a crash (no clean flush) forgets ids first seen since the last checkpoint.
    This pins the limitation so a change in either direction is noticed."""
    store = await _store(kind, tmp_path)
    d1 = Deduper()
    for i in range(5):
        d1.is_duplicate("s", f"before-{i}")
    await d1.flush(store)                                   # checkpoint
    for i in range(5):
        d1.is_duplicate("s", f"after-{i}")                  # never flushed: process "crashes" here
    d2 = Deduper()
    await d2.load(store)
    assert all(d2.is_duplicate("s", f"before-{i}") for i in range(5))
    assert not any(d2.is_duplicate("s", f"after-{i}") for i in range(5))   # replayed after the crash
    await store.close()


# -- pipeline integration -----------------------------------------------------------------

def _auth(ts, user="U-9", outcome="failure", reg="RU"):
    return json.dumps({"ts": ts, "type": "auth", "user_id": user, "outcome": outcome,
                       "source_region": reg, "user_region": "IN", "source_ip": "192.0.2.5"})


async def _pipeline(**settings_kw):
    work = Path(tempfile.mkdtemp())
    (work / "logs").mkdir()
    s = _isolated_settings(work)
    for k, v in settings_kw.items():
        setattr(s, k, v)
    p = Pipeline(s, load_config())
    await p.store.connect()
    await p.baseline.load(p.store)
    return p


async def test_duplicate_batch_does_not_inflate_severity_in_opt_in_content_mode():
    """Audit: the same 5 failures + 1 success delivered twice turned HIGH into CRITICAL."""
    fails = [_auth(f"2026-03-10T16:0{i}:00Z") for i in range(5)]
    ok = _auth("2026-03-10T16:06:00Z", outcome="success")

    once = await _pipeline(ingest_dedupe="content")
    for line in fails + [ok]:
        await once._process_line(line)
    twice = await _pipeline(ingest_dedupe="content")
    for line in fails + fails + [ok]:
        await twice._process_line(line)
    sev = lambda p: [(i.kind, i.peak_severity) for i in p.incidents.list_incidents()]
    assert sev(once) == sev(twice) == [("auth_suspicious_login", "HIGH")]
    assert twice.deduper.stats()["duplicates_dropped"] == {"legacy": 5}
    await once.store.close(); await twice.store.close()


async def test_legacy_default_cannot_dedupe_and_says_so():
    """Legacy synthetic events carry no event id, so the default mode does not drop them.
    This is the documented reason legacy mode is unsuitable for real logs."""
    fails = [_auth(f"2026-03-10T16:0{i}:00Z") for i in range(5)]
    ok = _auth("2026-03-10T16:06:00Z", outcome="success")
    p = await _pipeline()
    assert p.deduper.mode == "event_id"
    for line in fails + fails + [ok]:
        await p._process_line(line)
    assert [(i.peak_severity) for i in p.incidents.list_incidents()] == ["CRITICAL"]   # known legacy limitation
    await p.store.close()


async def test_rejections_are_quarantined_without_content_or_logs(caplog, tmp_path):
    caplog.set_level(logging.DEBUG)
    p = await _pipeline()
    await p._process_line(f'{{"type":"auth","note":"{CANARY}"')                    # invalid JSON containing the canary
    await p._process_line(json.dumps({"type": "auth", "user_id": CANARY}))        # missing fields
    await p._process_line(json.dumps({"type": "nope", "x": CANARY}))
    await p._process_line(_auth("2026-03-10T16:00:00Z", user=CANARY, outcome="denied"))
    assert p.quarantine.by_reason() == {"invalid_json": 1, "missing_field": 1, "unknown_type": 1, "bad_value": 1}
    await p._save_state()
    rows = await p.store.list_ingest_rejects()
    dump = json.dumps(rows) + json.dumps(p.quarantine.summary()) + json.dumps(p.health_snapshot())
    assert CANARY not in dump and CANARY not in caplog.text
    for table in ("ingest_reject_counts", "ingest_rejects", "ingest_seen"):
        cur = await p.store.conn.execute(f"SELECT * FROM {table}")
        assert CANARY not in json.dumps([list(r) for r in await cur.fetchall()])
    await p.store.close()


async def test_oversize_and_malformed_lines_reach_quarantine_through_the_tailers(tmp_path):
    work = tmp_path
    logs = work / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("x" * 5000 + "\n" + "not json\n")
    (logs / "audit.log").write_text("")
    (logs / "auth.log").write_text(_auth("2026-03-10T16:00:00Z") + "\n")
    s = _isolated_settings(work)
    s.ingest_max_line_bytes = 1000
    p = Pipeline(s, load_config())
    await p.start()
    try:
        for _ in range(200):
            await asyncio.sleep(0.02)
            if all(t.caught_up for t in p._tailers) and p.queue._unfinished_tasks == 0:
                break
    finally:
        await p.stop()
    store = Store(s.db_path)
    await store.connect()
    counts = {(a, b): c for a, b, c in await store.load_ingest_reject_counts()}
    assert counts[("app.log", "line_too_long")] == 1 and counts[("app.log", "invalid_json")] == 1
    assert p.events_processed["auth"] == 1
    await store.close()
