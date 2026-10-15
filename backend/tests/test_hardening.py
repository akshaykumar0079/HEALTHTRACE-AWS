"""Regression tests for defects found by running the real backend against
real generator output (see README "Backend hardening")."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.ws import CLIENT_QUEUE_SIZE, Broadcaster, _Client
from app.config import Settings, load_config
from app.demo import SCENARIO_NAMES
from app.ingest.tailer import Tailer
from app.main import create_app
from app.models import Alert, Anomaly
from app.pipeline import Pipeline, mask_patient_id
from app.store.db import Store
from generator.scenarios import ALL_SCENARIO_NAMES

T0 = datetime(2026, 9, 28, 14, 0, 0, tzinfo=timezone.utc)


def _settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(
        aws_mode="off", demo_mode=True, log_dir=tmp_path / "logs", db_path=tmp_path / "medguard.db",
        control_file=tmp_path / "control.json", static_dir=tmp_path / "no-frontend",
    )
    base.update(overrides)
    return Settings(**base)


def _init_logs(settings: Settings, app_lines: list[str] = (), audit_lines: list[str] = ()) -> None:
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    (settings.log_dir / "app.log").write_text("".join(line + "\n" for line in app_lines), encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("".join(line + "\n" for line in audit_lines), encoding="utf-8")


def _app_line(ts: datetime, *, service: str = "claims", level: str = "INFO", status: int = 200) -> str:
    return json.dumps({
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "type": "app", "service": service, "level": level,
        "priority": "routine", "request_id": "X-1", "patient_id": "P-000123", "status": status,
        "latency_ms": 100, "msg": "Claims database timeout" if level == "ERROR" else "ok",
    })


def _audit_line(ts: datetime, *, user: str = "U-001", patient: int = 1, region: str = "TN-North") -> str:
    return json.dumps({
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "type": "audit", "user_id": user,
        "role": "care_manager", "action": "VIEW_RECORD", "patient_id": f"P-{patient:06d}",
        "patient_region": region, "user_region": "TN-North",
    })


async def _wait_idle(pipeline: Pipeline, timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if all(t.caught_up for t in pipeline._tailers) and pipeline.queue._unfinished_tasks == 0:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("pipeline did not become idle")


# -- tailer -------------------------------------------------------------------


async def test_tailer_streams_large_files_in_bounded_chunks(tmp_path: Path):
    path = tmp_path / "big.log"
    lines = [f"line-{i}-é" for i in range(2000)]  # multi-byte chars straddle chunk boundaries
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    queue: asyncio.Queue[str] = asyncio.Queue()
    tailer = Tailer(path, queue, from_start=True, max_chunk_bytes=97)

    await tailer.poll_once()
    assert not tailer.caught_up
    assert queue.qsize() < 20  # one poll reads one chunk, not the whole file
    while not tailer.caught_up:
        await tailer.poll_once()
    got = [queue.get_nowait() for _ in range(queue.qsize())]
    assert got == lines


async def test_tailer_resumes_from_a_saved_position(tmp_path: Path):
    path = tmp_path / "app.log"
    path.write_text("one\ntwo\n", encoding="utf-8")
    first: asyncio.Queue[str] = asyncio.Queue()
    t1 = Tailer(path, first, from_start=True)
    await t1.poll_once()
    offset, file_id = t1.committed_offset, t1.file_id

    with path.open("a", encoding="utf-8") as f:
        f.write("three\n")
    second: asyncio.Queue[str] = asyncio.Queue()
    t2 = Tailer(path, second, resume_offset=offset, resume_file_id=file_id)
    await t2.poll_once()
    assert [second.get_nowait() for _ in range(second.qsize())] == ["three"]


async def test_tailer_reads_a_rotated_file_whole_on_resume(tmp_path: Path):
    path = tmp_path / "app.log"
    path.write_text("fresh-1\nfresh-2\n", encoding="utf-8")
    queue: asyncio.Queue[str] = asyncio.Queue()
    tailer = Tailer(path, queue, resume_offset=5, resume_file_id=-12345)  # a different file than the one saved
    await tailer.poll_once()
    assert [queue.get_nowait() for _ in range(queue.qsize())] == ["fresh-1", "fresh-2"]


# -- restart safety -------------------------------------------------------------


async def test_restart_resumes_exactly_where_it_left_off(tmp_path: Path):
    settings = _settings(tmp_path)
    _init_logs(settings, [_app_line(T0 + timedelta(seconds=i)) for i in range(20)])

    first = Pipeline(settings, load_config())
    await first.start()
    await _wait_idle(first)
    assert first.events_processed["app"] == 20
    await first.stop()

    with (settings.log_dir / "app.log").open("a", encoding="utf-8") as f:
        for i in range(20, 25):
            f.write(_app_line(T0 + timedelta(seconds=i)) + "\n")

    second = Pipeline(settings, load_config())
    await second.start()
    await _wait_idle(second)
    try:
        assert second.events_processed["app"] == 5  # nothing re-read, nothing skipped
    finally:
        await second.stop()


async def test_interrupted_first_run_does_not_skip_history(tmp_path: Path):
    """Regression: a first start that saved even one baseline row made every
    later start tail from the end, silently skipping the whole backfill."""
    settings = _settings(tmp_path)
    history = [_app_line(T0 + timedelta(seconds=i)) for i in range(400)]
    _init_logs(settings, history)

    first = Pipeline(settings, load_config())
    await first.start()
    # Nothing has awaited since start(), so the background tasks have not run yet. Stop them and
    # read exactly two ~10-line chunks by hand: the interruption point is then deterministic
    # instead of depending on how the event loop interleaves the tailer with database I/O
    # (the original free-running version failed ~3-7% of runs, also on the unmodified baseline).
    for tailer in first._tailers:
        tailer.max_chunk_bytes = len(history[0]) * 10
        tailer.stop()
    for task in first._tasks:
        task.cancel()
    await asyncio.gather(*first._tasks, return_exceptions=True)
    for tailer in first._tailers:
        for _ in range(2):
            try:
                await tailer.poll_once()
            except FileNotFoundError:  # a log this test never creates (run() would also tolerate it)
                break
    # A periodic save lands (enough windows to have learned baselines), then the process dies.
    await first.queue.join()
    await first._save_state()
    seen_first = first.events_processed["app"]
    first._consumer_task.cancel()
    await first.store.close()
    assert 12 <= seen_first < 400
    assert not first.baseline.is_empty()

    second = Pipeline(settings, load_config())
    await second.start()
    await _wait_idle(second)
    try:
        assert seen_first + second.events_processed["app"] == 400
    finally:
        await second.stop()


async def test_incident_ids_continue_after_restart(tmp_path: Path):
    """Regression: ids restarted at 1, so new incidents overwrote persisted ones."""
    settings = _settings(tmp_path)
    _init_logs(settings)
    anomaly = Anomaly(kind="error_rate", ts=T0, service="claims", z=5.0)
    alert = Alert(ts=T0, kind="error_rate", service="claims", severity="HIGH", score=0.6, explanation="first")

    first = Pipeline(settings, load_config())
    await first.start()
    await first._handle_alert(anomaly, alert)
    first_id = first.incidents.list_incidents()[0].id
    await first.stop()

    second = Pipeline(settings, load_config())
    await second.start()
    try:
        other = Anomaly(kind="error_rate", ts=T0, service="pharmacy", z=5.0)
        other_alert = Alert(ts=T0, kind="error_rate", service="pharmacy", severity="LOW", score=0.1, explanation="2")
        await second._handle_alert(other, other_alert)
        stored = await second.store.list_incidents()
        assert {i.service for i in stored} == {"claims", "pharmacy"}
        assert len({i.id for i in stored}) == 2
        assert first_id in {i.id for i in stored}
        # The still-open claims incident is live again: a new alert attaches to it.
        update = second.incidents.record_alert(anomaly, alert)
        assert update.incident.id == first_id and not update.is_new
    finally:
        await second.stop()


# -- HIPAA alert volume -----------------------------------------------------


async def test_unchanged_hipaa_pattern_is_throttled_but_escalation_is_not(tmp_path: Path):
    settings = _settings(tmp_path)
    _init_logs(settings)
    pipeline = Pipeline(settings, load_config())
    await pipeline.store.connect()
    try:
        # Same user touching out-of-region patients on consecutive seconds.
        for i in range(5):
            await pipeline._process_line(_audit_line(T0 + timedelta(seconds=i), user="U-088", patient=i,
                                                     region="TN-South"))
        mismatch = [a for a in pipeline.recent_alerts if a.kind == "hipaa_region_mismatch"]
        assert len(mismatch) == 1  # not one per event

        # Crossing into HIGH (> 5 patients) alerts immediately despite the throttle.
        for i in range(5, 7):
            await pipeline._process_line(_audit_line(T0 + timedelta(seconds=i), user="U-088", patient=i,
                                                     region="TN-South"))
        mismatch = [a for a in pipeline.recent_alerts if a.kind == "hipaa_region_mismatch"]
        assert [a.severity for a in mismatch] == ["MEDIUM", "HIGH"]
    finally:
        await pipeline.store.close()


async def test_stale_replayed_alerts_are_not_sent_to_aws(tmp_path: Path):
    settings = _settings(tmp_path, aws_mode="mock")
    _init_logs(settings)
    pipeline = Pipeline(settings, load_config())
    await pipeline.store.connect()
    try:
        old = datetime.now(timezone.utc) - timedelta(hours=3)
        anomaly = Anomaly(kind="error_rate", ts=old, service="claims", z=9.0)
        alert = Alert(ts=old, kind="error_rate", service="claims", severity="CRITICAL", score=0.9, explanation="x")
        await pipeline._handle_alert(anomaly, alert)
        assert pipeline.notifier.queue_depth == 0

        fresh = datetime.now(timezone.utc)
        anomaly2 = Anomaly(kind="error_rate", ts=fresh, service="pharmacy", z=9.0)
        alert2 = Alert(ts=fresh, kind="error_rate", service="pharmacy", severity="CRITICAL", score=0.9,
                       explanation="y")
        await pipeline._handle_alert(anomaly2, alert2)
        assert pipeline.notifier.queue_depth == 2  # CloudWatch alert + SNS incident
    finally:
        await pipeline.store.close()


def test_patient_ids_are_masked():
    assert mask_patient_id("P-000123") == "P-****23"
    assert mask_patient_id(None) is None


# -- WebSocket fan-out -----------------------------------------------------------


class _StuckSocket:
    async def send_text(self, _: str) -> None:
        await asyncio.sleep(3600)

    async def close(self, code: int = 1000) -> None:
        return None


async def test_a_stuck_client_never_blocks_broadcast_and_is_dropped():
    broadcaster = Broadcaster()
    client = _Client(_StuckSocket())  # type: ignore[arg-type]
    broadcaster.add(client)
    pump = asyncio.create_task(client.pump())
    try:
        started = asyncio.get_running_loop().time()
        for i in range(CLIENT_QUEUE_SIZE + 10):
            await broadcaster.broadcast({"type": "metric", "i": i})
        assert asyncio.get_running_loop().time() - started < 1.0
        assert client.too_slow
        assert broadcaster.client_count == 0
    finally:
        pump.cancel()


# -- API contract -------------------------------------------------------------


def _client(tmp_path: Path, **overrides):
    settings = _settings(tmp_path, **overrides)
    _init_logs(settings)
    app = create_app(settings=settings, config=load_config())
    return app, app.state.pipeline


def test_demo_scenario_catalogue_matches_the_generator():
    assert SCENARIO_NAMES == set(ALL_SCENARIO_NAMES)


def test_demo_inject_rejects_unknown_scenarios_and_bad_durations(tmp_path: Path):
    app, pipeline = _client(tmp_path)
    with TestClient(app) as client:
        assert client.post("/api/demo/inject", json={"scenario": "rm -rf"}).status_code == 422
        assert client.post("/api/demo/inject", json={"scenario": "batch_spike", "duration_s": 99999}).status_code == 422
        assert not pipeline.settings.control_file.exists()
        assert client.get("/api/demo/scenarios").json()["enabled"] is True


def test_operator_token_guards_writes_but_not_reads(tmp_path: Path):
    app, _ = _client(tmp_path, operator_token="s3cret")
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        assert client.post("/api/demo/inject", json={"scenario": "recovery"}).status_code == 401
        bad = client.post("/api/demo/inject", json={"scenario": "recovery"}, headers={"X-Operator-Token": "nope"})
        assert bad.status_code == 401
        ok = client.post("/api/demo/inject", json={"scenario": "recovery"}, headers={"X-Operator-Token": "s3cret"})
        assert ok.status_code == 200


def test_incident_detail_includes_events_alerts_and_rule(tmp_path: Path):
    app, pipeline = _client(tmp_path)
    with TestClient(app) as client:
        anomaly = Anomaly(kind="error_rate", ts=T0, service="claims", z=5.0)
        alert = Alert(ts=T0, kind="error_rate", service="claims", severity="HIGH", score=0.6, explanation="boom")
        client.portal.call(pipeline._handle_alert, anomaly, alert)
        incident_id = pipeline.incidents.list_incidents()[0].id

        body = client.get(f"/api/incidents/{incident_id}").json()
        assert body["incident"]["id"] == incident_id
        assert [e["event_type"] for e in body["events"]] == ["opened"]
        assert body["alerts"][0]["explanation"] == "boom"
        assert body["detection"]["z_threshold"] == 3.0
        assert client.get("/api/incidents/9999").status_code == 404


def test_log_search_supports_field_filters_and_free_text(tmp_path: Path):
    app, pipeline = _client(tmp_path)
    with TestClient(app) as client:
        for line in (_app_line(T0, level="ERROR", status=504), _app_line(T0, service="pharmacy"),
                     _audit_line(T0, user="U-042")):
            client.portal.call(pipeline._process_line, line)

        hits = client.get("/api/logs", params={"q": "timeout AND service:claims"}).json()["events"]
        assert len(hits) == 1 and hits[0]["status"] == 504
        assert hits[0]["patient_id"] == "P-****23"
        assert len(client.get("/api/logs", params={"q": "user:U-042"}).json()["events"]) == 1
        assert len(client.get("/api/logs", params={"q": "service:eligibility"}).json()["events"]) == 0

        seq = hits[0]["seq"]
        context = client.get(f"/api/logs/{seq}/context").json()
        assert context["event"]["seq"] == seq and len(context["after"]) == 2


def test_read_models_respond(tmp_path: Path):
    app, _ = _client(tmp_path)
    with TestClient(app) as client:
        health = client.get("/api/health").json()
        assert {"event_lag_seconds", "throughput", "replay", "events_processed"} <= set(health)
        assert client.get("/api/services/claims").json()["baselines"]["error_rate"] == []
        assert client.get("/api/services/nope").status_code == 404
        assert client.get("/api/analytics").json()["incidents"]["total"] == 0
        assert client.get("/api/config").json()["detection"]["hipaa"]["timezone"] == "America/Chicago"
        aws = client.get("/api/aws/status").json()
        assert aws["mode"] == "off" and aws["cloudwatch"]["sent"] == 0
        assert client.post("/api/aws/test-connection").json()["mode"] == "off"
        assert client.get("/api/hipaa/users").json() == []
        assert client.get("/api/incidents", params={"state": "BOGUS"}).status_code == 422


async def test_mock_mode_test_alert_reports_real_outcome(tmp_path: Path):
    from app.notify.aws import AwsNotifier

    notifier = AwsNotifier("mock", mock_log_path=tmp_path / "aws_mock.log")
    result = await notifier.send_test_alert()
    assert result["cloudwatch"]["ok"] and result["sns"]["ok"]
    assert notifier.status["cloudwatch"].sent == 1
    assert (tmp_path / "aws_mock.log").read_text(encoding="utf-8").count("\n") == 2


async def test_live_mode_without_topic_skips_sns_instead_of_retrying():
    from app.models import Incident
    from app.notify.aws import AwsNotifier

    notifier = AwsNotifier("live", sns_topic_arn="", base_backoff=0.01)
    await notifier.start()
    notifier.notify_incident(
        Incident(id=1, fingerprint="error_rate:claims", kind="error_rate", service="claims",
                 peak_severity="CRITICAL", opened_at=T0),
        "x",
    )
    await notifier.stop()
    assert notifier.status["sns"].skipped == 1
    assert notifier.status["sns"].retries == 0


async def test_store_persists_tail_positions(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite")
    await store.connect()
    await store.save_tail_position("/x/app.log", 42, 1234)
    await store.save_tail_position("/x/app.log", 42, 2048)
    assert await store.load_tail_positions() == {"/x/app.log": (42, 2048)}
    await store.close()


def test_mute_suppresses_notifications_until_it_expires(tmp_path: Path):
    app, pipeline = _client(tmp_path)
    with TestClient(app) as client:
        now = datetime.now(timezone.utc)
        anomaly = Anomaly(kind="error_rate", ts=now, service="claims", z=5.0)
        low = Alert(ts=now, kind="error_rate", service="claims", severity="LOW", score=0.1, explanation="a")
        incident_id = pipeline.incidents.record_alert(anomaly, low).incident.id

        body = client.post(f"/api/incidents/{incident_id}/mute", json={"minutes": 30}).json()
        assert body["muted_until"] is not None
        critical = Alert(ts=now, kind="error_rate", service="claims", severity="CRITICAL", score=0.9, explanation="b")
        update = pipeline.incidents.record_alert(anomaly, critical)
        assert update.is_escalation and not update.should_notify

        assert client.post(f"/api/incidents/{incident_id}/mute", json={"minutes": 0}).json()["muted_until"] is None
        assert client.post("/api/incidents/999/mute", json={"minutes": 5}).status_code == 404


async def test_metrics_keep_the_baseline_they_were_judged_against(tmp_path: Path):
    import aiosqlite

    legacy = tmp_path / "legacy.db"
    async with aiosqlite.connect(legacy) as db:  # a database from before the columns existed
        await db.execute(
            "CREATE TABLE metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL, window_end TEXT NOT NULL,"
            " total INTEGER NOT NULL, errors INTEGER NOT NULL, error_rate REAL NOT NULL, p95_latency_ms REAL NOT NULL,"
            " urgent_errors INTEGER NOT NULL, affected_patients_urgent INTEGER NOT NULL,"
            " affected_patients_routine INTEGER NOT NULL, malformed_lines INTEGER NOT NULL DEFAULT 0)"
        )
        await db.commit()
    store = Store(legacy)
    await store.connect()
    from app.models import WindowMetrics

    await store.save_metrics(WindowMetrics(
        service="claims", window_end=T0, total=10, errors=1, error_rate=0.1, p95_latency_ms=100, urgent_errors=0,
        affected_patients_urgent=0, affected_patients_routine=1, baseline_mean=0.02, baseline_std=0.01,
    ))
    rows = await store.list_metrics(service="claims", minutes=5, before=T0)
    assert rows[0].baseline_mean == 0.02 and rows[0].baseline_std == 0.01
    await store.close()


async def test_hipaa_incidents_auto_resolve_on_app_traffic_alone(tmp_path: Path):
    """Regression: the HIPAA timeout sweep only ran on audit events, so with no
    staff traffic (outside business hours) HIPAA incidents never resolved."""
    settings = _settings(tmp_path)
    _init_logs(settings)
    pipeline = Pipeline(settings, load_config())
    await pipeline.store.connect()
    try:
        await pipeline._process_line(_audit_line(T0, user="U-088", patient=1, region="TN-South"))
        assert any(i.state == "OPEN" for i in pipeline.incidents.list_incidents())
        await pipeline._process_line(_app_line(T0 + timedelta(minutes=11)))
        assert all(i.state == "RESOLVED" for i in pipeline.incidents.list_incidents())
    finally:
        await pipeline.store.close()
