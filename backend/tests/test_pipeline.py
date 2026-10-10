"""Milestone 5: pipeline wiring — first-run backfill replay (SPEC.md 6.4)
and that processing an event actually flows through to storage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.config import Settings, load_config
from app.detect.baseline import BaselineRow
from app.pipeline import Pipeline
from app.store.db import Store


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        aws_mode="off", demo_mode=True,
        log_dir=tmp_path / "logs", db_path=tmp_path / "medguard.db", control_file=tmp_path / "control.json",
    )


async def test_first_run_tails_app_log_from_the_start(tmp_path: Path):
    settings = _settings(tmp_path)
    settings.log_dir.mkdir(parents=True)
    (settings.log_dir / "app.log").write_text("", encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("", encoding="utf-8")

    pipeline = Pipeline(settings, load_config())
    await pipeline.start()
    try:
        assert all(t.from_start for t in pipeline._tailers)
    finally:
        await pipeline.stop()


async def test_later_run_with_persisted_baselines_tails_from_the_end(tmp_path: Path):
    settings = _settings(tmp_path)
    settings.log_dir.mkdir(parents=True)
    (settings.log_dir / "app.log").write_text("", encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("", encoding="utf-8")

    # Simulate a previous session having already persisted a warm baseline.
    seed_store = Store(settings.db_path)
    await seed_store.connect()
    await seed_store.save_baseline(BaselineRow("claims", 9, "error_rate", 0.02, 0.0001, 20))
    await seed_store.close()

    pipeline = Pipeline(settings, load_config())
    await pipeline.start()
    try:
        assert all(not t.from_start for t in pipeline._tailers)
    finally:
        await pipeline.stop()


async def test_processing_an_app_line_updates_service_state_and_persists_metrics(tmp_path: Path):
    settings = _settings(tmp_path)
    settings.log_dir.mkdir(parents=True)
    (settings.log_dir / "app.log").write_text("", encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("", encoding="utf-8")

    pipeline = Pipeline(settings, load_config())
    await pipeline.store.connect()
    try:
        # Relative to now: list_metrics only returns the last N minutes, so a
        # fixed date here made this test fail once that date passed.
        t0 = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(second=0, microsecond=0)
        ts1 = t0.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ts2 = (t0 + timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        line1 = (
            '{"ts":"' + ts1 + '","type":"app","service":"claims","level":"INFO",'
            '"priority":"routine","request_id":"X-1","patient_id":"P-000001","status":200,'
            '"latency_ms":100,"msg":"ok"}'
        )
        line2 = (
            '{"ts":"' + ts2 + '","type":"app","service":"claims","level":"INFO",'
            '"priority":"routine","request_id":"X-2","patient_id":"P-000002","status":200,'
            '"latency_ms":100,"msg":"ok"}'
        )
        await pipeline._process_line(line1)
        await pipeline._process_line(line2)  # crosses the 5s step boundary -> emits a metric

        assert "claims" in pipeline.service_states
        assert pipeline.service_states["claims"].total == 1

        stored = await pipeline.store.list_metrics(service="claims", minutes=60)
        assert len(stored) == 1
    finally:
        await pipeline.store.close()


async def test_malformed_line_is_counted_not_raised(tmp_path: Path):
    settings = _settings(tmp_path)
    settings.log_dir.mkdir(parents=True)
    (settings.log_dir / "app.log").write_text("", encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("", encoding="utf-8")

    pipeline = Pipeline(settings, load_config())
    await pipeline.store.connect()
    try:
        await pipeline._process_line("not json")
        assert pipeline.parser.malformed_lines == 1
        assert pipeline.health_snapshot()["malformed_lines"] == 1
    finally:
        await pipeline.store.close()
