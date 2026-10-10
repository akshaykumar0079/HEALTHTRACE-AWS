"""Hosting support: embedded generator, metrics throttle, rate limit, PORT."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import REPO_ROOT, Settings, load_config
from app.embedded_generator import EmbeddedGenerator
from app.main import create_app
from app.models import WindowMetrics

from tests.test_workflow import _build


def test_embedded_generator_backfills_streams_and_stops(tmp_path: Path):
    async def go():
        gen = EmbeddedGenerator(log_dir=tmp_path / "logs", control_file=tmp_path / "c.json",
                                root=REPO_ROOT, rate=20, backfill_hours=0.05)
        await gen.start()
        for _ in range(100):
            await asyncio.sleep(0.2)
            if (tmp_path / "logs" / "app.log").stat().st_size > 0 and gen.running:
                break
        assert gen.running
        size = (tmp_path / "logs" / "app.log").stat().st_size
        assert size > 0
        await gen.stop()
        assert not gen.running
    asyncio.run(go())


def test_metrics_persist_throttle(tmp_path: Path):
    _, pipeline = _build(tmp_path, metrics_persist_interval_seconds=60)
    m = WindowMetrics.model_construct(service="claims")
    assert pipeline._should_persist_metrics(m) is True
    assert pipeline._should_persist_metrics(m) is False
    other = WindowMetrics.model_construct(service="portal")
    assert pipeline._should_persist_metrics(other) is True


def test_metrics_persist_default_every_window(tmp_path: Path):
    _, pipeline = _build(tmp_path)
    m = WindowMetrics.model_construct(service="claims")
    assert pipeline._should_persist_metrics(m) and pipeline._should_persist_metrics(m)


def test_write_rate_limit(tmp_path: Path):
    app, _ = _build(tmp_path, demo_mode=False)
    with TestClient(app) as client:
        codes = [client.post("/api/demo/inject", json={}).status_code for _ in range(125)]
    assert 429 in codes
    assert codes.index(429) <= 121


def test_health_ok(tmp_path: Path):
    app, _ = _build(tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
