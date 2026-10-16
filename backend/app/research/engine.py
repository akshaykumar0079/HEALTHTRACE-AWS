"""Run a method over a list of detector-format lines and return incident-level detections.

The pipeline methods use the real pipeline in the simulator's isolated, temporary SQLite database (AWS off,
email disabled, nothing written to the real store). Nothing here opens a socket.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from app.evaluation.methods import METHODS, detections_from_pipeline, effective_config, threshold_detections
from app.evaluation.scoring import Detection
from app.pipeline import Pipeline
from app.simulation.runner import _isolated_settings


async def _run_pipeline(lines: list[str], method_id: str) -> list[Detection]:
    cfg = effective_config(METHODS[method_id])
    with tempfile.TemporaryDirectory(prefix="healthtrace-research-") as tmp:
        workdir = Path(tmp)
        (workdir / "logs").mkdir()
        pipeline = Pipeline(_isolated_settings(workdir), cfg)
        await pipeline.store.connect()
        try:
            for line in lines:
                await pipeline._process_line(line)          # noqa: SLF001  (same entry point the simulator uses)
            incidents = await pipeline.store.list_incidents()
            alerts = await pipeline.store.list_alerts(limit=1_000_000)
        finally:
            await pipeline.store.close()
    return detections_from_pipeline(incidents, alerts)


def detect(lines: list[str], method_id: str) -> list[Detection]:
    """Synchronous; call from a worker thread when already inside an event loop."""
    method = METHODS[method_id]
    if method.kind == "pipeline":
        return asyncio.run(_run_pipeline(lines, method_id))
    return threshold_detections(lines, float(method.threshold))
