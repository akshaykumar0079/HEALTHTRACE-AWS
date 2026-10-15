"""Ingestion throughput benchmark on synthetic data only.

Feeds a fixed synthetic stream through the real ``Pipeline._process_line`` in a
temporary database (no network, no .env) and, separately, through the file
tailer. Run from ``backend/``:  ../.venv/bin/python ../scripts/bench_ingest.py
Prints lines/second; compare before and after a change on the same machine.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.config import load_config  # noqa: E402
from app.ingest.tailer import Tailer  # noqa: E402
from app.pipeline import Pipeline  # noqa: E402
from app.simulation.runner import _isolated_settings, build_stream  # noqa: E402
from app.simulation.scenarios import SCENARIOS  # noqa: E402

logging.disable(logging.CRITICAL)


async def pipeline_rate(lines: list[str]) -> float:
    work = Path(tempfile.mkdtemp())
    (work / "logs").mkdir()
    p = Pipeline(_isolated_settings(work), load_config())
    await p.store.connect()
    await p.baseline.load(p.store)
    start = time.perf_counter()
    for line in lines:
        await p._process_line(line)
    elapsed = time.perf_counter() - start
    await p.store.close()
    return len(lines) / elapsed


async def tailer_rate(lines: list[str]) -> float:
    work = Path(tempfile.mkdtemp())
    path = work / "x.log"
    path.write_text("\n".join(lines) + "\n")
    q: "asyncio.Queue[str]" = asyncio.Queue()
    t = Tailer(path, q, from_start=True)
    start = time.perf_counter()
    while not t.caught_up:
        await t.poll_once()
    elapsed = time.perf_counter() - start
    return len(lines) / elapsed


async def main(runs: int = 3) -> None:
    scn = SCENARIOS["normal_control"]
    lines, _ = build_stream(scn, scn.seed)
    lines = lines[:30000]
    pr = [await pipeline_rate(lines) for _ in range(runs)]
    tr = [await tailer_rate(lines) for _ in range(runs)]
    print(f"lines={len(lines)} runs={runs}")
    print(f"pipeline lines/s: median={statistics.median(pr):,.0f} all={[round(x) for x in pr]}")
    print(f"tailer   lines/s: median={statistics.median(tr):,.0f} all={[round(x) for x in tr]}")


if __name__ == "__main__":
    asyncio.run(main())
