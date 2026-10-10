"""Run the synthetic log generator inside the backend process tree.

Hosted free tiers (one web service, no sidecar) cannot run the docker-compose
generator container, so with ``EMBEDDED_GENERATOR=true`` the backend starts the
same ``python -m generator.generate`` as a child process. Output is synthetic
and the UI labels it SIMULATED. It is off by default; local runs keep using
``start.sh`` / docker-compose.

The child is restarted with backoff if it dies and is terminated on shutdown.
It never touches the database, so a generator failure cannot affect detection.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger("healthtrace.generator")


class EmbeddedGenerator:
    def __init__(self, *, log_dir: Path, control_file: Path, root: Path, rate: float = 20.0,
                 backfill_hours: float = 2.0) -> None:
        self.log_dir = log_dir
        self.control_file = control_file
        self.root = root
        self.rate = rate
        self.backfill_hours = backfill_hours
        self._task: Optional[asyncio.Task] = None
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._stopping = False
        self.restarts = 0

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    def _argv(self, *extra: str) -> list[str]:
        return [sys.executable, "-m", "generator.generate", "--log-dir", str(self.log_dir),
                "--control-file", str(self.control_file), *extra]

    async def _run_once(self, *extra: str) -> int:
        self._proc = await asyncio.create_subprocess_exec(
            *self._argv(*extra), cwd=str(self.root),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        return await self._proc.wait()

    async def _supervise(self) -> None:
        app_log = self.log_dir / "app.log"
        if self.backfill_hours > 0 and (not app_log.exists() or app_log.stat().st_size == 0):
            code = await self._run_once("--backfill-hours", str(self.backfill_hours), "--rate", str(self.rate))
            log.info("embedded generator backfill finished (exit %s)", code)
        delay = 1.0
        while not self._stopping:
            code = await self._run_once("--rate", str(self.rate))
            if self._stopping:
                break
            self.restarts += 1
            log.warning("embedded generator exited (%s); restarting in %.0fs", code, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)

    async def start(self) -> None:
        if self._task is not None:
            return
        self.log_dir.mkdir(parents=True, exist_ok=True)
        for name in ("app.log", "audit.log", "auth.log"):
            (self.log_dir / name).touch(exist_ok=True)
        self._stopping = False
        self._task = asyncio.create_task(self._supervise(), name="embedded-generator")
        log.info("embedded synthetic generator started (rate %.0f/s)", self.rate)

    async def stop(self) -> None:
        self._stopping = True
        proc = self._proc
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
