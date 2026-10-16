"""EWMA baseline per (service, hour_of_day), with warm-up and poisoning
protection (SPEC.md section 6.4).

``update()`` must only be called for windows the anomaly engine judged
non-anomalous — that's what keeps a sustained outage from dragging the
baseline's mean toward the outage rate. This module doesn't decide that; it
just remembers whatever it's told. See ``AnomalyEngine.evaluate``, which is
the one caller responsible for gating updates.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from typing import Optional

from app.config import BaselineConfig
from app.store.db import BaselineRow, Store

GLOBAL_HOUR = -1  # fallback bucket: this service's baseline across all hours


@dataclass
class BaselineStats:
    mean: float
    variance: float
    count: int
    is_global_fallback: bool


class _EwmaCell:
    __slots__ = ("mean", "variance", "count")

    def __init__(self, mean: float = 0.0, variance: float = 0.0, count: int = 0) -> None:
        self.mean = mean
        self.variance = variance
        self.count = count

    def update(self, value: float, alpha: float) -> None:
        if self.count == 0:
            self.mean = value
            self.variance = 0.0
        else:
            delta = value - self.mean
            self.mean += alpha * delta
            self.variance = (1 - alpha) * (self.variance + alpha * delta * delta)
        self.count += 1


class BaselineEngine:
    def __init__(self, config: BaselineConfig) -> None:
        self._config = config
        # (service, hour_of_day, metric) -> cell; hour_of_day may be GLOBAL_HOUR.
        self._cells: dict[tuple[str, int, str], _EwmaCell] = {}

    def get(self, service: str, hour_of_day: int, metric: str) -> Optional[BaselineStats]:
        """The ready baseline for (service, hour_of_day, metric), falling back
        to the global per-service baseline if the hourly bucket hasn't warmed
        up yet, or None if neither has (SPEC.md 6.4: "emit no anomalies")."""
        hourly = self._cells.get((service, hour_of_day, metric)) if self._config.time_aware else None
        if hourly is not None and hourly.count >= self._config.warmup_windows:
            return BaselineStats(hourly.mean, hourly.variance, hourly.count, is_global_fallback=False)

        global_cell = self._cells.get((service, GLOBAL_HOUR, metric))
        if global_cell is not None and global_cell.count >= self._config.warmup_windows:
            return BaselineStats(global_cell.mean, global_cell.variance, global_cell.count, is_global_fallback=True)

        return None

    def update(self, service: str, hour_of_day: int, metric: str, value: float) -> None:
        """Only call this for windows the anomaly engine judged non-anomalous."""
        hourly = self._cells.setdefault((service, hour_of_day, metric), _EwmaCell())
        hourly.update(value, self._config.alpha)
        global_cell = self._cells.setdefault((service, GLOBAL_HOUR, metric), _EwmaCell())
        global_cell.update(value, self._config.alpha)

    def is_ready(self, service: str, hour_of_day: int, metric: str) -> bool:
        return self.get(service, hour_of_day, metric) is not None

    def is_empty(self) -> bool:
        """True until anything has ever been learned or reloaded — used by the
        pipeline to detect a first run, per SPEC.md 6.4's "backend replays
        [the backfill] on first run so every hour bucket is ready"."""
        return not self._cells

    # -- persistence (SPEC.md 6.4: every 60s and on shutdown; reload on startup) --

    async def save(self, store: Store) -> None:
        rows = [
            BaselineRow(
                service=svc, hour_of_day=hour, metric=metric,
                mean=cell.mean, variance=cell.variance, count=cell.count,
            )
            for (svc, hour, metric), cell in self._cells.items()
        ]
        await store.save_baselines(rows)

    async def load(self, store: Store) -> None:
        for row in await store.load_baselines():
            cell = self._cells.setdefault((row.service, row.hour_of_day, row.metric), _EwmaCell())
            cell.mean, cell.variance, cell.count = row.mean, row.variance, row.count

    def cells_for(self, service: str, metric: str) -> list[dict]:
        """Every learned bucket for one service/metric, for the baseline chart.
        hour_of_day == GLOBAL_HOUR is the all-hours fallback."""
        return [
            {
                "hour_of_day": hour, "mean": cell.mean, "std": sqrt(max(cell.variance, 0.0)), "count": cell.count,
                "ready": cell.count >= self._config.warmup_windows,
            }
            for (svc, hour, m), cell in sorted(self._cells.items(), key=lambda kv: kv[0][1])
            if svc == service and m == metric
        ]
