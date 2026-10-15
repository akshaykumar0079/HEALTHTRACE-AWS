"""Quarantine metadata for rejected input (docs/ingestion.md).

Records *that* something was refused and *why*: source, stable reason code,
byte offset and length. **The rejected line is never stored, logged or exposed**;
a rejected line from a hospital log may be exactly the one carrying an
identifier that must not be kept.

Rejections are counted in memory per ``(source, reason)`` and a bounded sample
of recent ones is kept; both are flushed to the database at checkpoints, so a
malformed-input flood costs a few counters, not one write per line.
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Deque, Optional

from app.ingest import reasons

RECENT_SAMPLE = 200          # recent rejections kept in memory / reported
DB_SAMPLE_ROWS = 2000        # rows kept in ingest_rejects after a trim


class Quarantine:
    def __init__(self) -> None:
        self.counts: Counter[tuple[str, str]] = Counter()
        self._unflushed_counts: Counter[tuple[str, str]] = Counter()
        self._last_at: dict[tuple[str, str], str] = {}
        self.recent: Deque[dict[str, Any]] = deque(maxlen=RECENT_SAMPLE)
        self._unflushed_rows: Deque[dict[str, Any]] = deque(maxlen=DB_SAMPLE_ROWS)

    def record(self, source: str, reason: str, offset: Optional[int] = None, length: Optional[int] = None) -> None:
        if reason not in reasons.ALL_CODES:
            reason = reasons.SCHEMA_INVALID  # never let a typo create an unbounded set of codes
        now = datetime.now(timezone.utc).isoformat()
        key = (source, reason)
        self.counts[key] += 1
        self._unflushed_counts[key] += 1
        self._last_at[key] = now
        row = {"ts": now, "source": source, "reason": reason, "offset": offset, "length": length}
        self.recent.append(row)
        self._unflushed_rows.append(row)

    def total(self, source: Optional[str] = None) -> int:
        return sum(n for (s, _), n in self.counts.items() if source is None or s == source)

    def by_reason(self, source: Optional[str] = None) -> dict[str, int]:
        out: Counter[str] = Counter()
        for (s, r), n in self.counts.items():
            if source is None or s == source:
                out[r] += n
        return dict(out)

    def summary(self) -> dict[str, Any]:
        per_source: dict[str, dict[str, int]] = {}
        for (s, r), n in self.counts.items():
            per_source.setdefault(s, {})[r] = n
        return {"total": self.total(), "by_source": per_source, "recent": list(self.recent)[-20:]}

    # -- persistence ---------------------------------------------------------------------

    async def flush(self, store: Any) -> None:
        if not self._unflushed_counts and not self._unflushed_rows:
            return
        counts = dict(self._unflushed_counts)
        rows = list(self._unflushed_rows)
        await store.save_ingest_rejects(counts, self._last_at, rows)
        # Only forget what was written; anything recorded meanwhile stays queued.
        for key, n in counts.items():
            self._unflushed_counts[key] -= n
            if self._unflushed_counts[key] <= 0:
                del self._unflushed_counts[key]
        for _ in rows:
            if self._unflushed_rows:
                self._unflushed_rows.popleft()

    async def load(self, store: Any) -> None:
        for source, reason, count in await store.load_ingest_reject_counts():
            self.counts[(source, reason)] += count
