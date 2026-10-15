"""Event de-duplication (docs/ingestion.md).

Modes (``INGEST_DEDUPE``):

* ``event_id`` - **default.** An event is a duplicate when its *source-provided
  event id* has already been seen for that source. An event with no id is never
  dropped (it is counted in ``no_event_id``): without an id there is no safe way
  to tell a retransmission from two real events.
* ``content``  - **opt-in.** The key is a digest of the whole raw line. Two
  genuinely distinct events that serialize identically (one-second timestamps,
  the same actor and action) are collapsed, so enable it only for a source known
  to retransmit and to carry fine-grained timestamps.
* ``off``      - no de-duplication.

Memory is bounded (an LRU of ``capacity`` ids per source). A recent window is
persisted at checkpoints (``ingest_seen``) and reloaded at start-up, so a
retransmission that arrives after a restart is still recognized. Limit: ids
first seen *after* the last checkpoint are lost in a crash (clean shutdowns
checkpoint), so a crash can reprocess at most that window.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import OrderedDict, Counter
from typing import Any, Optional

MODES = ("event_id", "content", "off")
DEFAULT_CAPACITY = 200_000
PERSIST_PER_SOURCE = 50_000


class Deduper:
    def __init__(self, mode: str = "event_id", *, capacity: int = DEFAULT_CAPACITY, key: Optional[bytes] = None) -> None:
        if mode not in MODES:
            raise ValueError(f"INGEST_DEDUPE must be one of {MODES}, not {mode!r}")
        self.mode = mode
        self.capacity = max(1, int(capacity))
        self._key = key
        self._seen: dict[str, "OrderedDict[str, None]"] = {}
        self._pending: list[tuple[str, str]] = []
        self.duplicates: Counter[str] = Counter()
        self.no_event_id: Counter[str] = Counter()

    # -- keys -----------------------------------------------------------------------------

    def key_for(self, event_id: Optional[str], raw_line: Optional[str]) -> Optional[str]:
        if self.mode == "off":
            return None
        if self.mode == "content":
            if raw_line is None:
                return None
            data = raw_line.encode("utf-8", errors="replace")
            if self._key:
                return "c:" + hmac.new(self._key, data, hashlib.sha256).hexdigest()
            return "c:" + hashlib.sha256(data).hexdigest()
        if event_id is None or str(event_id).strip() == "":
            return None
        text = str(event_id).strip()[:256]
        if self._key:  # a source event id can itself embed an identifier: store a keyed digest, not the id
            return "i:" + hmac.new(self._key, text.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()
        return "i:" + text

    # -- check ----------------------------------------------------------------------------

    def is_duplicate(self, source: str, event_id: Optional[str] = None, raw_line: Optional[str] = None) -> bool:
        """Record the event and report whether it was already seen."""
        key = self.key_for(event_id, raw_line)
        if key is None:
            if self.mode == "event_id":
                self.no_event_id[source] += 1
            return False
        seen = self._seen.setdefault(source, OrderedDict())
        if key in seen:
            seen.move_to_end(key)
            self.duplicates[source] += 1
            return True
        seen[key] = None
        if len(seen) > self.capacity:
            seen.popitem(last=False)
        self._pending.append((source, key))
        return False

    def stats(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "duplicates_dropped": dict(self.duplicates),
            "events_without_id": dict(self.no_event_id),
            "tracked": {s: len(v) for s, v in self._seen.items()},
        }

    # -- persistence --------------------------------------------------------------------

    async def flush(self, store: Any) -> None:
        if not self._pending:
            return
        batch = list(self._pending)
        await store.save_ingest_seen(batch, keep_per_source=PERSIST_PER_SOURCE)
        del self._pending[: len(batch)]

    async def load(self, store: Any) -> None:
        for source, keys in (await store.load_ingest_seen(limit_per_source=min(self.capacity, PERSIST_PER_SOURCE))).items():
            seen = self._seen.setdefault(source, OrderedDict())
            for k in keys:  # oldest first
                seen[k] = None
