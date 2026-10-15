"""Timestamp normalization at the ingest boundary (docs/ingestion.md).

Every event time becomes a **timezone-aware UTC** ``datetime`` before it reaches
a detector, so detectors never compare naive and aware values (the audited
``TypeError`` that silently dropped events).

Accepted input
* ISO-8601 strings with an offset or ``Z`` (any offset is converted to UTC);
* ISO-8601 strings *without* an offset, **only** when a default timezone is
  supplied (the source's configured zone) and the local time is unambiguous;
* numbers: epoch seconds, or epoch milliseconds when the magnitude says so.

Rejected, with a stable reason code (``app.ingest.reasons``)
* ``ts_invalid``   - missing, unparseable, boolean, NaN/inf, out of the sane
  year range, or a local time that does not exist (DST gap);
* ``ts_no_tz``     - no offset and no default timezone configured;
* ``ts_ambiguous`` - a local time that occurs twice (DST fall-back);
* ``ts_skew``      - further in the future than ``max_future_skew`` allows.
  Old timestamps are fine: replaying history is legitimate.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.ingest import reasons

UTC = timezone.utc
MIN_YEAR = 2000
MAX_YEAR = 2100
_MS_THRESHOLD = 1e11  # epoch seconds this large would be year 5138: treat as milliseconds


class TimestampError(ValueError):
    """Carries a stable ``code`` from ``app.ingest.reasons``."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code


def resolve_timezone(name: Optional[str]) -> Optional[tzinfo]:
    """``None``/empty -> no default zone. Raises ``ValueError`` for an unknown
    name so a typo in configuration fails at start-up, not per event."""
    if not name:
        return None
    if name.upper() == "UTC":
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown timezone {name!r}") from exc


def _localize(naive: datetime, tz: tzinfo) -> datetime:
    """Attach ``tz`` to a naive local time, rejecting DST gaps and overlaps."""
    first = naive.replace(tzinfo=tz, fold=0)
    second = naive.replace(tzinfo=tz, fold=1)
    off1, off2 = first.utcoffset(), second.utcoffset()
    if off1 != off2:
        # fold=0 and fold=1 disagree: either the time occurs twice (overlap)
        # or it never occurs (gap). A round trip through UTC tells them apart.
        back = first.astimezone(UTC).astimezone(tz).replace(tzinfo=None)
        if back != naive:
            raise TimestampError(reasons.TS_INVALID, "local time does not exist (DST gap)")
        raise TimestampError(reasons.TS_AMBIGUOUS, "local time occurs twice (DST overlap)")
    return first


def normalize_ts(
    value: Any,
    *,
    default_tz: Optional[tzinfo] = None,
    assume_utc_if_naive: bool = False,
    max_future_skew: Optional[timedelta] = None,
    now: Optional[datetime] = None,
    min_year: int = MIN_YEAR,
    max_year: int = MAX_YEAR,
) -> datetime:
    """Return an aware UTC ``datetime`` or raise :class:`TimestampError`.

    ``assume_utc_if_naive`` is the legacy compatibility switch (generator logs
    always carry ``Z``); configured sources leave it off and either supply
    ``default_tz`` or get ``ts_no_tz``.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, bool) or value is None:
        raise TimestampError(reasons.TS_INVALID, "missing or boolean timestamp")
    elif isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise TimestampError(reasons.TS_INVALID, "non-finite timestamp")
        seconds = float(value) / 1000.0 if abs(value) >= _MS_THRESHOLD else float(value)
        try:
            dt = datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise TimestampError(reasons.TS_INVALID, "epoch out of range") from exc
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise TimestampError(reasons.TS_INVALID, "empty timestamp")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise TimestampError(reasons.TS_INVALID, "not ISO-8601") from exc
    else:
        raise TimestampError(reasons.TS_INVALID, f"unsupported type {type(value).__name__}")

    if dt.tzinfo is None or dt.utcoffset() is None:
        if default_tz is not None:
            dt = _localize(dt, default_tz)
        elif assume_utc_if_naive:
            dt = dt.replace(tzinfo=UTC)
        else:
            raise TimestampError(reasons.TS_NO_TZ, "no timezone offset and no default timezone configured")

    dt = dt.astimezone(UTC)
    if not (min_year <= dt.year <= max_year):
        raise TimestampError(reasons.TS_INVALID, "year outside the accepted range")
    if max_future_skew is not None:
        reference = (now or datetime.now(UTC)).astimezone(UTC)
        if dt - reference > max_future_skew:
            raise TimestampError(reasons.TS_SKEW, "timestamp is too far in the future")
    return dt
