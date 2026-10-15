"""Parse raw JSON lines into typed events, never raising on bad input (SPEC.md 6.2).

A bad line (invalid JSON, wrong shape, unrecognized "type", bad timestamp) is
counted in ``malformed_lines`` and dropped - it never crashes the pipeline.
Each rejection also has a stable reason code (``app.ingest.reasons``) counted in
``reject_counts``; the line's content is never kept.

This is the **legacy** parser for the project's own three synthetic schemas
(``INGEST_MODE=legacy``). Timestamps are normalized to aware UTC; a timestamp
without an offset is assumed to be UTC and counted in ``naive_assumed_utc``
(configured sources are stricter, see docs/ingestion.md).
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from typing import NamedTuple, Optional, Union

from pydantic import ValidationError

from app.ingest import reasons
from app.ingest.timestamps import TimestampError, normalize_ts
from app.models import AppEvent, AuditEvent, AuthEvent

logger = logging.getLogger(__name__)

ParsedEvent = Union[AppEvent, AuditEvent, AuthEvent]

_MODELS = {"app": AppEvent, "audit": AuditEvent, "auth": AuthEvent}


class ParseResult(NamedTuple):
    event: Optional[ParsedEvent]
    reason: Optional[str]  # a code from app.ingest.reasons when event is None


def reason_for_validation_error(exc: ValidationError) -> str:
    """Map the first pydantic error to a stable reason code."""
    errors = exc.errors()
    first = errors[0] if errors else {}
    loc = first.get("loc", ())
    kind = first.get("type", "")
    if kind == "missing":
        return reasons.MISSING_FIELD
    if loc and loc[0] == "service" and kind == "literal_error":
        return reasons.UNKNOWN_SERVICE
    return reasons.BAD_VALUE


class Parser:
    def __init__(self) -> None:
        self.malformed_lines = 0
        self.reject_counts: Counter[str] = Counter()
        self.naive_assumed_utc = 0

    def _reject(self, reason: str) -> ParseResult:
        self.malformed_lines += 1
        self.reject_counts[reason] += 1
        return ParseResult(None, reason)

    def parse(self, line: str) -> ParseResult:
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, TypeError, RecursionError):
            logger.debug("malformed line (invalid JSON), %d chars", len(line) if isinstance(line, str) else -1)
            return self._reject(reasons.INVALID_JSON)

        if not isinstance(data, dict):
            return self._reject(reasons.NOT_AN_OBJECT)

        model = _MODELS.get(data.get("type"))
        if model is None:
            return self._reject(reasons.UNKNOWN_TYPE)

        if "ts" not in data:
            return self._reject(reasons.MISSING_FIELD)
        try:
            try:
                data["ts"] = normalize_ts(data["ts"])
            except TimestampError as exc:
                if exc.code != reasons.TS_NO_TZ:
                    raise
                data["ts"] = normalize_ts(data["ts"], assume_utc_if_naive=True)
                self.naive_assumed_utc += 1
        except TimestampError as exc:
            return self._reject(exc.code)

        try:
            return ParseResult(model.model_validate(data), None)
        except ValidationError as exc:
            reason = reason_for_validation_error(exc)
            logger.debug("malformed line (%s)", reason)
            return self._reject(reason)

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        return self.parse(line).event
