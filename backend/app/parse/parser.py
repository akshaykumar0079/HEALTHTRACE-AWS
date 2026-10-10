"""Parse raw JSON lines into typed events, never raising on bad input (SPEC.md 6.2).

A bad line (invalid JSON, wrong shape, or an unrecognized "type") is counted
in ``malformed_lines`` and dropped — it never crashes the pipeline.
"""

from __future__ import annotations

import json
import logging
from typing import Optional, Union

from pydantic import ValidationError

from app.models import AppEvent, AuditEvent, AuthEvent

logger = logging.getLogger(__name__)

ParsedEvent = Union[AppEvent, AuditEvent, AuthEvent]


class Parser:
    def __init__(self) -> None:
        self.malformed_lines = 0

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            self.malformed_lines += 1
            logger.debug("malformed line (invalid JSON): %r", line[:200])
            return None

        if not isinstance(data, dict):
            self.malformed_lines += 1
            return None

        event_type = data.get("type")
        try:
            if event_type == "app":
                return AppEvent.model_validate(data)
            if event_type == "audit":
                return AuditEvent.model_validate(data)
            if event_type == "auth":
                return AuthEvent.model_validate(data)
        except ValidationError:
            self.malformed_lines += 1
            logger.debug("malformed line (schema): %r", line[:200])
            return None

        self.malformed_lines += 1
        logger.debug("malformed line (unknown type %r): %r", event_type, line[:200])
        return None
