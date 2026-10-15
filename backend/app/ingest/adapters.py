"""Source adapters: one raw line in, one validated event (or a reason code) out.

* :class:`JsonLinesAdapter` reads structured JSON lines through an *explicit*
  field mapping (``config.yaml: ingest.sources[].fields/values/defaults``). It
  pseudonymizes identifiers **before** any event object is built and redacts
  free text, so a raw identifier never leaves this function.
* :class:`GeneratorV1Adapter` keeps the project's own synthetic formats working
  in configured mode (the legacy parser), pseudonymizing afterwards.

No adapter writes anywhere, opens a file, or touches the network.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from typing import Any, Callable, NamedTuple, Optional
from zoneinfo import ZoneInfo  # noqa: F401  (documents the tz type resolve_timezone returns)

from pydantic import ValidationError

from app.config import CANONICAL_FIELDS, REQUIRED_FIELDS, SourceConfig
from app.ingest import reasons
from app.ingest.pseudonym import Pseudonymizer
from app.ingest.timestamps import TimestampError, normalize_ts, resolve_timezone
from app.models import AppEvent, AuditEvent, AuthEvent
from app.privacy.safe_log import scrub_text
from app.parse.parser import ParsedEvent, Parser, reason_for_validation_error

_MODELS = {"app": AppEvent, "audit": AuditEvent, "auth": AuthEvent}


OMITTED_MSG = "[free text omitted]"   # constant used when a source does not opt in to free text


class AdapterResult(NamedTuple):
    event: Optional[ParsedEvent]
    reason: Optional[str]
    event_id: Optional[str]


def _lookup(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def pseudonymize_event(event: ParsedEvent, ps: Pseudonymizer) -> ParsedEvent:
    """Replace identifiers on an already-built event (used for generator_v1)."""
    update: dict[str, Any] = {}
    if hasattr(event, "user_id"):
        update["user_id"] = ps.user(event.user_id)
    if getattr(event, "patient_id", None):
        update["patient_id"] = ps.patient(event.patient_id)
    if getattr(event, "source_ip", None):
        update["source_ip"] = ps.ip(event.source_ip)
    if getattr(event, "request_id", None):
        update["request_id"] = ps.request(event.request_id)
    return event.model_copy(update=update)


class GeneratorV1Adapter:
    def __init__(self, parser: Parser, pseudonymizer: Pseudonymizer, include_msg: bool = False) -> None:
        self._parser = parser
        self._ps = pseudonymizer
        self._include_msg = include_msg

    def parse(self, line: str) -> AdapterResult:
        event, reason = self._parser.parse(line)
        if event is None:
            return AdapterResult(None, reason, None)
        try:
            out = pseudonymize_event(event, self._ps)
            if not self._include_msg and getattr(out, "msg", None) is not None:
                out = out.model_copy(update={"msg": OMITTED_MSG})
            return AdapterResult(out, None, None)
        except ValueError:
            return AdapterResult(None, reasons.PSEUDONYM_UNAVAILABLE, None)


class JsonLinesAdapter:
    def __init__(
        self,
        cfg: SourceConfig,
        *,
        pseudonymizer: Pseudonymizer,
        redact_text: Callable[[Optional[str]], Optional[str]],
        services: set[str],
        max_future_skew: Optional[timedelta] = None,
    ) -> None:
        if cfg.kind is None:
            raise ValueError("json_lines source needs a kind")
        self.cfg = cfg
        self._kind = cfg.kind
        self._ps = pseudonymizer
        self._redact = redact_text
        self._services = services
        self._skew = max_future_skew
        self._tz = resolve_timezone(cfg.timezone)  # raises ValueError on a typo: fail at start-up
        self._model = _MODELS[cfg.kind]
        self.parser_rejects = 0

    def _canonical(self, record: dict[str, Any]) -> tuple[dict[str, Any], Optional[str]]:
        out: dict[str, Any] = {}
        for name in CANONICAL_FIELDS[self._kind]:
            value = _lookup(record, self.cfg.fields[name]) if name in self.cfg.fields else None
            if value is None and name in self.cfg.defaults:
                value = self.cfg.defaults[name]
            if value is None:
                continue
            mapping = self.cfg.values.get(name)
            if mapping is not None and name not in ("ts", "event_id"):
                key = str(value)
                if key in mapping:
                    value = mapping[key]
                elif name == "service" and key in self._services:
                    pass  # already a configured canonical service name
                elif name == "service":
                    return out, reasons.UNKNOWN_SERVICE
                else:
                    return out, reasons.BAD_VALUE
            elif name == "service" and str(value) not in self._services:
                return out, reasons.UNKNOWN_SERVICE
            out[name] = value
        return out, None

    @staticmethod
    def _scrub_identifiers(text: str, raw_ids: list[str]) -> str:
        """Opt-in free text only: also remove this event's own raw identifiers (literal, case-insensitive)."""
        for raw in sorted({r for r in raw_ids if len(r) >= 3}, key=len, reverse=True):
            text = re.sub(re.escape(raw), "[id]", text, flags=re.IGNORECASE)
        return scrub_text(text)  # plus e-mail/SSN/phone/card/token and IPv4/IPv6 patterns

    def parse(self, line: str, *, now=None) -> AdapterResult:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError, RecursionError):
            return AdapterResult(None, reasons.INVALID_JSON, None)
        if not isinstance(record, dict):
            return AdapterResult(None, reasons.NOT_AN_OBJECT, None)

        fields, bad = self._canonical(record)
        raw_event_id = fields.pop("event_id", None)
        event_id = str(raw_event_id) if raw_event_id is not None and not isinstance(raw_event_id, (dict, list)) else None
        if bad:
            return AdapterResult(None, bad, event_id)
        needed = [f for f in REQUIRED_FIELDS[self._kind] if f != "msg" or self.cfg.include_msg]
        if any(f not in fields for f in needed):
            return AdapterResult(None, reasons.MISSING_FIELD, event_id)

        try:
            fields["ts"] = normalize_ts(fields["ts"], default_tz=self._tz, max_future_skew=self._skew, now=now)
        except TimestampError as exc:
            return AdapterResult(None, exc.code, event_id)

        raw_ids = [str(fields[k]) for k in ("user_id", "patient_id", "source_ip", "request_id")
                   if fields.get(k) is not None] + ([event_id] if event_id else [])
        try:
            if "user_id" in fields:
                fields["user_id"] = self._ps.user(fields["user_id"])
            if fields.get("patient_id") is not None:
                fields["patient_id"] = self._ps.patient(fields["patient_id"])
            if fields.get("source_ip") is not None:
                fields["source_ip"] = self._ps.ip(fields["source_ip"])
            if fields.get("request_id") is not None:
                fields["request_id"] = self._ps.request(fields["request_id"])
        except ValueError:
            return AdapterResult(None, reasons.PSEUDONYM_UNAVAILABLE, event_id)

        if self._kind == "app":
            if self.cfg.include_msg:
                text = self._redact(self._scrub_identifiers(str(fields["msg"]), raw_ids)) or ""
                fields["msg"] = text[: self.cfg.max_msg_chars]
            else:
                # Never copy source free text. An operator-written constant (defaults.msg) is allowed.
                const = self.cfg.defaults.get("msg")
                fields["msg"] = str(const)[: self.cfg.max_msg_chars] if const else OMITTED_MSG
        fields["type"] = self._kind
        try:
            return AdapterResult(self._model.model_validate(fields), None, event_id)
        except ValidationError as exc:
            return AdapterResult(None, reason_for_validation_error(exc), event_id)
