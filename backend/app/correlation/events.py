"""The normalised event interface and the adapters that produce it.

Sources
-------
``app``       application logs (the existing ``app.log``)
``auth``      authentication events (the existing ``auth.log``)
``audit``     application PHI-access audit (the existing ``audit.log``)
``server``    host/server logs                (synthetic adapter only)
``db_audit``  database audit logs             (synthetic adapter only)

Only the first three read formats this project already produces. The
``server`` and ``db_audit`` adapters define a documented, synthetic format so
the interface can be exercised and tested; they have NOT been validated
against any real server or database product.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

SOURCES = ("app", "auth", "audit", "server", "db_audit")


class AdapterError(ValueError):
    """The raw record cannot be placed in time or is not this adapter's format."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class NormalizedEvent:
    id: str
    source: str
    ts: datetime                         # when it happened (event time, UTC)
    received_at: Optional[datetime] = None  # when it reached us; later than ts for late arrivals
    actor: Optional[str] = None          # user / service account
    resource: Optional[str] = None       # exact resource id (patient id, table); None when masked or absent
    service: Optional[str] = None
    host: Optional[str] = None
    request_id: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None        # success | failure | error | ok
    message: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "source": self.source, "ts": self.ts.isoformat(),
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "actor": self.actor, "resource": self.resource, "service": self.service, "host": self.host,
            "request_id": self.request_id, "action": self.action, "outcome": self.outcome,
            "message": self.message,
        }


def parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        ts = value
    elif isinstance(value, str) and value:
        try:
            ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AdapterError("bad_timestamp", value) from exc
    else:
        raise AdapterError("missing_timestamp")
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _exact_resource(value: Any) -> Optional[str]:
    """A masked identifier (``P-****42``) matches many patients, so it can
    never serve as a join key: treat it as absent."""
    text = _clean(value)
    if text is None or "*" in text:
        return None
    return text


def _make_id(source: str, raw: dict[str, Any], ts: datetime) -> str:
    given = _clean(raw.get("id") or raw.get("event_id"))
    if given:
        return f"{source}:{given}"
    basis = "|".join([source, ts.isoformat(), *(str(raw.get(k, "")) for k in sorted(raw) if k not in ("seq", "received_at"))])
    return f"{source}:{hashlib.sha1(basis.encode()).hexdigest()[:12]}"


def _received(raw: dict[str, Any]) -> Optional[datetime]:
    value = raw.get("received_at")
    if not value:
        return None
    try:
        return parse_ts(value)
    except AdapterError:
        return None


def adapt_app(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_ts(raw.get("ts"))
    is_error = bool(raw.get("is_error")) or raw.get("level") == "ERROR" or int(raw.get("status") or 0) >= 500
    return NormalizedEvent(
        id=_make_id("app", raw, ts), source="app", ts=ts, received_at=_received(raw),
        resource=_exact_resource(raw.get("patient_id")), service=_clean(raw.get("service")),
        host=_clean(raw.get("host")), request_id=_clean(raw.get("request_id")),
        action=_clean(raw.get("action")), outcome="error" if is_error else "ok",
        message=str(raw.get("msg") or ""), raw=raw,
    )


def adapt_auth(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_ts(raw.get("ts"))
    return NormalizedEvent(
        id=_make_id("auth", raw, ts), source="auth", ts=ts, received_at=_received(raw),
        actor=_clean(raw.get("user_id")), host=_clean(raw.get("host")), request_id=_clean(raw.get("request_id")),
        action="login", outcome=_clean(raw.get("outcome")),
        message=str(raw.get("msg") or f"login {raw.get('outcome', '?')}"), raw=raw,
    )


def adapt_audit(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_ts(raw.get("ts"))
    return NormalizedEvent(
        id=_make_id("audit", raw, ts), source="audit", ts=ts, received_at=_received(raw),
        actor=_clean(raw.get("user_id")), resource=_exact_resource(raw.get("patient_id")),
        request_id=_clean(raw.get("request_id")), action=_clean(raw.get("action")), outcome="ok",
        message=str(raw.get("msg") or ""), raw=raw,
    )


def adapt_server(raw: dict[str, Any]) -> NormalizedEvent:
    """Synthetic format: ``{ts, host, process, level, message, request_id?}``."""
    ts = parse_ts(raw.get("ts"))
    level = str(raw.get("level") or "").upper()
    return NormalizedEvent(
        id=_make_id("server", raw, ts), source="server", ts=ts, received_at=_received(raw),
        host=_clean(raw.get("host")), service=_clean(raw.get("process")), request_id=_clean(raw.get("request_id")),
        action=_clean(raw.get("process")), outcome="error" if level in ("ERROR", "FATAL", "CRITICAL") else
        ("warning" if level in ("WARN", "WARNING") else "ok"),
        message=str(raw.get("message") or ""), raw=raw,
    )


def adapt_db_audit(raw: dict[str, Any]) -> NormalizedEvent:
    """Synthetic format: ``{ts, db_user, statement_type, object, rows, host?, request_id?}``."""
    ts = parse_ts(raw.get("ts"))
    return NormalizedEvent(
        id=_make_id("db_audit", raw, ts), source="db_audit", ts=ts, received_at=_received(raw),
        actor=_clean(raw.get("db_user")), resource=_exact_resource(raw.get("object")), host=_clean(raw.get("host")),
        request_id=_clean(raw.get("request_id")), action=_clean(raw.get("statement_type")), outcome="ok",
        message=str(raw.get("message") or f"{raw.get('statement_type', '?')} on {raw.get('object', '?')}"), raw=raw,
    )


ADAPTERS: dict[str, Callable[[dict[str, Any]], NormalizedEvent]] = {
    "app": adapt_app, "auth": adapt_auth, "audit": adapt_audit, "server": adapt_server, "db_audit": adapt_db_audit,
}

# Which adapters read a format this project really produces, vs a synthetic one.
ADAPTER_STATUS = {
    "app": "native: reads app.log records", "auth": "native: reads auth.log records",
    "audit": "native: reads audit.log records",
    "server": "synthetic format only; not validated against a real server log",
    "db_audit": "synthetic format only; not validated against a real database audit log",
}


def normalize(source: str, raw: dict[str, Any]) -> NormalizedEvent:
    adapter = ADAPTERS.get(source)
    if adapter is None:
        raise AdapterError("unknown_source", source)
    if not isinstance(raw, dict):
        raise AdapterError("not_an_object")
    return adapter(raw)


def normalize_all(items: list[tuple[str, dict[str, Any]]]) -> tuple[list[NormalizedEvent], list[dict[str, Any]]]:
    """Adapt many records; unusable ones are reported, never silently dropped
    and never given an invented timestamp."""
    events: list[NormalizedEvent] = []
    skipped: list[dict[str, Any]] = []
    for index, (source, raw) in enumerate(items):
        try:
            events.append(normalize(source, raw))
        except (AdapterError, TypeError, ValueError) as exc:
            skipped.append({"index": index, "source": source,
                            "reason": exc.code if isinstance(exc, AdapterError) else "invalid_record"})
    return events, skipped
