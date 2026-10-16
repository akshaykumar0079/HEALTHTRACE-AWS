"""Helpers that keep identifiers out of log lines and error text (M2).

Log lines are an output path like any other: exception messages routinely embed
the value that caused them, database drivers print bound parameters at DEBUG,
and SMTP/HTTP errors echo recipient addresses. These helpers give call sites a
short, predictable alternative:

* :func:`scrub_text` - pattern-redact a string (e-mail, SSN, phone, card, token,
  IPv4/IPv6). Defence in depth only; it does not prove a string is free of
  identifiers.
* :func:`safe_exc` - exception *type and code location*, never its message.
* :func:`sanitize_error` - type plus a scrubbed, truncated message, for places
  (operator-facing status endpoints) where the message is useful.
* :func:`mask_email` - ``j***@example.org`` for operator-configured recipients.
* :func:`quiet_driver_logs` - stops database drivers logging SQL parameters.
"""

from __future__ import annotations

import logging
import re
import traceback
from typing import Optional

from app.privacy.redaction import DEFAULT_PATTERNS

_COMPILED = [(re.compile(p), r) for _, p, r in DEFAULT_PATTERNS]
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\w)")
# IPv6 needs "::" compression or all eight groups; plain "12:03:48" (a time) must not match.
_IPV6 = re.compile(
    r"(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
    r"|::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?)(?![\w:])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MAX_ERROR_CHARS = 200


def scrub_text(text: object, *, limit: Optional[int] = None) -> str:
    """Pattern-redact ``text`` (including IP addresses) and optionally truncate."""
    out = str(text)
    for pattern, replacement in _COMPILED:
        out = pattern.sub(replacement, out)
    out = _IPV4.sub("[IP]", out)
    out = _IPV6.sub("[IP]", out)
    if limit is not None and len(out) > limit:
        out = out[:limit] + "..."
    return out


def mask_email(address: object) -> str:
    """``alice@example.org`` -> ``a***@example.org`` (operator-configured recipients only)."""
    text = str(address).strip()
    local, sep, domain = text.partition("@")
    if not sep or not local:
        return "[address]"
    return f"{local[0]}***@{domain}"


def mask_emails_in(text: object) -> str:
    return _EMAIL.sub(lambda m: mask_email(m.group(0)), str(text))


def safe_exc(exc: BaseException) -> str:
    """``ValueError at pipeline.py:123 in _process_line`` - no message, no arguments."""
    where = ""
    tb = exc.__traceback__
    if tb is not None:
        frames = traceback.extract_tb(tb)
        if frames:
            last = frames[-1]
            base = last.filename.replace("\\", "/").rsplit("/", 1)[-1]
            where = f" at {base}:{last.lineno} in {last.name}"
    return f"{type(exc).__name__}{where}"


def sanitize_error(exc: object, *, limit: int = MAX_ERROR_CHARS) -> str:
    """Type name plus a scrubbed, truncated message, for operator-facing status text."""
    if isinstance(exc, BaseException):
        return f"{type(exc).__name__}: {scrub_text(exc, limit=limit)}"
    return scrub_text(exc, limit=limit)


class _DropBelowWarning(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


_DRIVER_LOGGERS = ("aiosqlite", "psycopg", "psycopg.pool")
_filter = _DropBelowWarning()


def quiet_driver_logs() -> None:
    """Database drivers log every statement *with its bound parameters* at DEBUG.
    In legacy mode those are raw identifiers; in every mode they are row contents.
    Keep them below WARNING and re-apply a filter so a later ``setLevel(DEBUG)``
    elsewhere cannot turn the parameter logging back on."""
    for name in _DRIVER_LOGGERS:
        lg = logging.getLogger(name)
        lg.setLevel(logging.WARNING)
        if _filter not in lg.filters:
            lg.addFilter(_filter)
