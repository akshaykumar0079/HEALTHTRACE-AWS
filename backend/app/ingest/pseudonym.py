"""Keyed pseudonymization at the configured ingestion boundary (docs/ingestion.md).

Identifiers that detection needs only for *grouping* (who, which patient, which
address) are replaced with a keyed HMAC-SHA256 digest **before** an event object
exists, so the raw value never reaches a detector, the database, the API, the
WebSocket, a log line or a notification.

* The key comes from the environment (``PSEUDONYM_KEY``), is never hard-coded,
  never stored in the database, never logged, and held as a ``SecretStr``.
* There is **no fallback**: configured ingestion refuses to start without a
  valid key (:class:`IngestConfigError`), instead of quietly passing raw values.
* The same value always maps to the same pseudonym (so a repeat offender is still
  one actor), a different key maps it differently, and the mapping is not
  reversible without the key. Re-identification is a deliberate, out-of-band
  step performed by an authorized person who holds the key and the source logs;
  this application keeps no lookup table.
* Domain separation: the same text as a user id and as an IP gives different
  pseudonyms, so values cannot be cross-linked by accident.

Pseudonyms are *not anonymization*: anyone with the key (or a dictionary of
candidate identifiers and the key) can recompute them. Protect the key like a
credential and rotate it with a documented procedure (rotation changes every
pseudonym; open incidents keep the old ones).
"""

from __future__ import annotations

import hashlib
import hmac
import string
from typing import Any, Optional

MIN_KEY_CHARS = 32
DIGEST_HEX_CHARS = 12  # 48 bits: collisions are negligible at hospital scale, and short enough to read


class IngestConfigError(RuntimeError):
    """Configured ingestion cannot start safely. The message never contains the
    key or any value taken from the key."""


def load_key(raw: Optional[str]) -> bytes:
    """Validate and return the key bytes, or raise :class:`IngestConfigError`."""
    if raw is None or not str(raw).strip():
        raise IngestConfigError(
            "PSEUDONYM_KEY is not set. Configured ingestion will not run without it "
            "(it will not fall back to raw identifiers). Generate one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    key = str(raw).strip()
    if len(key) < MIN_KEY_CHARS:
        raise IngestConfigError(f"PSEUDONYM_KEY is too short: at least {MIN_KEY_CHARS} characters are required")
    if len(set(key)) < 8 or key.lower() in {c * len(key) for c in string.printable}:
        raise IngestConfigError("PSEUDONYM_KEY has too little variety; generate a random key")
    if any(marker in key.lower() for marker in ("changeme", "change-me", "your-key", "example", "placeholder")):
        raise IngestConfigError("PSEUDONYM_KEY looks like a placeholder; generate a random key")
    return key.encode("utf-8")


class Pseudonymizer:
    def __init__(self, key: bytes) -> None:
        if not key or len(key) < MIN_KEY_CHARS:
            raise IngestConfigError("pseudonymizer requires a validated key")
        self._key = key

    @classmethod
    def from_setting(cls, raw: Optional[str]) -> "Pseudonymizer":
        return cls(load_key(raw))

    @property
    def key(self) -> bytes:
        """Exposed only so other keyed components (event-id and content digests)
        can derive from the same secret; never log or serialize it."""
        return self._key

    def _digest(self, domain: str, value: Any) -> str:
        text = str(value).strip()
        if not text:
            raise ValueError("empty identifier")
        mac = hmac.new(self._key, f"{domain}\x00{text}".encode("utf-8"), hashlib.sha256).hexdigest()
        return mac[:DIGEST_HEX_CHARS]

    def user(self, value: Any) -> str:
        return "U-" + self._digest("user", value)

    def patient(self, value: Any) -> str:
        return "P-" + self._digest("patient", value)

    def ip(self, value: Any) -> str:
        return "ip-" + self._digest("ip", value)

    def request(self, value: Any) -> str:
        """Request/correlation ids are usually opaque but can embed an identifier;
        the keyed digest keeps them joinable across sources without exposing it."""
        return "req-" + self._digest("request", value)

    def fingerprint(self) -> str:
        """A short one-way tag of the key (HMAC of a fixed label). Safe to store and show:
        it lets an operator confirm two deployments use the same key, and lets the
        application notice that the key changed. It is not a pseudonym of anything."""
        return hmac.new(self._key, b"healthtrace:key-fingerprint:v1", hashlib.sha256).hexdigest()[:16]

    def __repr__(self) -> str:  # never reveal key material
        return "Pseudonymizer(key=<hidden>)"
