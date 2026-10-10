"""Configurable sensitive-field redaction.

Applied at three points (docs/privacy-and-retention.md):

* **before storage** - evidence records are redacted before they are written;
* **before display** - API read models redact again, so rows stored under an
  older/looser configuration are still masked when shown;
* **before external transmission** - email and CloudWatch/SNS text pass
  through ``redact_text``.

Defaults are conservative. ``REDACTION_ENABLED=false`` turns it off and the
security status endpoint then reports a warning.

Redaction is pattern/field based: it reduces accidental exposure, it does not
prove that a log line is free of identifiers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

REDACTED = "[REDACTED]"

# Keys whose value is always replaced outright (compared case-insensitively).
DEFAULT_FIELDS = frozenset({
    "ssn", "social_security_number", "dob", "date_of_birth", "email", "phone", "phone_number", "address",
    "street", "name", "full_name", "first_name", "last_name", "mrn", "medical_record_number", "insurance_id",
    "member_id", "password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "cookie",
    "diagnosis", "notes", "free_text",
})

# (name, pattern, replacement)
DEFAULT_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]"),
    ("phone", r"(?<!\d)(?:\+?1[ -.]?)?\(?\d{3}\)?[ -.]\d{3}[ -.]\d{4}(?!\d)", "[PHONE]"),
    ("card", r"\b(?:\d[ -]?){12,15}\d\b", "[CARD]"),
    ("mrn", r"(?i)\bMRN[:# ]*\d{4,}\b", "[MRN]"),
    ("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer [REDACTED]"),
    ("api_key", r"\bxkeysib-[A-Za-z0-9-]{10,}|\bxsmtpsib-[A-Za-z0-9-]{10,}|\bAKIA[0-9A-Z]{16}\b", "[KEY]"),
)

# Full patient identifiers (P-123456) are masked as P-****56 by the pipeline;
# anything still unmasked is masked here, whatever field it appears in.
_PATIENT_ID = re.compile(r"\bP-(\d{4})(\d{2})\b")


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass
class Redactor:
    enabled: bool = True
    fields: frozenset[str] = DEFAULT_FIELDS
    patterns: list[tuple[str, "re.Pattern[str]", str]] = field(default_factory=list)

    @classmethod
    def build(cls, *, enabled: bool = True, extra_fields: Iterable[str] = (),
              extra_patterns: Iterable[str] = ()) -> "Redactor":
        """Raises ``ValueError`` for an invalid extra pattern, so a typo in
        configuration fails at start-up instead of silently not redacting."""
        patterns = [(n, re.compile(p), r) for n, p, r in DEFAULT_PATTERNS]
        for i, raw in enumerate(p for p in extra_patterns if p.strip()):
            try:
                patterns.append((f"custom{i + 1}", re.compile(raw.strip()), REDACTED))
            except re.error as exc:
                raise ValueError(f"invalid redaction pattern {raw!r}: {exc}") from exc
        fields = DEFAULT_FIELDS | frozenset(f.strip().lower() for f in extra_fields if f.strip())
        return cls(enabled=enabled, fields=fields, patterns=patterns)

    # -- text ---------------------------------------------------------------

    def redact_text(self, text: Optional[str]) -> Optional[str]:
        if not self.enabled or not text:
            return text
        out = _PATIENT_ID.sub(lambda m: f"P-****{m.group(2)}", text)
        for name, pattern, replacement in self.patterns:
            if name == "card":  # only real card numbers (Luhn), not timestamps or ids
                out = pattern.sub(lambda m, r=replacement: r if _luhn_ok(m.group(0)) else m.group(0), out)
            else:
                out = pattern.sub(replacement, out)
        return out

    # -- structures ---------------------------------------------------------

    def redact_value(self, value: Any, key: Optional[str] = None) -> Any:
        if not self.enabled:
            return value
        if key is not None and key.lower() in self.fields and value not in (None, "", False, 0):
            return REDACTED
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {k: self.redact_value(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact_value(v) for v in value]
        return value

    def redact_record(self, record: dict[str, Any]) -> dict[str, Any]:
        return self.redact_value(record) if self.enabled else record

    def redact_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.redact_record(r) for r in records] if self.enabled else records
