"""Stable rejection reason codes (docs/ingestion.md).

Codes are part of the operator-facing contract: dashboards, metrics and tests
refer to them by value, so they are never renamed. New codes may be added.
A rejection records *that* a line was refused and *why*, never its content.
"""

from __future__ import annotations

# Transport / framing
LINE_TOO_LONG = "line_too_long"
# Parsing
INVALID_JSON = "invalid_json"
NOT_AN_OBJECT = "not_an_object"
UNKNOWN_TYPE = "unknown_type"
SCHEMA_INVALID = "schema_invalid"
MISSING_FIELD = "missing_field"
BAD_VALUE = "bad_value"
# Timestamps
TS_INVALID = "ts_invalid"
TS_NO_TZ = "ts_no_tz"
TS_AMBIGUOUS = "ts_ambiguous"
TS_SKEW = "ts_skew"
# Mapping
UNKNOWN_SERVICE = "unknown_service"
# Pseudonymization (configured mode)
PSEUDONYM_UNAVAILABLE = "pseudonym_unavailable"
# Deduplication is a drop, not a rejection, but is counted under its own code.
DUPLICATE = "duplicate"

ALL_CODES = frozenset({
    LINE_TOO_LONG, INVALID_JSON, NOT_AN_OBJECT, UNKNOWN_TYPE, SCHEMA_INVALID, MISSING_FIELD, BAD_VALUE,
    TS_INVALID, TS_NO_TZ, TS_AMBIGUOUS, TS_SKEW, UNKNOWN_SERVICE, PSEUDONYM_UNAVAILABLE, DUPLICATE,
})
