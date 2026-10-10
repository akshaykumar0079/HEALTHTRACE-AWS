"""A fixed synthetic data set that exercises every correlation rule.

All identifiers are invented (``P-`` patient ids, RFC 5737 addresses, hosts
under ``.example``). Used by the demo endpoint and the tests; it is not a
claim that any real system produces these records.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

T0 = datetime(2026, 3, 10, 16, 0, 0, tzinfo=timezone.utc)


def _t(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def demo_records() -> list[tuple[str, dict[str, Any]]]:
    recs: list[tuple[str, dict[str, Any]]] = []
    # 1. U-064: two failed logins, a successful one, then DB and application record access (valid chain).
    recs += [
        ("auth", {"id": "a1", "ts": _t(0), "user_id": "U-064", "outcome": "failure"}),
        ("auth", {"id": "a2", "ts": _t(30), "user_id": "U-064", "outcome": "failure"}),
        ("auth", {"id": "a3", "ts": _t(90), "user_id": "U-064", "outcome": "success"}),
        ("db_audit", {"id": "d1", "ts": _t(150), "db_user": "U-064", "statement_type": "SELECT",
                      "object": "patients", "rows": 300}),
        ("audit", {"id": "u1", "ts": _t(160), "user_id": "U-064", "action": "VIEW_RECORD", "patient_id": "P-100001"}),
    ]
    # 2. One request traced through app, server and db audit by request id.
    recs += [
        ("app", {"id": "p1", "ts": _t(400), "service": "eligibility", "level": "ERROR", "status": 503,
                 "request_id": "req-7001", "host": "app-1.example", "msg": "Eligibility lookup failed",
                 "patient_id": "P-100002"}),
        ("server", {"id": "s1", "ts": _t(405), "host": "app-1.example", "process": "eligibility-worker",
                    "level": "ERROR", "message": "upstream timeout", "request_id": "req-7001"}),
        ("db_audit", {"id": "d2", "ts": _t(410), "db_user": "svc-eligibility", "statement_type": "SELECT",
                      "object": "P-100002", "request_id": "req-7001"}),
    ]
    # 3. Unrelated noise: same minute, nothing in common. Must stay unlinked.
    recs += [
        ("auth", {"id": "a9", "ts": _t(402), "user_id": "U-200", "outcome": "success"}),
        ("server", {"id": "s9", "ts": _t(403), "host": "app-9.example", "process": "cron", "level": "WARN",
                    "message": "disk 81% full"}),
        ("app", {"id": "p9", "ts": _t(404), "service": "claims", "level": "INFO", "status": 200,
                 "request_id": "req-9999", "host": "app-5.example", "msg": "ok"}),
    ]
    # 4. A late-arriving database audit entry that belongs with U-064's activity.
    recs += [
        ("db_audit", {"id": "d3", "ts": _t(200), "received_at": _t(1500), "db_user": "U-064",
                      "statement_type": "EXPORT", "object": "claims", "rows": 5000}),
    ]
    # 5. Missing fields: no actor, no request id. Reported, not guessed.
    recs += [
        ("auth", {"id": "a8", "ts": _t(500), "outcome": "success"}),
        ("db_audit", {"id": "d8", "ts": _t(505), "statement_type": "SELECT", "object": "patients"}),
    ]
    return recs
