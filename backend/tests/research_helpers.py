"""Synthetic datasets in a *foreign* schema (not the project's own), for the user-dataset tests.

Everything is generated with the project's synthetic generator and then renamed, so no real data is involved.
Sentinel strings are planted in identifier and free-text columns so the privacy tests can prove they never
reach a result, a log line, an error message or a stored record.
"""

from __future__ import annotations

import csv
import io
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

from generator import generate as gen

START = datetime(2026, 3, 10, 9, 0, 0, tzinfo=timezone.utc)
SENTINEL_PATIENT = "MRN-SENTINEL-4471"
SENTINEL_USER = "alice.sentinel@example.org"
SENTINEL_NOTE = "patient John Sentinel Doe called about results"

SERVICE_NAMES = {"eligibility": "ELIGIBILITY", "prior_auth": "Prior-Auth", "pharmacy": "RX", "claims": "claims", "batch": "batch"}
LEVELS = {"INFO": "info", "WARN": "warning", "ERROR": "error"}

APP_COLUMNS = ["Time", "Component", "Severity", "HTTP", "Duration_ms", "Urgency", "PatientRef", "ReqID", "Notes", "Flag"]

APP_MAPPING = {
    "kind": "app",
    "columns": {"ts": "Time", "service": "Component", "level": "Severity", "status": "HTTP", "latency_ms": "Duration_ms",
                "priority": "Urgency", "patient_id": "PatientRef", "request_id": "ReqID"},
    "values": {"service": {"RX": "pharmacy"}},
    "timezone": "UTC",
}


def app_rows(*, seed: int = 7, rate: float = 10.0, warmup: int = 900, inject: int = 180, tail: int = 420,
             scenario: Optional[str] = "eligibility_outage") -> list[dict]:
    rng = random.Random(seed)
    inject_start = START + timedelta(seconds=warmup)
    inject_end = inject_start + timedelta(seconds=inject)
    events: list[dict] = []
    for name, start, dur in ((None, START, warmup), (scenario, inject_start, inject), (None, inject_end, tail)):
        app, _, _ = gen.generate_events(name, dur, rate, start, rng)
        events += app
    events.sort(key=lambda e: e["ts"])
    rows = []
    for i, e in enumerate(events):
        ts = datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
        in_window = inject_start <= ts < inject_end and e["service"] == "eligibility" and scenario is not None
        rows.append({
            "Time": e["ts"], "Component": SERVICE_NAMES[e["service"]], "Severity": LEVELS[e["level"]], "HTTP": e["status"],
            "Duration_ms": e["latency_ms"], "Urgency": e["priority"],
            "PatientRef": f"{SENTINEL_PATIENT}-{e['patient_id']}" if e["patient_id"] else "",
            "ReqID": f"{SENTINEL_USER}-{i}", "Notes": SENTINEL_NOTE, "Flag": "1" if in_window else "0",
        })
    return rows


def to_csv(rows: list[dict], columns: Optional[list[str]] = None, delimiter: str = ",") -> bytes:
    cols = columns or list(rows[0])
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=cols, delimiter=delimiter, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode("utf-8")


def to_jsonl(rows: list[dict]) -> bytes:
    return ("\n".join(json.dumps({"event": {"time": r["Time"], "svc": r["Component"], "sev": r["Severity"]},
                                  "http": r["HTTP"], "ms": r["Duration_ms"], "flag": r["Flag"]}) for r in rows) + "\n").encode("utf-8")


def small_csv(n: int = 40, **replace) -> bytes:
    """A handful of valid rows (too little data to detect anything) for validation tests."""
    rows = []
    for i in range(n):
        row = {"Time": (START + timedelta(seconds=i)).isoformat().replace("+00:00", "Z"), "Component": "claims",
               "Severity": "info", "HTTP": 200, "Duration_ms": 120, "Urgency": "routine", "PatientRef": f"{SENTINEL_PATIENT}-{i}",
               "ReqID": f"r{i}", "Notes": SENTINEL_NOTE, "Flag": "0"}
        row.update(replace)
        rows.append(row)
    return to_csv(rows)
