"""Turn the user's rows into validated, pseudonymized detector events.

Each row is translated to the detector's canonical field names, then handed to the project's own
:class:`~app.ingest.adapters.JsonLinesAdapter`, which normalizes the timestamp, replaces identifiers with
keyed pseudonyms **before** an event object exists, never copies free text, and validates the model.
Rejections carry the row number and a reason code only. Row values are never put in a message.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from app.config import AppConfig, SourceConfig
from app.ingest import reasons
from app.ingest.adapters import JsonLinesAdapter
from app.ingest.pseudonym import Pseudonymizer
from app.privacy.redaction import Redactor
from app.privacy.safe_log import scrub_text
from app.research.dataset import ParsedDataset, iter_good
from app.research.mapping import FIELD_SPECS, MappingSpec

MAX_REJECT_ROWS_PER_CODE = 20
MAX_UNMAPPED_VALUES = 20

_EPOCH = re.compile(r"^-?\d+(\.\d+)?$")
_LEVEL_AUTO = {"info": "INFO", "debug": "INFO", "trace": "INFO", "notice": "INFO",
               "warn": "WARN", "warning": "WARN",
               "error": "ERROR", "err": "ERROR", "fatal": "ERROR", "critical": "ERROR", "severe": "ERROR"}
_OUTCOME_AUTO = {"success": "success", "succeeded": "success", "ok": "success",
                 "failure": "failure", "failed": "failure", "fail": "failure", "denied": "failure"}
_CANON = {
    "service": {"prior_auth", "eligibility", "pharmacy", "claims", "batch"},
    "priority": {"urgent", "routine"},
    "action": {"VIEW_RECORD", "EDIT_RECORD", "EXPORT_RECORDS", "SEARCH"},
}


@dataclass
class Point:
    ts: datetime
    entity: str
    positive: bool


@dataclass
class Conversion:
    lines: list[str] = field(default_factory=list)          # detector-format JSON lines, time ordered
    points: list[Point] = field(default_factory=list)       # same order: (time, entity, labelled anomaly?)
    rows_total: int = 0
    rows_accepted: int = 0
    rejects: Counter = field(default_factory=Counter)
    reject_rows: dict[str, list[int]] = field(default_factory=dict)     # code -> first row numbers
    unmapped: dict[str, list[str]] = field(default_factory=dict)        # field -> values that could not be interpreted
    warnings: list[str] = field(default_factory=list)
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    out_of_order: int = 0
    label_missing: int = 0
    labelled_rows_rejected: int = 0


def _norm_key(text: str) -> str:
    return re.sub(r"[\s\-]+", "_", text.strip()).lower()


def _enum(field_name: str, raw: str, spec: MappingSpec) -> Optional[str]:
    """Canonical value for ``raw``, or None. The user's explicit value map wins over the built-in matching."""
    explicit = spec.values.get(field_name, {})
    if raw in explicit:
        return explicit[raw]
    lowered = {k.strip().lower(): v for k, v in explicit.items()}
    if raw.strip().lower() in lowered:
        return lowered[raw.strip().lower()]
    key = _norm_key(raw)
    if field_name == "level":
        return _LEVEL_AUTO.get(key)
    if field_name == "outcome":
        return _OUTCOME_AUTO.get(key)
    if field_name == "action":
        up = key.upper()
        return up if up in _CANON["action"] else None
    if key in _CANON.get(field_name, ()):
        return key
    return None


def _num(raw: Any) -> Optional[float]:
    if isinstance(raw, bool):
        return None
    try:
        v = float(str(raw).strip())
    except ValueError:
        return None
    return v if v == v and abs(v) != float("inf") else None


def build_adapter(spec: MappingSpec, config: AppConfig, pseudonymizer: Pseudonymizer, redactor: Redactor) -> JsonLinesAdapter:
    names = [f["name"] for f in FIELD_SPECS[spec.kind]]
    cfg = SourceConfig(id="upload", path="upload", kind=spec.kind, timezone=spec.timezone,
                       fields={n: n for n in names if n != "msg"})
    return JsonLinesAdapter(cfg, pseudonymizer=pseudonymizer, redact_text=redactor.redact_text,
                            services=set(config.services), max_future_skew=None)


def _record(row: dict[str, Any], row_no: int, spec: MappingSpec, conv: Conversion) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Canonical record for one row, or (None, reason code)."""
    rec: dict[str, Any] = {}
    cols = spec.columns

    def get(name: str) -> Any:
        col = cols.get(name)
        if col is None:
            return spec.defaults.get(name)
        v = row.get(col)
        return None if v is None or (isinstance(v, str) and not v.strip()) else v

    def note_unmapped(name: str, raw: Any) -> None:
        bucket = conv.unmapped.setdefault(name, [])
        shown = scrub_text(str(raw), limit=60)
        if shown not in bucket and len(bucket) < MAX_UNMAPPED_VALUES:
            bucket.append(shown)

    ts_raw = row.get(cols["ts"]) if "ts" in cols else None
    if isinstance(ts_raw, str) and _EPOCH.match(ts_raw.strip()):
        ts_raw = float(ts_raw.strip())          # CSV cells are text: an epoch number arrives as a string
    rec["ts"] = ts_raw
    if spec.kind == "app":
        svc = get("service")
        if svc is not None:
            canon = _enum("service", str(svc), spec)
            if canon is None:
                note_unmapped("service", svc)
                return None, reasons.UNKNOWN_SERVICE
            rec["service"] = canon
        level, status = get("level"), get("status")
        lvl = None
        if level is not None:
            lvl = _enum("level", str(level), spec)
            if lvl is None:
                note_unmapped("level", level)
                return None, reasons.BAD_VALUE
        st: Optional[int] = None
        if status is not None:
            n = _num(status)
            if n is None or not 100 <= n <= 599:
                return None, reasons.BAD_VALUE
            st = int(n)
        if lvl is None and st is not None:
            lvl = "ERROR" if st >= 500 else "WARN" if st >= 400 else "INFO"
        if st is None and lvl is not None:
            st = 500 if lvl == "ERROR" else 200
        if lvl is None or st is None:
            return None, reasons.MISSING_FIELD
        rec["level"], rec["status"] = lvl, st
        latency = get("latency_ms")
        if latency is None:
            rec["latency_ms"] = 0
        else:
            n = _num(latency)
            if n is None or n < 0:
                return None, reasons.BAD_VALUE
            rec["latency_ms"] = int(round(n))
        prio = get("priority")
        if prio is None:
            rec["priority"] = "routine"
        else:
            canon = _enum("priority", str(prio), spec)
            if canon is None:
                note_unmapped("priority", prio)
                return None, reasons.BAD_VALUE
            rec["priority"] = canon
        rid = get("request_id")
        rec["request_id"] = str(rid) if rid is not None else f"row-{row_no}"
        pid = get("patient_id")
        if pid is not None:
            rec["patient_id"] = str(pid)
        rec["msg"] = ""
    else:
        for name in ("user_id", "patient_id", "source_ip"):
            v = get(name)
            if v is not None:
                rec[name] = str(v)
        if spec.kind == "audit":
            act = get("action")
            canon = _enum("action", str(act), spec) if act is not None else None
            if canon is None:
                if act is not None:
                    note_unmapped("action", act)
                return None, reasons.BAD_VALUE if act is not None else reasons.MISSING_FIELD
            rec["action"] = canon
            for name in ("role", "patient_region", "user_region"):
                v = get(name)
                rec[name] = str(v) if v is not None else "unknown"
        else:
            out = get("outcome")
            canon = _enum("outcome", str(out), spec) if out is not None else None
            if canon is None:
                if out is not None:
                    note_unmapped("outcome", out)
                return None, reasons.BAD_VALUE if out is not None else reasons.MISSING_FIELD
            rec["outcome"] = canon
            for name, default in (("method", "password"), ("source_region", "unknown"), ("user_region", "unknown")):
                v = get(name)
                rec[name] = str(v) if v is not None else default
    return rec, None


def convert(ds: ParsedDataset, spec: MappingSpec, *, config: AppConfig, pseudonymizer: Pseudonymizer,
            redactor: Redactor) -> Conversion:
    adapter = build_adapter(spec, config, pseudonymizer, redactor)
    label = spec.label
    positives = {p.strip().lower() for p in label.positive_values} if label else set()
    conv = Conversion()
    rows: list[tuple[datetime, int, str, Point]] = []

    for n, rec, err in ds.rows:
        conv.rows_total += 1
        if err is not None:
            _reject(conv, err, n)
            continue
        assert rec is not None
        canonical, reason = _record(rec, n, spec, conv)
        is_positive = False
        if label is not None:
            raw_label = rec.get(label.column)
            if raw_label is None or str(raw_label).strip() == "":
                conv.label_missing += 1
            else:
                is_positive = str(raw_label).strip().lower() in positives
        if canonical is None:
            _reject(conv, reason or reasons.SCHEMA_INVALID, n)
            if is_positive:
                conv.labelled_rows_rejected += 1
            continue
        result = adapter.parse(json.dumps(canonical))
        if result.event is None:
            _reject(conv, result.reason or reasons.SCHEMA_INVALID, n)
            if is_positive:
                conv.labelled_rows_rejected += 1
            continue
        event = result.event
        entity = event.service if spec.kind == "app" else event.user_id  # type: ignore[union-attr]
        line = json.dumps(event.model_dump(mode="json"))
        rows.append((event.ts, n, line, Point(event.ts, entity, is_positive)))
        conv.rows_accepted += 1

    last: Optional[datetime] = None
    for ts, _, _, _ in rows:
        if last is not None and ts < last:
            conv.out_of_order += 1
        last = ts if last is None or ts > last else last
    rows.sort(key=lambda r: (r[0], r[1]))            # stable: ties keep file order
    conv.lines = [r[2] for r in rows]
    conv.points = [r[3] for r in rows]
    if rows:
        conv.first_ts, conv.last_ts = rows[0][0], rows[-1][0]
    _warnings(conv, spec, ds)
    return conv


def _reject(conv: Conversion, code: str, row_no: int) -> None:
    conv.rejects[code] += 1
    bucket = conv.reject_rows.setdefault(code, [])
    if len(bucket) < MAX_REJECT_ROWS_PER_CODE:
        bucket.append(row_no)


def _warnings(conv: Conversion, spec: MappingSpec, ds: ParsedDataset) -> None:
    w = conv.warnings
    if ds.truncated:
        w.append("The file has more rows than the configured limit; only the first rows were read.")
    if spec.kind == "app":
        if "latency_ms" not in spec.columns:
            w.append("Latency is not mapped: latency anomalies cannot be detected (latency is treated as 0).")
        if "patient_id" not in spec.columns:
            w.append("No patient identifier mapped: patient-impact scoring has nothing to count, so severity rests on criticality alone.")
        if "priority" not in spec.columns and "priority" not in spec.defaults:
            w.append("Priority is not mapped: every event is treated as routine.")
    if spec.kind == "audit" and not ({"patient_region", "user_region"} <= set(spec.columns)):
        w.append("Both regions are not mapped: region-mismatch detection is effectively disabled.")
    if spec.kind == "auth" and not ({"source_region", "user_region"} <= set(spec.columns)):
        w.append("Both regions are not mapped: the unfamiliar-region signal is effectively disabled.")
    if conv.out_of_order:
        w.append(f"{conv.out_of_order} rows were out of time order; events were sorted by timestamp before detection.")
    if conv.first_ts and conv.last_ts and (conv.last_ts - conv.first_ts).total_seconds() < 300:
        w.append("The data spans under 5 minutes. The detector needs about 2 minutes of normal traffic to learn a baseline "
                 "before it can flag anything, so little can be detected.")
    if spec.label is not None:
        if conv.label_missing:
            w.append(f"{conv.label_missing} rows have an empty label and are treated as normal.")
        if conv.labelled_rows_rejected:
            w.append(f"{conv.labelled_rows_rejected} rows labelled as anomalies were rejected and are not part of the ground truth.")
