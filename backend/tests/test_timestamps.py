"""Stage B regression tests: timestamp normalization (audit section 1.5)."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.config import load_config
from app.ingest import reasons
from app.ingest.timestamps import TimestampError, normalize_ts, resolve_timezone
from app.parse.parser import Parser
from app.pipeline import Pipeline
from app.simulation.runner import _isolated_settings

UTC = timezone.utc
T = datetime(2026, 3, 10, 16, 0, 0, tzinfo=UTC)


def code(value, **kw) -> str:
    with pytest.raises(TimestampError) as e:
        normalize_ts(value, **kw)
    return e.value.code


@pytest.mark.parametrize("value", [
    "2026-03-10T16:00:00Z",
    "2026-03-10T16:00:00+00:00",
    "2026-03-10T21:30:00+05:30",
    "2026-03-10T11:00:00-05:00",
    " 2026-03-10T16:00:00Z ",
    1773158400,
    1773158400.0,
    1773158400000,           # epoch milliseconds
    T,
    datetime(2026, 3, 10, 21, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
])
def test_equivalent_forms_normalize_to_the_same_utc_instant(value):
    out = normalize_ts(value)
    assert out == T and out.utcoffset() == timedelta(0) and out.tzinfo is not None


def test_naive_without_default_is_rejected_not_guessed():
    assert code("2026-03-10T16:00:00") == reasons.TS_NO_TZ
    assert code(datetime(2026, 3, 10, 16, 0)) == reasons.TS_NO_TZ


def test_naive_uses_the_configured_source_timezone():
    kolkata = resolve_timezone("Asia/Kolkata")
    assert normalize_ts("2026-03-10T21:30:00", default_tz=kolkata) == T
    assert normalize_ts("2026-03-10T16:00:00", default_tz=resolve_timezone("UTC")) == T
    # An explicit offset always wins over the default zone.
    assert normalize_ts("2026-03-10T16:00:00Z", default_tz=kolkata) == T


def test_legacy_switch_assumes_utc():
    assert normalize_ts("2026-03-10T16:00:00", assume_utc_if_naive=True) == T


def test_dst_gap_and_overlap_are_rejected():
    chicago = resolve_timezone("America/Chicago")
    assert code("2026-03-08T02:30:00", default_tz=chicago) == reasons.TS_INVALID      # spring forward: never happens
    assert code("2026-11-01T01:30:00", default_tz=chicago) == reasons.TS_AMBIGUOUS    # fall back: happens twice
    assert normalize_ts("2026-11-01T03:30:00", default_tz=chicago) == datetime(2026, 11, 1, 9, 30, tzinfo=UTC)
    assert normalize_ts("2026-07-01T12:00:00", default_tz=chicago) == datetime(2026, 7, 1, 17, 0, tzinfo=UTC)


@pytest.mark.parametrize("value", [
    None, True, False, "", "   ", "yesterday", "2026-13-40T00:00:00Z", "10/03/2026", [], {}, b"2026",
    float("nan"), float("inf"), -float("inf"), 0, -1, 10**30, "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z",
])
def test_invalid_values_are_rejected_with_ts_invalid(value):
    assert code(value) == reasons.TS_INVALID


def test_future_skew_rejected_past_accepted():
    now = T
    assert normalize_ts(T + timedelta(minutes=4), max_future_skew=timedelta(minutes=5), now=now)
    assert code(T + timedelta(minutes=6), max_future_skew=timedelta(minutes=5), now=now) == reasons.TS_SKEW
    # History replay is legitimate: old timestamps are never "skew".
    assert normalize_ts(T - timedelta(days=400), max_future_skew=timedelta(minutes=5), now=now)


def test_unknown_timezone_name_fails_loudly():
    with pytest.raises(ValueError):
        resolve_timezone("Mars/Olympus")
    assert resolve_timezone("") is None and resolve_timezone(None) is None


# -- legacy parser: no exceptions, reason codes, counters ---------------------------------

def _auth(ts, user="U-9", outcome="failure", reg="RU"):
    return json.dumps({"ts": ts, "type": "auth", "user_id": user, "outcome": outcome,
                       "source_region": reg, "user_region": "IN", "source_ip": "192.0.2.5"})


def test_parser_reason_codes_and_counters():
    p = Parser()
    assert p.parse("not json").reason == reasons.INVALID_JSON
    assert p.parse("[1,2]").reason == reasons.NOT_AN_OBJECT
    assert p.parse('{"type":"syslog"}').reason == reasons.UNKNOWN_TYPE
    assert p.parse('{"type":"auth"}').reason == reasons.MISSING_FIELD
    assert p.parse(_auth("nonsense")).reason == reasons.TS_INVALID
    assert p.parse(_auth("2026-03-10T16:00:00Z", outcome="denied")).reason == reasons.BAD_VALUE
    bad_service = json.dumps({"ts": "2026-03-10T16:00:00Z", "type": "app", "service": "radiology", "level": "ERROR",
                              "priority": "urgent", "request_id": "r", "status": 500, "latency_ms": 3, "msg": "x"})
    assert p.parse(bad_service).reason == reasons.UNKNOWN_SERVICE
    ok = p.parse(_auth("2026-03-10T21:30:00+05:30"))
    assert ok.event is not None and ok.event.ts == T and ok.event.ts.utcoffset() == timedelta(0)
    assert p.malformed_lines == 7 and sum(p.reject_counts.values()) == 7
    # The legacy wrapper is unchanged for existing callers.
    assert p.parse_line(_auth("2026-03-10T16:00:00Z")) is not None


def test_legacy_parser_counts_naive_timestamps_assumed_utc():
    p = Parser()
    r = p.parse(_auth("2026-03-10T16:00:00"))
    assert r.event is not None and r.event.ts == T
    assert p.naive_assumed_utc == 1 and p.malformed_lines == 0


# -- pipeline regression: the audited TypeError ------------------------------------------

async def _run(lines: list[str]):
    work = Path(tempfile.mkdtemp())
    (work / "logs").mkdir()
    pl = Pipeline(_isolated_settings(work), load_config())
    await pl.store.connect()
    await pl.baseline.load(pl.store)
    errors = []
    for line in lines:
        try:
            await pl._process_line(line)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
    kinds = [(i.kind, i.peak_severity) for i in pl.incidents.list_incidents()]
    await pl.store.close()
    return kinds, errors


async def test_naive_failures_then_aware_success_still_alerts_without_exceptions():
    """Audit: 5 naive-ts failures then an aware success raised TypeError and raised no alert."""
    fails = [_auth(f"2026-03-10T16:0{i}:00") for i in range(5)]          # naive
    success = _auth("2026-03-10T16:06:00Z", outcome="success")            # aware
    kinds, errors = await _run(fails + [success])
    assert errors == []
    assert kinds == [("auth_suspicious_login", "HIGH")]


async def test_mixed_offsets_compare_on_the_utc_timeline():
    # 21:30+05:30 == 16:00Z: the failures are within the window only if offsets are honoured.
    fails = [_auth(f"2026-03-10T21:3{i}:00+05:30") for i in range(5)]
    success = _auth("2026-03-10T16:06:00Z", outcome="success")
    kinds, errors = await _run(fails + [success])
    assert errors == [] and kinds == [("auth_suspicious_login", "HIGH")]
