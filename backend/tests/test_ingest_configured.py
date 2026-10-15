"""Stage D tests: configured source registry and JSON-lines adapter (explicit
mapping, safe paths, fail-closed configuration, event-id de-duplication,
generator_v1 preserved). Synthetic fixtures only."""

from __future__ import annotations

import asyncio
import json
import os
import socket
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.config import SourceConfig
from app.ingest import reasons
from app.ingest.pseudonym import IngestConfigError
from app.main import create_app
from app.pipeline import Pipeline
from app.simulation.runner import build_stream
from app.simulation.scenarios import SCENARIOS
from tests.ingest_helpers import (
    APP_SRC, AUDIT_SRC, AUTH_SRC, KEY, claims, config_for, ehr, failures_then_success, idp, incidents, iso,
    make_pipeline, now, settings_for,
)


def rejects(p: Pipeline, source: str) -> dict[str, int]:
    return p.quarantine.by_reason(source)


# -- mapping: same alert as the synthetic schema -----------------------------------------------

async def test_differently_named_source_produces_the_same_incident_as_the_synthetic_schema():
    p = await make_pipeline()
    for line in failures_then_success(now() - timedelta(minutes=5)):
        await p._process_line(line, "idp_fixture")
    assert incidents(p) == [("auth_suspicious_login", "HIGH")]
    assert p.events_processed["auth"] == 6 and p.quarantine.total() == 0
    await p.store.close()


async def test_audit_and_app_sources_map_into_the_existing_events():
    p = await make_pipeline()
    t = now() - timedelta(minutes=1)
    await p._process_line(ehr(t, "nurse.a", "READ", "MRN-777", eid="e1"), "ehr_audit_fixture")
    await p._process_line(claims(t, eid="c1", lvl="error", http=503, message="eligibility timeout"), "claims_app_fixture")
    assert p.events_processed["audit"] == 1 and p.events_processed["app"] == 1
    log = {r["type"]: r for r in p.recent_logs}
    assert log["audit"]["action"] == "VIEW_RECORD" and log["app"]["service"] == "claims" and log["app"]["is_error"]
    await p.store.close()


# -- rejection reason codes ------------------------------------------------------------------

async def test_unknown_service_is_rejected_until_mapped():
    p = await make_pipeline()
    t = now()
    await p._process_line(claims(t, eid="1", svc="radiology-pacs"), "claims_app_fixture")
    assert rejects(p, "claims_app_fixture") == {reasons.UNKNOWN_SERVICE: 1} and p.events_processed["app"] == 0
    # An explicit mapping makes the same line acceptable.
    mapped = dict(APP_SRC, values={**APP_SRC["values"], "service": {"radiology-pacs": "eligibility"}})
    q = await make_pipeline(srcs=[mapped])
    await q._process_line(claims(t, eid="1", svc="radiology-pacs"), "claims_app_fixture")
    assert q.events_processed["app"] == 1 and q.quarantine.total() == 0
    # A name that is already a configured canonical service is accepted as-is.
    await q._process_line(claims(t, eid="2", svc="claims"), "claims_app_fixture")
    assert q.events_processed["app"] == 2
    await p.store.close(); await q.store.close()


async def test_every_rejection_has_a_stable_code():
    p = await make_pipeline()
    t = now()
    cases = {
        "not json": reasons.INVALID_JSON,
        "[1]": reasons.NOT_AN_OBJECT,
        json.dumps({"@timestamp": iso(t), "actor": {"name": "u"}}): reasons.MISSING_FIELD,
        idp(t, "u", "Weird", eid="x"): reasons.BAD_VALUE,                         # unmapped outcome value
        json.dumps({"@timestamp": "2026-03-10T16:00:00", "event": {"outcome": "Failure"}, "actor": {"name": "u", "home_geo": "IN"},
                    "client": {"geo": "IN"}}): reasons.TS_NO_TZ,
        json.dumps({"@timestamp": "garbage", "event": {"outcome": "Failure"}, "actor": {"name": "u", "home_geo": "IN"},
                    "client": {"geo": "IN"}}): reasons.TS_INVALID,
        idp(t + timedelta(hours=2), "u", "Failure", eid="x"): reasons.TS_SKEW,    # beyond the 300 s future bound
    }
    for line, expected in cases.items():
        before = p.quarantine.by_reason("idp_fixture").get(expected, 0)
        await p._process_line(line, "idp_fixture")
        assert p.quarantine.by_reason("idp_fixture").get(expected, 0) == before + 1, expected
    assert p.events_processed["auth"] == 0
    await p.store.close()


async def test_naive_timestamps_use_the_configured_source_timezone():
    from zoneinfo import ZoneInfo

    p = await make_pipeline(srcs=[dict(AUTH_SRC, timezone="Asia/Kolkata")])
    base = now() - timedelta(minutes=10)
    for i in range(5):
        rec = json.loads(idp(base, "u", "Failure", eid=f"f{i}"))
        # Naive wall-clock time in IST: the same instant as base+i seconds in UTC.
        rec["@timestamp"] = (base + timedelta(seconds=i)).astimezone(ZoneInfo("Asia/Kolkata")).replace(tzinfo=None).isoformat()
        await p._process_line(json.dumps(rec), "idp_fixture")
    assert p.quarantine.total() == 0 and p.events_processed["auth"] == 5
    await p.store.close()


# -- audit regression: duplicate batch (configured mode has real event ids) ------------------------

async def test_duplicate_batch_with_event_ids_gives_the_same_incident_as_once():
    base = now() - timedelta(minutes=5)
    once = await make_pipeline()
    for line in failures_then_success(base):
        await once._process_line(line, "idp_fixture")
    twice = await make_pipeline()
    batch = failures_then_success(base)
    for line in batch + batch:
        await twice._process_line(line, "idp_fixture")
    assert incidents(once) == incidents(twice) == [("auth_suspicious_login", "HIGH")]
    assert twice.deduper.stats()["duplicates_dropped"] == {"idp_fixture": 6}
    assert twice.events_processed["auth"] == 6
    await once.store.close(); await twice.store.close()


async def test_events_without_ids_are_not_deduplicated_by_default_but_are_in_content_mode():
    base = now() - timedelta(minutes=5)
    batch = failures_then_success(base, ids=False)
    default = await make_pipeline()
    for line in batch + batch:
        await default._process_line(line, "idp_fixture")
    assert default.events_processed["auth"] == 12 and default.deduper.no_event_id["idp_fixture"] == 12
    opt_in = await make_pipeline(ingest_dedupe="content")
    for line in batch + batch:
        await opt_in._process_line(line, "idp_fixture")
    assert opt_in.events_processed["auth"] == 6
    await default.store.close(); await opt_in.store.close()


# -- generator_v1 preserved in configured mode ------------------------------------------------------

async def test_generator_format_still_works_as_a_configured_source():
    gen = dict(id="synthetic_auth", path="auth.log", format="generator_v1")
    p = await make_pipeline(srcs=[gen])
    scn = SCENARIOS["failed_logins_then_success"]
    lines, _ = build_stream(scn, scn.seed)
    auth = [l for l in lines if '"type":"auth"' in l or '"type": "auth"' in l]
    assert auth
    for line in auth:
        await p._process_line(line, "synthetic_auth")
    kinds = {k for k, _ in incidents(p)}
    assert "auth_suspicious_login" in kinds
    assert all(i.user_id.startswith("U-") and len(i.user_id) == 14 for i in p.incidents.list_incidents())  # pseudonymized
    await p.store.close()


# -- fail-closed configuration ---------------------------------------------------------------------------

def test_source_config_rejects_bad_mappings():
    with pytest.raises(ValidationError):
        SourceConfig(id="a", path="x", kind="auth", fields={"ts": "t"})                       # required fields unmapped
    with pytest.raises(ValidationError):
        SourceConfig(**dict(AUTH_SRC, fields={**AUTH_SRC["fields"], "ssn": "x.y"}))           # unknown canonical field
    with pytest.raises(ValidationError):
        SourceConfig(**dict(AUTH_SRC, kind=None))                                              # kind required
    with pytest.raises(ValidationError):
        SourceConfig(**dict(AUTH_SRC, bogus=True))                                             # unknown key
    with pytest.raises(ValidationError):
        SourceConfig(**{**AUTH_SRC, "fields": {k: v for k, v in AUTH_SRC["fields"].items() if k != "user_id"},
                        "defaults": {"user_id": "everyone"}})                                  # identity cannot be defaulted
    with pytest.raises(ValidationError):
        SourceConfig(**dict(AUTH_SRC, id="../evil"))


async def test_bad_timezone_and_unmappable_config_fail_at_start(tmp_path):
    with pytest.raises(IngestConfigError):
        Pipeline(settings_for(tmp_path), config_for(dict(AUTH_SRC, timezone="Mars/Olympus")))
    with pytest.raises(IngestConfigError):
        Pipeline(settings_for(tmp_path), config_for())                                         # configured, zero sources
    with pytest.raises(IngestConfigError):
        Pipeline(settings_for(tmp_path), config_for(AUTH_SRC, dict(AUDIT_SRC, id=AUTH_SRC["id"])))   # duplicate id
    with pytest.raises(IngestConfigError):
        Pipeline(settings_for(tmp_path), config_for(AUTH_SRC, dict(AUDIT_SRC, path="idp.jsonl")))    # same file twice


async def test_paths_outside_the_allowed_directories_are_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.log").write_text("x\n")
    s = settings_for(tmp_path)
    for bad in ("../outside/secret.log", str(outside / "secret.log"), "/etc/passwd"):
        with pytest.raises(IngestConfigError):
            Pipeline(s, config_for(dict(AUTH_SRC, path=bad)))
    link = s.log_dir / "link.jsonl"
    link.symlink_to(outside / "secret.log")                                                    # symlink escaping LOG_DIR
    with pytest.raises(IngestConfigError):
        Pipeline(s, config_for(dict(AUTH_SRC, path="link.jsonl")))
    # An explicitly allowed extra directory works; a relative entry in the allow-list does not.
    ok = settings_for(tmp_path, ingest_allowed_dirs=str(outside))
    Pipeline(ok, config_for(dict(AUTH_SRC, path=str(outside / "secret.log"))))
    with pytest.raises(IngestConfigError):
        Pipeline(settings_for(tmp_path, ingest_allowed_dirs="relative/dir"), config_for(AUTH_SRC))


async def test_only_regular_files_are_accepted(tmp_path):
    s = settings_for(tmp_path)
    (s.log_dir / "adir").mkdir()
    with pytest.raises(IngestConfigError):
        Pipeline(s, config_for(dict(AUTH_SRC, path="adir")))
    fifo = s.log_dir / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(IngestConfigError):
        Pipeline(s, config_for(dict(AUTH_SRC, path="pipe")))


async def test_invalid_ingest_mode_is_refused(tmp_path):
    with pytest.raises(IngestConfigError):
        Pipeline(settings_for(tmp_path, ingest_mode="auto"), config_for(AUTH_SRC))


# -- end to end through files: tail, quarantine offsets, restart + retransmission ----------------------

async def _wait(p: Pipeline) -> None:
    for _ in range(300):
        await asyncio.sleep(0.02)
        if all(t.caught_up for t in p._tailers) and p.queue._unfinished_tasks == 0:
            return
    raise AssertionError("pipeline did not drain")


async def test_files_end_to_end_with_restart_and_retransmission(tmp_path):
    s = settings_for(tmp_path)
    cfg = config_for(AUTH_SRC)
    f = s.log_dir / "idp.jsonl"
    base = now() - timedelta(minutes=5)
    batch = failures_then_success(base)
    f.write_text("\n".join(batch[:3] + ["not json"] + batch[3:]) + "\n")

    p1 = Pipeline(s, cfg)
    await p1.start()
    try:
        await _wait(p1)
    finally:
        await p1.stop()
    assert p1.events_processed["auth"] == 6 and p1.quarantine.by_reason("idp_fixture") == {"invalid_json": 1}
    assert [(i.kind, i.peak_severity) for i in p1.incidents.list_incidents()] == [("auth_suspicious_login", "HIGH")]
    offset = [r for r in p1.quarantine.recent][0]["offset"]
    assert offset == len("\n".join(batch[:3]) + "\n")                                       # quarantine offset is the line start

    # "Restart" and have the forwarder retransmit the whole batch: all 6 are recognized as duplicates.
    with f.open("a") as h:
        h.write("\n".join(batch) + "\n")
    p2 = Pipeline(s, cfg)
    await p2.start()
    try:
        await _wait(p2)
    finally:
        await p2.stop()
    assert p2.deduper.stats()["duplicates_dropped"] == {"idp_fixture": 6}
    assert p2.events_processed["auth"] == 0
    assert [(i.kind, i.peak_severity) for i in p2.incidents.list_incidents()] == [("auth_suspicious_login", "HIGH")]
    assert p2.incidents.list_incidents()[0].alert_count == p1.incidents.list_incidents()[0].alert_count


async def test_stalled_source_is_reported(tmp_path):
    s = settings_for(tmp_path)
    cfg = config_for(dict(AUTH_SRC, stalled_after_seconds=0.1))
    (s.log_dir / "idp.jsonl").write_text("")
    p = Pipeline(s, cfg)
    await p.start()
    try:
        await asyncio.sleep(0.5)
        assert p._tailers[0].state == "stalled"
    finally:
        await p.stop()
