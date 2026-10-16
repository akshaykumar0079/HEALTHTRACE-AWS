"""User-provided dataset workflow: parsing and limits, mapping validation, conversion and privacy, labelled and
unlabelled evaluation, storage immutability, reproducibility, retention, and the API (docs/user-datasets.md)."""

from __future__ import annotations

import json
import logging
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import load_config
from app.evaluation.scoring import Detection
from app.privacy.redaction import Redactor
from app.research import dataset as ds
from app.research.convert import Point, convert
from app.research.labels import ANY, Interval, build_intervals, score_intervals
from app.research.mapping import MappingSpec, spec_problems
from app.research.service import ResearchService, ValidationFailed
from app.research.store import IntegrityError, NotFound, ResearchStore
from tests import research_helpers as H
from tests.test_workflow import _build

CFG = load_config()
REDACTOR = Redactor.build()
LIMITS = dict(max_rows=1000, max_columns=20)
SENTINELS = (H.SENTINEL_PATIENT, H.SENTINEL_USER, H.SENTINEL_NOTE, "John Sentinel", "alice.sentinel")


def spec(**over) -> MappingSpec:
    data = json.loads(json.dumps(H.APP_MAPPING))
    data.update(over)
    return MappingSpec.model_validate(data)


def parse(data: bytes, name: str = "d.csv", **kw):
    return ds.parse_dataset(data, name, **{**LIMITS, **kw})


# -- parsing, formats and limits -------------------------------------------------------------------------


def test_csv_is_parsed_with_header_and_rows():
    p = parse(H.small_csv(5))
    assert p.fmt == "csv" and p.columns == H.APP_COLUMNS and len(p.rows) == 5 and p.rows[0][2] is None


def test_semicolon_and_tab_delimiters_are_detected():
    assert parse(H.to_csv(H.app_rows(rate=1, warmup=5, inject=5, tail=5), delimiter=";")).delimiter == ";"
    assert parse(H.to_csv(H.app_rows(rate=1, warmup=5, inject=5, tail=5), delimiter="\t")).delimiter == "\t"


def test_jsonl_is_parsed_and_nested_objects_are_flattened():
    p = parse(H.to_jsonl(H.app_rows(rate=1, warmup=5, inject=5, tail=5)), "d.jsonl")
    assert p.fmt == "jsonl" and "event.time" in p.columns and "event.svc" in p.columns and "http" in p.columns


@pytest.mark.parametrize("name", ["data.xlsx", "data.json", "data.txt", "data", "data.csv.exe", "../../etc/passwd"])
def test_unsupported_types_are_rejected(name):
    with pytest.raises(ds.DatasetError) as e:
        ds.format_for(name)
    assert e.value.code == "unsupported_type"


def test_file_level_problems_are_reported_without_content():
    cases = {
        "binary_content": (b"a,b\n1,\x00\x01\n", "x.csv"),
        "not_utf8": ("a,b\n1,\xe9\n".encode("latin-1"), "x.csv"),
        "empty_file": (b"   \n", "x.csv"),
        "duplicate_columns": (b"a,a\n1,2\n", "x.csv"),
        "bad_header": (b"a,,c\n1,2,3\n", "x.csv"),
        "json_array": (b'[{"a": 1}]', "x.jsonl"),
        "no_records": (b"1\n2\n", "x.jsonl"),
        "too_many_columns": ((",".join(f"c{i}" for i in range(30)) + "\n").encode(), "x.csv"),
    }
    for code, (data, name) in cases.items():
        with pytest.raises(ds.DatasetError) as e:
            parse(data, name)
        assert e.value.code == code, code


def test_malformed_rows_are_rejected_by_number_and_code_not_content():
    p = parse(b"a,b\n1,2\n3\n4,5,6\n,\n7,8\n")
    codes = {n: err for n, _, err in p.rows}
    assert codes == {1: None, 2: ds.ROW_BAD_COLUMN_COUNT, 3: ds.ROW_BAD_COLUMN_COUNT, 4: ds.ROW_EMPTY, 5: None}
    j = parse(b'{"a": 1}\nnot json at all\n[1,2]\n{"a": 2}\n', "x.jsonl")
    assert [err for _, _, err in j.rows] == [None, ds.ROW_INVALID_JSON, ds.ROW_NOT_AN_OBJECT, None]


def test_overlong_cells_reject_the_row():
    p = parse(("a,b\n1," + "x" * (ds.MAX_CELL_CHARS + 1) + "\n2,ok\n").encode())
    assert [err for _, _, err in p.rows] == [ds.ROW_CELL_TOO_LONG, None]


def test_row_limit_truncates_and_says_so():
    p = parse(b"a\n" + b"1\n" * 50, max_rows=10)
    assert len(p.rows) == 10 and p.truncated is True


def test_inspection_masks_sensitive_columns_and_redacts_cells():
    csv_bytes = b"ts,name,note,svc\n2026-01-01T00:00:00Z,Jane Roe,call 555-123-4567 or a@b.org,claims\n"
    p = parse(csv_bytes)
    info = ds.inspect_dataset(p, size_bytes=len(csv_bytes), sha256="0" * 64, redactor=REDACTOR)
    row = info["preview_rows"][0]
    assert row["name"] == ds.MASKED and row["note"] == ds.MASKED
    assert "555-123-4567" not in json.dumps(info) and "a@b.org" not in json.dumps(info) and "Jane" not in json.dumps(info)
    assert info["sensitive_columns"] == ["name"] and "name" not in info["distinct_values"] and "note" in info["masked_columns"]
    assert info["distinct_values"]["svc"] == ["claims"]
    kinds = {c["name"]: c["kind"] for c in info["columns"]}
    assert kinds["ts"] == "timestamp"


# -- mapping validation -------------------------------------------------------------------------------------


def problems(**over):
    return {(p["field"], p["code"]) for p in spec_problems(spec(**over), H.APP_COLUMNS, CFG)}


def test_a_complete_mapping_has_no_problems():
    assert problems() == set()


def test_missing_required_unknown_column_and_bad_target_are_reported():
    assert ("ts", "missing_required") in problems(columns={"service": "Component", "level": "Severity"})
    assert ("service", "missing_required") in problems(columns={"ts": "Time", "level": "Severity"})
    assert ("level", "missing_required") in problems(columns={"ts": "Time", "service": "Component"})
    assert ("ts", "unknown_column") in problems(columns={**H.APP_MAPPING["columns"], "ts": "Nope"})
    assert ("bogus", "unknown_field") in problems(columns={**H.APP_MAPPING["columns"], "bogus": "Time"})
    assert ("service", "bad_mapping_target") in problems(values={"service": {"RX": "not_a_service"}})
    assert ("timezone", "bad_timezone") in problems(timezone="Mars/Olympus")
    assert ("patient_id", "default_not_allowed") in problems(defaults={"patient_id": "x"})
    assert ("priority", "bad_default") in problems(defaults={"priority": "high"})


def test_a_constant_service_replaces_the_service_column():
    cols = {k: v for k, v in H.APP_MAPPING["columns"].items() if k != "service"}
    assert problems(columns=cols, defaults={"service": "claims"}) == set()
    assert ("service", "bad_default") in problems(columns=cols, defaults={"service": "nope"})


def test_label_column_must_not_also_be_an_input():
    label = {"column": "Severity", "positive_values": ["error"]}
    assert ("label", "label_is_feature") in problems(label=label)
    assert ("label", "unknown_column") in problems(label={"column": "Missing", "positive_values": ["1"]})
    assert problems(label={"column": "Flag", "positive_values": ["1"]}) == set()


# -- conversion: normalization, pseudonyms, rejects --------------------------------------------------------


def convert_csv(data: bytes, mapping: MappingSpec | None = None):
    store_key = "k" * 8 + "abcdefghijklmnopqrstuvwxyz0123456789"
    from app.ingest.pseudonym import Pseudonymizer
    return convert(parse(data), mapping or spec(), config=CFG, pseudonymizer=Pseudonymizer.from_setting(store_key), redactor=REDACTOR)


def test_valid_rows_become_pseudonymized_events_with_no_raw_identifiers_or_text():
    conv = convert_csv(H.small_csv(30))
    assert conv.rows_accepted == 30 and not conv.rejects
    blob = "\n".join(conv.lines)
    for s in SENTINELS:
        assert s not in blob
    first = json.loads(conv.lines[0])
    assert first["service"] == "claims" and first["patient_id"].startswith("P-") and first["request_id"].startswith("req-")
    assert first["msg"] == "[free text omitted]"


def test_service_names_are_normalized_and_user_value_maps_apply():
    conv = convert_csv(H.small_csv(3, Component="Prior-Auth") + H.small_csv(3, Component="RX").split(b"\n", 1)[1])
    assert {json.loads(l)["service"] for l in conv.lines} == {"prior_auth", "pharmacy"}


def test_unknown_values_reject_rows_and_are_reported_for_mapping():
    conv = convert_csv(H.small_csv(10, Component="MysteryService"))
    assert conv.rows_accepted == 0 and conv.rejects == {"unknown_service": 10}
    assert conv.unmapped["service"] == ["MysteryService"]
    assert conv.reject_rows["unknown_service"] == list(range(1, 11))


def test_bad_values_and_bad_timestamps_are_rejected_with_codes():
    data = (H.small_csv(2) + H.small_csv(1, HTTP="abc").split(b"\n", 1)[1] + H.small_csv(1, Time="yesterday").split(b"\n", 1)[1]
            + H.small_csv(1, Severity="catastrophic").split(b"\n", 1)[1] + H.small_csv(1, Duration_ms="-5").split(b"\n", 1)[1])
    conv = convert_csv(data)
    assert conv.rows_accepted == 2
    assert conv.rejects == {"bad_value": 3, "ts_invalid": 1}


def test_naive_timestamps_use_the_chosen_timezone_and_epoch_ms_is_accepted():
    naive = H.small_csv(1, Time="2026-03-10 09:00:00")
    c_utc = convert_csv(naive, spec(timezone="UTC"))
    c_chi = convert_csv(naive, spec(timezone="America/Chicago"))
    t_utc, t_chi = (datetime.fromisoformat(json.loads(c.lines[0])["ts"].replace("Z", "+00:00")) for c in (c_utc, c_chi))
    assert (t_chi - t_utc) == timedelta(hours=5) or (t_chi - t_utc) == timedelta(hours=6)
    epoch = convert_csv(H.small_csv(1, Time="1773133200000"))
    assert epoch.rows_accepted == 1


def test_level_and_status_are_derived_from_each_other():
    cols = {k: v for k, v in H.APP_MAPPING["columns"].items() if k != "level"}
    c = convert_csv(H.small_csv(1, HTTP=503), spec(columns=cols))
    assert json.loads(c.lines[0])["level"] == "ERROR"
    cols = {k: v for k, v in H.APP_MAPPING["columns"].items() if k != "status"}
    c = convert_csv(H.small_csv(1, Severity="error"), spec(columns=cols))
    assert json.loads(c.lines[0])["status"] == 500


def test_out_of_order_rows_are_sorted_and_warned():
    rows = [r for r in H.app_rows(rate=2, warmup=10, inject=10, tail=10, scenario=None)]
    rows.reverse()
    conv = convert_csv(H.to_csv(rows))
    stamps = [json.loads(l)["ts"] for l in conv.lines]
    assert stamps == sorted(stamps) and conv.out_of_order > 0 and any("out of time order" in w for w in conv.warnings)


def test_warnings_explain_what_an_unmapped_field_costs():
    cols = {k: v for k, v in H.APP_MAPPING["columns"].items() if k not in ("latency_ms", "patient_id", "priority")}
    conv = convert_csv(H.small_csv(5), spec(columns=cols))
    text = " ".join(conv.warnings)
    assert "Latency is not mapped" in text and "patient identifier" in text and "Priority is not mapped" in text and "under 5 minutes" in text


# -- labels: intervals and scoring -------------------------------------------------------------------------


T = datetime(2026, 3, 10, 9, 0, tzinfo=timezone.utc)


def pts(spec_: list[tuple[int, str, bool]]) -> list[Point]:
    return [Point(T + timedelta(seconds=s), e, p) for s, e, p in spec_]


def test_intervals_merge_by_gap_and_split_by_entity():
    points = pts([(0, "a", True), (30, "a", True), (200, "a", True), (10, "b", True), (5, "a", False)])
    iv = build_intervals(points, scope="entity", merge_gap_seconds=60)
    assert [(i.entity, int((i.end - i.start).total_seconds()), i.rows) for i in iv] == [("a", 30, 2), ("b", 0, 1), ("a", 0, 1)] or \
        sorted((i.entity, int((i.end - i.start).total_seconds()), i.rows) for i in iv) == [("a", 0, 1), ("a", 30, 2), ("b", 0, 1)]
    one = build_intervals(points, scope="dataset", merge_gap_seconds=60)
    assert [i.entity for i in one] == [ANY, ANY] and len(one) == 2


def det(entity, at, sev="HIGH", kind="error_rate"):
    ts = T + timedelta(seconds=at)
    return Detection(kind, entity, ts, sev, ts if sev in ("HIGH", "CRITICAL") else None)


def test_scoring_hit_miss_false_alarm_and_delay():
    ivs = [Interval("a", T + timedelta(seconds=100), T + timedelta(seconds=160), 5),
           Interval("b", T + timedelta(seconds=500), T + timedelta(seconds=520), 3)]
    out = score_intervals(ivs, [det("a", 110), det("a", 130), det("c", 300), det("b", 900)], span_hours=1.0,
                          warmup_seconds=120, data_start=T)
    m = out["metrics"]
    assert (m["tp"], m["fp"], m["fn"], m["duplicates"]) == (1, 2, 1, 1)
    assert m["precision"] == pytest.approx(1 / 3, abs=0.001) and m["recall"] == 0.5
    assert m["false_alarms_per_hour"] == 2.0 and m["delay_s"]["median"] == 10.0
    assert [i["detected"] for i in out["intervals"]] == [True, False]
    assert {f["entity"] for f in out["false_alarms"]} == {"c", "b"}


def test_a_detection_within_60s_after_the_interval_counts_and_one_before_does_not():
    iv = [Interval("a", T + timedelta(seconds=100), T + timedelta(seconds=160), 2)]
    assert score_intervals(iv, [det("a", 219)], span_hours=1, warmup_seconds=0, data_start=None)["metrics"]["tp"] == 1
    out = score_intervals(iv, [det("a", 99)], span_hours=1, warmup_seconds=0, data_start=None)["metrics"]
    assert out["tp"] == 0 and out["fp"] == 1 and out["fn"] == 1


def test_dataset_scope_matches_any_entity_and_warmup_is_flagged():
    iv = [Interval(ANY, T + timedelta(seconds=30), T + timedelta(seconds=50), 2)]
    out = score_intervals(iv, [det("zzz", 40)], span_hours=1, warmup_seconds=120, data_start=T)
    assert out["metrics"]["tp"] == 1 and out["intervals"][0]["starts_in_detector_warmup"] is True


# -- storage: immutability, integrity, retention ---------------------------------------------------------------


def test_upload_is_stored_byte_for_byte_read_only_and_deduplicated(tmp_path):
    store = ResearchStore(tmp_path)
    data = H.small_csv(3)
    meta = store.save_upload(data, ext=".csv", filename="x.csv", fmt="csv", uploaded_by="op")
    blob = tmp_path / "uploads" / f"{meta['id']}.csv"
    assert blob.read_bytes() == data and not os.access(blob, os.W_OK)
    again = store.save_upload(data, ext=".csv", filename="other.csv", fmt="csv", uploaded_by="op2")
    assert again == meta and len(list((tmp_path / "uploads").glob("*.csv"))) == 1


def test_tampered_upload_is_refused(tmp_path):
    store = ResearchStore(tmp_path)
    meta = store.save_upload(H.small_csv(3), ext=".csv", filename="x.csv", fmt="csv", uploaded_by="op")
    blob = tmp_path / "uploads" / f"{meta['id']}.csv"
    os.chmod(blob, stat.S_IWRITE)
    blob.write_bytes(b"a,b\n1,2\n")
    with pytest.raises(IntegrityError):
        store.read_upload(meta["id"])


def test_ids_cannot_name_paths(tmp_path):
    store = ResearchStore(tmp_path)
    for bad in ("../../etc/passwd", "..", "a" * 64 + "/x", "exp-x"):
        with pytest.raises(NotFound):
            store.upload_meta(bad)
        with pytest.raises(NotFound):
            store.get_experiment(bad)


def test_purge_removes_old_records_but_keeps_uploads_still_referenced(tmp_path):
    store = ResearchStore(tmp_path)
    old, new = datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 3, 1, tzinfo=timezone.utc)
    a = store.save_upload(b"a\n1\n", ext=".csv", filename="a", fmt="csv", uploaded_by="x", now=old)
    b = store.save_upload(b"b\n2\n", ext=".csv", filename="b", fmt="csv", uploaded_by="x", now=old)
    store.save_experiment({"id": "exp-20260101T000000Z-aaaaaaaa", "created_at": old.isoformat(), "upload": {"sha256": a["id"]}})
    store.save_experiment({"id": "exp-20260301T000000Z-bbbbbbbb", "created_at": new.isoformat(), "upload": {"sha256": b["id"]}})
    now = datetime(2026, 3, 10, tzinfo=timezone.utc)
    assert store.purge(30, now=now, dry_run=True) == {"research_experiments": 1, "research_uploads": 1}
    assert len(store.list_experiments()) == 2                                        # dry run deletes nothing
    assert store.purge(30, now=now) == {"research_experiments": 1, "research_uploads": 1}
    assert [e["id"] for e in store.list_experiments()] == ["exp-20260301T000000Z-bbbbbbbb"]
    store.upload_meta(b["id"])                                                       # referenced by the newer experiment
    with pytest.raises(NotFound):
        store.upload_meta(a["id"])
    assert store.purge(0, now=now) == {"research_experiments": 0, "research_uploads": 0}


def test_pseudonym_key_is_created_once_and_reused(tmp_path):
    a = ResearchStore(tmp_path).pseudonymizer(None)
    b = ResearchStore(tmp_path).pseudonymizer(None)
    assert a.patient("x") == b.patient("x") and a.fingerprint() == b.fingerprint()
    assert (tmp_path / ".pseudonym_key").read_text() not in json.dumps({"fp": a.fingerprint()})


# -- service: end-to-end runs ---------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("research")
    app, pipeline = _build(tmp, research_dir=tmp / "research")
    svc: ResearchService = pipeline.research
    data = H.to_csv(H.app_rows())
    out = svc.save_upload(data, "my data.csv", "tester")
    return {"svc": svc, "upload_id": out["upload"]["id"], "data": data, "tmp": tmp, "app": app, "pipeline": pipeline}


LABEL = {"column": "Flag", "positive_values": ["1"], "scope": "entity", "merge_gap_seconds": 60}


def test_unlabeled_run_reports_incidents_but_measures_nothing(env):
    rec = env["svc"].run(env["upload_id"], spec(), ["current"], "auto", "tester")
    res = rec["result"]["methods"][0]
    assert res["incidents_found"] >= 1 and any(i["entity"] == "eligibility" for i in res["incidents"])
    ev = res["evaluation"]
    assert ev["mode"] == "descriptive" and ev["metrics_measured"] is False and ev["metrics"] is None
    assert "NOT measured" in ev["note"]
    flat = json.dumps(rec)
    for key in ("precision", "recall", "false_alarms_per_hour", "f1"):
        assert f'"{key}"' not in flat
    assert rec["config"]["mode"] == "descriptive"


def test_labeled_run_measures_precision_recall_false_alarms_and_delay(env):
    rec = env["svc"].run(env["upload_id"], spec(label=LABEL), ["current"], "auto", "tester")
    ev = rec["result"]["methods"][0]["evaluation"]
    m = ev["metrics"]
    assert ev["mode"] == "labeled" and ev["metrics_measured"] is True
    assert m["tp"] == 1 and m["fn"] == 0 and m["recall"] == 1.0
    assert 0 <= m["delay_s"]["median"] <= 120 and m["intervals"] == 1
    assert ev["intervals"][0]["entity"] == "eligibility" and ev["intervals"][0]["detected"] is True
    assert m["fp"] == len(ev["false_alarms"]) and m["false_alarms_per_hour"] is not None
    assert any("exhaustive" in a for a in ev["assumptions"])


def test_descriptive_mode_ignores_a_mapped_label(env):
    rec = env["svc"].run(env["upload_id"], spec(label=LABEL), ["current"], "descriptive", "tester")
    assert rec["result"]["methods"][0]["evaluation"]["metrics_measured"] is False and rec["config"]["mapping"]["label"] is None


def test_methods_can_be_compared_and_service_only_methods_skip_other_kinds(env):
    rec = env["svc"].run(env["upload_id"], spec(label=LABEL), ["current", "threshold_10pct"], "labeled", "tester")
    by = {m["method"]: m for m in rec["result"]["methods"]}
    assert by["threshold_10pct"]["evaluation"]["metrics"]["tp"] == 1


def test_labeled_mode_without_a_label_is_refused(env):
    with pytest.raises(ValueError):
        env["svc"].run(env["upload_id"], spec(), ["current"], "labeled", "tester")
    with pytest.raises(ValueError):
        env["svc"].run(env["upload_id"], spec(), ["nonsense"], "auto", "tester")


def test_invalid_mapping_stops_the_run_with_a_report(env):
    bad = spec(columns={"ts": "Time"})
    with pytest.raises(ValidationFailed) as e:
        env["svc"].run(env["upload_id"], bad, ["current"], "auto", "tester")
    assert not e.value.report["ok"] and {p["code"] for p in e.value.report["errors"]} >= {"missing_required"}
    wrong = spec(columns={**H.APP_MAPPING["columns"], "ts": "Notes"})
    with pytest.raises(ValidationFailed) as e2:
        env["svc"].run(env["upload_id"], wrong, ["current"], "auto", "tester")
    assert {p["code"] for p in e2.value.report["errors"]} & {"no_rows_accepted", "mostly_rejected"}


def test_run_is_reproducible_and_the_original_upload_is_untouched(env):
    svc = env["svc"]
    first = svc.run(env["upload_id"], spec(label=LABEL), ["current"], "auto", "tester")
    again = svc.rerun(first["id"], "tester")
    assert again["rerun_of"] == first["id"] and again["reproduced"] is True
    assert again["results_sha256"] == first["results_sha256"] and again["id"] != first["id"]
    blob = svc.store.uploads / f"{env['upload_id']}.csv"
    assert blob.read_bytes() == env["data"] and not os.access(blob, os.W_OK)
    # a "restart": a brand-new service over the same directory gives the same pseudonyms and the same hash
    fresh = ResearchService(svc.settings, svc.config, svc.redactor)
    third = fresh.run(env["upload_id"], spec(label=LABEL), ["current"], "auto", "tester")
    assert third["results_sha256"] == first["results_sha256"]
    # a different mapping is a different experiment
    other = svc.run(env["upload_id"], spec(label=LABEL, timezone="Asia/Kolkata"), ["current"], "auto", "tester")
    assert other["results_sha256"] != first["results_sha256"] and other["config_fingerprint"] != first["config_fingerprint"]


def test_compare_two_experiments(env):
    svc = env["svc"]
    a = svc.run(env["upload_id"], spec(label=LABEL), ["current"], "auto", "t")
    b = svc.run(env["upload_id"], spec(label=LABEL), ["threshold_10pct"], "auto", "t")
    out = svc.compare(a["id"], b["id"])
    assert out["same_upload"] and out["same_mapping"] and not out["same_methods"] and not out["results_identical"]
    assert any(r["metric"] == "recall" and r["a"] == 1.0 for r in out["rows"])


def test_results_and_stored_files_contain_no_raw_identifiers_or_text(env):
    rec = env["svc"].run(env["upload_id"], spec(label=LABEL), ["current"], "auto", "tester")
    blobs = [json.dumps(rec)] + [p.read_text(encoding="utf-8") for p in (env["svc"].store.experiments).glob("*.json")]
    blobs += [p.read_text(encoding="utf-8") for p in (env["svc"].store.uploads).glob("*.json")]
    for text in blobs:
        for s in SENTINELS:
            assert s not in text


def test_audit_style_dataset_with_a_label_is_evaluated(tmp_path):
    from generator.scenarios import ALL_SCENARIO_NAMES
    import random
    rng = random.Random(3)
    rows, bulk_user = [], "u-bulk"
    for name, start, dur in ((None, H.START, 900), ("bulk_phi_access", H.START + timedelta(seconds=900), 300), (None, H.START + timedelta(seconds=1200), 420)):
        assert name is None or name in ALL_SCENARIO_NAMES
        _, audit, _ = H.gen.generate_events(name, dur, 20, start, rng)
        rows += audit
    lines = [{"when": e["ts"], "who": f"staff-{e['user_id']}" if e["user_id"] != "U-117" else bulk_user, "what": e["action"].lower().replace("_record", ""),
              "patient": e["patient_id"], "flag": "1" if e["user_id"] == "U-117" else "0"} for e in rows]
    actions = {"view": "VIEW_RECORD", "edit": "EDIT_RECORD", "export": "EXPORT_RECORDS", "search": "SEARCH", "exports": "EXPORT_RECORDS"}
    mapping = MappingSpec.model_validate({
        "kind": "audit", "columns": {"ts": "when", "user_id": "who", "action": "what", "patient_id": "patient"},
        "values": {"action": {k: v for k, v in actions.items()}}, "label": {"column": "flag", "positive_values": ["1"], "scope": "entity"}})
    _, pipeline = _build(tmp_path, research_dir=tmp_path / "r")
    svc = pipeline.research
    up = svc.save_upload(H.to_csv(lines, ["when", "who", "what", "patient", "flag"]), "audit.csv", "t")
    rec = svc.run(up["upload"]["id"], mapping, ["current", "threshold_10pct"], "auto", "t")
    cur, thr = rec["result"]["methods"]
    assert cur["evaluation"]["metrics"]["tp"] == 1 and thr["applicable"] is False
    assert cur["evaluation"]["metrics"]["fn"] == 0 and cur["incidents"][0]["entity"].startswith("U-")


# -- limits ----------------------------------------------------------------------------------------------------


def test_upload_size_and_type_limits_in_the_service(tmp_path):
    _, pipeline = _build(tmp_path, research_dir=tmp_path / "r", research_max_upload_mb=1, research_max_rows=50)
    svc = pipeline.research
    with pytest.raises(ds.DatasetError) as e:
        svc.save_upload(b"a\n" + b"1\n" * (1024 * 1024), "big.csv", "t")
    assert e.value.code == "too_large"
    with pytest.raises(ds.DatasetError) as e2:
        svc.save_upload(b"x", "x.exe", "t")
    assert e2.value.code == "unsupported_type"
    out = svc.save_upload(b"a\n" + b"1\n" * 80, "rows.csv", "t")
    assert out["inspection"]["rows_truncated_at_limit"] is True and out["inspection"]["rows_parsed"] == 50
    assert list((tmp_path / "r" / "uploads").glob("*.exe")) == []


# -- API ---------------------------------------------------------------------------------------------------------


def hdr(token=None, **extra):
    h = {"X-Privacy-Ack": "yes", "X-Filename": "data.csv", "Content-Type": "application/octet-stream", **extra}
    if token:
        h["X-Operator-Token"] = token
    return h


@pytest.fixture()
def client(tmp_path):
    app, _ = _build(tmp_path, research_dir=tmp_path / "research")
    with TestClient(app) as c:
        yield c


def test_api_info_states_limits_and_warning(client):
    body = client.get("/api/research/info").json()
    assert body["enabled"] and "not HIPAA-certified" in body["warning"] and body["limits"]["max_upload_mb"] == 25
    assert body["external_calls"] == 0 and ".csv" in body["formats"]


def test_api_upload_requires_the_privacy_acknowledgement_and_a_supported_file(client):
    data = H.small_csv(10)
    no_ack = client.post("/api/research/uploads", content=data, headers={"X-Filename": "d.csv"})
    assert no_ack.status_code == 400
    bad = client.post("/api/research/uploads", content=data, headers=hdr(**{"X-Filename": "d.xlsx"}))
    assert bad.status_code == 415 and bad.json()["detail"]["code"] == "unsupported_type"
    garbage = client.post("/api/research/uploads", content=b"\x00\x01\x02", headers=hdr())
    assert garbage.status_code == 422
    ok = client.post("/api/research/uploads", content=data, headers=hdr())
    assert ok.status_code == 200
    body = ok.json()
    assert [c["name"] for c in body["inspection"]["columns"]] == H.APP_COLUMNS and len(body["inspection"]["preview_rows"]) == 5


def test_api_oversize_upload_is_cut_off(tmp_path):
    app, _ = _build(tmp_path, research_dir=tmp_path / "r", research_max_upload_mb=1)
    with TestClient(app) as c:
        r = c.post("/api/research/uploads", content=b"a\n" + b"1\n" * (1024 * 1024), headers=hdr())
        assert r.status_code == 413 and r.json()["detail"]["code"] == "too_large"
        assert not list((tmp_path / "r").glob("uploads/*.csv"))


def test_api_full_flow_validate_run_list_get_rerun_compare_delete(client):
    data = H.to_csv(H.app_rows(rate=8, warmup=600, inject=150, tail=240))
    up = client.post("/api/research/uploads", content=data, headers=hdr()).json()["upload"]["id"]
    mapping = json.loads(json.dumps(H.APP_MAPPING))
    labelled = {**mapping, "label": LABEL}

    v = client.post(f"/api/research/uploads/{up}/validate", json={"mapping": labelled}).json()
    assert v["ok"] is True and v["mode"] == "labeled" and v["rows"]["rejected"] == 0 and v["labels"]["intervals"] == 1
    broken = client.post(f"/api/research/uploads/{up}/validate", json={"mapping": {**mapping, "columns": {"ts": "Time"}}}).json()
    assert broken["ok"] is False and {e["code"] for e in broken["errors"]} >= {"missing_required"}
    unknown = client.post(f"/api/research/uploads/{up}/validate",
                          json={"mapping": {**mapping, "values": {}, "columns": {**mapping["columns"], "service": "Severity"}}}).json()
    assert unknown["ok"] is False and unknown["rows"]["rejects_by_code"]

    body = {"upload_id": up, "mapping": labelled, "methods": ["current"], "mode": "auto"}
    assert client.post("/api/research/experiments", json=body).status_code == 400            # warning not acknowledged
    bad = client.post("/api/research/experiments", json={**body, "acknowledged_privacy_warning": True, "mapping": {**mapping, "columns": {}}})
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "validation_failed"
    run = client.post("/api/research/experiments", json={**body, "acknowledged_privacy_warning": True})
    assert run.status_code == 200
    exp = run.json()
    assert exp["result"]["methods"][0]["evaluation"]["metrics"]["tp"] == 1 and exp["privacy"]["external_calls"] == 0

    listed = client.get("/api/research/experiments").json()["items"]
    assert [i["id"] for i in listed] == [exp["id"]]
    assert client.get(f"/api/research/experiments/{exp['id']}").json()["results_sha256"] == exp["results_sha256"]
    again = client.post(f"/api/research/experiments/{exp['id']}/rerun").json()
    assert again["reproduced"] is True
    cmp = client.get("/api/research/experiments/compare", params={"a": exp["id"], "b": again["id"]}).json()
    assert cmp["results_identical"] is True
    audit = [a["action"] for a in client.get("/api/audit").json()]
    assert {"research.upload", "research.run", "research.rerun"} <= set(audit)
    assert client.delete(f"/api/research/uploads/{up}").json() == {"deleted": True}
    assert client.get(f"/api/research/experiments/{exp['id']}").status_code == 404
    assert client.post(f"/api/research/uploads/{up}/validate", json={"mapping": mapping}).status_code == 404


def test_api_rejects_path_like_and_unknown_ids(client):
    assert client.get("/api/research/experiments/..%2f..%2fetc").status_code in (404, 422)
    assert client.get("/api/research/experiments/exp-nope").status_code == 404
    assert client.get("/api/research/uploads/zzz").status_code == 404
    assert client.get("/api/research/experiments/compare", params={"a": "x", "b": "y"}).status_code == 404
    bad_id = {"upload_id": "../../x", "mapping": H.APP_MAPPING, "acknowledged_privacy_warning": True}
    assert client.post("/api/research/experiments", json=bad_id).status_code == 422


def test_api_roles(tmp_path):
    app, _ = _build(tmp_path, research_dir=tmp_path / "r", operator_token="op", viewer_token="view", admin_token="adm")
    data = H.small_csv(10)
    with TestClient(app) as c:
        assert c.post("/api/research/uploads", content=data, headers=hdr()).status_code == 401
        assert c.post("/api/research/uploads", content=data, headers=hdr("view")).status_code == 403
        up = c.post("/api/research/uploads", content=data, headers=hdr("op"))
        assert up.status_code == 200
        uid = up.json()["upload"]["id"]
        assert c.get(f"/api/research/uploads/{uid}", headers={"X-Operator-Token": "view"}).status_code == 403   # preview needs operator
        assert c.get("/api/research/experiments", headers={"X-Operator-Token": "view"}).status_code == 200
        assert c.delete(f"/api/research/uploads/{uid}", headers={"X-Operator-Token": "op"}).status_code == 403
        assert c.delete(f"/api/research/uploads/{uid}", headers={"X-Operator-Token": "adm"}).status_code == 200


def test_api_disabled_flag_hides_the_feature(tmp_path):
    app, _ = _build(tmp_path, research_dir=tmp_path / "r", research_enabled=False)
    with TestClient(app) as c:
        assert c.get("/api/research/info").json()["enabled"] is False
        assert c.post("/api/research/uploads", content=b"a\n1\n", headers=hdr()).status_code == 404
        assert c.get("/api/research/experiments").status_code == 404


# -- privacy: logs, errors, audit trail ------------------------------------------------------------------------


def test_nothing_from_the_file_reaches_logs_errors_or_the_audit_trail(tmp_path, caplog):
    app, pipeline = _build(tmp_path, research_dir=tmp_path / "research")
    rows = H.app_rows(rate=5, warmup=300, inject=60, tail=120)
    rows[10]["HTTP"] = "not-a-number"
    rows[11]["Time"] = "garbage " + H.SENTINEL_NOTE
    rows[12]["Component"] = "Svc-" + H.SENTINEL_USER
    data = H.to_csv(rows) + b'\n"unterminated,' + H.SENTINEL_NOTE.encode()
    caplog.set_level(logging.DEBUG)
    responses = []
    with TestClient(app) as c:
        r = c.post("/api/research/uploads", content=data, headers=hdr())
        responses.append(r.text)
        uid = r.json()["upload"]["id"] if r.status_code == 200 else None
        if uid:
            responses.append(c.get(f"/api/research/uploads/{uid}").text)
            for mapping in (H.APP_MAPPING, {**H.APP_MAPPING, "columns": {"ts": "Notes"}}):
                v = c.post(f"/api/research/uploads/{uid}/validate", json={"mapping": mapping})
                responses.append(v.text)
            run = c.post("/api/research/experiments", json={"upload_id": uid, "mapping": {**H.APP_MAPPING, "columns": {"ts": "Notes"}},
                                                           "acknowledged_privacy_warning": True})
            responses.append(run.text)
        responses.append(c.post("/api/research/uploads", content=b"a,b\n" + H.SENTINEL_USER.encode(), headers=hdr(**{"X-Filename": H.SENTINEL_USER + ".xlsx"})).text)
        audit = c.get("/api/audit").text
    for s in ("alice.sentinel", H.SENTINEL_PATIENT, "John Sentinel"):
        assert s not in audit and s not in caplog.text, s
        for body in responses:
            assert s not in body, s
    assert caplog.text.count("Sentinel") == 0


# -- retention hook ------------------------------------------------------------------------------------------------


def test_pipeline_retention_covers_research_files_and_the_policy_lists_them(tmp_path):
    import asyncio

    _, pipeline = _build(tmp_path, research_dir=tmp_path / "r", retention_research_days=30)
    svc = pipeline.research
    old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    up = svc.store.save_upload(b"a\n1\n", ext=".csv", filename="a", fmt="csv", uploaded_by="x", now=old)
    svc.store.save_experiment({"id": "exp-20260101T000000Z-aaaaaaaa", "created_at": old.isoformat(), "upload": {"sha256": up["id"]}})
    assert any(r["data"] == "Research uploads and experiments" and r["keep"] == "30 days" for r in pipeline.retention.describe())

    async def go():
        await pipeline.store.connect()
        try:
            dry = await pipeline.run_retention(dry_run=True)
            assert dry["deleted"]["research_experiments"] == 1 and dry["deleted"]["research_uploads"] == 1
            assert svc.store.list_experiments()                          # dry run keeps everything
            real = await pipeline.run_retention()
            assert real["deleted"]["research_experiments"] == 1 and not svc.store.list_experiments()
        finally:
            await pipeline.store.close()

    asyncio.run(go())


def test_jsonl_with_nested_fields_runs_end_to_end(tmp_path):
    _, pipeline = _build(tmp_path, research_dir=tmp_path / "r")
    svc = pipeline.research
    rows = H.app_rows(rate=4, warmup=300, inject=90, tail=150)
    up = svc.save_upload(H.to_jsonl(rows), "events.jsonl", "t")
    assert up["inspection"]["format"] == "jsonl" and {"event.time", "event.svc", "http", "ms", "flag"} <= {c["name"] for c in up["inspection"]["columns"]}
    mapping = MappingSpec.model_validate({
        "kind": "app", "columns": {"ts": "event.time", "service": "event.svc", "level": "event.sev", "status": "http", "latency_ms": "ms"},
        "values": {"service": {"RX": "pharmacy"}}, "label": {"column": "flag", "positive_values": ["1"]}})
    rec = svc.run(up["upload"]["id"], mapping, ["current"], "auto", "t")
    ds_ = rec["result"]["dataset"]
    assert ds_["rows_accepted"] == len(rows) and ds_["rows_rejected"] == 0
    assert rec["result"]["methods"][0]["evaluation"]["metrics_measured"] is True
    assert any("Patient" in w or "patient" in w for w in ds_["warnings"])         # no patient column: severity caveat is shown
