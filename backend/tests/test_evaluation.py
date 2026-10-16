"""Evaluation harness: metric definitions, baselines, ablations, reproducibility, and the
documented simulator false positive (docs/evaluation.md)."""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.config import REPO_ROOT, load_config
from app.detect.anomaly import AnomalyEngine
from app.detect.baseline import BaselineEngine
from app.evaluation.experiment import run_cell, run_experiment, truth_for
from app.evaluation.methods import METHODS, effective_config, threshold_detections
from app.evaluation.report import write_all
from app.evaluation.scoring import Detection, Truth, aggregate, score_run, wilson_interval
from app.models import WindowMetrics
from app.simulation.scenarios import SCENARIOS

T0 = datetime(2026, 3, 10, 16, 0, tzinfo=timezone.utc)
START, END = T0 + timedelta(seconds=900), T0 + timedelta(seconds=1200)


def truth(**kw) -> Truth:
    base = dict(inject_start=START, inject_end=END, sim_hours=1.0, kind="error_rate", entity="eligibility")
    base.update(kw)
    return Truth(**base)


def det(kind="error_rate", entity="eligibility", at=10.0, sev="HIGH", actionable_at=None) -> Detection:
    act = START + timedelta(seconds=actionable_at) if actionable_at is not None else None
    return Detection(kind, entity, START + timedelta(seconds=at), sev, act)


# -- scoring: the definitions in docs/evaluation.md ------------------------------------------------------


def test_hit_has_delay_and_actionable_delay():
    s = score_run(truth(), [det(at=7.5, actionable_at=12.5)])
    assert (s.tp, s.fp, s.fn) == (1, 0, 0)
    assert s.delay_s == 7.5 and s.actionable_delay_s == 12.5 and s.actionable_detected is True


def test_hit_that_never_reaches_high_is_detected_but_not_actionable():
    s = score_run(truth(), [det(sev="LOW", at=30)])
    assert s.tp == 1 and s.delay_s == 30 and s.actionable_detected is False and s.actionable_delay_s is None


def test_no_detection_is_a_miss_without_a_delay():
    s = score_run(truth(), [])
    assert (s.tp, s.fp, s.fn) == (0, 0, 1) and s.delay_s is None and s.actionable_detected is False


def test_control_run_counts_every_incident_as_false_positive():
    s = score_run(truth(kind=None, entity=None), [det(entity="batch", sev="LOW"), det(entity="claims")])
    assert (s.tp, s.fp, s.fn) == (0, 2, 0) and s.injected is False
    assert all(l["reason"].startswith("control run") for l in s.labels)


def test_wrong_entity_before_injection_and_late_detections_are_false_positives():
    s = score_run(truth(), [
        det(entity="claims", at=20),                                  # unrelated entity
        det(at=-5),                                                   # before the injection
        det(at=300 + 61),                                             # right target, > 60 s after it ended
    ])
    assert (s.tp, s.fp, s.fn) == (0, 3, 1)
    assert {l["reason"] for l in s.labels} == {"unrelated kind/entity", "before the injection", "after the injection ended"}


def test_detection_within_the_60s_grace_after_the_end_still_counts():
    assert score_run(truth(), [det(at=300 + 59)]).tp == 1


def test_collateral_and_duplicates_are_neither_hits_nor_false_alarms():
    t = truth(collateral=frozenset({("error_rate", "prior_auth")}))
    s = score_run(t, [det(at=5), det(at=100), det(entity="prior_auth", at=40)])
    assert (s.tp, s.fp, s.fn, s.collateral, s.duplicates) == (1, 0, 0, 1, 1)
    agg = aggregate([s])
    assert agg["precision"] == 1.0 and agg["precision_strict"] == pytest.approx(1 / 3, abs=0.001)


def test_collateral_before_the_injection_is_a_false_positive():
    t = truth(collateral=frozenset({("error_rate", "prior_auth")}))
    assert score_run(t, [det(entity="prior_auth", at=-10)]).fp == 1


def test_only_the_first_matching_incident_is_the_hit():
    s = score_run(truth(), [det(at=50), det(at=5)])
    assert s.tp == 1 and s.delay_s == 5 and s.duplicates == 1      # sorted by time, not input order


def test_aggregate_metrics_by_hand():
    hit = score_run(truth(), [det(at=10, actionable_at=10)])
    miss = score_run(truth(), [])
    fp_run = score_run(truth(kind=None, entity=None, sim_hours=0.5), [det(entity="batch", sev="LOW")])
    a = aggregate([hit, miss, fp_run])
    assert (a["tp"], a["fp"], a["fn"]) == (1, 1, 1)
    assert a["precision"] == 0.5 and a["recall"] == 0.5 and a["f1"] == 0.5
    assert a["false_alarms_per_hour"] == pytest.approx(1 / 2.5, abs=0.001)
    assert a["runs_with_false_alarm"] == 1 and a["control_runs"] == 1 and a["injected_runs"] == 2
    assert a["delay_s"]["n"] == 1 and a["delay_s"]["median"] == 10
    assert a["actionable_recall"] == 0.5


def test_aggregate_with_nothing_to_divide_is_none_not_zero():
    a = aggregate([score_run(truth(kind=None, entity=None), [])])
    assert a["precision"] is None and a["recall"] is None and a["f1"] is None and a["delay_s"]["median"] is None


def test_wilson_interval():
    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(10, 10)
    assert hi == 1.0 and 0.7 < lo < 0.75
    lo, hi = wilson_interval(5, 10)
    assert lo < 0.5 < hi


# -- the fixed-threshold baseline ---------------------------------------------------------------------------


def _line(ts: datetime, service: str, error: bool, i: int) -> str:
    return json.dumps({"ts": ts.isoformat().replace("+00:00", "Z"), "type": "app", "service": service,
                       "level": "ERROR" if error else "INFO", "priority": "routine", "request_id": f"R-{i:05d}",
                       "patient_id": f"P-{i:06d}", "status": 500 if error else 200, "latency_ms": 100, "msg": "m"})


def _stream(bursts: list[tuple[int, int]], error_every: int, seconds: int = 400) -> list[str]:
    """4 events/s on one service; inside each (from, until) second range every `error_every`-th event fails."""
    lines = []
    for sec in range(seconds):
        failing = any(a <= sec < b for a, b in bursts)
        for k in range(4):
            n = sec * 4 + k
            lines.append(_line(T0 + timedelta(seconds=sec, milliseconds=k * 100), "claims", failing and n % error_every == 0, n))
    return lines


def test_threshold_baseline_flags_a_sustained_spike_once():
    found = threshold_detections(_stream([(100, 200)], 2), 0.10)      # 50% errors for 100 s
    assert len(found) == 1 and found[0].entity == "claims" and found[0].kind == "error_rate"
    assert found[0].peak_severity is None and found[0].first_actionable_ts == found[0].first_ts
    assert T0 + timedelta(seconds=100) < found[0].first_ts < T0 + timedelta(seconds=125)


def test_threshold_baseline_is_silent_below_the_threshold_and_respects_min_errors():
    assert threshold_detections(_stream([(0, 400)], 25), 0.10) == []      # 4% errors
    assert len(threshold_detections(_stream([(0, 400)], 12), 0.05)) == 1   # ~8% errors, lower threshold
    assert threshold_detections(_stream([(100, 200)], 2), 0.10, min_errors=10_000) == []


def test_threshold_baseline_groups_one_burst_and_splits_bursts_separated_by_calm_windows():
    assert len(threshold_detections(_stream([(50, 110)], 2, 300), 0.10)) == 1
    assert len(threshold_detections(_stream([(50, 110), (250, 310)], 2, 400), 0.10)) == 2


# -- methods and ablations ---------------------------------------------------------------------------------------


def test_ablation_configs_are_private_copies_with_exactly_the_documented_change():
    shared = load_config()
    assert shared.baseline.time_aware is True
    cfg = effective_config(METHODS["no_time_aware"])
    assert cfg.baseline.time_aware is False and shared.baseline.time_aware is True and cfg is not shared
    cfg = effective_config(METHODS["no_patient_impact"])
    assert (cfg.severity.criticality_weight, cfg.severity.patient_factor_weight) == (1.0, 0.0)
    assert (shared.severity.criticality_weight, shared.severity.patient_factor_weight) == (0.5, 0.5)
    assert effective_config(METHODS["current"]).model_dump() == shared.model_dump()


def test_time_aware_flag_changes_which_bucket_is_used():
    cfg = load_config().baseline
    off = cfg.model_copy(update={"time_aware": False})
    for conf, expect_fallback in ((cfg, False), (off, True)):
        engine = BaselineEngine(conf)
        for _ in range(conf.warmup_windows):
            engine.update("claims", 9, "error_rate", 0.02)           # hour 9 is ready on its own
        assert engine.get("claims", 9, "error_rate").is_global_fallback is expect_fallback


def test_methods_declare_where_they_apply():
    assert METHODS["threshold_10pct"].applies_to("error_rate")[0] is True
    assert METHODS["threshold_10pct"].applies_to(None)[0] is True            # control: it can false-alarm
    ok, why = METHODS["threshold_10pct"].applies_to("hipaa_bulk_access")
    assert ok is False and "rule-based" in why
    assert METHODS["current"].applies_to("auth_suspicious_login")[0] is True


# -- the documented false positive (docs/simulator.md, docs/evaluation.md) ---------------------------------


def _window(errors: int, total: int) -> WindowMetrics:
    return WindowMetrics(service="batch", window_end=T0, total=total, errors=errors, error_rate=errors / total,
                         p95_latency_ms=100.0, urgent_errors=0, affected_patients_urgent=0, affected_patients_routine=0)


def test_false_positive_mechanism_a_5_percent_window_on_a_1_percent_service_passes_every_guard():
    """The seed-33 false positive, reduced to its cause: 5 errors in 100 events (5.0%) against a 1.05% baseline
    clears z >= 3 (the std is floored at 1%), >= 5 errors and >= 5% at the same moment. One fewer error does not."""
    cfg = load_config()
    engine = BaselineEngine(cfg.baseline)
    for i in range(300):                                                # ~1% mean with realistic spread
        engine.update("batch", 16, "error_rate", 0.0105 + (0.009 if i % 2 else -0.009))
    ae = AnomalyEngine(cfg.anomaly, engine)
    hit = ae.evaluate(_window(5, 100)).anomalies
    assert [a.kind for a in hit] == ["error_rate"] and hit[0].z >= cfg.anomaly.error_rate_z_threshold
    assert ae.evaluate(_window(4, 100)).anomalies == []                 # below min_errors and min_rate


def test_documented_false_positive_is_counted_not_hidden():
    """normal_control with seed 33 raises one LOW error_rate incident on `batch` although nothing was injected.
    The evaluation must report it as a false positive. If a detector change fixes this, update this test and
    docs/evaluation.md together; do not special-case the seed."""
    rows = run_cell("normal_control", 33, ("current",))
    row = rows[0]
    assert row["applicable"] and row["fp"] == 1 and row["tp"] == 0 and row["fn"] == 0
    fp = [l for l in row["incident_labels"] if l["label"] == "fp"][0]
    assert (fp["kind"], fp["entity"], fp["peak_severity"]) == ("error_rate", "batch", "LOW")
    assert fp["first_ts"].startswith("2026-03-10T16:30:00")
    # and the same stream is clean for the other two documented seeds
    assert all(run_cell("normal_control", s, ("current",))[0]["fp"] == 0 for s in (11, 22))


# -- reproducibility and output ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def small_result() -> dict:
    return run_experiment((5,), ("normal_control", "error_spike"), ("current", "threshold_10pct"), workers=1)


def test_same_inputs_give_identical_results_and_hash(small_result):
    again = run_experiment((5,), ("normal_control", "error_spike"), ("current", "threshold_10pct"), workers=1)
    assert again["runs"] == small_result["runs"]
    assert again["results_sha256"] == small_result["results_sha256"]
    assert again["per_scenario"] == small_result["per_scenario"]


def test_different_seed_changes_the_hash_and_workers_do_not():
    a = run_experiment((5,), ("normal_control",), ("threshold_10pct",), workers=1)
    b = run_experiment((6,), ("normal_control",), ("threshold_10pct",), workers=1)
    c = run_experiment((5,), ("normal_control",), ("threshold_10pct",), workers=2)
    assert a["results_sha256"] != b["results_sha256"]
    assert a["results_sha256"] == c["results_sha256"]


def test_result_records_configuration_and_synthetic_flag(small_result):
    cfg = small_result["config"]
    assert cfg["seeds"] == [5] and cfg["synthetic_only"] is True
    assert len(cfg["config_yaml_sha256"]) == 64 and cfg["detector_config"]["baseline"]["time_aware"] is True
    assert cfg["methods"]["threshold_10pct"]["parameters"]["error_rate_threshold"] == 0.10
    assert cfg["scenarios"]["error_spike"]["labels"]["inject_start"].startswith("2026-03-10T16:15")
    assert "git_commit" in small_result["run_info"] and "generated_at" not in json.dumps(small_result["config"])


def test_error_spike_is_detected_and_scored_for_both_methods(small_result):
    by = {(r["scenario_id"], r["method"]): r for r in small_result["runs"]}
    for m in ("current", "threshold_10pct"):
        r = by[("error_spike", m)]
        assert r["tp"] == 1 and r["fn"] == 0 and 0 <= r["delay_s"] < 120
    assert small_result["aggregate_service_metric_subset"]["current"]["recall"] == 1.0


def test_outputs_are_written_and_parseable(small_result, tmp_path):
    paths = write_all(small_result, tmp_path)
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["results_sha256"] == small_result["results_sha256"]
    with paths["runs_csv"].open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(small_result["runs"]) and {"scenario_id", "seed", "method", "tp", "fp", "fn"} <= set(rows[0])
    with paths["per_scenario_csv"].open(encoding="utf-8") as f:
        assert len(list(csv.reader(f))) > 1
    text = paths["summary"].read_text(encoding="utf-8")
    assert "Synthetic data only" in text and "Limitations" in text and "n/as" not in text


def test_result_hash_is_stable_across_processes_and_hash_seeds(tmp_path):
    """Two fresh interpreters with different PYTHONHASHSEED must agree: no set-order or id() dependence."""
    hashes = []
    for hashseed in ("1", "2"):
        env = {**os.environ, "PYTHONHASHSEED": hashseed}
        out = subprocess.run(
            [sys.executable, "-m", "app.evaluation", "--seeds", "5", "--scenarios", "normal_control",
             "--methods", "current,threshold_10pct", "--workers", "1", "--out", str(tmp_path / hashseed)],
            cwd=REPO_ROOT / "backend", env=env, capture_output=True, text=True, timeout=300)
        assert out.returncode == 0, out.stderr
        hashes.append(out.stdout.split()[2])
    assert hashes[0] == hashes[1] and len(hashes[0]) == 64


def test_cli_rejects_unknown_names(capsys):
    from app.evaluation.__main__ import main
    assert main(["--scenarios", "nope"]) == 2
    assert main(["--methods", "nope"]) == 2


def test_every_scenario_has_a_truth_definition():
    for sid, scn in SCENARIOS.items():
        t = truth_for(scn)
        assert t.inject_start < t.inject_end and t.sim_hours > 0
        assert t.injected is (scn.expectation is not None)
