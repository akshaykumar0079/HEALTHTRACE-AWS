"""Run the evaluation grid (scenario x seed x method) and assemble the result document.

The grid is deterministic: a (scenario, seed) pair always yields the same synthetic
stream, every method is deterministic, and parallel workers do not share state, so
the ``results_sha256`` of two runs with the same inputs and code is identical.
Wall-clock facts (time, duration, machine) live in ``run_info`` and are excluded
from that hash.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import CONFIG_YAML_PATH, REPO_ROOT, load_config
from app.evaluation.methods import (
    DEFAULT_METHODS, METHODS, detections_from_pipeline, effective_config, threshold_detections,
)
from app.evaluation.report import SERVICE_SCENARIOS
from app.evaluation.scoring import RunScore, Truth, aggregate, score_run
from app.simulation.runner import build_stream, run_scenario, stream_labels
from app.simulation.scenarios import SCENARIOS, SimScenario

SCHEMA_VERSION = 1
# The three seeds of the existing benchmark first (docs/simulator.md), then seven more.
DEFAULT_SEEDS = (11, 22, 33, 44, 55, 66, 77, 88, 99, 110)


def truth_for(scn: SimScenario) -> Truth:
    labels = stream_labels(scn)
    start, end = datetime.fromisoformat(labels["start"]), datetime.fromisoformat(labels["end"])
    exp = scn.expectation
    return Truth(
        inject_start=datetime.fromisoformat(labels["inject_start"]),
        inject_end=datetime.fromisoformat(labels["inject_end"]),
        sim_hours=(end - start).total_seconds() / 3600,
        kind=exp.kind if exp else None, entity=exp.entity if exp else None,
        collateral=frozenset(scn.allowed_extra),
    )


def run_cell(scenario_id: str, seed: int, method_ids: tuple[str, ...]) -> list[dict[str, Any]]:
    """All requested methods on one (scenario, seed). Module-level so worker processes can import it."""
    scn = SCENARIOS[scenario_id]
    truth = truth_for(scn)
    lines, _ = build_stream(scn, seed)
    rows = []
    for mid in method_ids:
        method = METHODS[mid]
        row: dict[str, Any] = {"scenario_id": scenario_id, "seed": seed, "method": mid,
                               "known_limit": scn.known_limit,
                               "expected_kind": truth.kind, "expected_entity": truth.entity}
        ok, reason = method.applies_to(truth.kind)
        if not ok:
            rows.append({**row, "applicable": False, "reason": reason})
            continue
        if method.kind == "pipeline":
            collected: dict[str, Any] = {}
            run_scenario(scenario_id, seed, config=effective_config(method), collect=collected, lines=lines)
            detections = detections_from_pipeline(collected["incidents"], collected["alerts"])
        else:
            detections = threshold_detections(lines, float(method.threshold))
        s = score_run(truth, detections)
        rows.append({**row, "applicable": True, "reason": "", "detections": len(detections),
                     "tp": s.tp, "fp": s.fp, "fn": s.fn, "collateral": s.collateral, "duplicates": s.duplicates,
                     "delay_s": s.delay_s, "actionable_delay_s": s.actionable_delay_s,
                     "actionable_detected": s.actionable_detected, "sim_hours": round(s.sim_hours, 4),
                     "incident_labels": s.labels})
    return rows


def _to_score(row: dict) -> RunScore:
    return RunScore(injected=row["expected_kind"] is not None, tp=row["tp"], fp=row["fp"], fn=row["fn"],
                    collateral=row["collateral"], duplicates=row["duplicates"], delay_s=row["delay_s"],
                    actionable_delay_s=row["actionable_delay_s"], actionable_detected=row["actionable_detected"],
                    sim_hours=row["sim_hours"])


def summarize(rows: list[dict], method_ids: tuple[str, ...], scenario_ids: tuple[str, ...]) -> dict[str, Any]:
    per_scenario: dict[str, dict] = {m: {} for m in method_ids}
    pooled: dict[str, list[RunScore]] = {m: [] for m in method_ids}
    common: dict[str, list[RunScore]] = {m: [] for m in method_ids}
    not_applicable: dict[str, list[str]] = {m: [] for m in method_ids}
    for m in method_ids:
        for sid in scenario_ids:
            mine = [r for r in rows if r["method"] == m and r["scenario_id"] == sid]
            if not mine:
                continue
            if not mine[0]["applicable"]:
                not_applicable[m].append(sid)
                per_scenario[m][sid] = {"applicable": False, "reason": mine[0]["reason"]}
                continue
            scores = [_to_score(r) for r in mine]
            per_scenario[m][sid] = {"applicable": True, "known_limit": SCENARIOS[sid].known_limit,
                                    "expected_kind": mine[0]["expected_kind"],
                                    "expected_entity": mine[0]["expected_entity"], **aggregate(scores)}
            pooled[m] += scores
            if sid in SERVICE_SCENARIOS:
                common[m] += scores
    return {
        "per_scenario": per_scenario,
        "aggregate_all_applicable": {m: aggregate(v) for m, v in pooled.items() if v},
        "aggregate_service_metric_subset": {m: aggregate(v) for m, v in common.items() if v},
        "not_applicable": {m: v for m, v in not_applicable.items() if v},
    }


def _flat_diff(a: Any, b: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(a, dict) and isinstance(b, dict):
        out: dict[str, Any] = {}
        for k in sorted(set(a) | set(b)):
            out.update(_flat_diff(a.get(k), b.get(k), f"{prefix}{k}."))
        return out
    return {} if a == b else {prefix.rstrip("."): b}


def describe_config(method_ids: tuple[str, ...]) -> dict[str, Any]:
    base = load_config().model_dump(mode="json")
    methods = {}
    for mid in method_ids:
        m = METHODS[mid]
        entry: dict[str, Any] = {"title": m.title, "description": m.description, "type": m.kind,
                                 "sensitivity_variant": m.sensitivity, "service_metric_scenarios_only": m.service_only}
        if m.kind == "pipeline":
            entry["config_overrides"] = _flat_diff(base, effective_config(m).model_dump(mode="json"))
        else:
            cfg = load_config()
            entry["parameters"] = {"error_rate_threshold": m.threshold,
                                   "min_errors": cfg.anomaly.error_rate_min_errors,
                                   "window_seconds": cfg.window.size_seconds, "step_seconds": cfg.window.step_seconds,
                                   "close_after_calm_windows": cfg.incident.service_auto_resolve_windows}
        methods[mid] = entry
    return {
        "config_yaml_sha256": hashlib.sha256(CONFIG_YAML_PATH.read_bytes()).hexdigest(),
        "detector_config": base,
        "methods": methods,
        "scenarios": {sid: {
            "title": s.title, "generator_scenario": s.generator_scenario, "inject_seconds": s.inject_seconds,
            "events_per_second": s.rate, "known_limit": s.known_limit, "labelled_normal": s.labelled_normal,
            "expected_kind": s.expectation.kind if s.expectation else None,
            "expected_entity": s.expectation.entity if s.expectation else None,
            "collateral_allowed": [list(x) for x in s.allowed_extra],
            "labels": stream_labels(s)} for sid, s in SCENARIOS.items()},
        "synthetic_only": True,
    }


def _git(*args: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def canonical_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_experiment(seeds: tuple[int, ...] = DEFAULT_SEEDS, scenario_ids: Optional[tuple[str, ...]] = None,
                   method_ids: tuple[str, ...] = DEFAULT_METHODS, workers: int = 1) -> dict[str, Any]:
    scenario_ids = tuple(scenario_ids or SCENARIOS)
    for sid in scenario_ids:
        if sid not in SCENARIOS:
            raise KeyError(f"unknown scenario: {sid}")
    for mid in method_ids:
        if mid not in METHODS:
            raise KeyError(f"unknown method: {mid}")
    started = time.time()
    cells = [(sid, seed) for sid in scenario_ids for seed in seeds]
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(run_cell, [c[0] for c in cells], [c[1] for c in cells], [method_ids] * len(cells)))
    else:
        results = [run_cell(sid, seed, method_ids) for sid, seed in cells]
    rows = [r for cell in results for r in cell]

    config = {"seeds": list(seeds), "scenario_ids": list(scenario_ids), "method_ids": list(method_ids),
              **describe_config(method_ids)}
    body = {"schema_version": SCHEMA_VERSION, "config": config, "runs": rows,
            **summarize(rows, method_ids, scenario_ids)}
    body["results_sha256"] = canonical_hash({"config": config, "runs": rows})
    body["run_info"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "elapsed_seconds": round(time.time() - started, 1),
        "git_commit": _git("rev-parse", "HEAD"), "git_dirty": bool(_git("status", "--porcelain")),
        "python": sys.version.split()[0], "platform": platform.platform(), "workers": workers,
        "note": "run_info is excluded from results_sha256",
    }
    return body
