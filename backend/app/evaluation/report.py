"""Write the machine-readable results (JSON, CSV) and the readable summary (Markdown)."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Optional

from app.simulation.scenarios import SCENARIOS

# Scenarios whose expected detection is an application-service metric (plus the control run).
SERVICE_SCENARIOS = tuple(sid for sid, s in SCENARIOS.items()
                          if s.expectation is None or s.expectation.kind in ("error_rate", "latency_degradation"))

RUN_COLUMNS = ["scenario_id", "seed", "method", "applicable", "known_limit", "expected_kind", "expected_entity",
               "detections", "tp", "fp", "fn", "collateral", "duplicates", "delay_s", "actionable_delay_s",
               "actionable_detected", "sim_hours", "reason"]
AGG_COLUMNS = ["runs", "injected_runs", "control_runs", "tp", "fp", "fn", "collateral", "duplicates", "precision",
               "precision_strict", "recall", "f1", "actionable_recall", "simulated_hours", "false_alarms_per_hour",
               "runs_with_false_alarm"]


def _pct(v: Optional[float]) -> str:
    return "n/a" if v is None else f"{v * 100:.0f}%"


def _num(v: Optional[float]) -> str:
    return "n/a" if v is None else f"{v:g}"


def _sec(v: Optional[float]) -> str:
    return "n/a" if v is None else f"{v:g}s"


def _ci(v: Optional[list]) -> str:
    return "" if not v else f" ({v[0] * 100:.0f}-{v[1] * 100:.0f}%)"


def _delay(d: dict) -> str:
    return "n/a" if not d["n"] else f"{d['median']:g} (max {d['max']:g}, n={d['n']})"


def distinct_false_alarms(rows: list[dict], method: str, scenario_ids: Optional[set] = None) -> int:
    """False-alarm incidents with the same seed, kind, entity and first-alert second collapsed into one.

    Runs that share a seed share their warm-up traffic (and sometimes the tail), so the same chance
    fluctuation can be counted once per scenario. This is the count closest to 'independent events'."""
    seen = set()
    for r in rows:
        if r["method"] != method or not r["applicable"] or (scenario_ids is not None and r["scenario_id"] not in scenario_ids):
            continue
        for l in r["incident_labels"]:
            if l["label"] == "fp":
                seen.add((r["seed"], l["kind"], l["entity"], l["first_ts"][:19]))
    return len(seen)


def write_all(result: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {k: out_dir / v for k, v in {
        "json": "results.json", "runs_csv": "runs.csv", "per_scenario_csv": "per_scenario.csv",
        "aggregate_csv": "aggregate.csv", "summary": "summary.md"}.items()}
    paths["json"].write_text(json.dumps(result, indent=2), encoding="utf-8")

    with paths["runs_csv"].open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=RUN_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(result["runs"])

    with paths["per_scenario_csv"].open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["method", "scenario_id", "applicable", "known_limit", *AGG_COLUMNS,
                    "delay_median_s", "delay_max_s", "delay_n", "actionable_delay_median_s"])
        for method, scenarios in result["per_scenario"].items():
            for sid, a in scenarios.items():
                if not a["applicable"]:
                    w.writerow([method, sid, False])
                    continue
                w.writerow([method, sid, True, a["known_limit"], *[a[c] for c in AGG_COLUMNS],
                            a["delay_s"]["median"], a["delay_s"]["max"], a["delay_s"]["n"],
                            a["actionable_delay_s"]["median"]])

    with paths["aggregate_csv"].open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pool", "method", *AGG_COLUMNS, "delay_median_s", "delay_max_s", "delay_n"])
        for pool in ("aggregate_all_applicable", "aggregate_service_metric_subset"):
            for method, a in result[pool].items():
                w.writerow([pool, method, *[a[c] for c in AGG_COLUMNS],
                            a["delay_s"]["median"], a["delay_s"]["max"], a["delay_s"]["n"]])

    paths["summary"].write_text(render_summary(result), encoding="utf-8")
    return paths


def _same_outcomes(rows: list[dict], a: str, b: str) -> Optional[bool]:
    key = lambda r: (r["scenario_id"], r["seed"])  # noqa: E731
    fields = ("tp", "fp", "fn", "collateral", "duplicates", "delay_s", "actionable_delay_s", "actionable_detected")
    ra = {key(r): r for r in rows if r["method"] == a and r["applicable"]}
    rb = {key(r): r for r in rows if r["method"] == b and r["applicable"]}
    common = ra.keys() & rb.keys()
    if not common:
        return None
    return all(all(ra[k][f] == rb[k][f] for f in fields) for k in common)


def render_summary(result: dict[str, Any]) -> str:
    cfg, info = result["config"], result["run_info"]
    methods = cfg["method_ids"]
    L: list[str] = []
    add = L.append
    add("# HEALTH TRACE evaluation summary")
    add("")
    add("**Synthetic data only.** Results describe this prototype on the generator's scenarios. They are not a claim "
        "about real-world accuracy, clinical validity or HIPAA compliance.")
    add("")
    add(f"- Seeds ({len(cfg['seeds'])}): {', '.join(map(str, cfg['seeds']))}")
    add(f"- Scenarios: {', '.join(cfg['scenario_ids'])}")
    add(f"- Methods: {', '.join(methods)}")
    add(f"- Runs recorded: {len(result['runs'])} (method x scenario x seed)")
    add(f"- config.yaml sha256: `{cfg['config_yaml_sha256'][:16]}...`; results sha256: `{result['results_sha256'][:16]}...`")
    add(f"- Code: commit `{(info['git_commit'] or 'unknown')[:10]}`{' (uncommitted changes present)' if info['git_dirty'] else ''}; "
        f"Python {info['python']}; generated {info['generated_at']}")
    add("")
    add("## Headline: service-metric scenarios, all methods on identical runs")
    add("")
    add("Scenarios: error spike, prior-auth failure, recovery, mild degradation and the normal control. The access and "
        "login scenarios are rule-based (the baseline and service ablations do not apply) and appear only in the per-scenario tables. Intervals are 95% Wilson intervals.")
    add("")
    add("| Method | TP | FP | Distinct FP events | FN | Collateral | Precision | Recall | False alarms / h | Delay s, median | Actionable (HIGH+) recall |")
    add("|---|---|---|---|---|---|---|---|---|---|---|")
    service_ids = {sid for sid in cfg["scenario_ids"] if sid in SERVICE_SCENARIOS}
    for m in methods:
        a = result["aggregate_service_metric_subset"].get(m)
        if a is None:
            continue
        add(f"| {m} | {a['tp']} | {a['fp']} | {distinct_false_alarms(result['runs'], m, service_ids)} | {a['fn']} | {a['collateral']} | {_pct(a['precision'])}{_ci(a['precision_ci95'])} | "
            f"{_pct(a['recall'])}{_ci(a['recall_ci95'])} | {_num(a['false_alarms_per_hour'])} | {_delay(a['delay_s'])} | "
            f"{_pct(a['actionable_recall'])} |")
    add("")
    add("## Current detector, all scenarios")
    add("")
    add("| Scenario | Runs | Recall | FP | Collateral | Delay s, median (max, n) | Actionable delay s, median | Notes |")
    add("|---|---|---|---|---|---|---|---|")
    for sid in cfg["scenario_ids"]:
        a = result["per_scenario"].get("current", {}).get(sid)
        if a is None or not a["applicable"]:
            continue
        note = "documented known limit" if a["known_limit"] else ("control: any incident is a false alarm" if not a["injected_runs"] else "")
        rec = "n/a (control)" if not a["injected_runs"] else f"{_pct(a['recall'])} ({a['tp']}/{a['tp'] + a['fn']})"
        add(f"| {sid} | {a['runs']} | {rec} | {a['fp']} | {a['collateral']} | {_delay(a['delay_s'])} | "
            f"{_num(a['actionable_delay_s']['median'])} | {note} |")
    add("")
    agg = result["aggregate_all_applicable"].get("current")
    if agg:
        add(f"Pooled over every scenario: precision {_pct(agg['precision'])}{_ci(agg['precision_ci95'])}, strict precision "
            f"(collateral and duplicate incidents counted as errors) {_pct(agg['precision_strict'])}, recall "
            f"{_pct(agg['recall'])}{_ci(agg['recall_ci95'])}, F1 {_num(agg['f1'])}, {_num(agg['false_alarms_per_hour'])} false "
            f"alarms per simulated hour ({agg['runs_with_false_alarm']} of {agg['runs']} runs had one).")
        add("")
    add("## Per-scenario comparison (recall, false positives, median delay)")
    add("")
    add("| Scenario | " + " | ".join(methods) + " |")
    add("|---|" + "---|" * len(methods))
    for sid in cfg["scenario_ids"]:
        cells = []
        for m in methods:
            a = result["per_scenario"][m].get(sid)
            if a is None:
                cells.append("")
            elif not a["applicable"]:
                cells.append("n/a")
            else:
                rec = "ctrl" if not a["injected_runs"] else f"{a['tp']}/{a['tp'] + a['fn']}"
                cells.append(f"{rec}, FP {a['fp']}, {_sec(a['delay_s']['median'])}")
        add(f"| {sid} | " + " | ".join(cells) + " |")
    add("")
    add("`n/a` = the method does not act on that scenario's detector (see Limitations). Cell = hits/injected runs, false-positive "
        "incidents, median detection delay.")
    add("")
    add("## Findings that follow from these runs")
    add("")
    findings = []
    rows = result["runs"]
    for abl, what in (("no_time_aware", "time-aware baselines disabled"), ("no_patient_impact", "patient-impact scoring disabled")):
        if abl in methods and "current" in methods:
            same = _same_outcomes(rows, "current", abl)
            if same is True:
                findings.append(f"With {what}, every applicable run produced exactly the same outcome as the current detector "
                                "(same TP/FP/FN and same delays).")
            elif same is False:
                a, c = result["aggregate_service_metric_subset"].get(abl), result["aggregate_service_metric_subset"].get("current")
                if a and c:
                    findings.append(f"With {what}: recall {_pct(c['recall'])} -> {_pct(a['recall'])}, actionable (HIGH+) recall "
                                    f"{_pct(c['actionable_recall'])} -> {_pct(a['actionable_recall'])}, false alarms/h "
                                    f"{_num(c['false_alarms_per_hour'])} -> {_num(a['false_alarms_per_hour'])}.")
    if "threshold_10pct" in methods and "current" in methods:
        t, c = result["aggregate_service_metric_subset"].get("threshold_10pct"), result["aggregate_service_metric_subset"].get("current")
        if t and c:
            findings.append(f"Fixed 10% threshold vs current detector on the same service-metric runs: recall {_pct(t['recall'])} vs "
                            f"{_pct(c['recall'])}; false alarms/h {_num(t['false_alarms_per_hour'])} vs {_num(c['false_alarms_per_hour'])}; "
                            f"median delay {_num(t['delay_s']['median'])}s vs {_num(c['delay_s']['median'])}s.")
    for f in findings:
        add(f"- {f}")
    if not findings:
        add("- (none computed for the selected methods)")
    add("")
    add("## Limitations of this evaluation")
    add("")
    add("- One synthetic generator with one configuration; the scenarios were written by the same project that wrote the detector. "
        "Nothing here shows the detector works on real logs.")
    add("- The generator has no time-of-day pattern in error rates or latency, and each simulated run lies inside one UTC hour, so "
        "the time-aware baseline cannot show a benefit here. A neutral result for that ablation means 'untested', not 'unnecessary'.")
    add("- The `no_patient_impact` ablation changes the score scale (criticality gets weight 1 instead of 0.5) and the severity "
        "thresholds were not re-tuned, so differences in HIGH+ (actionable) results mix the loss of the patient term with a shifted scale.")
    add("- The HIPAA bulk-access and login detectors are fixed rules; the threshold baseline and the two service ablations "
        "do not apply to them (`n/a`).")
    add("- Incidents are matched to one expected (kind, entity) per scenario. Documented downstream effects are reported as "
        "`collateral`, not as hits or false alarms; the `precision_strict` figure counts them as errors.")
    add(f"- {len(cfg['seeds'])} seeds per scenario: percentages move by several points per run. Runs that share a seed share their "
        "warm-up traffic, so they are not independent: the same chance fluctuation can appear as a false alarm in several scenarios "
        "(see 'Distinct FP events'). The Wilson intervals treat runs as independent and are therefore too narrow; the number of "
        "independent samples is closer to the number of seeds.")
    add("- The injected anomalies are large and abrupt, apart from the single mild-degradation scenario. Performance on slow "
        "drifts, bursty traffic and multi-service incidents is not measured.")
    add("- Detection delay is in simulated event time, measured from the start of the injection to the first alert of the matched "
        "incident. Runs that were missed have no delay and are excluded from it (they appear in recall).")
    add("")
    return "\n".join(L)
