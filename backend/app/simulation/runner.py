"""Headless simulation runner.

Safety properties (each is asserted by tests):

* The pipeline runs against a fresh SQLite file in a temporary directory that is
  deleted afterwards; the dashboard's database is never opened.
* ``aws_mode`` is ``off`` and email is disabled; the notifiers are never started.
* Input is generated in memory by ``generator`` (synthetic ids, RFC 5737
  documentation IPs); no log file or real system is read.
* Notification *decisions* are counted, so flood prevention is measurable, but
  nothing is sent.
"""

from __future__ import annotations

import asyncio
import json
import random
import statistics
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from app.config import REPO_ROOT, AppConfig, Settings, load_config
from app.incidents.view import evidence_quality
from app.pipeline import Pipeline
from app.simulation.scenarios import (
    DEFAULT_BENCHMARK_SEEDS, SCENARIOS, SIM_START, TAIL_SECONDS, WARMUP_SECONDS, SimScenario,
)

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _generator():
    from generator import generate as gen  # imported late: the generator is a sibling package

    return gen


def stream_labels(scn: SimScenario) -> dict[str, str]:
    """The labelled injection interval; identical for every seed."""
    t0 = SIM_START
    inject_start = t0 + timedelta(seconds=WARMUP_SECONDS)
    inject_end = inject_start + timedelta(seconds=scn.inject_seconds)
    end = inject_end + timedelta(seconds=TAIL_SECONDS)
    return {"start": t0.isoformat(), "inject_start": inject_start.isoformat(),
            "inject_end": inject_end.isoformat(), "end": end.isoformat()}


def build_stream(scn: SimScenario, seed: int) -> tuple[list[str], dict[str, str]]:
    """Deterministic synthetic log lines (all three logs merged by timestamp)
    plus the labelled injection interval."""
    gen = _generator()
    rng = random.Random(seed)
    t0 = SIM_START
    inject_start = t0 + timedelta(seconds=WARMUP_SECONDS)
    inject_end = inject_start + timedelta(seconds=scn.inject_seconds)

    events: list[dict] = []
    for name, start, duration in (
        (None, t0, WARMUP_SECONDS),
        (scn.generator_scenario, inject_start, scn.inject_seconds),
        (None, inject_end, TAIL_SECONDS),
    ):
        app, audit, auth = gen.generate_events(name, duration, scn.rate, start, rng)
        events += app + audit + auth
    events.sort(key=lambda e: e["ts"])
    return [json.dumps(e) for e in events], stream_labels(scn)


def _isolated_settings(workdir: Path) -> Settings:
    # Explicit values beat the environment and .env, so credentials configured
    # for the real app can never leak into a simulation.
    return Settings(
        _env_file=None,
        aws_mode="off", email_enabled=False, database_url="",
        log_dir=workdir / "logs", db_path=workdir / "sim.db", control_file=workdir / "control.json",
        static_dir=workdir / "static", embedded_generator=False, metrics_persist_interval_seconds=0.0,
        retention_interval_hours=0, redaction_enabled=True,
    )


def _first_alert_ts(incident, alerts_by_incident: dict[int, list]) -> datetime:
    alerts = alerts_by_incident.get(incident.id or -1) or []
    return min((a.ts for a in alerts), default=incident.opened_at)


def _entity(incident) -> str:
    return incident.service or incident.user_id or ""


async def run_scenario_async(
    scenario_id: str, seed: Optional[int] = None, *,
    config: Optional[AppConfig] = None, collect: Optional[dict[str, Any]] = None,
    lines: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Run one scenario through the real pipeline.

    ``config`` overrides config.yaml (used by the evaluation ablations; the
    caller must pass a copy, never the cached shared object). ``collect``, when
    given, is filled with the raw ``incidents`` and ``alerts`` so the evaluation
    can score them on its own terms. ``lines`` lets a caller reuse an already
    built stream for the same (scenario, seed). None of these change the default
    behaviour or the result dict.
    """
    scn = SCENARIOS.get(scenario_id)
    if scn is None:
        raise KeyError(scenario_id)
    seed = scn.seed if seed is None else int(seed)
    built, labels = build_stream(scn, seed) if lines is None else (lines, stream_labels(scn))
    lines = built
    inject_start = datetime.fromisoformat(labels["inject_start"])
    inject_end = datetime.fromisoformat(labels["inject_end"])
    sim_end = datetime.fromisoformat(labels["end"])

    with tempfile.TemporaryDirectory(prefix="healthtrace-sim-") as tmp:
        workdir = Path(tmp)
        (workdir / "logs").mkdir()
        pipeline = Pipeline(_isolated_settings(workdir), config or load_config())
        decisions: list[dict[str, Any]] = []
        original_record = pipeline.incidents.record_alert

        def recording(anomaly, alert):
            update = original_record(anomaly, alert)
            if update.should_notify and (update.is_new or update.is_escalation):
                decisions.append({"ts": alert.ts.isoformat(), "incident_id": update.incident.id,
                                  "severity": update.incident.peak_severity, "escalation": update.is_escalation})
            return update

        pipeline.incidents.record_alert = recording  # type: ignore[method-assign]
        await pipeline.store.connect()
        try:
            for line in lines:
                await pipeline._process_line(line)
            incidents = await pipeline.store.list_incidents()
            alerts = await pipeline.store.list_alerts(limit=100000)
            evidence: dict[int, list[dict]] = {}
            for inc in incidents:
                rows = await (await pipeline.store.conn.execute(
                    "SELECT record_json FROM evidence_events WHERE incident_id = ? ORDER BY ts, id", (inc.id,))
                ).fetchall()
                evidence[inc.id] = [json.loads(r[0]) for r in rows]
            events_processed = dict(pipeline.events_processed)
        finally:
            await pipeline.store.close()

    if collect is not None:
        collect["incidents"], collect["alerts"], collect["labels"] = incidents, alerts, labels
    alerts_by_incident: dict[int, list] = {}
    for a in alerts:
        alerts_by_incident.setdefault(a.incident_id or -1, []).append(a)

    exp = scn.expectation
    allowed = {(k, e) for k, e in scn.allowed_extra}
    matched = None
    false_positives: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for inc in sorted(incidents, key=lambda i: _first_alert_ts(i, alerts_by_incident)):
        first = _first_alert_ts(inc, alerts_by_incident)
        row = {
            "incident_id": inc.id, "kind": inc.kind, "entity": _entity(inc), "peak_severity": inc.peak_severity,
            "state": inc.state, "first_alert_at": first.isoformat(), "alert_count": inc.alert_count,
            "evidence_count": len(evidence.get(inc.id, [])),
            "evidence_quality": evidence_quality(len(evidence.get(inc.id, []))),
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        }
        is_target = exp is not None and inc.kind == exp.kind and _entity(inc) == exp.entity
        if is_target and first >= inject_start and matched is None:
            row["label"] = "expected"
            matched = (inc, first)
        elif (inc.kind, _entity(inc)) in allowed and first >= inject_start:
            row["label"] = "related"
            related.append(row)
        else:
            row["label"] = "false_positive"
            false_positives.append(row)
        rows.append(row)

    hours = (sim_end - SIM_START).total_seconds() / 3600
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, expected: Any, observed: Any) -> None:
        checks.append({"name": name, "passed": bool(passed), "expected": expected, "observed": observed})

    delay: Optional[float] = None
    if exp is not None:
        check("detected", matched is not None, f"{exp.kind} incident for {exp.entity}",
              f"{matched[0].kind} #{matched[0].id}" if matched else "no matching incident")
        if matched:
            inc, first = matched
            delay = round((first - inject_start).total_seconds(), 1)
            ev = evidence.get(inc.id, [])
            check("severity", inc.peak_severity in exp.severities, " or ".join(exp.severities), inc.peak_severity)
            check("detection_delay", 0 <= delay <= exp.max_delay_s, f"<= {exp.max_delay_s:g}s", f"{delay:g}s")
            check("evidence_count", len(ev) >= exp.min_evidence, f">= {exp.min_evidence}", len(ev))
            wrong = [r for r in ev if r.get("type") != exp.evidence_type]
            check("evidence_source", bool(ev) and not wrong, f"all '{exp.evidence_type}' records",
                  "ok" if ev and not wrong else f"{len(wrong)} of {len(ev)} from another log")
            if scn.must_resolve:
                check("resolved", inc.state == "RESOLVED", "RESOLVED", inc.state)
    check("false_positives", len(false_positives) == 0, 0, len(false_positives))
    staff = [d for d in decisions if d["severity"] in ("HIGH", "CRITICAL")]
    repeats = len(decisions) - len({(d["incident_id"], d["severity"]) for d in decisions})
    check("notification_flood", repeats == 0 and len(staff) <= scn.max_notifications,
          f"no repeat at the same severity; <= {scn.max_notifications} HIGH/CRITICAL notifications",
          f"{repeats} repeats; {len(staff)} HIGH/CRITICAL")

    passed = all(c["passed"] for c in checks)
    failed = [c["name"] for c in checks if not c["passed"]]
    summary = ("PASS: " if passed else "FAIL (" + ", ".join(failed) + "): ") + scn.title
    resolve_s = None
    if matched and matched[0].resolved_at:
        resolve_s = round((matched[0].resolved_at - inject_end).total_seconds(), 1)

    return {
        "scenario_id": scn.id, "title": scn.title, "description": scn.description, "seed": seed,
        "synthetic": True, "known_limit": scn.known_limit, "passed": passed, "summary": summary, "checks": checks,
        "expected_alerts": scn.expected_alerts,
        "metrics": {
            "detection_delay_s": delay,
            "false_positive_incidents": len(false_positives),
            "false_positives_per_hour": round(len(false_positives) / hours, 3) if hours else 0.0,
            "simulated_hours": round(hours, 3),
            "notification_decisions": len(decisions),
            "staff_notifications": len(staff),
            "time_to_resolve_s": resolve_s,
            "events_processed": events_processed,
            "alerts": len(alerts), "incidents": len(incidents),
        },
        "labels": labels,
        "incidents": rows,
        "notification_decisions": decisions,
        "isolation": {"database": "temporary SQLite file, deleted after the run", "aws_mode": "off",
                      "email": "disabled", "external_calls": 0},
    }


def run_scenario(scenario_id: str, seed: Optional[int] = None, **kwargs: Any) -> dict[str, Any]:
    """Synchronous entry point; runs in its own event loop (use from a thread when already inside one)."""
    return asyncio.run(run_scenario_async(scenario_id, seed, **kwargs))


async def run_scenario_threaded(scenario_id: str, seed: Optional[int] = None) -> dict[str, Any]:
    return await asyncio.to_thread(run_scenario, scenario_id, seed)


def summarize_benchmark(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate detection delay and false-positive rate over labelled runs."""
    attack = [r for r in results if r["scenario_id"] != "normal_control" and not r.get("known_limit")]
    limit = [r for r in results if r.get("known_limit")]
    control = [r for r in results if r["scenario_id"] == "normal_control"]
    delays = [r["metrics"]["detection_delay_s"] for r in attack if r["metrics"]["detection_delay_s"] is not None]
    detected = sum(1 for r in attack if r["metrics"]["detection_delay_s"] is not None)
    ctrl_hours = sum(r["metrics"]["simulated_hours"] for r in control)
    ctrl_fp = sum(r["metrics"]["false_positive_incidents"] for r in control)
    all_hours = sum(r["metrics"]["simulated_hours"] for r in results)
    all_fp = sum(r["metrics"]["false_positive_incidents"] for r in results)
    return {
        "runs": len(results), "passed": sum(1 for r in results if r["passed"]),
        "injected_runs": len(attack), "detected": detected,
        "detection_rate": round(detected / len(attack), 3) if attack else None,
        "detection_delay_s": {
            "median": statistics.median(delays) if delays else None,
            "max": max(delays) if delays else None,
        },
        "known_limit_runs": len(limit),
        "known_limit_detected": sum(1 for r in limit if r["metrics"]["detection_delay_s"] is not None),
        "control_runs": len(control), "control_false_positives": ctrl_fp,
        "control_false_positives_per_hour": round(ctrl_fp / ctrl_hours, 3) if ctrl_hours else None,
        "all_false_positives": all_fp,
        "all_false_positives_per_hour": round(all_fp / all_hours, 3) if all_hours else None,
    }


def run_benchmark(seeds: tuple[int, ...] = DEFAULT_BENCHMARK_SEEDS, scenario_ids: Optional[list[str]] = None) -> dict[str, Any]:
    ids = scenario_ids or list(SCENARIOS)
    results = [run_scenario(sid, seed) for seed in seeds for sid in ids]
    return {"seeds": list(seeds), "summary": summarize_benchmark(results),
            "runs": [{"scenario_id": r["scenario_id"], "seed": r["seed"], "passed": r["passed"],
                      "detection_delay_s": r["metrics"]["detection_delay_s"], "known_limit": r["known_limit"],
                      "false_positive_incidents": r["metrics"]["false_positive_incidents"],
                      "failed_checks": [c["name"] for c in r["checks"] if not c["passed"]]} for r in results]}
