"""Why an incident was raised: the rule, its thresholds and the observed
values, taken from stored alerts and the live configuration (never invented)."""

from __future__ import annotations

from typing import Any, Optional

from app.config import AppConfig
from app.models import Alert, Incident


def detection_rule(config: AppConfig, kind: str) -> dict[str, Any]:
    """The detection rule for this kind in config terms."""
    a, s, h, w = config.anomaly, config.severity, config.hipaa, config.window
    if kind == "error_rate":
        return {"metric": "error_rate", "z_threshold": a.error_rate_z_threshold, "min_errors": a.error_rate_min_errors,
                "min_rate": a.error_rate_min_rate, "min_std": a.min_std, "window_seconds": w.size_seconds,
                "step_seconds": w.step_seconds, "severity": s.model_dump()}
    if kind == "latency_degradation":
        return {"metric": "p95_latency_ms", "z_threshold": a.latency_z_threshold, "min_std": a.latency_min_std_ms,
                "window_seconds": w.size_seconds, "step_seconds": w.step_seconds, "severity": s.model_dump()}
    if kind == "auth_suspicious_login":
        return {"metric": kind, **config.auth.model_dump()}
    return {"metric": kind, "rolling_window_minutes": 10, "hipaa": h.model_dump()}


def _rule_text(config: AppConfig, kind: str) -> str:
    a = config.anomaly
    if kind == "error_rate":
        return (f"Alert when the 60s error rate is at least {a.error_rate_z_threshold:g} standard deviations above "
                f"this service's learned baseline for the hour of day, with at least {a.error_rate_min_errors} errors "
                f"and a rate of at least {a.error_rate_min_rate:.0%}.")
    if kind == "latency_degradation":
        return (f"Alert when 60s p95 latency is at least {a.latency_z_threshold:g} standard deviations above this "
                "service's learned baseline.")
    if kind == "auth_suspicious_login":
        c = config.auth
        return (f"Alert when a successful login follows at least {c.failure_threshold} failed logins for the same user "
                f"within {c.window_minutes:g} minutes. Severity rises for an unfamiliar region or "
                f"{c.failure_threshold * c.high_failure_multiple}+ failures.")
    h = config.hipaa
    return {
        "hipaa_bulk_access": f"Alert when a user touches more distinct patients in 10 minutes than {h.bulk_multiplier_high:g}x their baseline (floor {h.bulk_min_threshold:g}).",
        "hipaa_bulk_export": f"Alert when a user exports at least {h.export_min_threshold:g} records in 10 minutes.",
        "hipaa_off_hours": f"Alert on record access outside {h.off_hours_start}-{h.off_hours_end} ({h.timezone}).",
        "hipaa_region_mismatch": "Alert when a user accesses patients registered in a different region.",
    }.get(kind, kind)


def explain_detection(config: AppConfig, incident: Incident, alerts: list[Alert], *, alert_id: Optional[int] = None) -> dict[str, Any]:
    """Baseline vs observed, rule, threshold and reason for the alert behind
    an incident: the selected alert, else the highest-severity (then newest)."""
    rule = detection_rule(config, incident.kind)
    base: dict[str, Any] = {"rule": rule, "rule_text": _rule_text(config, incident.kind), "kind": incident.kind,
                            "alert_id": None, "alert_ts": None, "reason": None, "severity": incident.peak_severity,
                            "observed": None, "baseline": None, "threshold": None, "deviation": None,
                            "available": False,
                            "note": "No stored alert for this incident, so the detection values are unavailable."}
    chosen: Optional[Alert] = None
    if alert_id is not None:
        chosen = next((a for a in alerts if a.id == alert_id), None)
    if chosen is None and alerts:
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        chosen = max(alerts, key=lambda a: (order[a.severity], a.ts, a.id or 0))
    if chosen is None:
        return base
    m = chosen.metrics or {}
    base.update(alert_id=chosen.id, alert_ts=chosen.ts.isoformat(), reason=chosen.explanation,
                severity=chosen.severity, available=True, note=None)
    kind = incident.kind
    if kind == "error_rate":
        base["observed"] = {"error_rate": m.get("error_rate"), "errors": m.get("errors"), "total": m.get("total")}
        base["baseline"] = {"mean": m.get("baseline_mean"), "std": m.get("baseline_std")}
        base["threshold"] = {"z": rule["z_threshold"], "min_errors": rule["min_errors"], "min_rate": rule["min_rate"]}
        base["deviation"] = {"z": m.get("z")}
    elif kind == "latency_degradation":
        base["observed"] = {"p95_latency_ms": m.get("p95_latency_ms")}
        base["baseline"] = {"mean": m.get("baseline_mean"), "std": m.get("baseline_std")}
        base["threshold"] = {"z": rule["z_threshold"]}
        base["deviation"] = {"z": m.get("z")}
    elif kind == "auth_suspicious_login":
        base["observed"] = {"failures": m.get("failures"), "success_region": m.get("success_region"),
                            "user_region": m.get("user_region"), "failure_regions": m.get("failure_regions")}
        base["threshold"] = {"failures": m.get("failure_threshold", rule["failure_threshold"])}
        base["baseline"] = None
    else:
        base["observed"] = {k: m.get(k) for k in ("distinct_patients", "records", "multiplier") if k in m}
        base["threshold"] = {k: v for k, v in rule["hipaa"].items() if k.startswith(kind.replace("hipaa_", "").split("_")[0])}
        base["baseline"] = None
    return base
