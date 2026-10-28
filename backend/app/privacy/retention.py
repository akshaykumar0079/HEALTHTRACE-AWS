"""Retention policy and cleanup (docs/privacy-and-retention.md).

Rules, applied by age against the wall clock:

* ``metrics``            window metrics older than ``metrics_hours``;
* ``evidence``           evidence of **resolved/absent** incidents older than ``evidence_days``;
* ``alerts``             alerts of resolved/absent incidents older than ``alerts_days``;
* ``resolved_incidents`` resolved, **unpinned** incidents resolved more than
                         ``resolved_incidents_days`` ago, with their events,
                         alerts and evidence;
* ``notification_attempts`` / ``simulation_runs`` / ``audit`` by their own ages.

Never deleted: incidents that are not resolved, and pinned incidents (a pin
is a deliberate "keep this findable"; unpin to let retention apply).
``0`` disables a rule. ``dry_run`` reports what would be deleted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.store.db import Store


@dataclass(frozen=True)
class RetentionPolicy:
    metrics_hours: int = 24
    evidence_days: int = 30
    alerts_days: int = 90
    resolved_incidents_days: int = 90
    notification_attempts_days: int = 30
    simulation_runs_days: int = 30
    audit_days: int = 365
    research_days: int = 0     # the dataclass default is 'off'; Settings supplies 30 (RETENTION_RESEARCH_DAYS)

    @classmethod
    def from_settings(cls, settings: Any) -> "RetentionPolicy":
        return cls(
            metrics_hours=max(0, int(settings.retention_metrics_hours)),
            evidence_days=max(0, int(settings.retention_evidence_days)),
            alerts_days=max(0, int(settings.retention_alerts_days)),
            resolved_incidents_days=max(0, int(settings.retention_resolved_incidents_days)),
            notification_attempts_days=max(0, int(settings.retention_notification_attempts_days)),
            simulation_runs_days=max(0, int(settings.retention_simulation_runs_days)),
            audit_days=max(0, int(settings.retention_audit_days)),
            research_days=max(0, int(getattr(settings, "retention_research_days", 30))),
        )

    @property
    def all_disabled(self) -> bool:
        return not any(asdict(self).values())

    def describe(self) -> list[dict[str, Any]]:
        def row(name: str, value: int, unit: str, rule: str) -> dict[str, Any]:
            return {"data": name, "keep": f"{value} {unit}" if value else "forever", "enabled": bool(value), "rule": rule}

        return [
            row("Window metrics", self.metrics_hours, "hours", "Deleted when older than the limit."),
            row("Evidence records", self.evidence_days, "days", "Only for resolved incidents; open incidents keep all evidence."),
            row("Alerts", self.alerts_days, "days", "Only for resolved incidents."),
            row("Resolved incidents", self.resolved_incidents_days, "days",
                "Resolved and unpinned only; events, alerts and evidence go with them."),
            row("Notification attempts", self.notification_attempts_days, "days", "Deleted when older than the limit."),
            row("Simulation runs", self.simulation_runs_days, "days", "Deleted when older than the limit."),
            row("Audit log", self.audit_days, "days", "Longest by default; do not shorten without a policy decision."),
            row("Research uploads and experiments", self.research_days, "days",
                "Uploaded datasets and saved experiment records (files, not database rows). An upload still "
                "referenced by a newer experiment is kept until that experiment expires."),
        ]


def _cut(now: datetime, *, days: int = 0, hours: int = 0) -> str:
    return (now - timedelta(days=days, hours=hours)).isoformat()


async def _scalar(store: Store, sql: str, params: tuple = ()) -> int:
    row = await (await store.conn.execute(sql, params)).fetchone()
    return int(row[0]) if row else 0


async def apply_retention(
    store: Store, policy: RetentionPolicy, *, now: Optional[datetime] = None, dry_run: bool = False
) -> dict[str, int]:
    """Returns {data: rows deleted (or that would be deleted)}."""
    now = now or datetime.now(timezone.utc)
    result: dict[str, int] = {}

    resolved_ids_sql = "SELECT id FROM incidents WHERE state = 'RESOLVED'"
    # Incidents eligible for deletion.
    purge_sql = None
    purge_params: tuple = ()
    if policy.resolved_incidents_days:
        purge_sql = (
            "SELECT id FROM incidents WHERE state = 'RESOLVED' AND pinned = 0 "
            "AND resolved_at IS NOT NULL AND resolved_at < ?"
        )
        purge_params = (_cut(now, days=policy.resolved_incidents_days),)

    async def run(name: str, count_sql: str, delete_sql: str, params: tuple) -> None:
        n = await _scalar(store, count_sql, params)
        result[name] = n
        if n and not dry_run:
            await store.conn.execute(delete_sql, params)
            await store.conn.commit()

    if policy.metrics_hours:
        p = (_cut(now, hours=policy.metrics_hours),)
        await run("metrics", "SELECT COUNT(*) FROM metrics WHERE window_end < ?",
                  "DELETE FROM metrics WHERE window_end < ?", p)
    if policy.evidence_days:
        p = (_cut(now, days=policy.evidence_days),)
        cond = f"ts < ? AND (incident_id IN ({resolved_ids_sql}) OR incident_id NOT IN (SELECT id FROM incidents))"
        await run("evidence", f"SELECT COUNT(*) FROM evidence_events WHERE {cond}",
                  f"DELETE FROM evidence_events WHERE {cond}", p)
    if policy.alerts_days:
        p = (_cut(now, days=policy.alerts_days),)
        cond = (f"ts < ? AND (incident_id IS NULL OR incident_id IN ({resolved_ids_sql}) "
                "OR incident_id NOT IN (SELECT id FROM incidents))")
        await run("alerts", f"SELECT COUNT(*) FROM alerts WHERE {cond}", f"DELETE FROM alerts WHERE {cond}", p)
    if purge_sql:
        n = await _scalar(store, f"SELECT COUNT(*) FROM ({purge_sql}) AS t", purge_params)
        result["resolved_incidents"] = n
        if n and not dry_run:
            for table in ("incident_events", "evidence_events", "alerts", "ai_insights"):
                await store.conn.execute(f"DELETE FROM {table} WHERE incident_id IN ({purge_sql})", purge_params)
            await store.conn.execute(f"DELETE FROM incidents WHERE id IN ({purge_sql})", purge_params)
            await store.conn.commit()
    if policy.evidence_days:
        # AI insights are derived from evidence, so they follow the evidence rule (and are regenerable).
        p = (_cut(now, days=policy.evidence_days),)
        cond = "created_at < ?"
        n = await _scalar(store, f"SELECT COUNT(*) FROM ai_insights WHERE {cond}", p)
        if n:
            result["ai_insights"] = n
            if not dry_run:
                await store.conn.execute(f"DELETE FROM ai_insights WHERE {cond}", p)
                await store.conn.commit()
    if policy.notification_attempts_days:
        p = (_cut(now, days=policy.notification_attempts_days),)
        await run("notification_attempts", "SELECT COUNT(*) FROM notification_attempts WHERE ts < ?",
                  "DELETE FROM notification_attempts WHERE ts < ?", p)
    if policy.simulation_runs_days:
        p = (_cut(now, days=policy.simulation_runs_days),)
        await run("simulation_runs", "SELECT COUNT(*) FROM simulation_runs WHERE created_at < ?",
                  "DELETE FROM simulation_runs WHERE created_at < ?", p)
    if policy.audit_days:
        p = (_cut(now, days=policy.audit_days),)
        await run("audit", "SELECT COUNT(*) FROM audit_log WHERE ts < ?", "DELETE FROM audit_log WHERE ts < ?", p)
    return result
