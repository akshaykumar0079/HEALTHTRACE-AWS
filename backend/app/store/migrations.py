"""Versioned, additive schema migrations for SQLite and PostgreSQL.

Rules every migration follows:

* **Never destructive.** Only ``CREATE ... IF NOT EXISTS`` and ``ADD COLUMN``;
  no DROP, no DELETE, no type rewrites. An existing database keeps every row.
* **Idempotent.** Re-running a migration that half-applied is safe, so a crash
  mid-migration cannot wedge startup.
* **Recorded.** ``schema_migrations`` lists what has run and when.

Version 1 is the schema the app shipped with before migrations existed. A
database created by an older build already has those tables; ``IF NOT EXISTS``
adopts it without touching its data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

from app.store.database import Database

log = logging.getLogger("healthtrace.db")

SEVERITIES = "('LOW','MEDIUM','HIGH','CRITICAL')"
INCIDENT_STATES = "('OPEN','ACKNOWLEDGED','INVESTIGATING','RESOLVED')"


async def _m001_baseline_schema(db: Database) -> None:
    pk, real, big = db.pk, db.real, db.bigint
    await db.run_script(
        f"""
        CREATE TABLE IF NOT EXISTS metrics (
            id {pk},
            service TEXT NOT NULL,
            window_end TEXT NOT NULL,
            total INTEGER NOT NULL,
            errors INTEGER NOT NULL,
            error_rate {real} NOT NULL,
            p95_latency_ms {real} NOT NULL,
            urgent_errors INTEGER NOT NULL,
            affected_patients_urgent INTEGER NOT NULL,
            affected_patients_routine INTEGER NOT NULL,
            malformed_lines INTEGER NOT NULL DEFAULT 0,
            baseline_mean {real},
            baseline_std {real}
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_service_ts ON metrics(service, window_end);

        CREATE TABLE IF NOT EXISTS alerts (
            id {pk},
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            service TEXT,
            user_id TEXT,
            severity TEXT NOT NULL,
            score {real} NOT NULL,
            explanation TEXT NOT NULL,
            metrics_json TEXT NOT NULL DEFAULT '{{}}',
            incident_id {big}
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_service ON alerts(service);

        CREATE TABLE IF NOT EXISTS incidents (
            id {pk},
            fingerprint TEXT NOT NULL,
            kind TEXT NOT NULL,
            service TEXT,
            user_id TEXT,
            state TEXT NOT NULL,
            peak_severity TEXT NOT NULL,
            alert_count INTEGER NOT NULL DEFAULT 1,
            opened_at TEXT NOT NULL,
            acknowledged_at TEXT,
            resolved_at TEXT,
            mttr_seconds {real}
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state);

        CREATE TABLE IF NOT EXISTS incident_events (
            id {pk},
            incident_id {big} NOT NULL,
            ts TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);

        CREATE TABLE IF NOT EXISTS baselines (
            service TEXT NOT NULL,
            hour_of_day INTEGER NOT NULL,
            metric TEXT NOT NULL,
            mean {real} NOT NULL,
            variance {real} NOT NULL,
            count INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (service, hour_of_day, metric)
        );

        CREATE TABLE IF NOT EXISTS tail_positions (
            path TEXT PRIMARY KEY,
            file_id {big},
            "offset" {big} NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS access_stats (
            user_id TEXT NOT NULL,
            metric TEXT NOT NULL,
            mean {real} NOT NULL,
            variance {real} NOT NULL,
            count INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, metric)
        )
        """
    )
    # Databases from builds that predate the baseline columns on `metrics`.
    for column in ("baseline_mean", "baseline_std"):
        await db.add_column_if_missing("metrics", column, real)


async def _m002_incident_workflow(db: Database) -> None:
    """Pinning, the INVESTIGATING status, last-seen/peak-score tracking, the
    evidence table, the audit log and persisted notification settings."""
    pk, real, big = db.pk, db.real, db.bigint

    await db.add_column_if_missing("incidents", "pinned", "INTEGER NOT NULL DEFAULT 0")
    await db.add_column_if_missing("incidents", "pinned_at", "TEXT")
    await db.add_column_if_missing("incidents", "investigating_at", "TEXT")
    await db.add_column_if_missing("incidents", "last_seen_at", "TEXT")
    # Highest real detector score seen (NULL for rule-based HIPAA detections).
    await db.add_column_if_missing("incidents", "peak_score", real)
    await db.add_column_if_missing("incidents", "muted_until", "TEXT")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_pinned ON incidents(pinned)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_opened ON incidents(opened_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")

    if db.dialect == "postgres":
        # SQLite cannot add a CHECK to an existing table; PostgreSQL can.
        for name, expr in (
            ("ck_incidents_state", f"state IN {INCIDENT_STATES}"),
            ("ck_incidents_severity", f"peak_severity IN {SEVERITIES}"),
        ):
            rows = await db.execute("SELECT 1 FROM pg_constraint WHERE conname = ?", (name,))
            if not await rows.fetchall():
                await db.execute(f"ALTER TABLE incidents ADD CONSTRAINT {name} CHECK ({expr})")

    await db.run_script(
        f"""
        CREATE TABLE IF NOT EXISTS evidence_events (
            id {pk},
            incident_id {big} NOT NULL,
            alert_id {big},
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            service TEXT,
            level TEXT,
            summary TEXT NOT NULL,
            record_json TEXT NOT NULL,
            digest TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT uq_evidence_digest UNIQUE (incident_id, digest)
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence_events(incident_id, ts);

        CREATE TABLE IF NOT EXISTS audit_log (
            id {pk},
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT,
            detail TEXT,
            outcome TEXT NOT NULL DEFAULT 'ok'
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
        CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);

        CREATE TABLE IF NOT EXISTS notification_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 1,
            recipients TEXT NOT NULL DEFAULT '',
            min_severity TEXT NOT NULL DEFAULT 'HIGH' CHECK (min_severity IN {SEVERITIES}),
            cooldown_seconds INTEGER NOT NULL DEFAULT 300 CHECK (cooldown_seconds >= 0),
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL DEFAULT 'system'
        );

        CREATE TABLE IF NOT EXISTS notification_attempts (
            id {pk},
            ts TEXT NOT NULL,
            channel TEXT NOT NULL,
            kind TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('accepted','failed','skipped')),
            incident_id {big},
            severity TEXT,
            provider_message_id TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_notif_attempts_ts ON notification_attempts(ts)
        """
    )


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Database], Awaitable[None]]


MIGRATIONS: list[Migration] = [
    Migration(1, "baseline_schema", _m001_baseline_schema),
    Migration(2, "incident_workflow", _m002_incident_workflow),
]

LATEST_VERSION = MIGRATIONS[-1].version


async def applied_versions(db: Database) -> dict[int, str]:
    if not await db.table_exists("schema_migrations"):
        return {}
    rows = await (await db.execute("SELECT version, applied_at FROM schema_migrations ORDER BY version")).fetchall()
    return {int(r[0]): r[1] for r in rows}


async def migrate(db: Database) -> list[int]:
    """Apply every pending migration in order. Returns the versions applied."""
    await db.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    await db.commit()
    done = await applied_versions(db)
    newly: list[int] = []
    for migration in MIGRATIONS:
        if migration.version in done:
            continue
        log.info("applying migration %03d %s (%s)", migration.version, migration.name, db.dialect)
        await migration.apply(db)
        await db.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (migration.version, migration.name, datetime.now(timezone.utc).isoformat()),
        )
        await db.commit()
        newly.append(migration.version)
    return newly
