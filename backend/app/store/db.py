"""Persistence (SPEC.md section 6.10) over SQLite locally or PostgreSQL when
``DATABASE_URL`` is set. Statements are written once with ``?`` placeholders;
``app.store.database`` adapts them per engine and ``app.store.migrations``
owns the schema (versioned, additive, never destructive)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from app.models import Alert, Incident, IncidentEvent, WindowMetrics
from app.store.database import Database, create_database
from app.store.migrations import migrate

@dataclass
class BaselineRow:
    service: str
    hour_of_day: int
    metric: str
    mean: float
    variance: float
    count: int


class Store:
    def __init__(self, db_path: Path | str, database_url: Optional[str] = None) -> None:
        self.db_path = Path(db_path)
        self.database_url = database_url or None
        self._db: Optional[Database] = None
        self._last_prune_cutoff: Optional[datetime] = None

    async def connect(self) -> None:
        db = create_database(self.db_path, self.database_url)
        await db.connect()
        self._db = db
        await migrate(db)

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @property
    def conn(self) -> Database:
        if self._db is None:
            raise RuntimeError("Store is not connected; call connect() first")
        return self._db

    @property
    def dialect(self) -> str:
        return self._db.dialect if self._db else "unconnected"

    async def ping(self) -> None:
        await self.conn.ping()

    # -- baselines (Milestone 3) --------------------------------------------

    async def save_baseline(self, row: BaselineRow, *, updated_at: Optional[datetime] = None) -> None:
        ts = (updated_at or datetime.now(timezone.utc)).isoformat()
        await self.conn.execute(
            """
            INSERT INTO baselines (service, hour_of_day, metric, mean, variance, count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(service, hour_of_day, metric)
            DO UPDATE SET mean=excluded.mean, variance=excluded.variance,
                          count=excluded.count, updated_at=excluded.updated_at
            """,
            (row.service, row.hour_of_day, row.metric, row.mean, row.variance, row.count, ts),
        )
        await self.conn.commit()

    async def save_baselines(self, rows: list[BaselineRow]) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        await self.conn.executemany(
            """
            INSERT INTO baselines (service, hour_of_day, metric, mean, variance, count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(service, hour_of_day, metric)
            DO UPDATE SET mean=excluded.mean, variance=excluded.variance,
                          count=excluded.count, updated_at=excluded.updated_at
            """,
            [(r.service, r.hour_of_day, r.metric, r.mean, r.variance, r.count, ts) for r in rows],
        )
        await self.conn.commit()

    # -- tail positions --------------------------------------------------------

    async def save_tail_position(self, path: str, file_id: Optional[int], offset: int) -> None:
        await self.conn.execute(
            """
            INSERT INTO tail_positions (path, file_id, "offset", updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET file_id=excluded.file_id, "offset"=excluded."offset",
                                            updated_at=excluded.updated_at
            """,
            (path, file_id, offset, datetime.now(timezone.utc).isoformat()),
        )
        await self.conn.commit()

    async def load_tail_positions(self) -> dict[str, tuple[Optional[int], int]]:
        cursor = await self.conn.execute('SELECT path, file_id, "offset" FROM tail_positions')
        return {row[0]: (row[1], row[2]) for row in await cursor.fetchall()}

    async def load_baselines(self) -> list[BaselineRow]:
        cursor = await self.conn.execute(
            "SELECT service, hour_of_day, metric, mean, variance, count FROM baselines"
        )
        rows = await cursor.fetchall()
        return [BaselineRow(*row) for row in rows]

    # -- metrics (Milestone 5): 24h retention per SPEC.md 6.10 ----------------

    async def save_metrics(self, metrics: WindowMetrics) -> None:
        await self.conn.execute(
            """
            INSERT INTO metrics
                (service, window_end, total, errors, error_rate, p95_latency_ms,
                 urgent_errors, affected_patients_urgent, affected_patients_routine, malformed_lines,
                 baseline_mean, baseline_std)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                metrics.service, metrics.window_end.isoformat(), metrics.total, metrics.errors,
                metrics.error_rate, metrics.p95_latency_ms, metrics.urgent_errors,
                metrics.affected_patients_urgent, metrics.affected_patients_routine, metrics.malformed_lines,
                metrics.baseline_mean, metrics.baseline_std,
            ),
        )
        cutoff = metrics.window_end - timedelta(hours=24)
        if self._last_prune_cutoff is None or cutoff - self._last_prune_cutoff >= timedelta(minutes=1):
            await self.conn.execute("DELETE FROM metrics WHERE window_end < ?", (cutoff.isoformat(),))
            self._last_prune_cutoff = cutoff
        await self.conn.commit()

    async def list_metrics(self, *, service: str, minutes: int = 15, before: Optional[datetime] = None) -> list[WindowMetrics]:
        end = before or datetime.now(timezone.utc)
        since = (end - timedelta(minutes=minutes)).isoformat()
        cursor = await self.conn.execute(
            """
            SELECT service, window_end, total, errors, error_rate, p95_latency_ms,
                   urgent_errors, affected_patients_urgent, affected_patients_routine, malformed_lines,
                   baseline_mean, baseline_std
            FROM metrics WHERE service = ? AND window_end >= ? ORDER BY window_end ASC
            """,
            (service, since),
        )
        rows = await cursor.fetchall()
        return [
            WindowMetrics(
                service=r[0], window_end=datetime.fromisoformat(r[1]), total=r[2], errors=r[3], error_rate=r[4],
                p95_latency_ms=r[5], urgent_errors=r[6], affected_patients_urgent=r[7],
                affected_patients_routine=r[8], malformed_lines=r[9], baseline_mean=r[10], baseline_std=r[11],
            )
            for r in rows
        ]

    # -- alerts (Milestone 4) -------------------------------------------------

    async def save_alert(self, alert: Alert) -> int:
        new_id = await self.conn.insert(
            """
            INSERT INTO alerts (ts, kind, service, user_id, severity, score, explanation, metrics_json, incident_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.ts.isoformat(), alert.kind, alert.service, alert.user_id, alert.severity, alert.score,
                alert.explanation, json.dumps(alert.metrics), alert.incident_id,
            ),
        )
        await self.conn.commit()
        return new_id

    async def list_alerts(
        self,
        *,
        limit: int = 100,
        severity: Optional[str] = None,
        service: Optional[str] = None,
        kind: Optional[str] = None,
        incident_id: Optional[int] = None,
        user_id: Optional[str] = None,
    ) -> list[Alert]:
        query = "SELECT id, ts, kind, service, user_id, severity, score, explanation, metrics_json, incident_id FROM alerts"
        clauses: list[str] = []
        params: list[object] = []
        for column, value in (
            ("severity", severity), ("service", service), ("kind", kind),
            ("incident_id", incident_id), ("user_id", user_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        cursor = await self.conn.execute(query, params)
        rows = await cursor.fetchall()
        return [_row_to_alert(row) for row in rows]

    # -- incidents ----------------------------------------------------------------

    async def upsert_incident(self, incident: Incident) -> None:
        await self.conn.execute(
            """
            INSERT INTO incidents
                (id, fingerprint, kind, service, user_id, state, peak_severity, alert_count,
                 opened_at, acknowledged_at, resolved_at, mttr_seconds,
                 pinned, pinned_at, investigating_at, last_seen_at, peak_score, muted_until)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                state=excluded.state, peak_severity=excluded.peak_severity, alert_count=excluded.alert_count,
                acknowledged_at=excluded.acknowledged_at, resolved_at=excluded.resolved_at,
                mttr_seconds=excluded.mttr_seconds, pinned=excluded.pinned, pinned_at=excluded.pinned_at,
                investigating_at=excluded.investigating_at, last_seen_at=excluded.last_seen_at,
                peak_score=excluded.peak_score, muted_until=excluded.muted_until
            """,
            (
                incident.id, incident.fingerprint, incident.kind, incident.service, incident.user_id,
                incident.state, incident.peak_severity, incident.alert_count, incident.opened_at.isoformat(),
                _iso_or_none(incident.acknowledged_at), _iso_or_none(incident.resolved_at), incident.mttr_seconds,
                1 if incident.pinned else 0, _iso_or_none(incident.pinned_at), _iso_or_none(incident.investigating_at),
                _iso_or_none(incident.last_seen_at), incident.peak_score, _iso_or_none(incident.muted_until),
            ),
        )
        await self.conn.commit()

    async def get_incident(self, incident_id: int) -> Optional[Incident]:
        cursor = await self.conn.execute(f"SELECT {_INCIDENT_COLS} FROM incidents WHERE id = ?", (incident_id,))
        row = await cursor.fetchone()
        return _row_to_incident(row) if row else None

    async def list_incidents(self, *, state: Optional[str] = None, limit: Optional[int] = None) -> list[Incident]:
        query = f"SELECT {_INCIDENT_COLS} FROM incidents"
        params: list[object] = []
        if state is not None:
            query += " WHERE state = ?"
            params.append(state)
        query += " ORDER BY opened_at DESC, id DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        cursor = await self.conn.execute(query, params)
        rows = await cursor.fetchall()
        return [_row_to_incident(row) for row in rows]

    async def query_incidents(
        self,
        *,
        states: Optional[list[str]] = None,
        severities: Optional[list[str]] = None,
        service: Optional[str] = None,
        pinned: Optional[bool] = None,
        kinds: Optional[list[str]] = None,
        text: Optional[str] = None,
        text_kinds: Optional[list[str]] = None,
        incident_id: Optional[int] = None,
        since: Optional[datetime] = None,
        limit: int = 2000,
    ) -> list[Incident]:
        """Filtered incident search over persisted history. All values are bound
        parameters; ``text`` is matched case-insensitively against service,
        user id, fingerprint and (via ``text_kinds``) the human title."""
        clauses: list[str] = []
        params: list[object] = []

        def in_clause(column: str, values: list[str]) -> None:
            clauses.append(f"{column} IN ({','.join('?' for _ in values)})")
            params.extend(values)

        if states:
            in_clause("state", states)
        if severities:
            in_clause("peak_severity", severities)
        if kinds:
            in_clause("kind", kinds)
        if service:
            clauses.append("service = ?")
            params.append(service)
        if pinned is not None:
            clauses.append("pinned = ?")
            params.append(1 if pinned else 0)
        if since is not None:
            clauses.append("COALESCE(last_seen_at, opened_at) >= ?")
            params.append(since.isoformat())
        if incident_id is not None:
            clauses.append("id = ?")
            params.append(incident_id)
        if text:
            like = f"%{_escape_like(text.lower())}%"
            ors = [
                "LOWER(COALESCE(service, '')) LIKE ? ESCAPE '\\'",
                "LOWER(COALESCE(user_id, '')) LIKE ? ESCAPE '\\'",
                "LOWER(fingerprint) LIKE ? ESCAPE '\\'",
                "LOWER(kind) LIKE ? ESCAPE '\\'",
            ]
            params.extend([like] * 4)
            if text_kinds:
                ors.append(f"kind IN ({','.join('?' for _ in text_kinds)})")
                params.extend(text_kinds)
            clauses.append("(" + " OR ".join(ors) + ")")
        query = f"SELECT {_INCIDENT_COLS} FROM incidents"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY opened_at DESC, id DESC LIMIT ?"
        params.append(limit)
        rows = await (await self.conn.execute(query, params)).fetchall()
        return [_row_to_incident(r) for r in rows]

    # -- evidence (bounded log events that explain an incident) -----------------

    async def save_evidence(
        self, incident_id: int, alert_id: Optional[int], records: list[dict[str, Any]], *, max_per_incident: int = 200
    ) -> int:
        """Persist already-masked log records as evidence. Idempotent per
        (incident, record digest) and capped per incident, so an incident that
        lasts for hours cannot grow the database without bound."""
        import hashlib

        if not records:
            return 0
        current = await self.count_evidence(incident_id)
        room = max_per_incident - current
        if room <= 0:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        saved = 0
        for record in records[:room]:
            body = json.dumps({k: v for k, v in record.items() if k != "seq"}, sort_keys=True, default=str)
            digest = hashlib.sha256(body.encode()).hexdigest()[:32]
            await self.conn.execute(
                """
                INSERT INTO evidence_events
                    (incident_id, alert_id, ts, source, service, level, summary, record_json, digest, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (incident_id, digest) DO NOTHING
                """,
                (
                    incident_id, alert_id, str(record.get("ts", now)), str(record.get("type", "app")),
                    record.get("service"), record.get("level"), str(record.get("msg") or record.get("action") or "")[:300],
                    body, digest, now,
                ),
            )
            saved += 1
        await self.conn.commit()
        return saved

    async def count_evidence(self, incident_id: int) -> int:
        row = await (await self.conn.execute(
            "SELECT COUNT(*) FROM evidence_events WHERE incident_id = ?", (incident_id,))).fetchone()
        return int(row[0]) if row else 0

    async def list_evidence(self, incident_id: int, limit: int = 100) -> list[dict[str, Any]]:
        rows = await (await self.conn.execute(
            "SELECT id, alert_id, ts, record_json FROM evidence_events WHERE incident_id = ? "
            "ORDER BY ts DESC, id DESC LIMIT ?", (incident_id, limit))).fetchall()
        return [{"id": r[0], "alert_id": r[1], "ts": r[2], "record": json.loads(r[3])} for r in rows]

    # -- audit log -------------------------------------------------------------------

    async def add_audit(
        self, *, actor: str, action: str, target_type: str, target_id: Optional[str] = None,
        detail: Optional[str] = None, outcome: str = "ok", ts: Optional[datetime] = None,
    ) -> int:
        new_id = await self.conn.insert(
            "INSERT INTO audit_log (ts, actor, action, target_type, target_id, detail, outcome) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ((ts or datetime.now(timezone.utc)).isoformat(), actor, action, target_type,
             None if target_id is None else str(target_id), (detail or "")[:500] or None, outcome),
        )
        await self.conn.commit()
        return new_id

    async def list_audit(
        self, *, limit: int = 100, target_type: Optional[str] = None, target_id: Optional[str] = None,
        action: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        for column, value in (("target_type", target_type), ("target_id", target_id), ("action", action)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(str(value))
        query = "SELECT id, ts, actor, action, target_type, target_id, detail, outcome FROM audit_log"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        rows = await (await self.conn.execute(query, params)).fetchall()
        keys = ("id", "ts", "actor", "action", "target_type", "target_id", "detail", "outcome")
        return [dict(zip(keys, r)) for r in rows]

    # -- notification settings / attempts ---------------------------------------------

    async def get_notification_settings(self) -> Optional[dict[str, Any]]:
        row = await (await self.conn.execute(
            "SELECT enabled, recipients, min_severity, cooldown_seconds, updated_at, updated_by "
            "FROM notification_settings WHERE id = 1")).fetchone()
        if not row:
            return None
        return {"enabled": bool(row[0]), "recipients": [r for r in (row[1] or "").split(",") if r],
                "min_severity": row[2], "cooldown_seconds": int(row[3]), "updated_at": row[4], "updated_by": row[5]}

    async def save_notification_settings(
        self, *, enabled: bool, recipients: list[str], min_severity: str, cooldown_seconds: int, updated_by: str
    ) -> None:
        await self.conn.execute(
            """
            INSERT INTO notification_settings (id, enabled, recipients, min_severity, cooldown_seconds, updated_at, updated_by)
            VALUES (1, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, recipients=excluded.recipients,
                min_severity=excluded.min_severity, cooldown_seconds=excluded.cooldown_seconds,
                updated_at=excluded.updated_at, updated_by=excluded.updated_by
            """,
            (1 if enabled else 0, ",".join(recipients), min_severity, cooldown_seconds,
             datetime.now(timezone.utc).isoformat(), updated_by),
        )
        await self.conn.commit()

    async def add_notification_attempt(
        self, *, channel: str, kind: str, provider: str, status: str, incident_id: Optional[int] = None,
        severity: Optional[str] = None, provider_message_id: Optional[str] = None, detail: Optional[str] = None,
        ts: Optional[datetime] = None,
    ) -> int:
        new_id = await self.conn.insert(
            "INSERT INTO notification_attempts (ts, channel, kind, provider, status, incident_id, severity, "
            "provider_message_id, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ((ts or datetime.now(timezone.utc)).isoformat(), channel, kind, provider, status, incident_id,
             severity, provider_message_id, (detail or "")[:500] or None),
        )
        await self.conn.commit()
        return new_id

    async def list_notification_attempts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = await (await self.conn.execute(
            "SELECT id, ts, channel, kind, provider, status, incident_id, severity, provider_message_id, detail "
            "FROM notification_attempts ORDER BY ts DESC, id DESC LIMIT ?", (limit,))).fetchall()
        keys = ("id", "ts", "channel", "kind", "provider", "status", "incident_id", "severity",
                "provider_message_id", "detail")
        return [dict(zip(keys, r)) for r in rows]

    async def max_incident_id(self) -> int:
        cursor = await self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM incidents")
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def last_alert_ts_by_incident(self, incident_ids: list[int]) -> dict[int, datetime]:
        if not incident_ids:
            return {}
        marks = ",".join("?" for _ in incident_ids)
        cursor = await self.conn.execute(
            f"SELECT incident_id, MAX(ts) FROM alerts WHERE incident_id IN ({marks}) GROUP BY incident_id",
            incident_ids,
        )
        return {row[0]: datetime.fromisoformat(row[1]) for row in await cursor.fetchall()}

    async def recent_incident_events(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = await (await self.conn.execute(
            "SELECT e.id, e.incident_id, e.ts, e.event_type, e.severity, e.detail, i.kind, i.service, i.user_id "
            "FROM incident_events e LEFT JOIN incidents i ON i.id = e.incident_id "
            "ORDER BY e.ts DESC, e.id DESC LIMIT ?", (limit,))).fetchall()
        keys = ("id", "incident_id", "ts", "event_type", "severity", "detail", "kind", "service", "user_id")
        return [dict(zip(keys, r)) for r in rows]

    # -- analytics ---------------------------------------------------------------

    async def alert_counts(self, *, since: datetime) -> list[tuple[str, str, str, int]]:
        """(hour bucket 'YYYY-MM-DDTHH', severity, service-or-'hipaa', count) for alerts since ``since``."""
        cursor = await self.conn.execute(
            """
            SELECT substr(ts, 1, 13) AS hour, severity, COALESCE(service, 'hipaa'), COUNT(*)
            FROM alerts WHERE ts >= ? GROUP BY hour, severity, COALESCE(service, 'hipaa') ORDER BY hour
            """,
            (since.isoformat(),),
        )
        return [(r[0], r[1], r[2], r[3]) for r in await cursor.fetchall()]

    async def alert_kind_counts(self, *, since: datetime) -> list[tuple[str, int]]:
        cursor = await self.conn.execute(
            "SELECT kind, COUNT(*) FROM alerts WHERE ts >= ? GROUP BY kind ORDER BY COUNT(*) DESC",
            (since.isoformat(),),
        )
        return [(r[0], r[1]) for r in await cursor.fetchall()]

    async def metrics_hourly(self, *, since: datetime) -> list[tuple[str, str, int, int, float]]:
        """(hour bucket, service, summed total, summed errors, avg p95) from stored windows.

        Each 60s window is re-emitted every 5s, so raw sums over-count events
        by window/step; callers divide by that factor."""
        cursor = await self.conn.execute(
            """
            SELECT substr(window_end, 1, 13) AS hour, service, SUM(total), SUM(errors), AVG(p95_latency_ms)
            FROM metrics WHERE window_end >= ? GROUP BY hour, service ORDER BY hour
            """,
            (since.isoformat(),),
        )
        return [(r[0], r[1], r[2] or 0, r[3] or 0, r[4] or 0.0) for r in await cursor.fetchall()]

    async def save_incident_event(self, event: IncidentEvent) -> int:
        new_id = await self.conn.insert(
            "INSERT INTO incident_events (incident_id, ts, event_type, severity, detail) VALUES (?, ?, ?, ?, ?)",
            (event.incident_id, event.ts.isoformat(), event.event_type, event.severity, event.detail),
        )
        await self.conn.commit()
        return new_id

    async def list_incident_events(self, incident_id: int) -> list[IncidentEvent]:
        cursor = await self.conn.execute(
            "SELECT id, incident_id, ts, event_type, severity, detail FROM incident_events "
            "WHERE incident_id = ? ORDER BY ts ASC",
            (incident_id,),
        )
        rows = await cursor.fetchall()
        return [
            IncidentEvent(id=r[0], incident_id=r[1], ts=datetime.fromisoformat(r[2]), event_type=r[3],
                          severity=r[4], detail=r[5])
            for r in rows
        ]

    # -- access_stats (Milestone 4: per-user access baseline persistence) ----

    async def save_access_stat(
        self, user_id: str, metric: str, mean: float, variance: float, count: int,
        *, updated_at: Optional[datetime] = None,
    ) -> None:
        ts = (updated_at or datetime.now(timezone.utc)).isoformat()
        await self.conn.execute(
            """
            INSERT INTO access_stats (user_id, metric, mean, variance, count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, metric)
            DO UPDATE SET mean=excluded.mean, variance=excluded.variance,
                          count=excluded.count, updated_at=excluded.updated_at
            """,
            (user_id, metric, mean, variance, count, ts),
        )
        await self.conn.commit()

    async def load_access_stats(self) -> list[tuple[str, str, float, float, int]]:
        cursor = await self.conn.execute("SELECT user_id, metric, mean, variance, count FROM access_stats")
        return list(await cursor.fetchall())


def _iso_or_none(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _row_to_alert(row) -> Alert:
    return Alert(
        id=row[0], ts=datetime.fromisoformat(row[1]), kind=row[2], service=row[3], user_id=row[4],
        severity=row[5], score=row[6], explanation=row[7], metrics=json.loads(row[8]), incident_id=row[9],
    )


_INCIDENT_COLS = (
    "id, fingerprint, kind, service, user_id, state, peak_severity, alert_count, opened_at, acknowledged_at, "
    "resolved_at, mttr_seconds, pinned, pinned_at, investigating_at, last_seen_at, peak_score, muted_until"
)


def _dt(value: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(value) if value else None


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _row_to_incident(row) -> Incident:
    return Incident(
        id=row[0], fingerprint=row[1], kind=row[2], service=row[3], user_id=row[4], state=row[5],
        peak_severity=row[6], alert_count=row[7], opened_at=datetime.fromisoformat(row[8]),
        acknowledged_at=_dt(row[9]), resolved_at=_dt(row[10]), mttr_seconds=row[11],
        pinned=bool(row[12]), pinned_at=_dt(row[13]), investigating_at=_dt(row[14]), last_seen_at=_dt(row[15]),
        peak_score=row[16], muted_until=_dt(row[17]),
    )
