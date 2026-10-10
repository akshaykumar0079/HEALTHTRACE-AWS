"""Wires ingest -> parse/enrich -> detect -> incidents -> store/broadcast/
notify together (SPEC.md section 3).

All detection runs off event timestamps (SPEC.md section 1): app and audit
events advance an internal event-time clock, which is what drives the
HIPAA incident auto-resolve sweep — not the wall clock — so replay stays
deterministic.

Restart safety: each tailer's byte position is persisted together with the
learned baselines (only at moments when every line read has also been
processed), so a restart resumes exactly where the learned state left off —
no history is skipped and none is learned twice. A backlog (the first-run
backfill, or logs written while the backend was down) is processed in
*replay* mode: detection and storage run as normal, but live clients get a
progress stream instead of a firehose of historical messages, then a fresh
snapshot once caught up.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import sqrt
from typing import Any, Optional, Union

from app.api.ws import Broadcaster
from app.config import AppConfig, Settings
from app.detect.access import AccessDetector
from app.detect.anomaly import AnomalyEngine
from app.detect.baseline import BaselineEngine
from app.detect.severity import score_hipaa_anomaly, score_service_anomaly
from app.detect.window import SlidingWindow
from app.incidents.engine import IncidentEngine, IncidentUpdate, fingerprint_for
from app.incidents.view import incident_view
from app.ingest.tailer import Tailer
from app.models import Alert, Anomaly, AppEvent, AuditEvent, WindowMetrics
from app.notify.aws import AwsNotifier
from app.notify.mailer import EmailNotifier, EmailSettings
from app.parse.enricher import Enricher
from app.parse.parser import Parser
from app.store.db import Store

logger = logging.getLogger(__name__)

BASELINE_SAVE_INTERVAL_SECONDS = 60
HEARTBEAT_INTERVAL_SECONDS = 10
TICK_SECONDS = 1.0
STOP_DRAIN_TIMEOUT_SECONDS = 10.0
RECENT_LOGS = 5000
LOG_BROADCAST_CAP = 60
THROUGHPUT_HISTORY = 120
# Alerts whose event time is older than this (replayed history, or a long
# backlog after downtime) are stored and shown but not pushed to AWS.
NOTIFY_MAX_AGE = timedelta(minutes=15)

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def mask_patient_id(patient_id: Optional[str]) -> Optional[str]:
    """P-000123 -> P-****23 (SPEC.md 6.12)."""
    if not patient_id or len(patient_id) < 4:
        return patient_id
    return f"{patient_id[:2]}****{patient_id[-2:]}"


@dataclass
class ServiceState:
    service: str
    window_end: Optional[datetime] = None
    total: int = 0
    errors: int = 0
    error_rate: float = 0.0
    p95_latency_ms: float = 0.0
    urgent_errors: int = 0
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None
    z: Optional[float] = None
    latency_baseline_mean: Optional[float] = None
    baseline_is_fallback: bool = False
    affected_patients_urgent: int = 0
    affected_patients_routine: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "total": self.total,
            "errors": self.errors,
            "error_rate": self.error_rate,
            "p95_latency_ms": self.p95_latency_ms,
            "urgent_errors": self.urgent_errors,
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "z": self.z,
            "latency_baseline_mean": self.latency_baseline_mean,
            "baseline_is_fallback": self.baseline_is_fallback,
            "affected_patients_urgent": self.affected_patients_urgent,
            "affected_patients_routine": self.affected_patients_routine,
        }


class Pipeline:
    def __init__(self, settings: Settings, config: AppConfig) -> None:
        self._last_metric_save: dict[str, float] = {}
        self.settings = settings
        self.config = config

        self.queue: "asyncio.Queue[str]" = asyncio.Queue(maxsize=10000)
        self.parser = Parser()
        self.enricher = Enricher(config)
        self.window = SlidingWindow(config.window.size_seconds, config.window.step_seconds)
        self.baseline = BaselineEngine(config.baseline)
        self.anomaly_engine = AnomalyEngine(config.anomaly, self.baseline)
        self.access_detector = AccessDetector(config.hipaa)
        self.incidents = IncidentEngine(config.incident)
        self.store = Store(settings.db_path, settings.database_url or None)
        self.notifier = AwsNotifier(
            mode=settings.aws_mode,
            region=settings.aws_region,
            log_group=settings.cloudwatch_log_group,
            log_stream=settings.cloudwatch_log_stream,
            sns_topic_arn=settings.sns_topic_arn,
            mock_log_path=settings.log_dir.parent / "aws_mock.log",
        )
        self.email = EmailNotifier(EmailSettings.from_settings(settings), app_config=config)
        self.broadcaster = Broadcaster()
        self.db_errors = 0
        self.last_db_error: Optional[str] = None

        self.service_states: dict[str, ServiceState] = {}
        self.recent_alerts: list[Alert] = []  # newest last; capped at _MAX_RECENT_ALERTS
        self._MAX_RECENT_ALERTS = 500

        self.recent_logs: "deque[dict[str, Any]]" = deque(maxlen=RECENT_LOGS)
        self._pending_logs: list[dict[str, Any]] = []
        self._log_seq = 0
        self._hipaa_last_alert: dict[str, tuple[datetime, int]] = {}

        self.started_at: Optional[datetime] = None
        self.events_processed = {"app": 0, "audit": 0}
        self.alerts_emitted = 0
        self._throughput: "deque[dict[str, Any]]" = deque(maxlen=THROUGHPUT_HISTORY)
        self._last_tick_counts = (0, 0)
        self._last_tick_mono = time.monotonic()

        self.replay_active = False
        self._replay_total_bytes = 0
        self._replay_start_bytes = 0

        self._event_clock: Optional[datetime] = None
        self._last_hipaa_sweep: Optional[datetime] = None
        self._tailers: list[Tailer] = []
        self._tasks: list[asyncio.Task] = []
        self._consumer_task: Optional[asyncio.Task] = None

    # -- lifecycle -------------------------------------------------------------

    async def start(self) -> None:
        self.started_at = datetime.now(timezone.utc)
        await self.store.connect()
        await self.baseline.load(self.store)
        await self._restore_incidents()
        await self.notifier.start()
        await self._load_notification_prefs()
        self.email.attempt_hook = self._record_email_attempt
        await self.email.start()

        positions = await self.store.load_tail_positions()
        # First run (nothing learned, nothing read): replay existing history,
        # SPEC.md 6.4. A database from before positions were persisted has
        # baselines but no positions: keep its old behaviour and tail from
        # the end rather than learning the same history twice.
        first_run = not positions and self.baseline.is_empty()
        self._tailers = []
        for name in ("app.log", "audit.log"):
            path = self.settings.log_dir / name
            saved = positions.get(str(path))
            self._tailers.append(
                Tailer(
                    path, self.queue, from_start=first_run,
                    resume_file_id=saved[0] if saved else None,
                    resume_offset=saved[1] if saved else None,
                )
            )
        self._init_replay_tracking()

        for tailer in self._tailers:
            self._tasks.append(asyncio.create_task(tailer.run()))
        self._consumer_task = asyncio.create_task(self._consume())
        self._tasks.append(asyncio.create_task(self._periodic_save()))
        self._tasks.append(asyncio.create_task(self._heartbeat()))
        self._tasks.append(asyncio.create_task(self._tick()))

    async def stop(self) -> None:
        for tailer in self._tailers:
            tailer.stop()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks = []
        # Everything the tailers read must be processed before offsets are
        # saved, or those lines would be skipped on the next start.
        drained = True
        if self._consumer_task is not None:
            try:
                await asyncio.wait_for(self.queue.join(), timeout=STOP_DRAIN_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                drained = False
                logger.warning("pipeline: stopping with %d unprocessed lines", self.queue.qsize())
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
            self._consumer_task = None
        await self._save_state(save_positions=drained)
        await self.notifier.stop()
        await self.email.stop()
        await self.store.close()

    async def _load_notification_prefs(self) -> None:
        """Settings saved from the UI win over the env defaults; on first run
        the env defaults are written once so the UI shows what is in effect.
        A database problem here must never stop monitoring."""
        try:
            saved = await self.store.get_notification_settings()
            if saved is None:
                es = self.email.settings
                await self.store.save_notification_settings(
                    enabled=es.enabled, recipients=es.recipients, min_severity=es.min_severity,
                    cooldown_seconds=es.cooldown_seconds, updated_by="system")
            else:
                self.email.apply_prefs(
                    enabled=saved["enabled"], recipients=saved["recipients"] or self.email.settings.recipients,
                    min_severity=saved["min_severity"], cooldown_seconds=saved["cooldown_seconds"])
        except Exception as exc:
            self._db_failed("load notification settings", exc)

    async def _record_email_attempt(self, info: dict[str, Any]) -> None:
        try:
            await self.store.add_notification_attempt(
                channel="email", kind=info.get("kind", "incident"), provider=info.get("provider", "unknown"),
                status=info["status"], incident_id=info.get("incident_id"), severity=info.get("severity"),
                provider_message_id=info.get("provider_message_id"), detail=info.get("detail"))
        except Exception as exc:
            self._db_failed("record notification attempt", exc)

    def _db_failed(self, what: str, exc: BaseException) -> None:
        """Count and log a persistence failure without raising: the detector,
        WebSocket and notifiers must keep running when the database hiccups."""
        self.db_errors += 1
        self.last_db_error = f"{what}: {type(exc).__name__}"
        logger.error("pipeline: database error during %s (%s): %s", what, type(exc).__name__, str(exc)[:200])

    async def audit(self, actor: str, action: str, target_type: str, target_id: object = None,
                    detail: Optional[str] = None, outcome: str = "ok") -> None:
        try:
            await self.store.add_audit(actor=actor, action=action, target_type=target_type,
                                       target_id=None if target_id is None else str(target_id),
                                       detail=detail, outcome=outcome)
        except Exception as exc:
            self._db_failed("write audit log", exc)

    async def _restore_incidents(self) -> None:
        stored = await self.store.list_incidents(limit=500)
        active_ids = [i.id for i in stored if i.state != "RESOLVED" and i.id is not None]
        last_alert = await self.store.last_alert_ts_by_incident(active_ids)
        self.incidents.restore(stored, next_id=await self.store.max_incident_id() + 1, last_alert_ts=last_alert)
        self.recent_alerts = list(reversed(await self.store.list_alerts(limit=50))) + self.recent_alerts

    def _init_replay_tracking(self) -> None:
        total = start = 0
        for tailer in self._tailers:
            try:
                size = tailer.path.stat().st_size
            except FileNotFoundError:
                continue
            if tailer._resume_offset is not None and tailer._resume_offset <= size:
                offset = tailer._resume_offset
            elif tailer._resume_offset is not None or tailer.from_start:
                offset = 0
            else:
                offset = size
            total += size
            start += offset
        self._replay_total_bytes = total
        self._replay_start_bytes = start
        self.replay_active = total - start > 0

    async def _save_state(self, *, save_positions: bool = True) -> None:
        await self.baseline.save(self.store)
        if save_positions:
            for tailer in self._tailers:
                if tailer.file_id is not None:
                    await self.store.save_tail_position(str(tailer.path), tailer.file_id, tailer.committed_offset)

    async def _periodic_save(self) -> None:
        while True:
            await asyncio.sleep(BASELINE_SAVE_INTERVAL_SECONDS)
            # Positions are only consistent with the baselines when nothing is
            # in flight between a tailer and the consumer.
            await self._save_state(save_positions=self.queue._unfinished_tasks == 0)  # noqa: SLF001

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            await self.broadcaster.broadcast({"type": "heartbeat", "ts": datetime.now(timezone.utc).isoformat()})

    async def _tick(self) -> None:
        """Once a second: throughput sample, batched log stream, replay progress."""
        while True:
            await asyncio.sleep(TICK_SECONDS)
            self._sample_throughput()
            if self.replay_active:
                if all(t.caught_up for t in self._tailers) and self.queue._unfinished_tasks == 0:  # noqa: SLF001
                    self.replay_active = False
                    self._pending_logs.clear()
                    await self._save_state()
                    await self.broadcaster.broadcast(self.snapshot())
                else:
                    await self.broadcaster.broadcast({"type": "replay", **self.replay_status()})
                    continue
            if self._pending_logs:
                batch = self._pending_logs[-LOG_BROADCAST_CAP:]
                dropped = len(self._pending_logs) - len(batch)
                self._pending_logs = []
                await self.broadcaster.broadcast({"type": "logs", "events": batch, "dropped": dropped})

    def _sample_throughput(self) -> None:
        now = time.monotonic()
        elapsed = max(now - self._last_tick_mono, 1e-6)
        app, audit = self.events_processed["app"], self.events_processed["audit"]
        last_app, last_audit = self._last_tick_counts
        self._throughput.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "app_eps": round((app - last_app) / elapsed, 2),
                "audit_eps": round((audit - last_audit) / elapsed, 2),
            }
        )
        self._last_tick_counts = (app, audit)
        self._last_tick_mono = now

    # -- ingestion loop ----------------------------------------------------

    async def _consume(self) -> None:
        while True:
            line = await self.queue.get()
            try:
                await self._process_line(line)
            except Exception:
                logger.exception("pipeline: error processing line")
            finally:
                self.queue.task_done()

    async def _process_line(self, line: str) -> None:
        event = self.parser.parse_line(line)
        if event is None:
            return
        self._remember_log(event)
        if isinstance(event, AppEvent):
            self.events_processed["app"] += 1
            await self._process_app_event(event)
        else:
            self.events_processed["audit"] += 1
            await self._process_audit_event(event)

    def _advance_clock(self, ts: datetime) -> None:
        if self._event_clock is None or ts > self._event_clock:
            self._event_clock = ts

    # -- app events: window -> anomaly -> severity -> incident --------------

    async def _process_app_event(self, event: AppEvent) -> None:
        self._advance_clock(event.ts)
        enriched = self.enricher.enrich(event)
        for metrics in self.window.add(enriched):
            await self._process_window_metrics(metrics)
        await self._sweep_hipaa()

    async def _sweep_hipaa(self) -> None:
        """HIPAA incidents resolve after 10 quiet minutes of *event time*.
        App traffic advances that clock too, so the sweep can't depend on audit
        events arriving (there are none outside business hours). Runs at most
        once per event-second."""
        clock = self._event_clock
        if clock is None:
            return
        if self._last_hipaa_sweep is not None and (clock - self._last_hipaa_sweep).total_seconds() < 1:
            return
        self._last_hipaa_sweep = clock
        for update in self.incidents.sweep_hipaa_timeouts(clock):
            await self.apply_incident_update(update)

    def _should_persist_metrics(self, metrics: WindowMetrics) -> bool:
        interval = self.settings.metrics_persist_interval_seconds
        if interval <= 0:
            return True
        last = self._last_metric_save.get(metrics.service)
        now = time.monotonic()
        if last is not None and now - last < interval:
            return False
        self._last_metric_save[metrics.service] = now
        return True

    async def _process_window_metrics(self, metrics: WindowMetrics) -> None:
        metrics.malformed_lines = self.parser.malformed_lines
        # The baseline this window is judged against, captured before
        # evaluate() lets a normal window update it.
        judged_against = self.baseline.get(metrics.service, metrics.window_end.hour, "error_rate")
        if judged_against is not None:
            metrics.baseline_mean = judged_against.mean
            metrics.baseline_std = sqrt(max(judged_against.variance, 0.0))
        result = self.anomaly_engine.evaluate(metrics)
        self._update_service_state(metrics)

        if self._should_persist_metrics(metrics):
            await self.store.save_metrics(metrics)
        await self._broadcast_live({"type": "metric", **self.service_states[metrics.service].to_dict(),
                                    **metrics.model_dump(mode="json")})

        criticality = self.config.services[metrics.service].criticality
        sev = self.config.severity
        for anomaly in result.anomalies:
            alert = score_service_anomaly(anomaly, metrics, criticality, sev)
            # The inputs of the severity formula, so an investigation can show
            # exactly how the score was reached.
            patients = 2 * metrics.affected_patients_urgent + metrics.affected_patients_routine
            alert.metrics.update({
                "z": anomaly.z,
                "baseline_mean": anomaly.baseline_mean,
                "baseline_std": anomaly.baseline_std,
                "criticality": criticality,
                "deviation_factor": min(anomaly.z / sev.deviation_z_cap, 1.0),
                "patient_factor": min(patients / sev.patient_factor_cap, 1.0),
            })
            await self._handle_alert(anomaly, alert)

        if result.error_rate_normal:
            update = self.incidents.record_normal_window("error_rate", metrics.service, metrics.window_end)
            if update:
                await self.apply_incident_update(update)
        if result.latency_normal:
            update = self.incidents.record_normal_window("latency_degradation", metrics.service, metrics.window_end)
            if update:
                await self.apply_incident_update(update)

    def _update_service_state(self, metrics: WindowMetrics) -> None:
        baseline = self.baseline.get(metrics.service, metrics.window_end.hour, "error_rate")
        latency_baseline = self.baseline.get(metrics.service, metrics.window_end.hour, "p95_latency_ms")
        z = None
        baseline_std = None
        if baseline is not None:
            baseline_std = sqrt(max(baseline.variance, 0.0))
            std_eff = max(baseline_std, self.config.anomaly.min_std)
            z = (metrics.error_rate - baseline.mean) / std_eff
        self.service_states[metrics.service] = ServiceState(
            service=metrics.service,
            window_end=metrics.window_end,
            total=metrics.total,
            errors=metrics.errors,
            error_rate=metrics.error_rate,
            p95_latency_ms=metrics.p95_latency_ms,
            urgent_errors=metrics.urgent_errors,
            baseline_mean=baseline.mean if baseline else None,
            baseline_std=baseline_std,
            z=z,
            latency_baseline_mean=latency_baseline.mean if latency_baseline else None,
            baseline_is_fallback=baseline.is_global_fallback if baseline else False,
            affected_patients_urgent=metrics.affected_patients_urgent,
            affected_patients_routine=metrics.affected_patients_routine,
        )

    # -- audit events: access detector -> severity -> incident --------------

    async def _process_audit_event(self, event: AuditEvent) -> None:
        self._advance_clock(event.ts)
        anomalies = self.access_detector.evaluate(event)
        for anomaly in anomalies:
            alert = score_hipaa_anomaly(anomaly, self.config.hipaa)
            if self._hipaa_should_alert(anomaly, alert):
                await self._handle_alert(anomaly, alert)

        await self._sweep_hipaa()

    def _hipaa_should_alert(self, anomaly: Anomaly, alert: Alert) -> bool:
        """The access detector reports a pattern on every event that exhibits
        it; re-alerting an unchanged pattern more than once per
        ``realert_seconds`` only floods storage, the feed and CloudWatch.
        An escalation in severity always gets through immediately."""
        fp = fingerprint_for(anomaly)
        rank = _SEVERITY_RANK[alert.severity]
        last = self._hipaa_last_alert.get(fp)
        if last is not None:
            last_ts, last_rank = last
            elapsed = (anomaly.ts - last_ts).total_seconds()
            if rank <= last_rank and 0 <= elapsed < self.config.hipaa.realert_seconds:
                return False
        self._hipaa_last_alert[fp] = (anomaly.ts, rank)
        return True

    # -- shared: alerts -> incidents -> store/broadcast/notify --------------

    async def _handle_alert(self, anomaly: Anomaly, alert: Alert) -> None:
        update = self.incidents.record_alert(anomaly, alert)
        alert.incident_id = update.incident.id

        try:
            alert.id = await self.store.save_alert(alert)
        except Exception as exc:
            self._db_failed("save alert", exc)
        self._remember_alert(alert)
        self.alerts_emitted += 1
        fresh = datetime.now(timezone.utc) - alert.ts <= NOTIFY_MAX_AGE
        if fresh:
            self.notifier.notify_alert(alert)  # CloudWatch: every alert
        await self._broadcast_live({"type": "alert", **alert.model_dump(mode="json")})

        await self.apply_incident_update(update)
        await self._capture_evidence(update.incident, alert)
        if fresh and update.should_notify and (update.is_new or update.is_escalation):
            self.notifier.notify_incident(update.incident, alert.explanation)
            self.email.notify_incident(update.incident, alert, escalated=update.is_escalation)

    EVIDENCE_PER_ALERT = 15

    def evidence_candidates(self, alert: Alert) -> list[dict[str, Any]]:
        """Recent already-masked log records that explain ``alert``: the failing
        or slowest requests of the service, or the user's recent audit actions."""
        try:
            alert_ts = alert.ts
            out: list[dict[str, Any]] = []
            for record in reversed(self.recent_logs):
                try:
                    delta = (alert_ts - datetime.fromisoformat(record["ts"])).total_seconds()
                except (KeyError, ValueError):
                    continue
                if delta < 0 and not self.replay_active:
                    continue
                if alert.kind.startswith("hipaa_"):
                    if record.get("type") != "audit" or record.get("user_id") != alert.user_id or delta > 600:
                        continue
                else:
                    if record.get("type") != "app" or record.get("service") != alert.service or delta > 120:
                        continue
                    if alert.kind == "error_rate" and not record.get("is_error"):
                        continue
                out.append(record)
                if len(out) >= self.EVIDENCE_PER_ALERT * (4 if alert.kind == "latency_degradation" else 1):
                    break
            if alert.kind == "latency_degradation":
                out.sort(key=lambda r: r.get("latency_ms", 0), reverse=True)
            return out[: self.EVIDENCE_PER_ALERT]
        except Exception:  # evidence is best-effort
            logger.exception("pipeline: evidence selection failed")
            return []

    async def _capture_evidence(self, incident, alert: Alert) -> None:
        if incident.id is None:
            return
        records = self.evidence_candidates(alert)
        if not records:
            return
        try:
            await self.store.save_evidence(incident.id, alert.id, records)
        except Exception as exc:
            self._db_failed("save evidence", exc)

    async def apply_incident_update(self, update: IncidentUpdate) -> None:
        try:
            await self.store.upsert_incident(update.incident)
        except Exception as exc:
            self._db_failed("save incident", exc)
        for event in update.events:
            try:
                event.id = await self.store.save_incident_event(event)
            except Exception as exc:
                self._db_failed("save incident event", exc)
            await self._broadcast_live(
                {"type": "incident_update", "incident": incident_view(update.incident),
                 **event.model_dump(mode="json")}
            )

    async def _broadcast_live(self, message: dict[str, Any]) -> None:
        if not self.replay_active:
            await self.broadcaster.broadcast(message)

    def _remember_alert(self, alert: Alert) -> None:
        self.recent_alerts.append(alert)
        if len(self.recent_alerts) > self._MAX_RECENT_ALERTS:
            self.recent_alerts = self.recent_alerts[-self._MAX_RECENT_ALERTS :]

    def _remember_log(self, event: Union[AppEvent, AuditEvent]) -> None:
        self._log_seq += 1
        if isinstance(event, AppEvent):
            record = {
                "seq": self._log_seq, "ts": event.ts.isoformat(), "type": "app", "service": event.service,
                "level": event.level, "priority": event.priority, "request_id": event.request_id,
                "patient_id": mask_patient_id(event.patient_id), "status": event.status,
                "latency_ms": event.latency_ms, "msg": event.msg, "is_error": event.is_error,
            }
        else:
            record = {
                "seq": self._log_seq, "ts": event.ts.isoformat(), "type": "audit", "user_id": event.user_id,
                "role": event.role, "action": event.action, "patient_id": mask_patient_id(event.patient_id),
                "patient_region": event.patient_region, "user_region": event.user_region,
                "region_mismatch": event.is_region_mismatch,
                "level": "WARN" if event.is_region_mismatch or event.action == "EXPORT_RECORDS" else "INFO",
                "msg": f"{event.user_id} {event.action} {mask_patient_id(event.patient_id)}",
            }
        self.recent_logs.append(record)
        if not self.replay_active:
            self._pending_logs.append(record)
            if len(self._pending_logs) > LOG_BROADCAST_CAP * 20:
                del self._pending_logs[: -LOG_BROADCAST_CAP]

    # -- read models for the API ---------------------------------------------

    def replay_status(self) -> dict[str, Any]:
        remaining = sum(max(t.file_size - t.committed_offset, 0) for t in self._tailers)
        todo = max(self._replay_total_bytes - self._replay_start_bytes, 1)
        done = max(todo - remaining, 0)
        return {
            "active": self.replay_active,
            "progress": round(min(done / todo, 1.0), 4) if self.replay_active else 1.0,
            "event_clock": self._event_clock.isoformat() if self._event_clock else None,
            "events_processed": sum(self.events_processed.values()),
        }

    def health_snapshot(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        lag = (now - self._event_clock).total_seconds() if self._event_clock else None
        recent = list(self._throughput)
        return {
            "status": "replaying" if self.replay_active else "ok",
            "queue_depth": self.queue.qsize(),
            "malformed_lines": self.parser.malformed_lines,
            "aws_mode": self.settings.aws_mode,
            "notifier_queue_depth": self.notifier.queue_depth,
            "email_enabled": self.email.settings.enabled,
            "email_queue_depth": self.email.queue_depth,
            "database": {"dialect": self.store.dialect, "errors": self.db_errors, "last_error": self.last_db_error},
            "demo_mode": self.settings.demo_mode,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "uptime_seconds": (now - self.started_at).total_seconds() if self.started_at else 0,
            "event_clock": self._event_clock.isoformat() if self._event_clock else None,
            "event_lag_seconds": lag,
            "events_processed": dict(self.events_processed),
            "alerts_emitted": self.alerts_emitted,
            "ws_clients": self.broadcaster.client_count,
            "throughput": recent[-1] if recent else {"app_eps": 0.0, "audit_eps": 0.0},
            "throughput_history": recent[-60:],
            "replay": self.replay_status(),
            "tailers": [
                {"path": t.path.name, "offset": t.committed_offset, "size": t.file_size, "caught_up": t.caught_up}
                for t in self._tailers
            ],
        }

    def services_snapshot(self) -> list[dict[str, Any]]:
        known = set(self.config.services) | set(self.service_states)
        active = [i for i in self.incidents.list_incidents() if i.state != "RESOLVED" and i.service]
        out = []
        for s in sorted(known):
            row = self.service_states[s].to_dict() if s in self.service_states else ServiceState(service=s).to_dict()
            mine = [i for i in active if i.service == s]
            svc_cfg = self.config.services.get(s)
            row["criticality"] = svc_cfg.criticality if svc_cfg else None
            row["label"] = (svc_cfg.label if svc_cfg else None) or s
            row["depends_on"] = svc_cfg.depends_on if svc_cfg else []
            row["active_incidents"] = len(mine)
            row["worst_severity"] = max((i.peak_severity for i in mine), key=_SEVERITY_RANK.__getitem__, default=None)
            row["baseline_ready"] = row["baseline_mean"] is not None
            row["requests_per_second"] = row["total"] / self.config.window.size_seconds
            out.append(row)
        return out

    def snapshot(self) -> dict[str, Any]:
        return {
            "type": "snapshot",
            "services": self.services_snapshot(),
            "alerts": [a.model_dump(mode="json") for a in self.recent_alerts[-50:]],
            "incidents": [incident_view(i) for i in self.incidents.list_incidents()],
            "metrics": {s.service: s.to_dict() for s in self.service_states.values()},
            "health": self.health_snapshot(),
            "logs": list(self.recent_logs)[-100:],
        }

    def write_control_file(self, scenario: str, duration_s: float) -> None:
        """POST /api/demo/inject writes this file; generator.generate polls it
        once a second (SPEC.md section 7)."""
        path = self.settings.control_file
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "scenario": scenario,
            "duration_s": duration_s,
            "injected_at": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
