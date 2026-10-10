"""Incident lifecycle: dedup, escalation, cooldown, auto-resolve, MTTR
(SPEC.md section 6.8).

Two independent sources drive a fingerprint's lifecycle:

- ``record_alert()``: a new Alert for some anomaly. Deduplicated by
  fingerprint — attached to any existing OPEN/ACKNOWLEDGED incident (bumping
  ``alert_count`` and ``peak_severity``), or opens a new one.
- ``record_normal_window()`` / ``sweep_hipaa_timeouts()``: the *absence* of
  further anomalies, which is what lets a service incident auto-resolve
  after 6 consecutive normal windows, and a HIPAA incident auto-resolve
  after 10 minutes with no new matching alert.

Fingerprint: ``(kind, service)`` for service anomalies, ``(kind, user_id)``
for HIPAA anomalies — SPEC.md's rule exactly.

``IncidentUpdate.should_notify`` is only ever a hint for the AWS notifier
(Milestone 5) about whether to push a message out. Storage and the
WebSocket broadcast are unconditional: SPEC.md 6.8 says "every state change
is written to the incident_events table and broadcast over WebSocket",
full stop — cooldown only suppresses the *external* notification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from app.config import IncidentConfig
from app.models import Alert, Anomaly, Incident, IncidentEvent, Severity

_SEVERITY_ORDER: dict[Severity, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
# Lifecycle states in which an incident still absorbs new alerts for its fingerprint.
ACTIVE_STATES = ("OPEN", "ACKNOWLEDGED", "INVESTIGATING")


def _track_peak_score(incident: Incident, alert: Alert) -> None:
    """Keep the highest *real* detector score. HIPAA rules have no continuous
    score (the alert carries 0.0 as a placeholder), so they leave this None."""
    if alert.kind.startswith("hipaa_"):
        return
    if incident.peak_score is None or alert.score > incident.peak_score:
        incident.peak_score = alert.score


def fingerprint_for(anomaly: Anomaly) -> str:
    if anomaly.user_id is not None:
        return f"{anomaly.kind}:{anomaly.user_id}"
    return f"{anomaly.kind}:{anomaly.service}"


@dataclass
class _IncidentState:
    incident: Incident
    consecutive_normal_windows: int = 0
    last_alert_ts: Optional[datetime] = None
    suppressed_until: Optional[datetime] = None  # cooldown, set once this fingerprint resolves


@dataclass
class IncidentUpdate:
    incident: Incident
    events: list[IncidentEvent] = field(default_factory=list)
    should_notify: bool = False
    is_new: bool = False
    is_escalation: bool = False


class IncidentEngine:
    def __init__(self, config: IncidentConfig) -> None:
        self._config = config
        self._by_fingerprint: dict[str, _IncidentState] = {}
        self._by_id: dict[int, _IncidentState] = {}
        self._next_id = 1

    def restore(
        self, incidents: list[Incident], *, next_id: int, last_alert_ts: dict[int, datetime]
    ) -> None:
        """Rehydrate from the store on startup. Without this, ids restart at 1
        and new incidents overwrite persisted ones (upsert is keyed on id).
        ``incidents`` is newest-first; only the newest per fingerprint is
        tracked, matching how the engine itself keys live state."""
        self._next_id = max(self._next_id, next_id)
        for incident in incidents:
            if incident.id is None or incident.fingerprint in self._by_fingerprint:
                continue
            state = _IncidentState(incident=incident, last_alert_ts=last_alert_ts.get(incident.id, incident.opened_at))
            if incident.state == "RESOLVED" and incident.resolved_at is not None:
                state.suppressed_until = incident.resolved_at + timedelta(minutes=self._config.cooldown_minutes)
            self._by_fingerprint[incident.fingerprint] = state
            self._by_id[incident.id] = state

    def record_alert(self, anomaly: Anomaly, alert: Alert) -> IncidentUpdate:
        fp = fingerprint_for(anomaly)
        state = self._by_fingerprint.get(fp)

        if state is not None and state.incident.state in ACTIVE_STATES:
            return self._attach(state, anomaly, alert)

        # No active incident for this fingerprint right now: a fresh one,
        # possibly still inside the previous incident's cooldown window.
        in_cooldown = (
            state is not None
            and state.incident.state == "RESOLVED"
            and state.suppressed_until is not None
            and anomaly.ts < state.suppressed_until
        )
        return self._open(fp, anomaly, alert, carry_over_cooldown=state.suppressed_until if in_cooldown else None)

    def _attach(self, state: _IncidentState, anomaly: Anomaly, alert: Alert) -> IncidentUpdate:
        state.consecutive_normal_windows = 0
        state.last_alert_ts = anomaly.ts
        incident = state.incident
        incident.alert_count += 1
        incident.last_seen_at = anomaly.ts
        _track_peak_score(incident, alert)

        escalated = _SEVERITY_ORDER[alert.severity] > _SEVERITY_ORDER[incident.peak_severity]
        if escalated:
            incident.peak_severity = alert.severity

        in_cooldown = state.suppressed_until is not None and anomaly.ts < state.suppressed_until
        event = IncidentEvent(
            incident_id=incident.id,
            ts=anomaly.ts,
            event_type="escalated" if escalated else "alert_attached",
            severity=alert.severity,
        )
        return IncidentUpdate(
            incident=incident, events=[event], should_notify=escalated and not in_cooldown, is_escalation=escalated
        )

    def _open(
        self, fingerprint: str, anomaly: Anomaly, alert: Alert, *, carry_over_cooldown: Optional[datetime]
    ) -> IncidentUpdate:
        incident = Incident(
            id=self._next_id,
            fingerprint=fingerprint,
            kind=anomaly.kind,
            service=anomaly.service,
            user_id=anomaly.user_id,
            state="OPEN",
            peak_severity=alert.severity,
            alert_count=1,
            opened_at=anomaly.ts,
            last_seen_at=anomaly.ts,
        )
        _track_peak_score(incident, alert)
        self._next_id += 1

        new_state = _IncidentState(
            incident=incident, last_alert_ts=anomaly.ts, suppressed_until=carry_over_cooldown
        )
        self._by_fingerprint[fingerprint] = new_state
        self._by_id[incident.id] = new_state

        event = IncidentEvent(incident_id=incident.id, ts=anomaly.ts, event_type="opened", severity=alert.severity)
        return IncidentUpdate(
            incident=incident, events=[event], should_notify=carry_over_cooldown is None, is_new=True
        )

    def acknowledge(self, incident_id: int, now: datetime) -> Optional[IncidentUpdate]:
        state = self._by_id.get(incident_id)
        if state is None or state.incident.state != "OPEN":
            return None
        state.incident.state = "ACKNOWLEDGED"
        state.incident.acknowledged_at = now
        event = IncidentEvent(incident_id=incident_id, ts=now, event_type="acknowledged")
        return IncidentUpdate(incident=state.incident, events=[event])

    def investigate(self, incident_id: int, now: datetime) -> Optional[IncidentUpdate]:
        """Mark an active incident as being worked on. Detection keeps
        attaching alerts and auto-resolve still applies."""
        state = self._by_id.get(incident_id)
        if state is None or state.incident.state not in ("OPEN", "ACKNOWLEDGED"):
            return None
        state.incident.state = "INVESTIGATING"
        state.incident.investigating_at = now
        if state.incident.acknowledged_at is None:
            state.incident.acknowledged_at = now
        event = IncidentEvent(incident_id=incident_id, ts=now, event_type="investigating")
        return IncidentUpdate(incident=state.incident, events=[event])

    def set_pinned(self, incident_id: int, pinned: bool, now: datetime) -> Optional[IncidentUpdate]:
        """Pin/unpin a tracked incident. Only the ``pinned`` flag changes:
        severity, risk score and status are deliberately untouched."""
        state = self._by_id.get(incident_id)
        if state is None:
            return None
        if state.incident.pinned == pinned:
            return IncidentUpdate(incident=state.incident)
        state.incident.pinned = pinned
        state.incident.pinned_at = now if pinned else None
        event = IncidentEvent(incident_id=incident_id, ts=now, event_type="pinned" if pinned else "unpinned")
        return IncidentUpdate(incident=state.incident, events=[event])

    def mute(self, incident_id: int, now: datetime, minutes: float) -> Optional[IncidentUpdate]:
        """Suppress external notifications for this incident's fingerprint
        (the same mechanism as post-resolve cooldown); 0 minutes unmutes.
        Detection, storage and the live feed are unaffected."""
        state = self._by_id.get(incident_id)
        if state is None:
            return None
        until = now + timedelta(minutes=minutes) if minutes > 0 else None
        state.suppressed_until = until
        state.incident.muted_until = until
        detail = f"notifications muted for {minutes:g} min" if until else "notifications unmuted"
        event = IncidentEvent(incident_id=incident_id, ts=now, event_type="muted", detail=detail)
        return IncidentUpdate(incident=state.incident, events=[event])

    def resolve(self, incident_id: int, now: datetime) -> Optional[IncidentUpdate]:
        state = self._by_id.get(incident_id)
        if state is None or state.incident.state == "RESOLVED":
            return None
        return self._resolve(state, now, auto=False)

    def _resolve(self, state: _IncidentState, now: datetime, *, auto: bool) -> IncidentUpdate:
        incident = state.incident
        incident.state = "RESOLVED"
        incident.resolved_at = now
        incident.mttr_seconds = (now - incident.opened_at).total_seconds()
        state.suppressed_until = now + timedelta(minutes=self._config.cooldown_minutes)
        event = IncidentEvent(
            incident_id=incident.id, ts=now, event_type="auto_resolved" if auto else "resolved"
        )
        return IncidentUpdate(incident=incident, events=[event])

    # -- auto-resolve: service incidents (6 consecutive normal windows) -----

    def record_normal_window(self, kind: str, service: str, window_end: datetime) -> Optional[IncidentUpdate]:
        state = self._by_fingerprint.get(f"{kind}:{service}")
        if state is None or state.incident.state not in ACTIVE_STATES:
            return None
        state.consecutive_normal_windows += 1
        if state.consecutive_normal_windows >= self._config.service_auto_resolve_windows:
            return self._resolve(state, window_end, auto=True)
        return None

    # -- auto-resolve: HIPAA incidents (10 minutes with no new alert) -------

    def sweep_hipaa_timeouts(self, now: datetime) -> list[IncidentUpdate]:
        timeout = timedelta(minutes=self._config.hipaa_auto_resolve_minutes)
        updates = []
        for state in self._by_fingerprint.values():
            if state.incident.state not in ACTIVE_STATES:
                continue
            if not state.incident.kind.startswith("hipaa_"):
                continue
            if state.last_alert_ts is not None and now - state.last_alert_ts >= timeout:
                updates.append(self._resolve(state, now, auto=True))
        return updates

    # -- queries -------------------------------------------------------------

    def get(self, incident_id: int) -> Optional[Incident]:
        state = self._by_id.get(incident_id)
        return state.incident if state else None

    def list_incidents(self, *, state: Optional[str] = None) -> list[Incident]:
        incidents = [s.incident for s in self._by_fingerprint.values()]
        if state is not None:
            incidents = [i for i in incidents if i.state == state]
        return incidents
