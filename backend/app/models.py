"""Pydantic models shared across the MedGuard backend (SPEC.md section 4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Service = Literal["claims", "prior_auth", "eligibility", "pharmacy", "batch"]
Level = Literal["INFO", "WARN", "ERROR"]
Priority = Literal["urgent", "routine"]
AuditAction = Literal["VIEW_RECORD", "EDIT_RECORD", "EXPORT_RECORDS", "SEARCH"]
AuthOutcome = Literal["success", "failure"]

# Synthetic patient IDs only, e.g. "P-000123" (SPEC.md section 1: hard rules).
PATIENT_ID_PATTERN = r"^P-\d{6}$"


class AppEvent(BaseModel):
    """One JSON line from data/logs/app.log (SPEC.md section 5)."""

    ts: datetime
    type: Literal["app"] = "app"
    service: Service
    level: Level
    priority: Priority
    request_id: str
    patient_id: Optional[str] = Field(default=None, pattern=PATIENT_ID_PATTERN)
    status: int = Field(ge=100, le=599)
    latency_ms: int = Field(ge=0)
    msg: str

    @property
    def is_error(self) -> bool:
        """An event counts as an error when level == ERROR or status >= 500."""
        return self.level == "ERROR" or self.status >= 500


class AuditEvent(BaseModel):
    """One JSON line from data/logs/audit.log (SPEC.md section 5)."""

    ts: datetime
    type: Literal["audit"] = "audit"
    user_id: str
    role: str
    action: AuditAction
    patient_id: str = Field(pattern=PATIENT_ID_PATTERN)
    patient_region: str
    user_region: str

    @property
    def is_region_mismatch(self) -> bool:
        return self.patient_region != self.user_region


class AuthEvent(BaseModel):
    """One JSON line from data/logs/auth.log: a login attempt. Synthetic only;
    ``source_ip`` uses the documentation range 192.0.2.0/24 (RFC 5737)."""

    ts: datetime
    type: Literal["auth"] = "auth"
    user_id: str
    outcome: AuthOutcome
    method: str = "password"
    source_region: str
    user_region: str
    source_ip: Optional[str] = None

    @property
    def is_unfamiliar_region(self) -> bool:
        return self.source_region != self.user_region


class WindowMetrics(BaseModel):
    """One 60s-window snapshot for one service, emitted every 5s of event time
    (SPEC.md section 6.3)."""

    service: Service
    window_end: datetime
    total: int
    errors: int
    error_rate: float
    p95_latency_ms: float
    urgent_errors: int
    affected_patients_urgent: int
    affected_patients_routine: int
    malformed_lines: int = 0
    # The error-rate baseline in force for this window (None while warming up).
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None


AnomalyKind = Literal[
    "error_rate",
    "latency_degradation",
    "hipaa_bulk_access",
    "hipaa_off_hours",
    "hipaa_region_mismatch",
    "hipaa_bulk_export",
    "auth_suspicious_login",
]


class Anomaly(BaseModel):
    """Output of the anomaly engine / access detector (SPEC.md sections 6.5, 6.7)."""

    kind: AnomalyKind
    ts: datetime
    service: Optional[Service] = None
    user_id: Optional[str] = None
    z: float = 0.0
    metrics: dict[str, Any] = Field(default_factory=dict)
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
IncidentState = Literal["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"]


class Alert(BaseModel):
    """A single detected anomaly, scored and explained (SPEC.md section 6.6)."""

    id: Optional[int] = None
    ts: datetime
    kind: AnomalyKind
    service: Optional[Service] = None
    user_id: Optional[str] = None
    severity: Severity
    score: float
    explanation: str
    metrics: dict[str, Any] = Field(default_factory=dict)
    incident_id: Optional[int] = None


class Incident(BaseModel):
    """A de-duplicated, lifecycle-tracked group of alerts (SPEC.md section 6.8)."""

    id: Optional[int] = None
    fingerprint: str
    kind: AnomalyKind
    service: Optional[Service] = None
    user_id: Optional[str] = None
    state: IncidentState = "OPEN"
    peak_severity: Severity
    alert_count: int = 1
    opened_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    mttr_seconds: Optional[float] = None
    # External notifications suppressed until then (persisted so a restart keeps the mute).
    muted_until: Optional[datetime] = None
    # Workflow fields. Pinning is purely an organisational flag: it never
    # changes severity, risk score or status.
    pinned: bool = False
    pinned_at: Optional[datetime] = None
    investigating_at: Optional[datetime] = None
    # Newest alert attached to this incident (what the UI shows as "last seen").
    last_seen_at: Optional[datetime] = None
    # Highest real detector score among attached alerts; None for rule-based
    # (HIPAA) detections, which have no continuous score. Never fabricated.
    peak_score: Optional[float] = None
    # Latest alert's real score (None for rule-based detections) and the
    # direction of recent risk. Trend is derived from stored alerts only.
    latest_score: Optional[float] = None
    risk_trend: Literal["rising", "falling", "stable", "unknown"] = "unknown"
    # How many times a resolved incident was reopened by a recurrence (see
    # docs/incident-grouping.md) and how many evidence records are stored.
    reopen_count: int = 0
    evidence_count: int = 0


IncidentEventType = Literal[
    "opened", "alert_attached", "escalated", "acknowledged", "investigating", "resolved", "auto_resolved",
    "muted", "pinned", "unpinned", "reopened",
]


class IncidentEvent(BaseModel):
    """One row of an incident's audit trail (SPEC.md section 6.8), also
    broadcast over the WebSocket as an ``incident_update`` message."""

    id: Optional[int] = None
    incident_id: int
    ts: datetime
    event_type: IncidentEventType
    severity: Optional[Severity] = None
    detail: Optional[str] = None
