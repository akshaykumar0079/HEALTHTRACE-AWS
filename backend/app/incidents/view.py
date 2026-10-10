"""How an Incident is presented over the API and WebSocket: the stored fields
plus derived display fields. Shared by REST routes and live broadcasts so the
two never disagree."""

from __future__ import annotations

from typing import Any

from app.incidents.engine import is_rule_based
from app.models import Incident

# What the UI calls each internal state. OPEN is shown as "New".
STATUS_LABEL = {"OPEN": "New", "ACKNOWLEDGED": "Acknowledged", "INVESTIGATING": "Investigating", "RESOLVED": "Resolved"}
KIND_TITLE = {
    "error_rate": "Error rate spike",
    "latency_degradation": "Latency degradation",
    "hipaa_bulk_access": "Bulk PHI access",
    "hipaa_bulk_export": "Bulk PHI export",
    "hipaa_off_hours": "Off-hours PHI access",
    "hipaa_region_mismatch": "Cross-region PHI access",
    "auth_suspicious_login": "Suspicious login",
}


_EVIDENCE_LEVELS = ((0, "none"), (1, "limited"), (5, "moderate"), (15, "strong"))


def evidence_quality(evidence_count: int) -> str:
    """none (0 stored records), limited (1-4), moderate (5-14), strong (15+).
    Independent of severity and risk score: it says how much stored material
    backs the incident, not how bad it is."""
    label = "none"
    for floor, name in _EVIDENCE_LEVELS:
        if evidence_count >= floor:
            label = name
    return label


def grouping_info(incident: Incident) -> dict[str, Any]:
    """Why these alerts form one incident, in plain words."""
    if incident.user_id is not None:
        key, subject = f"{incident.kind} + user", incident.user_id
        rule = "same detection kind and same user"
    else:
        key, subject = f"{incident.kind} + service", incident.service or "unknown"
        rule = "same detection kind and same service"
    return {
        "rule": rule,
        "key": incident.fingerprint,
        "explanation": (
            f"Alerts are grouped when they share the {rule} ({key} = {subject}). Repeats attach to the open "
            "incident; a recurrence shortly after resolution reopens it; otherwise a new incident starts."
        ),
    }


def incident_view(incident: Incident) -> dict[str, Any]:
    """Incident as the API returns it: stored fields plus derived display
    fields. ``risk_score`` is the detector's own score on a 0-100 scale; rule
    based HIPAA detections have none, so it is null rather than invented."""
    data = incident.model_dump(mode="json")
    source = incident.service or incident.user_id or "unknown"
    data.update(
        title=f"{KIND_TITLE.get(incident.kind, incident.kind)}: {source}",
        source=source,
        status=incident.state,
        status_label=STATUS_LABEL.get(incident.state, incident.state),
        severity=incident.peak_severity,
        occurrence_count=incident.alert_count,
        first_seen_at=incident.opened_at.isoformat(),
        last_seen_at=(incident.last_seen_at or incident.opened_at).isoformat(),
        risk_score=None if incident.peak_score is None else max(0, min(100, round(incident.peak_score * 100))),
        risk_basis="statistical score" if incident.peak_score is not None else "rule-based detection (no score)",
        risk_trend_basis="alert score" if not is_rule_based(incident.kind) else "alert severity (rule-based)",
        evidence_quality=evidence_quality(incident.evidence_count),
        grouping=grouping_info(incident),
    )
    return data
