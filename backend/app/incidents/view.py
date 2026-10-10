"""How an Incident is presented over the API and WebSocket: the stored fields
plus derived display fields. Shared by REST routes and live broadcasts so the
two never disagree."""

from __future__ import annotations

from typing import Any

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
    )
    return data
