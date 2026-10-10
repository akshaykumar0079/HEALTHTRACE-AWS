"""Failed logins followed by an unusual successful login (``auth.log``).

Rule (documented in docs/incident-grouping.md and docs/simulator.md):

* every *failure* is remembered per user for ``window_minutes`` of event time;
* a *success* with at least ``failure_threshold`` remembered failures raises
  ``auth_suspicious_login``;
* the failures are then forgotten, so an unchanged pattern cannot alert again
  from the same burst (a new burst is needed).

Severity is rule-based (no continuous score is invented):

* MEDIUM  - threshold reached, success from the user's usual region;
* HIGH    - success from an unfamiliar region, or failures >= threshold * ``high_failure_multiple``;
* CRITICAL - both.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Optional

from app.config import AuthConfig
from app.models import Alert, Anomaly, AuthEvent, Severity


class AuthDetector:
    def __init__(self, config: AuthConfig) -> None:
        self._config = config
        self._failures: dict[str, deque[AuthEvent]] = {}

    def evaluate(self, event: AuthEvent) -> list[Anomaly]:
        window = timedelta(minutes=self._config.window_minutes)
        recent = self._failures.setdefault(event.user_id, deque())
        # Late-arriving or out-of-order events must not wipe newer history.
        while recent and event.ts - recent[0].ts > window:
            recent.popleft()

        if event.outcome == "failure":
            recent.append(event)
            return []

        count = len(recent)
        if count < self._config.failure_threshold:
            return []
        first, last = recent[0], recent[-1]
        sources = sorted({f.source_region for f in recent})
        anomaly = Anomaly(
            kind="auth_suspicious_login",
            ts=event.ts,
            user_id=event.user_id,
            metrics={
                "failures": count,
                "failure_threshold": self._config.failure_threshold,
                "first_failure_ts": first.ts.isoformat(),
                "last_failure_ts": last.ts.isoformat(),
                "failure_regions": sources,
                "success_region": event.source_region,
                "user_region": event.user_region,
                "unfamiliar_region": event.is_unfamiliar_region,
                "method": event.method,
            },
        )
        recent.clear()
        return [anomaly]


def score_auth_anomaly(anomaly: Anomaly, config: AuthConfig) -> Alert:
    m = anomaly.metrics
    failures = int(m.get("failures", 0))
    unfamiliar = bool(m.get("unfamiliar_region"))
    many = failures >= config.failure_threshold * config.high_failure_multiple
    severity: Severity
    if unfamiliar and many:
        severity = "CRITICAL"
    elif unfamiliar or many:
        severity = "HIGH"
    else:
        severity = "MEDIUM"
    where = f" from unfamiliar region {m.get('success_region')}" if unfamiliar else ""
    explanation = f"user {anomaly.user_id}: {failures} failed logins, then a successful login{where}"
    return Alert(
        ts=anomaly.ts, kind="auth_suspicious_login", user_id=anomaly.user_id, severity=severity,
        score=0.0,  # rule-based, not a continuous score
        explanation=explanation, metrics=dict(m),
    )
