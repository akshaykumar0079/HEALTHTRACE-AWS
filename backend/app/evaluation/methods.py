"""The methods compared by the evaluation.

* ``current``            - the shipped detector, config.yaml unchanged.
* ``no_time_aware``      - ablation: every window is judged against the service's
                           all-hours baseline (``baseline.time_aware: false``).
* ``no_patient_impact``  - ablation: severity ignores the patient-impact term
                           (``criticality_weight=1``, ``patient_factor_weight=0``).
* ``threshold_*``        - a fixed error-rate threshold with no learning (below).

Each method turns a synthetic log stream into a list of incident-level
``Detection`` objects, which ``scoring`` then compares with the ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

from app.config import AppConfig, load_config
from app.evaluation.scoring import ACTIONABLE, Detection
from app.models import AppEvent
from app.parse.enricher import Enricher
from app.parse.parser import Parser
from app.detect.window import SlidingWindow

# Detector kinds that are computed from application-service metrics. The two
# service ablations and the threshold baseline only act on these.
SERVICE_KINDS = frozenset({"error_rate", "latency_degradation"})


@dataclass(frozen=True)
class Method:
    id: str
    title: str
    description: str
    kind: str                       # "pipeline" | "threshold"
    # pipeline methods: apply to a deep copy of the config
    config_edit: Optional[Callable[[AppConfig], None]] = None
    # threshold methods
    threshold: Optional[float] = None
    sensitivity: bool = False       # reported, but not the headline baseline
    service_only: bool = False      # only meaningful for service-metric scenarios

    def applies_to(self, expected_kind: Optional[str]) -> tuple[bool, str]:
        """(applicable, reason). ``expected_kind`` is None for the control run.

        The control run is always applicable: any method can raise a false alarm
        on ordinary traffic. A method restricted to service metrics is not scored
        on scenarios whose detector is a different (rule-based) one."""
        if not self.service_only or expected_kind is None or expected_kind in SERVICE_KINDS:
            return True, ""
        return False, ("not applicable: this scenario is detected by a rule-based access/auth detector "
                       "that the method does not change or cannot see")


def _no_time_aware(cfg: AppConfig) -> None:
    cfg.baseline.time_aware = False


def _no_patient_impact(cfg: AppConfig) -> None:
    cfg.severity.criticality_weight = 1.0
    cfg.severity.patient_factor_weight = 0.0


METHODS: dict[str, Method] = {m.id: m for m in (
    Method("current", "Current detector", "EWMA baseline per service and hour + z-score + patient-impact severity, "
           "and the rule-based HIPAA access and login detectors.", "pipeline", config_edit=lambda cfg: None),
    Method("threshold_10pct", "Fixed threshold (10%)",
           "Alert when a service's 60 s error rate is >= 10% and it has >= 5 errors. No learning, no severity.",
           "threshold", threshold=0.10, service_only=True),
    Method("threshold_5pct", "Fixed threshold (5%), sensitivity",
           "Same rule at 5%.", "threshold", threshold=0.05, sensitivity=True, service_only=True),
    Method("threshold_20pct", "Fixed threshold (20%), sensitivity",
           "Same rule at 20%.", "threshold", threshold=0.20, sensitivity=True, service_only=True),
    Method("no_time_aware", "Ablation: no time-aware baseline",
           "Current detector, but the per-hour-of-day baseline bucket is ignored.", "pipeline",
           config_edit=_no_time_aware, service_only=True),
    Method("no_patient_impact", "Ablation: no patient-impact scoring",
           "Current detector, but severity = deviation x criticality (patient-impact term weight 0).",
           "pipeline", config_edit=_no_patient_impact, service_only=True),
)}

DEFAULT_METHODS = tuple(METHODS)


def effective_config(method: Method) -> AppConfig:
    """A private, edited copy of config.yaml. ``load_config`` is cached and shared, so it must never be mutated."""
    cfg = load_config().model_copy(deep=True)
    if method.config_edit:
        method.config_edit(cfg)
    return cfg


def detections_from_pipeline(incidents: list, alerts: list) -> list[Detection]:
    by_incident: dict[int, list] = {}
    for a in alerts:
        by_incident.setdefault(a.incident_id or -1, []).append(a)
    out = []
    for inc in incidents:
        own = sorted(by_incident.get(inc.id or -1, []), key=lambda a: a.ts)
        first = own[0].ts if own else inc.opened_at
        actionable = next((a.ts for a in own if a.severity in ACTIONABLE), None)
        out.append(Detection(kind=inc.kind, entity=inc.service or inc.user_id or "",
                             first_ts=first, peak_severity=inc.peak_severity, first_actionable_ts=actionable,
                             last_ts=own[-1].ts if own else first, alert_count=len(own)))
    return out


# -- fixed-threshold baseline -----------------------------------------------------------------


def threshold_detections(lines: list[str], threshold: float, *, min_errors: Optional[int] = None,
                         resolve_windows: Optional[int] = None) -> list[Detection]:
    """The simple baseline: no baseline, no z-score, no severity.

    It reuses the product's 60 s / 5 s sliding window so the only difference from
    the detector is the decision rule. A window is *flagged* when
    ``error_rate >= threshold`` and ``errors >= min_errors`` (the detector's own
    minimum-evidence rule, default 5). Consecutive flagged windows of one service
    form one incident; it closes after ``resolve_windows`` consecutive unflagged
    windows (default: the detector's ``service_auto_resolve_windows``, 6) and a
    later flag opens a new incident. Every alert counts as actionable because the
    rule has no severity levels. Only ``error_rate`` is monitored (no latency).
    """
    cfg = load_config()
    min_errors = cfg.anomaly.error_rate_min_errors if min_errors is None else min_errors
    resolve_windows = cfg.incident.service_auto_resolve_windows if resolve_windows is None else resolve_windows
    parser, enricher = Parser(), Enricher(cfg)
    window = SlidingWindow(cfg.window.size_seconds, cfg.window.step_seconds)
    open_since: dict[str, datetime] = {}
    calm: dict[str, int] = {}
    found: list[Detection] = []
    for line in lines:
        event, _ = parser.parse(line)
        if not isinstance(event, AppEvent):
            continue
        for m in window.add(enricher.enrich(event)):
            if m.errors >= min_errors and m.error_rate >= threshold:
                calm[m.service] = 0
                if m.service not in open_since:
                    open_since[m.service] = m.window_end
                    found.append(Detection(kind="error_rate", entity=m.service, first_ts=m.window_end,
                                           peak_severity=None, first_actionable_ts=m.window_end))
            elif m.service in open_since:
                calm[m.service] = calm.get(m.service, 0) + 1
                if calm[m.service] >= resolve_windows:
                    del open_since[m.service]
    return found
