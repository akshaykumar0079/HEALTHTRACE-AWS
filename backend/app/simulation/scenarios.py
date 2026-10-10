"""Scenario catalogue: what is injected and what the detector is expected to do.

Each scenario is repeatable: the same ``seed`` always produces the same
synthetic events, so the same alerts. Expectations are written *before* a run
and checked against what the pipeline actually produced; a run passes only if
every check passes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# A fixed synthetic start. 16:00Z is 11:00 in America/Chicago (the configured
# business-hours zone), so ordinary staff traffic exists and nothing is
# off-hours unless a scenario makes it so.
SIM_START = datetime(2026, 3, 10, 16, 0, 0, tzinfo=timezone.utc)
WARMUP_SECONDS = 900.0     # normal traffic so baselines are warm before injection
TAIL_SECONDS = 1200.0      # normal traffic afterwards, so incidents can resolve


@dataclass(frozen=True)
class Expectation:
    """The incident the detector must raise."""

    kind: str
    entity: str                     # service name, or user id for HIPAA/auth kinds
    severities: tuple[str, ...]     # acceptable peak severities
    max_delay_s: float              # detection delay budget, in event time
    min_evidence: int               # evidence records captured for the incident
    evidence_type: str              # "app" | "audit" | "auth": which log the evidence must come from


@dataclass(frozen=True)
class SimScenario:
    id: str
    title: str
    description: str
    generator_scenario: Optional[str]      # name in generator.scenarios, None = normal traffic only
    inject_seconds: float
    seed: int
    expectation: Optional[Expectation]
    # Incidents that are a legitimate side effect of the injection, not false positives.
    allowed_extra: tuple[tuple[str, str], ...] = ()
    must_resolve: bool = False             # the expected incident must be RESOLVED by the end of the run
    max_notifications: int = 6             # flood guard: HIGH/CRITICAL notifications allowed per run
    rate: float = 20.0                     # synthetic app events per second
    expected_alerts: str = ""              # plain-language expectation shown in the dashboard
    labelled_normal: bool = False          # control run: any incident is a false positive
    known_limit: bool = False              # documented weak spot: reported, but not a regression gate


SCENARIOS: dict[str, SimScenario] = {
    s.id: s
    for s in (
        SimScenario(
            id="error_spike",
            title="Application error spike",
            description="The eligibility service starts failing 80% of requests for 5 minutes.",
            generator_scenario="eligibility_outage",
            inject_seconds=300,
            seed=1101,
            expectation=Expectation(
                kind="error_rate", entity="eligibility", severities=("HIGH", "CRITICAL"),
                max_delay_s=120, min_evidence=5, evidence_type="app",
            ),
            allowed_extra=(("error_rate", "prior_auth"), ("error_rate", "pharmacy"), ("error_rate", "claims"),
                           ("latency_degradation", "eligibility")),
            expected_alerts="error_rate incident on eligibility, HIGH or CRITICAL, with failing requests as evidence.",
        ),
        SimScenario(
            id="failed_logins_then_success",
            title="Failed logins, then an unusual successful login",
            description="Synthetic user U-064 fails 8 logins from an unfamiliar region, then succeeds from it.",
            generator_scenario="suspicious_login",
            inject_seconds=300,
            seed=1202,
            expectation=Expectation(
                kind="auth_suspicious_login", entity="U-064", severities=("HIGH", "CRITICAL"),
                max_delay_s=300, min_evidence=5, evidence_type="auth",
            ),
            expected_alerts="auth_suspicious_login incident for U-064, HIGH or CRITICAL, with the login attempts as evidence.",
        ),
        SimScenario(
            id="bulk_record_access",
            title="Bulk access to synthetic patient records",
            description="Synthetic user U-117 views 300 synthetic patient records in 5 minutes.",
            generator_scenario="bulk_phi_access",
            inject_seconds=300,
            seed=1303,
            expectation=Expectation(
                kind="hipaa_bulk_access", entity="U-117", severities=("HIGH", "CRITICAL"),
                max_delay_s=300, min_evidence=5, evidence_type="audit",
            ),
            expected_alerts="hipaa_bulk_access incident for U-117, HIGH or CRITICAL, with the audit entries as evidence.",
        ),
        SimScenario(
            id="prior_auth_pipeline_failure",
            title="Prior-authorization pipeline failure",
            description="Urgent prior-authorization requests fail at 35% for 5 minutes.",
            generator_scenario="urgent_prior_auth_failure",
            inject_seconds=300,
            seed=1404,
            expectation=Expectation(
                kind="error_rate", entity="prior_auth", severities=("HIGH", "CRITICAL"),
                max_delay_s=120, min_evidence=5, evidence_type="app",
            ),
            allowed_extra=(("latency_degradation", "prior_auth"),),
            expected_alerts="error_rate incident on prior_auth, HIGH or CRITICAL, with failing urgent requests as evidence.",
        ),
        SimScenario(
            id="recovery_resolution",
            title="Recovery and resolution",
            description="Eligibility fails for 3 minutes, then traffic returns to normal and the incident resolves itself.",
            generator_scenario="eligibility_outage",
            inject_seconds=180,
            seed=1505,
            expectation=Expectation(
                kind="error_rate", entity="eligibility", severities=("HIGH", "CRITICAL"),
                max_delay_s=120, min_evidence=5, evidence_type="app",
            ),
            allowed_extra=(("error_rate", "prior_auth"), ("error_rate", "pharmacy"), ("error_rate", "claims"),
                           ("latency_degradation", "eligibility")),
            must_resolve=True,
            expected_alerts="error_rate incident on eligibility that is RESOLVED automatically once traffic is normal.",
        ),
        SimScenario(
            id="mild_degradation",
            title="Mild claims degradation (known limit)",
            description="Claims error rate rises to 8-10% for 5 minutes. Small shifts like this are not reliably detected.",
            generator_scenario="claims_degradation",
            inject_seconds=300,
            seed=1707,
            expectation=Expectation(
                kind="error_rate", entity="claims", severities=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
                max_delay_s=180, min_evidence=3, evidence_type="app",
            ),
            allowed_extra=(("latency_degradation", "claims"),),
            known_limit=True,
            expected_alerts="error_rate incident on claims. Documented weak spot: detected in only some seeds.",
        ),
        SimScenario(
            id="normal_control",
            title="Normal traffic (false-positive control)",
            description="Only ordinary synthetic traffic. Any incident here is a false positive.",
            generator_scenario=None,
            inject_seconds=300,
            seed=1606,
            expectation=None,
            labelled_normal=True,
            expected_alerts="No incidents.",
        ),
    )
}

DEFAULT_BENCHMARK_SEEDS = (11, 22, 33)


def list_scenarios() -> list[dict]:
    return [
        {
            "id": s.id, "title": s.title, "description": s.description, "seed": s.seed,
            "expected_alerts": s.expected_alerts,
            "expected_severity": list(s.expectation.severities) if s.expectation else [],
            "expected_kind": s.expectation.kind if s.expectation else None,
            "expected_entity": s.expectation.entity if s.expectation else None,
            "max_detection_delay_s": s.expectation.max_delay_s if s.expectation else None,
            "min_evidence": s.expectation.min_evidence if s.expectation else 0,
            "must_resolve": s.must_resolve, "known_limit": s.known_limit,
            "inject_seconds": s.inject_seconds,
            "synthetic": True,
        }
        for s in SCENARIOS.values()
    ]
