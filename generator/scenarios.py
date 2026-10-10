"""Incident injection definitions (SPEC.md section 7).

Two kinds of scenario:

- ``ServiceScenario`` overrides one app-log service's error rate / urgent mix
  / latency for the scenario's duration.
- ``AccessScenario`` drives one user's audit-log activity into a HIPAA
  access-anomaly pattern (bulk access, off-hours, region mismatch).

``"recovery"`` is not itself a scenario with an effect: it just clears
whichever scenario is currently active, so traffic returns to normal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

RECOVERY_SCENARIO = "recovery"


@dataclass(frozen=True)
class ServiceScenario:
    name: str
    service: str
    error_rate: float
    urgent_fraction: float  # fraction of that service's ERRORS marked urgent
    affected_patients: bool  # False => events carry no patient_id (e.g. batch)
    latency_multiplier: float = 1.0
    description: str = ""


@dataclass(frozen=True)
class AccessScenario:
    name: str
    user_id: str
    kind: str  # "bulk_access" | "off_hours" | "region_mismatch"
    total_patients: int
    hour_of_day: Optional[int] = None  # forced ts hour, for off-hours
    description: str = ""


@dataclass(frozen=True)
class AuthScenario:
    """Repeated failed logins for one user followed by a successful login."""

    name: str
    user_id: str
    failures: int
    source_region: str  # where the failed and the successful logins come from
    description: str = ""


SERVICE_SCENARIOS: dict[str, ServiceScenario] = {
    "urgent_prior_auth_failure": ServiceScenario(
        name="urgent_prior_auth_failure",
        service="prior_auth",
        error_rate=0.35,
        urgent_fraction=0.85,
        affected_patients=True,
        description="prior_auth errors reach 35%, mostly urgent, 20+ patients",
    ),
    "eligibility_outage": ServiceScenario(
        name="eligibility_outage",
        service="eligibility",
        error_rate=0.80,
        urgent_fraction=0.30,
        affected_patients=True,
        description="eligibility returns 503 at an 80% rate",
    ),
    "claims_degradation": ServiceScenario(
        name="claims_degradation",
        service="claims",
        error_rate=0.09,
        urgent_fraction=0.0,
        affected_patients=True,
        description="claims error rate 8-10%, routine",
    ),
    "batch_spike": ServiceScenario(
        name="batch_spike",
        service="batch",
        error_rate=0.60,
        urgent_fraction=0.0,
        affected_patients=False,
        description="batch error rate 60%, no patients",
    ),
    "latency_degradation": ServiceScenario(
        name="latency_degradation",
        service="pharmacy",
        error_rate=0.02,
        urgent_fraction=0.10,
        affected_patients=True,
        latency_multiplier=5.0,
        description="pharmacy p95 latency x5, few errors",
    ),
}

ACCESS_SCENARIOS: dict[str, AccessScenario] = {
    "bulk_phi_access": AccessScenario(
        name="bulk_phi_access",
        user_id="U-117",
        kind="bulk_access",
        total_patients=300,
        description="U-117 views 300 patients in 5 minutes",
    ),
    "off_hours_access": AccessScenario(
        name="off_hours_access",
        user_id="U-042",
        kind="off_hours",
        total_patients=15,
        hour_of_day=3,
        description="U-042 accesses records at a simulated 03:00",
    ),
    "region_mismatch": AccessScenario(
        name="region_mismatch",
        user_id="U-088",
        kind="region_mismatch",
        total_patients=12,
        description="U-088 views 12 patients from another region",
    ),
}

AUTH_SCENARIOS: dict[str, AuthScenario] = {
    "suspicious_login": AuthScenario(
        name="suspicious_login",
        user_id="U-064",
        failures=8,
        source_region="EXT-VPN",
        description="U-064 fails to log in 8 times, then succeeds from an unfamiliar region",
    ),
}

ALL_SCENARIO_NAMES: list[str] = [
    *SERVICE_SCENARIOS.keys(),
    *ACCESS_SCENARIOS.keys(),
    *AUTH_SCENARIOS.keys(),
    RECOVERY_SCENARIO,
]


def get_service_scenario(name: str) -> Optional[ServiceScenario]:
    return SERVICE_SCENARIOS.get(name)


def get_access_scenario(name: str) -> Optional[AccessScenario]:
    return ACCESS_SCENARIOS.get(name)


def get_auth_scenario(name: str) -> Optional[AuthScenario]:
    return AUTH_SCENARIOS.get(name)
