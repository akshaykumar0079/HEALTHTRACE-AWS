"""Demo scenarios the dashboard may inject (SPEC.md section 7).

The backend owns this catalogue so ``POST /api/demo/inject`` can reject
unknown names before writing the control file; a test keeps it in sync with
``generator.scenarios``.
"""

from __future__ import annotations

from typing import Optional, TypedDict


class Scenario(TypedDict):
    name: str
    label: str
    target: Optional[str]
    family: str
    effect: str
    expected: str


SCENARIOS: list[Scenario] = [
    {"name": "urgent_prior_auth_failure", "label": "Urgent prior-auth failure", "target": "prior_auth",
     "family": "service", "effect": "prior_auth errors reach 35%, mostly urgent, 20+ patients",
     "expected": "CRITICAL"},
    {"name": "eligibility_outage", "label": "Eligibility outage", "target": "eligibility",
     "family": "service", "effect": "eligibility returns 503 at an 80% rate", "expected": "CRITICAL"},
    {"name": "claims_degradation", "label": "Claims degradation", "target": "claims",
     "family": "service", "effect": "claims error rate 8-10%, routine", "expected": "LOW or MEDIUM"},
    {"name": "batch_spike", "label": "Batch error spike", "target": "batch",
     "family": "service", "effect": "batch error rate 60%, no patients", "expected": "LOW"},
    {"name": "latency_degradation", "label": "Pharmacy latency", "target": "pharmacy",
     "family": "service", "effect": "pharmacy p95 latency x5, few errors", "expected": "MEDIUM"},
    {"name": "bulk_phi_access", "label": "Bulk PHI access", "target": "U-117",
     "family": "hipaa", "effect": "U-117 views 300 patients in 5 minutes", "expected": "HIGH or CRITICAL"},
    {"name": "off_hours_access", "label": "Off-hours access", "target": "U-042",
     "family": "hipaa", "effect": "U-042 accesses records at a simulated 03:00", "expected": "MEDIUM or HIGH"},
    {"name": "region_mismatch", "label": "Region mismatch", "target": "U-088",
     "family": "hipaa", "effect": "U-088 views 12 patients from another region", "expected": "HIGH"},
    {"name": "suspicious_login", "label": "Suspicious login", "target": "U-064",
     "family": "auth", "effect": "U-064 fails 8 logins, then succeeds from an unfamiliar region",
     "expected": "HIGH"},
    {"name": "recovery", "label": "Recovery", "target": None,
     "family": "recovery", "effect": "return to normal traffic", "expected": "incidents auto-resolve"},
]

SCENARIO_NAMES: frozenset[str] = frozenset(s["name"] for s in SCENARIOS)
MIN_DURATION_S = 5.0
MAX_DURATION_S = 600.0
