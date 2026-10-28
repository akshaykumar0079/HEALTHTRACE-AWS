"""Shapes shared by the AI package. Nothing here touches the network or the database."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

PROMPT_VERSION = "incident-insight-v1"

Confidence = Literal["low", "medium", "high"]
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

# Short machine codes only; never text from a model or a log.
FallbackReason = Literal[
    "ai_disabled", "provider_not_configured", "provider_unavailable", "provider_error",
    "invalid_response", "prompt_too_large", "sanitization_failed",
]

MAX_CLAIM_CHARS = 400
MAX_HYPOTHESES = 4
MAX_STEPS = 6


class Claim(BaseModel):
    text: str
    evidence_refs: list[str] = Field(default_factory=list)


class Hypothesis(Claim):
    # Set by the code, never by a model: a hypothesis is not a finding.
    label: Literal["hypothesis"] = "hypothesis"
    confidence: Confidence = "low"


class EvidenceRef(BaseModel):
    id: str
    type: str
    label: str


class Insight(BaseModel):
    incident_id: int
    generated_at: str
    generated_by: Literal["deterministic", "ollama"]
    model: Optional[str] = None
    prompt_version: str = PROMPT_VERSION
    bundle_hash: str
    status: Literal["ok", "fallback"] = "ok"
    fallback_reason: Optional[FallbackReason] = None
    dropped_claims: int = 0
    summary: Claim
    severity_rationale: Claim
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    next_steps: list[Claim] = Field(default_factory=list)
    overall_confidence: Confidence = "low"
    evidence_quality: str = "none"
    insufficient_evidence: bool = False
    evidence: list[EvidenceRef] = Field(default_factory=list)
    # Recommendations are advice only. Phase 1 never executes anything.
    executed_actions: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "Generated analysis from stored, pseudonymised evidence. Hypotheses are possibilities, not findings, "
        "and nothing listed here has been done automatically."
    )
