"""Check a model's answer against the bundle it was given.

A model answer is accepted claim by claim. A claim survives only if:

* it cites at least one fact id and every id exists in the bundle;
* it contains no forbidden identifier, e-mail, IP address, URL, key or SSN pattern;
* any ``actor-N`` alias, ISO timestamp and number in it appears in the bundle
  (so a figure cannot be invented);
* it does not say that an action has already been taken (recommendations only).

The summary, the severity rationale and at least one next step must survive,
otherwise the whole answer is rejected and the deterministic insight is used.
Hypotheses that fail are dropped and counted. Confidence is set by the code from
the stored evidence, never taken from the model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from app.ai.sanitize import Bundle, SanitizationError, strip_refs
from app.ai.schema import (
    MAX_CLAIM_CHARS, MAX_HYPOTHESES, MAX_STEPS, PROMPT_VERSION, Claim, Hypothesis, Insight,
)
from app.ai.templates import cap_confidence, confidence_cap, evidence_list

_NUM = re.compile(r"(?<![\w.:-])\d+(?:\.\d+)?(?![\w:-])")
_XX = re.compile(r"\b[1-5]xx\b", re.I)
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.+\-Z]{6,40}")
_ALIAS = re.compile(r"\bactor-\d+\b")
_EXECUTED = re.compile(
    r"\b(?:I|we)\s+(?:have|had|will|did|am|are)\b|"
    r"\b(?:has|have|was|were)\s+(?:been\s+)?(?:already\s+)?(?:blocked|disabled|locked|reset|isolated|quarantined|"
    r"deleted|notified|paged|escalated|suspended|revoked|remediated|fixed)\b", re.I)
_BAD_CHARS = re.compile(r"[<>`\x00-\x08\x0b\x0c\x0e-\x1f]")


@dataclass
class Validation:
    insight: Optional[Insight]
    reason: Optional[str] = None
    dropped: int = 0


def number_ok(x: float, known: list[float]) -> bool:
    for v in known:
        if abs(x - v) <= max(0.51 if abs(v) >= 1 else 0.0051, 0.011 * abs(v)):
            return True
        if abs(v) <= 1 and abs(x - v * 100) <= 0.51:
            return True
    return False


def claim_problem(text: Any, refs: Any, bundle: Bundle, known: list[float], times: set[str]) -> Optional[str]:
    if not isinstance(text, str) or not text.strip():
        return "empty text"
    if len(text) > MAX_CLAIM_CHARS:
        return "too long"
    if _BAD_CHARS.search(text):
        return "disallowed characters"
    if not isinstance(refs, list) or not refs or len(refs) > 8 or not all(isinstance(r, str) for r in refs):
        return "missing evidence refs"
    if any(r not in bundle.facts for r in refs):
        return "unknown evidence id"
    try:
        bundle.verify_clean(text)
    except SanitizationError:
        return "forbidden content"
    if any(a not in bundle.aliases for a in _ALIAS.findall(text)):
        return "unknown actor alias"
    if _EXECUTED.search(text):
        return "claims an action was taken"
    stamps = _ISO.findall(text)
    if any(s not in times for s in stamps):
        return "unknown timestamp"
    body = _ALIAS.sub(" ", _ISO.sub(" ", strip_refs(text)))
    body = _XX.sub(" ", body)
    for token in _NUM.findall(body):
        if not number_ok(float(token), known):
            return "number not in evidence"
    return None


def _extract_json(raw: str, max_chars: int) -> Optional[dict[str, Any]]:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > max_chars:
        return None
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I).strip()
    if not text.startswith("{"):
        return None
    try:
        obj, end = json.JSONDecoder().raw_decode(text)
    except (ValueError, RecursionError):
        return None
    if text[end:].strip() or not isinstance(obj, dict):
        return None
    return obj


def validate_model_output(raw: str, bundle: Bundle, *, model: str, max_chars: int = 8000) -> Validation:
    obj = _extract_json(raw, max_chars)
    if obj is None:
        return Validation(None, "invalid_response")
    known, times = bundle.numbers(), bundle.timestamps()
    dropped = 0

    def one(item: Any) -> Optional[Claim]:
        if not isinstance(item, dict):
            return None
        if claim_problem(item.get("text"), item.get("evidence_refs"), bundle, known, times):
            return None
        return Claim(text=item["text"].strip(), evidence_refs=list(dict.fromkeys(item["evidence_refs"])))

    summary = one(obj.get("summary"))
    rationale = one(obj.get("severity_rationale"))
    if summary is None or rationale is None:
        return Validation(None, "invalid_response")

    quality = bundle.evidence_quality
    insufficient = bool(obj.get("insufficient_evidence")) is True or not any(
        f.get("type") in ("alert", "aggregate") for f in bundle.facts.values())

    hypotheses: list[Hypothesis] = []
    raw_h = obj.get("hypotheses", [])
    for item in (raw_h if isinstance(raw_h, list) else [])[: MAX_HYPOTHESES + 2]:
        claim = one(item)
        if claim is None or insufficient or len(hypotheses) >= MAX_HYPOTHESES:
            dropped += 1
            continue
        said = item.get("confidence") if isinstance(item, dict) else None
        conf = said if said in ("low", "medium", "high") else "low"
        hypotheses.append(Hypothesis(text=claim.text, evidence_refs=claim.evidence_refs,
                                     confidence=cap_confidence(conf, quality)))
    steps: list[Claim] = []
    raw_s = obj.get("next_steps", [])
    for item in (raw_s if isinstance(raw_s, list) else [])[: MAX_STEPS + 2]:
        claim = one(item)
        if claim is None or len(steps) >= MAX_STEPS:
            dropped += 1
            continue
        steps.append(claim)
    if not steps:
        return Validation(None, "invalid_response")

    insight = Insight(
        incident_id=bundle.incident_id, generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by="ollama", model=model, prompt_version=PROMPT_VERSION, bundle_hash=bundle.hash,
        dropped_claims=dropped, summary=summary, severity_rationale=rationale, hypotheses=hypotheses,
        next_steps=steps, overall_confidence=confidence_cap(quality) if not insufficient else "low",
        evidence_quality=quality, insufficient_evidence=insufficient,
    )
    insight.evidence = evidence_list(bundle, insight)
    return Validation(insight, None, dropped)
