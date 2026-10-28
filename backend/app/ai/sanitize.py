"""Build the only thing a model (or the template) is ever allowed to see.

The bundle is assembled from an **allow-list**: a field that is not named here
cannot reach a prompt, whatever the log contained. In particular it never holds
the alert explanation text (it names the user), log ``msg`` text, request ids,
patient ids, IP addresses or the incident's raw ``user_id``. Actors become
per-bundle aliases (``actor-1``) in both ingest modes, because in legacy mode
the stored ``user_id`` is a raw synthetic identifier and in configured mode it
is a pseudonym that should still not be handed to a model.

Every fact has an id (``inc:7``, ``alert:12``, ``ev:30``, ``rule:error_rate``,
``agg:ev``, ``iev:4``). A claim must cite those ids; ``validate`` rejects any
other id, so evidence cannot be invented.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from app.config import AppConfig
from app.incidents.explain import detection_rule
from app.incidents.view import KIND_TITLE, evidence_quality
from app.models import Alert, Incident, IncidentEvent
from app.privacy.redaction import Redactor


class SanitizationError(RuntimeError):
    """A forbidden value would have reached a prompt. The caller falls back to the template."""


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$")
_ENUM = re.compile(r"^[A-Za-z_]{1,32}$")

_ALERT_NUMBERS = (
    "error_rate", "errors", "total", "p95_latency_ms", "urgent_errors", "affected_patients_urgent",
    "affected_patients_routine", "baseline_mean", "baseline_std", "z", "failures", "failure_threshold",
    "distinct_patients", "records", "multiplier",
)
_ALERT_TOKENS = ("success_region", "user_region")
_ALERT_TIMES = ("first_failure_ts", "last_failure_ts")
_EVIDENCE_NUMBERS = ("status", "latency_ms")
_EVIDENCE_BOOLS = ("is_error", "region_mismatch")
_EVIDENCE_ENUMS = ("type", "level", "priority", "action", "outcome", "role", "method")
_EVIDENCE_TOKENS = ("service", "source_region", "user_region", "patient_region")

# Raw record keys whose values must never appear anywhere in a prompt or an answer.
_SENSITIVE_RECORD_KEYS = ("user_id", "patient_id", "request_id", "source_ip", "msg")

_ID_REF = re.compile(r"\b(?:inc|alert|ev|rule|agg|iev|svc):[A-Za-z0-9_-]+")


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def _clean_num(value: Any) -> Optional[float | int]:
    n = _num(value)
    if n is None:
        return None
    return int(value) if isinstance(value, int) else round(n, 6)


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}T[\d:.+\-Z]{6,40}$", value):
        return value
    return None


def _numeric_only(d: dict[str, Any], depth: int = 2) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict) and depth > 0:
            inner = _numeric_only(v, depth - 1)
            if inner:
                out[str(k)] = inner
        else:
            n = _clean_num(v)
            if n is not None:
                out[str(k)] = n
    return out


@dataclass
class Bundle:
    incident_id: int
    facts: dict[str, dict[str, Any]]
    forbidden: list[str] = field(default_factory=list)
    aliases: set[str] = field(default_factory=set)
    evidence_quality: str = "none"
    truncated: bool = False

    @property
    def ids(self) -> set[str]:
        return set(self.facts)

    def expand(self, refs: Iterable[str]) -> set[str]:
        """Refs plus the evidence rows an aggregate fact summarises."""
        out: set[str] = set()
        for ref in refs:
            out.add(ref)
            out.update(self.facts.get(ref, {}).get("members", []))
        return out

    def canonical(self) -> str:
        return json.dumps(self.facts, sort_keys=True, separators=(",", ":"), default=str)

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()

    def numbers(self) -> list[float]:
        found: list[float] = []

        def walk(v: Any) -> None:
            if isinstance(v, bool):
                return
            if isinstance(v, (int, float)):
                if math.isfinite(v):
                    found.append(float(v))
            elif isinstance(v, dict):
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)

        for fact in self.facts.values():
            walk({k: v for k, v in fact.items() if k != "members"})
        return found

    def timestamps(self) -> set[str]:
        out: set[str] = set()

        def walk(v: Any) -> None:
            if isinstance(v, str) and _iso(v):
                out.add(v)
            elif isinstance(v, dict):
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)

        walk(self.facts)
        return out

    def prompt_json(self) -> str:
        return json.dumps(self.facts, sort_keys=True, indent=1, default=str)

    def verify_clean(self, text: str) -> None:
        """Raise if a forbidden raw value, an e-mail, an IP or a key pattern is present in ``text``."""
        low = text.lower()
        for raw in self.forbidden:
            if len(raw) >= 3 and raw.lower() in low:
                raise SanitizationError("a forbidden identifier is present")
        if find_sensitive_pattern(text):
            raise SanitizationError("a sensitive pattern is present")


_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"https?://", re.I),
    "key": re.compile(r"\b(?:xkeysib|xsmtpsib)-[A-Za-z0-9-]{6,}|\bAKIA[0-9A-Z]{16}\b|\bBearer\s+\S{8,}", re.I),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


def find_sensitive_pattern(text: str) -> Optional[str]:
    for name, pat in _PATTERNS.items():
        if pat.search(text):
            return name
    return None


def strip_refs(text: str) -> str:
    return _ID_REF.sub(" ", text)


def _alert_fact(alert: Alert) -> dict[str, Any]:
    m = alert.metrics or {}
    metrics: dict[str, Any] = {}
    for key in _ALERT_NUMBERS:
        n = _clean_num(m.get(key))
        if n is not None:
            metrics[key] = n
    for key in _ALERT_TOKENS:
        v = m.get(key)
        if isinstance(v, str) and _TOKEN.match(v):
            metrics[key] = v
    for key in _ALERT_TIMES:
        t = _iso(m.get(key))
        if t:
            metrics[key] = t
    regions = m.get("failure_regions")
    if isinstance(regions, list):
        ok = [r for r in regions[:5] if isinstance(r, str) and _TOKEN.match(r)]
        if ok:
            metrics["failure_regions"] = ok
    if isinstance(m.get("unfamiliar_region"), bool):
        metrics["unfamiliar_region"] = m["unfamiliar_region"]
    return {"type": "alert", "ts": alert.ts.isoformat(), "severity": alert.severity, "kind": alert.kind,
            "score": _clean_num(alert.score) if alert.kind in ("error_rate", "latency_degradation") else None,
            "metrics": metrics}


def _evidence_fact(row: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    rec = row.get("record") or {}
    fact: dict[str, Any] = {"type": "evidence", "ts": _iso(row.get("ts")) or _iso(rec.get("ts"))}
    for key in _EVIDENCE_NUMBERS:
        n = _clean_num(rec.get(key))
        if n is not None:
            fact[key] = n
    for key in _EVIDENCE_BOOLS:
        if isinstance(rec.get(key), bool):
            fact[key] = rec[key]
    for key in _EVIDENCE_ENUMS:
        v = rec.get(key)
        if isinstance(v, str) and _ENUM.match(v):
            fact["record_type" if key == "type" else key] = v
    for key in _EVIDENCE_TOKENS:
        v = rec.get(key)
        if isinstance(v, str) and _TOKEN.match(v):
            fact[key] = v
    raw_sensitive = [str(rec[k]) for k in _SENSITIVE_RECORD_KEYS if rec.get(k) not in (None, "")]
    return fact, raw_sensitive


def _aggregate(evidence_facts: dict[str, dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not evidence_facts:
        return None
    agg: dict[str, Any] = {"type": "aggregate", "of": "evidence", "n": len(evidence_facts),
                           "members": list(evidence_facts)}
    errors = sum(1 for f in evidence_facts.values() if f.get("is_error") is True)
    s5 = sum(1 for f in evidence_facts.values() if isinstance(f.get("status"), int) and f["status"] >= 500)
    s4 = sum(1 for f in evidence_facts.values() if isinstance(f.get("status"), int) and 400 <= f["status"] < 500)
    lat = [f["latency_ms"] for f in evidence_facts.values() if isinstance(f.get("latency_ms"), (int, float))]
    if any("status" in f for f in evidence_facts.values()):
        agg.update(error_n=errors, status_5xx_n=s5, status_4xx_n=s4)
    if lat:
        agg["max_latency_ms"] = max(lat)
    for key in ("action", "outcome"):
        counts: dict[str, int] = {}
        for f in evidence_facts.values():
            if key in f:
                counts[f[key]] = counts.get(f[key], 0) + 1
        if counts:
            agg[f"{key}_counts"] = dict(sorted(counts.items()))
    mism = sum(1 for f in evidence_facts.values() if f.get("region_mismatch") is True)
    if any("region_mismatch" in f for f in evidence_facts.values()):
        agg["region_mismatch_n"] = mism
    return agg


def build_bundle(
    config: AppConfig,
    incident: Incident,
    alerts: list[Alert],
    evidence: list[dict[str, Any]],
    events: list[IncidentEvent],
    *,
    redactor: Optional[Redactor] = None,
    max_alerts: int = 8,
    max_evidence: int = 15,
    max_events: int = 10,
    related: Optional[list[dict[str, Any]]] = None,
) -> Bundle:
    if incident.id is None:
        raise SanitizationError("incident has no id")
    forbidden: list[str] = []
    aliases: dict[str, str] = {}

    def alias_for(raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        forbidden.append(str(raw))
        if raw not in aliases:
            aliases[raw] = f"actor-{len(aliases) + 1}"
        return aliases[raw]

    facts: dict[str, dict[str, Any]] = {}
    actor = alias_for(incident.user_id)
    facts[f"inc:{incident.id}"] = {
        "type": "incident", "kind": incident.kind, "title": KIND_TITLE.get(incident.kind, incident.kind),
        "service": incident.service if incident.service and _TOKEN.match(incident.service) else None,
        "actor": actor, "state": incident.state, "peak_severity": incident.peak_severity,
        "alert_count": incident.alert_count, "opened_at": incident.opened_at.isoformat(),
        "last_seen_at": incident.last_seen_at.isoformat() if incident.last_seen_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "risk_trend": incident.risk_trend, "reopen_count": incident.reopen_count,
        "evidence_count": incident.evidence_count,
        "peak_score": _clean_num(incident.peak_score) if incident.kind in ("error_rate", "latency_degradation") else None,
    }
    facts[f"rule:{incident.kind}"] = {"type": "rule", "kind": incident.kind,
                                      "thresholds": _numeric_only(detection_rule(config, incident.kind))}

    svc_cfg = config.services.get(incident.service) if incident.service else None
    if svc_cfg is not None:
        facts[f"svc:{incident.service}"] = {
            "type": "service", "criticality": _clean_num(svc_cfg.criticality),
            "depends_on": [d for d in svc_cfg.depends_on if isinstance(d, str) and _TOKEN.match(d)][:6],
        }

    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    stored = [a for a in alerts if a.id is not None]
    for a in stored:
        alias_for(a.user_id)
    newest = sorted(stored, key=lambda a: (a.ts, a.id or 0), reverse=True)[:max_alerts]
    peak = max(stored, key=lambda a: (rank[a.severity], a.ts, a.id or 0), default=None)
    chosen = {a.id: a for a in newest}
    if peak is not None:
        chosen[peak.id] = peak
    for a in sorted(chosen.values(), key=lambda a: (a.ts, a.id or 0)):
        facts[f"alert:{a.id}"] = _alert_fact(a)

    ev_facts: dict[str, dict[str, Any]] = {}
    for row in evidence[:max_evidence]:
        if not isinstance(row.get("id"), int):
            continue
        fact, sensitive = _evidence_fact(row)
        forbidden.extend(sensitive)
        rec = row.get("record") or {}
        if rec.get("user_id") and rec["user_id"] not in aliases:
            alias_for(rec["user_id"])
        ev_facts[f"ev:{row['id']}"] = fact
    facts.update(ev_facts)
    agg = _aggregate(ev_facts)
    if agg:
        facts["agg:ev"] = agg

    for e in sorted(events, key=lambda e: (e.ts, e.id or 0), reverse=True)[:max_events]:
        if e.id is not None:
            facts[f"iev:{e.id}"] = {"type": "incident_event", "ts": e.ts.isoformat(), "event_type": e.event_type,
                                    "severity": e.severity}

    # Deterministic related-incident matches (already computed; the model may only explain them). Allow-listed
    # labels and numbers: no actor, fingerprint or text.
    for r in (related or [])[:5]:
        if not isinstance(r.get("id"), int) or r["id"] == incident.id:
            continue
        facts[f"rel:{r['id']}"] = {
            "type": "related_incident", "kind": r.get("kind"), "title": KIND_TITLE.get(r.get("kind"), r.get("kind")),
            "service": r["service"] if r.get("service") and _TOKEN.match(r["service"]) else None,
            "state": r.get("state"), "peak_severity": r.get("severity"), "score": _clean_num(r.get("score")),
            "signals": [x for x in r.get("signals", []) if isinstance(x, str) and _TOKEN.match(x)][:6],
            "basis": "deterministic_match",
        }

    bundle = Bundle(
        incident_id=incident.id, facts=facts, forbidden=sorted(set(forbidden), key=len, reverse=True),
        aliases=set(aliases.values()), evidence_quality=evidence_quality(incident.evidence_count),
        truncated=len(evidence) > max_evidence,
    )
    # Defence in depth: nothing forbidden may survive in the serialised facts. A coincidence
    # (an id that equals a service name) trips this and the model path falls back.
    return bundle
