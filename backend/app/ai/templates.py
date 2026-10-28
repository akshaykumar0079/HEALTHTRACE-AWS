"""The deterministic insight: always available, no model, no network.

Every sentence is built from fields of the sanitised bundle and carries the ids
of the facts it came from. Hypotheses are written as possibilities (always with a
benign or unconfirmed alternative where one exists), capped in confidence, and
labelled by the code. Nothing here is executed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from app.ai.sanitize import Bundle
from app.ai.schema import CONFIDENCE_RANK, Claim, Confidence, EvidenceRef, Hypothesis, Insight, PROMPT_VERSION

_QUALITY_CAP: dict[str, Confidence] = {"none": "low", "limited": "low", "moderate": "medium", "strong": "medium"}


def confidence_cap(quality: str) -> Confidence:
    """Never 'high': stored evidence can support a possibility, not prove a cause."""
    return _QUALITY_CAP.get(quality, "low")


def cap_confidence(value: Confidence, quality: str) -> Confidence:
    cap = confidence_cap(quality)
    return value if CONFIDENCE_RANK[value] <= CONFIDENCE_RANK[cap] else cap


def _pct(v: Optional[float]) -> str:
    return f"{round(v * 100)}%"


def _get(d: dict[str, Any], *path: str) -> Any:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _latest_alert(bundle: Bundle) -> Optional[tuple[str, dict[str, Any]]]:
    alerts = [(k, v) for k, v in bundle.facts.items() if v.get("type") == "alert"]
    if not alerts:
        return None
    return max(alerts, key=lambda kv: (kv[1]["ts"], kv[0]))


def _peak_alert(bundle: Bundle) -> Optional[tuple[str, dict[str, Any]]]:
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    alerts = [(k, v) for k, v in bundle.facts.items() if v.get("type") == "alert"]
    if not alerts:
        return None
    return max(alerts, key=lambda kv: (rank[kv[1]["severity"]], kv[1]["ts"], kv[0]))


def _refs(*ids: Optional[str]) -> list[str]:
    seen: list[str] = []
    for i in ids:
        if i and i not in seen:
            seen.append(i)
    return seen


def _evidence_sentence(bundle: Bundle) -> tuple[str, list[str]]:
    agg = bundle.facts.get("agg:ev")
    if not agg:
        return "No evidence records are stored for this incident.", []
    n = agg["n"]
    parts = [f"{n} stored evidence record{'s' if n != 1 else ''} reviewed"]
    if "status_5xx_n" in agg:
        parts.append(f"{agg['status_5xx_n']} with a 5xx status, {agg['error_n']} flagged as errors")
    if "max_latency_ms" in agg:
        parts.append(f"slowest {round(agg['max_latency_ms'])} ms")
    if agg.get("action_counts"):
        parts.append("actions " + ", ".join(f"{k} x{v}" for k, v in agg["action_counts"].items()))
    if agg.get("outcome_counts"):
        parts.append("outcomes " + ", ".join(f"{k} x{v}" for k, v in agg["outcome_counts"].items()))
    if "region_mismatch_n" in agg:
        parts.append(f"{agg['region_mismatch_n']} cross-region")
    suffix = " (older records omitted)" if bundle.truncated else ""
    return "; ".join(parts) + suffix + ".", ["agg:ev"]


def _incident(bundle: Bundle) -> tuple[str, dict[str, Any]]:
    return next((k, v) for k, v in bundle.facts.items() if v.get("type") == "incident")


def _service_fact(bundle: Bundle) -> Optional[tuple[str, dict[str, Any]]]:
    return next(((k, v) for k, v in bundle.facts.items() if v.get("type") == "service"), None)


def build_deterministic(bundle: Bundle) -> Insight:
    inc_id, inc = _incident(bundle)
    kind = inc["kind"]
    latest = _latest_alert(bundle)
    peak = _peak_alert(bundle)
    la_id, la = latest if latest else (None, {})
    m = la.get("metrics", {}) if la else {}
    rule_id = f"rule:{kind}"
    th = bundle.facts[rule_id]["thresholds"]
    who = inc.get("actor") or inc.get("service") or "the subject"
    where = f" on {inc['service']}" if inc.get("service") else ""
    head = f"{inc['title']}{where}: {inc['alert_count']} alert{'s' if inc['alert_count'] != 1 else ''} since {inc['opened_at']}, state {inc['state']}, peak severity {inc['peak_severity']}."
    detail = ""
    rationale = f"Peak severity is {inc['peak_severity']}."
    s_refs = _refs(inc_id, la_id)
    r_refs = _refs(inc_id, rule_id, peak[0] if peak else None)
    hyps: list[Hypothesis] = []
    steps: list[Claim] = []
    quality = bundle.evidence_quality
    ev_text, ev_refs = _evidence_sentence(bundle)
    agg = bundle.facts.get("agg:ev", {})
    svc = _service_fact(bundle)
    deps = svc[1].get("depends_on", []) if svc else []

    def H(text: str, refs: list[str], conf: Confidence = "low") -> None:
        hyps.append(Hypothesis(text=text, evidence_refs=refs, confidence=cap_confidence(conf, quality)))

    def S(text: str, refs: list[str]) -> None:
        steps.append(Claim(text=text, evidence_refs=refs))

    if kind == "error_rate":
        if "error_rate" in m:
            detail = f" Latest stored window: error rate {_pct(m['error_rate'])}"
            if "errors" in m and "total" in m:
                detail += f" ({m['errors']} of {m['total']} requests)"
            if "baseline_mean" in m:
                detail += f" against a learned baseline of {_pct(m['baseline_mean'])}"
            detail += "."
        rationale = (
            f"Peak severity {inc['peak_severity']}. The detector alerts when the error rate is at least "
            f"{th.get('z_threshold')} standard deviations above this service's baseline, with at least "
            f"{th.get('min_errors')} errors and a rate of at least {_pct(th.get('min_rate', 0))}. "
            "Severity combines how far the rate deviates with the service's criticality and the patients affected.")
        if agg.get("status_5xx_n") and agg["status_5xx_n"] * 2 >= agg["n"]:
            H("The failures are mostly server-side (5xx) in the stored records, which would point at the service or "
              "its dependencies rather than at bad client requests.", _refs("agg:ev", inc_id),
              "medium")
        if deps:
            H(f"An upstream dependency of {inc['service']} ({', '.join(deps)}) may be failing, because this service "
              "depends on them. The stored evidence does not show which one, if any.", _refs(svc[0], inc_id, la_id))
        H("A recent change or a load increase on this service could produce a rate this far above baseline. "
          "The stored evidence cannot confirm or rule this out.", _refs(inc_id, la_id))
        S("Review the stored evidence records listed for this incident and confirm which status codes dominate.",
          _refs("agg:ev") or _refs(inc_id))
        if deps:
            S(f"Check the health of {inc['service']}'s dependencies ({', '.join(deps)}).", _refs(svc[0]))
        S(f"Compare the onset time {inc['opened_at']} with recent deployments or configuration changes.", _refs(inc_id))
    elif kind == "latency_degradation":
        if "p95_latency_ms" in m:
            detail = f" Latest stored window: p95 latency {round(m['p95_latency_ms'])} ms"
            if "baseline_mean" in m:
                detail += f" against a learned baseline of {round(m['baseline_mean'])} ms"
            detail += "."
        rationale = (
            f"Peak severity {inc['peak_severity']}. The detector alerts when p95 latency is at least "
            f"{th.get('z_threshold')} standard deviations above this service's baseline. Severity combines the "
            "deviation with the service's criticality and the patients affected.")
        if deps:
            H(f"A slow upstream dependency of {inc['service']} ({', '.join(deps)}) may be adding latency. The stored "
              "evidence does not show which one, if any.", _refs(svc[0], inc_id, la_id))
        H("Increased load or a recent change on this service could raise p95 latency without raising errors. "
          "The stored evidence cannot confirm or rule this out.", _refs(inc_id, la_id))
        S("Look at the slowest stored evidence records for this incident and see whether one operation dominates.",
          _refs("agg:ev") or _refs(inc_id))
        if deps:
            S(f"Check the latency of {inc['service']}'s dependencies ({', '.join(deps)}).", _refs(svc[0]))
        S(f"Compare the onset time {inc['opened_at']} with recent deployments or traffic changes.", _refs(inc_id))
    elif kind == "auth_suspicious_login":
        if "failures" in m:
            detail = f" {m['failures']} failed logins were followed by a successful login (threshold {m.get('failure_threshold', th.get('failure_threshold'))})."
        if m.get("unfamiliar_region") is True and m.get("success_region"):
            detail += f" The success came from region {m['success_region']}, which is not the usual region for this user."
        rationale = (
            f"Peak severity {inc['peak_severity']}. The rule alerts when a success follows at least "
            f"{th.get('failure_threshold')} failed logins within the window; severity rises for an unfamiliar region "
            f"or {th.get('failure_threshold', 0) * th.get('high_failure_multiple', 1)} or more failures.")
        H("Repeated guessing of this account's password may have succeeded.", _refs(inc_id, la_id),
          "medium" if m.get("unfamiliar_region") else "low")
        if m.get("unfamiliar_region") is True:
            H("The account may have been used from an unfamiliar location.", _refs(inc_id, la_id))
        H("A legitimate user mistyping a password several times before succeeding is also consistent with this "
          "pattern, particularly if the region is the usual one.", _refs(inc_id, la_id))
        S("Confirm with the account owner whether the successful login was theirs.", _refs(inc_id))
        S("Review the stored authentication evidence records for this incident, in time order.", _refs("agg:ev") or _refs(inc_id))
        S("If the login was not the owner's, follow your organisation's credential-reset procedure.", _refs(inc_id))
    else:  # HIPAA access rules
        hip = th.get("hipaa", {})
        if kind == "hipaa_bulk_access" and "distinct_patients" in m:
            detail = f" {who} accessed {m['distinct_patients']} distinct patients"
            if "multiplier" in m:
                detail += f", {m['multiplier']} times their own baseline"
            detail += "."
            rationale = (f"Peak severity {inc['peak_severity']}. The rule alerts when access exceeds "
                         f"{hip.get('bulk_multiplier_high')} times the actor's baseline and becomes critical above "
                         f"{hip.get('bulk_multiplier_critical')} times.")
        elif kind == "hipaa_bulk_export" and "records" in m:
            detail = f" {who} exported {m['records']} records."
            rationale = (f"Peak severity {inc['peak_severity']}. The rule alerts at {hip.get('export_min_threshold')} or "
                         f"more exported records and becomes critical above {hip.get('export_critical_records')}.")
        elif kind == "hipaa_off_hours" and "records" in m:
            detail = f" {who} accessed {m['records']} records outside the configured working hours."
            rationale = (f"Peak severity {inc['peak_severity']}. The rule alerts on record access outside working hours "
                         f"and rises to HIGH above {hip.get('off_hours_high_records')} records.")
        elif kind == "hipaa_region_mismatch" and "distinct_patients" in m:
            detail = f" {who} accessed {m['distinct_patients']} patients registered in a different region."
            rationale = (f"Peak severity {inc['peak_severity']}. The rule alerts on cross-region access and rises to "
                         f"HIGH above {hip.get('region_mismatch_medium_max')} patients.")
        else:
            rationale = f"Peak severity {inc['peak_severity']}, set by the {kind} rule."
        H("Planned batch work such as an audit, a report or a data migration could explain this volume. "
          "The stored evidence does not say why the access happened.", _refs(inc_id, la_id))
        H("Misuse of the account or of the access it was granted is also possible. The stored evidence cannot "
          "distinguish this from legitimate work.", _refs(inc_id, la_id))
        S("Ask the actor's manager or the privacy officer whether this access was expected.", _refs(inc_id))
        S("Review the stored audit evidence records for this incident, in time order.", _refs("agg:ev") or _refs(inc_id))

    rel = sorted(k for k, v in bundle.facts.items() if v.get("type") == "related_incident")
    if rel and len(steps) < 5:
        top = rel[0]
        S(f"Look at incident {top.split(':', 1)[1]}, a deterministic match (same service, type or timing). It may or "
          "may not share a cause; compare the two before treating them as one problem.", _refs(inc_id, top))
    S("Acknowledge the incident in the dashboard once someone owns it; resolve it when the pattern ends.",
      _refs(inc_id))

    no_alerts = latest is None
    insufficient = no_alerts and not agg
    summary_text = head + detail + " " + ev_text
    if no_alerts:
        summary_text += " No stored alert details are available, so the detection values are unknown."
    overall = cap_confidence("medium", quality)
    if insufficient:
        hyps = []
        overall = "low"
    insight = Insight(
        incident_id=bundle.incident_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by="deterministic",
        prompt_version=PROMPT_VERSION,
        bundle_hash=bundle.hash,
        summary=Claim(text=summary_text, evidence_refs=_refs(*s_refs, *ev_refs)),
        severity_rationale=Claim(text=rationale, evidence_refs=r_refs),
        hypotheses=hyps[:4],
        next_steps=steps[:6],
        overall_confidence=overall,
        evidence_quality=quality,
        insufficient_evidence=insufficient,
    )
    insight.evidence = evidence_list(bundle, insight)
    return insight


def label_for(fact_id: str, fact: dict[str, Any]) -> str:
    t = fact.get("type")
    if t == "incident":
        return f"Incident {fact_id.split(':', 1)[1]}: {fact.get('title')}"
    if t == "alert":
        return f"Alert {fact_id.split(':', 1)[1]} ({fact.get('severity')}, {fact.get('ts')})"
    if t == "evidence":
        return f"Evidence record {fact_id.split(':', 1)[1]}"
    if t == "rule":
        return f"Detection rule: {fact.get('kind')}"
    if t == "aggregate":
        return f"Summary of {fact.get('n')} stored evidence records"
    if t == "incident_event":
        return f"Incident event {fact_id.split(':', 1)[1]} ({fact.get('event_type')})"
    if t == "service":
        return "Service configuration"
    if t == "related_incident":
        return f"Possibly related incident {fact_id.split(':', 1)[1]} (deterministic match, not proof of a shared cause)"
    return fact_id


def evidence_list(bundle: Bundle, insight: Insight) -> list[EvidenceRef]:
    cited: list[str] = []
    claims = [insight.summary, insight.severity_rationale, *insight.hypotheses, *insight.next_steps]
    for c in claims:
        for ref in c.evidence_refs:
            for r in (ref, *bundle.facts.get(ref, {}).get("members", [])):
                if r in bundle.facts and r not in cited:
                    cited.append(r)
    return [EvidenceRef(id=r, type=bundle.facts[r]["type"], label=label_for(r, bundle.facts[r])) for r in cited]
