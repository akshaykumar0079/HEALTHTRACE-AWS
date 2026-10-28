"""Phase 1 - AI incident intelligence (docs/ai-incident-intelligence.md).

Synthetic data only. No real model, e-mail, AWS or network is used: the model is a fake
provider object, and the Ollama client talks to a throw-away HTTP server on 127.0.0.1.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

import pytest
from fastapi.testclient import TestClient

from app.ai.prompt import build_prompt
from app.ai.provider import OllamaProvider, ProviderError, build_provider, parse_loopback_url
from app.ai.sanitize import Bundle, SanitizationError, build_bundle, find_sensitive_pattern
from app.ai.schema import Insight
from app.ai.service import InsightService, TooSoon
from app.ai.templates import build_deterministic
from app.ai.validate import claim_problem, validate_model_output
from app.config import Settings, load_config
from app.main import create_app
from app.models import Alert, Anomaly, Incident, IncidentEvent
from app.privacy.redaction import Redactor
from app.store.db import Store
from app.store.migrations import LATEST_VERSION, applied_versions

T0 = datetime(2026, 10, 20, 9, 0, 0, tzinfo=timezone.utc)
CFG = load_config()

# Canary values: if any of these ever reaches a bundle, a prompt, a stored insight or an API reply, a test fails.
USER = "dr.alice.canary"
PATIENT = "PAT-CANARY-77"
REQ = "req-canary-9"
IP = "10.77.88.99"
MSG = "SSN 123-45-6789 for dr.alice.canary from 10.77.88.99"
CANARIES = (USER, PATIENT, REQ, IP, "123-45-6789")


# -- builders -----------------------------------------------------------------------------------------------


def make_incident(kind="error_rate", *, id=7, service: Optional[str] = "claims", user: Optional[str] = None,
                  severity="HIGH", evidence_count=6, alert_count=3, state="OPEN") -> Incident:
    return Incident(id=id, fingerprint=f"{kind}:{user or service}", kind=kind, service=None if user else service,
                    user_id=user, state=state, peak_severity=severity, alert_count=alert_count, opened_at=T0,
                    last_seen_at=T0 + timedelta(minutes=2), peak_score=0.61, latest_score=0.58,
                    risk_trend="rising", evidence_count=evidence_count)


METRICS = {
    "error_rate": {"service": "claims", "total": 120, "errors": 44, "error_rate": 0.3667, "p95_latency_ms": 900.0,
                   "urgent_errors": 5, "affected_patients_urgent": 3, "affected_patients_routine": 4,
                   "baseline_mean": 0.02, "baseline_std": 0.01, "patient_id": PATIENT},
    "latency_degradation": {"total": 90, "errors": 1, "error_rate": 0.01, "p95_latency_ms": 2400.0,
                            "baseline_mean": 300.0, "baseline_std": 40.0},
    "auth_suspicious_login": {"failures": 6, "failure_threshold": 5, "failure_regions": ["eu-west", "ap-south"],
                              "success_region": "ap-south", "user_region": "us-east", "unfamiliar_region": True,
                              "first_failure_ts": T0.isoformat(), "last_failure_ts": (T0 + timedelta(minutes=1)).isoformat(),
                              "method": "password", "source_ip": IP},
    "hipaa_bulk_access": {"multiplier": 7.5, "distinct_patients": 150},
    "hipaa_bulk_export": {"records": 400},
    "hipaa_off_hours": {"records": 30},
    "hipaa_region_mismatch": {"distinct_patients": 12},
}


def make_alert(kind="error_rate", *, id=11, user: Optional[str] = None, severity="HIGH", ts=T0, incident_id=7) -> Alert:
    return Alert(id=id, ts=ts, kind=kind, service=None if user else "claims", user_id=user, severity=severity,
                 score=0.61, explanation=f"user {user or 'x'} did something. {MSG}", metrics=dict(METRICS[kind]),
                 incident_id=incident_id)


def make_evidence(kind="error_rate", n=4) -> list[dict]:
    rows = []
    for i in range(n):
        if kind in ("error_rate", "latency_degradation"):
            rec = {"type": "app", "service": "claims", "status": 503 if i % 2 == 0 else 200,
                   "latency_ms": 800 + i, "is_error": i % 2 == 0, "request_id": REQ, "patient_id": PATIENT,
                   "msg": MSG, "level": "ERROR", "priority": "URGENT", "unlisted_field": "SECRET-NOTE"}
        elif kind == "auth_suspicious_login":
            rec = {"type": "auth", "user_id": USER, "outcome": "failure", "source_region": "eu-west",
                   "user_region": "us-east", "source_ip": IP, "msg": MSG, "method": "password"}
        else:
            rec = {"type": "audit", "user_id": USER, "role": "clinician", "action": "EXPORT_RECORDS",
                   "patient_id": PATIENT, "patient_region": "eu-west", "user_region": "us-east",
                   "region_mismatch": True, "msg": MSG}
        rows.append({"id": 100 + i, "alert_id": 11, "ts": (T0 + timedelta(seconds=i)).isoformat(), "record": rec})
    return rows


def make_events(incident_id=7) -> list[IncidentEvent]:
    return [IncidentEvent(id=1, incident_id=incident_id, ts=T0, event_type="opened", severity="HIGH",
                          detail=f"detail naming {USER}")]


def bundle_for(kind="error_rate", **kw) -> Bundle:
    user = USER if kind.startswith(("hipaa", "auth")) else None
    inc = make_incident(kind, user=user, **kw)
    return build_bundle(CFG, inc, [make_alert(kind, user=user)], make_evidence(kind), make_events(),
                        redactor=Redactor.build())


ALL_KINDS = list(METRICS)


def good_output(bundle: Bundle, **over) -> dict:
    inc_id = next(k for k, v in bundle.facts.items() if v["type"] == "incident")
    alert_id = next(k for k, v in bundle.facts.items() if v["type"] == "alert")
    out = {
        "summary": {"text": f"The error rate reached 37% in the latest window, with 44 of 120 requests failing.",
                    "evidence_refs": [inc_id, alert_id]},
        "severity_rationale": {"text": "Peak severity is HIGH because the rate is well above its baseline of 2%.",
                               "evidence_refs": [inc_id, alert_id]},
        "hypotheses": [{"text": "A failing upstream dependency could be causing the errors.",
                        "evidence_refs": [alert_id], "confidence": "medium"}],
        "next_steps": [{"text": "Review the stored evidence records and confirm which status codes dominate.",
                        "evidence_refs": ["agg:ev"]}],
        "insufficient_evidence": False,
    }
    out.update(over)
    return out


# -- sanitisation ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_bundle_never_contains_raw_identifiers_or_free_text(kind):
    b = bundle_for(kind)
    text = b.canonical() + build_prompt(b)[1]
    for canary in CANARIES:
        assert canary not in text, canary
    assert "SECRET-NOTE" not in text and "unlisted_field" not in text
    assert "did something" not in text                       # the alert explanation names the user
    assert find_sensitive_pattern(text) is None
    b.verify_clean(build_prompt(b)[0] + build_prompt(b)[1])   # must not raise


def test_actors_become_aliases_in_both_modes():
    b = bundle_for("hipaa_bulk_access")
    inc = next(v for v in b.facts.values() if v["type"] == "incident")
    assert inc["actor"] == "actor-1" and b.aliases == {"actor-1"}
    # a different actor in the same bundle gets another alias; none is derived from the identifier
    other = make_evidence("hipaa_bulk_access")
    other[0]["record"]["user_id"] = "someone.else"
    b2 = build_bundle(CFG, make_incident("hipaa_bulk_access", user=USER), [make_alert("hipaa_bulk_access", user=USER)],
                      other, [], redactor=Redactor.build())
    assert b2.aliases == {"actor-1", "actor-2"} and "someone.else" in b2.forbidden


def test_only_allow_listed_evidence_fields_and_valid_values_survive():
    rows = make_evidence("hipaa_bulk_export", 1)
    rows[0]["record"]["action"] = "DROP TABLE;--"            # not an enum-looking value
    rows[0]["record"]["patient_region"] = "eu west <script>"
    b = build_bundle(CFG, make_incident("hipaa_bulk_export", user=USER), [make_alert("hipaa_bulk_export", user=USER)],
                     rows, [], redactor=Redactor.build())
    ev = b.facts["ev:100"]
    assert "action" not in ev and "patient_region" not in ev and "msg" not in ev and "user_id" not in ev
    assert ev["role"] == "clinician" and ev["region_mismatch"] is True


def test_verify_clean_blocks_forbidden_values_and_patterns():
    b = bundle_for("auth_suspicious_login")
    for bad in (f"the user {USER} logged in", f"from {IP}", "mail bob@example.org", "see https://x.example",
                "key xkeysib-abcdef123456", "ssn 123-45-6789"):
        with pytest.raises(SanitizationError):
            b.verify_clean(bad)
    b.verify_clean("the account actor-1 had failures")


def test_evidence_beyond_the_limit_is_marked_truncated_and_never_exceeds_it():
    inc = make_incident()
    b = build_bundle(CFG, inc, [make_alert()], make_evidence(n=30), [], redactor=Redactor.build(), max_evidence=5)
    assert len([k for k in b.facts if k.startswith("ev:")]) == 5 and b.truncated


# -- deterministic summaries -----------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_deterministic_insight_is_complete_cited_and_consistent(kind):
    b = bundle_for(kind)
    ins = build_deterministic(b)
    assert ins.generated_by == "deterministic" and ins.status == "ok" and ins.executed_actions == []
    assert ins.summary.text and ins.severity_rationale.text and ins.next_steps and ins.hypotheses
    known, times = b.numbers(), b.timestamps()
    for claim in [ins.summary, ins.severity_rationale, *ins.hypotheses, *ins.next_steps]:
        assert claim.evidence_refs, claim.text
        assert set(claim.evidence_refs) <= b.ids, claim.text
        # the template obeys the same rules a model answer must obey
        assert claim_problem(claim.text, claim.evidence_refs, b, known, times) is None, (kind, claim.text)
    assert all(h.label == "hypothesis" and h.confidence in ("low", "medium") for h in ins.hypotheses)
    assert {e.id for e in ins.evidence} <= b.ids
    for canary in CANARIES:
        assert canary not in ins.model_dump_json()


def test_error_rate_summary_uses_real_numbers():
    ins = build_deterministic(bundle_for("error_rate"))
    assert "37%" in ins.summary.text and "44 of 120" in ins.summary.text and "2%" in ins.summary.text
    assert "2 stored" not in ins.summary.text
    assert "4 stored evidence records" in ins.summary.text and "2 with a 5xx status" in ins.summary.text
    assert any("dependency" in h.text for h in ins.hypotheses)      # claims -> depends_on from config


def test_hypotheses_include_a_benign_or_unconfirmed_alternative():
    for kind in ("hipaa_bulk_access", "auth_suspicious_login"):
        texts = " ".join(h.text for h in build_deterministic(bundle_for(kind)).hypotheses).lower()
        assert "legitimate" in texts or "planned" in texts
    err = " ".join(h.text for h in build_deterministic(bundle_for("error_rate")).hypotheses).lower()
    assert "cannot confirm" in err or "does not show" in err


def test_no_alerts_and_no_evidence_is_reported_as_insufficient():
    inc = make_incident(evidence_count=0)
    b = build_bundle(CFG, inc, [], [], [], redactor=Redactor.build())
    ins = build_deterministic(b)
    assert ins.insufficient_evidence is True and ins.hypotheses == [] and ins.overall_confidence == "low"
    assert "unknown" in ins.summary.text and "No evidence records are stored" in ins.summary.text


def test_confidence_is_capped_by_stored_evidence_and_never_high():
    low = build_deterministic(build_bundle(CFG, make_incident(evidence_count=0), [make_alert()], make_evidence(),
                                           [], redactor=Redactor.build()))
    strong = build_deterministic(build_bundle(CFG, make_incident(evidence_count=40), [make_alert()],
                                              make_evidence(), [], redactor=Redactor.build()))
    assert low.evidence_quality == "none" and {h.confidence for h in low.hypotheses} == {"low"}
    assert strong.evidence_quality == "strong" and strong.overall_confidence == "medium"
    assert all(h.confidence != "high" for h in strong.hypotheses)


def test_bundle_hash_changes_when_evidence_changes_and_is_stable_otherwise():
    assert bundle_for().hash == bundle_for().hash
    inc = make_incident()
    a = build_bundle(CFG, inc, [make_alert()], make_evidence(n=2), [], redactor=Redactor.build())
    b = build_bundle(CFG, inc, [make_alert()], make_evidence(n=3), [], redactor=Redactor.build())
    assert a.hash != b.hash


# -- model answer validation -------------------------------------------------------------------------------------


def run(b: Bundle, obj) -> "object":
    return validate_model_output(obj if isinstance(obj, str) else json.dumps(obj), b, model="test-model")


def test_good_model_answer_is_accepted_with_code_set_labels():
    b = bundle_for()
    v = run(b, good_output(b))
    assert v.insight is not None and v.insight.generated_by == "ollama" and v.insight.model == "test-model"
    h = v.insight.hypotheses[0]
    assert h.label == "hypothesis" and h.confidence in ("low", "medium")     # 'medium' was asked for, capped by evidence
    assert v.insight.executed_actions == [] and {e.id for e in v.insight.evidence} <= b.ids


def test_model_cannot_set_high_confidence_or_the_label():
    b = bundle_for(evidence_count=0)
    out = good_output(b)
    out["hypotheses"][0].update(confidence="high", label="fact")
    v = run(b, out)
    assert v.insight.hypotheses[0].confidence == "low" and v.insight.hypotheses[0].label == "hypothesis"


def test_unknown_evidence_id_is_rejected_for_the_summary_and_dropped_for_a_hypothesis():
    b = bundle_for()
    out = good_output(b)
    out["summary"]["evidence_refs"] = ["alert:99999"]
    assert run(b, out).insight is None
    out = good_output(b)
    out["hypotheses"][0]["evidence_refs"] = ["ev:424242"]
    v = run(b, out)
    assert v.insight is not None and v.insight.hypotheses == [] and v.dropped == 1


def test_claim_without_evidence_refs_is_not_accepted():
    b = bundle_for()
    out = good_output(b)
    out["summary"]["evidence_refs"] = []
    assert run(b, out).insight is None
    out = good_output(b)
    out["next_steps"][0].pop("evidence_refs")
    assert run(b, out).insight is None            # no step survives


def test_invented_numbers_and_times_are_rejected():
    b = bundle_for()
    out = good_output(b)
    out["summary"]["text"] = "The error rate reached 91% with 3000 failures."
    assert run(b, out).insight is None
    out = good_output(b)
    out["hypotheses"][0]["text"] = "A deployment at 2026-10-20T03:15:00+00:00 could be the cause."
    v = run(b, out)
    assert v.insight is not None and v.insight.hypotheses == []
    out = good_output(b)
    out["hypotheses"][0]["text"] = "Roughly 5xx responses from the service could be the cause."
    assert run(b, out).insight.hypotheses            # '5xx' is a status class, not a figure
    out = good_output(b)
    out["hypotheses"][0]["text"] = f"It began at {T0.isoformat()} and could be a dependency failure."
    assert run(b, out).insight.hypotheses            # a timestamp copied from the facts is allowed


@pytest.mark.parametrize("text", [
    f"The user {USER} caused this.", f"Traffic came from {IP}.", "Contact bob@example.org about it.",
    "The account actor-9 was involved.", "We have blocked the account.", "The user has been locked out.",
    "<script>alert(1)</script>", "See https://evil.example for details.",
])
def test_forbidden_content_and_claims_of_executed_actions_are_dropped(text):
    b = bundle_for("auth_suspicious_login")
    out = good_output(b)
    out["summary"]["text"] = "The account actor-1 had 6 failed logins."
    out["hypotheses"][0]["text"] = text
    v = run(b, out)
    assert v.insight is not None and v.insight.hypotheses == [] and v.dropped == 1


@pytest.mark.parametrize("raw", [
    "", "not json", "Sure! Here you go: {}", '{"summary": 1}', "[]", "{}", '{"summary": {"text":"x"}}',
    "x" * 20000,
])
def test_malformed_model_output_is_rejected(raw):
    assert run(bundle_for(), raw).insight is None


def test_trailing_text_after_the_json_is_rejected_but_a_code_fence_is_tolerated():
    b = bundle_for()
    body = json.dumps(good_output(b))
    assert run(b, body + " hope this helps").insight is None
    assert run(b, "```json\n" + body + "\n```").insight is not None


def test_insufficient_evidence_from_the_model_drops_hypotheses():
    b = bundle_for()
    v = run(b, good_output(b, insufficient_evidence=True))
    assert v.insight.insufficient_evidence is True and v.insight.hypotheses == [] and v.insight.overall_confidence == "low"


# -- provider -------------------------------------------------------------------------------------------------


def model_reply(prov) -> str:
    """A well-formed answer built from the ids that are actually in the prompt the fake model received."""
    import re

    text = prov.prompts[-1]
    inc, alert = re.search(r'"(inc:\d+)"', text).group(1), re.search(r'"(alert:\d+)"', text).group(1)
    return json.dumps(good_output(Bundle(0, {inc: {"type": "incident"}, alert: {"type": "alert"}, "agg:ev": {"type": "aggregate"}})))


class FakeProvider:
    name = "ollama"
    model = "fake-model"

    def __init__(self, reply=None, error: Optional[Exception] = None):
        self.reply, self.error, self.prompts = reply, error, []

    async def generate(self, system: str, prompt: str) -> str:
        self.prompts.append(system + "\n" + prompt)
        if self.error:
            raise self.error
        return self.reply(self) if callable(self.reply) else self.reply


class _Handler(BaseHTTPRequestHandler):
    mode = "ok"

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path != "/api/generate":
            self.send_response(404); self.end_headers(); return
        if self.mode == "500":
            self.send_response(500); self.end_headers(); return
        if self.mode == "huge":
            body = json.dumps({"response": "x" * 200_000}).encode()
        elif self.mode == "shape":
            body = b'{"other": 1}'
        else:
            body = json.dumps({"response": '{"hello": "world"}'}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def ollama_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


async def test_ollama_provider_round_trip_and_error_mapping(ollama_server):
    url = f"http://127.0.0.1:{ollama_server.server_port}"
    p = OllamaProvider(url, "m", timeout=5, max_response_bytes=10_000)
    _Handler.mode = "ok"
    assert json.loads(await p.generate("s", "p")) == {"hello": "world"}
    for mode in ("500", "huge", "shape"):
        _Handler.mode = mode
        with pytest.raises(ProviderError) as e:
            await p.generate("s", "p")
        assert e.value.code == "error"
    _Handler.mode = "ok"
    dead = OllamaProvider("http://127.0.0.1:1", "m", timeout=2)
    with pytest.raises(ProviderError) as e:
        await dead.generate("s", "p")
    assert e.value.code == "unavailable"


@pytest.mark.parametrize("url", ["http://example.com:11434", "https://127.0.0.1:11434", "http://192.168.1.5:11434",
                                 "http://user:pw@127.0.0.1:11434", "http://169.254.169.254"])
def test_only_a_loopback_http_url_is_accepted(url):
    with pytest.raises(ValueError):
        parse_loopback_url(url)
    assert parse_loopback_url("http://localhost:1234") == ("localhost", 1234)


def test_provider_is_off_unless_enabled_chosen_and_named(tmp_path):
    def s(**kw):
        return Settings(log_dir=tmp_path, db_path=tmp_path / "x.db", **kw)

    assert s().ai_enabled is False and s().ai_provider == "none"
    assert build_provider(s()) is None
    assert build_provider(s(ai_enabled=True)) is None                                # provider none
    assert build_provider(s(ai_enabled=True, ai_provider="ollama")) is None          # no model name
    assert build_provider(s(ai_provider="ollama", ai_model="m")) is None             # not enabled
    assert isinstance(build_provider(s(ai_enabled=True, ai_provider="ollama", ai_model="m")), OllamaProvider)


# -- service: fallback behaviour and storage ---------------------------------------------------------------------


@pytest.fixture()
async def env(tmp_path):
    store = Store(tmp_path / "ai.db", None)
    await store.connect()
    inc = make_incident()
    await store.upsert_incident(inc)
    await store.save_alert(make_alert())
    await store.save_evidence(7, 1, [r["record"] for r in make_evidence()])

    def service(provider=None, **kw):
        settings = Settings(log_dir=tmp_path, db_path=tmp_path / "ai.db", **kw)
        return InsightService(settings, CFG, store, Redactor.build(), provider)

    yield store, inc, service
    await store.close()


def _raw(svc_bundle: Bundle) -> str:
    return json.dumps(good_output(svc_bundle))


async def test_disabled_ai_returns_the_deterministic_insight_and_stores_nothing(env):
    store, inc, service = env
    svc = service()
    assert svc.status()["enabled"] is False and svc.status()["unavailable_reason"] == "ai_disabled"
    ins = await svc.generate(inc)
    assert (ins.generated_by, ins.status, ins.fallback_reason) == ("deterministic", "fallback", "ai_disabled")
    assert await store.latest_ai_insight(7) is None
    cur = await svc.current(inc)
    assert cur["insight"].generated_by == "deterministic" and cur["insight"].status == "ok"


async def test_enabled_without_a_model_falls_back(env):
    _, inc, service = env
    ins = await service().generate(inc)
    assert ins.fallback_reason == "ai_disabled"
    ins = await service(ai_enabled=True, ai_provider="ollama").generate(inc)
    assert ins.fallback_reason == "provider_not_configured" and ins.generated_by == "deterministic"


@pytest.mark.parametrize("error,reason", [(ProviderError("unavailable"), "provider_unavailable"),
                                          (ProviderError("error"), "provider_error"), (RuntimeError("boom"), "provider_error")])
async def test_provider_failures_fall_back_without_storing(env, error, reason):
    store, inc, service = env
    svc = service(FakeProvider(error=error), ai_enabled=True, ai_provider="ollama", ai_model="m")
    ins = await svc.generate(inc)
    assert ins.generated_by == "deterministic" and ins.status == "fallback" and ins.fallback_reason == reason
    assert ins.summary.text and ins.next_steps
    assert await store.latest_ai_insight(7) is None


@pytest.mark.parametrize("reply", ["I cannot help with that.", "{}", '{"summary": {"text": "x", "evidence_refs": ["inc:7"]}}'])
async def test_invalid_model_answers_fall_back_without_storing(env, reply):
    store, inc, service = env
    svc = service(FakeProvider(reply=reply), ai_enabled=True, ai_provider="ollama", ai_model="m")
    ins = await svc.generate(inc)
    assert ins.fallback_reason == "invalid_response" and ins.generated_by == "deterministic"
    assert await store.latest_ai_insight(7) is None


async def test_valid_model_answer_is_stored_then_goes_stale_when_evidence_changes(env):
    store, inc, service = env
    prov = FakeProvider(reply=model_reply)
    svc = service(prov, ai_enabled=True, ai_provider="ollama", ai_model="m")
    ins = await svc.generate(inc)
    assert ins.generated_by == "ollama" and ins.status == "ok" and ins.fallback_reason is None
    cur = await svc.current(inc)
    assert cur["insight"].generated_by == "ollama" and cur["stale_ai_available"] is False
    await store.save_alert(make_alert(id=12, ts=T0 + timedelta(minutes=5), severity="CRITICAL"))
    cur = await svc.current(inc)
    assert cur["insight"].generated_by == "deterministic" and cur["stale_ai_available"] is True


async def test_nothing_sensitive_reaches_the_model_and_the_stored_insight_is_clean(env):
    store, inc, service = env
    prov = FakeProvider(reply=model_reply)
    svc = service(prov, ai_enabled=True, ai_provider="ollama", ai_model="m")
    await svc.generate(inc)
    sent = "\n".join(prov.prompts)
    assert "FACTS" in sent and "inc:7" in sent
    for canary in CANARIES:
        assert canary not in sent, canary
    assert "SECRET-NOTE" not in sent and "did something" not in sent
    rows = await (await store.conn.execute("SELECT payload_json FROM ai_insights")).fetchall()
    assert rows and not any(c in r[0] for r in rows for c in CANARIES)


async def test_oversized_prompt_shrinks_evidence_then_falls_back(env):
    _, inc, service = env
    prov = FakeProvider(reply=model_reply)
    svc = service(prov, ai_enabled=True, ai_provider="ollama", ai_model="m", ai_max_prompt_chars=300)
    ins = await svc.generate(inc)
    assert ins.fallback_reason == "prompt_too_large" and prov.prompts == []


async def test_a_prompt_that_would_contain_a_forbidden_value_is_never_sent(env, monkeypatch):
    _, inc, service = env
    import app.ai.service as mod

    real = mod.build_prompt
    monkeypatch.setattr(mod, "build_prompt", lambda b: (real(b)[0], real(b)[1] + f"\nleak: {USER} {IP}"))
    prov = FakeProvider(reply="{}")
    ins = await service(prov, ai_enabled=True, ai_provider="ollama", ai_model="m").generate(inc)
    assert ins.fallback_reason == "sanitization_failed" and prov.prompts == []


async def test_repeat_requests_for_one_incident_are_rate_limited(env):
    _, inc, service = env
    svc = service(FakeProvider(error=ProviderError("unavailable")), ai_enabled=True, ai_provider="ollama", ai_model="m")
    await svc.generate(inc)
    with pytest.raises(TooSoon):
        await svc.generate(inc)


# -- API, audit, migration, retention, Brevo untouched -----------------------------------------------------------


def build_app(tmp_path: Path, **kw):
    kw.setdefault("aws_mode", "off")
    settings = Settings(log_dir=tmp_path / "logs", db_path=tmp_path / "m.db", control_file=tmp_path / "c.json",
                        static_dir=tmp_path / "nostatic", **kw)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    (settings.log_dir / "app.log").write_text("", encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("", encoding="utf-8")
    app = create_app(settings=settings, config=load_config())
    return app, app.state.pipeline


def seed(client: TestClient, pipeline, kind="error_rate", user: Optional[str] = None) -> int:
    async def go() -> int:
        alert = make_alert(kind, user=user, id=None, incident_id=None)
        anomaly = Anomaly(kind=kind, ts=T0, service=alert.service, user_id=user, z=5.0)
        update = pipeline.incidents.record_alert(anomaly, alert)
        alert.incident_id = update.incident.id
        await pipeline.apply_incident_update(update)
        alert.id = await pipeline.store.save_alert(alert)
        await pipeline.store.save_evidence(update.incident.id, alert.id, [r["record"] for r in make_evidence(kind)])
        update.incident.evidence_count = await pipeline.store.count_evidence(update.incident.id)
        await pipeline.store.upsert_incident(update.incident)
        return update.incident.id

    return client.portal.call(go)


def test_insight_endpoint_returns_a_cited_deterministic_insight_by_default(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        iid = seed(c, pipeline)
        r = c.get(f"/api/incidents/{iid}/insight")
        assert r.status_code == 200
        body = r.json()
        assert body["ai"]["enabled"] is False and body["ai"]["deterministic_fallback"] is True
        ins = body["insight"]
        assert ins["generated_by"] == "deterministic" and ins["executed_actions"] == []
        assert ins["summary"]["evidence_refs"] and all(h["label"] == "hypothesis" for h in ins["hypotheses"])
        for canary in CANARIES:
            assert canary not in r.text
        assert c.get("/api/incidents/9999/insight").status_code == 404
        assert c.get("/api/ai/status").json()["enabled"] is False


def test_generate_endpoint_audits_without_content_and_does_not_touch_notifications(tmp_path):
    app, pipeline = build_app(tmp_path)
    calls = []
    pipeline.email.notify_incident = lambda *a, **k: calls.append(("email", a))
    pipeline.notifier.notify_incident = lambda *a, **k: calls.append(("aws", a))
    pipeline.notifier.notify_alert = lambda *a, **k: calls.append(("aws-alert", a))
    with TestClient(app) as c:
        iid = seed(c, pipeline, "hipaa_bulk_access", user=USER)
        calls.clear()
        r = c.post(f"/api/incidents/{iid}/insight/generate")
        assert r.status_code == 200 and r.json()["insight"]["fallback_reason"] == "ai_disabled"
        rows = [a for a in c.get("/api/audit").json() if a["action"] == "ai_insight"] if isinstance(c.get("/api/audit").json(), list) \
            else [a for a in c.get("/api/audit").json()["items"] if a["action"] == "ai_insight"]
        assert len(rows) == 1 and rows[0]["target_id"] == str(iid)
        assert rows[0]["detail"] == "deterministic:ai_disabled"
        assert calls == []                                    # generating an insight never notifies anyone


def test_generate_requires_the_operator_role_when_tokens_are_configured(tmp_path):
    app, pipeline = build_app(tmp_path, operator_token="op-token-test", viewer_token="view-token-test",
                              admin_token="admin-token-test")
    with TestClient(app) as c:
        iid = seed(c, pipeline)
        assert c.post(f"/api/incidents/{iid}/insight/generate").status_code in (401, 403)
        assert c.post(f"/api/incidents/{iid}/insight/generate", headers={"X-Operator-Token": "view-token-test"}).status_code == 403
        ok = c.post(f"/api/incidents/{iid}/insight/generate", headers={"X-Operator-Token": "op-token-test"})
        assert ok.status_code == 200
        assert c.get(f"/api/incidents/{iid}/insight").status_code in (401, 403)       # reads follow the existing read rules
        assert c.get(f"/api/incidents/{iid}/insight", headers={"X-Operator-Token": "view-token-test"}).status_code == 200


def test_end_to_end_with_a_fake_model_through_the_api(tmp_path):
    app, pipeline = build_app(tmp_path, ai_enabled=True, ai_provider="ollama", ai_model="fake")
    with TestClient(app) as c:
        iid = seed(c, pipeline)

        c.get(f"/api/incidents/{iid}/insight")                     # creates the service lazily
        svc = app.state.ai_insights
        svc.provider = FakeProvider(reply=model_reply)
        r = c.post(f"/api/incidents/{iid}/insight/generate")
        assert r.status_code == 200 and r.json()["insight"]["generated_by"] == "ollama"
        again = c.get(f"/api/incidents/{iid}/insight").json()
        assert again["insight"]["generated_by"] == "ollama" and again["stale_ai_available"] is False
        assert c.post(f"/api/incidents/{iid}/insight/generate").status_code == 429


async def test_migration_006_is_additive_and_migrations_4_and_5_are_intact(tmp_path):
    store = Store(tmp_path / "m.db", None)
    await store.connect()
    versions = await applied_versions(store.conn)
    assert LATEST_VERSION == 6 and sorted(versions) == [1, 2, 3, 4, 5, 6]
    assert versions[4] and await store.conn.table_exists("ai_insights") and await store.conn.table_exists("ingest_meta")
    assert {"incident_id", "bundle_hash", "payload_json"} <= await store.conn.column_names("ai_insights")
    await store.close()


async def test_only_the_three_newest_insights_per_incident_are_kept(env):
    store, inc, service = env
    for i in range(5):
        ins = build_deterministic(bundle_for())
        ins.generated_by, ins.model = "ollama", "m"
        ins.bundle_hash = f"h{i}"
        await store.save_ai_insight(ins)
    n = (await (await store.conn.execute("SELECT COUNT(*) FROM ai_insights")).fetchone())[0]
    assert n == 3 and (await store.latest_ai_insight(7)).bundle_hash == "h4"


async def test_retention_removes_insights_with_purged_incidents_and_by_age(env):
    from app.privacy.retention import RetentionPolicy, apply_retention

    store, inc, service = env
    ins = build_deterministic(bundle_for())
    ins.generated_by, ins.model = "ollama", "m"
    await store.save_ai_insight(ins)
    old = build_deterministic(bundle_for())
    old.generated_by, old.generated_at = "ollama", (T0 - timedelta(days=90)).isoformat()
    await store.save_ai_insight(old)
    off = RetentionPolicy(0, 0, 0, 0, 0, 0, 0)
    assert await apply_retention(store, off, now=T0) == {}                        # nothing configured, nothing removed
    pol = RetentionPolicy(0, 30, 0, 0, 0, 0, 0)
    now = T0 + timedelta(days=1)
    assert await apply_retention(store, pol, now=now, dry_run=True) == {"evidence": 0, "ai_insights": 1}
    assert await apply_retention(store, pol, now=now) == {"evidence": 0, "ai_insights": 1}
    left = (await (await store.conn.execute("SELECT COUNT(*) FROM ai_insights")).fetchone())[0]
    assert left == 1


def test_brevo_email_settings_and_notifier_are_unchanged_by_the_ai_settings(tmp_path):
    app, pipeline = build_app(tmp_path)
    assert pipeline.settings.email_provider == "smtp" or pipeline.settings.email_provider == "brevo"
    assert pipeline.settings.email_min_severity == "HIGH" and pipeline.settings.email_cooldown_seconds == 300
    assert pipeline.settings.ai_enabled is False and pipeline.settings.aws_mode == "off"


# -- both database backends (PostgreSQL only when HEALTHTRACE_TEST_DATABASE_URL points at a disposable database) -------

import os

from app.store.database import PostgresDatabase

PG_URL = os.environ.get("HEALTHTRACE_TEST_DATABASE_URL", "")


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not PG_URL, reason="set HEALTHTRACE_TEST_DATABASE_URL to run the PostgreSQL cases"))])
async def any_store(request, tmp_path):
    if request.param == "postgres":
        db = PostgresDatabase(PG_URL)
        await db.connect()
        await db.execute("DROP SCHEMA public CASCADE")
        await db.execute("CREATE SCHEMA public")
        await db.close()
        s = Store(tmp_path / "unused.db", PG_URL)
    else:
        s = Store(tmp_path / "t.db")
    await s.connect()
    yield s
    await s.close()


async def test_insight_storage_round_trips_and_prunes_on_every_backend(any_store):
    store = any_store
    assert sorted(await applied_versions(store.conn)) == list(range(1, LATEST_VERSION + 1))
    await store.upsert_incident(make_incident())
    for other in (7, 8):
        for i in range(5):
            ins = build_deterministic(bundle_for())
            ins.incident_id, ins.generated_by, ins.model, ins.bundle_hash = other, "ollama", "m", f"h{other}-{i}"
            await store.save_ai_insight(ins)
    assert (await store.latest_ai_insight(7)).bundle_hash == "h7-4"
    assert (await store.latest_ai_insight(8)).bundle_hash == "h8-4"
    count = (await (await store.conn.execute("SELECT COUNT(*) FROM ai_insights WHERE incident_id = 7")).fetchone())[0]
    assert int(count) == 3
    assert await store.latest_ai_insight(999) is None
