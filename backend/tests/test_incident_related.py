"""Phase 2 - related incidents, duplicate suggestions and trends (docs/incident-intelligence.md).

Synthetic data only. All of it is read-only: the tests also prove that nothing is written.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, load_config
from app.incidents import related as intel
from app.main import create_app
from app.models import Incident
from app.store.database import PostgresDatabase
from app.store.db import Store

T0 = datetime(2026, 10, 20, 9, 0, 0, tzinfo=timezone.utc)
USER = "dr.alice.canary"          # canary: must never appear in any response
GRAPH = {"prior_auth": ["eligibility"], "eligibility": [], "claims": [], "pharmacy": ["eligibility"], "batch": []}


def inc(id, kind="error_rate", service: Optional[str] = "claims", *, start=0, minutes=10, severity="HIGH",
        state="OPEN", user: Optional[str] = None, resolved=False, mttr="auto", reopen=0) -> Incident:
    opened = T0 + timedelta(minutes=start)
    last = opened + timedelta(minutes=minutes)
    return Incident(
        id=id, fingerprint=f"{kind}:{user or service}", kind=kind, service=None if user else service, user_id=user,
        state="RESOLVED" if resolved else state, peak_severity=severity, alert_count=2, opened_at=opened,
        last_seen_at=last, resolved_at=last if resolved else None,
        mttr_seconds=(minutes * 60.0 if mttr == "auto" else mttr) if resolved else None, reopen_count=reopen)


# -- related: scoring rules ------------------------------------------------------------------------------------


def test_same_service_same_kind_close_in_time_is_related_with_reasons():
    m = intel.score_related(inc(1), inc(2, start=5))
    assert m and m.score >= 0.9
    assert {"same_service", "same_kind", "time_proximity"} <= set(m.signals)
    assert any("Same service (claims)" in r for r in m.reasons)
    assert any("overlap" in r for r in m.reasons)


def test_current_incident_is_never_its_own_match_and_ranking_excludes_it():
    a = inc(1)
    assert intel.score_related(a, a) is None
    assert intel.score_related(a, inc(1, start=3)) is None                 # same id
    assert [m.candidate.id for m in intel.rank_related(a, [a, inc(2, start=2)])] == [2]


def test_time_proximity_alone_never_links_incidents():
    a = inc(1, "error_rate", "claims")
    assert intel.score_related(a, inc(2, "hipaa_bulk_export", "pharmacy", start=1)) is None


def test_same_service_alone_is_not_enough_when_far_apart_in_time():
    # same service, different unrelated family, two days apart: only one signal type
    assert intel.score_related(inc(1, "error_rate"), inc(2, "auth_suspicious_login", "claims", start=3000)) is None


def test_compatible_kinds_on_a_dependent_service_are_related():
    a = inc(1, "error_rate", "prior_auth")
    m = intel.score_related(a, inc(2, "latency_degradation", "eligibility", start=20), graph=GRAPH)
    assert m and "dependent_service" in m.signals and "compatible_kind" in m.signals
    assert any("dependency graph" in r for r in m.reasons)
    assert intel.score_related(a, inc(3, "latency_degradation", "batch", start=20), graph=GRAPH) is None


def test_missing_service_and_missing_graph_are_handled():
    assert intel.score_related(inc(1, service=None, user=USER, kind="hipaa_bulk_access"),
                               inc(2, service=None, user="someone-else", kind="hipaa_bulk_access", start=2)) is not None
    a, b = inc(1), inc(2, service=None, start=1)
    b.user_id = None
    assert intel.score_related(a, b) is None or "same_service" not in intel.score_related(a, b).signals


def test_inconsistent_timestamps_do_not_crash():
    a = inc(1)
    b = inc(2, start=5)
    b.last_seen_at = b.opened_at - timedelta(hours=3)          # last seen before opened
    b.resolved_at = b.opened_at - timedelta(hours=1)
    assert intel.gap_seconds(a, b) == 0.0
    naive = inc(3)
    naive.opened_at = naive.opened_at.replace(tzinfo=None)     # naive datetime treated as UTC
    naive.last_seen_at = None
    assert intel.gap_seconds(a, naive) is not None
    assert intel.score_related(a, b) is not None


def test_actor_is_not_a_signal_unless_switched_on():
    a = inc(1, "hipaa_bulk_access", user=USER)
    b = inc(2, "hipaa_off_hours", user=USER, start=4)
    off = intel.score_related(a, b)
    on = intel.score_related(a, b, match_actor=True)
    assert off is None or "same_actor" not in off.signals
    assert on and "same_actor" in on.signals and on.score > (off.score if off else 0)
    assert all(USER not in r for r in on.reasons)               # the value is never reported


def test_evidence_shape_adds_a_signal_only_when_both_sides_have_evidence():
    a, b = inc(1), inc(2, start=1)
    shapes = intel.Evidence(frozenset({("api", "ERROR"), ("db", "WARN")}))
    withev = intel.score_related(a, b, src_evidence=shapes, cand_evidence=shapes)
    without = intel.score_related(a, b)
    assert "evidence_shape" in withev.signals and "evidence_shape" not in without.signals
    empty = intel.Evidence(frozenset())
    assert "evidence_shape" not in intel.score_related(a, b, src_evidence=shapes, cand_evidence=empty).signals


def test_ranking_is_deterministic_limited_and_ordered():
    a = inc(1)
    cands = [inc(10 + n, start=n * 4) for n in range(6)] + [inc(30, "error_rate", "pharmacy", start=1)]
    first = intel.rank_related(a, cands, limit=3)
    assert first == intel.rank_related(a, list(reversed(cands)), limit=3)
    assert len(first) == 3 and [m.score for m in first] == sorted((m.score for m in first), reverse=True)
    assert intel.rank_related(a, []) == []


# -- duplicates: conservative -----------------------------------------------------------------------------------


def test_duplicate_requires_same_kind_service_and_nearly_same_time():
    a = inc(1)
    d = intel.score_duplicate(a, inc(2, start=3))
    assert d and d.score >= 0.7 and d.confidence in ("likely", "possible")
    assert any("same service" in r for r in d.reasons)
    assert intel.score_duplicate(a, inc(3, "latency_degradation", start=3)) is None        # different kind
    assert intel.score_duplicate(a, inc(4, service="pharmacy", start=3)) is None           # different service
    assert intel.score_duplicate(a, inc(5, start=60 * 5)) is None                          # a recurrence hours later
    assert intel.score_duplicate(a, inc(6, start=3), max_gap_seconds=0) is not None        # overlap still counts


def test_duplicate_false_positive_prone_cases():
    a = inc(1, service=None)
    a.service = None
    assert intel.score_duplicate(a, inc(2, service=None)) is None                          # missing service
    both_resolved = intel.score_duplicate(inc(3, resolved=True), inc(4, start=35, resolved=True), max_gap_seconds=3600)
    assert both_resolved is None or both_resolved.confidence == "possible"
    far_sev = intel.score_duplicate(inc(5, severity="LOW"), inc(6, severity="CRITICAL", start=2))
    assert far_sev is None or far_sev.cautions                                             # severity mismatch is flagged


def test_actor_scoped_kinds_are_never_duplicates_without_actor_matching():
    a = inc(1, "hipaa_bulk_access", user=USER)
    b = inc(2, "hipaa_bulk_access", user=USER, start=2)
    assert intel.score_duplicate(a, b) is None                                             # cannot compare actors: skip
    assert intel.score_duplicate(a, b, match_actor=True) is None                         # per-person incidents carry no service
    other = inc(3, "hipaa_bulk_access", user="another.user", start=2)
    assert intel.score_duplicate(a, other, match_actor=True) is None                       # different people


def test_duplicate_view_requires_review_and_hides_identifiers():
    a = inc(1)
    view = intel.duplicate_view(1, intel.score_duplicate(a, inc(2, start=2)))
    assert view["requires_human_review"] is True and view["basis"] == "deterministic_match"
    assert set(view["incident"]) == {"id", "title", "kind", "service", "state", "status_label", "severity",
                                     "alert_count", "opened_at", "last_seen_at", "resolved_at"}


def test_related_view_hides_actor_and_fingerprint():
    v = intel.related_view(1, intel.score_related(inc(1, "hipaa_bulk_access", user=USER),
                                                   inc(2, "hipaa_bulk_access", user=USER, start=1), match_actor=True))
    assert USER not in str(v) and "fingerprint" not in v["incident"] and "user_id" not in v["incident"]


# -- trends: pure shaping ---------------------------------------------------------------------------------------


def _raw(**kw):
    base = {"series": [], "by_severity": [], "by_service": [], "by_kind": [], "by_state": [], "recurring": [],
            "resolved_total": 0, "durations": []}
    base.update(kw)
    return base


def test_empty_trends_are_zero_filled_and_make_no_estimates():
    out = intel.build_trends(_raw(), since=T0, until=T0 + timedelta(days=3), bucket="day")
    assert out["total"] == 0 and len(out["series"]) == 4 and all(p["total"] == 0 for p in out["series"])
    assert out["resolution"]["available"] is False and out["resolution"]["median_seconds"] is None
    assert out["status"] == {"open": 0, "resolved": 0, "by_state": {}} and out["recurring"] == []


def test_resolution_needs_enough_valid_samples():
    few = intel.build_trends(_raw(durations=[60.0] * 4, resolved_total=6), since=T0, until=T0 + timedelta(days=1), bucket="day")
    assert few["resolution"]["available"] is False and "at least 5" in few["resolution"]["reason"]
    assert few["resolved_without_valid_duration"] == 2
    enough = intel.build_trends(_raw(durations=[60, 120, 180, 240, 600], resolved_total=5), since=T0,
                                until=T0 + timedelta(days=1), bucket="day")
    assert enough["resolution"] == {"available": True, "sample_size": 5, "median_seconds": 180, "p90_seconds": 600,
                                    "max_seconds": 600, "reason": None}


# -- store aggregates + API on a real app -----------------------------------------------------------------------


def build_app(tmp_path: Path, **kw):
    kw.setdefault("aws_mode", "off")
    settings = Settings(log_dir=tmp_path / "logs", db_path=tmp_path / "m.db", control_file=tmp_path / "c.json",
                        static_dir=tmp_path / "nostatic", **kw)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    (settings.log_dir / "app.log").write_text("", encoding="utf-8")
    (settings.log_dir / "audit.log").write_text("", encoding="utf-8")
    app = create_app(settings=settings, config=load_config())
    return app, app.state.pipeline


def put(client, pipeline, *incidents):
    async def go():
        for i in incidents:
            await pipeline.store.upsert_incident(i)
    client.portal.call(go)


def snapshot(client, pipeline):
    async def go():
        rows = await (await pipeline.store.conn.execute(
            "SELECT id, state, alert_count, resolved_at, last_seen_at FROM incidents ORDER BY id")).fetchall()
        return [tuple(r) for r in rows]
    return client.portal.call(go)


def test_related_endpoint_returns_scored_reasoned_results_and_changes_nothing(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        put(c, pipeline, inc(1), inc(2, start=4), inc(3, "latency_degradation", "claims", start=8),
            inc(4, "error_rate", "batch", start=2), inc(5, start=60 * 24 * 3),
            inc(6, "hipaa_bulk_access", user=USER, start=3))
        before = snapshot(c, pipeline)
        r = c.get("/api/incidents/1/related")
        assert r.status_code == 200
        body = r.json()
        ids = [x["related_incident_id"] for x in body["related"]]
        assert 1 not in ids and 2 in ids and 5 not in ids and 6 not in ids        # self, far-in-time and unrelated excluded
        top = body["related"][0]
        assert top["source_incident_id"] == 1 and top["reasons"] and 0 < top["score"] <= 1
        assert top["incident"]["opened_at"] and top["basis"] == "deterministic_match"
        assert "not proof" in body["disclaimer"] and body["criteria"]["actor_matching"] is False
        assert USER not in r.text and "fingerprint" not in r.text and "user_id" not in r.text
        assert snapshot(c, pipeline) == before                                    # read-only
        assert c.get("/api/incidents/1/related?limit=1").json()["count"] == 1


def test_related_endpoint_validates_and_404s(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        put(c, pipeline, inc(1))
        assert c.get("/api/incidents/999/related").status_code == 404
        assert c.get("/api/incidents/1/related?limit=0").status_code == 422
        assert c.get("/api/incidents/1/related?limit=500").status_code == 422
        assert c.get("/api/incidents/1/related?min_score=2").status_code == 422
        assert c.get("/api/incidents/1/related?window_hours=0").status_code == 422
        assert c.get("/api/incidents/abc/related").status_code == 422
        empty = c.get("/api/incidents/1/related")
        assert empty.status_code == 200 and empty.json()["related"] == [] and empty.json()["count"] == 0


def test_actor_matching_is_opt_in_in_the_api(tmp_path):
    for flag in (False, True):
        sub = tmp_path / str(flag)
        sub.mkdir()
        app, pipeline = build_app(sub, incident_intel_match_actor=flag)
        with TestClient(app) as c:
            put(c, pipeline, inc(1, "hipaa_bulk_access", user=USER), inc(2, "hipaa_off_hours", user=USER, start=3))
            body = c.get("/api/incidents/1/related").json()
            has_actor = any("same_actor" in x["signals"] for x in body["related"])
            assert has_actor is flag and USER not in str(body)


def test_duplicates_endpoint(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        put(c, pipeline, inc(1), inc(2, start=3), inc(3, "latency_degradation", start=3), inc(4, start=60 * 6),
            inc(5, "hipaa_bulk_access", user=USER), inc(6, "hipaa_bulk_access", user=USER, start=2))
        before = snapshot(c, pipeline)
        body = c.get("/api/incidents/1/duplicates").json()
        assert [d["candidate_incident_id"] for d in body["duplicates"]] == [2]
        d = body["duplicates"][0]
        assert d["requires_human_review"] is True and d["reasons"] and "Nothing is merged" in body["disclaimer"]
        actor = c.get("/api/incidents/5/duplicates").json()
        assert actor["duplicates"] == [] and "grouped per person" in actor["skipped_reason"]
        assert c.get("/api/incidents/404/duplicates").status_code == 404
        assert c.get("/api/incidents/1/duplicates?limit=99").status_code == 422
        assert snapshot(c, pipeline) == before                                    # never merges or deletes
        assert USER not in str(actor)


def test_read_access_rules_apply_to_the_new_routes(tmp_path):
    app, pipeline = build_app(tmp_path, viewer_token="view-token-test", operator_token="op-token-test")
    with TestClient(app) as c:
        put(c, pipeline, inc(1), inc(2, start=2))
        for path in ("/api/incidents/1/related", "/api/incidents/1/duplicates", "/api/incidents/trends"):
            assert c.get(path).status_code in (401, 403)
            assert c.get(path, headers={"X-Operator-Token": "view-token-test"}).status_code == 200


def test_trends_endpoint_counts_stored_incidents_only(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        put(c, pipeline,
            inc(1, "error_rate", "claims", start=0, severity="HIGH"),
            inc(2, "error_rate", "claims", start=60 * 24, severity="CRITICAL", resolved=True, minutes=30),
            inc(3, "latency_degradation", "pharmacy", start=60 * 24 * 2, severity="LOW", resolved=True, minutes=10),
            inc(4, "error_rate", "claims", start=60 * 24 * 2 + 5, severity="HIGH", resolved=True, minutes=20, reopen=1),
            inc(5, "hipaa_bulk_access", user=USER, start=60 * 24 * 3, severity="MEDIUM"))
        q = f"since={T0.isoformat().replace('+00:00', 'Z')}&until={(T0 + timedelta(days=5)).isoformat().replace('+00:00', 'Z')}"
        body = c.get(f"/api/incidents/trends?{q}").json()
        assert body["total"] == 5 and body["range"]["bucket"] == "day" and len(body["series"]) == 6
        assert [p["total"] for p in body["series"]] == [1, 1, 2, 1, 0, 0]
        assert {x["key"]: x["count"] for x in body["by_severity"]} == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1}
        assert {x["key"]: x["count"] for x in body["by_service"]}["claims"] == 3
        assert {x["key"]: x["count"] for x in body["by_kind"]}["error_rate"] == 3
        assert body["status"]["open"] == 2 and body["status"]["resolved"] == 3
        rec = body["recurring"]
        assert rec[0]["kind"] == "error_rate" and rec[0]["service"] == "claims" and rec[0]["count"] == 3
        assert rec[0]["reopen_count"] == 1
        assert body["resolution"]["available"] is False and body["resolution"]["sample_size"] == 3   # 3 < 5: no figure
        assert USER not in c.get(f"/api/incidents/trends?{q}").text
        flt = c.get(f"/api/incidents/trends?{q}&service=claims&severity=HIGH").json()
        assert flt["total"] == 2 and flt["filters"]["service"] == "claims"


def test_trends_resolution_statistics_appear_with_enough_valid_timestamps(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        rows = [inc(i, start=i * 90, minutes=m, resolved=True) for i, m in enumerate((5, 10, 15, 20, 60), start=1)]
        bad = inc(9, start=700, minutes=5, resolved=True, mttr=None)             # resolved but no duration: excluded
        neg = inc(10, start=720, minutes=5, resolved=True, mttr=-30.0)           # impossible duration: excluded
        put(c, pipeline, *rows, bad, neg)
        body = c.get(f"/api/incidents/trends?since={T0.isoformat().replace('+00:00', 'Z')}&days=1").json()
        res = body["resolution"]
        assert res["available"] is True and res["sample_size"] == 5 and res["median_seconds"] == 900
        assert res["max_seconds"] == 3600 and body["resolved_without_valid_duration"] == 2


def test_trends_validation_and_empty_database(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        empty = c.get("/api/incidents/trends")
        assert empty.status_code == 200 and empty.json()["total"] == 0 and empty.json()["resolution"]["available"] is False
        assert c.get("/api/incidents/trends?days=0").status_code == 422
        assert c.get("/api/incidents/trends?days=9999").status_code == 422
        assert c.get("/api/incidents/trends?since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z").status_code == 422
        assert c.get("/api/incidents/trends?since=2024-01-01T00:00:00Z&until=2026-01-01T00:00:00Z").status_code == 422
        assert c.get("/api/incidents/trends?bucket=hour&days=30").status_code == 422
        assert c.get("/api/incidents/trends?service=nope").status_code == 422
        assert c.get("/api/incidents/trends?kind=nope").status_code == 422
        assert c.get("/api/incidents/trends?severity=EXTREME").status_code == 422
        assert c.get("/api/incidents/trends?bucket=week").status_code == 422
        # "trends" is a route of its own, not an incident id
        assert c.get("/api/incidents/trends").status_code == 200


def test_candidate_cap_is_reported_not_silent(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        put(c, pipeline, inc(1), *[inc(100 + n, start=n % 9, service="batch") for n in range(intel.MAX_CANDIDATES + 5)])
        body = c.get("/api/incidents/1/related").json()
        assert body["candidates_considered"] == intel.MAX_CANDIDATES and body["candidates_truncated"] is True
        put(c, pipeline, inc(2, start=60 * 24 * 10))
        small = c.get("/api/incidents/2/related").json()
        assert small["candidates_truncated"] is False


def test_duplicate_and_related_parameter_bounds_and_error_bodies(tmp_path):
    app, pipeline = build_app(tmp_path)
    with TestClient(app) as c:
        put(c, pipeline, inc(1))
        for path in ("/api/incidents/1/duplicates?max_gap_minutes=-1", "/api/incidents/1/duplicates?max_gap_minutes=999",
                     "/api/incidents/1/duplicates?limit=0", "/api/incidents/1/related?window_hours=500"):
            r = c.get(path)
            assert r.status_code == 422 and "Traceback" not in r.text and "sqlite" not in r.text.lower()
        r = c.get("/api/incidents/12345/related")
        assert r.status_code == 404 and r.json() == {"detail": "incident not found"}


# -- AI assistance: explains deterministic matches only ------------------------------------------------------------


def test_related_matches_enter_the_ai_bundle_as_labelled_facts_without_identifiers(tmp_path):
    from app.ai.sanitize import build_bundle
    from app.ai.templates import build_deterministic
    from app.ai.validate import validate_model_output
    cfg = load_config()
    src = inc(1, "hipaa_bulk_access", user=USER)
    related = [{"id": 2, "kind": "hipaa_bulk_access", "service": None, "state": "OPEN", "severity": "HIGH",
                "score": 0.55, "signals": ["same_kind", "time_proximity"], "fingerprint": "x:" + USER, "user_id": USER}]
    plain = build_bundle(cfg, src, [], [], [])
    bundle = build_bundle(cfg, src, [], [], [], related=related)
    assert "rel:2" not in plain.facts and bundle.hash != plain.hash
    fact = bundle.facts["rel:2"]
    assert fact["basis"] == "deterministic_match" and USER not in str(bundle.facts) and "user_id" not in fact
    insight = build_deterministic(bundle)
    step = [x for x in insight.next_steps if "rel:2" in x.evidence_refs]
    assert step and "may or may not share a cause" in step[0].text and insight.executed_actions == []
    assert any("not proof" in e.label for e in insight.evidence if e.id == "rel:2")
    # a model may cite the match; citing an id that was not computed is rejected
    ok = '{"summary":{"text":"Incident 2 may be related.","evidence_refs":["inc:1","rel:2"]},"severity_rationale":{"text":"High.","evidence_refs":["inc:1"]},"hypotheses":[],"next_steps":[{"text":"Compare incident 2 with this one.","evidence_refs":["rel:2"]}],"insufficient_evidence":false}'
    bad = ok.replace("rel:2", "rel:99")
    assert validate_model_output(ok, bundle, model="m").insight is not None
    assert validate_model_output(bad, bundle, model="m").insight is None


async def test_insight_service_passes_top_matches_and_survives_lookup_failure(tmp_path):
    from app.ai.service import InsightService
    from app.privacy.redaction import Redactor
    settings = Settings(log_dir=tmp_path, db_path=tmp_path / "x.db", control_file=tmp_path / "c.json", aws_mode="off")
    store = Store(tmp_path / "s.db")
    await store.connect()
    try:
        for i in (inc(1), inc(2, start=3)):
            await store.upsert_incident(i)
        svc = InsightService(settings, load_config(), store, Redactor.build())
        bundle = await svc.bundle_for(inc(1))
        assert "rel:2" in bundle.facts
        async def boom(*a, **k):
            raise RuntimeError("db down")
        store.incidents_overlapping = boom
        assert not [k for k in (await svc.bundle_for(inc(1))).facts if k.startswith("rel:")]
    finally:
        await store.close()


# -- both database backends ---------------------------------------------------------------------------------------

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


async def test_store_aggregates_agree_on_every_backend(any_store):
    s = any_store
    for i in (inc(1), inc(2, start=60, resolved=True, minutes=10), inc(3, "latency_degradation", "pharmacy", start=120),
              inc(4, start=180, resolved=True, minutes=20), inc(5, start=240, resolved=True, minutes=30),
              inc(6, start=300, resolved=True, minutes=40), inc(7, start=360, resolved=True, minutes=50)):
        await s.upsert_incident(i)
    raw = await s.incident_trends(since=T0, until=T0 + timedelta(days=1), bucket="hour")
    assert sum(n for *_, n in raw["series"]) == 7
    assert dict(raw["by_state"]) == {"OPEN": 2, "RESOLVED": 5}
    assert raw["recurring"][0][:3] == ("error_rate", "claims", 6)
    assert sorted(raw["durations"]) == [600.0, 1200.0, 1800.0, 2400.0, 3000.0]
    assert raw["resolved_total"] == 5
    near = await s.incidents_overlapping(T0 + timedelta(minutes=5), T0 + timedelta(minutes=65), exclude_id=2)
    assert {i.id for i in near} == {1}                                              # 2 is excluded, 3 starts later
    assert await s.incidents_overlapping(T0 + timedelta(minutes=55), T0 + timedelta(minutes=70), exclude_id=2) == []
    assert await s.incidents_overlapping(T0 - timedelta(days=9), T0 - timedelta(days=8)) == []
    assert await s.evidence_shapes([]) == {}
    assert await s.evidence_shapes([1, 2]) == {}
