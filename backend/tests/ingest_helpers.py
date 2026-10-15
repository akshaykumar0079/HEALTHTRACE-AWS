"""Shared synthetic fixtures for configured-ingestion tests. Every identifier here
is fake; the 'vendor' shapes are invented and match no real product."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import SecretStr

from app.config import IngestConfig, Settings, SourceConfig, load_config
from app.pipeline import Pipeline

KEY = "Zk3q9XvT7mPb2LwR8sNd5HcJ4fYg6AaE"          # 32 chars, fake test key
OTHER_KEY = "Qw8eR2tY6uI0oP4aS9dF3gH7jK1lZ5xC"

AUTH_SRC = dict(
    id="idp_fixture", path="idp.jsonl", kind="auth",
    fields={"ts": "@timestamp", "event_id": "event.id", "user_id": "actor.name", "outcome": "event.outcome",
            "source_region": "client.geo", "user_region": "actor.home_geo", "source_ip": "client.ip"},
    values={"outcome": {"Success": "success", "Failure": "failure", "Denied": "failure"}},
)
AUDIT_SRC = dict(
    id="ehr_audit_fixture", path="ehr.jsonl", kind="audit",
    fields={"ts": "time", "event_id": "uid", "user_id": "who", "role": "who_role", "action": "what",
            "patient_id": "record.patient", "patient_region": "record.site", "user_region": "site"},
    values={"action": {"READ": "VIEW_RECORD", "UPDATE": "EDIT_RECORD", "EXPORT": "EXPORT_RECORDS", "QUERY": "SEARCH"}},
)
APP_SRC = dict(
    id="claims_app_fixture", path="claims.jsonl", kind="app",
    fields={"ts": "ts", "event_id": "id", "service": "svc", "level": "lvl", "request_id": "req",
            "patient_id": "pt", "status": "http", "latency_ms": "ms"},
    values={"service": {"rcm-claims": "claims"}, "level": {"error": "ERROR", "info": "INFO", "warn": "WARN"}},
    defaults={"priority": "routine"},
)
# Explicit opt-in to free text (only pattern-redacted; the event's own identifiers are also scrubbed).
APP_SRC_MSG = dict(APP_SRC, fields={**APP_SRC["fields"], "msg": "message"}, include_msg=True)


def sources(*raw: dict[str, Any]) -> list[SourceConfig]:
    return [SourceConfig(**r) for r in raw]


def settings_for(work: Path, **kw: Any) -> Settings:
    (work / "logs").mkdir(parents=True, exist_ok=True)
    base: dict[str, Any] = dict(
        _env_file=None, aws_mode="off", email_enabled=False, database_url="",
        log_dir=work / "logs", db_path=work / "t.db", control_file=work / "control.json",
        static_dir=work / "static", embedded_generator=False, retention_interval_hours=0,
        ingest_mode="configured", pseudonym_key=SecretStr(KEY),
    )
    base.update(kw)
    return Settings(**base)


def config_for(*raw: dict[str, Any], max_future_skew_seconds: float = 300) -> Any:
    cfg = load_config().model_copy(deep=True)
    cfg.ingest = IngestConfig(sources=sources(*raw), max_future_skew_seconds=max_future_skew_seconds)
    return cfg


async def make_pipeline(work: Optional[Path] = None, srcs: Optional[list[dict[str, Any]]] = None, **kw: Any) -> Pipeline:
    work = work or Path(tempfile.mkdtemp())
    p = Pipeline(settings_for(work, **kw), config_for(*(srcs or [AUTH_SRC, AUDIT_SRC, APP_SRC])))
    await p.store.connect()
    await p.baseline.load(p.store)
    return p


def iso(dt: datetime, offset_hours: float = 0) -> str:
    tz = timezone(timedelta(hours=offset_hours))
    return dt.astimezone(tz).isoformat()


def idp(ts: datetime, user: str, outcome: str, *, eid: Optional[str], geo: str = "RU", home: str = "IN",
        ip: str = "203.0.113.50", offset_hours: float = 0) -> str:
    rec: dict[str, Any] = {"@timestamp": iso(ts, offset_hours), "event": {"outcome": outcome},
                           "actor": {"name": user, "home_geo": home}, "client": {"geo": geo, "ip": ip}}
    if eid is not None:
        rec["event"]["id"] = eid
    return json.dumps(rec)


def ehr(ts: datetime, user: str, what: str, patient: str, *, eid: Optional[str], site: str = "IN") -> str:
    rec: dict[str, Any] = {"time": iso(ts), "who": user, "who_role": "nurse", "what": what,
                           "record": {"patient": patient, "site": site}, "site": site}
    if eid is not None:
        rec["uid"] = eid
    return json.dumps(rec)


def claims(ts: datetime, *, eid: Optional[str], lvl: str = "info", http: int = 200, message: str = "ok",
           patient: Optional[str] = None, svc: str = "rcm-claims") -> str:
    rec: dict[str, Any] = {"ts": iso(ts), "svc": svc, "lvl": lvl, "req": f"r-{eid}", "http": http, "ms": 120,
                           "message": message}
    if patient:
        rec["pt"] = patient
    if eid is not None:
        rec["id"] = eid
    return json.dumps(rec)


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def failures_then_success(base: datetime, user: str = "svc.account", *, ids: bool = True, n: int = 5,
                          ip: str = "203.0.113.50") -> list[str]:
    lines = [idp(base + timedelta(seconds=i), user, "Failure", eid=f"f{i}" if ids else None, ip=ip) for i in range(n)]
    lines.append(idp(base + timedelta(seconds=n + 1), user, "Success", eid="s1" if ids else None, ip=ip))
    return lines


def incidents(p: Pipeline) -> list[tuple[str, str]]:
    return [(i.kind, i.peak_severity) for i in p.incidents.list_incidents()]
