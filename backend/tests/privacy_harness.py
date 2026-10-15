"""Shared M2 harness: plants synthetic canary identifiers in a configured-mode
deployment, drives them through ingestion, detection, persistence, the REST API,
the WebSocket, application logs and mocked notifications, and returns everything
that was emitted so tests can scan it.

Everything is synthetic and local: SMTP is `FakeSMTP`, AWS is the file-backed mock,
no network is used. Pseudonyms ARE allowed in outputs (they are the policy); the
planted raw values (`RAW_NEEDLES`) are not.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi.testclient import TestClient
from fastapi.routing import APIRoute

from app.ingest.pseudonym import Pseudonymizer
from app.main import create_app
from app.notify.mailer import EmailNotifier
from tests.ingest_helpers import (
    APP_SRC_MSG, AUDIT_SRC, AUTH_SRC, KEY, claims, config_for, ehr, failures_then_success, idp, now, settings_for,
)
from tests.test_email import FakeSMTP, email_settings

# ---- planted canaries (every one is fake) ------------------------------------------------------------
CANARY_USER = "jane.canary@hospital.test"          # username that is also an e-mail address
CANARY_USER2 = "dr.canary.smith"                   # employee-style account id
CANARY_IP = "198.51.100.231"                       # documentation range, fake
CANARY_PATIENT = "MRN-CANARY-"                     # + 6 digits -> medical record number
CANARY_EVENT = "evt-jane.canary@hospital.test-"    # raw event id that embeds a username
CANARY_UNMAPPED = "unmapped-canary-note-xyz"       # in a source field that is NOT mapped
CANARY_BAD_USER = "bad.canary@hospital.test"       # only ever on lines that must be rejected
CANARY_GARBAGE = "garbage-canary-line"             # a non-JSON line
CANARY_OVERSIZE = "oversize-canary-token"          # on a line longer than the cap
CANARY_UNKNOWN_SERVICE = "radiology-canary-pacs"   # a service nobody configured
CANARY_MSG_NAME = "Zed Canaryson"                  # free text name (opt-in source only)

RAW_NEEDLES = [
    "jane.canary", "dr.canary", "hospital.test", CANARY_IP, "198.51.100", "mrn-canary", "evt-jane", CANARY_UNMAPPED,
    "bad.canary", CANARY_GARBAGE, CANARY_OVERSIZE, CANARY_UNKNOWN_SERVICE, "radiology-canary",
]
SSN = "123-45-6789"
MAX_LINE = 2048


def scan(label: str, text: str, *, extra: tuple[str, ...] = (), check_key: bool = True) -> None:
    """Assert that no planted raw canary, the SSN, the key or any extra needle appears in ``text``."""
    low = text.lower()
    for needle in (*RAW_NEEDLES, SSN, *([KEY.lower()] if check_key else []), *(e.lower() for e in extra)):
        assert needle.lower() not in low, f"{label} leaked {needle!r}"


class LogCapture(logging.Handler):
    """Collects every record (message, arguments rendered, traceback text) from the root logger."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self._fmt = logging.Formatter("%(name)s %(levelname)s %(message)s")

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    # The HTTP client used BY THE TEST to call the API logs the request URL it was given;
    # that is the test's own traffic, not an application output path.
    TEST_CLIENT_LOGGERS = ("httpx", "httpcore")

    def _app_records(self) -> list[logging.LogRecord]:
        return [r for r in self.records if not r.name.startswith(self.TEST_CLIENT_LOGGERS)]

    @property
    def text(self) -> str:
        return "\n".join(self._fmt.format(r) for r in self._app_records())

    def has(self, fragment: str) -> bool:
        return fragment in self.text

    def from_loggers(self, *prefixes: str) -> list[str]:
        return [self._fmt.format(r) for r in self._app_records() if r.name.startswith(prefixes)]


class capture_logs:
    def __enter__(self) -> LogCapture:
        self.h = LogCapture()
        self.root = logging.getLogger()
        self.old_level = self.root.level
        self.root.addHandler(self.h)
        self.root.setLevel(logging.DEBUG)
        return self.h

    def __exit__(self, *exc: object) -> None:
        self.root.removeHandler(self.h)
        self.root.setLevel(self.old_level)


def db_text_sqlite(db_path: Path) -> str:
    con = sqlite3.connect(db_path)
    parts: list[str] = []
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        for row in con.execute(f'SELECT * FROM "{name}"').fetchall():
            parts.append(json.dumps(row, default=str))
    con.close()
    return "\n".join(parts)


def db_tables_sqlite(db_path: Path) -> dict[str, int]:
    con = sqlite3.connect(db_path)
    out = {n: con.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0]
           for (n,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    con.close()
    return out


def db_file_bytes(db_path: Path) -> bytes:
    return b"".join(p.read_bytes() for p in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")) if p.exists())


@dataclass
class Outputs:
    ps: Pseudonymizer
    settings: Any
    api: dict[str, str] = field(default_factory=dict)         # path -> response text
    api_status: dict[str, int] = field(default_factory=dict)
    ws_frames: list[dict[str, Any]] = field(default_factory=list)
    logs: Optional[LogCapture] = None
    emails: list[str] = field(default_factory=list)           # full RFC822 text
    aws_log: str = ""
    db_text: str = ""
    db_bytes: bytes = b""
    db_tables: dict[str, int] = field(default_factory=dict)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    ingest_status: dict[str, Any] = field(default_factory=dict)
    pipeline_counts: dict[str, int] = field(default_factory=dict)
    state_text: str = ""          # every string reachable from the live pipeline's detection state
    state_nodes: int = 0

    @property
    def ws_types(self) -> set[str]:
        return {f.get("type", "?") for f in self.ws_frames}

    @property
    def api_text(self) -> str:
        return "\n".join(self.api.values())


def _wait(cond: Callable[[], bool], seconds: float = 25.0) -> None:
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return
        time.sleep(0.05)
    raise AssertionError("condition not reached")


def _get_routes(app: Any = None) -> list[str]:
    """Every parameterless GET route of the API (so a newly added endpoint is swept automatically).
    Read from the router itself: newer FastAPI wraps included routers, so ``app.routes`` hides them."""
    from app.api.routes import router

    return sorted({"/api" + r.path for r in router.routes
                   if isinstance(r, APIRoute) and "GET" in r.methods and "{" not in r.path})


def run_scenario(tmp_path: Path, *, first_smtp_failure: bool = True) -> Outputs:
    """Plant every canary shape, historical and live, and collect every output."""
    FakeSMTP.instances = []
    FakeSMTP.fail_with = []
    if first_smtp_failure:
        import smtplib
        # transient failure on the first connection -> exercises retry + failed-attempt logging
        FakeSMTP.fail_with = [smtplib.SMTPServerDisconnected(f"connection lost for {email_settings().recipients[0]}")]

    s = settings_for(tmp_path, aws_mode="mock", demo_mode=False, ingest_max_line_bytes=MAX_LINE)
    cfg = config_for(AUTH_SRC, AUDIT_SRC, APP_SRC_MSG)  # strictest case: free text opted in on one source
    for name in ("idp.jsonl", "ehr.jsonl", "claims.jsonl"):
        (s.log_dir / name).write_text("")
    app = create_app(settings=s, config=cfg)
    pipeline = app.state.pipeline
    mailer = EmailNotifier(email_settings(), app_config=cfg, smtp_factory=FakeSMTP, base_backoff=0.01)
    mailer.redact = pipeline.redactor.redact_value
    pipeline.email = mailer

    ps = Pseudonymizer.from_setting(KEY)
    out = Outputs(ps=ps, settings=s)
    base = now() - timedelta(minutes=8)

    def append(path: str, lines: list[str]) -> None:
        with (s.log_dir / path).open("a") as f:
            f.write("\n".join(lines) + "\n")

    def quiet() -> bool:
        return all(t.caught_up for t in pipeline._tailers) and pipeline.queue._unfinished_tasks == 0

    with capture_logs() as logs:
        with TestClient(app) as client:
            # Phase 1 - history: every canary shape, plus lines that must be rejected.
            hist_auth = failures_then_success(base, user=CANARY_USER, ip=CANARY_IP, ids=False)[:3]
            hist_auth = [json.dumps({**json.loads(l), "notes": CANARY_UNMAPPED}) for l in hist_auth]
            append("idp.jsonl", hist_auth + [
                f"{CANARY_GARBAGE} {CANARY_USER}",                                                     # not JSON
                json.dumps({"@timestamp": "nonsense", "event": {"outcome": "Failure"},
                            "actor": {"name": CANARY_BAD_USER, "home_geo": "IN"}, "client": {"geo": "RU"}}),   # bad timestamp
                json.dumps({"@timestamp": base.isoformat(), "event": {"outcome": f"weird-{CANARY_BAD_USER}"},
                            "actor": {"name": CANARY_BAD_USER, "home_geo": "IN"}, "client": {"geo": "RU"}}),  # bad value
                json.dumps({"pad": CANARY_OVERSIZE + "x" * (MAX_LINE + 50)}),                          # over the cap
            ])
            append("claims.jsonl", [
                claims(base + timedelta(seconds=i), eid=f"{CANARY_EVENT}{i}", lvl="error", http=503,
                       message=f"login for {CANARY_USER} ssn {SSN} contact {CANARY_MSG_NAME} at {CANARY_IP}",
                       patient=f"{CANARY_PATIENT}{i:06d}") for i in range(5)
            ] + [claims(base, eid=f"{CANARY_EVENT}x", svc=CANARY_UNKNOWN_SERVICE)])                    # unknown service
            _wait(lambda: pipeline.events_processed["auth"] >= 3 and pipeline.events_processed["app"] >= 5 and quiet())

            # Phase 2 - live events while a WebSocket client is connected.
            with client.websocket_connect("/ws") as ws:
                guard = threading.Timer(30, ws.close)
                guard.start()
                out.ws_frames.append(ws.receive_json())                                               # snapshot
                live = now() - timedelta(minutes=2)
                append("idp.jsonl", [idp(live + timedelta(seconds=i), CANARY_USER, "Failure", eid=f"{CANARY_EVENT}auth{i}",
                                         ip=CANARY_IP) for i in range(5)]
                       + [idp(live + timedelta(seconds=9), CANARY_USER, "Success", eid=f"{CANARY_EVENT}ok", ip=CANARY_IP)])
                append("ehr.jsonl", [ehr(live + timedelta(seconds=i * 0.2), CANARY_USER2, "READ", f"{CANARY_PATIENT}{i:06d}",
                                         eid=f"{CANARY_EVENT}ehr{i}") for i in range(260)])
                append("claims.jsonl", [claims(live + timedelta(seconds=i), eid=f"{CANARY_EVENT}live{i}", lvl="error", http=503,
                                               message=f"retry for {CANARY_USER} {SSN}", patient=f"{CANARY_PATIENT}{900000 + i}")
                                        for i in range(8)])
                needed = {"alert", "logs", "incident_update", "metric"}
                for _ in range(1500):
                    f = ws.receive_json()
                    out.ws_frames.append(f)
                    needed -= {f.get("type")}
                    if not needed:
                        break
                guard.cancel()
            _wait(lambda: pipeline.events_processed["audit"] >= 260 and pipeline.events_processed["app"] >= 13 and quiet())
            _wait(lambda: len(FakeSMTP.all_sent()) >= 1, 15)

            # Phase 3 - operator actions create audit rows; then sweep the API.
            incs = client.get("/api/incidents").json()
            auth_inc = next(i for i in incs if i["kind"] == "auth_suspicious_login")
            for verb in ("ack", "investigate", "pin"):
                r = client.post(f"/api/incidents/{auth_inc['id']}/{verb}")
                out.api[f"POST {verb}"] = r.text
                out.api_status[f"POST {verb}"] = r.status_code
            incs = client.get("/api/incidents").json()
            out.incidents = incs
            for path in _get_routes(app):
                url = path + ("?service=claims" if path == "/api/metrics" else "")
                r = client.get(url)
                out.api[url], out.api_status[url] = r.text, r.status_code
            for inc in incs:
                for sub in ("", "/timeline", "/correlation"):
                    r = client.get(f"/api/incidents/{inc['id']}{sub}")
                    out.api[f"/api/incidents/{inc['id']}{sub}"], out.api_status[f"/api/incidents/{inc['id']}{sub}"] = r.text, r.status_code
                tl = client.get(f"/api/incidents/{inc['id']}/timeline").json()
                for entry in (tl if isinstance(tl, list) else tl.get("entries", []))[:5]:
                    eid = entry.get("id") if isinstance(entry, dict) else None
                    if eid:
                        u = f"/api/incidents/{inc['id']}/timeline/{eid}"
                        r = client.get(u)
                        out.api[u], out.api_status[u] = r.text, r.status_code
            logs_json = client.get("/api/logs?limit=500").json()
            for ev in logs_json["events"][:20]:
                u = f"/api/logs/{ev['seq']}/context"
                r = client.get(u)
                out.api[u], out.api_status[u] = r.text, r.status_code
            # Searching for a canary must not echo it, and must find nothing.
            for q in (CANARY_USER, CANARY_USER2, CANARY_IP, "canaryson"):
                u = f"/api/logs?q={q}"
                r = client.get(u)
                out.api[u], out.api_status[u] = r.text, r.status_code
            out.ingest_status = client.get("/api/ingest/status").json()
            out.pipeline_counts = dict(pipeline.events_processed)
            asyncio_run_checkpoint(pipeline, client)
            out.state_text, out.state_nodes = graph_text(pipeline)
        # leaving the TestClient context shuts the pipeline down cleanly (final checkpoint)
        out.logs = logs

    out.emails = [m.as_string() for m in FakeSMTP.all_sent()]
    aws = tmp_path / "aws_mock.log"
    out.aws_log = aws.read_text() if aws.exists() else ""
    out.db_text = db_text_sqlite(s.db_path)
    out.db_bytes = db_file_bytes(s.db_path)
    out.db_tables = db_tables_sqlite(s.db_path)
    return out


def asyncio_run_checkpoint(pipeline: Any, client: TestClient) -> None:
    """Force the 60 s checkpoint (dedupe + quarantine rows) so the tables can be inspected."""
    import asyncio

    portal = getattr(client, "portal", None)
    if portal is not None:
        portal.call(pipeline._save_state)
    else:  # pragma: no cover - older Starlette
        asyncio.get_event_loop().run_until_complete(pipeline._save_state())


# Attributes of the pipeline that legitimately hold secrets or configuration, not event-derived state.
_STATE_SKIP = {"settings", "config", "pseudonymizer", "registry", "_adapters", "store", "notifier", "email",
               "broadcaster", "_tasks", "_consumer_task", "started_at", "loop"}


def graph_text(pipeline: Any, max_nodes: int = 2_000_000) -> tuple[str, int]:
    """All strings reachable from the pipeline's own state (detectors, windows, baselines, incidents,
    recent-log buffer, queue, tailer buffers, dedupe and quarantine). Only this project's classes and
    plain containers are walked, so event loops, sockets and the database driver are never entered."""
    from collections import deque
    from datetime import date, datetime

    seen: set[int] = set()
    parts: list[str] = []
    stack: list[Any] = [v for k, v in vars(pipeline).items() if k not in _STATE_SKIP]
    nodes = 0
    while stack and nodes < max_nodes:
        o = stack.pop()
        if id(o) in seen:
            continue
        seen.add(id(o))
        nodes += 1
        if isinstance(o, str):
            parts.append(o)
        elif isinstance(o, (bytes, bytearray)):
            parts.append(bytes(o).decode("utf-8", "replace"))
        elif o is None or isinstance(o, (int, float, bool, datetime, date, type, Path)) or callable(o) and not hasattr(o, "__dict__"):
            continue
        elif isinstance(o, dict):
            stack.extend(o.keys()); stack.extend(o.values())
        elif isinstance(o, (list, tuple, set, frozenset, deque)):
            stack.extend(o)
        elif type(o).__module__ == "asyncio.queues":
            stack.append(getattr(o, "_queue", ()))
        elif type(o).__module__.startswith("app.") or type(o).__module__.startswith("tests."):
            if hasattr(o, "__dict__"):
                stack.append(vars(o))
            for slot in getattr(type(o), "__slots__", ()):
                if hasattr(o, slot):
                    stack.append(getattr(o, slot))
            if hasattr(o, "model_extra") and o.model_extra:  # pydantic
                stack.append(o.model_extra)
    return "\n".join(parts), nodes
