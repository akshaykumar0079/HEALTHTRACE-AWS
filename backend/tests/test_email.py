"""Direct email (Gmail SMTP) alerts for HIGH/CRITICAL incidents.

Every test uses FakeSMTP (or the conftest guard): nothing here can reach a
real mail server or the real recipient.
"""

from __future__ import annotations

import json
import smtplib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import SecretStr

from app.config import Settings, load_config
from app.models import Alert, Anomaly, Incident
from app.notify.mailer import EmailNotifier, EmailSettings
from app.pipeline import Pipeline

APP_PASSWORD = "abcd efgh ijkl mnop"  # fake, shaped like a Gmail App Password
NOW = datetime.now(timezone.utc).replace(microsecond=0)


class FakeSMTP:
    """Records what would have been sent. ``fail_with`` makes it raise."""

    instances: list["FakeSMTP"] = []
    fail_with: list[BaseException] = []  # consumed one per connection

    def __init__(self, host, port, timeout=None, **kwargs):
        self.host, self.port, self.timeout = host, port, timeout
        self.started_tls = False
        self.login_args = None
        self.sent = []
        FakeSMTP.instances.append(self)
        if FakeSMTP.fail_with:
            raise FakeSMTP.fail_with.pop(0)

    def ehlo(self):
        pass

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, user, password):
        self.login_args = (user, password)

    def send_message(self, msg):
        self.sent.append(msg)

    def quit(self):
        pass

    @classmethod
    def all_sent(cls):
        return [m for inst in cls.instances for m in inst.sent]


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeSMTP.instances = []
    FakeSMTP.fail_with = []


def email_settings(**overrides) -> EmailSettings:
    base = dict(
        enabled=True, host="smtp.gmail.com", port=587, use_tls=True,
        username="healthtrace.demo@gmail.com", password=SecretStr(APP_PASSWORD),
        sender="healthtrace.demo@gmail.com", recipients=["vasan.akxy@gmail.com"],
    )
    base.update(overrides)
    return EmailSettings(**base)


def notifier(**overrides) -> EmailNotifier:
    return EmailNotifier(email_settings(**overrides), app_config=load_config(),
                         smtp_factory=FakeSMTP, base_backoff=0.01)


def bulk_access(severity="CRITICAL") -> tuple[Incident, Alert]:
    alert = Alert(
        ts=NOW, kind="hipaa_bulk_access", user_id="U-117", severity=severity, score=0.0,
        explanation="user U-117 accessed 201 patients (7.0x their baseline)",
        metrics={"multiplier": 7.0, "distinct_patients": 201},
    )
    incident = Incident(id=42, fingerprint="hipaa_bulk_access:U-117", kind="hipaa_bulk_access", user_id="U-117",
                        state="OPEN", peak_severity=severity, alert_count=1, opened_at=NOW)
    return incident, alert


def prior_auth(severity="HIGH") -> tuple[Incident, Alert]:
    alert = Alert(
        ts=NOW, kind="error_rate", service="prior_auth", severity=severity, score=0.70,
        explanation="prior_auth error rate 22% vs baseline 2% (z=20.2); 79 urgent patients affected",
        metrics={"total": 1800, "errors": 396, "error_rate": 0.22, "p95_latency_ms": 661,
                 "urgent_errors": 120, "affected_patients_urgent": 79, "affected_patients_routine": 3,
                 "baseline_mean": 0.02, "baseline_std": 0.008},
    )
    incident = Incident(id=7, fingerprint="error_rate:prior_auth", kind="error_rate", service="prior_auth",
                        state="OPEN", peak_severity=severity, alert_count=1, opened_at=NOW)
    return incident, alert


def body_text(msg) -> str:
    return msg.get_body(preferencelist=("plain",)).get_content()


# -- 1. disabled ---------------------------------------------------------------

async def test_disabled_sends_nothing():
    n = notifier(enabled=False)
    await n.start()
    n.notify_incident(*prior_auth("CRITICAL"))
    await n.stop()
    assert n.queue_depth == 0 and FakeSMTP.instances == []
    assert n.status.sent == n.status.skipped == 0


# -- 2-4. enabled: HIGH and CRITICAL send ----------------------------------------

@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
async def test_high_and_critical_send_one_email_over_starttls(severity):
    n = notifier()
    await n.start()
    n.notify_incident(*bulk_access(severity))
    await n.stop()

    [conn] = FakeSMTP.instances
    assert (conn.host, conn.port, conn.started_tls) == ("smtp.gmail.com", 587, True)
    assert conn.login_args == ("healthtrace.demo@gmail.com", APP_PASSWORD)
    [msg] = conn.sent
    assert msg["To"] == "vasan.akxy@gmail.com"
    assert "healthtrace.demo@gmail.com" in msg["From"]
    assert n.status.sent == 1 and n.status.failed == 0


# -- 5. LOW/MEDIUM incidents and normal traffic: no email ---------------------------

@pytest.mark.parametrize("severity", ["LOW", "MEDIUM"])
async def test_low_and_medium_incidents_do_not_email(severity):
    n = notifier()
    await n.start()
    n.notify_incident(*prior_auth(severity))
    await n.stop()
    assert FakeSMTP.instances == []


def _pipeline(tmp_path: Path) -> Pipeline:
    settings = Settings(
        aws_mode="off", demo_mode=True, email_enabled=True,
        smtp_username="healthtrace.demo@gmail.com", smtp_password=APP_PASSWORD,
        log_dir=tmp_path / "logs", db_path=tmp_path / "m.db", control_file=tmp_path / "control.json",
    )
    settings.log_dir.mkdir(parents=True)
    for name in ("app.log", "audit.log"):
        (settings.log_dir / name).write_text("", encoding="utf-8")
    pipeline = Pipeline(settings, load_config())
    pipeline.email._smtp_factory = FakeSMTP
    pipeline.email.base_backoff = 0.01
    return pipeline


async def test_normal_traffic_sends_no_email(tmp_path: Path):
    pipeline = _pipeline(tmp_path)
    await pipeline.store.connect()
    await pipeline.email.start()
    try:
        start = NOW - timedelta(minutes=3)
        for i in range(120):
            ts = (start + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            await pipeline._process_line(
                '{"ts":"' + ts + '","type":"app","service":"claims","level":"INFO","priority":"routine",'
                '"request_id":"R-' + str(i) + '","patient_id":"P-000001","status":200,"latency_ms":120,"msg":"ok"}'
            )
    finally:
        await pipeline.email.stop()
        await pipeline.store.close()
    assert pipeline.alerts_emitted == 0
    assert FakeSMTP.instances == []


# -- 6. missing credentials ------------------------------------------------------

async def test_missing_credentials_warns_and_skips_without_crashing():
    n = notifier(username="", password=SecretStr(""))
    warnings = n.config_warnings()
    assert len(warnings) == 1
    assert "SMTP_USERNAME" in warnings[0] and "SMTP_PASSWORD" in warnings[0]
    assert n.status_dict()["missing"] == ["SMTP_USERNAME", "SMTP_PASSWORD"]

    await n.start()
    n.notify_incident(*bulk_access())
    await n.stop()
    assert FakeSMTP.instances == []
    assert n.status.skipped == 1
    assert "SMTP_PASSWORD" in n.status.to_dict()["recent"][0]["error"]


def test_disabled_needs_no_credentials():
    n = notifier(enabled=False, username="", password=SecretStr(""))
    assert n.config_warnings() == []
    assert n.status_dict()["missing"] == []


# -- 7. SMTP failures never crash and never leak the password -----------------------

async def test_transient_smtp_failure_retries_then_succeeds():
    FakeSMTP.fail_with = [smtplib.SMTPServerDisconnected("Connection unexpectedly closed")]
    n = notifier()
    await n.start()
    n.notify_incident(*bulk_access())
    await n.stop()
    assert n.status.sent == 1 and n.status.retries == 1


async def test_smtp_down_is_bounded_and_the_notifier_keeps_working():
    FakeSMTP.fail_with = [TimeoutError("timed out")] * 3
    n = notifier()
    await n.start()
    n.notify_incident(*bulk_access())  # fails 3 times, then given up
    n.notify_incident(*prior_auth())   # the next email still goes out
    await n.stop()
    assert (n.status.failed, n.status.sent, n.status.retries) == (1, 1, 2)
    assert len(FakeSMTP.instances) == 4  # 3 attempts + 1, no infinite retry


async def test_auth_failure_is_not_retried_and_hides_the_password():
    FakeSMTP.fail_with = [smtplib.SMTPAuthenticationError(535, f"bad credentials {APP_PASSWORD}".encode())]
    n = notifier()
    await n.start()
    n.notify_incident(*bulk_access())
    await n.stop()
    assert len(FakeSMTP.instances) == 1 and n.status.failed == 1
    assert "App Password" in n.status.last_error
    assert APP_PASSWORD not in json.dumps(n.status_dict())


def test_password_never_exposed_by_settings_or_status():
    s = Settings(smtp_password=APP_PASSWORD, _env_file=None)
    assert APP_PASSWORD not in repr(s) and APP_PASSWORD not in str(s.model_dump())
    n = notifier()
    assert APP_PASSWORD not in json.dumps(n.status_dict())


# -- 8. de-duplication through the real incident engine -------------------------------

async def test_one_email_per_incident_then_one_on_escalation(tmp_path: Path):
    pipeline = _pipeline(tmp_path)
    await pipeline.store.connect()
    await pipeline.email.start()

    def anomaly_and_alert(severity: str, seconds: int):
        ts = NOW + timedelta(seconds=seconds)
        anomaly = Anomaly(kind="hipaa_bulk_access", ts=ts, user_id="U-117",
                          metrics={"multiplier": 5.0, "distinct_patients": 150})
        alert = Alert(ts=ts, kind="hipaa_bulk_access", user_id="U-117", severity=severity, score=0.0,
                      explanation=f"user U-117 accessed 150 patients ({severity})", metrics=anomaly.metrics)
        return anomaly, alert

    try:
        await pipeline._handle_alert(*anomaly_and_alert("HIGH", 0))      # new incident -> email
        await pipeline._handle_alert(*anomaly_and_alert("HIGH", 5))      # same incident -> no email
        await pipeline._handle_alert(*anomaly_and_alert("HIGH", 10))     # same incident -> no email
        await pipeline._handle_alert(*anomaly_and_alert("CRITICAL", 15))  # escalation -> email
        await pipeline._handle_alert(*anomaly_and_alert("CRITICAL", 20))  # same again -> no email
    finally:
        await pipeline.email.stop()
        await pipeline.store.close()

    sent = FakeSMTP.all_sent()
    assert [m["Subject"].split(":")[0] for m in sent] == [
        "[HEALTHTRACE] HIGH Security Alert",
        "[HEALTHTRACE] CRITICAL Security Alert (escalated)",
    ]
    assert len({m["X-HEALTHTRACE-Incident"] for m in sent}) == 1


# -- 9-10. subject and body ------------------------------------------------------

def test_subject_contains_healthtrace_and_severity():
    msg = notifier().build_message(*bulk_access("CRITICAL"))
    assert msg["Subject"] == "[HEALTHTRACE] CRITICAL Security Alert: Bulk PHI Access Detected - U-117"
    msg = notifier().build_message(*prior_auth("HIGH"))
    assert msg["Subject"].startswith("[HEALTHTRACE] HIGH Security Alert")


def test_body_contains_the_real_incident_information():
    n = notifier(dashboard_url="http://localhost:5173")
    body = body_text(n.build_message(*bulk_access("CRITICAL")))
    for expected in (
        "HEALTHTRACE SECURITY ALERT", "Severity:\nCRITICAL", "Incident:\nBulk PHI Access Detected",
        "user U-117 accessed 201 patients (7.0x their baseline)",  # the actual explanation
        NOW.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Detection Reason:", "CRITICAL above 6x",                   # from config.yaml thresholds
        "Distinct patient records: 201", "Access vs user's baseline: 7.0x",
        "Recommended Action:", "U-117", "Incident ID:\n#42",
        "http://localhost:5173/app/anomalies/42",
        "This alert was generated automatically by HEALTHTRACE.",
    ):
        assert expected in body, expected

    body = body_text(n.build_message(*prior_auth("HIGH")))
    for expected in ("Prior Authorization (prior_auth", "79 urgent", "Error rate: 22.0% (396 of 1800 requests)",
                     "Baseline error rate: 2.0%", "p95 latency: 661 ms", "Severity score: 0.70",
                     "eligibility", "Incident ID:\n#7"):
        assert expected in body, expected
    assert "P-0" not in body  # no patient identifiers


def test_settings_build_email_settings_from_env(monkeypatch):
    monkeypatch.setenv("EMAIL_ENABLED", "true")
    monkeypatch.setenv("SMTP_USERNAME", "me@gmail.com")
    monkeypatch.setenv("SMTP_PASSWORD", APP_PASSWORD)
    monkeypatch.delenv("ALERT_EMAIL_FROM", raising=False)
    monkeypatch.delenv("ALERT_EMAIL_TO", raising=False)
    es = EmailSettings.from_settings(Settings(_env_file=None))
    assert es.enabled and es.sender == "me@gmail.com"  # From defaults to the Gmail login
    assert es.recipients == ["vasan.akxy@gmail.com"]   # default recipient
    assert (es.host, es.port, es.use_tls) == ("smtp.gmail.com", 587, True)
    assert es.password.get_secret_value() == APP_PASSWORD.replace(" ", "")  # Gmail display spaces removed


async def test_suite_guard_blocks_real_smtp():
    """Without an injected fake, the notifier hits conftest's blocker, never the network."""
    import conftest

    n = EmailNotifier(email_settings(), base_backoff=0.01, max_attempts=1)  # no smtp_factory
    await n.start()
    n.notify_incident(*bulk_access())
    await n.stop()
    assert n.status.failed == 1 and "blocked during tests" in n.status.last_error
    assert conftest._RealSmtpBlocked.attempts == [("smtp.gmail.com", 587)]
    conftest._RealSmtpBlocked.attempts.clear()  # expected here; any other attempt fails the test


def test_email_status_api_never_returns_the_password(tmp_path: Path):
    from fastapi.testclient import TestClient

    from app.main import create_app

    settings = Settings(
        aws_mode="off", email_enabled=True, smtp_username="me@gmail.com", smtp_password=APP_PASSWORD,
        log_dir=tmp_path / "logs", db_path=tmp_path / "m.db", control_file=tmp_path / "control.json",
    )
    settings.log_dir.mkdir(parents=True)
    for name in ("app.log", "audit.log"):
        (settings.log_dir / name).write_text("", encoding="utf-8")
    app = create_app(settings=settings, config=load_config())
    with TestClient(app) as client:
        body = client.get("/api/notifications/email").json()
        config = client.get("/api/config").text
        health = client.get("/api/health").json()
    assert body["enabled"] is True and body["configured"] is True
    assert body["recipients"] == ["vasan.akxy@gmail.com"] and body["sender"] == "me@gmail.com"
    assert APP_PASSWORD not in json.dumps(body) and APP_PASSWORD not in config
    assert "password" not in json.dumps(body).lower()
    assert health["email_enabled"] is True


# -- Brevo HTTPS API transport (urlopen faked: nothing leaves the machine) -------

import io  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

BREVO_KEY = "xkeysib-" + "0" * 64 + "-FAKEFAKEFAKE"


class FakeBrevo:
    """Stands in for urllib.request.urlopen. ``responses`` are consumed per call:
    an int is an HTTP error status, an Exception is raised, None means 201."""

    def __init__(self, responses=None):
        self.requests = []
        self.responses = list(responses or [])

    def __call__(self, request, timeout=None, context=None):
        self.requests.append(request)
        nxt = self.responses.pop(0) if self.responses else None
        if isinstance(nxt, BaseException):
            raise nxt
        if isinstance(nxt, int):
            body = json.dumps({"code": "unauthorized" if nxt == 401 else "error",
                               "message": f"Key not found {BREVO_KEY}" if nxt == 401 else "server error"})
            raise urllib.error.HTTPError(request.full_url, nxt, "err", {}, io.BytesIO(body.encode()))
        return io.BytesIO(b'{"messageId":"<1@smtp-relay.mailin.fr>"}')


def brevo_notifier(**overrides) -> EmailNotifier:
    base = dict(provider="brevo", api_key=SecretStr(BREVO_KEY), sender="sender@example.com",
                username="", password=SecretStr(""))
    base.update(overrides)
    return EmailNotifier(email_settings(**base), app_config=load_config(), base_backoff=0.01)


async def test_brevo_sends_the_alert_through_the_https_api(monkeypatch):
    fake = FakeBrevo()
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    n = brevo_notifier()
    await n.start()
    n.notify_incident(*bulk_access("CRITICAL"))
    await n.stop()

    [req] = fake.requests
    assert req.full_url == "https://api.brevo.com/v3/smtp/email" and req.get_method() == "POST"
    assert req.get_header("Api-key") == BREVO_KEY
    payload = json.loads(req.data)
    assert payload["sender"]["email"] == "sender@example.com"
    assert payload["to"] == [{"email": "vasan.akxy@gmail.com"}]
    assert payload["subject"] == "[HEALTHTRACE] CRITICAL Security Alert: Bulk PHI Access Detected - U-117"
    assert "user U-117 accessed 201 patients" in payload["textContent"]
    assert "Bulk PHI Access Detected" in payload["htmlContent"]
    assert n.status.sent == 1 and FakeSMTP.instances == []


async def test_brevo_test_email_payload_has_no_blank_fields(monkeypatch):
    """Regression: the manual test email sent ``"headers": {}``, which Brevo
    rejects with HTTP 400 missing_parameter "headers is blank"."""
    fake = FakeBrevo()
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    n = brevo_notifier()
    ok, error = await n.send_test_email()
    assert ok and error is None
    payload = json.loads(fake.requests[0].data)
    assert "headers" not in payload
    blank = [k for k, v in payload.items() if v in ("", {}, [], None)]
    assert blank == [], f"blank fields would be rejected by Brevo: {blank}"
    assert payload["textContent"].startswith("HEALTHTRACE TEST EMAIL")
    assert payload["to"] == [{"email": "vasan.akxy@gmail.com"}]

    for incident_alert in (bulk_access("CRITICAL"), prior_auth("HIGH")):  # real alerts too
        fake.requests.clear()
        await n._send_with_retry(n.build_message(*incident_alert))
        payload = json.loads(fake.requests[0].data)
        assert [k for k, v in payload.items() if v in ("", {}, [], None)] == []


@pytest.mark.parametrize("severity", ["LOW", "MEDIUM"])
async def test_brevo_low_and_medium_send_nothing(monkeypatch, severity):
    fake = FakeBrevo()
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    n = brevo_notifier()
    await n.start()
    n.notify_incident(*prior_auth(severity))
    await n.stop()
    assert fake.requests == []


async def test_brevo_bad_key_is_not_retried_and_never_leaks_the_key(monkeypatch):
    fake = FakeBrevo([401])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    n = brevo_notifier()
    await n.start()
    n.notify_incident(*bulk_access())
    await n.stop()
    assert len(fake.requests) == 1 and n.status.failed == 1
    assert "401" in n.status.last_error and "BREVO_API_KEY" in n.status.last_error
    assert BREVO_KEY not in json.dumps(n.status_dict())


async def test_brevo_outage_is_retried_and_bounded(monkeypatch):
    fake = FakeBrevo([503, urllib.error.URLError("timed out"), None])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    n = brevo_notifier()
    await n.start()
    n.notify_incident(*bulk_access())
    await n.stop()
    assert (len(fake.requests), n.status.sent, n.status.retries) == (3, 1, 2)

    fake = FakeBrevo([503, 503, 503])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    n = brevo_notifier()
    await n.start()
    n.notify_incident(*bulk_access())
    await n.stop()
    assert (len(fake.requests), n.status.failed) == (3, 1)  # no infinite retry


def test_brevo_missing_key_or_sender_is_reported_clearly():
    n = brevo_notifier(api_key=SecretStr(""), sender="")
    assert n.missing_settings() == ["BREVO_API_KEY", "ALERT_EMAIL_FROM"]
    assert "setup_email.py" in n.config_warnings()[0]
    status = n.status_dict()
    assert status["provider"] == "brevo" and status["configured"] is False


def test_brevo_settings_from_env(monkeypatch):
    monkeypatch.setenv("EMAIL_ENABLED", "true")
    monkeypatch.setenv("EMAIL_PROVIDER", "brevo")
    monkeypatch.setenv("BREVO_API_KEY", f"  {BREVO_KEY}  ")
    monkeypatch.setenv("ALERT_EMAIL_FROM", "sender@example.com")
    monkeypatch.delenv("ALERT_EMAIL_TO", raising=False)
    s = Settings(_env_file=None)
    assert BREVO_KEY not in repr(s)
    es = EmailSettings.from_settings(s)
    assert (es.provider, es.sender, es.recipients) == ("brevo", "sender@example.com", ["vasan.akxy@gmail.com"])
    assert es.api_key.get_secret_value() == BREVO_KEY  # whitespace trimmed
    assert EmailNotifier(es).configured
