"""Suite-wide safety net: no test may ever send a real email.

A developer's local .env may have EMAIL_ENABLED=true and a real Gmail App
Password. Settings() reads that file, so without this every pipeline/API
test that produces a HIGH alert could email the real recipient. Two layers:

1. EMAIL_ENABLED=false and an empty SMTP_PASSWORD in the process
   environment, which takes precedence over .env (tests that need email
   pass ``email_enabled=True`` explicitly, which takes precedence over both).
2. smtplib.SMTP / SMTP_SSL and urllib.request.urlopen (the Brevo API
   transport) replaced by stubs that refuse to connect and fail the test if
   anything tried. Tests inject their own fakes.
"""

from __future__ import annotations

import smtplib
import urllib.request

import pytest


class _RealSmtpBlocked:
    attempts: list[tuple] = []

    def __init__(self, host, port=0, *args, **kwargs):
        _RealSmtpBlocked.attempts.append((host, port))
        raise ConnectionRefusedError("real SMTP is blocked during tests")


def _blocked_urlopen(request, *args, **kwargs):
    url = getattr(request, "full_url", request)
    _RealSmtpBlocked.attempts.append(("http", url))
    raise ConnectionRefusedError("real HTTP email API calls are blocked during tests")


@pytest.fixture(autouse=True)
def _never_send_real_email(monkeypatch):
    monkeypatch.setenv("EMAIL_ENABLED", "false")
    monkeypatch.setenv("SMTP_PASSWORD", "")
    monkeypatch.setenv("BREVO_API_KEY", "")
    monkeypatch.setattr(smtplib, "SMTP", _RealSmtpBlocked)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _RealSmtpBlocked)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked_urlopen)
    _RealSmtpBlocked.attempts = []
    yield
    assert not _RealSmtpBlocked.attempts, f"a test tried to reach a real mail server/API: {_RealSmtpBlocked.attempts}"
