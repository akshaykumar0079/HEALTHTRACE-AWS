"""Email notifications for HIGH/CRITICAL incidents. Independent of AWS:
works with AWS_MODE=off|mock|live.

Two transports, chosen by EMAIL_PROVIDER, sharing everything else (queue,
retry, message content, status):
- ``brevo``: Brevo's transactional email HTTPS API. One API key, no SMTP
  ports, no Gmail App Password; free tier is enough for a demo.
- ``smtp``: any SMTP server (Gmail by default).

Same shape as the AWS notifier: ``notify_incident`` only does a
``put_nowait`` on an unbounded queue, and a single worker sends with a small
bounded retry (3 attempts, exponential backoff). An SMTP outage therefore
never blocks detection, the dashboard or the WebSocket stream, and a failing
message is logged, counted and dropped rather than retried forever.

*When* to email is decided by the incident engine, exactly as for SNS: the
pipeline calls ``notify_incident`` only when an incident is opened or
escalated (so cooldown, de-duplication and mute are respected). This module
re-checks severity (HIGH/CRITICAL) as a safety net.

Secrets: the SMTP password is held as a pydantic ``SecretStr`` and is only
unwrapped inside ``_send_sync``. It never appears in logs, errors, the
status API or the email itself.
"""

from __future__ import annotations

import asyncio
import collections
import html
import json
import logging
import re
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Callable, Literal, Optional
from zoneinfo import ZoneInfo

from pydantic import SecretStr

from app.models import Alert, Incident
from app.notify.aws import ChannelStatus

logger = logging.getLogger(__name__)

EMAIL_SEVERITIES = ("HIGH", "CRITICAL")
# Only these can be chosen as the minimum: email stays an alert channel for
# serious incidents, never a LOW/MEDIUM firehose.
ALLOWED_MIN_SEVERITIES = ("HIGH", "CRITICAL")
MAX_RECIPIENTS = 5
DEFAULT_COOLDOWN_SECONDS = 300
MAX_COOLDOWN_SECONDS = 24 * 3600
# Hard flood guard regardless of settings: no more than this many alert emails per rolling hour.
MAX_EMAILS_PER_HOUR = 30
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")


def severities_at_or_above(minimum: str) -> tuple[str, ...]:
    return EMAIL_SEVERITIES[EMAIL_SEVERITIES.index(minimum):] if minimum in EMAIL_SEVERITIES else EMAIL_SEVERITIES


def parse_recipients(raw: "str | list[str]") -> list[str]:
    """Validate a recipient list (comma-separated string or list). Raises ValueError with a safe message."""
    items = [r.strip() for r in (raw.split(",") if isinstance(raw, str) else raw) if r and r.strip()]
    if not items:
        raise ValueError("at least one recipient email address is required")
    if len(items) > MAX_RECIPIENTS:
        raise ValueError(f"at most {MAX_RECIPIENTS} recipients are allowed")
    seen: list[str] = []
    for item in items:
        if len(item) > 254 or not _EMAIL_RE.match(item) or ".." in item:
            raise ValueError(f"not a valid email address: {item[:60]!r}")
        if item.lower() not in (x.lower() for x in seen):
            seen.append(item)
    return seen
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
EmailProvider = Literal["smtp", "brevo"]
MAX_ATTEMPTS = 3
BASE_BACKOFF_SECONDS = 2.0
STOP_DRAIN_TIMEOUT_SECONDS = 10.0

_TITLES: dict[str, str] = {
    "error_rate": "Error Rate Spike Detected",
    "latency_degradation": "Latency Degradation Detected",
    "hipaa_bulk_access": "Bulk PHI Access Detected",
    "hipaa_bulk_export": "Bulk PHI Export Detected",
    "hipaa_off_hours": "Off-Hours PHI Access Detected",
    "hipaa_region_mismatch": "Cross-Region PHI Access Detected",
    "auth_suspicious_login": "Suspicious Login Detected",
}

# SMTP errors that will not fix themselves on retry.
_PERMANENT_ERRORS = (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused,
                     smtplib.SMTPSenderRefused, smtplib.SMTPNotSupportedError)


class BrevoApiError(RuntimeError):
    """A non-2xx answer from the Brevo API (message is credential-free)."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"Brevo API HTTP {status}: {detail}")
        self.status = status

    @property
    def permanent(self) -> bool:
        # Bad key, unverified sender, invalid payload: retrying won't help.
        # 429 (rate limit) and 5xx are worth retrying.
        return 400 <= self.status < 500 and self.status != 429


def _tls_context() -> ssl.SSLContext:
    """Prefer certifi's CA bundle: python.org builds on macOS often have no
    system CA store configured, which breaks HTTPS with CERTIFICATE_VERIFY_FAILED."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


@dataclass
class EmailSettings:
    enabled: bool = False
    provider: EmailProvider = "smtp"
    api_key: SecretStr = field(default_factory=lambda: SecretStr(""))
    host: str = "smtp.gmail.com"
    port: int = 587
    use_tls: bool = True
    username: str = ""
    password: SecretStr = field(default_factory=lambda: SecretStr(""))
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    timeout_seconds: float = 15.0
    display_timezone: str = "Asia/Kolkata"
    dashboard_url: str = ""
    min_severity: str = "HIGH"
    # Minimum seconds between emails for the same incident fingerprint
    # (escalations to a higher severity bypass it). 0 disables.
    cooldown_seconds: int = 0
    max_per_hour: int = MAX_EMAILS_PER_HOUR

    @classmethod
    def from_settings(cls, s: Any) -> "EmailSettings":
        password = s.smtp_password
        if s.smtp_host.strip().lower() == "smtp.gmail.com":
            # Google shows App Passwords as "abcd efgh ijkl mnop"; the real
            # password has no spaces, so accept it pasted either way.
            password = SecretStr(password.get_secret_value().replace(" ", ""))
        provider = s.email_provider
        return cls(
            enabled=s.email_enabled,
            provider=provider,
            api_key=SecretStr(s.brevo_api_key.get_secret_value().strip()),
            host=s.smtp_host.strip(),
            port=s.smtp_port,
            use_tls=s.smtp_use_tls,
            username=s.smtp_username.strip(),
            password=password,
            # Brevo needs an explicit, verified sender; SMTP defaults to the login.
            sender=(s.alert_email_from or ("" if provider == "brevo" else s.smtp_username)).strip(),
            recipients=[r.strip() for r in s.alert_email_to.split(",") if r.strip()],
            timeout_seconds=s.smtp_timeout_seconds,
            display_timezone=s.alert_email_timezone,
            dashboard_url=s.dashboard_url.rstrip("/"),
            min_severity=getattr(s, "email_min_severity", "HIGH"),
            cooldown_seconds=getattr(s, "email_cooldown_seconds", DEFAULT_COOLDOWN_SECONDS),
        )


class EmailNotConfigured(RuntimeError):
    pass


class EmailNotifier:
    def __init__(
        self,
        settings: EmailSettings,
        *,
        app_config: Any = None,
        max_attempts: int = MAX_ATTEMPTS,
        base_backoff: float = BASE_BACKOFF_SECONDS,
        smtp_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.settings = settings
        self.app_config = app_config
        self.max_attempts = max_attempts
        self.base_backoff = base_backoff
        # Injected in tests; resolved at send time otherwise, so patching
        # smtplib (the test-suite guard does) always takes effect.
        self._smtp_factory = smtp_factory
        # Applied to text leaving the process; the pipeline sets the redactor.
        self.redact: Callable[[Any], Any] = lambda value: value
        self._queue: "asyncio.Queue[tuple[Incident, Alert, bool]]" = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self.status = ChannelStatus()
        self._last_sent_by_fp: dict[str, datetime] = {}
        self._sent_times: "collections.deque[datetime]" = collections.deque()
        self.last_test_at: Optional[datetime] = None
        # Called with a dict after each final outcome (accepted/failed/skipped);
        # the pipeline uses it to persist notification_attempts. May be sync or async.
        self.attempt_hook: Optional[Callable[[dict[str, Any]], Any]] = None
        self.last_provider_message_id: Optional[str] = None

    # -- configuration -------------------------------------------------------

    def missing_settings(self) -> list[str]:
        s = self.settings
        missing = []
        if s.provider == "brevo":
            if not s.api_key.get_secret_value():
                missing.append("BREVO_API_KEY")
            if not s.sender:
                missing.append("ALERT_EMAIL_FROM")
        else:
            if not s.host:
                missing.append("SMTP_HOST")
            if not s.username:
                missing.append("SMTP_USERNAME")
            if not s.password.get_secret_value():
                missing.append("SMTP_PASSWORD")
        if not s.recipients:
            missing.append("ALERT_EMAIL_TO")
        return missing

    @property
    def configured(self) -> bool:
        return not self.missing_settings()

    def config_warnings(self) -> list[str]:
        if not self.settings.enabled:
            return []
        warnings = []
        missing = self.missing_settings()
        if missing:
            warnings.append(
                f"EMAIL_ENABLED=true but {', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not set: "
                "alert emails will be skipped ("
                + ("run `python scripts/setup_email.py` to set them"
                   if self.settings.provider == "brevo"
                   else "set them in your local .env; SMTP_PASSWORD must be a Gmail App Password")
                + ")"
            )
        if self.settings.provider == "smtp" and not self.settings.use_tls and self.settings.port != 465:
            warnings.append("SMTP_USE_TLS=false: the password would be sent unencrypted (Gmail requires TLS)")
        return warnings

    def status_dict(self) -> dict[str, Any]:
        """Safe for the API: never includes the password."""
        s = self.settings
        brevo = s.provider == "brevo"
        return {
            "enabled": s.enabled,
            "provider": s.provider,
            "configured": self.configured,
            "missing": self.missing_settings() if s.enabled else [],
            "host": "api.brevo.com" if brevo else s.host,
            "port": 443 if brevo else s.port,
            "use_tls": True if brevo else s.use_tls,
            "sender": s.sender or None,
            "recipients": s.recipients,
            "severities": list(severities_at_or_above(s.min_severity)),
            "min_severity": s.min_severity,
            "cooldown_seconds": s.cooldown_seconds,
            "max_per_hour": s.max_per_hour,
            "sent_last_hour": self._sent_in_last_hour(),
            "last_provider_message_id": self.last_provider_message_id,
            # Honest wording: a 2xx from the provider means it ACCEPTED the message
            # for sending. HEALTHTRACE cannot see inbox delivery.
            "delivery_confirmed": False,
            "delivery_note": ("'sent' means the provider accepted the message; it does not guarantee inbox delivery. "
                              "Check the provider's dashboard for delivery status."),
            "queue_depth": self._queue.qsize(),
            "config_warnings": self.config_warnings(),
            **self.status.to_dict(),
        }

    # -- lifecycle -------------------------------------------------------------

    async def start(self) -> None:
        for warning in self.config_warnings():
            logger.warning("email notifier: %s", warning)
        if self._worker_task is None:
            # The worker always runs (idle when disabled) so the channel can be
            # switched on from Settings without a restart.
            if self.settings.enabled and self.configured:
                via = "Brevo API" if self.settings.provider == "brevo" else f"{self.settings.host}:{self.settings.port}"
                logger.info("email notifier: enabled, HIGH/CRITICAL incidents -> %s via %s",
                            ", ".join(self.settings.recipients), via)
            self._worker_task = asyncio.create_task(self._run())

    async def stop(self, drain_timeout: float = STOP_DRAIN_TIMEOUT_SECONDS) -> None:
        if self._worker_task is not None:
            try:
                await asyncio.wait_for(self._queue.join(), timeout=drain_timeout)
            except asyncio.TimeoutError:
                logger.warning("email notifier: shutdown with %d emails unsent", self._queue.qsize())
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    # -- producer --------------------------------------------------------------

    def notify_incident(self, incident: Incident, alert: Alert, *, escalated: bool = False) -> None:
        """Call on incident creation or escalation, like SNS. Never blocks."""
        if not self.settings.enabled:
            return
        if incident.peak_severity not in severities_at_or_above(self.settings.min_severity):
            return
        subject = self._subject(incident, alert, escalated)
        if not self.configured:
            self._skip(incident, subject, f"not configured: {', '.join(self.missing_settings())} missing")
            return
        now = datetime.now(timezone.utc)
        if self._sent_in_last_hour(now) + self._queue.qsize() >= self.settings.max_per_hour:
            self._skip(incident, subject, f"flood guard: {self.settings.max_per_hour} emails per hour reached")
            return
        cooldown = self.settings.cooldown_seconds
        last = self._last_sent_by_fp.get(incident.fingerprint)
        if cooldown > 0 and not escalated and last is not None and (now - last).total_seconds() < cooldown:
            self._skip(incident, subject, f"cooldown: another email for this incident was sent within {cooldown}s")
            return
        self._last_sent_by_fp[incident.fingerprint] = now
        self._queue.put_nowait((incident, alert, escalated))

    def _skip(self, incident: Incident, subject: str, reason: str) -> None:
        self.status.record("skipped", subject, reason)
        self._emit({"kind": "incident", "status": "skipped", "incident_id": incident.id,
                    "severity": incident.peak_severity, "detail": reason})

    def _sent_in_last_hour(self, now: Optional[datetime] = None) -> int:
        now = now or datetime.now(timezone.utc)
        while self._sent_times and (now - self._sent_times[0]).total_seconds() > 3600:
            self._sent_times.popleft()
        return len(self._sent_times)

    def _emit(self, info: dict[str, Any]) -> None:
        hook = self.attempt_hook
        if hook is None:
            return
        info = {"provider": self.settings.provider, **info}
        try:
            result = hook(info)
            if asyncio.iscoroutine(result):
                asyncio.ensure_future(result)
        except Exception:  # persistence must never break sending
            logger.exception("email notifier: attempt hook failed")

    # -- runtime preferences (Settings -> Notifications) ---------------------------

    def apply_prefs(self, *, enabled: bool, recipients: list[str], min_severity: str, cooldown_seconds: int) -> None:
        if min_severity not in ALLOWED_MIN_SEVERITIES:
            raise ValueError(f"min_severity must be one of {list(ALLOWED_MIN_SEVERITIES)}")
        if not 0 <= cooldown_seconds <= MAX_COOLDOWN_SECONDS:
            raise ValueError(f"cooldown_seconds must be between 0 and {MAX_COOLDOWN_SECONDS}")
        self.settings.enabled = enabled
        self.settings.recipients = parse_recipients(recipients)
        self.settings.min_severity = min_severity
        self.settings.cooldown_seconds = cooldown_seconds

    # -- worker ------------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            incident, alert, escalated = await self._queue.get()
            try:
                await self._send_with_retry(
                    self.build_message(incident, alert, escalated=escalated),
                    context={"kind": "incident", "incident_id": incident.id, "severity": incident.peak_severity},
                )
            except Exception:
                logger.exception("email notifier: unexpected error for incident #%s", incident.id)
            finally:
                self._queue.task_done()

    async def _send_with_retry(self, message: EmailMessage, context: Optional[dict[str, Any]] = None) -> bool:
        subject = str(message["Subject"])
        context = context or {"kind": "test"}
        for attempt in range(1, self.max_attempts + 1):
            try:
                message_id = await asyncio.to_thread(self._send_sync, message)
                self.last_provider_message_id = message_id or None
                self._sent_times.append(datetime.now(timezone.utc))
                self.status.record("sent", subject)
                self._emit({**context, "status": "accepted", "provider_message_id": message_id,
                            "detail": f"accepted by {self.settings.provider} (not a delivery confirmation)"})
                logger.info("email notifier: sent %r to %s", subject, message["To"])
                return True
            except Exception as exc:
                error = self._describe_error(exc)
                permanent = isinstance(exc, (_PERMANENT_ERRORS, EmailNotConfigured)) or (
                    isinstance(exc, BrevoApiError) and exc.permanent)
                if permanent or attempt == self.max_attempts:
                    logger.error("email notifier: failed to send %r after %d attempt(s): %s", subject, attempt, error)
                    self.status.record("failed", subject, error)
                    self._emit({**context, "status": "failed", "detail": error})
                    return False
                self.status.retries += 1
                logger.warning("email notifier: attempt %d failed (%s), retrying", attempt, error)
                await asyncio.sleep(self.base_backoff * (2 ** (attempt - 1)))
        return False

    def _send_sync(self, message: EmailMessage) -> Optional[str]:
        s = self.settings
        if not self.configured:
            raise EmailNotConfigured(f"{', '.join(self.missing_settings())} not set")
        if s.provider == "brevo":
            return self._send_brevo(message)
        password = s.password.get_secret_value()
        context = ssl.create_default_context()
        if s.port == 465:
            factory = self._smtp_factory or smtplib.SMTP_SSL
            server = factory(s.host, s.port, timeout=s.timeout_seconds, context=context)
        else:
            factory = self._smtp_factory or smtplib.SMTP
            server = factory(s.host, s.port, timeout=s.timeout_seconds)
        try:
            server.ehlo()
            if s.use_tls and s.port != 465:
                server.starttls(context=context)
                server.ehlo()
            server.login(s.username, password)
            server.send_message(message)
        finally:
            try:
                server.quit()
            except Exception:
                pass
        return str(message["Message-ID"] or "") or None

    def _send_brevo(self, message: EmailMessage) -> Optional[str]:
        """POST the already-built message to Brevo's transactional API."""
        s = self.settings
        text = message.get_body(preferencelist=("plain",))
        html_part = message.get_body(preferencelist=("html",))
        payload: dict[str, Any] = {
            "sender": {"name": "HEALTHTRACE Alerts", "email": s.sender},
            "to": [{"email": r} for r in s.recipients],
            "subject": str(message["Subject"]),
            "textContent": text.get_content() if text is not None else "",
            # No "headers" field: Brevo rejects an empty one ("headers is blank",
            # as the test email had), and the incident ID is already in the body.
        }
        if html_part is not None and html_part is not text:
            payload["htmlContent"] = html_part.get_content()
        request = urllib.request.Request(
            BREVO_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "api-key": s.api_key.get_secret_value(),
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "healthtrace-alerts",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=s.timeout_seconds, context=_tls_context()) as resp:
                raw = resp.read()
            try:
                # Brevo answers 201 {"messageId": "<...>"}: proof of acceptance, not of delivery.
                message_id = json.loads(raw.decode("utf-8", "replace") or "{}").get("messageId")
                return str(message_id)[:200] if message_id else None
            except Exception:
                return None
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                body = json.loads(exc.read().decode("utf-8", "replace") or "{}")
                detail = " - ".join(str(body[k]) for k in ("code", "message") if body.get(k))
            except Exception:
                pass
            raise BrevoApiError(exc.code, detail or exc.reason or "error") from None

    def _describe_error(self, exc: BaseException) -> str:
        """A short, credential-free description of an SMTP failure."""
        if isinstance(exc, BrevoApiError):
            text = str(exc)
            if exc.status == 401:
                text += " (BREVO_API_KEY is wrong or revoked: create a new API key in Brevo and run scripts/setup_email.py)"
            elif exc.status == 400 and "sender" in text.lower():
                text += " (ALERT_EMAIL_FROM must be a sender verified in Brevo, e.g. the email you signed up with)"
            elif exc.status == 403:
                text += " (Brevo has not activated sending on this account yet, or this IP is not authorised: check Brevo's dashboard)"
        elif isinstance(exc, urllib.error.URLError):
            text = f"cannot reach Brevo API: {exc.reason}"
        elif isinstance(exc, smtplib.SMTPAuthenticationError):
            text = ("SMTP login rejected (535). Check SMTP_USERNAME and that SMTP_PASSWORD is a 16-character "
                    "Gmail App Password with 2-Step Verification on, not your normal password")
        elif isinstance(exc, smtplib.SMTPResponseException):
            detail = exc.smtp_error.decode("utf-8", "replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
            text = f"{type(exc).__name__} {exc.smtp_code}: {detail[:160]}"
        elif isinstance(exc, smtplib.SMTPRecipientsRefused):
            text = f"recipient(s) refused: {', '.join(exc.recipients)}"
        else:
            text = f"{type(exc).__name__}: {str(exc)[:160]}"
        for secret in (self.settings.password.get_secret_value(), self.settings.api_key.get_secret_value()):
            if secret:
                text = text.replace(secret, "***")
        return " ".join(text.split())

    # -- message -----------------------------------------------------------------

    def _subject(self, incident: Incident, alert: Alert, escalated: bool) -> str:
        title = _TITLES.get(incident.kind, incident.kind)
        target = incident.service or incident.user_id or "unknown"
        prefix = f"[HEALTHTRACE] {incident.peak_severity} Security Alert"
        return f"{prefix}{' (escalated)' if escalated else ''}: {title} - {target}"

    def build_message(self, incident: Incident, alert: Alert, *, escalated: bool = False) -> EmailMessage:
        s = self.settings
        rows = [(label, self.redact(value)) for label, value in self._rows(incident, alert, escalated)]

        text_lines = ["HEALTHTRACE SECURITY ALERT", ""]
        for label, value in rows:
            text_lines += [f"{label}:", value, ""]
        text_lines.append("This alert was generated automatically by HEALTHTRACE. All data is synthetic.")

        sev_color = {"CRITICAL": "#b42318", "HIGH": "#c4320a"}.get(incident.peak_severity, "#344054")
        html_rows = "".join(
            f'<tr><td style="padding:8px 12px;color:#475467;vertical-align:top;white-space:nowrap">{html.escape(label)}</td>'
            f'<td style="padding:8px 12px;color:#101828;white-space:pre-wrap">{html.escape(value)}</td></tr>'
            for label, value in rows
        )
        html_body = (
            '<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:640px">'
            f'<div style="background:{sev_color};color:#fff;padding:14px 16px;border-radius:8px 8px 0 0">'
            f'<div style="font-size:12px;letter-spacing:.08em">HEALTHTRACE SECURITY ALERT</div>'
            f'<div style="font-size:20px;font-weight:600;margin-top:4px">{html.escape(incident.peak_severity)} - '
            f'{html.escape(_TITLES.get(incident.kind, incident.kind))}</div></div>'
            f'<table style="border-collapse:collapse;width:100%;border:1px solid #eaecf0;font-size:14px">{html_rows}</table>'
            '<p style="color:#667085;font-size:12px">This alert was generated automatically by HEALTHTRACE. '
            'All data is synthetic.</p></div>'
        )

        msg = EmailMessage()
        msg["Subject"] = self._subject(incident, alert, escalated)
        msg["From"] = f"HEALTHTRACE Alerts <{s.sender}>" if s.sender else "HEALTHTRACE Alerts"
        msg["To"] = ", ".join(s.recipients)
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = make_msgid(domain="healthtrace.local")
        msg["X-HEALTHTRACE-Incident"] = str(incident.id)
        msg.set_content("\n".join(text_lines))
        msg.add_alternative(html_body, subtype="html")
        return msg

    def _rows(self, incident: Incident, alert: Alert, escalated: bool) -> list[tuple[str, str]]:
        m = alert.metrics or {}
        rows: list[tuple[str, str]] = [
            ("Severity", incident.peak_severity + (" (escalated)" if escalated else "")),
            ("Incident", _TITLES.get(incident.kind, incident.kind)),
            ("Timestamp", self._format_ts(alert.ts)),
            ("Description", alert.explanation),
            ("Detection Reason", self._reason(alert)),
            ("Affected Data", self._affected(alert)),
        ]
        metrics = self._metrics(alert, m)
        if metrics:
            rows.append(("Metrics", metrics))
        rows.append(("Recommended Action", self._action(alert)))
        incident_line = (
            f"#{incident.id} - state {incident.state}, {incident.alert_count} alert(s), "
            f"opened {self._format_ts(incident.opened_at)}"
        )
        rows.append(("Incident ID", incident_line))
        if self.settings.dashboard_url and incident.id is not None:
            rows.append(("Open in HEALTHTRACE", f"{self.settings.dashboard_url}/app/anomalies/{incident.id}"))
        return rows

    def _format_ts(self, ts: datetime) -> str:
        utc = ts.astimezone(timezone.utc)
        out = utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            local = utc.astimezone(ZoneInfo(self.settings.display_timezone))
            out += f" ({local.strftime('%Y-%m-%d %H:%M:%S %Z')})"
        except Exception:
            pass
        return out

    def _service_label(self, service: Optional[str]) -> str:
        if not service:
            return "unknown service"
        svc = getattr(self.app_config, "services", {}).get(service) if self.app_config else None
        if svc is not None and svc.label:
            return f"{svc.label} ({service}, criticality {svc.criticality:g})"
        return service

    def _reason(self, alert: Alert) -> str:
        cfg = self.app_config
        a = getattr(cfg, "anomaly", None)
        h = getattr(cfg, "hipaa", None)
        kind = alert.kind
        if kind == "error_rate":
            extra = (f" (z >= {a.error_rate_z_threshold:g}, at least {a.error_rate_min_errors} errors and "
                     f"{a.error_rate_min_rate:.0%} error rate in the 60s window)") if a else ""
            return ("Error rate in the 60-second sliding window rose above this service's learned EWMA "
                    f"baseline for this hour of day{extra}.")
        if kind == "latency_degradation":
            extra = f" (z >= {a.latency_z_threshold:g})" if a else ""
            return ("p95 latency in the 60-second sliding window rose above this service's learned EWMA "
                    f"baseline for this hour of day{extra}.")
        if kind == "hipaa_bulk_access":
            extra = (f" HIGH above {h.bulk_multiplier_high:g}x, CRITICAL above {h.bulk_multiplier_critical:g}x."
                     if h else "")
            return "User accessed far more distinct patient records in 10 minutes than their own learned baseline." + extra
        if kind == "hipaa_bulk_export":
            extra = f" CRITICAL above {h.export_critical_records} records." if h else ""
            return "User exported an unusually large number of patient records." + extra
        if kind == "hipaa_off_hours":
            extra = f" (business hours end {h.off_hours_start}, resume {h.off_hours_end}, {h.timezone})" if h else ""
            return "Patient records accessed outside business hours" + extra + "."
        if kind == "hipaa_region_mismatch":
            return "User accessed records of patients registered in a different region from their own."
        if kind == "auth_suspicious_login":
            return ("A successful login followed repeated failed logins for the same user within the rolling "
                    "window; it is more serious when it comes from an unfamiliar region.")
        return alert.kind

    def _affected(self, alert: Alert) -> str:
        m = alert.metrics or {}
        if alert.service:
            parts = [f"Service: {self._service_label(alert.service)}"]
            urgent, routine = m.get("affected_patients_urgent"), m.get("affected_patients_routine")
            if urgent is not None or routine is not None:
                parts.append(f"Patients affected in window: {urgent or 0} urgent, {routine or 0} routine")
            if m.get("urgent_errors") is not None:
                parts.append(f"Failed urgent requests: {m['urgent_errors']}")
            return "\n".join(parts)
        parts = [f"User: {alert.user_id or 'unknown'}"]
        if "distinct_patients" in m:
            parts.append(f"Distinct patient records: {m['distinct_patients']}")
        if "records" in m:
            parts.append(f"Records: {m['records']}")
        if "failures" in m:
            parts.append(f"Failed logins before success: {m['failures']}")
        parts.append("Patient identifiers are deliberately not included in this email.")
        return "\n".join(parts)

    @staticmethod
    def _metrics(alert: Alert, m: dict[str, Any]) -> str:
        parts = []
        if alert.service:
            if "error_rate" in m:
                errors = f" ({m.get('errors')} of {m.get('total')} requests)" if m.get("total") is not None else ""
                parts.append(f"Error rate: {float(m['error_rate']):.1%}{errors}")
            if alert.kind == "error_rate" and m.get("baseline_mean") is not None:
                std = m.get("baseline_std")
                parts.append(f"Baseline error rate: {float(m['baseline_mean']):.1%}"
                             + (f" (std {float(std):.1%})" if std is not None else ""))
            if "p95_latency_ms" in m:
                parts.append(f"p95 latency: {float(m['p95_latency_ms']):.0f} ms")
            if alert.score:
                parts.append(f"Severity score: {alert.score:.2f}")
        else:
            if "multiplier" in m:
                parts.append(f"Access vs user's baseline: {float(m['multiplier']):.1f}x")
            for key, label in (("distinct_patients", "Distinct patients"), ("records", "Records")):
                if key in m:
                    parts.append(f"{label}: {m[key]}")
        return "\n".join(parts)

    def _action(self, alert: Alert) -> str:
        kind = alert.kind
        if kind in ("error_rate", "latency_degradation"):
            deps = []
            if self.app_config and alert.service in self.app_config.services:
                deps = self.app_config.services[alert.service].depends_on
            dep_text = f" and its dependencies ({', '.join(deps)})" if deps else ""
            what = "error logs" if kind == "error_rate" else "slow requests and resource saturation"
            return (f"Check the health of {alert.service}{dep_text}; review recent deployments and {what} "
                    "for this window. Acknowledge the incident in HEALTHTRACE once someone owns it.")
        if kind in ("hipaa_bulk_access", "hipaa_bulk_export"):
            return (f"Confirm with {alert.user_id}'s manager whether this access was authorised. If not, suspend "
                    "the account's PHI access, preserve the audit log and start a HIPAA access review.")
        if kind == "hipaa_off_hours":
            return (f"Confirm whether {alert.user_id} was on shift or on call. If not, treat as potential "
                    "unauthorised access: suspend PHI access and review the audit log.")
        if kind == "hipaa_region_mismatch":
            return (f"Verify that {alert.user_id} is assigned to these patients' region; if not, restrict "
                    "access and review the audit log.")
        if kind == "auth_suspicious_login":
            return (f"Contact {alert.user_id} to confirm the login. If it was not them, reset the credentials, "
                    "revoke active sessions and review the audit log.")
        return "Investigate the incident in HEALTHTRACE."

    # -- manual test (scripts/test_email.py) ------------------------------------

    def build_test_message(self) -> EmailMessage:
        s = self.settings
        msg = EmailMessage()
        msg["Subject"] = "[HEALTHTRACE] TEST - email notifications are working"
        msg["From"] = f"HEALTHTRACE Alerts <{s.sender}>" if s.sender else "HEALTHTRACE Alerts"
        msg["To"] = ", ".join(s.recipients)
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = make_msgid(domain="healthtrace.local")
        msg.set_content(
            "HEALTHTRACE TEST EMAIL\n\n"
            f"Sent: {self._format_ts(datetime.now(timezone.utc))}\n"
            + ("Delivered by: Brevo email API\n\n" if s.provider == "brevo" else
               f"SMTP server: {s.host}:{s.port} ({'STARTTLS' if s.use_tls and s.port != 465 else 'SSL' if s.port == 465 else 'no TLS'})\n\n")
            + "This is a manual test. Real alerts are sent only for HIGH and CRITICAL incidents.\n"
        )
        return msg

    async def send_test_email(self) -> tuple[bool, Optional[str]]:
        self.last_test_at = datetime.now(timezone.utc)
        ok = await self._send_with_retry(self.build_test_message(), context={"kind": "test"})
        return ok, None if ok else self.status.last_error
