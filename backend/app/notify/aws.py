"""AWS notifications: CloudWatch Logs (every alert) and SNS (HIGH/CRITICAL
incidents only), modes off|mock|live (SPEC.md section 6.9).

Runs its own async queue and worker so a slow or failing AWS call never
blocks the detection pipeline: ``notify_alert``/``notify_incident`` do a
``put_nowait`` on an unbounded queue and return immediately, no matter how
long the worker is currently stuck retrying a previous message. Retries with
exponential backoff, up to 5 attempts, then logs and drops the message
rather than blocking forever.

The caller decides *when* SNS should fire ("on creation or escalation" —
SPEC.md 6.9): this module only re-checks severity as a safety net.

Credentials are never configured here: in live mode boto3 resolves them
through its default chain (ECS task role, instance profile, SSO, env).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional, Union

from app.models import Alert, Incident

logger = logging.getLogger(__name__)

AwsMode = Literal["off", "mock", "live"]
Channel = Literal["cloudwatch", "sns"]
MAX_ATTEMPTS = 5
BASE_BACKOFF_SECONDS = 0.5
STOP_DRAIN_TIMEOUT_SECONDS = 10.0

_KIND_LABELS: dict[str, str] = {
    "error_rate": "error rate spike",
    "latency_degradation": "latency spike",
    "hipaa_bulk_access": "bulk record access",
    "hipaa_bulk_export": "bulk record export",
    "hipaa_off_hours": "off-hours access",
    "hipaa_region_mismatch": "cross-region access",
    "auth_suspicious_login": "suspicious login",
}

_CloudWatchItem = tuple[Literal["cloudwatch"], Alert]
_SnsItem = tuple[Literal["sns"], Incident, str]
_QueueItem = Union[_CloudWatchItem, _SnsItem]


class SnsNotConfigured(RuntimeError):
    pass


@dataclass
class ChannelStatus:
    sent: int = 0
    failed: int = 0
    skipped: int = 0
    retries: int = 0
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error: Optional[str] = None
    recent: list[dict[str, Any]] = field(default_factory=list)

    def record(self, outcome: str, subject: str, error: Optional[str] = None) -> None:
        now = datetime.now(timezone.utc)
        if outcome == "sent":
            self.sent += 1
            self.last_success_at = now
        elif outcome == "failed":
            self.failed += 1
            self.last_failure_at = now
            self.last_error = error
        else:
            self.skipped += 1
        self.recent.append({"ts": now.isoformat(), "outcome": outcome, "subject": subject, "error": error})
        del self.recent[:-25]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "failed": self.failed,
            "skipped": self.skipped,
            "retries": self.retries,
            "last_success_at": self.last_success_at.isoformat() if self.last_success_at else None,
            "last_failure_at": self.last_failure_at.isoformat() if self.last_failure_at else None,
            "last_error": self.last_error,
            "recent": list(reversed(self.recent)),
        }


class AwsNotifier:
    def __init__(
        self,
        mode: AwsMode,
        *,
        region: str = "us-east-1",
        log_group: str = "/medguard/alerts",
        log_stream: str = "",
        sns_topic_arn: str = "",
        mock_log_path: Optional[Path] = None,
        max_attempts: int = MAX_ATTEMPTS,
        base_backoff: float = BASE_BACKOFF_SECONDS,
    ) -> None:
        self.mode = mode
        self.region = region
        self.log_group = log_group
        # Fixed stream name, or "" for one stream per UTC day (the original behaviour).
        self.log_stream = log_stream
        self.sns_topic_arn = sns_topic_arn
        self.mock_log_path = mock_log_path
        self.max_attempts = max_attempts
        self.base_backoff = base_backoff
        # Applied to everything leaving the process (set by the pipeline to the
        # configured redactor); identity by default.
        self.redact: Callable[[Any], Any] = lambda value: value

        self._queue: "asyncio.Queue[_QueueItem]" = asyncio.Queue()  # unbounded: never blocks the producer
        self._worker_task: Optional[asyncio.Task] = None
        self._boto_logs_client = None
        self._boto_sns_client = None
        self._ensured_streams: set[str] = set()
        self._create_group_denied_logged = False
        self.status: dict[Channel, ChannelStatus] = {"cloudwatch": ChannelStatus(), "sns": ChannelStatus()}

    def config_warnings(self) -> list[str]:
        """Misconfigurations worth surfacing before the first alert, not after it fails."""
        if self.mode == "off":
            return []
        warnings: list[str] = []
        if not self.sns_topic_arn:
            warnings.append("SNS_TOPIC_ARN is not set: HIGH/CRITICAL incidents will not be published to SNS")
        else:
            parts = self.sns_topic_arn.split(":")
            if len(parts) != 6 or parts[:3] != ["arn", "aws", "sns"]:
                warnings.append(f"SNS_TOPIC_ARN does not look like an SNS topic ARN: {self.sns_topic_arn!r}")
            elif parts[3] != self.region:
                warnings.append(
                    f"SNS_TOPIC_ARN is in region {parts[3]} but AWS_REGION is {self.region}: publishes will fail"
                )
        if not self.log_group:
            warnings.append("CLOUDWATCH_LOG_GROUP is empty")
        return warnings

    def integration_status(self) -> dict[str, Any]:
        """One honest label for the AWS integration, computed without any AWS call.

        MOCK            AWS_MODE=mock: alerts go to a local file; AWS is not contacted.
        NOT CONFIGURED  AWS_MODE=off (the default), or live with required settings missing.
        CONFIGURED      AWS_MODE=live with settings present. Not proof that AWS accepts them:
                        ``verified`` turns true only after a call succeeded in this process.
        ERROR           AWS_MODE=live and the most recent calls failed with no success since.
        """
        cw, sns = self.status["cloudwatch"], self.status["sns"]
        verified = bool(cw.sent or sns.sent)
        if self.mode == "off":
            return {"status": "NOT CONFIGURED", "verified": False, "calls_aws": False,
                    "detail": "AWS integration is disabled (AWS_MODE=off). No AWS calls are made."}
        if self.mode == "mock":
            return {"status": "MOCK", "verified": False, "calls_aws": False,
                    "detail": "Mock mode: alerts are written to a local file. No AWS calls are made and "
                              "nothing is delivered to CloudWatch or SNS."}
        problems = [w for w in self.config_warnings()]
        if problems:
            return {"status": "NOT CONFIGURED", "verified": False, "calls_aws": True, "detail": problems[0],
                    "problems": problems}
        last_fail = max((c.last_failure_at for c in (cw, sns) if c.last_failure_at), default=None)
        last_ok = max((c.last_success_at for c in (cw, sns) if c.last_success_at), default=None)
        if last_fail and (last_ok is None or last_fail > last_ok):
            err = cw.last_error if cw.last_failure_at == last_fail else sns.last_error
            return {"status": "ERROR", "verified": verified, "calls_aws": True,
                    "detail": f"The latest AWS call failed: {err}"}
        return {"status": "CONFIGURED", "verified": verified, "calls_aws": True,
                "detail": ("AWS calls have succeeded in this session." if verified else
                           "Settings are present but no AWS call has succeeded yet; run the connection test.")}

    async def start(self) -> None:
        for warning in self.config_warnings():
            logger.warning("notifier (AWS_MODE=%s): %s", self.mode, warning)
        if self.mode != "off" and self._worker_task is None:
            self._worker_task = asyncio.create_task(self._run())

    async def stop(self, drain_timeout: float = STOP_DRAIN_TIMEOUT_SECONDS) -> None:
        """Drain pending notifications, but never let a failing AWS endpoint
        hold shutdown hostage beyond ``drain_timeout``."""
        if self._worker_task is not None:
            try:
                await asyncio.wait_for(self._queue.join(), timeout=drain_timeout)
            except asyncio.TimeoutError:
                logger.warning("notifier: shutdown with %d notifications undelivered", self._queue.qsize())
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

    def notify_alert(self, alert: Alert) -> None:
        """CloudWatch Logs: every alert (SPEC.md 6.9)."""
        if self.mode == "off":
            return
        self._queue.put_nowait(("cloudwatch", alert))

    def notify_incident(self, incident: Incident, explanation: str) -> None:
        """SNS: HIGH/CRITICAL only. Call this on incident creation or
        escalation (SPEC.md 6.9) — this method itself just re-checks severity."""
        if self.mode == "off":
            return
        if incident.peak_severity not in ("HIGH", "CRITICAL"):
            return
        self._queue.put_nowait(("sns", incident, explanation))

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def sns_configured(self) -> bool:
        return bool(self.sns_topic_arn)

    # -- worker ------------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                await self._process_with_retry(item)
            except Exception:
                logger.exception("notifier: unexpected error processing %r", item)
            finally:
                self._queue.task_done()

    async def _process_with_retry(self, item: _QueueItem) -> None:
        channel: Channel = item[0]
        subject = self._subject_for(item)
        status = self.status[channel]
        for attempt in range(1, self.max_attempts + 1):
            try:
                if item[0] == "cloudwatch":
                    await self._send_cloudwatch(item[1])
                else:
                    await self._send_sns(item[1], item[2])
                status.record("sent", subject)
                return
            except SnsNotConfigured as exc:
                status.record("skipped", subject, str(exc))
                return
            except Exception as exc:
                if attempt == self.max_attempts:
                    logger.error("notifier: giving up after %d attempts (%s): %s", attempt, channel, exc)
                    status.record("failed", subject, f"{type(exc).__name__}: {exc}")
                    return
                status.retries += 1
                await asyncio.sleep(self.base_backoff * (2 ** (attempt - 1)))

    @staticmethod
    def _subject_for(item: _QueueItem) -> str:
        if item[0] == "cloudwatch":
            alert = item[1]
            return f"{alert.severity} {alert.kind} {alert.service or alert.user_id or ''}".strip()
        incident = item[1]
        return f"incident #{incident.id} {incident.peak_severity}"

    # -- senders -----------------------------------------------------------------

    async def _send_cloudwatch(self, alert: Alert) -> None:
        if self.mode == "mock":
            self._append_mock(
                {"aws_service": "cloudwatch_logs", "log_group": self.log_group,
                 "log_stream": self._stream_for(alert.ts), "alert": self.redact(alert.model_dump(mode="json"))}
            )
            return
        await self._put_log_event(alert.ts, json.dumps(self.redact(alert.model_dump(mode="json"))))

    def _stream_for(self, ts: datetime) -> str:
        return self.log_stream or ts.strftime("%Y-%m-%d")

    async def _put_log_event(self, ts: datetime, message: str) -> None:
        client = self._logs_client()
        stream = self._stream_for(ts)
        await asyncio.to_thread(self._ensure_log_stream, client, stream)
        kwargs = dict(
            logGroupName=self.log_group,
            logStreamName=stream,
            logEvents=[{"timestamp": int(ts.timestamp() * 1000), "message": message}],
        )
        try:
            await asyncio.to_thread(client.put_log_events, **kwargs)
        except Exception as exc:
            if _aws_error_code(exc) != "ResourceNotFoundException":
                raise
            # The group or stream was deleted after we cached it as existing:
            # forget it, recreate, and try once more (the outer retry loop
            # still covers anything that fails after this).
            self._ensured_streams.discard(stream)
            await asyncio.to_thread(self._ensure_log_stream, client, stream)
            await asyncio.to_thread(client.put_log_events, **kwargs)

    async def _send_sns(self, incident: Incident, explanation: str) -> None:
        target = incident.service or incident.user_id or "unknown"
        label = _KIND_LABELS.get(incident.kind, incident.kind)
        subject = f"[MedGuard {incident.peak_severity}] {target}: {label}"[:100]
        body = self.redact(f"{explanation}\n\nIncident ID: {incident.id}")
        await self._publish(subject, body)

    async def _publish(self, subject: str, body: str) -> None:
        if self.mode == "mock":
            self._append_mock(
                {"aws_service": "sns", "topic_arn": self.sns_topic_arn, "subject": subject, "body": body}
            )
            return
        if not self.sns_topic_arn:
            raise SnsNotConfigured("SNS_TOPIC_ARN is not set")
        client = self._sns_client()
        await asyncio.to_thread(client.publish, TopicArn=self.sns_topic_arn, Subject=subject, Message=body)

    def _append_mock(self, payload: dict) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(), **payload}
        line = json.dumps(record, default=str)
        print(f"[aws:mock] {line}")
        if self.mock_log_path is not None:
            self.mock_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.mock_log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    # -- operator actions (AWS page) --------------------------------------------

    async def test_connection(self) -> dict[str, Any]:
        """Read-only reachability check against the configured resources."""
        if self.mode != "live":
            return {
                "mode": self.mode,
                "cloudwatch": {"ok": self.mode == "mock", "detail": f"AWS_MODE={self.mode}: no AWS calls are made"},
                "sns": {"ok": self.mode == "mock", "detail": f"AWS_MODE={self.mode}: no AWS calls are made"},
            }
        return {
            "mode": self.mode,
            "cloudwatch": await self._check(self._check_cloudwatch),
            "sns": await self._check(self._check_sns),
        }

    async def send_test_alert(self) -> dict[str, Any]:
        """Deliver one clearly-labelled test message through each channel,
        bypassing the queue so the operator sees the real outcome."""
        if self.mode == "off":
            return {"mode": self.mode, "cloudwatch": {"ok": False, "detail": "AWS_MODE=off"},
                    "sns": {"ok": False, "detail": "AWS_MODE=off"}}
        now = datetime.now(timezone.utc)
        message = json.dumps({"test": True, "ts": now.isoformat(), "explanation": "HEALTH TRACE test alert"})

        async def cloudwatch() -> str:
            if self.mode == "mock":
                self._append_mock({"aws_service": "cloudwatch_logs", "log_group": self.log_group, "test": True})
                return "written to data/aws_mock.log"
            await self._put_log_event(now, message)
            return f"put 1 event to {self.log_group}"

        async def sns() -> str:
            await self._publish("[MedGuard TEST] HEALTH TRACE test alert", "This is a test notification.")
            return "published" if self.mode == "live" else "written to data/aws_mock.log"

        results = {"mode": self.mode}
        for channel, fn in (("cloudwatch", cloudwatch), ("sns", sns)):
            result = await self._check(fn)
            self.status[channel].record("sent" if result["ok"] else "failed", "test alert",
                                        None if result["ok"] else result["detail"])
            results[channel] = result
        return results

    async def _check(self, fn) -> dict[str, Any]:
        try:
            detail = await asyncio.wait_for(fn(), timeout=10)
            return {"ok": True, "detail": detail}
        except Exception as exc:
            return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}

    async def _check_cloudwatch(self) -> str:
        client = self._logs_client()
        resp = await asyncio.to_thread(client.describe_log_groups, logGroupNamePrefix=self.log_group, limit=1)
        groups = [g["logGroupName"] for g in resp.get("logGroups", [])]
        return f"log group {self.log_group} {'exists' if self.log_group in groups else 'will be created on first alert'}"

    async def _check_sns(self) -> str:
        if not self.sns_topic_arn:
            raise SnsNotConfigured("SNS_TOPIC_ARN is not set")
        client = self._sns_client()
        attrs = await asyncio.to_thread(client.get_topic_attributes, TopicArn=self.sns_topic_arn)
        confirmed = attrs.get("Attributes", {}).get("SubscriptionsConfirmed", "?")
        return f"topic reachable, {confirmed} confirmed subscription(s)"

    def credentials_source(self) -> Optional[str]:
        """Where boto3 found credentials (e.g. 'container-role', 'env') — never the keys."""
        if self.mode != "live":
            return None
        try:
            import boto3

            creds = boto3.Session().get_credentials()
            return creds.method if creds is not None else None
        except Exception:
            return None

    # -- clients -----------------------------------------------------------------

    def _logs_client(self):
        if self._boto_logs_client is None:
            import boto3

            self._boto_logs_client = boto3.client("logs", region_name=self.region)
        return self._boto_logs_client

    def _sns_client(self):
        if self._boto_sns_client is None:
            import boto3

            self._boto_sns_client = boto3.client("sns", region_name=self.region)
        return self._boto_sns_client

    def _ensure_log_stream(self, client, stream: str) -> None:
        if stream in self._ensured_streams:
            return
        try:
            client.create_log_group(logGroupName=self.log_group)
        except Exception as exc:
            code = _aws_error_code(exc)
            if code == "AccessDeniedException":
                # Least-privilege roles (e.g. the CloudFormation task role) may
                # not hold logs:CreateLogGroup because the group is created
                # for them. Carry on: if the group really is missing,
                # create_log_stream below fails with a clear ResourceNotFound.
                if not self._create_group_denied_logged:
                    logger.info("notifier: no logs:CreateLogGroup permission; assuming %s is pre-created",
                                self.log_group)
                    self._create_group_denied_logged = True
            elif code != "ResourceAlreadyExistsException":
                raise
        try:
            client.create_log_stream(logGroupName=self.log_group, logStreamName=stream)
        except Exception as exc:
            if _aws_error_code(exc) != "ResourceAlreadyExistsException":
                raise
        self._ensured_streams.add(stream)


def _aws_error_code(exc: BaseException) -> Optional[str]:
    """The AWS error code of a botocore ClientError (None for anything else)."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None
