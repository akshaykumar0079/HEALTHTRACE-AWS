"""Milestone 5: AWS notifier modes, retry/backoff, and non-blocking queueing
(SPEC.md section 6.9)."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from app.models import Alert, Incident
from app.notify.aws import AwsNotifier

T0 = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def make_alert(severity="HIGH") -> Alert:
    return Alert(ts=T0, kind="error_rate", service="prior_auth", severity=severity, score=0.6, explanation="x")


def make_incident(severity="CRITICAL") -> Incident:
    return Incident(
        id=1, fingerprint="error_rate:prior_auth", kind="error_rate", service="prior_auth",
        state="OPEN", peak_severity=severity, alert_count=1, opened_at=T0,
    )


async def test_off_mode_does_nothing():
    notifier = AwsNotifier("off")
    await notifier.start()
    notifier.notify_alert(make_alert())
    notifier.notify_incident(make_incident(), "explanation")
    assert notifier.queue_depth == 0
    await notifier.stop()


async def test_mock_mode_writes_cloudwatch_and_sns(tmp_path: Path, capsys):
    mock_log = tmp_path / "aws_mock.log"
    notifier = AwsNotifier("mock", sns_topic_arn="arn:aws:sns:x", mock_log_path=mock_log)
    await notifier.start()

    notifier.notify_alert(make_alert(severity="LOW"))
    notifier.notify_incident(make_incident(severity="CRITICAL"), "prior_auth error rate 38%")
    await notifier.stop()

    lines = mock_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    records = [json.loads(line) for line in lines]
    assert records[0]["aws_service"] == "cloudwatch_logs"
    assert records[1]["aws_service"] == "sns"
    assert records[1]["subject"] == "[MedGuard CRITICAL] prior_auth: error rate spike"
    assert "Incident ID: 1" in records[1]["body"]

    captured = capsys.readouterr()
    assert "[aws:mock]" in captured.out


async def test_only_high_and_critical_incidents_reach_sns(tmp_path: Path):
    mock_log = tmp_path / "aws_mock.log"
    notifier = AwsNotifier("mock", mock_log_path=mock_log)
    await notifier.start()

    notifier.notify_alert(make_alert(severity="LOW"))  # every alert goes to CloudWatch...
    notifier.notify_incident(make_incident(severity="LOW"), "x")  # ...but LOW/MEDIUM incidents never reach SNS
    notifier.notify_incident(make_incident(severity="MEDIUM"), "x")
    await notifier.stop()

    records = [json.loads(line) for line in mock_log.read_text(encoding="utf-8").strip().splitlines()]
    assert len(records) == 1
    assert records[0]["aws_service"] == "cloudwatch_logs"


async def test_notify_alert_never_blocks_even_when_the_worker_is_slow(monkeypatch):
    notifier = AwsNotifier("mock", mock_log_path=None)

    async def slow_send(alert):
        await asyncio.sleep(0.3)

    monkeypatch.setattr(notifier, "_send_cloudwatch", slow_send)
    await notifier.start()

    start = time.monotonic()
    for _ in range(5):
        notifier.notify_alert(make_alert())
    elapsed = time.monotonic() - start

    assert elapsed < 0.05  # queuing 5 items must be near-instant regardless of the slow worker
    await notifier.stop()  # waits for the (slow) queue to drain before returning


async def test_retries_with_backoff_then_succeeds(monkeypatch):
    notifier = AwsNotifier("mock", base_backoff=0.01)
    attempts: list[int] = []

    async def flaky_send(alert):
        attempts.append(1)
        if len(attempts) < 3:
            raise RuntimeError("simulated AWS failure")

    monkeypatch.setattr(notifier, "_send_cloudwatch", flaky_send)
    await notifier.start()
    notifier.notify_alert(make_alert())
    await notifier.stop()

    assert len(attempts) == 3  # failed twice, succeeded on the 3rd attempt


async def test_gives_up_after_max_attempts(monkeypatch):
    notifier = AwsNotifier("mock", max_attempts=3, base_backoff=0.01)
    attempts: list[int] = []

    async def always_fails(alert):
        attempts.append(1)
        raise RuntimeError("simulated AWS failure")

    monkeypatch.setattr(notifier, "_send_cloudwatch", always_fails)
    await notifier.start()
    notifier.notify_alert(make_alert())
    await notifier.stop()

    assert len(attempts) == 3


# -- live-mode CloudWatch / config handling (botocore Stubber: no network) ------

import boto3  # noqa: E402
import pytest  # noqa: E402
from botocore.stub import ANY, Stubber  # noqa: E402

from app.config import Settings  # noqa: E402


def _stubbed_live_notifier(**kwargs):
    notifier = AwsNotifier("live", region="us-east-1", log_group="/healthtrace/test/alerts",
                           base_backoff=0.01, **kwargs)
    client = boto3.client("logs", region_name="us-east-1",
                          aws_access_key_id="testing", aws_secret_access_key="testing")
    notifier._boto_logs_client = client
    return notifier, Stubber(client)


def _put_params(stream: str):
    return {"logGroupName": "/healthtrace/test/alerts", "logStreamName": stream, "logEvents": ANY}


async def test_live_cloudwatch_tolerates_missing_create_log_group_permission():
    """The CloudFormation task role has no logs:CreateLogGroup; that must not
    stop alerts from reaching the pre-created group."""
    notifier, stub = _stubbed_live_notifier()
    stub.add_client_error("create_log_group", service_error_code="AccessDeniedException", http_status_code=400)
    stub.add_response("create_log_stream", {})
    stub.add_response("put_log_events", {}, _put_params("2026-09-28"))
    with stub:
        await notifier.start()
        notifier.notify_alert(make_alert())
        await notifier.stop()
        stub.assert_no_pending_responses()
    assert notifier.status["cloudwatch"].sent == 1
    assert notifier.status["cloudwatch"].failed == 0


async def test_live_cloudwatch_existing_group_and_stream_are_fine():
    notifier, stub = _stubbed_live_notifier()
    stub.add_client_error("create_log_group", service_error_code="ResourceAlreadyExistsException")
    stub.add_client_error("create_log_stream", service_error_code="ResourceAlreadyExistsException")
    stub.add_response("put_log_events", {}, _put_params("2026-09-28"))
    stub.add_response("put_log_events", {}, _put_params("2026-09-28"))  # second alert: stream cached
    with stub:
        await notifier.start()
        notifier.notify_alert(make_alert())
        notifier.notify_alert(make_alert())
        await notifier.stop()
        stub.assert_no_pending_responses()
    assert notifier.status["cloudwatch"].sent == 2


async def test_live_cloudwatch_recreates_a_stream_deleted_after_caching():
    notifier, stub = _stubbed_live_notifier()
    notifier._ensured_streams.add("2026-09-28")  # cached as existing...
    stub.add_client_error("put_log_events", service_error_code="ResourceNotFoundException")  # ...but deleted
    stub.add_response("create_log_group", {})
    stub.add_response("create_log_stream", {})
    stub.add_response("put_log_events", {}, _put_params("2026-09-28"))
    with stub:
        await notifier.start()
        notifier.notify_alert(make_alert())
        await notifier.stop()
        stub.assert_no_pending_responses()
    assert notifier.status["cloudwatch"].sent == 1
    assert notifier.status["cloudwatch"].retries == 0


async def test_live_cloudwatch_missing_group_without_permission_fails_cleanly():
    notifier, stub = _stubbed_live_notifier(max_attempts=2)
    for _ in range(2):
        stub.add_client_error("create_log_group", service_error_code="AccessDeniedException")
        stub.add_client_error("create_log_stream", service_error_code="ResourceNotFoundException",
                              service_message="The specified log group does not exist.")
    with stub:
        await notifier.start()
        notifier.notify_alert(make_alert())
        await notifier.stop()
    status = notifier.status["cloudwatch"]
    assert (status.sent, status.failed, status.retries) == (0, 1, 1)
    assert "log group does not exist" in status.last_error


async def test_live_cloudwatch_uses_configured_fixed_stream():
    notifier, stub = _stubbed_live_notifier(log_stream="healthtrace-demo")
    stub.add_response("create_log_group", {})
    stub.add_response("create_log_stream", {"ResponseMetadata": {}},
                      {"logGroupName": "/healthtrace/test/alerts", "logStreamName": "healthtrace-demo"})
    stub.add_response("put_log_events", {}, _put_params("healthtrace-demo"))
    with stub:
        await notifier.start()
        notifier.notify_alert(make_alert())
        await notifier.stop()
        stub.assert_no_pending_responses()
    assert notifier.status["cloudwatch"].sent == 1


async def test_live_sns_failure_is_recorded_without_crashing():
    notifier = AwsNotifier("live", region="us-east-1", sns_topic_arn="arn:aws:sns:us-east-1:123456789012:t",
                           max_attempts=2, base_backoff=0.01)
    client = boto3.client("sns", region_name="us-east-1",
                          aws_access_key_id="testing", aws_secret_access_key="testing")
    notifier._boto_sns_client = client
    stub = Stubber(client)
    for _ in range(2):
        stub.add_client_error("publish", service_error_code="NotFound", service_message="Topic does not exist")
    with stub:
        await notifier.start()
        notifier.notify_incident(make_incident("CRITICAL"), "x")
        await notifier.stop()
    status = notifier.status["sns"]
    assert (status.sent, status.failed, status.retries) == (0, 1, 1)


@pytest.mark.parametrize(
    ("mode", "arn", "expected"),
    [
        ("off", "", []),
        ("live", "arn:aws:sns:us-east-1:123456789012:healthtrace-alerts", []),
        ("live", "", ["SNS_TOPIC_ARN is not set"]),
        ("mock", "", ["SNS_TOPIC_ARN is not set"]),
        ("live", "arn:aws:sns:ap-south-1:123456789012:healthtrace-alerts", ["region ap-south-1"]),
        ("live", "healthtrace-alerts", ["does not look like an SNS topic ARN"]),
    ],
)
def test_config_warnings(mode, arn, expected):
    warnings = AwsNotifier(mode, region="us-east-1", sns_topic_arn=arn).config_warnings()
    assert len(warnings) == len(expected)
    for warning, fragment in zip(warnings, expected):
        assert fragment in warning


def test_settings_accept_aws_prefixed_aliases(monkeypatch, tmp_path):
    for name in ("CLOUDWATCH_LOG_GROUP", "CLOUDWATCH_LOG_STREAM", "SNS_TOPIC_ARN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_LOG_GROUP", "/healthtrace/x/alerts")
    monkeypatch.setenv("AWS_LOG_STREAM", "demo")
    monkeypatch.setenv("AWS_SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:t")
    s = Settings(_env_file=None)
    assert (s.cloudwatch_log_group, s.cloudwatch_log_stream, s.sns_topic_arn) == (
        "/healthtrace/x/alerts", "demo", "arn:aws:sns:us-east-1:123456789012:t")

    monkeypatch.setenv("CLOUDWATCH_LOG_GROUP", "/original/name")  # original name still works and wins
    assert Settings(_env_file=None).cloudwatch_log_group == "/original/name"
