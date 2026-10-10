"""Live AWS check for HEALTH TRACE: run on your own machine, with your own
AWS profile. It never reads, prints or stores access keys.

Default run (about 30-60 seconds):
  1. Shows which AWS identity is in use (account + ARN only).
  2. Checks the configuration (region, log group, topic ARN).
  3. Sends one synthetic HIGH alert and one synthetic CRITICAL incident
     through the app's own AwsNotifier in live mode (the exact production
     code path: queue, retry, CloudWatch PutLogEvents, SNS Publish).
  4. Reads the alert back from CloudWatch Logs to prove it arrived.
  5. Error handling: publishes to a topic that does not exist and confirms
     the notifier retries, records the failure and keeps running.

Read-back only (after running the full app in live mode and injecting a
scenario from the dashboard):
  python scripts/aws_live_check.py --stack healthtrace-alerts-local --readback-minutes 15

Settings come from --stack (CloudFormation outputs of deploy/aws/alerts-only.yaml),
else from flags, else from the same env vars / .env the app uses.
All data sent is synthetic and labelled; no patient data is involved.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.models import Alert, Incident  # noqa: E402
from app.notify.aws import AwsNotifier  # noqa: E402

OK, FAIL, INFO = "PASS", "FAIL", "    "
results: list[tuple[str, str]] = []


def report(status: str, message: str) -> None:
    print(f"[{status}] {message}")
    if status in (OK, FAIL):
        results.append((status, message))


def stack_outputs(session: boto3.Session, stack: str) -> dict[str, str]:
    cfn = session.client("cloudformation")
    stacks = cfn.describe_stacks(StackName=stack)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def readback(logs, log_group: str, pattern: str | None, since: datetime, timeout_s: float = 45) -> list[dict]:
    """Poll FilterLogEvents until something matching ``pattern`` shows up."""
    deadline = time.monotonic() + timeout_s
    while True:
        events: list[dict] = []
        kwargs = dict(logGroupName=log_group, startTime=int(since.timestamp() * 1000))
        if pattern:
            kwargs["filterPattern"] = pattern
        while True:
            resp = logs.filter_log_events(**kwargs)
            events.extend(resp.get("events", []))
            token = resp.get("nextToken")
            if not token:
                break
            kwargs["nextToken"] = token
        if events or time.monotonic() > deadline:
            return events
        time.sleep(3)


async def send_through_notifier(region: str, log_group: str, log_stream: str, topic_arn: str, marker: str):
    notifier = AwsNotifier("live", region=region, log_group=log_group, log_stream=log_stream,
                           sns_topic_arn=topic_arn, max_attempts=3, base_backoff=0.5)
    now = datetime.now(timezone.utc)
    alert = Alert(
        ts=now, kind="error_rate", service="prior_auth", severity="HIGH", score=0.7,
        explanation=f"HEALTHTRACE live check {marker}: synthetic test alert, not a real incident",
        metrics={"synthetic": True},
    )
    incident = Incident(
        id=999999, fingerprint=f"live-check:{marker}", kind="error_rate", service="prior_auth",
        state="OPEN", peak_severity="CRITICAL", alert_count=1, opened_at=now,
    )
    await notifier.start()
    notifier.notify_alert(alert)
    notifier.notify_incident(incident, f"HEALTHTRACE live check {marker}: synthetic CRITICAL test incident")
    await notifier.stop(drain_timeout=60)
    return notifier


async def failure_path(region: str, log_group: str, topic_arn: str) -> AwsNotifier:
    """Publish to a topic name that does not exist in this account/region."""
    parts = topic_arn.split(":")
    bogus = ":".join(parts[:5] + [f"healthtrace-does-not-exist-{uuid.uuid4().hex[:8]}"])
    notifier = AwsNotifier("live", region=region, log_group=log_group, sns_topic_arn=bogus,
                           max_attempts=2, base_backoff=0.2)
    incident = Incident(
        id=999998, fingerprint="live-check:failure", kind="error_rate", service="prior_auth",
        state="OPEN", peak_severity="CRITICAL", alert_count=1, opened_at=datetime.now(timezone.utc),
    )
    await notifier.start()
    notifier.notify_incident(incident, "HEALTHTRACE live check: expected-to-fail publish")
    await notifier.stop(drain_timeout=30)
    return notifier


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE"), help="AWS CLI profile name")
    parser.add_argument("--region", default=None, help=f"default: AWS_REGION ({settings.aws_region})")
    parser.add_argument("--stack", default=None, help="read log group + topic from this alerts-only stack")
    parser.add_argument("--log-group", default=None)
    parser.add_argument("--log-stream", default=None, help="default: CLOUDWATCH_LOG_STREAM or daily")
    parser.add_argument("--topic-arn", default=None)
    parser.add_argument("--readback-minutes", type=float, default=None,
                        help="only list alerts the running app wrote in the last N minutes")
    parser.add_argument("--skip-failure-test", action="store_true")
    args = parser.parse_args()

    region = args.region or os.environ.get("AWS_REGION") or settings.aws_region
    try:
        session = boto3.Session(profile_name=args.profile, region_name=region)
    except BotoCoreError as exc:
        report(FAIL, f"AWS profile problem: {exc}")
        return 1
    if args.profile:
        # AwsNotifier builds its own boto3 clients from the default session.
        os.environ["AWS_PROFILE"] = args.profile
    os.environ["AWS_DEFAULT_REGION"] = region

    print("HEALTH TRACE live AWS check\n")
    try:
        ident = session.client("sts").get_caller_identity()
        report(OK, f"credentials found: account {ident['Account']}, {ident['Arn']}")
    except (NoCredentialsError, ClientError, BotoCoreError) as exc:
        report(FAIL, f"no usable AWS credentials ({type(exc).__name__}). Run `aws configure` or "
                     f"`aws sso login`, or pass --profile.")
        return 1

    log_group, topic_arn = args.log_group, args.topic_arn
    if args.stack:
        try:
            out = stack_outputs(session, args.stack)
            log_group = log_group or out.get("LogGroupName")
            topic_arn = topic_arn or out.get("SnsTopicArn")
            report(OK, f"read stack {args.stack} outputs")
        except ClientError as exc:
            report(FAIL, f"cannot read stack {args.stack} in {region}: {exc.response['Error']['Message']}")
            return 1
    log_group = log_group or settings.cloudwatch_log_group
    topic_arn = topic_arn or settings.sns_topic_arn
    log_stream = args.log_stream if args.log_stream is not None else settings.cloudwatch_log_stream
    print(f"{INFO}region={region}\n{INFO}log_group={log_group}\n{INFO}log_stream={log_stream or 'daily (UTC date)'}"
          f"\n{INFO}topic_arn={topic_arn or '(not set)'}\n")

    probe = AwsNotifier("live", region=region, log_group=log_group, sns_topic_arn=topic_arn)
    warnings = probe.config_warnings()
    for w in warnings:
        report(FAIL, f"config: {w}")
    if warnings:
        return 1
    report(OK, "configuration looks valid")

    logs = session.client("logs")

    if args.readback_minutes is not None:
        since = datetime.now(timezone.utc) - timedelta(minutes=args.readback_minutes)
        try:
            raw = readback(logs, log_group, None, since, timeout_s=0)
        except ClientError as exc:
            report(FAIL, f"read back from {log_group}: {exc.response['Error']['Code']}")
            return 1
        by_sev: dict[str, int] = {}
        events = []
        for e in raw:
            try:
                alert = json.loads(e["message"])
            except ValueError:
                continue
            if not isinstance(alert, dict) or "severity" not in alert:
                continue  # e.g. the AWS page's "send test alert" entries
            events.append(alert)
            by_sev[alert.get("severity", "?")] = by_sev.get(alert.get("severity", "?"), 0) + 1
            print(f"{INFO}{alert.get('ts')}  {str(alert.get('severity')):8} {alert.get('kind')}  "
                  f"{alert.get('service') or alert.get('user_id')}: {alert.get('explanation')}")
        status = OK if events else FAIL
        report(status, f"{len(events)} alert(s) in CloudWatch in the last {args.readback_minutes:g} min {by_sev}")
        return 0 if events else 1

    # -- 1. real send through the production notifier -------------------------
    marker = f"lc-{uuid.uuid4().hex[:12]}"
    started = datetime.now(timezone.utc) - timedelta(seconds=5)
    print(f"{INFO}sending synthetic alert + incident (marker {marker})...")
    notifier = asyncio.run(send_through_notifier(region, log_group, log_stream, topic_arn, marker))
    cw, sns = notifier.status["cloudwatch"], notifier.status["sns"]
    report(OK if cw.sent == 1 else FAIL,
           f"CloudWatch PutLogEvents: sent={cw.sent} failed={cw.failed} retries={cw.retries}"
           + (f" error={cw.last_error}" if cw.last_error else ""))
    report(OK if sns.sent == 1 else FAIL,
           f"SNS Publish (CRITICAL incident): sent={sns.sent} failed={sns.failed} retries={sns.retries}"
           + (f" error={sns.last_error}" if sns.last_error else ""))

    # -- 2. read it back ------------------------------------------------------
    if cw.sent == 1:
        try:
            events = readback(logs, log_group, f'"{marker}"', started)
            report(OK if events else FAIL,
                   f"CloudWatch read-back: {len(events)} event(s) with the marker"
                   + (f" in stream {events[0]['logStreamName']}" if events else " (none within 45s)"))
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            report(FAIL, f"CloudWatch read-back: {code}"
                         + (" - attach the VerifierPolicy from the stack outputs" if code == "AccessDeniedException" else ""))

    if sns.sent == 1:
        try:
            attrs = session.client("sns").get_topic_attributes(TopicArn=topic_arn)["Attributes"]
            confirmed = attrs.get("SubscriptionsConfirmed", "0")
            pending = attrs.get("SubscriptionsPending", "0")
            print(f"{INFO}topic has {confirmed} confirmed / {pending} pending subscription(s)"
                  + ("; check your inbox for the CRITICAL test email" if confirmed != "0"
                     else "; no confirmed subscriber, so nobody receives it (publish still succeeded)"))
        except ClientError:
            pass

    # -- 3. failure / retry path ---------------------------------------------
    if not args.skip_failure_test:
        bad = asyncio.run(failure_path(region, log_group, topic_arn))
        s = bad.status["sns"]
        handled = s.failed == 1 and s.sent == 0 and s.retries >= 1
        report(OK if handled else FAIL,
               f"error handling: bad topic -> retries={s.retries}, failed={s.failed}, "
               f"notifier still stopped cleanly ({s.last_error.split(':')[0] if s.last_error else 'no error'})")

    failed = [m for status, m in results if status == FAIL]
    print(f"\n{'ALL CHECKS PASSED' if not failed else f'{len(failed)} CHECK(S) FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
