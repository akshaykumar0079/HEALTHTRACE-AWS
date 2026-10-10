"""Email cooldown, per-hour flood guard, redaction and failure isolation.
Uses an in-memory SMTP stand-in only; no mail server or API is ever contacted."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.models import Alert, Incident
from tests.test_email import FakeSMTP, NOW, bulk_access, notifier, prior_auth  # noqa: F401  (autouse fixtures reset FakeSMTP)
from tests.test_email import _reset_fake  # noqa: F401


async def _send(n, *pairs, escalated=False):
    await n.start()
    try:
        for incident, alert in pairs:
            n.notify_incident(incident, alert, escalated=escalated)
        await asyncio.wait_for(n._queue.join(), timeout=5)
    finally:
        await n.stop()


async def test_cooldown_suppresses_a_second_email_for_the_same_incident():
    n = notifier(cooldown_seconds=300)
    inc, alert = prior_auth("HIGH")
    await _send(n, (inc, alert), (inc, alert))
    assert len(FakeSMTP.all_sent()) == 1
    assert n.status.skipped == 1 and any("cooldown" in (r["error"] or "") for r in n.status.recent)


async def test_escalation_bypasses_the_cooldown():
    n = notifier(cooldown_seconds=300)
    inc, alert = prior_auth("HIGH")
    crit, crit_alert = prior_auth("CRITICAL")
    await n.start()
    try:
        n.notify_incident(inc, alert)
        n.notify_incident(crit, crit_alert, escalated=True)
        await asyncio.wait_for(n._queue.join(), timeout=5)
    finally:
        await n.stop()
    assert len(FakeSMTP.all_sent()) == 2


async def test_cooldown_is_per_incident_not_global():
    n = notifier(cooldown_seconds=300)
    a, a_alert = prior_auth("HIGH")
    b, b_alert = bulk_access("HIGH")
    await _send(n, (a, a_alert), (b, b_alert))
    assert len(FakeSMTP.all_sent()) == 2


async def test_zero_cooldown_allows_repeats():
    n = notifier(cooldown_seconds=0)
    inc, alert = prior_auth("HIGH")
    await _send(n, (inc, alert), (inc, alert))
    assert len(FakeSMTP.all_sent()) == 2


async def test_cooldown_expires():
    n = notifier(cooldown_seconds=300)
    inc, alert = prior_auth("HIGH")
    await n.start()
    try:
        n.notify_incident(inc, alert)
        await asyncio.wait_for(n._queue.join(), timeout=5)
        n._last_sent_by_fp[inc.fingerprint] = datetime.now(timezone.utc) - timedelta(seconds=301)
        n.notify_incident(inc, alert)
        await asyncio.wait_for(n._queue.join(), timeout=5)
    finally:
        await n.stop()
    assert len(FakeSMTP.all_sent()) == 2


async def test_per_hour_flood_guard_caps_distinct_incidents():
    n = notifier(max_per_hour=3, cooldown_seconds=0)
    pairs = []
    for i in range(10):
        inc, alert = prior_auth("HIGH")
        inc = inc.model_copy(update={"id": 100 + i, "fingerprint": f"error_rate:svc{i}"})
        pairs.append((inc, alert))
    await _send(n, *pairs)
    assert len(FakeSMTP.all_sent()) == 3
    assert n.status.skipped == 7 and any("flood guard" in (r["error"] or "") for r in n.status.recent)


async def test_failed_send_does_not_block_later_emails_and_is_recorded():
    FakeSMTP.fail_with = [ConnectionRefusedError("down")] * 4         # exhausts the first email's retries
    n = notifier(cooldown_seconds=0)
    first, first_alert = prior_auth("HIGH")
    second, second_alert = bulk_access("CRITICAL")
    await _send(n, (first, first_alert), (second, second_alert))
    sent = FakeSMTP.all_sent()
    assert len(sent) == 1 and sent[0]["X-HEALTHTRACE-Incident"] == str(second.id)
    assert n.status.failed == 1 and n.status.sent == 1 and n.status.last_error


async def test_outbound_email_text_goes_through_the_redactor():
    n = notifier()
    n.redact = lambda value: value.replace("U-117", "[USER]") if isinstance(value, str) else value
    inc, alert = bulk_access("CRITICAL")
    await _send(n, (inc, alert))
    msg = FakeSMTP.all_sent()[0]
    body = msg.get_body(preferencelist=("plain",)).get_content()
    assert "U-117" not in body and "[USER]" in body
