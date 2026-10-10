"""Send ONE test email with the SMTP settings in your local .env.

    python scripts/test_email.py              # check settings, then send one test email
    python scripts/test_email.py --check      # only check settings, send nothing
    python scripts/test_email.py --alert      # send a sample CRITICAL alert email instead

Reads the same .env / environment variables as the backend (EMAIL_ENABLED,
EMAIL_PROVIDER, BREVO_API_KEY or SMTP_*, ALERT_EMAIL_FROM, ALERT_EMAIL_TO).
Keys and passwords are never printed. For first-time Brevo setup use
scripts/setup_email.py instead. The
normal application never sends a test email by itself; only this script does.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.config import get_settings, load_config  # noqa: E402
from app.models import Alert, Incident  # noqa: E402
from app.notify.mailer import EmailNotifier, EmailSettings  # noqa: E402


def mask(address: str) -> str:
    if "@" not in address:
        return "(not set)" if not address else address[:2] + "***"
    user, domain = address.split("@", 1)
    return f"{user[:2]}***@{domain}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="validate settings only; send nothing")
    parser.add_argument("--alert", action="store_true", help="send a sample CRITICAL alert email (synthetic data)")
    args = parser.parse_args()

    env_file = REPO_ROOT / ".env"
    print("HEALTHTRACE email test\n")
    print(f"  .env file      : {'found' if env_file.exists() else 'NOT FOUND (using environment variables only)'}")
    settings = get_settings()
    es = EmailSettings.from_settings(settings)
    notifier = EmailNotifier(es, app_config=load_config(), max_attempts=1)

    print(f"  EMAIL_PROVIDER : {es.provider}")
    if es.provider == "brevo":
        key = es.api_key.get_secret_value()
        print(f"  EMAIL_ENABLED  : {es.enabled}")
        print(f"  BREVO_API_KEY  : {'set' if key else 'not set'}")
        print(f"  From           : {mask(es.sender)}")
        print(f"  To             : {', '.join(es.recipients) or '(not set)'}\n")
    password = es.password.get_secret_value()
    pw_note = "not set" if not password else (
        "set (16 characters, looks like an App Password)" if len(password.replace(" ", "")) == 16
        else f"set ({len(password.replace(' ', ''))} characters; a Gmail App Password has 16)"
    )
    if es.provider == "smtp":
        _print_smtp(es, pw_note)

    missing = notifier.missing_settings()
    if missing:
        print(f"[FAIL] missing in .env: {', '.join(missing)}")
        print("       Brevo: run `python scripts/setup_email.py`." if es.provider == "brevo" else
              "       SMTP_PASSWORD must be a Gmail App Password (Google Account > Security > App passwords).")
        return 1
    return _continue(args, es, notifier)


def _print_smtp(es, pw_note) -> None:
    print(f"  EMAIL_ENABLED  : {es.enabled}")
    print(f"  SMTP server    : {es.host}:{es.port} ({'STARTTLS' if es.use_tls and es.port != 465 else 'SSL' if es.port == 465 else 'NO TLS'})")
    print(f"  SMTP_USERNAME  : {mask(es.username)}")
    print(f"  SMTP_PASSWORD  : {pw_note}")
    print(f"  From           : {mask(es.sender)}")
    print(f"  To             : {', '.join(es.recipients) or '(not set)'}\n")


def _continue(args, es, notifier) -> int:
    for warning in notifier.config_warnings():
        print(f"[WARN] {warning}")
    if not es.enabled:
        print("[WARN] EMAIL_ENABLED=false: this test can still send, but the app will NOT email alerts "
              "until you set EMAIL_ENABLED=true.")
    if args.check:
        print("[PASS] settings look complete (nothing sent; run without --check to send a test email)")
        return 0

    if args.alert:
        now = datetime.now(timezone.utc)
        alert = Alert(ts=now, kind="hipaa_bulk_access", user_id="U-117", severity="CRITICAL", score=0.0,
                      explanation="user U-117 accessed 201 patients (7.0x their baseline) [SAMPLE - synthetic test]",
                      metrics={"multiplier": 7.0, "distinct_patients": 201})
        incident = Incident(id=0, fingerprint="test", kind="hipaa_bulk_access", user_id="U-117", state="OPEN",
                            peak_severity="CRITICAL", alert_count=1, opened_at=now)
        message = notifier.build_message(incident, alert)
        message.replace_header("Subject", "[TEST] " + str(message["Subject"]))
    else:
        message = notifier.build_test_message()

    print(f"Sending: {message['Subject']}")
    ok = asyncio.run(notifier._send_with_retry(message))  # noqa: SLF001
    if ok:
        print(f"[PASS] sent to {', '.join(es.recipients)}. Check the inbox (and the spam folder).")
        return 0
    print(f"[FAIL] {notifier.status.last_error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
