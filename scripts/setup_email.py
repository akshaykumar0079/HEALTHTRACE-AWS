"""One-step email setup for HEALTHTRACE using Brevo (no Gmail, no AWS).

    python scripts/setup_email.py

Asks for your Brevo API key (typed hidden, never printed) and the email you
signed up to Brevo with, writes them into the local, git-ignored .env, and
sends ONE test email to the alert recipient. Run it again any time to change
the key; everything else in .env is left as it is.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = REPO_ROOT / ".env"
EXAMPLE_PATH = REPO_ROOT / ".env.example"
DEFAULT_TO = "vasan.akxy@gmail.com"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

sys.path.insert(0, str(REPO_ROOT / "backend"))


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


def write_env(updates: dict[str, str]) -> None:
    """Update keys in place (or append them), keeping every other line."""
    if not ENV_PATH.exists():
        ENV_PATH.write_text(EXAMPLE_PATH.read_text(encoding="utf-8") if EXAMPLE_PATH.exists() else "",
                            encoding="utf-8")
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    pending = dict(updates)
    out = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in pending:
            out.append(f"{key}={pending.pop(key)}")
        else:
            out.append(line)
    if pending:
        out += ["", "# Email alerts via Brevo (written by scripts/setup_email.py)"]
        out += [f"{k}={v}" for k, v in pending.items()]
    ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_PATH, 0o600)  # readable by you only
    except OSError:
        pass


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or default


def main() -> int:
    print("HEALTHTRACE email setup (Brevo)\n")
    current = read_env()

    have_key = bool(current.get("BREVO_API_KEY"))
    key_prompt = "Brevo API key (input is hidden" + ("; press Enter to keep the saved one" if have_key else "") + ")"
    api_key = getpass.getpass(key_prompt + ": ").strip()
    if not api_key:
        if not have_key:
            print("No API key entered. Nothing changed.")
            return 1
        api_key = current["BREVO_API_KEY"]
    elif not api_key.startswith("xkeysib-"):
        print("[WARN] Brevo API keys normally start with 'xkeysib-'. Make sure you copied an API key, "
              "not an SMTP key (SMTP keys start with 'xsmtpsib-').")

    sender = ""
    while not EMAIL_RE.match(sender):
        sender = ask("Your Brevo login email (alerts are sent from it)", current.get("ALERT_EMAIL_FROM", ""))
    recipient = ask("Send alerts to", current.get("ALERT_EMAIL_TO") or DEFAULT_TO)

    write_env({
        "EMAIL_ENABLED": "true",
        "EMAIL_PROVIDER": "brevo",
        "BREVO_API_KEY": api_key,
        "ALERT_EMAIL_FROM": sender,
        "ALERT_EMAIL_TO": recipient,
        "AWS_MODE": current.get("AWS_MODE") if current.get("AWS_MODE") in ("off", "mock") else "mock",
    })
    print(f"\nSaved to {ENV_PATH.name} (git-ignored, not printed). AWS stays disabled (mock).")

    # Fresh Settings so the values just written are used.
    from app.config import Settings, load_config
    from app.notify.mailer import EmailNotifier, EmailSettings

    for name in ("EMAIL_ENABLED", "EMAIL_PROVIDER", "BREVO_API_KEY", "ALERT_EMAIL_FROM", "ALERT_EMAIL_TO"):
        os.environ.pop(name, None)  # a stale shell variable must not override the new .env
    notifier = EmailNotifier(EmailSettings.from_settings(Settings()), app_config=load_config(), max_attempts=2)
    missing = notifier.missing_settings()
    if missing:
        print(f"[FAIL] still missing: {', '.join(missing)}")
        return 1

    print(f"Sending one test email to {recipient} ...")
    ok, error = asyncio.run(notifier.send_test_email())
    if ok:
        print(f"[PASS] Brevo accepted the test email. It should arrive at {recipient} within a minute "
              "(check Spam/Promotions the first time).")
        print("\nEmail is ready. Restart the backend if it was already running.")
        return 0
    print(f"[FAIL] {error}")
    print("Fix the issue above and run this script again (your other settings are kept).")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled. Nothing else changed.")
        sys.exit(130)
