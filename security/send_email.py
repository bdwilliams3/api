#!/usr/bin/env python3
"""Email the latest security report via SMTP. Skips silently if unconfigured.

Env:
  SMTP_HOST, SMTP_PORT (465=SSL, otherwise STARTTLS), SMTP_USER, SMTP_PASS, SMTP_TO
"""
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

HOST = os.environ.get("SMTP_HOST", "").strip()
PORT = int(os.environ.get("SMTP_PORT", "587") or 587)
USER = os.environ.get("SMTP_USER", "").strip()
PASS = os.environ.get("SMTP_PASS", "")
TO = os.environ.get("SMTP_TO", "").strip()

REPORT = Path("SECURITY/LATEST.md")


def main():
    if not (HOST and USER and TO):
        print("SMTP not configured (SMTP_HOST/SMTP_USER/SMTP_TO missing); skipping email.")
        return
    if not REPORT.exists():
        print("No report at SECURITY/LATEST.md; skipping email.")
        return

    body = REPORT.read_text(encoding="utf-8", errors="replace")[:200_000]

    msg = EmailMessage()
    msg["Subject"] = f"API security posture report - {datetime.now(timezone.utc):%Y-%m-%d}"
    msg["From"] = USER
    msg["To"] = TO
    msg.set_content(body)

    if PORT == 465:
        with smtplib.SMTP_SSL(HOST, PORT, timeout=30) as s:
            s.login(USER, PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP(HOST, PORT, timeout=30) as s:
            s.starttls()
            s.login(USER, PASS)
            s.send_message(msg)

    print(f"Report emailed to {TO}")


if __name__ == "__main__":
    main()
