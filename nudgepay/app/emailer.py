"""Email sending helpers."""

from __future__ import annotations

import logging
import smtplib
import time
import uuid
from email.message import EmailMessage
from typing import Any, Optional

from .config import get_settings
from .metrics import record_email

logger = logging.getLogger(__name__)
settings = get_settings()


def _build_message(to: str, subject: str, html: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.from_email
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = message.get("Message-ID", f"<{uuid.uuid4()}@nudgepay>")
    message.set_content("This email requires an HTML-capable email client.")
    message.add_alternative(html, subtype="html")
    return message


def _deliver(message: EmailMessage) -> None:
    delay = 1
    for attempt in range(3):
        try:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as client:
                if settings.smtp_user and settings.smtp_pass:
                    client.starttls()
                    client.login(settings.smtp_user, settings.smtp_pass)
                client.send_message(message)
            return
        except Exception:
            if attempt == 2:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 30)


def _derive_recipient(candidate: Optional[str], *, hints: dict[str, Any] | None = None) -> Optional[str]:
    """Return the best-effort recipient email address from available hints."""

    if candidate:
        return str(candidate).strip()

    hints = hints or {}
    for key in ("to", "recipient", "email", "client_email", "user_email"):
        value = hints.get(key)
        if value:
            return str(value).strip()

    user = hints.get("user")
    if user is not None:
        email = getattr(user, "email", None)
        if email:
            return str(email).strip()

    return None


def send_email(to: Optional[str], subject: str, html: str, **extra: Any) -> None:
    """Send an HTML email if an address is provided."""

    recipient = _derive_recipient(to, hints=extra)
    if not recipient:
        logger.debug("Skipping email send because no recipient was provided")
        record_email("skipped")
        return

    message = _build_message(recipient, subject, html)

    try:
        _deliver(message)
    except Exception:
        record_email("failed")
        raise

    logger.info("Email sent to %s", recipient)
    record_email("sent")


__all__ = ["send_email"]
