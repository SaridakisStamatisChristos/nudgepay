"""Alert transport implementations for automation and incident response."""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Iterable, Mapping

from .config import Settings
from .http_utils import safe_urlopen

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PagerDutyTransport:
    """Send incident events to PagerDuty via the Events API v2."""

    routing_key: str

    def notify(
        self, *, event: str, severity: str, payload: Mapping[str, object]
    ) -> None:
        envelope = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"{event}: {payload.get('status', 'automation alert')}",
                "severity": severity,
                "source": payload.get("source", "nudgepay"),
                "custom_details": dict(payload),
            },
        }
        request = urllib.request.Request(
            "https://events.pagerduty.com/v2/enqueue",
            data=json.dumps(envelope).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with safe_urlopen(
                request, timeout=5
            ) as response:  # pragma: no cover - network
                response.read()
        except urllib.error.URLError as exc:  # pragma: no cover - network
            logger.error("Failed to send PagerDuty alert: %s", exc)
            raise


@dataclass(slots=True)
class SlackTransport:
    """Send alert payloads to Slack via incoming webhooks."""

    webhook_url: str

    def notify(
        self, *, event: str, severity: str, payload: Mapping[str, object]
    ) -> None:
        text = f"[{severity.upper()}] {event}: {payload.get('description', '') or json.dumps(payload)}"
        body = {"text": text}
        request = urllib.request.Request(
            self.webhook_url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with safe_urlopen(
                request, timeout=5
            ) as response:  # pragma: no cover - network
                response.read()
        except urllib.error.URLError as exc:  # pragma: no cover - network
            logger.error("Failed to send Slack alert: %s", exc)
            raise


class EmailTransport:
    """Send alert payloads via SMTP using the configured settings."""

    def __init__(self, *, settings: Settings, recipients: Iterable[str]) -> None:
        self.settings = settings
        self.recipients = tuple(
            recipient.strip() for recipient in recipients if recipient.strip()
        )

    def notify(
        self, *, event: str, severity: str, payload: Mapping[str, object]
    ) -> None:
        if not self.recipients:
            logger.debug("Email transport configured without recipients; skipping")
            return

        message = EmailMessage()
        message["Subject"] = f"[{severity.upper()}] {event}"
        message["From"] = self.settings.from_email
        message["To"] = ", ".join(self.recipients)
        message.set_content(json.dumps(dict(payload), indent=2, sort_keys=True))

        context = ssl.create_default_context()
        try:
            with smtplib.SMTP(
                self.settings.smtp_host, self.settings.smtp_port, timeout=10
            ) as client:
                if self.settings.smtp_user and self.settings.smtp_pass:
                    client.starttls(context=context)
                    client.login(self.settings.smtp_user, self.settings.smtp_pass)
                client.send_message(message)
        except Exception as exc:  # pragma: no cover - network / smtp interaction
            logger.error("Failed to send alert email: %s", exc)
            raise


__all__ = ["PagerDutyTransport", "SlackTransport", "EmailTransport"]
