"""Invitation delivery — MailTransport protocol + SMTP implementation.

When the shim is given a transport, invitation tokens are delivered by email
and never returned in the HTTP response (closing the enumeration gap of the
in-band mode). Without one, invitations are returned in-band, matching
studio-api's current behaviour.
"""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

log = logging.getLogger(__name__)


class MailTransport(Protocol):
    def send_invitation(self, email: str, invitation_token: str) -> None:
        """Deliver *invitation_token* to *email*. Raise on failure."""
        ...


@dataclass
class SmtpMailTransport:
    """Minimal SMTP transport (port of cantica-api's invite mailer)."""

    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    sender: str = "cantica-secure@localhost"
    use_tls: bool = True
    subject: str = "Your Cantica invitation"

    def send_invitation(self, email: str, invitation_token: str) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = email
        msg["Subject"] = self.subject
        msg.set_content(
            "You have been invited.\n\n"
            "Use this invitation token to enrol your client:\n\n"
            f"{invitation_token}\n\n"
            "The token is single-use and expires."
        )
        with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
            if self.use_tls:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(msg)
        log.info("invitation sent to %s", email)
