from __future__ import annotations

import smtplib
from email.message import EmailMessage

from agent_config import EmailConfig


def send_email_alert(email_config: EmailConfig, subject: str, body: str) -> None:
    if not email_config.enabled:
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = email_config.from_addr
    message["To"] = ", ".join(email_config.to_addrs)
    message.set_content(body)

    # Use STARTTLS when enabled, then authenticate and send.
    with smtplib.SMTP(email_config.smtp_host, email_config.smtp_port, timeout=30) as server:
        if email_config.use_tls:
            server.starttls()
        if email_config.username:
            server.login(email_config.username, email_config.app_password)
        server.send_message(message)
