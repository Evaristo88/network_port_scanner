from __future__ import annotations

import os

from twilio.rest import Client

from agent_config import WhatsAppConfig


def _resolve_value(value: str | None, env_key: str) -> str | None:
    if value:
        return value
    return os.getenv(env_key)


def send_whatsapp_alert(config: WhatsAppConfig, body: str) -> None:
    if not config.enabled:
        return

    account_sid = _resolve_value(config.account_sid, config.account_sid_env)
    auth_token = _resolve_value(config.auth_token, config.auth_token_env)
    from_number = _resolve_value(config.from_number, config.from_number_env)
    to_number = _resolve_value(config.to_number, config.to_number_env)
    status_callback = _resolve_value(config.status_callback, config.status_callback_env)
    if status_callback and status_callback.lower() == "none":
        status_callback = None

    if not all([account_sid, auth_token, from_number, to_number]):
        raise ValueError("WhatsApp config missing required credentials or numbers")

    client = Client(account_sid, auth_token)
    params = {"body": body, "from_": from_number, "to": to_number}
    if status_callback:
        params["status_callback"] = status_callback
    client.messages.create(**params)
