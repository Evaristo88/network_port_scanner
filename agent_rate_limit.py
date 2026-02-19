from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agent_db import get_alert_state, update_alert_state


def should_send_alert(conn, alert_key: str, cooldown_minutes: int) -> bool:
    last_sent = get_alert_state(conn, alert_key)
    if not last_sent:
        return True

    last_dt = datetime.fromisoformat(last_sent)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
    return last_dt < cutoff


def mark_alert_sent(conn, alert_key: str, sent_at: str) -> None:
    update_alert_state(conn, alert_key, sent_at)
