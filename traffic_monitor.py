from __future__ import annotations

from agent_config import TrafficConfig


def start_traffic_monitor(config: TrafficConfig) -> None:
    if not config.enabled:
        return

    raise NotImplementedError(
        "Traffic monitoring requires gateway/router deployment or port mirroring. "
        "Configure traffic.mode and interface once the agent is on the gateway."
    )
