from __future__ import annotations

from typing import Iterable, List

from agent_config import RecommendationsConfig
from port_scanner import ScanResult


def build_recommendations(
    config: RecommendationsConfig,
    new_devices: Iterable[str],
    new_ports: Iterable[tuple],
) -> List[str]:
    # AI recommendations are optional; this MVP uses rule-based guidance.
    recommendations = [
        "Verify device ownership and expected services.",
        "Disable or firewall unexpected ports.",
        "Ensure device firmware and OS patches are current.",
        "Consider network segmentation for untrusted devices.",
    ]

    if new_devices:
        recommendations.append("Add unknown devices to a guest or quarantine VLAN.")
    if new_ports:
        recommendations.append("Review new ports against your allowlist.")

    return recommendations


def format_recommendations(lines: Iterable[str]) -> str:
    return "\n".join(f"- {line}" for line in lines)
