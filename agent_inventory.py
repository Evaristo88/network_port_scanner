from __future__ import annotations

from typing import Iterable, List, Optional, Tuple


def read_arp_table(path: str = "/proc/net/arp") -> List[Tuple[str, str]]:
    """
    Parse /proc/net/arp and return (ip, mac) entries.

    This is best-effort. The ARP table only includes devices that recently
    communicated with this machine.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []

    entries: List[Tuple[str, str]] = []
    for line in lines[1:]:
        parsed = _parse_arp_line(line)
        if parsed:
            entries.append(parsed)
    return entries


def _parse_arp_line(line: str) -> Optional[Tuple[str, str]]:
    parts = line.split()
    if len(parts) < 4:
        return None

    # /proc/net/arp format: IP ... MAC ...
    ip_addr = parts[0]
    mac_addr = parts[3]
    if mac_addr == "00:00:00:00:00:00":
        return None
    return ip_addr, mac_addr
