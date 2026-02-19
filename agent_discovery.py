from __future__ import annotations

import ipaddress
import os
import socket
import struct
from typing import Optional, Tuple

import fcntl


SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891b


def discover_local_cidr() -> Optional[str]:
    """
    Attempt to determine the local IPv4 CIDR using the default route.

    Returns None if the subnet cannot be determined.
    """
    # Linux-only: read default route and inspect the interface IP/netmask.
    interface = _discover_default_interface()
    if not interface:
        return None

    info = _get_interface_ipv4(interface)
    if not info:
        return None

    ip_addr, netmask = info
    return cidr_from_ip_netmask(ip_addr, netmask)


def cidr_from_ip_netmask(ip_addr: str, netmask: str) -> str:
    network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
    return str(network)


def _discover_default_interface() -> Optional[str]:
    route_path = "/proc/net/route"
    if not os.path.exists(route_path):
        return None

    with open(route_path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        iface, destination, flags = fields[0], fields[1], fields[3]
        if destination == "00000000":
            try:
                flag_value = int(flags, 16)
            except ValueError:
                continue
            if flag_value & 0x2:
                return iface

    return None


def _get_interface_ipv4(interface: str) -> Optional[Tuple[str, str]]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_addr = _ioctl_addr(sock, interface, SIOCGIFADDR)
        netmask = _ioctl_addr(sock, interface, SIOCGIFNETMASK)
        return ip_addr, netmask
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _ioctl_addr(sock: socket.socket, interface: str, request: int) -> str:
    ifname = interface.encode("utf-8")[:15]
    packed = struct.pack("256s", ifname)
    response = fcntl.ioctl(sock.fileno(), request, packed)
    return socket.inet_ntoa(response[20:24])
