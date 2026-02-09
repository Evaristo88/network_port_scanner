#!/usr/bin/env python3
"""
Educational TCP port scanner using Python sockets.

This script scans IPv4 targets and attempts TCP connections on specified ports
to identify which ports are open.
"""

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set, Tuple


# A simple data record for scan results.
@dataclass(frozen=True)
class ScanResult:
    ip: str
    hostname: Optional[str]
    port: int
    protocol: str
    service: Optional[str]
    state: str


# Common TCP ports list for quick scans.
TOP_PORTS: Sequence[int] = (
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
    110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
    162, 179, 389, 443, 445, 465, 514, 515, 587, 636,
    873, 993, 995, 1080, 1194, 1433, 1521, 1723, 1812, 1813,
    1883, 2049, 2082, 2083, 2086, 2087, 2222, 2375, 2376, 2483,
    2484, 3128, 3306, 3389, 3690, 4443, 4567, 5000, 5001, 5060,
    5061, 5432, 5672, 5900, 5984, 6379, 6443, 6667, 7001, 7002,
    7070, 7443, 7777, 8000, 8008, 8010, 8020, 8069, 8080, 8081,
    8086, 8088, 8090, 8100, 8123, 8181, 8222, 8333, 8443, 8883,
    9000, 9001, 9042, 9090, 9200, 9300, 9418, 9443, 10000, 11211,
    15672, 27017, 27018, 27019
)


def parse_ports(port_text: str) -> List[int]:
    """
    Parse a port list string into a sorted list of unique ports.

    Supports:
    - "80"
    - "22,80,443"
    - "8000-8100"
    - Mixed: "22,80,443,8000-8100"
    """
    # Store ports in a set to avoid duplicates.
    ports: Set[int] = set()

    # Split on commas to support multiple entries.
    for part in port_text.split(","):
        part = part.strip()
        if not part:
            continue

        # Handle ranges like 8000-8100.
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            # Add each port in the range.
            for port in range(start, end + 1):
                ports.add(port)
        else:
            # Single port entry.
            ports.add(int(part))

    # Validate that ports fall within TCP range.
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")

    # Return a sorted list to produce stable output.
    return sorted(ports)


def get_top_ports(count: int) -> List[int]:
    """
    Return the first N ports from the common ports list.
    """
    if count <= 0:
        raise ValueError("Top ports count must be a positive integer")

    limit = min(count, len(TOP_PORTS))
    return list(TOP_PORTS[:limit])


def build_port_list(ports_text: Optional[str], top_ports: Optional[int]) -> List[int]:
    """
    Build a port list from explicit ports, top ports, or both.
    """
    ports: Set[int] = set()

    if ports_text:
        ports.update(parse_ports(ports_text))

    if top_ports is not None:
        ports.update(get_top_ports(top_ports))

    if not ports:
        raise ValueError("Provide --ports, --top-ports, or both")

    return sorted(ports)


def build_ip_list(start_ip: Optional[str], end_ip: Optional[str], cidr: Optional[str]) -> List[str]:
    """
    Build a list of IPv4 addresses from start/end or a CIDR block.
    """
    if cidr:
        # Expand the CIDR into individual IP addresses.
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]

    if not start_ip or not end_ip:
        raise ValueError("Provide --start-ip and --end-ip or --cidr")

    # Convert to IPv4Address objects so we can iterate safely.
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    # Swap if the range is reversed.
    if start > end:
        start, end = end, start

    # Build the full list from start to end, inclusive.
    current = start
    ips: List[str] = []
    while current <= end:
        ips.append(str(current))
        current += 1

    return ips


def resolve_hostname(ip: str) -> Optional[str]:
    """
    Attempt a reverse DNS lookup for the target IP.
    """
    try:
        # gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def resolve_service(port: int, protocol: str) -> Optional[str]:
    """
    Resolve a well-known service name for a port and protocol.
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return None


def is_tcp_port_open(ip: str, port: int, timeout: float) -> bool:
    """
    Attempt a TCP connection to determine if a port is open.
    """
    # Use a TCP socket with a short timeout.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex returns 0 on success; anything else means failure.
        result = sock.connect_ex((ip, port))
        return result == 0


def is_udp_port_open(ip: str, port: int, timeout: float) -> bool:
    """
    Attempt a UDP probe; any response indicates an open UDP port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(b"\x00", (ip, port))
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False
        except OSError:
            return False


def scan_target(
    ip: str,
    port: int,
    protocol: str,
    timeout: float,
    do_resolve: bool,
    do_service: bool,
) -> Optional[ScanResult]:
    """
    Scan a single IP/port combination and return a result if open.
    """
    is_open = False
    if protocol == "tcp":
        is_open = is_tcp_port_open(ip, port, timeout)
    elif protocol == "udp":
        is_open = is_udp_port_open(ip, port, timeout)

    if is_open:
        # Resolve hostname and service only for open ports to save time.
        hostname = resolve_hostname(ip) if do_resolve else None
        service = resolve_service(port, protocol) if do_service else None
        return ScanResult(
            ip=ip,
            hostname=hostname,
            port=port,
            protocol=protocol,
            service=service,
            state="open",
        )

    return None


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds as H:MM:SS.
    """
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


def run_scan(
    ips: Iterable[str],
    ports: Iterable[int],
    protocol: str,
    timeout: float,
    workers: int,
    do_resolve: bool,
    do_service: bool,
    show_progress: bool,
) -> List[ScanResult]:
    """
    Scan all targets concurrently and return a list of open ports.
    """
    results: List[ScanResult] = []

    # Prepare all target combinations to submit to the executor.
    targets: List[Tuple[str, int]] = [(ip, port) for ip in ips for port in ports]
    total_targets = len(targets)

    start_time = time.time()
    last_update = start_time
    completed = 0

    # Use a thread pool because sockets are I/O bound.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_target, ip, port, protocol, timeout, do_resolve, do_service)
            for ip, port in targets
        ]

        # Collect results as they complete.
        for future in as_completed(futures):
            result = future.result()
            completed += 1

            if show_progress and total_targets:
                now = time.time()
                if now - last_update >= 1 or completed == total_targets:
                    elapsed = now - start_time
                    rate = completed / elapsed if elapsed > 0 else 0
                    remaining = total_targets - completed
                    eta = remaining / rate if rate > 0 else 0
                    percent = (completed / total_targets) * 100
                    progress_line = (
                        f"Progress: {completed}/{total_targets} "
                        f"({percent:.1f}%) | elapsed {format_duration(elapsed)} "
                        f"| eta {format_duration(eta)}"
                    )
                    print(progress_line, end="\r", file=sys.stderr, flush=True)
                    last_update = now

            if result:
                results.append(result)
                # Print open ports immediately for feedback.
                hostname = f" {result.hostname}" if result.hostname else ""
                service = f" {result.service}" if result.service else ""
                print(
                    f"{result.ip}:{result.port}/{result.protocol} open{hostname}{service}"
                )

        if show_progress and total_targets:
            print(file=sys.stderr)

    # Sort results to provide a consistent report.
    results.sort(key=lambda r: (r.ip, r.port, r.protocol))
    return results


def write_json(results: List[ScanResult], path: str) -> None:
    """
    Write results to a JSON file.
    """
    payload = [
        {
            "ip": r.ip,
            "hostname": r.hostname,
            "port": r.port,
            "protocol": r.protocol,
            "service": r.service,
            "state": r.state,
        }
        for r in results
    ]

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def write_csv(results: List[ScanResult], path: str) -> None:
    """
    Write results to a CSV file.
    """
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "hostname", "port", "protocol", "service", "state"])
        for r in results:
            writer.writerow(
                [r.ip, r.hostname or "", r.port, r.protocol, r.service or "", r.state]
            )


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line parser.
    """
    parser = argparse.ArgumentParser(description="Simple TCP/UDP port scanner")

    # Range selection: either start/end or CIDR.
    parser.add_argument("--start-ip", help="Start IPv4 address")
    parser.add_argument("--end-ip", help="End IPv4 address")
    parser.add_argument("--cidr", help="CIDR block, e.g. 192.168.1.0/24")

    # Port list parsing.
    parser.add_argument("--ports", help="Ports list, e.g. 22,80,443 or 1-1024")
    parser.add_argument(
        "--top-ports",
        type=int,
        help="Scan the top N common ports (e.g. 20, 50, 100)",
    )

    # Performance tuning.
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=100, help="Number of concurrent threads")
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help="Protocol to scan (default: tcp)",
    )
    parser.add_argument("--progress", action="store_true", help="Show progress and ETA")
    parser.add_argument("--services", action="store_true", help="Resolve service names")

    # Output options.
    parser.add_argument("--json-out", help="Path to JSON report")
    parser.add_argument("--csv-out", help="Path to CSV report")
    parser.add_argument("--no-resolve", action="store_true", help="Skip reverse DNS lookup")

    return parser


def main() -> int:
    """
    Entry point for the CLI.
    """
    parser = build_parser()
    args = parser.parse_args()

    try:
        # Build the target lists based on input.
        ip_list = build_ip_list(args.start_ip, args.end_ip, args.cidr)
        port_list = build_port_list(args.ports, args.top_ports)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    # Run the scan and gather results.
    results = run_scan(
        ips=ip_list,
        ports=port_list,
        protocol=args.protocol,
        timeout=args.timeout,
        workers=args.workers,
        do_resolve=not args.no_resolve,
        do_service=args.services,
        show_progress=args.progress,
    )

    # Write optional reports to disk.
    if args.json_out:
        write_json(results, args.json_out)

    if args.csv_out:
        write_csv(results, args.csv_out)

    # Return a non-zero code if nothing was found.
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
