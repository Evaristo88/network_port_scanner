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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple


# A simple data record for scan results.
@dataclass(frozen=True)
class ScanResult:
    ip: str
    hostname: Optional[str]
    port: int
    state: str


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


def is_port_open(ip: str, port: int, timeout: float) -> bool:
    """
    Attempt a TCP connection to determine if a port is open.
    """
    # Use a TCP socket with a short timeout.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex returns 0 on success; anything else means failure.
        result = sock.connect_ex((ip, port))
        return result == 0


def scan_target(ip: str, port: int, timeout: float, do_resolve: bool) -> Optional[ScanResult]:
    """
    Scan a single IP/port combination and return a result if open.
    """
    if is_port_open(ip, port, timeout):
        # Resolve hostname only for open ports to save time.
        hostname = resolve_hostname(ip) if do_resolve else None
        return ScanResult(ip=ip, hostname=hostname, port=port, state="open")

    return None


def run_scan(ips: Iterable[str], ports: Iterable[int], timeout: float, workers: int, do_resolve: bool) -> List[ScanResult]:
    """
    Scan all targets concurrently and return a list of open ports.
    """
    results: List[ScanResult] = []

    # Prepare all target combinations to submit to the executor.
    targets: List[Tuple[str, int]] = [(ip, port) for ip in ips for port in ports]

    # Use a thread pool because sockets are I/O bound.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_target, ip, port, timeout, do_resolve)
            for ip, port in targets
        ]

        # Collect results as they complete.
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                # Print open ports immediately for feedback.
                hostname = result.hostname or ""
                print(f"{result.ip}:{result.port} open {hostname}")

    # Sort results to provide a consistent report.
    results.sort(key=lambda r: (r.ip, r.port))
    return results


def write_json(results: List[ScanResult], path: str) -> None:
    """
    Write results to a JSON file.
    """
    payload = [
        {"ip": r.ip, "hostname": r.hostname, "port": r.port, "state": r.state}
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
        writer.writerow(["ip", "hostname", "port", "state"])
        for r in results:
            writer.writerow([r.ip, r.hostname or "", r.port, r.state])


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line parser.
    """
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")

    # Range selection: either start/end or CIDR.
    parser.add_argument("--start-ip", help="Start IPv4 address")
    parser.add_argument("--end-ip", help="End IPv4 address")
    parser.add_argument("--cidr", help="CIDR block, e.g. 192.168.1.0/24")

    # Port list parsing.
    parser.add_argument("--ports", required=True, help="Ports list, e.g. 22,80,443 or 1-1024")

    # Performance tuning.
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=100, help="Number of concurrent threads")

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
        port_list = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    # Run the scan and gather results.
    results = run_scan(
        ips=ip_list,
        ports=port_list,
        timeout=args.timeout,
        workers=args.workers,
        do_resolve=not args.no_resolve,
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
