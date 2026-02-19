#!/usr/bin/env python3
"""
Continuous network monitoring agent (MVP).

Runs scheduled scans, stores history in SQLite, and sends email alerts when new
devices or new open ports are detected.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections import defaultdict
from typing import Dict, List, Sequence, Set, Tuple

from dotenv import load_dotenv

from agent_alerts import send_email_alert
from agent_config import AgentConfig, load_config
from agent_db import (
    fetch_known_devices,
    fetch_known_ports,
    init_db,
    insert_scan_features,
    prune_old_data,
    record_alert,
    record_scan,
    store_scan_results,
    upsert_devices,
    upsert_device_inventory,
    upsert_open_ports,
    utc_now,
)
from agent_discovery import discover_local_cidr
from agent_inventory import read_arp_table
from agent_ml import build_feature_vector, maybe_score_anomaly
from agent_rate_limit import mark_alert_sent, should_send_alert
from agent_recommendations import build_recommendations, format_recommendations
from agent_reports import maybe_generate_daily_pdf, utc_today_date, write_scan_csv
from agent_whatsapp import send_whatsapp_alert
from port_scanner import ScanResult, build_ip_list, build_port_list, run_scan
from traffic_monitor import start_traffic_monitor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Network monitoring agent")
    parser.add_argument(
        "--config",
        default="agent_config.json",
        help="Path to the agent config JSON file",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit",
    )
    return parser


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def resolve_cidr(config: AgentConfig) -> str:
    if not config.scan.auto_cidr and config.scan.cidr:
        return config.scan.cidr

    discovered = discover_local_cidr()
    if not discovered:
        raise ValueError(
            "Unable to auto-discover subnet. Set scan.cidr or start_ip/end_ip in config."
        )
    return discovered


def run_scan_once(config: AgentConfig) -> None:
    # Prefer explicit ranges when provided, otherwise auto-discover the subnet.
    if config.scan.start_ip and config.scan.end_ip:
        ip_list = build_ip_list(config.scan.start_ip, config.scan.end_ip, None)
        scan_scope = f"{config.scan.start_ip}-{config.scan.end_ip}"
        logging.info("Using IP range: %s", scan_scope)
    else:
        cidr = resolve_cidr(config)
        ip_list = build_ip_list(None, None, cidr)
        scan_scope = cidr
        logging.info("Using CIDR: %s", cidr)
    port_list = build_port_list(config.scan.ports, config.scan.top_ports)

    # Run the scan quietly; results are stored and reported by the agent.
    results = run_scan(
        ips=ip_list,
        ports=port_list,
        protocol=config.scan.protocol,
        timeout=config.scan.timeout,
        workers=config.scan.workers,
        do_resolve=config.scan.resolve,
        do_service=config.scan.services,
        show_progress=False,
        emit_open=False,
    )

    now = utc_now()
    conn = init_db(config.storage.db_path)

    prune_old_data(conn, config.storage.retention_days)
    existing_devices = fetch_known_devices(conn)
    existing_ports = fetch_known_ports(conn)

    scan_id = record_scan(
        conn,
        started_at=now,
        cidr=scan_scope,
        protocol=config.scan.protocol,
        host_count=len(ip_list),
        port_count=len(port_list),
    )

    # Persist raw results for historical baselining and reporting.
    store_scan_results(conn, scan_id, results)

    if config.reports.csv_enabled:
        csv_path = write_scan_csv(results, config.reports.output_dir, now, scan_scope)
        logging.info("CSV report written: %s", csv_path)

    if config.reports.pdf_enabled:
        report_date = utc_today_date()
        pdf_path = maybe_generate_daily_pdf(conn, config.reports.output_dir, report_date)
        if pdf_path:
            logging.info("Daily PDF report written: %s", pdf_path)

    # Compare the latest results against what we have already seen.
    new_device_ips = _new_devices(results, existing_devices)
    new_open_ports = _new_ports(results, existing_ports)

    total_open_ports = len(results)
    unique_devices = len({result.ip for result in results})

    all_ips = {result.ip for result in results}
    all_ports = {(result.ip, result.port, result.protocol) for result in results}
    upsert_devices(conn, all_ips, now)
    upsert_open_ports(conn, all_ports, now)

    # Best-effort MAC inventory from the local ARP cache.
    inventory_entries = read_arp_table()
    if inventory_entries:
        upsert_device_inventory(conn, inventory_entries, now)

    if new_device_ips or new_open_ports:
        recommendations = build_recommendations(
            config.recommendations, new_device_ips, new_open_ports
        )
        summary, details = _build_alert_message(
            scan_scope, results, new_device_ips, new_open_ports, recommendations
        )
        logging.warning("Alert triggered: %s", summary)
        record_alert(
            conn,
            created_at=now,
            alert_type="change",
            severity="medium",
            summary=summary,
            details=details,
        )
        if not config.rate_limit.enabled or should_send_alert(
            conn, "change", config.rate_limit.cooldown_minutes
        ):
            send_email_alert(config.alerts.email, summary, details)
            send_whatsapp_alert(config.alerts.whatsapp, details)
            if config.rate_limit.enabled:
                mark_alert_sent(conn, "change", now)
    else:
        logging.info("No new devices or ports detected.")

    # ML anomaly detection over scan-level features.
    feature_vector = build_feature_vector(
        total_open_ports,
        unique_devices,
        len(new_device_ips),
        len(new_open_ports),
    )
    ml_result = maybe_score_anomaly(conn, config.ml, feature_vector, scan_id)
    insert_scan_features(
        conn,
        scan_id,
        total_open_ports=total_open_ports,
        unique_devices=unique_devices,
        new_device_count=len(new_device_ips),
        new_port_count=len(new_open_ports),
        anomaly_score=ml_result.anomaly_score if ml_result else None,
        is_anomaly=ml_result.is_anomaly if ml_result else False,
    )

    if ml_result and ml_result.is_anomaly:
        ml_summary = "Network agent anomaly detected"
        recommendations = build_recommendations(
            config.recommendations, new_device_ips, new_open_ports
        )
        ml_details = (
            "Anomaly detected in scan-level metrics.\n"
            f"Scope: {scan_scope}\n"
            f"Timestamp (UTC): {now}\n"
            f"Anomaly score: {ml_result.anomaly_score:.4f}\n\n"
            "Recommendations:\n"
            f"{format_recommendations(recommendations)}"
        )
        record_alert(
            conn,
            created_at=now,
            alert_type="ml_anomaly",
            severity="medium",
            summary=ml_summary,
            details=ml_details,
        )
        if not config.rate_limit.enabled or should_send_alert(
            conn, "ml_anomaly", config.rate_limit.cooldown_minutes
        ):
            send_email_alert(config.alerts.email, ml_summary, ml_details)
            send_whatsapp_alert(config.alerts.whatsapp, ml_details)
            if config.rate_limit.enabled:
                mark_alert_sent(conn, "ml_anomaly", now)


def _new_devices(results: Sequence[ScanResult], known_devices: Set[str]) -> Set[str]:
    return {result.ip for result in results if result.ip not in known_devices}


def _new_ports(
    results: Sequence[ScanResult],
    known_ports: Set[Tuple[str, int, str]],
) -> Set[Tuple[str, int, str]]:
    return {
        (result.ip, result.port, result.protocol)
        for result in results
        if (result.ip, result.port, result.protocol) not in known_ports
    }


def _build_alert_message(
    scope: str,
    results: Sequence[ScanResult],
    new_device_ips: Set[str],
    new_open_ports: Set[Tuple[str, int, str]],
    recommendations: List[str],
) -> Tuple[str, str]:
    new_device_ports: Dict[str, List[ScanResult]] = defaultdict(list)
    new_port_entries: List[ScanResult] = []

    for result in results:
        if result.ip in new_device_ips:
            new_device_ports[result.ip].append(result)
        if (result.ip, result.port, result.protocol) in new_open_ports:
            if result.ip not in new_device_ips:
                new_port_entries.append(result)

    summary_parts = []
    if new_device_ips:
        summary_parts.append(f"{len(new_device_ips)} new device(s)")
    if new_open_ports:
        summary_parts.append(f"{len(new_open_ports)} new open port(s)")

    summary = "Network agent alert: " + ", ".join(summary_parts)

    lines = [
        f"Scope: {scope}",
        f"Timestamp (UTC): {utc_now()}",
        "",
    ]

    if new_device_ports:
        lines.append("New devices detected with open ports:")
        for ip, entries in sorted(new_device_ports.items()):
            port_list = ", ".join(f"{e.port}/{e.protocol}" for e in entries)
            hostname = entries[0].hostname or "unknown"
            lines.append(f"- {ip} ({hostname}): {port_list}")
        lines.append("")

    if new_port_entries:
        lines.append("New open ports on existing devices:")
        for entry in sorted(new_port_entries, key=lambda item: (item.ip, item.port)):
            hostname = entry.hostname or "unknown"
            lines.append(
                f"- {entry.ip} ({hostname}): {entry.port}/{entry.protocol}"
            )
        lines.append("")

    lines.append("Recommendations:")
    lines.extend(format_recommendations(recommendations).splitlines())

    return summary, "\n".join(lines)


def main() -> int:
    load_dotenv()
    setup_logging()
    parser = build_parser()
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        logging.error("Config error: %s", exc)
        return 2

    if config.traffic.enabled:
        start_traffic_monitor(config.traffic)

    if args.once:
        run_scan_once(config)
        return 0

    logging.info("Agent started. Interval: %s seconds", config.scan.interval_seconds)
    while True:
        try:
            run_scan_once(config)
        except Exception as exc:
            logging.exception("Agent scan failed: %s", exc)
        time.sleep(config.scan.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
