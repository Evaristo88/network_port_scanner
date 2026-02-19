from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from typing import Iterable, List, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from agent_db import (
    fetch_alerts_in_range,
    fetch_scan_stats,
    fetch_top_devices,
    report_exists,
    record_report_run,
    utc_now,
)
from port_scanner import ScanResult


def write_scan_csv(
    results: Iterable[ScanResult],
    output_dir: str,
    scan_time: str,
    scope: str,
) -> str:
    # Write a per-scan CSV with enough context to join later.
    os.makedirs(output_dir, exist_ok=True)
    timestamp = _safe_timestamp(scan_time)
    path = os.path.join(output_dir, f"scan_{timestamp}.csv")

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "scan_time_utc",
                "scope",
                "ip",
                "hostname",
                "port",
                "protocol",
                "service",
                "state",
            ]
        )
        for result in results:
            writer.writerow(
                [
                    scan_time,
                    scope,
                    result.ip,
                    result.hostname or "",
                    result.port,
                    result.protocol,
                    result.service or "",
                    result.state,
                ]
            )

    return path


def maybe_generate_daily_pdf(
    conn,
    output_dir: str,
    report_date: str,
) -> str | None:
    # Avoid regenerating the same daily report.
    if report_exists(conn, report_date, "daily_pdf"):
        return None

    path = generate_daily_pdf_summary(conn, output_dir, report_date)
    record_report_run(conn, report_date, "daily_pdf", path)
    return path


def generate_daily_pdf_summary(conn, output_dir: str, report_date: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"daily_summary_{report_date}.pdf")

    start_iso, end_iso = _day_bounds_iso(report_date)
    scan_stats = fetch_scan_stats(conn, start_iso, end_iso)
    top_devices = fetch_top_devices(conn, start_iso, end_iso)
    alerts = fetch_alerts_in_range(conn, start_iso, end_iso)

    # Simple PDF layout using reportlab tables.
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=letter, title="Network Agent Daily Summary")

    story: List[object] = []
    story.append(Paragraph("Network Agent Daily Summary", styles["Title"]))
    story.append(Paragraph(f"Report date (UTC): {report_date}", styles["Normal"]))
    story.append(Paragraph(f"Generated at (UTC): {utc_now()}", styles["Normal"]))
    story.append(Spacer(1, 12))

    stats_table = [
        ["Scans run", str(scan_stats["scan_count"])],
        ["Unique devices seen", str(scan_stats["device_count"])],
        ["Open ports observed", str(scan_stats["open_port_count"])],
    ]
    story.append(Paragraph("Scan Summary", styles["Heading2"]))
    story.append(_build_table(stats_table))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Top Devices (by open ports)", styles["Heading2"]))
    if top_devices:
        device_table = [["IP", "Open ports"]] + [
            [ip, str(count)] for ip, count in top_devices
        ]
        story.append(_build_table(device_table, header=True))
    else:
        story.append(Paragraph("No open ports recorded for this date.", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Alerts", styles["Heading2"]))
    if alerts:
        alert_table = [["Time (UTC)", "Severity", "Summary"]] + [
            [created_at, severity, summary] for created_at, severity, summary in alerts
        ]
        story.append(_build_table(alert_table, header=True, col_widths=[140, 60, 330]))
    else:
        story.append(Paragraph("No alerts triggered for this date.", styles["Normal"]))

    doc.build(story)
    return path


def _build_table(
    rows: List[List[str]],
    header: bool = False,
    col_widths: List[int] | None = None,
) -> Table:
    table = Table(rows, colWidths=col_widths)
    style = TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ])
    if header:
        style.add("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)
        style.add("TEXTCOLOR", (0, 0), (-1, 0), colors.black)
        style.add("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")
    table.setStyle(style)
    return table


def _safe_timestamp(iso_time: str) -> str:
    # Filesystem-safe UTC timestamp for report filenames.
    return iso_time.replace(":", "").replace("+", "").replace("-", "")


def _day_bounds_iso(report_date: str) -> Tuple[str, str]:
    start = datetime.strptime(report_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    end = start.replace(hour=23, minute=59, second=59)
    return start.isoformat(), end.isoformat()


def utc_today_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")
