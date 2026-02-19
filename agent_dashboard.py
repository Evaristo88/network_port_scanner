#!/usr/bin/env python3
"""
Lightweight dashboard for viewing agent activity.

This reads the agent SQLite database and renders recent scans, alerts, and
inventory details.
"""

from __future__ import annotations

import argparse
from typing import Dict, List

from flask import Flask, redirect, render_template, request, url_for

from agent_config import load_config
from agent_db import (
    acknowledge_alert,
    fetch_device_inventory,
    fetch_alerts_filtered,
    fetch_latest_scan_results,
    fetch_recent_devices,
    fetch_recent_scans,
    fetch_timeseries,
    init_db,
    utc_now,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agent dashboard")
    parser.add_argument(
        "--config",
        default="agent_config.json",
        help="Path to the agent config JSON file",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=5050, help="Bind port")
    return parser


def create_app(config_path: str) -> Flask:
    config = load_config(config_path)
    # The dashboard is read-only; allow cross-thread access for Flask.
    conn = init_db(config.storage.db_path, check_same_thread=False)

    app = Flask(__name__)

    @app.route("/")
    def index() -> str:
        recent_scans = fetch_recent_scans(conn)
        latest_results = fetch_latest_scan_results(conn)
        recent_devices = fetch_recent_devices(conn)
        inventory = fetch_device_inventory(conn)

        severity = request.args.get("severity", "all")
        alert_type = request.args.get("type", "all")
        acknowledged = request.args.get("ack", "all")
        filtered_alerts = fetch_alerts_filtered(
            conn,
            severity=severity,
            alert_type=alert_type,
            acknowledged=acknowledged,
        )

        timeseries = list(reversed(fetch_timeseries(conn, limit=120)))

        context: Dict[str, List] = {
            "recent_scans": recent_scans,
            "latest_results": latest_results,
            "recent_devices": recent_devices,
            "inventory": inventory,
            "filtered_alerts": filtered_alerts,
            "filters": {
                "severity": severity,
                "type": alert_type,
                "ack": acknowledged,
            },
            "timeseries": timeseries,
        }
        return render_template("dashboard.html", **context)

    @app.post("/alerts/<int:alert_id>/ack")
    def ack_alert(alert_id: int):
        acknowledge_alert(conn, alert_id, utc_now())
        return redirect(request.referrer or url_for("index"))

    return app


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    app = create_app(args.config)
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
