#!/usr/bin/env python3
"""
Local web UI for running port scans.

This app intentionally binds to 127.0.0.1 by default to avoid exposing
scanning capabilities beyond the local machine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from flask import Flask, render_template, request

from port_scanner import build_ip_list, build_port_list, run_scan


app = Flask(__name__)

# Prevent runaway scans by capping total targets.
MAX_TARGETS = 20000


def parse_int(value: str, field: str, errors: List[str]) -> Optional[int]:
    """
    Parse an integer input, adding an error if it is invalid.
    """
    value = value.strip()
    if not value:
        return None

    try:
        return int(value)
    except ValueError:
        errors.append(f"{field} must be an integer")
        return None


def parse_float(value: str, field: str, errors: List[str]) -> Optional[float]:
    """
    Parse a float input, adding an error if it is invalid.
    """
    value = value.strip()
    if not value:
        return None

    try:
        return float(value)
    except ValueError:
        errors.append(f"{field} must be a number")
        return None


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    """
    Render the web form and run scans on POST.
    """
    errors: List[str] = []
    results: List[Dict[str, Any]] = []

    form_data: Dict[str, Any] = {
        "start_ip": "127.0.0.1",
        "end_ip": "127.0.0.1",
        "cidr": "",
        "ports": "8000",
        "top_ports": "",
        "protocol": "tcp",
        "timeout": "0.5",
        "workers": "100",
        "resolve": True,
        "services": True,
    }

    if request.method == "POST":
        form_data["start_ip"] = request.form.get("start_ip", "").strip()
        form_data["end_ip"] = request.form.get("end_ip", "").strip()
        form_data["cidr"] = request.form.get("cidr", "").strip()
        form_data["ports"] = request.form.get("ports", "").strip()
        form_data["top_ports"] = request.form.get("top_ports", "").strip()
        form_data["protocol"] = request.form.get("protocol", "tcp")
        form_data["timeout"] = request.form.get("timeout", "0.5").strip()
        form_data["workers"] = request.form.get("workers", "100").strip()
        form_data["resolve"] = request.form.get("resolve") == "on"
        form_data["services"] = request.form.get("services") == "on"

        top_ports = parse_int(form_data["top_ports"], "Top ports", errors)
        workers = parse_int(form_data["workers"], "Workers", errors) or 100
        timeout = parse_float(form_data["timeout"], "Timeout", errors) or 0.5

        if workers <= 0:
            errors.append("Workers must be greater than 0")
        if timeout <= 0:
            errors.append("Timeout must be greater than 0")

        if not errors:
            try:
                ip_list = build_ip_list(
                    form_data["start_ip"] or None,
                    form_data["end_ip"] or None,
                    form_data["cidr"] or None,
                )
                port_list = build_port_list(form_data["ports"] or None, top_ports)
            except ValueError as exc:
                errors.append(str(exc))
            else:
                total_targets = len(ip_list) * len(port_list)
                if total_targets > MAX_TARGETS:
                    errors.append(
                        f"Scan is too large ({total_targets} targets). "
                        f"Reduce ranges or ports (limit {MAX_TARGETS})."
                    )
                else:
                    scan_results = run_scan(
                        ips=ip_list,
                        ports=port_list,
                        protocol=form_data["protocol"],
                        timeout=timeout,
                        workers=workers,
                        do_resolve=form_data["resolve"],
                        do_service=form_data["services"],
                        show_progress=False,
                    )

                    for item in scan_results:
                        results.append(
                            {
                                "ip": item.ip,
                                "hostname": item.hostname or "",
                                "port": item.port,
                                "protocol": item.protocol,
                                "service": item.service or "",
                                "state": item.state,
                            }
                        )

    return render_template(
        "index.html",
        errors=errors,
        results=results,
        form=form_data,
        max_targets=MAX_TARGETS,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
