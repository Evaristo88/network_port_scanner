from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Sequence, Set, Tuple

from port_scanner import ScanResult


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_db(db_path: str, check_same_thread: bool = True) -> sqlite3.Connection:
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    # WAL improves concurrency for reads from the dashboard.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # Core scan history tables.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            cidr TEXT NOT NULL,
            protocol TEXT NOT NULL,
            host_count INTEGER NOT NULL,
            port_count INTEGER NOT NULL
        )
        """
    )

    # Alert history and report metadata.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_results (
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            state TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
        """
    )

    # Best-effort device inventory (ARP-derived).
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS open_ports (
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (ip, port, protocol)
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            summary TEXT NOT NULL,
            details TEXT NOT NULL
        )
        """
    )

    _ensure_alert_ack_columns(conn)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS report_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_date TEXT NOT NULL,
            report_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            path TEXT NOT NULL,
            UNIQUE(report_date, report_type)
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS device_inventory (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_state (
            alert_key TEXT PRIMARY KEY,
            last_sent TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_features (
            scan_id INTEGER PRIMARY KEY,
            total_open_ports INTEGER NOT NULL,
            unique_devices INTEGER NOT NULL,
            new_device_count INTEGER NOT NULL,
            new_port_count INTEGER NOT NULL,
            anomaly_score REAL,
            is_anomaly INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
        """
    )

    conn.commit()
    return conn


def record_scan(
    conn: sqlite3.Connection,
    started_at: str,
    cidr: str,
    protocol: str,
    host_count: int,
    port_count: int,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO scans (started_at, cidr, protocol, host_count, port_count)
        VALUES (?, ?, ?, ?, ?)
        """,
        (started_at, cidr, protocol, host_count, port_count),
    )
    conn.commit()
    return int(cursor.lastrowid)


def store_scan_results(
    conn: sqlite3.Connection,
    scan_id: int,
    results: Sequence[ScanResult],
) -> None:
    conn.executemany(
        """
        INSERT INTO scan_results (scan_id, ip, hostname, port, protocol, service, state)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (scan_id, r.ip, r.hostname, r.port, r.protocol, r.service, r.state)
            for r in results
        ],
    )
    conn.commit()


def acknowledge_alert(conn: sqlite3.Connection, alert_id: int, ack_time: str) -> None:
    conn.execute(
        "UPDATE alerts SET acknowledged_at = ? WHERE id = ?",
        (ack_time, alert_id),
    )
    conn.commit()


def fetch_alerts_filtered(
    conn: sqlite3.Connection,
    severity: str | None = None,
    alert_type: str | None = None,
    acknowledged: str | None = None,
    limit: int = 50,
) -> List[Tuple[int, str, str, str, str | None]]:
    clauses = []
    params: List[object] = []

    if severity and severity != "all":
        clauses.append("severity = ?")
        params.append(severity)
    if alert_type and alert_type != "all":
        clauses.append("alert_type = ?")
        params.append(alert_type)
    if acknowledged == "yes":
        clauses.append("acknowledged_at IS NOT NULL")
    elif acknowledged == "no":
        clauses.append("acknowledged_at IS NULL")

    where_clause = ""
    if clauses:
        where_clause = "WHERE " + " AND ".join(clauses)

    query = (
        "SELECT id, created_at, severity, summary, acknowledged_at "
        "FROM alerts "
        f"{where_clause} "
        "ORDER BY created_at DESC "
        "LIMIT ?"
    )
    params.append(limit)

    cursor = conn.execute(query, params)
    return [
        (int(row[0]), row[1], row[2], row[3], row[4])
        for row in cursor.fetchall()
    ]
def fetch_known_devices(conn: sqlite3.Connection) -> Set[str]:
    cursor = conn.execute("SELECT ip FROM devices")
    return {row[0] for row in cursor.fetchall()}


def fetch_timeseries(conn: sqlite3.Connection, limit: int = 200) -> List[Tuple[str, int, int, int, int, int]]:
    cursor = conn.execute(
        """
        SELECT s.started_at,
               COALESCE(f.total_open_ports, 0),
               COALESCE(f.unique_devices, 0),
               COALESCE(f.new_device_count, 0),
               COALESCE(f.new_port_count, 0),
               COALESCE(f.is_anomaly, 0)
        FROM scans s
        LEFT JOIN scan_features f ON f.scan_id = s.id
        ORDER BY s.started_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [
        (row[0], int(row[1]), int(row[2]), int(row[3]), int(row[4]), int(row[5]))
        for row in cursor.fetchall()
    ]


def _ensure_alert_ack_columns(conn: sqlite3.Connection) -> None:
    cursor = conn.execute("PRAGMA table_info(alerts)")
    columns = {row[1] for row in cursor.fetchall()}
    if "acknowledged_at" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT")
    if "acknowledged_by" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT")
    conn.commit()

def fetch_known_ports(conn: sqlite3.Connection) -> Set[Tuple[str, int, str]]:
    cursor = conn.execute("SELECT ip, port, protocol FROM open_ports")
    return {(row[0], int(row[1]), row[2]) for row in cursor.fetchall()}


def upsert_devices(
    conn: sqlite3.Connection,
    ips: Iterable[str],
    now: str,
) -> None:
    for ip in ips:
        conn.execute(
            """
            INSERT INTO devices (ip, first_seen, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen
            """,
            (ip, now, now),
        )
    conn.commit()


def upsert_open_ports(
    conn: sqlite3.Connection,
    ports: Iterable[Tuple[str, int, str]],
    now: str,
) -> None:
    for ip, port, protocol in ports:
        conn.execute(
            """
            INSERT INTO open_ports (ip, port, protocol, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip, port, protocol) DO UPDATE SET last_seen=excluded.last_seen
            """,
            (ip, port, protocol, now, now),
        )
    conn.commit()


def record_alert(
    conn: sqlite3.Connection,
    created_at: str,
    alert_type: str,
    severity: str,
    summary: str,
    details: str,
) -> None:
    conn.execute(
        """
        INSERT INTO alerts (created_at, alert_type, severity, summary, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (created_at, alert_type, severity, summary, details),
    )
    conn.commit()


def get_alert_state(conn: sqlite3.Connection, alert_key: str) -> str | None:
    cursor = conn.execute(
        "SELECT last_sent FROM alert_state WHERE alert_key = ?",
        (alert_key,),
    )
    row = cursor.fetchone()
    return row[0] if row else None


def update_alert_state(conn: sqlite3.Connection, alert_key: str, last_sent: str) -> None:
    conn.execute(
        """
        INSERT INTO alert_state (alert_key, last_sent)
        VALUES (?, ?)
        ON CONFLICT(alert_key) DO UPDATE SET last_sent=excluded.last_sent
        """,
        (alert_key, last_sent),
    )
    conn.commit()


def prune_old_data(conn: sqlite3.Connection, retention_days: int) -> None:
    # Retention keeps the DB compact for long-running agents.
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cutoff_iso = cutoff.replace(microsecond=0).isoformat()

    conn.execute(
        "DELETE FROM scans WHERE started_at < ?",
        (cutoff_iso,),
    )
    conn.execute(
        "DELETE FROM scan_results WHERE scan_id NOT IN (SELECT id FROM scans)",
    )
    conn.execute(
        "DELETE FROM alerts WHERE created_at < ?",
        (cutoff_iso,),
    )
    conn.commit()


def record_report_run(
    conn: sqlite3.Connection,
    report_date: str,
    report_type: str,
    path: str,
) -> None:
    conn.execute(
        """
        INSERT INTO report_runs (report_date, report_type, created_at, path)
        VALUES (?, ?, ?, ?)
        """,
        (report_date, report_type, utc_now(), path),
    )
    conn.commit()


def report_exists(conn: sqlite3.Connection, report_date: str, report_type: str) -> bool:
    cursor = conn.execute(
        """
        SELECT 1 FROM report_runs
        WHERE report_date = ? AND report_type = ?
        LIMIT 1
        """,
        (report_date, report_type),
    )
    return cursor.fetchone() is not None


def fetch_scan_stats(conn: sqlite3.Connection, start_iso: str, end_iso: str) -> dict:
    # Aggregate scan counts and coverage for daily summaries.
    cursor = conn.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE started_at BETWEEN ? AND ?
        """,
        (start_iso, end_iso),
    )
    scan_count = int(cursor.fetchone()[0])

    cursor = conn.execute(
        """
        SELECT COUNT(*)
        FROM scan_results sr
        JOIN scans s ON sr.scan_id = s.id
        WHERE s.started_at BETWEEN ? AND ?
        """,
        (start_iso, end_iso),
    )
    open_port_count = int(cursor.fetchone()[0])

    cursor = conn.execute(
        """
        SELECT COUNT(DISTINCT sr.ip)
        FROM scan_results sr
        JOIN scans s ON sr.scan_id = s.id
        WHERE s.started_at BETWEEN ? AND ?
        """,
        (start_iso, end_iso),
    )
    device_count = int(cursor.fetchone()[0])

    return {
        "scan_count": scan_count,
        "open_port_count": open_port_count,
        "device_count": device_count,
    }


def insert_scan_features(
    conn: sqlite3.Connection,
    scan_id: int,
    total_open_ports: int,
    unique_devices: int,
    new_device_count: int,
    new_port_count: int,
    anomaly_score: float | None,
    is_anomaly: bool,
) -> None:
    conn.execute(
        """
        INSERT INTO scan_features (
            scan_id,
            total_open_ports,
            unique_devices,
            new_device_count,
            new_port_count,
            anomaly_score,
            is_anomaly
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            total_open_ports,
            unique_devices,
            new_device_count,
            new_port_count,
            anomaly_score,
            1 if is_anomaly else 0,
        ),
    )
    conn.commit()


def fetch_recent_features(conn: sqlite3.Connection, limit: int = 200) -> List[Tuple[int, int, int, int]]:
    cursor = conn.execute(
        """
        SELECT total_open_ports, unique_devices, new_device_count, new_port_count
        FROM scan_features
        ORDER BY scan_id DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [
        (int(row[0]), int(row[1]), int(row[2]), int(row[3]))
        for row in cursor.fetchall()
    ]


def fetch_top_devices(
    conn: sqlite3.Connection,
    start_iso: str,
    end_iso: str,
    limit: int = 10,
) -> List[Tuple[str, int]]:
    cursor = conn.execute(
        """
        SELECT sr.ip, COUNT(*) as port_count
        FROM scan_results sr
        JOIN scans s ON sr.scan_id = s.id
        WHERE s.started_at BETWEEN ? AND ?
        GROUP BY sr.ip
        ORDER BY port_count DESC
        LIMIT ?
        """,
        (start_iso, end_iso, limit),
    )
    return [(row[0], int(row[1])) for row in cursor.fetchall()]


def fetch_alerts_in_range(
    conn: sqlite3.Connection,
    start_iso: str,
    end_iso: str,
    limit: int = 20,
) -> List[Tuple[str, str, str]]:
    cursor = conn.execute(
        """
        SELECT created_at, severity, summary
        FROM alerts
        WHERE created_at BETWEEN ? AND ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (start_iso, end_iso, limit),
    )
    return [(row[0], row[1], row[2]) for row in cursor.fetchall()]


def upsert_device_inventory(
    conn: sqlite3.Connection,
    entries: Iterable[Tuple[str, str]],
    now: str,
) -> None:
    for ip, mac in entries:
        conn.execute(
            """
            INSERT INTO device_inventory (ip, mac, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac=COALESCE(excluded.mac, device_inventory.mac),
                last_seen=excluded.last_seen
            """,
            (ip, mac, now, now),
        )
    conn.commit()


def fetch_device_inventory(conn: sqlite3.Connection, limit: int = 200) -> List[Tuple[str, str, str]]:
    cursor = conn.execute(
        """
        SELECT ip, COALESCE(mac, ''), last_seen
        FROM device_inventory
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [(row[0], row[1], row[2]) for row in cursor.fetchall()]


def fetch_recent_scans(conn: sqlite3.Connection, limit: int = 20) -> List[Tuple[str, str, str, int, int]]:
    cursor = conn.execute(
        """
        SELECT started_at, cidr, protocol, host_count, port_count
        FROM scans
        ORDER BY started_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [
        (row[0], row[1], row[2], int(row[3]), int(row[4]))
        for row in cursor.fetchall()
    ]


def fetch_latest_scan_results(conn: sqlite3.Connection, limit: int = 200) -> List[Tuple[str, str, int, str, str, str]]:
    # Use the most recent scan ID as the dashboard data source.
    cursor = conn.execute(
        "SELECT id FROM scans ORDER BY started_at DESC LIMIT 1"
    )
    row = cursor.fetchone()
    if not row:
        return []
    scan_id = int(row[0])

    cursor = conn.execute(
        """
        SELECT ip, COALESCE(hostname, ''), port, protocol, COALESCE(service, ''), state
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY ip, port
        LIMIT ?
        """,
        (scan_id, limit),
    )
    return [
        (row[0], row[1], int(row[2]), row[3], row[4], row[5])
        for row in cursor.fetchall()
    ]


def fetch_latest_alerts(conn: sqlite3.Connection, limit: int = 20) -> List[Tuple[str, str, str]]:
    cursor = conn.execute(
        """
        SELECT created_at, severity, summary
        FROM alerts
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [(row[0], row[1], row[2]) for row in cursor.fetchall()]


def fetch_recent_devices(conn: sqlite3.Connection, limit: int = 50) -> List[Tuple[str, str]]:
    cursor = conn.execute(
        """
        SELECT ip, last_seen
        FROM devices
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [(row[0], row[1]) for row in cursor.fetchall()]
