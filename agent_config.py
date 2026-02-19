from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional


# Config sections are modeled as dataclasses for validation and clarity.


@dataclass(frozen=True)
class EmailConfig:
    enabled: bool
    smtp_host: str
    smtp_port: int
    use_tls: bool
    username: str
    app_password: str
    from_addr: str
    to_addrs: List[str]


@dataclass(frozen=True)
class AlertsConfig:
    email: EmailConfig
    whatsapp: "WhatsAppConfig"


@dataclass(frozen=True)
class WhatsAppConfig:
    enabled: bool
    account_sid: Optional[str]
    auth_token: Optional[str]
    from_number: Optional[str]
    to_number: Optional[str]
    account_sid_env: str
    auth_token_env: str
    from_number_env: str
    to_number_env: str
    status_callback: Optional[str]
    status_callback_env: str


@dataclass(frozen=True)
class StorageConfig:
    db_path: str
    retention_days: int


@dataclass(frozen=True)
class ReportsConfig:
    csv_enabled: bool
    pdf_enabled: bool
    output_dir: str


@dataclass(frozen=True)
class MlConfig:
    enabled: bool
    min_samples: int
    contamination: float
    retrain_every: int
    model_path: str


@dataclass(frozen=True)
class RecommendationsConfig:
    ai_enabled: bool


@dataclass(frozen=True)
class TrafficConfig:
    enabled: bool
    mode: str
    interface: Optional[str]


@dataclass(frozen=True)
class RateLimitConfig:
    enabled: bool
    cooldown_minutes: int


@dataclass(frozen=True)
class ScanConfig:
    cidr: Optional[str]
    auto_cidr: bool
    start_ip: Optional[str]
    end_ip: Optional[str]
    ports: Optional[str]
    top_ports: Optional[int]
    protocol: str
    timeout: float
    workers: int
    resolve: bool
    services: bool
    interval_seconds: int


@dataclass(frozen=True)
class AgentConfig:
    scan: ScanConfig
    storage: StorageConfig
    alerts: AlertsConfig
    reports: ReportsConfig
    ml: MlConfig
    recommendations: RecommendationsConfig
    traffic: TrafficConfig
    rate_limit: RateLimitConfig


def _require(obj: dict, key: str, expected_type: object) -> object:
    if key not in obj:
        raise ValueError(f"Missing required config key: {key}")
    value = obj[key]
    if not isinstance(value, expected_type):
        expected_name = _type_name(expected_type)
        raise ValueError(f"Config key {key} must be {expected_name}")
    return value


def _optional(obj: dict, key: str, expected_type: object) -> Optional[object]:
    if key not in obj or obj[key] is None:
        return None
    value = obj[key]
    if not isinstance(value, expected_type):
        expected_name = _type_name(expected_type)
        raise ValueError(f"Config key {key} must be {expected_name}")
    return value


def _type_name(expected: object) -> str:
    if isinstance(expected, tuple):
        return " or ".join(t.__name__ for t in expected)
    return expected.__name__


def load_config(path: str) -> AgentConfig:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    scan_raw = _require(payload, "scan", dict)
    storage_raw = _require(payload, "storage", dict)
    alerts_raw = _require(payload, "alerts", dict)
    reports_raw = _require(payload, "reports", dict)
    ml_raw = payload.get("ml", {})
    recommendations_raw = payload.get("recommendations", {})
    traffic_raw = payload.get("traffic", {})
    rate_limit_raw = payload.get("rate_limit", {})

    # Treat cidr="auto" or empty as auto-discovery.
    cidr_value = scan_raw.get("cidr")
    auto_cidr = cidr_value in (None, "", "auto")
    if cidr_value is not None and not auto_cidr and not isinstance(cidr_value, str):
        raise ValueError("scan.cidr must be a string, null, or 'auto'")

    scan = ScanConfig(
        cidr=None if auto_cidr else cidr_value,
        auto_cidr=auto_cidr,
        start_ip=_optional(scan_raw, "start_ip", str),
        end_ip=_optional(scan_raw, "end_ip", str),
        ports=_optional(scan_raw, "ports", str),
        top_ports=_optional(scan_raw, "top_ports", int),
        protocol=_require(scan_raw, "protocol", str),
        timeout=float(_require(scan_raw, "timeout", (int, float))),
        workers=int(_require(scan_raw, "workers", int)),
        resolve=bool(_require(scan_raw, "resolve", bool)),
        services=bool(_require(scan_raw, "services", bool)),
        interval_seconds=int(_require(scan_raw, "interval_seconds", int)),
    )

    storage = StorageConfig(
        db_path=_require(storage_raw, "db_path", str),
        retention_days=int(_require(storage_raw, "retention_days", int)),
    )

    email_raw = _require(alerts_raw, "email", dict)
    email = EmailConfig(
        enabled=bool(_require(email_raw, "enabled", bool)),
        smtp_host=_require(email_raw, "smtp_host", str),
        smtp_port=int(_require(email_raw, "smtp_port", int)),
        use_tls=bool(_require(email_raw, "use_tls", bool)),
        username=_require(email_raw, "username", str),
        app_password=_require(email_raw, "app_password", str),
        from_addr=_require(email_raw, "from_addr", str),
        to_addrs=list(_require(email_raw, "to_addrs", list)),
    )

    whatsapp_raw = alerts_raw.get("whatsapp", {})
    whatsapp = WhatsAppConfig(
        enabled=bool(whatsapp_raw.get("enabled", False)),
        account_sid=_optional(whatsapp_raw, "account_sid", str),
        auth_token=_optional(whatsapp_raw, "auth_token", str),
        from_number=_optional(whatsapp_raw, "from_number", str),
        to_number=_optional(whatsapp_raw, "to_number", str),
        account_sid_env=whatsapp_raw.get("account_sid_env", "TWILIO_ACCOUNT_SID"),
        auth_token_env=whatsapp_raw.get("auth_token_env", "TWILIO_AUTH_TOKEN"),
        from_number_env=whatsapp_raw.get("from_number_env", "TWILIO_WHATSAPP_FROM"),
        to_number_env=whatsapp_raw.get("to_number_env", "TWILIO_WHATSAPP_TO"),
        status_callback=_optional(whatsapp_raw, "status_callback", str),
        status_callback_env=whatsapp_raw.get("status_callback_env", "TWILIO_STATUS_CALLBACK"),
    )

    alerts = AlertsConfig(email=email, whatsapp=whatsapp)

    reports = ReportsConfig(
        csv_enabled=bool(_require(reports_raw, "csv_enabled", bool)),
        pdf_enabled=bool(_require(reports_raw, "pdf_enabled", bool)),
        output_dir=_require(reports_raw, "output_dir", str),
    )

    ml = MlConfig(
        enabled=bool(ml_raw.get("enabled", False)),
        min_samples=int(ml_raw.get("min_samples", 20)),
        contamination=float(ml_raw.get("contamination", 0.05)),
        retrain_every=int(ml_raw.get("retrain_every", 10)),
        model_path=ml_raw.get("model_path", "agent_data/models/isoforest.joblib"),
    )

    recommendations = RecommendationsConfig(
        ai_enabled=bool(recommendations_raw.get("ai_enabled", False)),
    )

    traffic = TrafficConfig(
        enabled=bool(traffic_raw.get("enabled", False)),
        mode=traffic_raw.get("mode", "gateway"),
        interface=_optional(traffic_raw, "interface", str),
    )

    rate_limit = RateLimitConfig(
        enabled=bool(rate_limit_raw.get("enabled", True)),
        cooldown_minutes=int(rate_limit_raw.get("cooldown_minutes", 15)),
    )

    _validate_scan(scan)
    _validate_storage(storage)
    _validate_email(email)
    _validate_reports(reports)
    _validate_whatsapp(whatsapp)
    _validate_ml(ml)
    _validate_traffic(traffic)
    _validate_rate_limit(rate_limit)

    return AgentConfig(
        scan=scan,
        storage=storage,
        alerts=alerts,
        reports=reports,
        ml=ml,
        recommendations=recommendations,
        traffic=traffic,
        rate_limit=rate_limit,
    )


def _validate_scan(scan: ScanConfig) -> None:
    if scan.interval_seconds <= 0:
        raise ValueError("scan.interval_seconds must be greater than 0")
    if scan.timeout <= 0:
        raise ValueError("scan.timeout must be greater than 0")
    if scan.workers <= 0:
        raise ValueError("scan.workers must be greater than 0")
    if scan.protocol not in ("tcp", "udp"):
        raise ValueError("scan.protocol must be tcp or udp")
    if scan.ports is None and scan.top_ports is None:
        raise ValueError("Provide scan.ports, scan.top_ports, or both")


def _validate_storage(storage: StorageConfig) -> None:
    if storage.retention_days <= 0:
        raise ValueError("storage.retention_days must be greater than 0")


def _validate_email(email: EmailConfig) -> None:
    if email.enabled and not email.to_addrs:
        raise ValueError("alerts.email.to_addrs must have at least one recipient")
    if any(not isinstance(addr, str) for addr in email.to_addrs):
        raise ValueError("alerts.email.to_addrs must contain only strings")


def _validate_reports(reports: ReportsConfig) -> None:
    if not reports.output_dir:
        raise ValueError("reports.output_dir must be set")


def _validate_whatsapp(whatsapp: WhatsAppConfig) -> None:
    if whatsapp.enabled:
        if not (whatsapp.account_sid or whatsapp.account_sid_env):
            raise ValueError("alerts.whatsapp.account_sid or account_sid_env must be set")
        if not (whatsapp.auth_token or whatsapp.auth_token_env):
            raise ValueError("alerts.whatsapp.auth_token or auth_token_env must be set")
        if not (whatsapp.from_number or whatsapp.from_number_env):
            raise ValueError("alerts.whatsapp.from_number or from_number_env must be set")
        if not (whatsapp.to_number or whatsapp.to_number_env):
            raise ValueError("alerts.whatsapp.to_number or to_number_env must be set")


def _validate_ml(ml: MlConfig) -> None:
    if ml.enabled and ml.min_samples < 5:
        raise ValueError("ml.min_samples must be at least 5")
    if ml.contamination <= 0 or ml.contamination >= 0.5:
        raise ValueError("ml.contamination must be between 0 and 0.5")
    if ml.retrain_every <= 0:
        raise ValueError("ml.retrain_every must be greater than 0")


def _validate_traffic(traffic: TrafficConfig) -> None:
    if traffic.enabled and not traffic.mode:
        raise ValueError("traffic.mode must be set when enabled")


def _validate_rate_limit(rate_limit: RateLimitConfig) -> None:
    if rate_limit.cooldown_minutes <= 0:
        raise ValueError("rate_limit.cooldown_minutes must be greater than 0")
