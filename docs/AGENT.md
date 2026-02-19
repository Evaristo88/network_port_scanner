# Agent Mode (MVP)

This document explains the new continuous monitoring agent, how it works, how to
configure it, and how to deploy it on Linux with systemd.

## What the Agent Does
- Runs scheduled port scans using the same core scanner used by the CLI and web UI.
- Stores scan history in a local SQLite database.
- Detects changes:
  - New device discovered (IP not seen before in the database).
  - New open port on any device.
- Sends email alerts via Gmail SMTP.
- Writes CSV reports for every scan.
- Generates a daily PDF summary report (UTC).
- Maintains a best-effort device inventory using the local ARP cache.
- Sends WhatsApp alerts via Twilio (optional).
- Runs ML anomaly detection on scan-level metrics (optional).
- Applies alert rate limiting to reduce noise.

## What "MVP" and "ML" Mean Here
**MVP (Minimum Viable Product)** is the smallest complete version of the agent
that still delivers the core value: scheduled scans, baselining, alerts, and
history storage. In this project, MVP means we built the reliable monitoring
loop first, then layered in extras like WhatsApp alerts and the dashboard.

**ML (Machine Learning)** refers to the optional anomaly detection step. The
agent collects simple scan metrics (open ports, devices seen, new devices, new
ports) and trains an Isolation Forest model once enough scans exist. On future
scans it scores those metrics and flags unusual patterns (anomalies) that might
indicate unexpected changes on the network.

## Files Added
- `agent.py`: The agent entrypoint (scan loop, alert logic).
- `agent_config.py`: Loads and validates JSON configuration.
- `agent_discovery.py`: Auto-discovers local subnet from the default route.
- `agent_db.py`: SQLite schema and persistence helpers.
- `agent_alerts.py`: Email alert sender.
- `agent_reports.py`: CSV per-scan reports + daily PDF summaries.
- `agent_inventory.py`: Parses `/proc/net/arp` for MAC inventory.
- `agent_dashboard.py`: Lightweight Flask dashboard for agent data.
- `agent_ml.py`: Isolation Forest anomaly detection.
- `agent_whatsapp.py`: Twilio WhatsApp sender.
- `agent_rate_limit.py`: Alert cooldown helpers.
- `traffic_monitor.py`: Gateway traffic monitoring stub.
- `agent_config.sample.json`: Sample configuration.

## How Auto-Discovery Works
The agent reads `/proc/net/route` to find the default network interface and then
uses `ioctl` calls to obtain the IPv4 address and netmask. From that, it derives
CIDR (example: `192.168.1.0/24`).

This auto-discovery method is Linux-specific. On other platforms, set `scan.cidr`
manually in the config.

If auto-discovery fails, set `scan.cidr` or `scan.start_ip`/`scan.end_ip` in the
config.

## Configuration
Copy the sample config and edit it:

```bash
cp agent_config.sample.json agent_config.json
```

`agent_config.json` is ignored by git to protect credentials. Do not commit
real SMTP passwords.

If you use the prefilled `agent_config.json`, replace `APP_PASSWORD_HERE` with
your Gmail App Password before running the agent.

## Local Setup Steps (Reference)
These are the exact steps used to set up the agent on Linux:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp agent_config.sample.json agent_config.json
```

Then update `agent_config.json` with your Gmail App Password.

### Scan Settings
- `scan.cidr`: CIDR block to scan. Use `"auto"` to auto-discover.
- `scan.start_ip` and `scan.end_ip`: Optional IP range (takes priority if both set).
- `scan.ports`: Port list string (`"22,80,443,8000-8100"`).
- `scan.top_ports`: Optional top-N ports to add.
- `scan.protocol`: `"tcp"` or `"udp"`.
- `scan.timeout`: Socket timeout in seconds.
- `scan.workers`: Number of threads.
- `scan.resolve`: Reverse DNS on open ports.
- `scan.services`: Resolve service names on open ports.
- `scan.interval_seconds`: How often to repeat scans.

### Storage Settings
- `storage.db_path`: Path to SQLite database.
- `storage.retention_days`: How many days to keep scan history.

### Alerts (Gmail)
- `alerts.email.enabled`: `true` to send email alerts.
- `alerts.email.smtp_host`: `smtp.gmail.com`.
- `alerts.email.smtp_port`: `587`.
- `alerts.email.use_tls`: `true` for STARTTLS.
- `alerts.email.username`: Gmail account.
- `alerts.email.app_password`: Gmail App Password.
- `alerts.email.from_addr`: Sender address (usually same as username).
- `alerts.email.to_addrs`: List of recipients.

### Alerts (WhatsApp via Twilio)
- `alerts.whatsapp.enabled`: Enable or disable WhatsApp alerts.
- `alerts.whatsapp.account_sid/auth_token`: Optional direct values.
- `alerts.whatsapp.from_number/to_number`: Optional direct values.
- `alerts.whatsapp.*_env`: Environment variable names to pull from `.env`.
- Optional: `alerts.whatsapp.status_callback` (or `TWILIO_STATUS_CALLBACK`) if
  Twilio requires a valid callback URL.

Recommended: store Twilio secrets in `.env` and keep the config file free of
credentials.

### Reports
- `reports.csv_enabled`: Write CSV output for each scan.
- `reports.pdf_enabled`: Generate a daily PDF summary in UTC.
- `reports.output_dir`: Directory for reports (CSV + PDF).

### ML Anomaly Detection
- `ml.enabled`: Toggle Isolation Forest scoring.
- `ml.min_samples`: Minimum scans required before scoring.
- `ml.contamination`: Expected anomaly rate.
- `ml.retrain_every`: Retrain cadence in scan count.
- `ml.model_path`: Path to the saved model.

### Recommendations
- `recommendations.ai_enabled`: Reserved for future GPT integration.

### Traffic Monitoring
- `traffic.enabled`: Enable when deployed on gateway.
- `traffic.mode`: `gateway` or `mirror` (planning only for now).
- `traffic.interface`: Optional interface name.

### Rate Limiting
- `rate_limit.enabled`: Enable cooldowns between alert sends.
- `rate_limit.cooldown_minutes`: Minimum minutes between alerts of the same type.

## Gmail App Password Setup
1) Enable 2-Step Verification on your Google account.
2) Create an App Password for "Mail".
3) Paste the 16-character password into `alerts.email.app_password`.

## How Alerts Work
The agent creates alerts when:
- A new device is discovered (IP not seen before) and it has open ports.
- A new open port appears on a device that was already known.

Alerts are stored in the SQLite database and sent via email.

When WhatsApp is enabled, the same alert body is sent to the configured number.

Rate limiting prevents multiple alerts of the same type within a cooldown window.

## Database Schema (SQLite)
The database lives at `storage.db_path` and includes:
- `scans`: metadata for each scan run.
- `scan_results`: open ports found in each scan.
- `devices`: first and last seen times per IP.
- `open_ports`: first and last seen times per IP/port/protocol.
- `alerts`: alert history and details.
- `report_runs`: record of daily PDF report runs.
- `device_inventory`: best-effort IP/MAC inventory from ARP.
- `alert_state`: cooldown tracking for alert types.
- `scan_features`: scan-level metrics used for anomaly detection.

## Running the Agent
One-time scan:

```bash
python agent.py --once
```

Continuous mode:

```bash
python agent.py
```

## Reports
CSV files are generated on every scan in `reports.output_dir`. The daily PDF
summary (UTC) is generated once per day and stored in the same directory.

## Device Inventory (Scope 2)
The agent reads `/proc/net/arp` to capture IP-to-MAC pairs for devices that
recently communicated with this machine. This is best-effort and depends on
local traffic. The inventory appears in the dashboard and is stored in
`device_inventory`.

## Dashboard
The dashboard is a lightweight Flask app that reads the agent database.

It now includes:
- Time-series charts for open ports, devices, and new changes.
- Alert filters (severity, type, acknowledged).
- Alert acknowledgment workflow.

Start it locally:

```bash
python agent_dashboard.py --config agent_config.json
```

Then open http://127.0.0.1:5050

## Deployment with systemd (Recommended)
A sample unit file is included at:
- `deploy/port_scanner_agent.service`

### Steps
1) Copy the service file and edit paths:

```bash
sudo cp deploy/port_scanner_agent.service /etc/systemd/system/port_scanner_agent.service
sudo nano /etc/systemd/system/port_scanner_agent.service
```

If your repo path contains spaces, systemd requires escaping. You can either:
- Move the repo to a path without spaces, or
- Use `systemd-escape` to generate a safe path.

Alternative (simple): create a symlink without spaces and point the service to it:

```bash
ln -s "/home/evaristo/Documents/My Projects/network_port_scanner" /home/evaristo/network_port_scanner
```

## Environment Variables (.env)
If using WhatsApp alerts, add the following to `.env`:

```
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_WHATSAPP_FROM=whatsapp:+1415...
TWILIO_WHATSAPP_TO=whatsapp:+254...
```

`.env` is ignored by git.

2) Reload and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now port_scanner_agent.service
```

3) View logs:

```bash
journalctl -u port_scanner_agent.service -f
```

## Notes and Limitations
- This MVP observes port changes only. It does not inspect network traffic.
- For full network traffic monitoring, the agent must run on the gateway or use
  port mirroring/monitor mode.
- Always use this tool on networks you own or have permission to monitor.
