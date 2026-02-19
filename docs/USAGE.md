# Detailed Usage Guide

## Overview

This project provides a clean, educational TCP/UDP port scanner using Python's `socket` module. It attempts TCP connections or UDP probes to determine whether ports are open.

For the continuous monitoring agent (MVP), see [docs/AGENT.md](AGENT.md).

The agent includes a lightweight dashboard and automated CSV/PDF reports. These
are covered in [docs/AGENT.md](AGENT.md).

## Command Examples

### 1) Scan a small IP range

```bash
python port_scanner.py --start-ip 192.168.1.1 --end-ip 192.168.1.5 --ports 22,80,443
```

### 2) Scan a CIDR block

```bash
python port_scanner.py --cidr 192.168.1.0/28 --ports 1-1024
```

### 3) Increase concurrency for faster scans

```bash
python port_scanner.py --cidr 10.0.0.0/24 --ports 22,80,443 --workers 300
```

### 4) Save output as JSON and CSV

```bash
python port_scanner.py --cidr 192.168.1.0/28 --ports 20-1024 --json-out results.json --csv-out results.csv
```

### 5) Skip reverse DNS to speed up scans

```bash
python port_scanner.py --cidr 192.168.1.0/24 --ports 22,80 --no-resolve
```

### 6) Scan the top 100 common ports

```bash
python port_scanner.py --cidr 192.168.1.0/24 --top-ports 100
```

### 7) Show progress and resolve service names

```bash
python port_scanner.py --cidr 192.168.1.0/24 --ports 22,80,443 --services --progress
```

### 8) UDP scan (best-effort)

```bash
python port_scanner.py --cidr 192.168.1.0/24 --ports 53,123 --protocol udp
```

### 9) Start the web UI (local-only)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 web_app.py
```

This UI binds to 127.0.0.1, so it only runs on your own machine. Anyone who
pulls the repo will scan from their local host, not from the author's IP.

## Port List Syntax

- Single port: `80`
- Comma-separated: `22,80,443`
- Range: `8000-8100`
- Mixed: `22,80,443,8000-8100`
- Top ports: `--top-ports 50`

## Understanding Results

- Each open port is printed immediately.
- The JSON/CSV report uses these fields:
  - `ip`: Target IPv4 address.
  - `hostname`: Reverse DNS name (if enabled, otherwise `null`).
  - `port`: Open port number.
  - `protocol`: `tcp` or `udp`.
  - `service`: Well-known service name, when available.
  - `state`: Always `open` for discovered open ports.

## Demo Output

Start a local server and scan it to see guaranteed output.

Terminal A:

```bash
python3 -m http.server 8000
```

Terminal B:

```bash
python3 port_scanner.py --start-ip 127.0.0.1 --end-ip 127.0.0.1 --ports 8000 --services --progress --no-resolve
```

Example output:

```text
Progress: 1/1 (100.0%) | elapsed 0:00 | eta 0:00
127.0.0.1:8000/tcp open http-alt
```

## UDP Notes

UDP scans are best-effort. Many UDP services do not respond to empty probes, so a lack of response does not always mean the port is closed.

## Common Issues

- **Slow scans**: Increase `--workers` or reduce `--timeout`.
- **No results**: Ensure targets are reachable and the port is actually open.
- **Permission errors**: On some systems, scanning privileged ports may require elevated permissions.

## Ethics

Only scan devices and networks you are authorized to test.

## License

MIT License

Copyright (c) 2026 Evaristo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
