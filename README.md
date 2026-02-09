# Network Port Scanner

[![Tests](https://github.com/Evaristo88/network_port_scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/Evaristo88/network_port_scanner/actions/workflows/tests.yml)

A simple, educational Python port scanner that attempts TCP connections across an IP range and port list to identify open ports.

## Features
- Scans IPv4 ranges (start/end) or CIDR blocks.
- Scans TCP or UDP with a selectable protocol.
- Scans single ports, port ranges, or top N common ports.
- Progress and ETA display for long scans.
- Optional service name resolution.
- Concurrency via thread pool for faster scans.
- CSV and JSON report output.
- Clear, commented code for learning.

## Quick Start

1. Create a virtual environment (optional but recommended):

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Run a scan:

```bash
python port_scanner.py --start-ip 192.168.1.1 --end-ip 192.168.1.10 --ports 22,80,443
```

3. Scan with CIDR and save output:

```bash
python port_scanner.py --cidr 192.168.1.0/28 --ports 20-1024 --timeout 0.7 --workers 200 --json-out results.json --csv-out results.csv
```

## Web UI (Local-Only)
Run a local-only web interface that wraps the scanner. This binds to 127.0.0.1
on your machine, so users who clone the repo will only scan from their own
computer (not your IP).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 web_app.py
```

Open http://127.0.0.1:5000 in your browser.

## Demo Output

1. Start a local HTTP server (leave it running):

```bash
python3 -m http.server 8000
```

2. Run the scanner in another terminal:

```bash
python3 port_scanner.py --start-ip 127.0.0.1 --end-ip 127.0.0.1 --ports 8000 --services --progress --no-resolve
```

Example output:
```text
Progress: 1/1 (100.0%) | elapsed 0:00 | eta 0:00
127.0.0.1:8000/tcp open http-alt
```

## Usage

```text
python port_scanner.py [--start-ip IP --end-ip IP | --cidr CIDR]
                       [--ports PORTS] [--top-ports N]
                       [--protocol tcp|udp]
                       [--timeout SECONDS] [--workers N]
                       [--json-out PATH] [--csv-out PATH]
                       [--no-resolve] [--services] [--progress]
```

### Arguments
- `--start-ip`: First IPv4 address in the scan range.
- `--end-ip`: Last IPv4 address in the scan range.
- `--cidr`: CIDR block (e.g., `10.0.0.0/24`).
- `--ports`: Port list or ranges (e.g., `22,80,443,8000-8100`).
- `--top-ports`: Scan the top N common ports (e.g., `20`, `50`, `100`).
- `--protocol`: Protocol to scan (`tcp` or `udp`, default: `tcp`).
- `--timeout`: Socket timeout in seconds (default: 0.5).
- `--workers`: Number of concurrent threads (default: 100).
- `--json-out`: Save results to a JSON file.
- `--csv-out`: Save results to a CSV file.
- `--no-resolve`: Skip DNS reverse lookups for speed.
- `--services`: Resolve well-known service names.
- `--progress`: Show progress and ETA during the scan.

## Output
The tool prints open ports to the console and optionally saves a report:

JSON:
```json
[
  {
    "ip": "192.168.1.2",
    "hostname": "host-2",
    "port": 22,
    "protocol": "tcp",
    "service": "ssh",
    "state": "open"
  }
]
```

CSV:
```csv
ip,hostname,port,protocol,service,state
192.168.1.2,host-2,22,tcp,ssh,open
```

## Safety and Ethics
Only scan networks and hosts that you own or have explicit permission to test. Unauthorized scanning may be illegal or violate policies.

## Security Notes
- The web UI binds to `127.0.0.1` by default to avoid exposing scans publicly.
- Do not change the host binding unless you understand the security risks.

## Documentation
- See [docs/USAGE.md](docs/USAGE.md) for detailed usage examples.

## Tests
Run the unit tests with Python's built-in `unittest` runner:

```bash
python -m unittest discover -s tests
```

## Project Structure
```
.
├── README.md
├── .gitignore
├── requirements.txt
├── docs
│   └── USAGE.md
├── port_scanner.py
├── web_app.py
├── templates
│   └── index.html
└── tests
    └── test_port_scanner.py
```

## License
MIT License. See [docs/USAGE.md](docs/USAGE.md) for details and notes.
