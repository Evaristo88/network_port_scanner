# Network Port Scanner

A simple, educational Python port scanner that attempts TCP connections across an IP range and port list to identify open ports.

## Features
- Scans IPv4 ranges (start/end) or CIDR blocks.
- Scans single ports, comma-separated lists, or ranges (e.g., `22,80,443,8000-8100`).
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

## Usage

```text
python port_scanner.py [--start-ip IP --end-ip IP | --cidr CIDR] --ports PORTS
                       [--timeout SECONDS] [--workers N]
                       [--json-out PATH] [--csv-out PATH]
                       [--no-resolve]
```

### Arguments
- `--start-ip`: First IPv4 address in the scan range.
- `--end-ip`: Last IPv4 address in the scan range.
- `--cidr`: CIDR block (e.g., `10.0.0.0/24`).
- `--ports`: Port list or ranges (e.g., `22,80,443,8000-8100`).
- `--timeout`: Socket timeout in seconds (default: 0.5).
- `--workers`: Number of concurrent threads (default: 100).
- `--json-out`: Save results to a JSON file.
- `--csv-out`: Save results to a CSV file.
- `--no-resolve`: Skip DNS reverse lookups for speed.

## Output
The tool prints open ports to the console and optionally saves a report:

JSON:
```json
[
  {"ip": "192.168.1.2", "hostname": "host-2", "port": 22, "state": "open"}
]
```

CSV:
```csv
ip,hostname,port,state
192.168.1.2,host-2,22,open
```

## Safety and Ethics
Only scan networks and hosts that you own or have explicit permission to test. Unauthorized scanning may be illegal or violate policies.

## Documentation
- See [docs/USAGE.md](docs/USAGE.md) for detailed usage examples.

## Project Structure
```
.
├── README.md
├── docs
│   └── USAGE.md
└── port_scanner.py
```

## License
MIT License. See [docs/USAGE.md](docs/USAGE.md) for details and notes.
