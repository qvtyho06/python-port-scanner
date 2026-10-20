# 🚀 Multi-threaded Python TCP Port Scanner

A fast, concurrent TCP connect port scanner built strictly with standard Python libraries. It can sweep a whole subnet, skip hosts that are down, grab service banners, handle Ctrl+C gracefully and save structured JSON reports.

> ⚠️ Only scan hosts and networks you own or are explicitly authorized to test.

## Features
- **Multi-threading:** Utilizes `concurrent.futures.ThreadPoolExecutor` for high-speed concurrent scanning.
- **Subnet Scanning:** Accepts a single host or an IPv4 subnet in CIDR notation (e.g. `192.168.1.0/24`, up to a `/20`).
- **Host Discovery:** Pings every target first and only port-scans hosts that reply. Use `--no-ping` for hosts that block ICMP.
- **Banner Grabbing:** Automatically detects HTTP servers, SSH, FTP, and other standard services by analyzing socket responses and sending HTTP probes.
- **Zero Third-Party Dependencies:** Built entirely using Python's built-in libraries (`socket`, `argparse`, `threading`, `ipaddress`, `subprocess`, `json`).
- **Data Export:** Displays clean ASCII tables in the terminal and exports comprehensive reports to structured JSON files.

## Prerequisites
- Python 3.13+
- [uv](https://github.com/astral-sh/uv) (Recommended for fast environment management)
- The system `ping` command (used for host discovery; Windows, Linux and macOS are supported)

## Setup & Installation

Clone the repository and install the project into a virtual environment:

```bash
git clone https://github.com/qvtyho06/python-port-scanner.git
cd python-port-scanner
uv sync
```

## Usage

```bash
uv run port-scanner-project -t <target> [options]
```

`python -m port_scanner_project` works too, once the environment is activated.

| Option | Description | Default |
| --- | --- | --- |
| `-t`, `--target` | Hostname, IPv4 address or IPv4 subnet in CIDR notation | required |
| `-p`, `--ports` | Ports to scan, e.g. `22,80,443`, `1-1024` or `22,8000-8100` | `1-1024` |
| `-w`, `--workers` | Number of worker threads (1-5000) | `100` |
| `--timeout` | TCP connect timeout in seconds | `1.0` |
| `--no-ping` | Skip the ping check and scan every host | off |
| `-o`, `--output` | Save results to this JSON file | — |

### Examples

Scan the default ports of a single host:

```bash
uv run port-scanner-project -t scanme.nmap.org
```

Scan selected ports with more threads and save a report:

```bash
uv run port-scanner-project -t 192.168.1.10 -p 22,80,443,8000-8100 -w 200 -o results.json
```

Sweep a subnet. Only hosts that answer ping are port-scanned:

```bash
uv run port-scanner-project -t 192.168.1.0/24 -p 22,80,443
```

Scan a host that blocks ICMP (for example, Windows with its firewall on):

```bash
uv run port-scanner-project -t 192.168.1.20 --no-ping
```

## Output

Open ports are printed as a table, followed by a summary line:

```text
+----------+--------+------------------------------------------------+
| PORT     | STATUS | SERVICE / BANNER                               |
+----------+--------+------------------------------------------------+
| 22/tcp   | open   | ssh: SSH-2.0-OpenSSH_9.6                       |
| 80/tcp   | open   | http: HTTP/1.1 200 OK | Server: nginx/1.24.0   |
+----------+--------+------------------------------------------------+

[*] Scan complete: 1024/1024 ports in 11.32s | open: 2, closed: 1022, filtered: 0
```

With `-o`, a single-host scan saves that host's report (target, IP, timings, port counts and `open_ports`). A subnet scan saves sweep totals (`hosts_total`, `hosts_up`, `hosts_scanned`, ...) plus a `hosts` list with one such report per scanned host. `*.json` is git-ignored so reports are not committed by accident.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan finished |
| `1` | Single host did not answer ping (try `--no-ping`), or the report could not be written |
| `2` | Invalid or unresolvable target, or subnet larger than `/20` |
| `130` | Interrupted with Ctrl+C (partial results are still shown and saved) |

## Running the tests

```bash
uv run python -m unittest discover -s tests -v
```
