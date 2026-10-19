# 🚀 Multi-threaded Python TCP Port Scanner

A fast, concurrent TCP connect port scanner built strictly with standard Python libraries. It features automated banner grabbing, graceful keyboard interruptions, and structured JSON reporting.

## Features
- **Multi-threading:** Utilizes `concurrent.futures.ThreadPoolExecutor` for high-speed concurrent scanning.
- **Banner Grabbing:** Automatically detects HTTP servers, SSH, FTP, and other standard services by analyzing socket responses and sending HTTP probes.
- **Zero Third-Party Dependencies:** Built entirely using Python's built-in libraries (`socket`, `argparse`, `threading`, `json`).
- **Data Export:** Displays clean ASCII tables in the terminal and exports comprehensive reports to structured JSON files.

## Prerequisites
- Python 3.9+
- [uv](https://github.com/astral-sh/uv) (Recommended for fast environment management)

## Setup & Installation

Clone the repository and initialize the project:

```bash
git clone https://github.com/qvtyho06/python-port-scanner.git
cd port-scanner-project
uv init