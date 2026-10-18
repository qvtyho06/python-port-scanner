from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set

DEFAULT_PORTS = "1-1024"
DEFAULT_WORKERS = 100
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 5000
MIN_PORT, MAX_PORT = 1, 65535

# Banner grabbing: wait this long for services that speak first (SSH, FTP,
# SMTP...), then send an HTTP probe and wait again for a reply.
PASSIVE_BANNER_TIMEOUT = 1.0
PROBE_BANNER_TIMEOUT = 2.0
BANNER_MAX_BYTES = 1024
BANNER_DISPLAY_WIDTH = 70
HTTP_PROBE_TEMPLATE = (
    b"GET / HTTP/1.1\r\n"
    b"Host: %s\r\n"
    b"User-Agent: scanner.py\r\n"
    b"Connection: close\r\n\r\n"
)

STATUS_OPEN = "open"
STATUS_CLOSED = "closed"
STATUS_FILTERED = "filtered"
STATUS_ERROR = "error"

# --------------------------------------------------------------------------
# CLI parsing
# --------------------------------------------------------------------------

def _to_port(value: str) -> int:
    """Convert a string to a valid TCP port number or raise ArgumentTypeError."""
    try:
        port = int(value.strip())
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {value!r}") from None
    if not MIN_PORT <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError(
            f"port {port} out of range ({MIN_PORT}-{MAX_PORT})"
        )
    return port


def parse_ports(spec: str) -> List[int]:
    """Parse a port specification into a sorted list of unique ports.

    Accepts comma-separated single ports and inclusive ranges, which may be
    mixed, e.g. ``"22,80,443"``, ``"1-1024"`` or ``"22,80,8000-8100"``.

    Raises:
        argparse.ArgumentTypeError: If the specification is malformed.
    """
    ports: Set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            start, end = _to_port(start_text), _to_port(end_text)
            if start > end:
                raise argparse.ArgumentTypeError(
                    f"invalid range {chunk!r}: start is greater than end"
                )
            ports.update(range(start, end + 1))
        else:
            ports.add(_to_port(chunk))
    if not ports:
        raise argparse.ArgumentTypeError("no ports specified")
    return sorted(ports)


def _positive_int(value: str) -> int:
    """argparse type: an integer between 1 and MAX_WORKERS."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from None
    if not 1 <= number <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_WORKERS}")
    return number


def _positive_float(value: str) -> float:
    """argparse type: a float greater than zero."""
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Build the argument parser and parse the command line."""
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP connect port scanner with banner "
                    "grabbing. Only scan hosts you are authorized to test.",
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="target hostname or IPv4 address",
    )
    parser.add_argument(
        "-p", "--ports", type=parse_ports, default=DEFAULT_PORTS,
        help="ports to scan, e.g. '22,80,443', '1-1024' or '22,8000-8100' "
             f"(default: {DEFAULT_PORTS})",
    )
    parser.add_argument(
        "-w", "--workers", type=_positive_int, default=DEFAULT_WORKERS,
        help=f"number of worker threads (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="save open ports and banners to this JSON file",
    )
    parser.add_argument(
        "--timeout", type=_positive_float, default=DEFAULT_TIMEOUT,
        help=f"TCP connect timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    return parser.parse_args(argv)

def main():
    args = parse_args()
    print(f"Target: {args.target}")
    print(f"Ports to scan: {len(args.ports)} ports, first port: {args.ports[0]}")
    print(f"Workers: {args.workers}")

if __name__ == "__main__":
    main()