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

# getservbyport() returns a pointer to static libc storage, so serialize it.
_SERVICE_LOOKUP_LOCK = threading.Lock()

@dataclass
class PortResult:
    """Outcome of probing a single TCP port."""

    port: int
    status: str
    service: str = ""
    banner: str = ""

class ResultCollector:
    """Thread-safe container that worker threads append results to."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._results: List[PortResult] = []

    def add(self, result: PortResult) -> None:
        """Append a result while holding the lock."""
        with self._lock:
            self._results.append(result)

    def snapshot(self) -> List[PortResult]:
        """Return a port-sorted copy of all results collected so far."""
        with self._lock:
            return sorted(self._results, key=lambda r: r.port)


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


# --------------------------------------------------------------------------
# Scanning engine
# --------------------------------------------------------------------------

def resolve_target(target: str) -> str:
    """Resolve a hostname to an IPv4 address.

    Raises:
        socket.gaierror: If the name cannot be resolved.
    """
    return socket.gethostbyname(target.strip())


def lookup_service(port: int) -> str:
    """Return the well-known TCP service name for a port, or 'unknown'."""
    with _SERVICE_LOOKUP_LOCK:
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

def clean_banner(raw: bytes) -> str:
    """Turn raw banner bytes into a single printable line.

    HTTP responses are summarised as the status line plus the ``Server``
    header (when present); anything else is flattened to one line with
    control characters removed.
    """
    text = raw.decode("utf-8", errors="replace")
    if text.startswith("HTTP/"):
        lines = text.splitlines()
        summary = lines[0].strip()
        for line in lines[1:]:
            if line.lower().startswith("server:"):
                summary += f" | {line.strip()}"
                break
        text = summary
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(printable.split())


def grab_banner(sock: socket.socket, probe_host: bytes) -> str:
    """Try to read a service banner from an already-connected socket.

    First waits passively for services that announce themselves on connect.
    If nothing arrives before the timeout, sends an HTTP GET probe and reads
    the reply. Every ``recv`` is bounded by a socket timeout, so this never
    hangs; any socket error simply yields an empty banner.
    """
    try:
        sock.settimeout(PASSIVE_BANNER_TIMEOUT)
        data = sock.recv(BANNER_MAX_BYTES)
        # b"" means the peer closed the connection without sending anything.
        return clean_banner(data) if data else ""
    except socket.timeout:
        pass
    except OSError:
        return ""

    try:
        sock.settimeout(PROBE_BANNER_TIMEOUT)
        sock.sendall(HTTP_PROBE_TEMPLATE % probe_host)
        data = sock.recv(BANNER_MAX_BYTES)
    except OSError:  # includes socket.timeout
        return ""
    return clean_banner(data)

def scan_port(
    ip: str,
    port: int,
    probe_host: bytes,
    timeout: float,
    stop_event: threading.Event,
) -> Optional[PortResult]:
    """Perform a TCP connect scan of one port and grab its banner if open.

    Returns:
        A PortResult, or None if the scan was cancelled before it started.
    """
    if stop_event.is_set():
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect((ip, port))
            except socket.timeout:
                return PortResult(port, STATUS_FILTERED)
            except ConnectionRefusedError:
                return PortResult(port, STATUS_CLOSED)
            except OSError:
                # Host/network unreachable, ICMP prohibited, etc.
                return PortResult(port, STATUS_FILTERED)
            banner = "" 
    except OSError:
        # Socket creation failed, e.g. the process ran out of file handles.
        return PortResult(port, STATUS_ERROR)
    return PortResult(port, STATUS_OPEN, lookup_service(port), banner)

def _scan_worker(
    ip: str,
    port: int,
    probe_host: bytes,
    timeout: float,
    stop_event: threading.Event,
    collector: ResultCollector,
) -> None:
    """Thread entry point: scan one port and store the result."""
    result = scan_port(ip, port, probe_host, timeout, stop_event)
    if result is not None:
        collector.add(result)


def _print_progress(done: int, total: int) -> None:
    """Show an in-place progress line on stderr when it is a terminal."""
    if sys.stderr.isatty():
        percent = done * 100 / total
        print(f"\r[*] Progress: {done}/{total} ports ({percent:5.1f}%)",
              end="", file=sys.stderr, flush=True)


def run_scan(
    ip: str,
    probe_host: bytes,
    ports: Sequence[int],
    workers: int,
    timeout: float,
    collector: ResultCollector,
) -> bool:
    """Scan all ports concurrently with a ThreadPoolExecutor.

    The main thread waits in short slices so Ctrl+C is delivered promptly on
    every platform. On interrupt, queued ports are cancelled, in-flight
    probes are told to skip banner grabbing, and the pool is drained (each
    in-flight probe is bounded by its socket timeouts).

    Returns:
        True if the scan was interrupted by the user, False otherwise.
    """
    stop_event = threading.Event()
    executor = ThreadPoolExecutor(max_workers=workers,
                                  thread_name_prefix="scanner")
    pending: Set[Future[None]] = {
        executor.submit(_scan_worker, ip, port, probe_host, timeout,
                        stop_event, collector)
        for port in ports
    }
    total = len(pending)
    interrupted = False
    try:
        while pending:
            done, pending = wait(pending, timeout=0.2,
                                 return_when=FIRST_COMPLETED)
            for future in done:
                error = future.exception()
                if error is not None:
                    print(f"\n[!] Worker error: {error!r}", file=sys.stderr)
            _print_progress(total - len(pending), total)
    except KeyboardInterrupt:
        interrupted = True
        stop_event.set()
        print("\n[!] Interrupted: cancelling queued ports and waiting for "
              "in-flight probes to finish...", file=sys.stderr)
        executor.shutdown(wait=False, cancel_futures=True)
    finally:
        try:
            executor.shutdown(wait=True)
        except KeyboardInterrupt:
            interrupted = True
            print("[!] Forced exit; skipped waiting for remaining threads.",
                  file=sys.stderr)
        if sys.stderr.isatty() and not interrupted:
            print(file=sys.stderr)
    return interrupted

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _truncate(text: str, width: int) -> str:
    """Shorten text to at most ``width`` characters, adding an ellipsis."""
    return text if len(text) <= width else text[: width - 3] + "..."


def print_table(open_results: Sequence[PortResult]) -> None:
    """Print open ports as an ASCII table: Port | Status | Banner/Service."""
    if not open_results:
        print("\nNo open ports found.")
        return

    headers = ("PORT", "STATUS", "SERVICE / BANNER")
    rows = []
    for result in open_results:
        cell = result.service
        if result.banner:
            cell = f"{result.service}: {result.banner}"
        rows.append((f"{result.port}/tcp", result.status,
                     _truncate(cell, BANNER_DISPLAY_WIDTH)))

    widths = [max(len(headers[i]), *(len(row[i]) for row in rows))
              for i in range(len(headers))]
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(cells: Sequence[str]) -> str:
        return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths)) + " |"

    print()
    print(border)
    print(fmt(headers))
    print(border)
    for row in rows:
        print(fmt(row))
    print(border)


def save_json(path: str, report: Dict[str, Any]) -> None:
    """Write the scan report to ``path`` as pretty-printed JSON.

    Raises:
        OSError: If the file cannot be written.
    """
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def build_report(
    target: str,
    ip: str,
    ports: Sequence[int],
    results: Sequence[PortResult],
    started: datetime,
    finished: datetime,
    duration: float,
    interrupted: bool,
) -> Dict[str, Any]:
    """Assemble the structured report saved with ``--output``."""
    return {
        "target": target,
        "ip": ip,
        "scan_started": started.isoformat(timespec="seconds"),
        "scan_finished": finished.isoformat(timespec="seconds"),
        "duration_seconds": round(duration, 2),
        "ports_requested": len(ports),
        "ports_scanned": len(results),
        "interrupted": interrupted,
        "open_ports": [asdict(r) for r in results if r.status == STATUS_OPEN],
    }


def _probe_host_bytes(target: str, ip: str) -> bytes:
    """Encode the HTTP Host header value, falling back to the IP address."""
    try:
        return target.strip().encode("idna")
    except UnicodeError:
        return ip.encode("ascii")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the scanner from the command line and return an exit code."""
    # Never crash on banners containing characters the console can't encode.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    args = parse_args(argv)
    ports: List[int] = args.ports

    try:
        ip = resolve_target(args.target)
    except (socket.gaierror, UnicodeError) as exc:
        print(f"[-] Could not resolve {args.target!r}: {exc}", file=sys.stderr)
        return 2

    print(f"[*] Target : {args.target} ({ip})")
    print(f"[*] Ports  : {len(ports)} ({ports[0]}-{ports[-1]})")
    print(f"[*] Workers: {args.workers} | Timeout: {args.timeout}s")

    collector = ResultCollector()
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    interrupted = run_scan(ip, _probe_host_bytes(args.target, ip), ports,
                           args.workers, args.timeout, collector)
    duration = time.perf_counter() - clock
    finished = datetime.now(timezone.utc)

    results = collector.snapshot()
    open_results = [r for r in results if r.status == STATUS_OPEN]
    print_table(open_results)

    counts = {status: sum(1 for r in results if r.status == status)
              for status in (STATUS_OPEN, STATUS_CLOSED, STATUS_FILTERED,
                             STATUS_ERROR)}
    state = "Partial scan" if interrupted else "Scan complete"
    print(f"\n[*] {state}: {len(results)}/{len(ports)} ports in "
          f"{duration:.2f}s | open: {counts[STATUS_OPEN]}, "
          f"closed: {counts[STATUS_CLOSED]}, "
          f"filtered: {counts[STATUS_FILTERED]}"
          + (f", errors: {counts[STATUS_ERROR]}" if counts[STATUS_ERROR] else ""))

    if args.output:
        report = build_report(args.target, ip, ports, results, started,
                              finished, duration, interrupted)
        try:
            save_json(args.output, report)
        except OSError as exc:
            print(f"[-] Could not write {args.output!r}: {exc}",
                  file=sys.stderr)
            return 1
        print(f"[+] Results saved to {args.output}")

    return 130 if interrupted else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.", file=sys.stderr)
        sys.exit(130)
