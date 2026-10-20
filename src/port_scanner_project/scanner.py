from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

DEFAULT_PORTS = "1-1024"
DEFAULT_WORKERS = 100
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 5000
MIN_PORT, MAX_PORT = 1, 65535

# Host discovery: each ping waits this long for an echo reply. Every ping is
# a separate subprocess, so the sweep uses fewer threads than the port scan.
PING_TIMEOUT = 1.0
PING_MAX_WORKERS = 64
# Refuse subnets larger than a /20 so a typo like /8 doesn't start a huge scan.
MAX_SUBNET_ADDRESSES = 4096

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
        help="target hostname, IPv4 address or IPv4 subnet in CIDR "
             "notation (e.g. 192.168.1.0/24)",
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
    parser.add_argument(
        "--no-ping", action="store_true",
        help="skip the ping check and scan every target host, even ones "
             "that don't answer ICMP (slower on subnets with many down hosts)",
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


def parse_network(target: str) -> Optional[ipaddress.IPv4Network]:
    """Return the IPv4 network for a CIDR target, or None for a single host.

    Host bits are allowed, so ``192.168.1.10/24`` means ``192.168.1.0/24``.

    Raises:
        ValueError: If the target contains '/' but is not a valid IPv4 network.
    """
    if "/" not in target:
        return None
    return ipaddress.IPv4Network(target.strip(), strict=False)


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
            banner = "" if stop_event.is_set() else grab_banner(sock, probe_host)
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


def _print_progress(done: int, total: int, unit: str = "ports") -> None:
    """Show an in-place progress line on stderr when it is a terminal."""
    if sys.stderr.isatty():
        percent = done * 100 / total
        print(f"\r[*] Progress: {done}/{total} {unit} ({percent:5.1f}%)",
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


def _ping_command(ip: str) -> List[str]:
    """Build a one-packet ping command for the current platform."""
    timeout_ms = int(PING_TIMEOUT * 1000)
    if sys.platform == "win32":
        # -n: packet count, -w: reply timeout in milliseconds.
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    if sys.platform == "darwin":
        # -c: packet count, -W: reply timeout in milliseconds.
        return ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    # Linux: -c: packet count, -W: reply timeout in whole seconds.
    return ["ping", "-c", "1", "-W", str(max(1, round(PING_TIMEOUT))), ip]


def ping_host(ip: str) -> Optional[str]:
    """Ping a single IP. Return the IP if it responds, else None."""
    try:
        result = subprocess.run(_ping_command(ip), capture_output=True,
                                text=True, errors="replace",
                                timeout=PING_TIMEOUT + 2)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    # Windows ping also exits 0 when a router answers "Destination host
    # unreachable", so require an actual echo reply (which carries a TTL).
    if sys.platform == "win32" and "TTL=" not in result.stdout.upper():
        return None
    return ip


def ping_sweep(ips: Sequence[str], workers: int) -> Tuple[List[str], bool]:
    """Ping hosts concurrently to find which ones are up.

    Uses the same Ctrl+C handling as ``run_scan``: queued pings are
    cancelled and in-flight ones (bounded by PING_TIMEOUT) are drained.

    Returns:
        The responding IPs in address order, and whether the user interrupted.
    """
    live: List[str] = []
    executor = ThreadPoolExecutor(
        max_workers=min(workers, PING_MAX_WORKERS, len(ips)),
        thread_name_prefix="pinger",
    )
    pending: Set[Future[Optional[str]]] = {
        executor.submit(ping_host, ip) for ip in ips
    }
    total = len(pending)
    interrupted = False
    try:
        while pending:
            done, pending = wait(pending, timeout=0.2,
                                 return_when=FIRST_COMPLETED)
            for future in done:
                ip = future.result()
                if ip is not None:
                    live.append(ip)
            _print_progress(total - len(pending), total, "hosts")
    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] Interrupted: cancelling ping sweep...", file=sys.stderr)
        executor.shutdown(wait=False, cancel_futures=True)
    finally:
        try:
            executor.shutdown(wait=True)
        except KeyboardInterrupt:
            interrupted = True
            print("[!] Forced exit; skipped waiting for remaining pings.",
                  file=sys.stderr)
        if sys.stderr.isatty() and not interrupted:
            print(file=sys.stderr)
    return sorted(live, key=ipaddress.IPv4Address), interrupted


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


def scan_host(
    target: str,
    ip: str,
    ports: Sequence[int],
    workers: int,
    timeout: float,
) -> Tuple[Dict[str, Any], bool]:
    """Scan one host, print its table and summary line.

    Returns:
        The host's report (as built by ``build_report``) and whether the
        user interrupted the scan.
    """
    collector = ResultCollector()
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    interrupted = run_scan(ip, _probe_host_bytes(target, ip), ports,
                           workers, timeout, collector)
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

    report = build_report(target, ip, ports, results, started, finished,
                          duration, interrupted)
    return report, interrupted


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the scanner from the command line and return an exit code."""
    # Never crash on banners containing characters the console can't encode.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    args = parse_args(argv)
    ports: List[int] = args.ports
    target: str = args.target.strip()

    try:
        network = parse_network(target)
    except ValueError as exc:
        print(f"[-] Invalid subnet {target!r}: {exc}", file=sys.stderr)
        return 2

    if network is not None:
        if network.num_addresses > MAX_SUBNET_ADDRESSES:
            print(f"[-] Subnet {network} has {network.num_addresses} "
                  f"addresses; the limit is {MAX_SUBNET_ADDRESSES} (/20).",
                  file=sys.stderr)
            return 2
        candidates = [str(host) for host in network.hosts()]
        print(f"[*] Target : {network} ({len(candidates)} hosts)")
    else:
        try:
            candidates = [resolve_target(target)]
        except (socket.gaierror, UnicodeError) as exc:
            print(f"[-] Could not resolve {target!r}: {exc}", file=sys.stderr)
            return 2
        print(f"[*] Target : {target} ({candidates[0]})")

    print(f"[*] Ports  : {len(ports)} ({ports[0]}-{ports[-1]})")
    print(f"[*] Workers: {args.workers} | Timeout: {args.timeout}s")

    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    interrupted = False

    if args.no_ping:
        live = candidates
        print("[*] Ping   : skipped (--no-ping), scanning every host")
    else:
        print(f"[*] Ping   : checking {len(candidates)} host(s)...")
        live, interrupted = ping_sweep(candidates, args.workers)
        print(f"[*] Hosts up: {len(live)}/{len(candidates)}"
              + (" (sweep interrupted)" if interrupted else ""))
        if not live and not interrupted:
            print("[-] No host answered ping. If the target blocks ICMP, "
                  "re-run with --no-ping.", file=sys.stderr)

    host_reports: List[Dict[str, Any]] = []
    for index, ip in enumerate(live, start=1):
        if interrupted:
            break
        if network is not None:
            print(f"\n[*] Host {index}/{len(live)}: {ip}")
        # Subnet hosts have no hostname, so their IP doubles as the label.
        label = target if network is None else ip
        report, interrupted = scan_host(label, ip, ports, args.workers,
                                        args.timeout)
        host_reports.append(report)

    duration = time.perf_counter() - clock
    finished = datetime.now(timezone.utc)

    if network is not None:
        total_open = sum(len(r["open_ports"]) for r in host_reports)
        state = "Partial subnet scan" if interrupted else "Subnet scan complete"
        print(f"\n[*] {state}: {len(host_reports)}/{len(live)} live hosts "
              f"scanned in {duration:.2f}s | open ports: {total_open}")

    if args.output:
        if network is not None:
            output: Optional[Dict[str, Any]] = {
                "target": str(network),
                "scan_started": started.isoformat(timespec="seconds"),
                "scan_finished": finished.isoformat(timespec="seconds"),
                "duration_seconds": round(duration, 2),
                "ping_check": not args.no_ping,
                "hosts_total": len(candidates),
                "hosts_up": len(live),
                "hosts_scanned": len(host_reports),
                "interrupted": interrupted,
                "hosts": host_reports,
            }
        else:
            output = host_reports[0] if host_reports else None
        if output is None:
            print(f"[-] Host was not scanned; nothing saved to {args.output}",
                  file=sys.stderr)
        else:
            try:
                save_json(args.output, output)
            except OSError as exc:
                print(f"[-] Could not write {args.output!r}: {exc}",
                      file=sys.stderr)
                return 1
            print(f"[+] Results saved to {args.output}")

    if interrupted:
        return 130
    # A single host that didn't answer ping was never scanned.
    return 1 if network is None and not live else 0


def cli() -> int:
    """Console entry point: ``main()`` plus a clean exit on a stray Ctrl+C."""
    try:
        return main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(cli())
