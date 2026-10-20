"""Unit tests for port_scanner_project.scanner (standard library only)."""

from __future__ import annotations

import argparse
import contextlib
import io
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from typing import List, Optional, Sequence
from unittest import mock

from port_scanner_project import scanner


def run_main(argv: Sequence[str]) -> int:
    """Call scanner.main with stdout/stderr silenced."""
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return scanner.main(list(argv))


class BannerServer:
    """Local TCP server that sends a fixed banner to every client."""

    def __init__(self, banner: bytes) -> None:
        self._banner = banner
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self.port: int = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                conn.sendall(self._banner)

    def __enter__(self) -> "BannerServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._sock.close()


class ParsePortsTest(unittest.TestCase):
    def test_single_ports_and_ranges(self) -> None:
        self.assertEqual(scanner.parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(scanner.parse_ports("1-3"), [1, 2, 3])
        self.assertEqual(scanner.parse_ports(" 80 , 20-22 "), [20, 21, 22, 80])

    def test_duplicates_are_removed_and_sorted(self) -> None:
        self.assertEqual(scanner.parse_ports("443,22,22,20-23"),
                         [20, 21, 22, 23, 443])

    def test_invalid_specs(self) -> None:
        for spec in ("", ",", "0", "65536", "abc", "10-5", "1-x"):
            with self.subTest(spec=spec):
                with self.assertRaises(argparse.ArgumentTypeError):
                    scanner.parse_ports(spec)


class ParseNetworkTest(unittest.TestCase):
    def test_single_host_is_not_a_network(self) -> None:
        self.assertIsNone(scanner.parse_network("192.168.1.10"))
        self.assertIsNone(scanner.parse_network("example.com"))

    def test_cidr_with_host_bits(self) -> None:
        self.assertEqual(scanner.parse_network(" 192.168.1.10/24 "),
                         ipaddress.IPv4Network("192.168.1.0/24"))

    def test_invalid_network(self) -> None:
        for target in ("1.2.3.4/33", "example.com/24", "::1/128"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    scanner.parse_network(target)


class CleanBannerTest(unittest.TestCase):
    def test_http_response_is_summarised(self) -> None:
        raw = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
               b"Server: nginx/1.24.0\r\n\r\n<html>")
        self.assertEqual(scanner.clean_banner(raw),
                         "HTTP/1.1 200 OK | Server: nginx/1.24.0")

    def test_control_characters_are_flattened(self) -> None:
        self.assertEqual(scanner.clean_banner(b"SSH-2.0-OpenSSH_9.6\r\n"),
                         "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(scanner.clean_banner(b"220 ftp\x00\tready\n"),
                         "220 ftp ready")


class PingTest(unittest.TestCase):
    def test_ping_command_per_platform(self) -> None:
        cases = {
            "win32": ["ping", "-n", "1", "-w", "1000", "10.0.0.1"],
            "darwin": ["ping", "-c", "1", "-W", "1000", "10.0.0.1"],
            "linux": ["ping", "-c", "1", "-W", "1", "10.0.0.1"],
        }
        for platform, expected in cases.items():
            with self.subTest(platform=platform), \
                    mock.patch.object(scanner.sys, "platform", platform):
                self.assertEqual(scanner._ping_command("10.0.0.1"), expected)

    def _ping(self, platform: str, returncode: int, stdout: str) -> Optional[str]:
        completed = subprocess.CompletedProcess([], returncode, stdout, "")
        with mock.patch.object(scanner.sys, "platform", platform), \
                mock.patch.object(scanner.subprocess, "run",
                                  return_value=completed):
            return scanner.ping_host("10.0.0.1")

    def test_ping_host_results(self) -> None:
        reply = "Reply from 10.0.0.1: bytes=32 time<1ms TTL=64"
        unreachable = "Reply from 10.0.0.254: Destination host unreachable."
        self.assertEqual(self._ping("win32", 0, reply), "10.0.0.1")
        self.assertIsNone(self._ping("win32", 0, unreachable))
        self.assertIsNone(self._ping("win32", 1, ""))
        self.assertEqual(self._ping("linux", 0, "64 bytes from 10.0.0.1"),
                         "10.0.0.1")
        self.assertIsNone(self._ping("linux", 1, ""))

    def test_ping_host_handles_missing_ping(self) -> None:
        with mock.patch.object(scanner.subprocess, "run",
                               side_effect=FileNotFoundError):
            self.assertIsNone(scanner.ping_host("10.0.0.1"))

    def test_ping_sweep_returns_live_hosts_in_order(self) -> None:
        live = {"10.0.0.10", "10.0.0.2"}
        ips = [f"10.0.0.{i}" for i in range(1, 12)]
        with mock.patch.object(scanner, "ping_host",
                               side_effect=lambda ip: ip if ip in live else None):
            result, interrupted = scanner.ping_sweep(ips, workers=4)
        self.assertEqual(result, ["10.0.0.2", "10.0.0.10"])
        self.assertFalse(interrupted)


class ScanPortTest(unittest.TestCase):
    def test_open_port_with_banner(self) -> None:
        with BannerServer(b"SSH-2.0-Test\r\n") as server:
            result = scanner.scan_port("127.0.0.1", server.port, b"127.0.0.1",
                                       1.0, threading.Event())
        assert result is not None
        self.assertEqual(result.status, scanner.STATUS_OPEN)
        self.assertEqual(result.banner, "SSH-2.0-Test")

    def test_cancelled_scan_returns_none(self) -> None:
        stop = threading.Event()
        stop.set()
        self.assertIsNone(scanner.scan_port("127.0.0.1", 1, b"", 1.0, stop))


class BuildReportTest(unittest.TestCase):
    def test_only_open_ports_are_listed(self) -> None:
        results = [scanner.PortResult(22, scanner.STATUS_OPEN, "ssh", "SSH-2.0"),
                   scanner.PortResult(23, scanner.STATUS_CLOSED)]
        now = scanner.datetime.now(scanner.timezone.utc)
        report = scanner.build_report("host", "10.0.0.1", [22, 23], results,
                                      now, now, 1.234, False)
        self.assertEqual(report["ports_requested"], 2)
        self.assertEqual(report["ports_scanned"], 2)
        self.assertEqual(report["duration_seconds"], 1.23)
        self.assertEqual([p["port"] for p in report["open_ports"]], [22])


class MainTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = os.path.join(tmp.name, "report.json")

    def _load(self) -> dict:
        with open(self.out, encoding="utf-8") as handle:
            return json.load(handle)

    def test_single_host_no_ping(self) -> None:
        with BannerServer(b"hello\r\n") as server, \
                mock.patch.object(scanner, "ping_host") as ping:
            code = run_main(["-t", "127.0.0.1", "-p", str(server.port),
                             "--no-ping", "-o", self.out])
        self.assertEqual(code, 0)
        ping.assert_not_called()
        report = self._load()
        self.assertEqual(report["ip"], "127.0.0.1")
        self.assertEqual(report["open_ports"][0]["banner"], "hello")

    def test_single_host_down_is_not_scanned(self) -> None:
        with mock.patch.object(scanner, "ping_host", return_value=None), \
                mock.patch.object(scanner, "run_scan") as run_scan:
            code = run_main(["-t", "127.0.0.1", "-p", "80", "-o", self.out])
        self.assertEqual(code, 1)
        run_scan.assert_not_called()
        self.assertFalse(os.path.exists(self.out))

    def test_subnet_scans_only_live_hosts(self) -> None:
        scanned: List[str] = []

        def fake_run_scan(ip, probe_host, ports, workers, timeout, collector):
            scanned.append(ip)
            collector.add(scanner.PortResult(ports[0], scanner.STATUS_OPEN,
                                             "http"))
            return False

        with mock.patch.object(scanner, "ping_host",
                               side_effect=lambda ip: ip
                               if ip.endswith((".1", ".3")) else None), \
                mock.patch.object(scanner, "run_scan", side_effect=fake_run_scan):
            code = run_main(["-t", "10.0.0.0/29", "-p", "80", "-o", self.out])

        self.assertEqual(code, 0)
        self.assertEqual(scanned, ["10.0.0.1", "10.0.0.3"])
        report = self._load()
        self.assertEqual(report["target"], "10.0.0.0/29")
        self.assertEqual(report["hosts_total"], 6)
        self.assertEqual(report["hosts_up"], 2)
        self.assertEqual([h["ip"] for h in report["hosts"]],
                         ["10.0.0.1", "10.0.0.3"])

    def test_subnet_no_ping_scans_every_host(self) -> None:
        with mock.patch.object(scanner, "ping_host") as ping, \
                mock.patch.object(scanner, "run_scan",
                                  return_value=False) as run_scan:
            code = run_main(["-t", "10.0.0.0/30", "-p", "80", "--no-ping"])
        self.assertEqual(code, 0)
        ping.assert_not_called()
        self.assertEqual([c.args[0] for c in run_scan.call_args_list],
                         ["10.0.0.1", "10.0.0.2"])

    def test_interrupt_stops_remaining_hosts(self) -> None:
        with mock.patch.object(scanner, "run_scan",
                               return_value=True) as run_scan:
            code = run_main(["-t", "10.0.0.0/29", "-p", "80", "--no-ping"])
        self.assertEqual(code, 130)
        self.assertEqual(run_scan.call_count, 1)

    def test_invalid_targets(self) -> None:
        for target in ("10.0.0.0/8", "1.2.3.4/33"):
            with self.subTest(target=target):
                self.assertEqual(run_main(["-t", target, "--no-ping"]), 2)


if __name__ == "__main__":
    unittest.main()
