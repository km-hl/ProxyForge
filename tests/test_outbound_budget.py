"""受控阻塞 DNS 与真实慢流，验证绝对期限及关闭而非模拟超时异常。"""
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from proxyforge.security import network_security as network
from proxyforge.security import outbound_budget as budgets
from test_outbound_pinning import allow_fixture_address
from test_outbound_session import response


@contextmanager
def slow_server(stage="body", stop_request=None):
    stop = threading.Event()
    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            received.append(self.path)
            try:
                if stage == "headers":
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n":
                        self.connection.sendall(bytes([byte]))
                        if stop.wait(0.02):
                            return
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "10000")
                    self.send_header("Connection", "close")
                    self.end_headers()
                if stop_request is not None:
                    stop_request.set()
                for _ in range(200):
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    if stop.wait(0.02):
                        return
            except OSError:
                pass  # Expected peer shutdown at deadline/cancellation.

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    worker.start()
    try:
        with allow_fixture_address(), patch.object(network, "_resolved_addresses", return_value=("127.0.0.1",)):
            yield f"http://subscription.example:{server.server_port}/sub", received
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        worker.join(2)


class OutboundBudgetTest(unittest.TestCase):
    def test_slow_headers_and_body_stop_at_total_deadline(self):
        for stage in ("headers", "body"):
            with self.subTest(stage=stage), slow_server(stage) as (url, received):
                started = time.monotonic()
                with self.assertRaises(budgets.OutboundTimeout):
                    network.safe_get(url, timeout=1, total_timeout=0.3)
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(len(received), 1)

    def test_stop_interrupts_active_stream_and_prevents_successful_partial_response(self):
        stop = threading.Event()
        with slow_server(stop_request=stop) as (url, _):
            started = time.monotonic()
            with self.assertRaises(budgets.OutboundCancelled):
                network.safe_get(url, timeout=2, total_timeout=5, stop_event=stop)
            self.assertLess(time.monotonic() - started, 1.5)

    def test_expired_or_stopped_request_never_starts_dns(self):
        stop = threading.Event()
        stop.set()
        with patch.object(network, "_resolved_addresses") as dns:
            for kwargs, error in (({"deadline": time.monotonic() - 1}, budgets.OutboundTimeout),
                                  ({"stop_event": stop}, budgets.OutboundCancelled)):
                with self.subTest(kwargs=kwargs), self.assertRaises(error):
                    network.safe_get("https://subscription.example/sub", **kwargs)
            dns.assert_not_called()

    def test_invalid_budgets_are_rejected_without_io(self):
        with patch.object(network, "_resolved_addresses") as dns:
            for field in ("timeout", "total_timeout", "deadline"):
                values = [float("nan"), float("inf"), True, "1"]
                if field != "deadline":
                    values += [0, -1, None]
                for value in values:
                    with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                        network.safe_get("https://subscription.example/sub", **{field: value})
            dns.assert_not_called()

    def test_blocked_dns_has_a_deadline_and_bounded_capacity_until_worker_exits(self):
        for dns_limit, total_limit in ((0.15, 2), (2, 0.15)):
            release, started = threading.Event(), threading.Event()
            workers = []

            def resolve(host, port):
                workers.append(threading.current_thread())
                started.set()
                release.wait(5)
                return ("93.184.216.34",)

            with self.subTest(dns_limit=dns_limit), \
                    patch.object(budgets, "_dns_slots", threading.BoundedSemaphore(1)), \
                    patch.object(budgets, "DNS_TIMEOUT", dns_limit), \
                    patch.object(network, "_resolved_addresses", side_effect=resolve), \
                    patch("requests.adapters.HTTPAdapter.send", side_effect=lambda request, **kwargs: response(request)) as send:
                try:
                    before = time.monotonic()
                    with self.assertRaises(budgets.OutboundTimeout):
                        network.safe_get("https://subscription.example/sub", total_timeout=total_limit)
                    self.assertTrue(started.is_set())
                    self.assertLess(time.monotonic() - before, 1.5)
                    self.assertTrue(workers[0].daemon)
                    with self.assertRaises(budgets.OutboundCapacityError):
                        network.safe_get("https://subscription.example/sub")
                    send.assert_not_called()
                finally:
                    release.set()
                    for worker in workers:
                        worker.join(2)
                send.assert_not_called()  # DNS result arriving late cannot connect.
                self.assertEqual(network.safe_get("https://subscription.example/sub").content, b"proxies: []")

    def test_stopping_does_not_wait_for_system_dns_to_return(self):
        stop, started, release = threading.Event(), threading.Event(), threading.Event()
        errors, dns_workers = [], []

        def resolve(host, port):
            dns_workers.append(threading.current_thread())
            started.set()
            release.wait(5)
            return ("93.184.216.34",)

        def fetch():
            try:
                network.safe_get("https://subscription.example/sub", stop_event=stop)
            except Exception as exc:
                errors.append(exc)

        with patch.object(network, "_resolved_addresses", side_effect=resolve), patch.object(socket.socket, "connect") as connect:
            worker = threading.Thread(target=fetch)
            worker.start()
            try:
                self.assertTrue(started.wait(2))
                stop.set()
                worker.join(1.5)
                self.assertFalse(worker.is_alive())
                self.assertIsInstance(errors[0], budgets.OutboundCancelled)
            finally:
                release.set()
                worker.join(2)
                for dns_worker in dns_workers:
                    dns_worker.join(2)
            connect.assert_not_called()

    def test_dns_error_releases_capacity_and_preserves_validation_error(self):
        with patch.object(budgets, "_dns_slots", threading.BoundedSemaphore(1)), \
                patch.object(network, "_resolved_addresses", side_effect=network.UnsafeOutboundUrl("fixture")):
            for _ in range(2):
                with self.assertRaises(network.UnsafeOutboundUrl):
                    network.safe_get("https://subscription.example/sub")

    def test_late_event_notification_cannot_extend_dns_phase_budget(self):
        class LateEvent:
            def wait(self, timeout):
                threading.Event().wait(0.04)
                return True

        with budgets.RequestBudget(1) as budget:
            with self.assertRaises(budgets.OutboundTimeout):
                budget.wait(LateEvent(), 0.01)

    def test_late_dns_worker_does_not_keep_an_isolated_process_alive(self):
        code = """
import threading
from proxyforge.security import network_security as network
from proxyforge.security.outbound_budget import OutboundTimeout
def blocked(*args):
    threading.Event().wait(3600)
network._resolved_addresses = blocked
try:
    network.safe_get('https://subscription.example/sub', total_timeout=0.1)
except OutboundTimeout:
    print('deadline reached')
"""
        result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), "deadline reached")

    def test_redirects_share_one_absolute_budget(self):
        from test_outbound_session import response
        calls = []

        def send(request, **kwargs):
            calls.append(kwargs["timeout"])
            # Controlled transport delay represents headers, not a fresh budget.
            threading.Event().wait(0.09)
            return response(request, 302, {"Location": "/next"})

        with patch.object(network, "_resolved_addresses", return_value=("93.184.216.34",)), \
                patch("requests.adapters.HTTPAdapter.send", side_effect=send):
            with self.assertRaises(budgets.OutboundTimeout):
                network.safe_get("https://subscription.example/sub", total_timeout=0.22, max_redirects=10)
        self.assertGreater(len(calls), 1)
        self.assertLessEqual(len(calls), 3)
        self.assertTrue(all(right < left for left, right in zip(calls, calls[1:])))

    def test_address_fallback_does_not_restart_budget(self):
        from unittest.mock import Mock
        sock = Mock()

        def slow_connect(address):
            threading.Event().wait(0.12)
            raise OSError("fixture")

        sock.connect.side_effect = slow_connect
        with patch.object(network, "_resolved_addresses", return_value=("93.184.216.34", "1.1.1.1")), \
                patch.object(socket, "socket", return_value=sock):
            with self.assertRaises(budgets.OutboundTimeout):
                network.safe_get("https://subscription.example/sub", total_timeout=0.08)
        sock.connect.assert_called_once()
        sock.close.assert_called_once()

    def test_tls_handshake_wait_is_capped_by_remaining_total_budget(self):
        import requests
        stop = threading.Event()
        accepted = threading.Event()

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                accepted.set()
                stop.wait(3)  # Accept TCP but never complete the TLS handshake.

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        worker.start()
        try:
            with allow_fixture_address(), patch.object(network, "_resolved_addresses", return_value=("127.0.0.1",)):
                started = time.monotonic()
                with self.assertRaises(requests.Timeout):
                    network.safe_get(f"https://subscription.example:{server.server_address[1]}/sub",
                                     timeout=2, total_timeout=0.3)
                self.assertTrue(accepted.is_set())
                self.assertLess(time.monotonic() - started, 2)
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            worker.join(2)
