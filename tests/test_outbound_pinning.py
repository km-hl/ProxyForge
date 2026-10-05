"""Observe real TCP connections; loopback is allowed only inside fixtures."""
import socket
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import requests

from proxyforge.security import network_security as network


@contextmanager
def allow_fixture_address(address="127.0.0.1"):
    original = network._is_public_address
    with patch.object(network, "_is_public_address", side_effect=lambda value: value == address or original(value)):
        yield


@contextmanager
def observe_connect():
    destinations = []
    original = socket.socket.connect

    def connect(sock, address):
        destinations.append(address)
        return original(sock, address)

    with patch.object(socket.socket, "connect", connect):
        yield destinations


@contextmanager
def http_server(*, ipv6=False, redirect=None):
    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            received.append((self.path, dict(self.headers)))
            self.send_response(302 if redirect and self.path == "/sub" else 200)
            if redirect and self.path == "/sub":
                self.send_header("Location", redirect)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                # Redirect bodies are deliberately closed without reading.
                pass

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET

    server = Server(("::1" if ipv6 else "127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    worker.start()
    try:
        yield server.server_port, received
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)


class OutboundPinningTest(unittest.TestCase):
    def test_real_tcp_does_not_resolve_again_after_validation(self):
        with http_server() as (port, received), allow_fixture_address(), observe_connect() as destinations:
            with patch.object(socket, "getaddrinfo", side_effect=[
                [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))],
                [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.2", port))],
            ]) as dns:
                response = network.safe_get(f"http://subscription.example:{port}/sub", timeout=1,
                                            headers={"hOsT": "forged.example"})
            self.assertEqual(response.content, b"ok")
            self.assertEqual(destinations, [("127.0.0.1", port)])
            dns.assert_called_once_with("subscription.example", port, type=socket.SOCK_STREAM)
            self.assertEqual(received[0][1]["Host"], f"subscription.example:{port}")

    def test_redirect_and_next_call_each_open_a_new_validated_connection(self):
        with http_server(redirect="/final") as (port, received), allow_fixture_address(), observe_connect() as destinations:
            with patch.object(network, "_resolved_addresses", return_value=("127.0.0.1",)) as dns:
                for _ in range(2):
                    self.assertEqual(network.safe_get(f"http://subscription.example:{port}/sub").content, b"ok")
            self.assertEqual(dns.call_count, 4)
            self.assertEqual(destinations, [("127.0.0.1", port)] * 4)
            self.assertEqual([path for path, _ in received], ["/sub", "/final"] * 2)

    def test_same_origin_redirect_cannot_reuse_connection_after_dns_becomes_private(self):
        with http_server(redirect="/final") as (port, received), allow_fixture_address(), observe_connect() as destinations:
            with patch.object(network, "_resolved_addresses", side_effect=[("127.0.0.1",), ("127.0.0.2",)]):
                with self.assertRaises(network.UnsafeOutboundUrl):
                    network.safe_get(f"http://subscription.example:{port}/sub")
            self.assertEqual(len(received), 1)
            self.assertEqual(destinations, [("127.0.0.1", port)])

    def test_idna_name_is_canonicalized_before_dns_and_host(self):
        with http_server() as (port, received), allow_fixture_address():
            with patch.object(network, "_resolved_addresses", return_value=("127.0.0.1",)) as dns:
                network.safe_get(f"http://例子.example:{port}/sub")
            dns.assert_called_once_with("xn--fsqu00a.example", port)
            self.assertEqual(received[0][1]["Host"], f"xn--fsqu00a.example:{port}")

    def test_pools_close_after_success_and_size_failure(self):
        pools = []
        original = network._PinnedAdapter.get_connection_with_tls_context

        def get_pool(adapter, *args, **kwargs):
            pool = original(adapter, *args, **kwargs)
            pools.append(pool)
            return pool

        with http_server() as (port, _), allow_fixture_address():
            with patch.object(network, "_resolved_addresses", return_value=("127.0.0.1",)), \
                    patch.object(network._PinnedAdapter, "get_connection_with_tls_context", get_pool):
                network.safe_get(f"http://subscription.example:{port}/sub", max_response_bytes=2)
                with self.assertRaises(network.ResponseTooLarge):
                    network.safe_get(f"http://subscription.example:{port}/sub", max_response_bytes=1)
            self.assertEqual(len(pools), 2)
            self.assertTrue(all(pool.pool is None for pool in pools))

    def test_real_ipv6_numeric_connection(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            probe.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        finally:
            probe.close()
        with http_server(ipv6=True) as (port, received), allow_fixture_address("::1"), observe_connect() as destinations:
            with patch.object(socket, "getaddrinfo", return_value=[
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
            ]) as dns:
                network.safe_get(f"http://subscription.example:{port}/sub")
            self.assertEqual(destinations, [("::1", port, 0, 0)])
            self.assertEqual(dns.call_count, 1)
            self.assertEqual(len(received), 1)

    def test_private_reserved_mixed_empty_and_scoped_answers_never_connect(self):
        rejected = ("127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1",
                    "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "::", "fc00::1", "fe80::1",
                    "2001:db8::1", "ff02::1", "::ffff:127.0.0.1", "2606:4700:4700::1111%3")
        with patch.object(socket.socket, "connect") as connect:
            for address in rejected:
                for addresses in ((address,), ("93.184.216.34", address)):
                    with self.subTest(addresses=addresses), patch.object(network, "_resolved_addresses", return_value=addresses):
                        with self.assertRaises(network.UnsafeOutboundUrl):
                            network.safe_get("https://subscription.example/sub")
            with patch.object(network, "_resolved_addresses", return_value=()):
                with self.assertRaises(network.UnsafeOutboundUrl):
                    network.safe_get("https://subscription.example/sub")
            connect.assert_not_called()

    def test_local_names_and_literals_are_rejected_before_dns(self):
        with patch.object(network, "_resolved_addresses") as dns:
            for host in ("localhost", "a.localhost", "a.internal", "a.local", "127.0.0.1",
                         "[::1]", "[ff02::1]", "[2606:4700:4700::1111%253]"):
                with self.subTest(host=host), self.assertRaises(network.UnsafeOutboundUrl):
                    network.safe_get("http://" + host + "/sub")
            dns.assert_not_called()

    def test_tcp_fallback_uses_only_this_hops_validated_addresses(self):
        failed, connected = Mock(), Mock()
        failed.connect.side_effect = OSError("unreachable")
        with patch.object(network, "_resolved_addresses", return_value=("2606:4700:4700::1111", "93.184.216.34")):
            addresses = network._validated_addresses(network.urllib.parse.urlsplit("https://subscription.example/sub"))
        connection = network._PinnedHTTPSConnection("subscription.example", port=443, timeout=2, pinned_addresses=addresses)
        with patch.object(socket, "socket", side_effect=[failed, connected]) as factory, patch.object(socket, "getaddrinfo") as dns:
            self.assertIs(connection._new_conn(), connected)
            self.assertEqual([call.args[0] for call in factory.call_args_list], [socket.AF_INET6, socket.AF_INET])
            failed.connect.assert_called_once_with(("2606:4700:4700::1111", 443, 0, 0))
            connected.connect.assert_called_once_with(("93.184.216.34", 443))
            failed.close.assert_called_once()
            dns.assert_not_called()

    def test_all_tcp_failures_close_sockets_without_http_retry_or_dns_refresh(self):
        for error, expected in ((OSError("unreachable"), requests.ConnectionError), (socket.timeout(), requests.ConnectTimeout)):
            with self.subTest(error=type(error)), patch.object(network, "_resolved_addresses", return_value=("93.184.216.34",)) as dns:
                sock = Mock()
                sock.connect.side_effect = error
                with patch.object(socket, "socket", return_value=sock):
                    with self.assertRaises(expected):
                        network.safe_get("http://subscription.example/sub", timeout=1)
                dns.assert_called_once()
                sock.connect.assert_called_once()
                sock.close.assert_called_once()

    def test_adapter_rejects_different_url_or_proxy(self):
        url = "http://subscription.example/sub"
        adapter = network._PinnedAdapter(url, ("93.184.216.34",))
        self.addCleanup(adapter.close)
        for target, proxies in ((url + "?changed", {}), (url, {"http": "http://proxy.example"})):
            with self.subTest(target=target, proxies=proxies), self.assertRaises(network.UnsafeOutboundUrl):
                adapter.get_connection_with_tls_context(requests.Request("GET", target).prepare(), True, proxies)
