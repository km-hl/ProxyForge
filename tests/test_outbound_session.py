import concurrent.futures
import os
import tempfile
import threading
import unittest
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

from proxyforge.security.network_security import safe_get, ResponseTooLarge, UnsafeOutboundUrl


class RawResponse:
    def __init__(self, chunks, headers=None):
        self.chunks = chunks
        self.reads = 0
        self.closed = False
        self.released = False
        message = Message()
        for name, value in (headers or {}).items():
            message[name] = value
        self._original_response = SimpleNamespace(msg=message)

    def stream(self, size, decode_content=True):
        for chunk in self.chunks:
            self.reads += 1
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


def response(request, status=200, headers=None, chunks=(b"proxies: []",)):
    result = requests.Response()
    result.status_code = status
    result.url = request.url
    result.request = request
    result.headers.update(headers or {})
    result.raw = RawResponse(chunks, headers)
    return result


class OutboundSessionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(patch.stopall)
        patch("proxyforge.security.network_security._resolved_addresses", return_value={"93.184.216.34"}).start()
        # Exercise real Requests preparation and environment merging; intercept
        # only the transport so tests never access a proxy or external host.
        self.send = patch("requests.adapters.HTTPAdapter.send").start()
        self.send.side_effect = lambda request, **kwargs: response(request)
        self.closed_sessions = []
        original_close = requests.Session.close

        def close(session):
            self.closed_sessions.append(session)
            original_close(session)

        patch.object(requests.Session, "close", close).start()

    def test_environment_proxy_and_ca_are_not_inherited(self):
        settings = {key: "http://127.0.0.1:9" for key in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}
        settings.update(REQUESTS_CA_BUNDLE="private-ca-path", CURL_CA_BUNDLE="another-private-path")
        with patch.dict(os.environ, settings, clear=True):
            result = safe_get("https://subscription.example/sub")
        self.assertEqual(result.content, b"proxies: []")
        self.assertEqual(self.send.call_args.kwargs["proxies"], {})
        self.assertIs(self.send.call_args.kwargs["verify"], True)

    def test_netrc_credentials_are_not_sent(self):
        netrc = Path(self.temp.name) / "netrc"
        netrc.write_text("machine subscription.example login fixture-user password fixture-password\n", encoding="utf-8")
        netrc.chmod(0o600)
        with patch.dict(os.environ, {"NETRC": str(netrc)}, clear=True):
            safe_get("https://subscription.example/sub")
        self.assertNotIn("Authorization", self.send.call_args.args[0].headers)

    def test_redirect_body_is_not_eagerly_consumed_by_requests(self):
        replies = []

        def send(request, **kwargs):
            reply = response(request, 302, {"Location": "/next"}, [AssertionError("redirect body consumed")]) if not replies else response(request)
            replies.append(reply)
            return reply

        self.send.side_effect = send
        safe_get("https://subscription.example/sub")
        self.assertEqual(replies[0].raw.reads, 0)
        self.assertTrue(replies[0].raw.closed)
        self.assertTrue(replies[0].raw.released)

    def test_success_keeps_response_usable_after_resources_close(self):
        self.send.side_effect = lambda request, **kwargs: response(
            request, headers={"subscription-userinfo": "upload=7", "Content-Type": "text/plain; charset=utf-8"},
            chunks=[b"proxies:", b" []"])
        result = safe_get("https://subscription.example/sub", headers={"User-Agent": "fixture"}, timeout=7)
        self.assertEqual(result.text, "proxies: []")
        self.assertEqual(result.headers["subscription-userinfo"], "upload=7")
        result.raise_for_status()
        self.assertTrue(result.raw.released)
        self.assertEqual(len(self.closed_sessions), 1)
        self.assertFalse(self.closed_sessions[0].trust_env)
        self.assertEqual(self.send.call_args.kwargs["timeout"], 7)
        self.assertTrue(self.send.call_args.kwargs["stream"])
        self.assertEqual(self.send.call_args.args[0].headers["User-Agent"], "fixture")

    def test_relative_redirects_use_one_session_and_validate_each_hop(self):
        replies = []

        def send(request, **kwargs):
            number = len(replies)
            reply = response(request, 302, {"Location": "/hop" + str(number)}) if number < 3 else response(request)
            replies.append(reply)
            return reply

        self.send.side_effect = send
        with patch("proxyforge.security.network_security._resolved_addresses", return_value={"93.184.216.34"}) as dns:
            result = safe_get("https://subscription.example/sub")
        self.assertEqual(self.send.call_count, 4)
        self.assertEqual(dns.call_count, 4)
        self.assertEqual(result.url, "https://subscription.example/hop2")
        self.assertEqual(len(self.closed_sessions), 1)
        self.assertTrue(all(reply.raw.released for reply in replies))

    def test_redirect_limit_and_missing_location_close_all_resources(self):
        for location, count in (("/loop", 4), (None, 1)):
            with self.subTest(location=location):
                replies = []
                self.closed_sessions.clear()

                def send(request, **kwargs):
                    reply = response(request, 302, {"Location": location} if location else {})
                    replies.append(reply)
                    return reply

                self.send.side_effect = send
                with self.assertRaises(UnsafeOutboundUrl):
                    safe_get("https://subscription.example/sub")
                self.assertEqual(len(replies), count)
                self.assertTrue(all(reply.raw.closed and reply.raw.released for reply in replies))
                self.assertEqual(len(self.closed_sessions), 1)

    def test_redirect_private_or_mixed_dns_is_rejected_before_second_send(self):
        for addresses in ({"127.0.0.1"}, {"::1"}, {"93.184.216.34", "10.0.0.1"}):
            with self.subTest(addresses=addresses):
                self.send.reset_mock()
                replies = []

                def send(request, **kwargs):
                    reply = response(request, 302, {"Location": "https://next.example/sub"})
                    replies.append(reply)
                    return reply

                self.send.side_effect = send
                with patch("proxyforge.security.network_security._resolved_addresses",
                           side_effect=[{"93.184.216.34"}, addresses]):
                    with self.assertRaises(UnsafeOutboundUrl):
                        safe_get("https://subscription.example/sub")
                self.send.assert_called_once()
                self.assertTrue(replies[0].raw.closed)

    def test_oversized_or_failed_stream_closes_response_and_session(self):
        cases = [({"Content-Length": "11"}, [b"unused"], ResponseTooLarge, 0),
                 ({}, [b"12345", b"678901", b"unused"], ResponseTooLarge, 2),
                 ({"Content-Length": "invalid"}, [b"12345678901"], ResponseTooLarge, 1),
                 ({}, [b"ok", requests.exceptions.ConnectionError("fixture")], requests.exceptions.ConnectionError, 2)]
        for headers, chunks, exception, reads in cases:
            with self.subTest(headers=headers, exception=exception):
                replies = []
                self.closed_sessions.clear()

                def send(request, **kwargs):
                    reply = response(request, headers=headers, chunks=chunks)
                    replies.append(reply)
                    return reply

                self.send.side_effect = send
                with self.assertRaises(exception):
                    safe_get("https://subscription.example/sub", max_response_bytes=10)
                self.assertEqual(replies[0].raw.reads, reads)
                self.assertTrue(replies[0].raw.closed and replies[0].raw.released)
                self.assertEqual(len(self.closed_sessions), 1)

    def test_transport_error_closes_session(self):
        for exception in (requests.exceptions.Timeout, requests.exceptions.SSLError):
            with self.subTest(exception=exception):
                self.closed_sessions.clear()
                self.send.side_effect = exception("fixture")
                with self.assertRaises(exception):
                    safe_get("https://subscription.example/sub")
                self.assertEqual(len(self.closed_sessions), 1)

    def test_http_error_retains_status_after_closing(self):
        self.send.side_effect = lambda request, **kwargs: response(request, 503, chunks=[b"unavailable"])
        result = safe_get("https://subscription.example/sub")
        self.assertEqual(result.text, "unavailable")
        self.assertTrue(result.raw.released)
        with self.assertRaises(requests.exceptions.HTTPError):
            result.raise_for_status()

    def test_cookies_are_not_carried_to_next_hop_or_request(self):
        replies = []

        def send(request, **kwargs):
            self.assertNotIn("Cookie", request.headers)
            reply = response(request, 302, {"Location": "/next", "Set-Cookie": "private=fixture; Path=/"}) if len(replies) % 2 == 0 else response(request)
            replies.append(reply)
            return reply

        self.send.side_effect = send
        for _ in range(2):
            safe_get("https://subscription.example/sub")
        self.assertEqual(len(self.closed_sessions), 2)
        self.assertIsNot(self.closed_sessions[0], self.closed_sessions[1])

    def test_parallel_fetches_do_not_share_sessions(self):
        barrier = threading.Barrier(4)

        def send(request, **kwargs):
            barrier.wait(timeout=5)
            return response(request)

        self.send.side_effect = send
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(safe_get, ["https://subscription.example/sub"] * 4))
        self.assertEqual(len(results), 4)
        self.assertEqual(len({id(session) for session in self.closed_sessions}), 4)
        self.assertTrue(all(not session.trust_env for session in self.closed_sessions))

    def test_explicit_ca_overrides_environment_without_allowing_verification_off(self):
        with patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": "ignored"}, clear=True):
            safe_get("https://subscription.example/sub", ca_bundle="trusted-fixture.pem")
        self.assertEqual(self.send.call_args.kwargs["verify"], "trusted-fixture.pem")
        for value in (False, True, "", "   "):
            with self.subTest(value=value):
                self.send.reset_mock()
                with self.assertRaises(ValueError):
                    safe_get("https://subscription.example/sub", ca_bundle=value)
                self.send.assert_not_called()

    def test_explicit_url_credentials_still_work_without_netrc(self):
        safe_get("https://fixture-user:fixture-password@subscription.example/sub")
        expected = requests.auth._basic_auth_str("fixture-user", "fixture-password")
        self.assertEqual(self.send.call_args.args[0].headers["Authorization"], expected)

    def test_both_airport_callers_pass_deployment_ca_setting(self):
        from test_api_integration import load_isolated_application
        with patch.dict(os.environ, {"PROXYFORGE_AIRPORT_CA_BUNDLE": "trusted-fixture.pem"}):
            app = load_isolated_application(Path(self.temp.name))
        result = SimpleNamespace(headers={}, text="proxies: []", raise_for_status=lambda: None)
        with patch.object(app, "safe_get", return_value=result) as fetch:
            app.fetch_airport_item("https://subscription.example/sub")
            app.fetch_single_airport_info("https://subscription.example/sub")
        self.assertEqual(fetch.call_count, 2)
        self.assertTrue(all(call.kwargs["ca_bundle"] == "trusted-fixture.pem" for call in fetch.call_args_list))
