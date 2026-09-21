import unittest
from unittest.mock import Mock, patch

from network_security import (
    ResponseTooLarge,
    UnsafeOutboundUrl,
    safe_get,
    validate_outbound_url,
)


class FakeResponse:
    def __init__(self, status_code=200, headers=None, chunks=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks or []
        self.closed = False

    def iter_content(self, chunk_size):
        yield from self._chunks

    def close(self):
        self.closed = True


class NetworkSecurityTest(unittest.TestCase):
    def test_rejects_non_http_and_private_literal_urls(self):
        for url in (
            "file:///etc/passwd",
            "http://127.0.0.1/sub",
            "http://10.0.0.1/sub",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/sub",
            "https://subscription.example:not-a-port/sub",
            "https://subscription.example:0/sub",
        ):
            with self.subTest(url=url):
                with self.assertRaises(UnsafeOutboundUrl):
                    validate_outbound_url(url)

    @patch("network_security.socket.getaddrinfo")
    def test_rejects_hostname_that_resolves_to_private_network(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.5", 443)),
        ]

        with self.assertRaises(UnsafeOutboundUrl):
            validate_outbound_url("https://subscription.example/path", resolve_dns=True)

    @patch("network_security.socket.getaddrinfo")
    @patch("network_security.requests.get")
    def test_redirect_target_is_revalidated(self, request_get, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ]
        request_get.return_value = FakeResponse(
            status_code=302,
            headers={"Location": "http://127.0.0.1/private"},
        )

        with self.assertRaises(UnsafeOutboundUrl):
            safe_get("https://subscription.example/path")

        request_get.assert_called_once()

    @patch("network_security.socket.getaddrinfo")
    @patch("network_security.requests.get")
    def test_response_size_is_limited(self, request_get, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ]
        response = FakeResponse(
            headers={"Content-Length": "100"},
            chunks=[b"ignored"],
        )
        request_get.return_value = response

        with self.assertRaises(ResponseTooLarge):
            safe_get("https://subscription.example/path", max_response_bytes=10)

        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
