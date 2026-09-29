"""Real loopback TLS; URL validation is bypassed only for this isolated fixture."""
import ipaddress
import os
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from proxyforge.security.network_security import safe_get


class OutboundTLSIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ProxyForge test CA")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                  key_encipherment=False, data_encipherment=False, key_agreement=False,
                  key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
              .sign(ca_key, hashes.SHA256()))
        cls.ca_path = cls.root / "ca.pem"
        cls.ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        for label, address in (("valid", "127.0.0.1"), ("wrong-host", "127.0.0.2")):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
                    .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]), critical=False)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .sign(ca_key, hashes.SHA256()))
            (cls.root / (label + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (cls.root / (label + ".key")).write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    @contextmanager
    def server(self, label="valid"):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(dict(self.headers))
                self.send_response(200)
                self.send_header("Content-Length", "11")
                self.end_headers()
                self.wfile.write(b"proxies: []")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.root / (label + ".pem")), str(self.root / (label + ".key")))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        try:
            with patch("proxyforge.security.network_security.validate_outbound_url", side_effect=lambda url, **kwargs: url):
                yield "https://127.0.0.1:" + str(server.server_port) + "/sub", received
        finally:
            server.shutdown()
            server.server_close()
            worker.join(5)

    def test_explicit_ca_validates_real_https_without_environment_proxy(self):
        with self.server() as (url, received), patch.dict(os.environ, {
                "HTTPS_PROXY": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1",
                "REQUESTS_CA_BUNDLE": "nonexistent-env.pem", "CURL_CA_BUNDLE": "nonexistent-env.pem"}, clear=True):
            result = safe_get(url, ca_bundle=str(self.ca_path), timeout=2)
        self.assertEqual(result.content, b"proxies: []")
        self.assertEqual(len(received), 1)

    def test_environment_ca_does_not_trust_an_unknown_certificate(self):
        with self.server() as (url, received), patch.dict(os.environ, {
                "REQUESTS_CA_BUNDLE": str(self.ca_path), "CURL_CA_BUNDLE": str(self.ca_path)}, clear=True):
            with self.assertRaises(requests.exceptions.SSLError):
                safe_get(url, timeout=2)
        self.assertEqual(received, [])

    def test_explicit_ca_still_rejects_hostname_mismatch(self):
        with self.server("wrong-host") as (url, received):
            with self.assertRaises(requests.exceptions.SSLError):
                safe_get(url, ca_bundle=str(self.ca_path), timeout=2)
        self.assertEqual(received, [])

    def test_missing_explicit_ca_fails_without_insecure_fallback(self):
        with self.server() as (url, received):
            with self.assertRaises(OSError):
                safe_get(url, ca_bundle=str(self.root / "missing.pem"), timeout=2)
        self.assertEqual(received, [])
