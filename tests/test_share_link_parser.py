import ast
import base64
import json
import re
import unittest
import urllib.parse
from pathlib import Path
from typing import Any, Dict


def load_functions(*names):
    source = Path(__file__).resolve().parents[1] / "main.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    namespace = {"Any": Any, "Dict": Dict, "base64": base64, "json": json, "re": re, "urllib": urllib}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
    return [namespace[name] for name in names]


_, _, parse_share_link, strip_internal_proxy_fields, add_flag_to_proxy_name = load_functions(
    "has_country_flag",
    "keyword_matches_name",
    "parse_share_link",
    "strip_internal_proxy_fields",
    "add_flag_to_proxy_name",
)


class ShareLinkParserTest(unittest.TestCase):
    def test_vless_reality_keeps_xtls_vision_fields(self):
        uuid = "bb8a0000-0000-4000-8000-000000000001"
        link = (
            f"vless://{uuid}@edge.example.com:443"
            "?encryption=none"
            "&security=reality"
            "&sni=www.cloudflare.com"
            "&fp=chrome"
            "&pbk=public-key"
            "&sid=1a2b"
            "&spx=%2F"
            "&type=tcp"
            "&flow=xtls-rprx-vision"
            "&packetEncoding=xudp"
            "#Home"
        )

        node = parse_share_link(link)

        self.assertEqual(node["type"], "vless")
        self.assertEqual(node["uuid"], uuid)
        self.assertEqual(node["server"], "edge.example.com")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["servername"], "www.cloudflare.com")
        self.assertTrue(node["tls"])
        self.assertEqual(node["flow"], "xtls-rprx-vision")
        self.assertEqual(node["packet-encoding"], "xudp")
        self.assertEqual(node["client-fingerprint"], "chrome")
        self.assertEqual(node["reality-opts"]["public-key"], "public-key")
        self.assertEqual(node["reality-opts"]["short-id"], "1a2b")
        self.assertEqual(node["reality-opts"]["spider-x"], "/")

    def test_vless_without_security_keeps_legacy_tls_default(self):
        link = "vless://bb8a0000-0000-4000-8000-000000000001@example.com:443#LegacyTLS"

        node = parse_share_link(link)

        self.assertTrue(node["tls"])

    def test_shadowsocks_sip002_link_converts_to_yaml_node(self):
        link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.0.2.1:8388#SSNode"

        node = parse_share_link(link)

        self.assertEqual(
            node,
            {
                "name": "SSNode",
                "type": "ss",
                "server": "192.0.2.1",
                "port": 8388,
                "cipher": "aes-256-gcm",
                "password": "password",
                "udp": True,
            },
        )

    def test_shadowsocks_plain_userinfo_link_converts_to_yaml_node(self):
        link = "ss://aes-256-gcm:password@192.0.2.1:8388#PlainSS"

        node = parse_share_link(link)

        self.assertEqual(node["name"], "PlainSS")
        self.assertEqual(node["type"], "ss")
        self.assertEqual(node["server"], "192.0.2.1")
        self.assertEqual(node["port"], 8388)
        self.assertEqual(node["cipher"], "aes-256-gcm")
        self.assertEqual(node["password"], "password")

    def test_shadowsocks_legacy_base64_link_converts_to_yaml_node(self):
        link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjgzODg=#FullB64SS"

        node = parse_share_link(link)

        self.assertEqual(node["name"], "FullB64SS")
        self.assertEqual(node["type"], "ss")
        self.assertEqual(node["server"], "192.0.2.1")
        self.assertEqual(node["port"], 8388)
        self.assertEqual(node["cipher"], "aes-256-gcm")
        self.assertEqual(node["password"], "password")

    def test_trojan_websocket_keeps_transport_options(self):
        link = (
            "trojan://pass@example.com:443"
            "?security=tls"
            "&sni=example.com"
            "&type=ws"
            "&path=%2Fws"
            "&host=cdn.example.com"
            "#TrojanWS"
        )

        node = parse_share_link(link)

        self.assertEqual(node["type"], "trojan")
        self.assertEqual(node["network"], "ws")
        self.assertEqual(node["sni"], "example.com")
        self.assertEqual(
            node["ws-opts"],
            {"path": "/ws", "headers": {"Host": "cdn.example.com"}},
        )

    def test_hysteria2_uses_mihomo_sni_field(self):
        link = (
            "hy2://pass@example.com:443"
            "?sni=example.com"
            "&obfs=salamander"
            "&obfs-password=obfsPass"
            "&alpn=h3"
            "#HY2"
        )

        node = parse_share_link(link)

        self.assertEqual(node["type"], "hysteria2")
        self.assertEqual(node["sni"], "example.com")
        self.assertEqual(node["alpn"], ["h3"])
        self.assertNotIn("servername", node)

    def test_hysteria2_without_explicit_port_defaults_to_443(self):
        node = parse_share_link(
            "hysteria2://secret@hy2.example.com/?sni=hy2.example.com#HY2Default"
        )

        self.assertEqual(node["port"], 443)
        self.assertEqual(node["password"], "secret")

    def test_hysteria2_preserves_userpass_auth(self):
        node = parse_share_link(
            "hysteria2://alice%3As3cr3t@hy2.example.com:8443/#HY2UserPass"
        )

        self.assertEqual(node["password"], "alice:s3cr3t")
        self.assertEqual(node["port"], 8443)

    def test_hysteria2_multi_port_authority_becomes_mihomo_ports(self):
        node = parse_share_link(
            "hy2://secret@hy2.example.com:443,2000-3000/"
            "?insecure=1&obfs=salamander&obfsPassword=mask#HY2Hop"
        )

        self.assertEqual(node["port"], 443)
        self.assertEqual(node["ports"], "443,2000-3000")
        self.assertEqual(node["server"], "hy2.example.com")
        self.assertTrue(node["skip-cert-verify"])
        self.assertEqual(node["obfs-password"], "mask")

    def test_hysteria2_obfs_none_does_not_emit_invalid_mihomo_obfs(self):
        node = parse_share_link(
            "hysteria2://secret@hy2.example.com:443/?obfs=none&obfs-password=unused#HY2"
        )

        self.assertNotIn("obfs", node)
        self.assertNotIn("obfs-password", node)

    def test_internal_source_marker_is_removed_before_saving_or_output(self):
        node = {
            "name": "Lightlayer - HK",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "_airport_name": "_custom_nodes_",
        }

        cleaned = strip_internal_proxy_fields(node)

        self.assertEqual(
            cleaned,
            {
                "name": "Lightlayer - HK",
                "type": "vless",
                "server": "example.com",
                "port": 443,
            },
        )
        self.assertIn("_airport_name", node)

    def test_output_proxy_name_gets_country_flag_prefix_once(self):
        self.assertEqual(add_flag_to_proxy_name("Lightlayer - HK"), "🇭🇰 Lightlayer - HK")
        self.assertEqual(add_flag_to_proxy_name("🇭🇰 Lightlayer - HK"), "🇭🇰 Lightlayer - HK")
        self.assertEqual(add_flag_to_proxy_name("Tokyo JP 01"), "🇯🇵 Tokyo JP 01")
        self.assertEqual(add_flag_to_proxy_name("US Relay"), "🇺🇸 US Relay")
        self.assertEqual(add_flag_to_proxy_name("Unknown Relay"), "Unknown Relay")


if __name__ == "__main__":
    unittest.main()
