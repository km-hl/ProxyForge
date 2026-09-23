import copy
import json
import unittest
from pathlib import Path

from network_config import validate_network_config, effective_network


def codes(report, level="errors"):
    return [item["code"] for item in report[level]]


class NetworkConfigTest(unittest.TestCase):
    def test_shared_contract_and_no_mutation(self):
        cases = json.loads((Path(__file__).parent / "fixtures/network_config_cases.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["name"]):
                before = copy.deepcopy(case["config"])
                result = validate_network_config(case["config"])
                self.assertEqual(codes(result), case["errors"])
                self.assertEqual(codes(result, "warnings"), case["warnings"])
                self.assertEqual(case["config"], before)

    def test_valid_fake_ip_and_strict_route(self):
        config = {"dns": {"enable": True, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16"},
                  "tun": {"enable": True, "strict-route": True, "dns-hijack": ["any:53", "tcp://any:53"]}}
        result = validate_network_config(config)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["status"], "success")

    def test_invalid_section_types(self):
        for name in ("dns", "tun"):
            for value in ([], "invalid", False, 5):
                with self.subTest(name=name, value=value):
                    self.assertIn("section_type", codes(validate_network_config({name: value})))

    def test_root_types(self):
        for value in (None, [], 5, "dns"):
            self.assertEqual(codes(validate_network_config(value)), ["root_type"])

    def test_null_blocks_and_scalars_preserve_defaults(self):
        self.assertEqual(effective_network({"dns": None, "tun": None}), effective_network({}))
        self.assertEqual(validate_network_config({"dns": None})["errors"], [])
        self.assertFalse(effective_network({"dns": {"enable": None}})["dns"]["enable"])

    def test_types_do_not_coerce(self):
        result = validate_network_config({"dns": {"enable": "false", "nameserver": [42]}, "tun": {"auto-route": 1}})
        self.assertEqual(codes(result).count("boolean_type"), 2)
        self.assertIn("list_item", codes(result))

    def test_bad_range_and_mode(self):
        for value in ("bad", "2001:db8::/32", "198.18.0.1", 12):
            self.assertIn("fake_ip_range", codes(validate_network_config({"dns": {"fake-ip-range": value}})))
        self.assertIn("dns_mode", codes(validate_network_config({"dns": {"enhanced-mode": []}})))

    def test_empty_bootstrap_is_not_missing(self):
        for value in ([], None):
            self.assertIn("bootstrap_required", codes(validate_network_config({"dns": {"default-nameserver": value}})))
        self.assertEqual(validate_network_config({})["errors"], [])

    def test_bootstrap_ip_hosts_and_system(self):
        for value in ("1.1.1.1", "https://1.1.1.1/dns-query#h3", "tls://[2606:4700:4700::1111]:853", "system"):
            self.assertEqual(validate_network_config({"dns": {"default-nameserver": [value]}})["errors"], [])
        self.assertIn("bootstrap_address", codes(validate_network_config({"dns": {"default-nameserver": ["https://dns.example/dns-query"]}})))

    def test_client_local_dns_and_custom_address_are_preserved(self):
        config = {"dns": {"nameserver": ["192.168.1.1", "dhcp://eth0", "https://dns.example/dns-query#RULES&ecs=1.2.3.0/24"]}}
        before = copy.deepcopy(config)
        self.assertEqual(validate_network_config(config)["errors"], [])
        self.assertEqual(config, before)

    def test_invalid_address_and_hijack(self):
        self.assertIn("dns_address", codes(validate_network_config({"dns": {"nameserver": ["https://a:99999/dns-query"]}})))
        self.assertIn("hijack_address", codes(validate_network_config({"tun": {"dns-hijack": ["any:bad"]}})))

    def test_hijack_warnings_only_when_tun_active(self):
        self.assertEqual(validate_network_config({"tun": {"dns-hijack": []}})["warnings"], [])
        report = validate_network_config({"tun": {"enable": True, "dns-hijack": []}})
        self.assertIn("tun_without_dns", codes(report, "warnings"))
        self.assertIn("hijack_missing", codes(report, "warnings"))
        self.assertEqual(report["errors"], [])

    def test_default_hijack_and_explicit_udp_are_equivalent(self):
        a = validate_network_config({"tun": {"enable": True}})
        b = validate_network_config({"tun": {"enable": True, "dns-hijack": ["udp://any:53"]}})
        self.assertEqual(codes(a, "warnings"), codes(b, "warnings"))
        self.assertNotIn("hijack_missing", codes(a, "warnings"))

    def test_ipv6_redir_host_are_not_risks(self):
        result = validate_network_config({"dns": {"enable": True, "ipv6": True, "enhanced-mode": "redir-host"}})
        self.assertEqual(result["warnings"], [])

    def test_respect_h3_warning(self):
        report = validate_network_config({"dns": {"respect-rules": True, "prefer-h3": True, "proxy-server-nameserver": ["1.1.1.1"]}})
        self.assertEqual(codes(report, "warnings"), ["respect_h3"])

    def test_policy_scalar_list_and_references(self):
        config = {"dns": {"nameserver-policy": {"+.a.test": "1.1.1.1", "rule-set:local": ["192.168.1.1"]}},
                  "rule-providers": {"local": {"behavior": "domain"}}}
        self.assertEqual(validate_network_config(config)["errors"], [])
        config["rule-providers"]["local"]["behavior"] = "ipcidr"
        self.assertIn("policy_behavior", codes(validate_network_config(config)))
        config["rule-providers"] = {}
        self.assertIn("policy_reference", codes(validate_network_config(config)))

    def test_policy_invalid_types(self):
        for value in ([], "bad", 5):
            self.assertIn("policy_type", codes(validate_network_config({"dns": {"nameserver-policy": value}})))

    def test_unknown_fields_and_stack_mark_partial(self):
        result = validate_network_config({"dns": {"enable": True, "future-option": True}, "tun": {"stack": "mips"}})
        self.assertEqual(result["errors"], [])
        self.assertIn("stack_version", codes(result, "warnings"))
        self.assertIn("advanced_unverified", codes(result, "info"))

    def test_encryption_covers_policy_bootstrap_fallback_direct(self):
        result = validate_network_config({"dns": {"nameserver-policy": {"+.a": ["1.1.1.1", "https://1.1.1.1/dns-query"]},
                "fallback": ["tls://8.8.8.8"], "direct-nameserver": ["system"]}})
        self.assertEqual(result["encryption"]["nameserver-policy"], {"total": 2, "encrypted": 1})
        self.assertEqual(result["encryption"]["default-nameserver"]["encrypted"], 0)
        self.assertEqual(result["encryption"]["fallback"]["encrypted"], 1)


if __name__ == "__main__":
    unittest.main()
