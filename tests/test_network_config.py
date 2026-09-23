import copy
import json
import unittest
from pathlib import Path

import yaml
from mihomo_compat import BASELINE, DEFAULTS, KNOWN_DNS_FIELDS, KNOWN_TUN_FIELDS
from network_config import validate_network_config, effective_network


def codes(report, level="errors"):
    return [item["code"] for item in report[level]]


class NetworkConfigTest(unittest.TestCase):
    def test_baseline_and_raw_defaults(self):
        release = json.loads((Path(__file__).parent / "mihomo/release.json").read_text())
        self.assertEqual(BASELINE, "Mihomo " + release["version"])
        effective = effective_network({})
        self.assertEqual(effective["dns"]["fake-ip-ttl"], 1)
        self.assertEqual(effective["dns"]["ipv6-timeout"], 100)
        self.assertTrue(effective["dns"]["use-hosts"])
        self.assertTrue(effective["dns"]["use-system-hosts"])
        self.assertEqual(effective["dns"]["cache-max-size"], 0)
        self.assertEqual(effective["dns"]["cache-algorithm"], "")
        self.assertEqual(effective["tun"]["inet6-address"], ["fdfe:dcba:9876::1/126"])
        self.assertTrue(set(effective["dns"]) <= KNOWN_DNS_FIELDS)
        self.assertTrue(set(effective["tun"]) <= KNOWN_TUN_FIELDS)

    def test_real_parser_fixtures_share_static_expectations_and_preserve_values(self):
        root = Path(__file__).parent / "mihomo"
        for case in json.loads((root / "cases.json").read_text()):
            with self.subTest(case=case["file"]):
                config = yaml.safe_load((root / case["file"]).read_text(encoding="utf-8"))
                before = copy.deepcopy(config)
                report = validate_network_config(config)
                expected = case.get("static_valid", case["exit_code"] == 0)
                self.assertEqual(not report["errors"], expected, report["errors"])
                if expected != (case["exit_code"] == 0):
                    self.assertTrue(case.get("static_difference"))
                self.assertEqual(config, before)

    def test_extended_null_defaults_and_empty_values(self):
        before = copy.deepcopy(DEFAULTS)
        value = effective_network({"dns": {"fake-ip-ttl": None, "ipv6-timeout": None,
            "use-hosts": None, "cache-max-size": None, "proxy-server-nameserver-policy": None,
            "fallback-filter": {"geoip": None, "geoip-code": None, "ipcidr": None}},
            "tun": {"inet6-address": None}})
        self.assertEqual(value["dns"]["fake-ip-ttl"], 1)
        self.assertEqual(value["dns"]["ipv6-timeout"], 100)
        self.assertTrue(value["dns"]["use-hosts"])
        self.assertEqual(value["dns"]["fallback-filter"], before["dns"]["fallback-filter"])
        self.assertEqual(value["dns"]["proxy-server-nameserver-policy"], {})
        self.assertEqual(value["tun"]["inet6-address"], [])
        self.assertEqual(DEFAULTS, before)

    def test_ipv6_pool_family_capacity_and_joint_requirements(self):
        base = {"dns": {"enhanced-mode": "fake-ip", "fake-ip-range": "",
                        "fake-ip-range6": "fdfe:dcba:9876::1/64", "ipv6": False}}
        self.assertEqual(validate_network_config(base)["errors"], [])
        self.assertIn("ipv6_environment_unverified", codes(validate_network_config(base), "info"))
        self.assertIn("fake_ip_pools_empty", codes(validate_network_config({**base, "ipv6": False})))
        inactive = {"ipv6": False, "dns": {"fake-ip-range6": "preserved-but-inactive"}}
        self.assertEqual(validate_network_config(inactive)["errors"], [])
        self.assertEqual(inactive["dns"]["fake-ip-range6"], "preserved-but-inactive")
        for value in ("192.0.2.0/24", "fdfe::/129", "fdfe::", [], 12):
            with self.subTest(value=value):
                self.assertIn("fake_ip_range6", codes(validate_network_config({"dns": {"fake-ip-range6": value}})))
        self.assertIn("fake_ip_capacity", codes(validate_network_config({"dns": {
            "enhanced-mode": "fake-ip", "fake-ip-range6": "fdfe::/126"}})))
        # Small pools are only constructed in fake-ip mode.
        self.assertEqual(validate_network_config({"dns": {"fake-ip-range": "192.0.2.0/32"}})["errors"], [])

    def test_numeric_types_ranges_and_parser_coercion(self):
        for field in ("fake-ip-ttl", "cache-max-size", "ipv6-timeout"):
            for value in (True, "1", [], float("nan"), float("inf")):
                with self.subTest(field=field, value=value):
                    self.assertIn("integer_type", codes(validate_network_config({"dns": {field: value}})))
        for field, value in (("fake-ip-ttl", 2 ** 63), ("ipv6-timeout", -1)):
            self.assertIn("integer_range", codes(validate_network_config({"dns": {field: value}})))
        report = validate_network_config({"dns": {"fake-ip-ttl": -1, "cache-max-size": 0, "ipv6-timeout": 1.5}})
        self.assertEqual(report["errors"], [])
        self.assertIn("negative_dns_value", codes(report, "warnings"))
        self.assertIn("integer_coercion", codes(report, "warnings"))

    def test_cache_algorithms_do_not_reject_future_strings(self):
        for algorithm in ("", "lru", "arc"):
            self.assertEqual(validate_network_config({"dns": {"cache-algorithm": algorithm}})["warnings"], [])
        report = validate_network_config({"dns": {"cache-algorithm": "future"}})
        self.assertEqual(report["errors"], [])
        self.assertIn("cache_algorithm_fallback", codes(report, "warnings"))
        self.assertIn("string_type", codes(validate_network_config({"dns": {"cache-algorithm": []}})))

    def test_proxy_policy_requires_base_dns_independently_of_respect_rules(self):
        for respect in (False, True):
            report = validate_network_config({"dns": {"respect-rules": respect,
                "proxy-server-nameserver-policy": {"+.test": "192.0.2.53"}}})
            self.assertIn("proxy_policy_dns_required", codes(report))
        self.assertEqual(validate_network_config({"dns": {"proxy-server-nameserver-policy": {}}})["errors"], [])
        config = {"dns": {"proxy-server-nameserver": ["192.0.2.53"],
            "proxy-server-nameserver-policy": {"+.test": ["https://1.1.1.1/dns-query"]}}}
        self.assertEqual(validate_network_config(config)["encryption"]["proxy-server-nameserver-policy"],
                         {"total": 1, "encrypted": 1})

    def test_policy_reference_case_and_classical_domain_only(self):
        for field in ("nameserver-policy", "proxy-server-nameserver-policy"):
            config = {"dns": {"proxy-server-nameserver": ["192.0.2.53"],
                              field: {"RULE-SET:local,other": "192.0.2.53"}},
                      "rule-providers": {"local": {"behavior": "domain"}, "other": {"behavior": "classical"}}}
            report = validate_network_config(config)
            self.assertEqual(report["errors"], [])
            self.assertIn("policy_classical", codes(report, "warnings"))
            config["rule-providers"].pop("other")
            self.assertIn("policy_reference", codes(validate_network_config(config)))

    def test_policy_null_is_unsafe_but_empty_list_is_parser_compatible(self):
        for field in ("nameserver-policy", "proxy-server-nameserver-policy"):
            for value in ([], ""):
                report = validate_network_config({"dns": {"proxy-server-nameserver": ["192.0.2.53"], field: {"+.test": value}}})
                self.assertEqual(report["errors"], [])
                self.assertIn("policy_empty", codes(report, "warnings"))
            self.assertIn("policy_null", codes(validate_network_config({"dns": {field: {"+.test": None}}})))

    def test_tun_advanced_types_and_platform_advice(self):
        config = {"tun": {"gso": True, "mtu": 0, "gso-max-size": 65536,
            "auto-redirect": True, "include-uid": [0, 1000], "exclude-uid-range": ["2000:2001"],
            "include-interface": ["eth0"], "route-address-set": ["client-side-provider"],
            "loopback-address": ["::1"], "route-address": ["::/0"], "inet6-address": ["192.0.2.1/24"]}}
        report = validate_network_config(config)
        self.assertEqual(report["errors"], [])
        self.assertIn("tun_platform_unverified", codes(report, "info"))
        self.assertNotIn("advanced_unverified", codes(report, "info"))
        for field, value, code in (("mtu", -1, "integer_range"), ("mtu", 2 ** 32, "integer_range"),
                ("gso", 1, "boolean_type"), ("include-uid", [True], "integer_type"),
                ("route-address", ["192.0.2.0/255.255.255.0"], "tun_address"),
                ("loopback-address", ["192.0.2.1/24"], "tun_address")):
            with self.subTest(field=field, value=value):
                self.assertIn(code, codes(validate_network_config({"tun": {field: value}})))

    def test_fallback_nested_defaults_types_and_geodata(self):
        report = validate_network_config({"dns": {"fallback": ["192.0.2.53"],
            "fallback-filter": {"ipcidr": ["bad"], "future-filter": {"custom": True}}}})
        self.assertIn("fallback_prefix", codes(report))
        self.assertIn("geodata_unverified", codes(report, "info"))
        self.assertIn("advanced_unverified", codes(report, "info"))
        self.assertIn("fallback_filter_type", codes(validate_network_config({"dns": {"fallback-filter": []}})))

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
        result = validate_network_config({"dns": {"enable": True, "future-option": True}, "tun": {"stack": "future-stack"}})
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
