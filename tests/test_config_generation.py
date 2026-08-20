import ast
import copy
import re
import unittest
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List

import yaml


def load_config_functions():
    source = Path(__file__).resolve().parents[1] / "main.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    wanted = {
        "get_airport_name",
        "strip_internal_proxy_fields",
        "has_country_flag",
        "keyword_matches_name",
        "add_flag_to_proxy_name",
        "ConfigValidationError",
        "_is_valid_port",
        "validate_proxy_nodes",
        "validate_mihomo_config",
        "assert_valid_mihomo_config",
        "build_airport_providers",
        "build_airport_provider_document",
        "decorate_proxy_names",
        "cleanup_proxy_group_references",
        "build_subscription_config",
    }
    nodes = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in wanted
    ]
    namespace = {
        "Any": Any,
        "Dict": Dict,
        "List": List,
        "copy": copy,
        "re": re,
        "urllib": urllib,
        "yaml": yaml,
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace


FUNCTIONS = load_config_functions()
validate_mihomo_config = FUNCTIONS["validate_mihomo_config"]
validate_proxy_nodes = FUNCTIONS["validate_proxy_nodes"]
build_subscription_config = FUNCTIONS["build_subscription_config"]
build_airport_provider_document = FUNCTIONS["build_airport_provider_document"]
cleanup_proxy_group_references = FUNCTIONS["cleanup_proxy_group_references"]


class ConfigValidationTest(unittest.TestCase):
    def test_missing_rule_target_is_reported_with_rule_number(self):
        config = {
            "proxies": [],
            "proxy-groups": [{"name": "Proxy", "type": "select", "proxies": ["DIRECT"]}],
            "rules": ["GEOSITE,youtube,YouTube", "MATCH,Proxy"],
        }

        errors = validate_mihomo_config(config)

        self.assertTrue(any("rules[1]" in error and "YouTube" in error for error in errors))

    def test_missing_proxy_provider_and_rule_provider_are_reported(self):
        config = {
            "proxies": [],
            "proxy-groups": [{"name": "Proxy", "type": "select", "use": ["MissingAirport"]}],
            "rules": ["RULE-SET,missing_rules,Proxy"],
        }

        errors = validate_mihomo_config(config)

        self.assertTrue(any("MissingAirport" in error for error in errors))
        self.assertTrue(any("missing_rules" in error for error in errors))

    def test_proxy_group_cycle_is_rejected(self):
        config = {
            "proxies": [],
            "proxy-groups": [
                {"name": "A", "type": "select", "proxies": ["B"]},
                {"name": "B", "type": "select", "proxies": ["A"]},
            ],
            "rules": ["MATCH,A"],
        }

        errors = validate_mihomo_config(config)

        self.assertTrue(any("循环引用" in error for error in errors))

    def test_invalid_hysteria2_node_is_rejected(self):
        errors = validate_proxy_nodes([
            {
                "name": "Broken HY2",
                "type": "hysteria2",
                "server": "hy2.example.com",
                "port": None,
                "password": "",
            }
        ])

        self.assertTrue(any("port/ports" in error for error in errors))
        self.assertTrue(any("password" in error for error in errors))

    def test_airports_are_emitted_as_secure_proxy_providers_and_group_use(self):
        config = {
            "proxy-groups": [{
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["DIRECT"],
                "use": ["LiangXin", "PeiQian", "Mitce", "SakuraCat"],
            }],
            "rules": ["MATCH,🚀 节点选择"],
        }
        airports = [
            {"name": name, "url": f"https://{name.lower()}.invalid/private-subscription"}
            for name in ["LiangXin", "PeiQian", "Mitce", "SakuraCat"]
        ]
        custom_nodes = [{
            "name": "HK-HY2",
            "type": "hysteria2",
            "server": "hy2.example.com",
            "port": 443,
            "password": "secret",
        }]

        output = build_subscription_config(
            config, custom_nodes, airports, "https://proxyforge.example", "token"
        )

        self.assertEqual(
            output["proxy-groups"][0]["use"],
            ["LiangXin", "PeiQian", "Mitce", "SakuraCat"],
        )
        self.assertEqual(set(output["proxy-providers"]), {"LiangXin", "PeiQian", "Mitce", "SakuraCat"})
        self.assertTrue(all(
            provider["url"].startswith("https://proxyforge.example/provider/")
            for provider in output["proxy-providers"].values()
        ))
        rendered = yaml.safe_dump(output, allow_unicode=True)
        self.assertNotIn("private-subscription", rendered)
        self.assertEqual(len(output["proxies"]), 1)
        self.assertEqual(validate_mihomo_config(output), [])

    def test_http_airport_provider_document_uses_proxies_key(self):
        proxies = [{"name": "Airport Node", "type": "ss"}]

        document = build_airport_provider_document(proxies)

        self.assertEqual(document, {"proxies": proxies})
        self.assertNotIn("payload", document)

    def test_stale_group_proxy_and_provider_references_are_cleaned(self):
        config = {
            "proxies": [],
            "proxy-groups": [
                {
                    "name": "GitHub",
                    "type": "select",
                    "proxies": ["DIRECT", "Deleted-HY2", "Existing-HY2"],
                    "use": ["CurrentAirport", "DeletedAirport"],
                },
                {
                    "name": "EmptyAfterCleanup",
                    "type": "select",
                    "proxies": ["Deleted-HY2"],
                },
            ],
            "rules": ["MATCH,GitHub"],
        }

        result = cleanup_proxy_group_references(
            config,
            valid_proxy_names=["Existing-HY2"],
            valid_provider_names=["CurrentAirport"],
        )

        self.assertEqual(result["total"], 3)
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["DIRECT", "Existing-HY2"])
        self.assertEqual(config["proxy-groups"][0]["use"], ["CurrentAirport"])
        self.assertEqual(config["proxy-groups"][1]["proxies"], ["DIRECT"])

    def test_delete_cascade_removes_only_the_deleted_node(self):
        config = {
            "proxy-groups": [{
                "name": "Proxy",
                "type": "select",
                "proxies": ["Deleted-HY2", "Unresolved-But-Not-Deleted"],
            }],
            "rules": ["DOMAIN-SUFFIX,example.com,Deleted-HY2"],
        }

        result = cleanup_proxy_group_references(
            config,
            removed_proxy_names=["Deleted-HY2"],
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(
            config["proxy-groups"][0]["proxies"],
            ["Unresolved-But-Not-Deleted"],
        )
        self.assertEqual(config["rules"], ["DOMAIN-SUFFIX,example.com,Deleted-HY2"])


if __name__ == "__main__":
    unittest.main()
