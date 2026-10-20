"""格式错误保留回退，非预期故障向调用边界传播，不伪装成空节点。"""
import base64
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from proxyforge.airports import parser
from proxyforge.airports.service import AirportService
from proxyforge.subscription import links
from test_parser_cancellation import SS_LINK, VMESS_LINK, subscription


UNEXPECTED = (RuntimeError, MemoryError, AssertionError)


class ParserExpectedErrorsTest(unittest.TestCase):
    def test_yaml_unexpected_failure_does_not_start_base64_fallback(self):
        for kind in UNEXPECTED:
            error = kind('fixture-sensitive-canary')
            with self.subTest(kind=kind.__name__), patch.object(parser.yaml, 'safe_load', side_effect=error), \
                    patch.object(parser.base64, 'b64decode') as decode:
                with self.assertRaises(kind) as caught:
                    parser.parse_airport_response(subscription(SS_LINK))
                self.assertIs(caught.exception, error)
                decode.assert_not_called()

    def test_base64_unexpected_failure_does_not_return_empty_nodes(self):
        for kind in UNEXPECTED:
            error = kind('fixture-sensitive-canary')
            with self.subTest(kind=kind.__name__), patch.object(parser.yaml, 'safe_load', return_value=None), \
                    patch.object(parser.base64, 'b64decode', side_effect=error), \
                    patch.object(parser, 'parse_share_link') as parse:
                with self.assertRaises(kind) as caught:
                    parser.parse_airport_response(subscription(SS_LINK))
                self.assertIs(caught.exception, error)
                parse.assert_not_called()

    def test_each_share_link_branch_does_not_hide_unexpected_library_failures(self):
        cases = [(VMESS_LINK, links.base64, 'urlsafe_b64decode'),
                 (SS_LINK, links.base64, 'urlsafe_b64decode')]
        cases += [(scheme + '://fixture@node.example:443', links.urllib.parse, 'urlparse')
                  for scheme in ['vless', 'trojan', 'hysteria2', 'hy2', 'tuic', 'anytls', 'wireguard']]
        for link, target, name in cases:
            for kind in UNEXPECTED:
                error = kind('fixture-sensitive-canary')
                with self.subTest(scheme=link.split(':')[0], kind=kind.__name__), \
                        patch.object(target, name, side_effect=error):
                    with self.assertRaises(kind) as caught:
                        links.parse_share_link(link)
                    self.assertIs(caught.exception, error)

    def test_nested_line_failure_has_no_partial_result_or_later_line(self):
        for kind in UNEXPECTED:
            seen = []
            error = kind('fixture-sensitive-canary')

            def parse(line):
                seen.append(line)
                if len(seen) == 2:
                    raise error
                return links.parse_share_link(line)

            with self.subTest(kind=kind.__name__), patch.object(parser, 'parse_share_link', side_effect=parse):
                with self.assertRaises(kind) as caught:
                    parser.parse_airport_response(subscription(SS_LINK, SS_LINK + '2', SS_LINK + '3'))
                self.assertIs(caught.exception, error)
                self.assertEqual(seen, [SS_LINK, SS_LINK + '2'])

    def test_real_yaml_base64_and_legacy_input_failures_keep_fallback(self):
        values = ['', None, 17, b'not a subscription', 'not a subscription', '中文',
                  '- password: [fixture', '[2026-99-99]', '!<tag:fixture> value',
                  "!!int ''", "!!int '+'", "!!float ''", '!!bool maybe', "!!bool ''", "!!timestamp ''",
                  '[' * 1100 + '0' + ']' * 1100, base64.b64encode(b'\xff').decode()]
        for value in values:
            with self.subTest(kind=type(value).__name__, prefix=str(value)[:24]):
                self.assertEqual(parser.parse_airport_response(value), [])
        nodes = [{'name': '中文', 'extension': {'unchanged': True}}]
        yaml_bytes = parser.yaml.safe_dump({'proxies': nodes}, allow_unicode=True).encode()
        self.assertEqual(parser.parse_airport_response(yaml_bytes), nodes)
        self.assertEqual(parser.parse_airport_response(subscription(SS_LINK, '', 'unsupported://fixture', SS_LINK)),
                         [links.parse_share_link(SS_LINK), links.parse_share_link(SS_LINK)])

    def test_real_vmess_json_shape_numeric_and_depth_errors_still_return_none(self):
        values = [None, True, 1, [], 'fixture', {'port': []}, {'port': None}, {'port': {}},
                  {'port': float('inf')}, {'aid': 'invalid'}, {'port': 'invalid'}]
        for value in values:
            link = 'vmess://' + base64.b64encode(json.dumps(value).encode()).decode()
            with self.subTest(value=repr(value)):
                self.assertIsNone(links.parse_share_link(link))
        deep = '[' * 1100 + '0' + ']' * 1100
        self.assertIsNone(links.parse_share_link('vmess://' + base64.b64encode(deep.encode()).decode()))
        self.assertIsNone(links.parse_share_link('vmess://' + base64.b64encode(b'\xff').decode()))

    def test_real_ss_and_uri_errors_keep_none_and_valid_protocol_fields(self):
        for link in ['ss://invalid', 'vless://fixture@node.example:invalid',
                     'wireguard://fixture@node.example:443?address=not-an-ip',
                     'anytls://fixture@node.example:443?udp=maybe',
                     'trojan://fixture@node.example:443?allowInsecure=maybe']:
            with self.subTest(link=link):
                self.assertIsNone(links.parse_share_link(link))
        self.assertEqual(links.parse_share_link(SS_LINK)['password'], 'fixture')
        self.assertEqual(links.parse_share_link('hy2://user:pass@node.example:443,2000-3000')['ports'], '443,2000-3000')
        self.assertIsNone(links.parse_share_link('anytls://fixture@node.example:443?security=reality'))

    def test_existing_per_source_service_boundary_keeps_safe_failure_results(self):
        source = {'name': 'fixture', 'url': 'https://source.example/sub'}
        response = SimpleNamespace(text=subscription(SS_LINK), headers={}, raise_for_status=Mock())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = AirportService(sources_reader=lambda: [source], cache_path=root / 'nodes.yaml',
                info_cache_path=root / 'info.json', http_get=Mock(return_value=response),
                clock=time.time, monotonic=time.monotonic, configuration_lock=nullcontext, logger=Mock())
            with patch.object(parser.yaml, 'safe_load', side_effect=RuntimeError('fixture-sensitive-canary')):
                self.assertEqual(service.fetch_airport_item(source), [])
                self.assertEqual(service.fetch_single_airport_info(source)['error'], 'RuntimeError')
            self.assertNotIn('fixture-sensitive-canary', repr(service.logger.mock_calls))
            self.assertEqual(list(root.iterdir()), [])
