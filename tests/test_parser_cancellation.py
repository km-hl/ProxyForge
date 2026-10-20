"""纯解析与机场线程池内的控制信号传播；只使用合成订阅与模拟 HTTP。"""
import asyncio
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
from proxyforge.subscription.links import parse_share_link


SIGNALS = (KeyboardInterrupt, SystemExit, asyncio.CancelledError, GeneratorExit)
SS_LINK = 'ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@node.example:8388#fixture'
VMESS_LINK = 'vmess://' + base64.b64encode(json.dumps({
    'ps': 'fixture', 'add': 'node.example', 'port': 443, 'id': 'fixture',
}).encode()).decode()


def subscription(*links):
    return base64.b64encode('\n'.join(links).encode()).decode().rstrip('=')


class ParserCancellationTest(unittest.TestCase):
    def test_yaml_control_signal_does_not_start_base64_fallback(self):
        for kind in SIGNALS:
            signal = kind()
            with self.subTest(signal=kind.__name__), \
                    patch.object(parser.yaml, 'safe_load', side_effect=signal), \
                    patch.object(parser.base64, 'b64decode') as decode:
                with self.assertRaises(kind) as raised:
                    parser.parse_airport_response(subscription(SS_LINK))
                self.assertIs(raised.exception, signal)
                decode.assert_not_called()

    def test_base64_control_signal_does_not_parse_links_or_return_empty(self):
        encoded = subscription(SS_LINK)
        for kind in SIGNALS:
            signal = kind()
            with self.subTest(signal=kind.__name__), \
                    patch.object(parser.base64, 'b64decode', side_effect=signal), \
                    patch.object(parser, 'parse_share_link') as parse:
                with self.assertRaises(kind) as raised:
                    parser.parse_airport_response(encoded)
                self.assertIs(raised.exception, signal)
                parse.assert_not_called()

    def test_share_link_adapter_control_signal_is_not_treated_as_empty_subscription(self):
        for kind in SIGNALS:
            signal = kind()
            with self.subTest(signal=kind.__name__), \
                    patch.object(parser, 'parse_share_link', side_effect=signal):
                with self.assertRaises(kind) as raised:
                    parser.parse_airport_response(subscription(SS_LINK))
                self.assertIs(raised.exception, signal)

    def assert_inner_signal_survives(self, link, target):
        encoded = subscription(link)
        for kind in SIGNALS:
            for name, parse, value in [('direct', parse_share_link, link),
                                       ('subscription', parser.parse_airport_response, encoded)]:
                signal = kind()
                with self.subTest(link=link.split(':', 1)[0], signal=kind.__name__, path=name), \
                        patch(target, side_effect=signal):
                    with self.assertRaises(kind) as raised:
                        parse(value)
                    self.assertIs(raised.exception, signal)

    def test_vmess_json_control_signal_survives_direct_and_subscription_parsing(self):
        self.assert_inner_signal_survives(VMESS_LINK, 'proxyforge.subscription.links.json.loads')

    def test_ss_url_control_signal_survives_direct_and_subscription_parsing(self):
        self.assert_inner_signal_survives(SS_LINK, 'proxyforge.subscription.links.urllib.parse.urlparse')

    def test_other_supported_schemes_propagate_control_signals_through_both_layers(self):
        for scheme in ['vless', 'trojan', 'hysteria2', 'hy2', 'tuic', 'anytls', 'wireguard']:
            self.assert_inner_signal_survives(scheme + '://fixture@node.example:443#fixture',
                                             'proxyforge.subscription.links.urllib.parse.urlparse')

    def test_cancelled_multiline_subscription_never_returns_partial_nodes_or_parses_later_lines(self):
        for kind in SIGNALS:
            signal = kind()
            seen = []

            def parse(line):
                seen.append(line)
                if len(seen) == 2:
                    raise signal
                return parse_share_link(line)

            with self.subTest(signal=kind.__name__), patch.object(parser, 'parse_share_link', side_effect=parse):
                with self.assertRaises(kind) as raised:
                    parser.parse_airport_response(subscription(SS_LINK, SS_LINK + '2', SS_LINK + '3'))
                self.assertIs(raised.exception, signal)
                self.assertEqual(seen, [SS_LINK, SS_LINK + '2'])

    def test_service_fetch_metadata_and_thread_pool_do_not_convert_signals_to_data(self):
        source = {'name': 'fixture', 'url': 'https://airport.example/sub'}
        response = SimpleNamespace(text=subscription(SS_LINK), headers={}, raise_for_status=Mock())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = AirportService(
                sources_reader=lambda: [source], cache_path=root / 'nodes.yaml',
                info_cache_path=root / 'info.json', http_get=Mock(return_value=response),
                clock=time.time, monotonic=time.monotonic, configuration_lock=nullcontext, logger=Mock(),
            )
            for kind in SIGNALS:
                for name, operation in [
                    ('nodes', lambda: service.fetch_airport_item(source)),
                    ('metadata', lambda: service.fetch_single_airport_info(source)),
                    ('pool', service.fetch_airport_proxies),
                ]:
                    signal = kind()
                    with self.subTest(signal=kind.__name__, operation=name), \
                            patch.object(parser.yaml, 'safe_load', side_effect=signal):
                        with self.assertRaises(kind) as raised:
                            operation()
                        self.assertIs(raised.exception, signal)
            service.logger.error.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_yaml_priority_and_unpadded_base64_keep_original_success_behavior(self):
        nodes = [{'name': '中文', 'extension': {'keep': True}}]
        self.assertEqual(parser.parse_airport_response(parser.yaml.safe_dump({'proxies': nodes})), nodes)
        self.assertEqual(parser.parse_airport_response(subscription(SS_LINK, '', 'unsupported://fixture', SS_LINK)),
                         [parse_share_link(SS_LINK), parse_share_link(SS_LINK)])

    def test_ordinary_invalid_input_keeps_silent_empty_or_none_fallback(self):
        for text in ['', 'not a subscription', '中文', '- password: [fixture', '[2026-99-99]',
                     '[' * 1100 + '0' + ']' * 1100, subscription('unsupported://fixture'),
                     base64.b64encode(b'\xff').decode()]:
            with self.subTest(input=text[:24]):
                self.assertEqual(parser.parse_airport_response(text), [])
        for link in ['vmess://not-json', 'ss://invalid', 'vless://fixture@node.example:invalid']:
            with self.subTest(scheme=link.split(':', 1)[0]):
                self.assertIsNone(parse_share_link(link))
