"""来源别名可能含秘密；日志使用位置，节点/API 的原别名保持。"""
from contextlib import nullcontext
import logging
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import yaml

from proxyforge.airports import service as module
from proxyforge.airports.sources import AirportSource


CANARY = 'fixture-sensitive-canary'


class AirportLogIdentitiesTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.root = root
        self.alias = 'https://private.example/sub?token=' + CANARY + '\nprivate-key=' + CANARY
        self.source = {'name': self.alias, 'url': 'https://source.example/sub'}
        self.logger = logging.getLogger(__name__)
        self.http = Mock()
        self.service = module.AirportService(sources_reader=lambda: [self.source],
            cache_path=root / 'nodes.yaml', info_cache_path=root / 'info.json',
            http_get=self.http, clock=lambda: 0, monotonic=lambda: 0,
            configuration_lock=nullcontext, logger=self.logger)

    def response(self, proxies):
        self.http.return_value = SimpleNamespace(text=yaml.safe_dump({'proxies': proxies}),
                                                headers={}, raise_for_status=Mock())

    def assert_safe(self, captured):
        for record in captured.records:
            self.assertNotIn(CANARY, record.getMessage())
            self.assertNotIn(CANARY, repr((record.msg, record.args)))
            self.assertIsNone(record.exc_info)
            self.assertIsNone(record.stack_info)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_success_keeps_exact_source_name_and_request_but_logs_only_position(self):
        self.response([{'name': 'node', 'password': CANARY}])
        with self.assertLogs(self.logger, level='INFO') as captured:
            result = self.service.fetch_airport_item(self.source, 3)
        self.assertEqual(result, [{'name': 'node', 'password': CANARY, '_airport_name': self.alias}])
        self.assertEqual(self.http.call_args.args, (self.source['url'],))
        self.assertEqual([r.getMessage() for r in captured.records],
                         ['正在拉取机场来源 #4 的节点', '机场来源 #4 已拉取 1 个节点'])
        self.assert_safe(captured)

    def test_empty_subscription_logs_only_position_and_keeps_empty_result(self):
        self.response([])
        with self.assertLogs(self.logger, level='INFO') as captured:
            self.assertEqual(self.service.fetch_airport_item(self.source, 1), [])
        self.assertEqual([r.getMessage() for r in captured.records],
                         ['正在拉取机场来源 #2 的节点', '机场来源 #2 订阅内容解析成功，但未找到代理节点'])
        self.assert_safe(captured)

    def test_failure_does_not_log_name_url_exception_message_or_traceback(self):
        class SensitiveError(RuntimeError):
            def __str__(self):
                raise AssertionError('must not stringify exception')
        self.http.side_effect = SensitiveError(CANARY)
        # An already normalized source retains its own position, as before.
        with self.assertLogs(self.logger, level='INFO') as captured:
            self.assertEqual(self.service.fetch_airport_item(AirportSource(7, self.source), 0), [])
        self.assertEqual([r.getMessage() for r in captured.records],
                         ['正在拉取机场来源 #8 的节点', '机场来源 #8 拉取失败（SensitiveError）'])
        self.assert_safe(captured)

    def test_legacy_names_and_control_signals_still_propagate_without_sensitive_logs(self):
        for source, name in [('https://source.example/sub', 'source.example'),
                             ({'name': '中文别名', 'url': 'https://source.example/sub'}, '中文别名')]:
            self.response([{'name': 'node'}])
            with self.subTest(source=source), self.assertLogs(self.logger, level='INFO') as captured:
                result = self.service.fetch_airport_item(source)
            self.assertEqual(result[0]['_airport_name'], name)
            self.assert_safe(captured)
        for kind in [KeyboardInterrupt, SystemExit]:
            self.http.side_effect = kind(CANARY)
            with self.subTest(kind=kind.__name__), self.assertLogs(self.logger, level='INFO') as captured:
                with self.assertRaises(kind):
                    self.service.fetch_airport_item(self.source)
            self.assert_safe(captured)

    def test_nonstandard_internal_index_cannot_become_a_log_value(self):
        # Python callers can construct AirportSource directly; do not stringify
        # arbitrary index values just to improve a diagnostic.
        self.response([{'name': 'node'}])
        with self.assertLogs(self.logger, level='INFO') as captured:
            result = self.service.fetch_airport_item(AirportSource(CANARY, self.source))
        self.assertEqual(result[0]['_airport_name'], self.alias)
        self.assertEqual(captured.records[0].getMessage(), '正在拉取机场来源 #0 的节点')
        self.assert_safe(captured)
