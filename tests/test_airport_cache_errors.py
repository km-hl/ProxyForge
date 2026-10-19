"""节点缓存损坏/读取失败的日志脱敏与异常边界，全部使用临时合成数据。"""
import asyncio
from contextlib import contextmanager
import logging
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import yaml

from proxyforge.airports.service import AirportService


class AirportCacheErrorsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'airport_cache.yaml'
        self.logger = logging.getLogger(__name__)
        lock = threading.RLock()
        self.service = AirportService(
            sources_reader=Mock(return_value=[]), cache_path=self.path,
            info_cache_path=self.root / 'info.json', http_get=Mock(),
            clock=time.time, monotonic=time.monotonic, configuration_lock=lambda: lock,
            logger=self.logger,
        )

    def assert_safe_failure(self, expected_type):
        before = self.path.read_bytes()
        with self.assertLogs(self.logger, level='ERROR') as logs:
            self.assertEqual(self.service.load_cache_from_file(), [])
        self.assertEqual(len(logs.records), 1)
        record = logs.records[0]
        self.assertEqual(record.getMessage(), '读取节点持久化缓存失败（' + expected_type + '）')
        self.assertIsNone(record.exc_info)
        self.assertIsNone(record.stack_info)
        self.assertEqual(self.path.read_bytes(), before)
        self.service.http_get.assert_not_called()

    def test_unknown_yaml_tag_is_not_echoed_into_error_logs(self):
        # PyYAML 的未知 tag 异常会回显 tag 本身，即使输入是文件流。
        self.path.write_text('!<tag:fixture-sensitive-canary> value\n', encoding='utf-8')
        self.assert_safe_failure('ConstructorError')

    def test_malformed_yaml_and_invalid_utf8_still_return_empty_without_rewriting(self):
        for data, error in [(b'- password: [fixture-sensitive-canary', 'ParserError'),
                            (b'\x00fixture-sensitive-canary', 'ReaderError'),
                            (b'\xfffixture-sensitive-canary', 'UnicodeDecodeError')]:
            with self.subTest(error=error):
                self.path.write_bytes(data)
                self.assert_safe_failure(error)

    def test_filesystem_error_does_not_log_private_path_or_exception_message(self):
        self.path.write_text('[]\n', encoding='utf-8')
        with patch('builtins.open', side_effect=PermissionError('fixture-sensitive-canary/private-path')):
            with self.assertLogs(self.logger, level='ERROR') as logs:
                self.assertEqual(self.service.load_cache_from_file(), [])
        self.assertEqual(logs.records[0].getMessage(), '读取节点持久化缓存失败（PermissionError）')
        self.assertIsNone(logs.records[0].exc_info)
        self.assertEqual(self.path.read_text(encoding='utf-8'), '[]\n')

    def test_invalid_yaml_scalar_and_excessive_nesting_keep_corrupt_cache_fallback(self):
        # SafeLoader 的非法日期/递归上限错误并非 YAMLError，仍属于输入失败。
        for text, error in [('[2026-99-99]', 'ValueError'),
                            ('[' * 1100 + '0' + ']' * 1100, 'RecursionError')]:
            with self.subTest(error=error):
                self.path.write_text(text, encoding='utf-8')
                self.assert_safe_failure(error)

    def test_unexpected_programming_error_is_not_treated_as_corrupt_cache(self):
        self.path.write_text('[]\n', encoding='utf-8')
        failure = RuntimeError('fixture programming error')
        with patch('proxyforge.airports.service.yaml.safe_load', side_effect=failure), \
                patch.object(self.logger, 'error') as log:
            with self.assertRaises(RuntimeError) as raised:
                self.service.load_cache_from_file()
        self.assertIs(raised.exception, failure)
        log.assert_not_called()

    def test_process_and_task_cancellation_are_not_swallowed_or_logged(self):
        self.path.write_text('[]\n', encoding='utf-8')
        for failure in [KeyboardInterrupt(), SystemExit(4), asyncio.CancelledError()]:
            with self.subTest(error=type(failure).__name__), \
                    patch('proxyforge.airports.service.yaml.safe_load', side_effect=failure), \
                    patch.object(self.logger, 'error') as log:
                with self.assertRaises(type(failure)) as raised:
                    self.service.load_cache_from_file()
                self.assertIs(raised.exception, failure)
                log.assert_not_called()

    def test_missing_nonlist_and_valid_legacy_cache_keep_readonly_behavior(self):
        with patch.object(self.logger, 'error') as log:
            self.assertEqual(self.service.load_cache_from_file(), [])
            self.assertFalse(self.path.exists())
            for value in [None, {'proxies': []}, [{'name': '中文', '_airport_name': 'A',
                                                   'extension': {'keep': True}, 'password': 'fixture'}]]:
                content = yaml.safe_dump(value, allow_unicode=True)
                self.path.write_text(content, encoding='utf-8')
                self.assertEqual(self.service.load_cache_from_file(), value if isinstance(value, list) else [])
                self.assertEqual(self.path.read_text(encoding='utf-8'), content)
            log.assert_not_called()
        self.service.http_get.assert_not_called()

    def test_configuration_recovery_error_still_reaches_storage_adapter(self):
        @contextmanager
        def unavailable():
            raise OSError('fixture recovery error')
            yield

        self.service.configuration_lock = unavailable
        with patch.object(self.logger, 'error') as log, self.assertRaises(OSError):
            self.service.load_cache_from_file()
        log.assert_not_called()

    def test_corrupt_cache_cannot_fill_a_missing_airport_or_replace_fresh_nodes(self):
        self.path.write_text('!<tag:fixture-sensitive-canary> value\n', encoding='utf-8')
        fresh = [{'name': 'fresh', '_airport_name': 'A'}]
        sources = [{'name': 'A', 'url': 'https://a.example/sub'},
                   {'name': 'B', 'url': 'https://b.example/sub'}]
        with self.assertLogs(self.logger, level='ERROR') as logs:
            merged, missing = self.service.merge_airport_proxies_with_cache(fresh, sources)
        self.assertEqual(merged, fresh)
        self.assertEqual(missing, ['B'])
        self.assertNotIn('fixture-sensitive-canary', '\n'.join(logs.output))
        self.service.http_get.assert_not_called()
