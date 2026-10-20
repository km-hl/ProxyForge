"""YAML/JSON 文件数据错误回退，非预期读取故障不伪装成空配置。"""
import builtins
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from proxyforge.airports import service as service_module
from test_api_integration import load_isolated_application, TEST_SUBSCRIPTION_TOKEN


class ConfigReaderErrorsTest(unittest.TestCase):
    def setUp(self):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        self.app = load_isolated_application(Path(runtime.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.readers = [
            (self.app.load_airports, Path(self.app.AIRPORTS_PATH), self.app, '读取机场列表失败'),
            (self.app.load_manual_nodes, Path(self.app.CUSTOM_NODES_PATH), self.app, '读取自建节点文件失败'),
            (self.app.airport_service.load_cache_from_file, self.app.airport_service.cache_path,
             service_module, '读取节点持久化缓存失败'),
        ]
        for _, path, _, _ in self.readers:
            path.write_text('[]\n', encoding='utf-8')
        self.info_path = self.app.airport_service.info_cache_path
        self.info_path.write_text('{}\n', encoding='utf-8')

    def test_real_yaml_scalar_errors_keep_empty_fallback_and_original_bytes(self):
        for reader, path, _, label in self.readers:
            for content, kind in [("!!int ''", 'IndexError'), ("!!float ''", 'IndexError'),
                                  ('!!bool maybe', 'KeyError'), ("!!timestamp ''", 'AttributeError'),
                                  ('[2026-99-99]', 'ValueError'),
                                  ('[' * 1100 + '0' + ']' * 1100, 'RecursionError')]:
                with self.subTest(reader=reader.__name__, kind=kind):
                    path.write_text(content, encoding='utf-8')
                    before = path.read_bytes()
                    with self.assertLogs(self.app.logger, level='ERROR') as captured:
                        self.assertEqual(reader(), [])
                    self.assertEqual([record.getMessage() for record in captured.records], [f'{label}（{kind}）'])
                    self.assertIsNone(captured.records[0].exc_info)
                    self.assertEqual(path.read_bytes(), before)

    def test_unexpected_io_failures_propagate_without_rewriting_or_fallback_logs(self):
        operations = [*self.readers, (self.app.airport_service.load_airport_info_cache,
                                     self.info_path, service_module, 'unused')]
        for reader, path, target, _ in operations:
            for kind in [RuntimeError, MemoryError, AssertionError, TypeError]:
                error = kind('fixture-sensitive-canary')
                before = path.read_bytes()
                with self.subTest(reader=reader.__name__, kind=kind.__name__), \
                        patch.object(target, 'open', create=True, side_effect=error), \
                        patch.object(self.app.logger, 'error') as error_log, \
                        patch.object(self.app.logger, 'warning') as warning_log:
                    with self.assertRaises(kind) as caught:
                        reader()
                    self.assertIs(caught.exception, error)
                    error_log.assert_not_called()
                    warning_log.assert_not_called()
                self.assertEqual(path.read_bytes(), before)

    def test_expected_io_errors_still_return_the_original_empty_shape(self):
        operations = [(*entry, []) for entry in self.readers]
        operations.append((self.app.airport_service.load_airport_info_cache, self.info_path,
                           service_module, '读取机场信息缓存失败', {}))
        for reader, path, target, label, empty in operations:
            before = path.read_bytes()
            with self.subTest(reader=reader.__name__), patch.object(
                    target, 'open', create=True, side_effect=PermissionError('fixture-sensitive-canary')):
                with self.assertLogs(self.app.logger, level='WARNING') as captured:
                    self.assertEqual(reader(), empty)
            self.assertEqual([r.getMessage() for r in captured.records], [f'{label}（PermissionError）'])
            self.assertIsNone(captured.records[0].exc_info)
            self.assertEqual(path.read_bytes(), before)

    def test_deep_json_cache_returns_empty_without_logging_data_or_rewriting(self):
        self.info_path.write_text('{"fixture-sensitive-canary":' * 1100 + '0' + '}' * 1100, encoding='utf-8')
        before = self.info_path.read_bytes()
        with self.assertLogs(self.app.logger, level='WARNING') as captured:
            self.assertEqual(self.app.airport_service.load_airport_info_cache(), {})
        self.assertIn([r.getMessage() for r in captured.records], [
            ['读取机场信息缓存失败（RecursionError）'], ['机场信息缓存包含无效条目，忽略损坏条目']])
        self.assertIsNone(captured.records[0].exc_info)
        self.assertEqual(self.info_path.read_bytes(), before)
        # JSON 的实际递归阈值随 Python 版本/平台不同，另固定触发解码器边界。
        with patch.object(service_module.json, 'load', side_effect=RecursionError('fixture-sensitive-canary')):
            with self.assertLogs(self.app.logger, level='WARNING') as captured:
                self.assertEqual(self.app.airport_service.load_airport_info_cache(), {})
        self.assertEqual([r.getMessage() for r in captured.records], ['读取机场信息缓存失败（RecursionError）'])
        self.assertEqual(self.info_path.read_bytes(), before)

    def test_subscription_unexpected_reader_failure_is_an_error_without_config_write(self):
        airports = Path(self.app.AIRPORTS_PATH)
        before = airports.read_bytes()

        def reader(path, *args, **kwargs):
            if Path(path) == airports:
                raise RuntimeError('fixture-sensitive-canary')
            return builtins.open(path, *args, **kwargs)

        for format in ['clash', 'egern']:
            with self.subTest(format=format), patch.object(self.app, 'open', create=True, side_effect=reader):
                with self.assertLogs(self.app.logger, level='ERROR') as captured:
                    result = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN, 'format': format})
            self.assertEqual(result.status_code, 500)
            self.assertEqual(result.text, '生成订阅时发生内部错误，请查看服务端日志。')
            self.assertEqual([r.getMessage() for r in captured.records], ['订阅生成失败（RuntimeError）'])
            self.assertIsNone(captured.records[0].exc_info)
            self.assertEqual(airports.read_bytes(), before)
