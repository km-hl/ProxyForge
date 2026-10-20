"""配置读取/迁移/引用清理的日志脱敏与实际订阅调用链回归。"""
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import yaml

from test_api_integration import load_isolated_application, TEST_SUBSCRIPTION_TOKEN


class ConfigErrorLogsTest(unittest.TestCase):
    def setUp(self):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        self.root = Path(runtime.name)
        self.app = load_isolated_application(self.root)
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.template = Path(self.app.TEMPLATE_PATH)
        self.airports = Path(self.app.AIRPORTS_PATH)
        self.nodes = Path(self.app.CUSTOM_NODES_PATH)
        self.template.write_text('proxy-groups: []\nrules: []\n', encoding='utf-8')
        self.airports.write_text('[]\n', encoding='utf-8')
        self.nodes.write_text('[]\n', encoding='utf-8')
        self.network = Mock(side_effect=AssertionError('unexpected network request'))
        self.enterContext(patch.object(self.app.airport_service, 'http_get', self.network))

    def snapshot(self):
        return [p.read_bytes() if p.exists() else None
                for p in [self.template, self.airports, self.nodes]]

    def assert_safe_records(self, captured, messages):
        self.assertEqual([r.getMessage() for r in captured.records], messages)
        for record in captured.records:
            self.assertIsNone(record.exc_info)
            self.assertIsNone(record.exc_text)
            self.assertIsNone(record.stack_info)

    def test_real_yaml_and_utf8_errors_keep_empty_reader_fallback_and_bytes(self):
        for path, reader, label in [(self.airports, self.app.load_airports, '读取机场列表失败'),
                                    (self.nodes, self.app.load_manual_nodes, '读取自建节点文件失败')]:
            for data, kind in [(b'!<tag:fixture-sensitive-canary> value\n', 'ConstructorError'),
                               (b'- password: [fixture-sensitive-canary', 'ParserError'),
                               (b'\x00fixture-sensitive-canary', 'ReaderError'),
                               (b'\xfffixture-sensitive-canary', 'UnicodeDecodeError')]:
                with self.subTest(reader=reader.__name__, kind=kind):
                    path.write_bytes(data)
                    before = self.snapshot()
                    with self.assertLogs(self.app.logger, level='ERROR') as captured:
                        self.assertEqual(reader(), [])
                    self.assert_safe_records(captured, [f'{label}（{kind}）'])
                    self.assertEqual(self.snapshot(), before)
        self.network.assert_not_called()

    def test_reader_io_errors_preserve_current_fallback(self):
        for reader, label in [(self.app.load_airports, '读取机场列表失败'),
                              (self.app.load_manual_nodes, '读取自建节点文件失败')]:
            for kind in [PermissionError]:
                with self.subTest(reader=reader.__name__, kind=kind.__name__):
                    before = self.snapshot()
                    with patch.object(self.app, 'open', create=True,
                                      side_effect=kind('/private/fixture-sensitive-canary')):
                        with self.assertLogs(self.app.logger, level='ERROR') as captured:
                            self.assertEqual(reader(), [])
                    self.assert_safe_records(captured, [f'{label}（{kind.__name__}）'])
                    self.assertEqual(self.snapshot(), before)

    def test_template_cleanup_preserves_empty_result_and_invalid_file(self):
        self.template.write_text('!<tag:fixture-sensitive-canary> value\n', encoding='utf-8')
        before = self.snapshot()
        with self.assertLogs(self.app.logger, level='ERROR') as captured:
            result = self.app.cleanup_runtime_template_references()
        self.assertEqual(result, {'proxyReferences': [], 'providerReferences': [], 'total': 0})
        self.assert_safe_records(captured, ['无法清理模板引用，YAML 格式错误（ConstructorError）'])
        self.assertEqual(self.snapshot(), before)

    def migration_cases(self):
        return [
            (self.app.initialize_template_storage, self.template, 'LEGACY_TEMPLATE_PATH',
             '初始化持久化模板失败'),
            (self.app.initialize_custom_nodes_storage, self.nodes, 'LEGACY_CUSTOM_NODES_PATH',
             '迁移自建节点文件失败'),
        ]

    def test_migration_copy_failures_keep_sources_and_no_destination(self):
        for initialize, destination, source_attr, label in self.migration_cases():
            with self.subTest(initialize=initialize.__name__):
                destination.unlink()
                source = self.root / (source_attr + '.yaml')
                source.write_text('fixture-sensitive-canary\n', encoding='utf-8')
                with patch.object(self.app, source_attr, str(source)), patch.object(
                        self.app.shutil, 'copyfile', side_effect=PermissionError('fixture-sensitive-canary')):
                    with self.assertLogs(self.app.logger, level='ERROR') as captured:
                        self.assertEqual(initialize(), '')
                self.assert_safe_records(captured, [f'{label}（PermissionError）'])
                self.assertFalse(destination.exists())
                self.assertEqual(source.read_text(encoding='utf-8'), 'fixture-sensitive-canary\n')

    def test_all_five_error_handlers_do_not_stringify_exceptions(self):
        stringify = Mock(side_effect=AssertionError('must not stringify'))

        class UnprintableIOError(OSError):
            def __str__(self):
                return stringify()

        class UnprintableYamlError(yaml.YAMLError):
            def __str__(self):
                return stringify()

        for reader in [self.app.load_airports, self.app.load_manual_nodes]:
            with patch.object(self.app, 'open', create=True, side_effect=UnprintableIOError()):
                with self.assertLogs(self.app.logger, level='ERROR'):
                    self.assertEqual(reader(), [])
        with patch.object(self.app.yaml, 'safe_load', side_effect=UnprintableYamlError()):
            with self.assertLogs(self.app.logger, level='ERROR'):
                self.assertEqual(self.app.cleanup_runtime_template_references()['total'], 0)
        for initialize, destination, source_attr, _ in self.migration_cases():
            destination.unlink()
            source = self.root / (source_attr + '.yaml')
            source.write_text('fixture\n', encoding='utf-8')
            with patch.object(self.app, source_attr, str(source)), patch.object(
                    self.app.shutil, 'copyfile', side_effect=UnprintableIOError()):
                with self.assertLogs(self.app.logger, level='ERROR'):
                    self.assertEqual(initialize(), '')
        stringify.assert_not_called()

    def test_control_signals_propagate_from_read_cleanup_and_migration(self):
        for kind in [KeyboardInterrupt, SystemExit, asyncio.CancelledError, GeneratorExit]:
            for reader in [self.app.load_airports, self.app.load_manual_nodes]:
                signal = kind()
                with self.subTest(kind=kind.__name__, reader=reader.__name__), patch.object(
                        self.app, 'open', create=True, side_effect=signal), patch.object(
                        self.app.logger, 'error') as error_log:
                    with self.assertRaises(kind) as caught:
                        reader()
                    self.assertIs(caught.exception, signal)
                    error_log.assert_not_called()
            with patch.object(self.app.yaml, 'safe_load', side_effect=kind()):
                with self.assertRaises(kind):
                    self.app.cleanup_runtime_template_references()
            for initialize, destination, source_attr, _ in self.migration_cases():
                if destination.exists():
                    destination.unlink()
                source = self.root / (source_attr + '.yaml')
                source.write_text('fixture\n', encoding='utf-8')
                with patch.object(self.app, source_attr, str(source)), patch.object(
                        self.app.shutil, 'copyfile', side_effect=kind()):
                    with self.assertRaises(kind):
                        initialize()
                # 后续用例仍需要这份临时文件，避免绕过待验证的读取入口。
                destination.write_text('proxy-groups: []\nrules: []\n' if destination == self.template
                                       else '[]\n', encoding='utf-8')

    def test_actual_subscription_pipeline_has_no_raw_template_error_log(self):
        self.template.write_text('!<tag:fixture-sensitive-canary> value\n', encoding='utf-8')
        before = self.snapshot()
        for format in ['clash', 'egern']:
            with self.subTest(format=format):
                with self.assertLogs(self.app.logger, level='ERROR') as captured:
                    result = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN,
                                                            'format': format})
                self.assertEqual(result.status_code, 500)
                self.assertEqual(result.text, '生成订阅时发生内部错误，请查看服务端日志。')
                self.assert_safe_records(captured, [
                    '无法清理模板引用，YAML 格式错误（ConstructorError）',
                    '订阅生成失败（ConstructorError）',
                ])
                self.assertEqual(self.snapshot(), before)
        self.network.assert_not_called()

    def test_actual_subscription_pipeline_preserves_broken_source_fallback(self):
        self.airports.write_text('!<tag:fixture-sensitive-canary> value\n', encoding='utf-8')
        self.nodes.write_text('!<tag:fixture-sensitive-canary> value\n', encoding='utf-8')
        before = self.snapshot()
        for format in ['clash', 'egern']:
            with self.subTest(format=format):
                with self.assertLogs(self.app.logger, level='ERROR') as captured:
                    result = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN,
                                                            'format': format})
                self.assertEqual(result.status_code, 200, result.text)
                self.assertIsInstance(yaml.safe_load(result.text), dict)
                messages = [record.getMessage() for record in captured.records]
                self.assertIn('读取机场列表失败（ConstructorError）', messages)
                self.assertIn('读取自建节点文件失败（ConstructorError）', messages)
                self.assertTrue(set(messages) <= {'读取机场列表失败（ConstructorError）',
                                                  '读取自建节点文件失败（ConstructorError）'})
                for record in captured.records:
                    self.assertIsNone(record.exc_info)
                self.assertEqual(self.snapshot(), before)
        self.network.assert_not_called()

    def test_successful_readers_preserve_legacy_values_and_internal_node_label(self):
        sources = ['https://source.example/sub', {'url': ' https://other.example/sub ',
                                                'unknown': {'fixture': [1, 2]}}]
        nodes = [{'name': 'Fixture', 'password': 'fixture-sensitive-canary', 'unknown': {'a': 1}}]
        self.airports.write_text(yaml.safe_dump(sources), encoding='utf-8')
        self.nodes.write_text(yaml.safe_dump(nodes), encoding='utf-8')
        before = self.snapshot()
        with patch.object(self.app.logger, 'error') as error_log:
            self.assertEqual(self.app.load_airports(), sources)
            self.assertEqual(self.app.load_manual_nodes(),
                             [{**nodes[0], '_airport_name': self.app.CUSTOM_NODES_SOURCE}])
            error_log.assert_not_called()
        self.assertEqual(self.snapshot(), before)
