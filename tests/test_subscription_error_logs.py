"""订阅通用错误仅记录类型，保留响应、控制信号和正常导出契约。"""
import asyncio
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.parse

from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
import yaml

from test_api_integration import load_isolated_application, TEST_SUBSCRIPTION_TOKEN


class SubscriptionErrorLogsTest(unittest.TestCase):
    def setUp(self):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        self.app = load_isolated_application(Path(runtime.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.stack = self.enterContext(ExitStack())
        fixtures = {
            'cleanup_runtime_template_references': {},
            'subscription_airports': ([], []),
            'load_custom_nodes': [{'name': 'Fixture', 'type': 'ss', 'server': 'node.example',
                                   'port': 8388, 'cipher': 'aes-256-gcm', 'password': 'fixture'}],
            'load_template_content': 'proxy-groups: []\nrules: []\n',
            'managed_node_names': [],
            'resolve_provider_nodes': {},
        }
        for name, value in fixtures.items():
            self.stack.enter_context(patch.object(self.app, name, return_value=value))
        self.paths = [Path(getattr(self.app, name)) for name in
                      ['TEMPLATE_PATH', 'CUSTOM_NODES_PATH', 'AIRPORTS_PATH']]
        self.before = self.snapshot()
        self.addCleanup(self.assert_storage_unchanged)

    def snapshot(self):
        return [path.read_bytes() if path.exists() else None for path in self.paths]

    def assert_storage_unchanged(self):
        self.assertEqual(self.snapshot(), self.before)

    def request(self, format='clash', **params):
        return self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN,
                                              'format': format, **params})

    def assert_safe_failure(self, format, error_type):
        with self.assertLogs(self.app.logger, level='ERROR') as captured:
            result = self.request(format)
        self.assertEqual(result.status_code, 500)
        self.assertEqual(result.text, '生成订阅时发生内部错误，请查看服务端日志。')
        self.assertTrue(result.headers['content-type'].startswith('text/plain'))
        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertEqual(record.getMessage(), f'订阅生成失败（{error_type}）')
        self.assertIsNone(record.exc_info)
        self.assertIsNone(record.exc_text)
        self.assertIsNone(record.stack_info)

    def test_builder_exception_messages_and_tracebacks_are_not_logged(self):
        for format in ['clash', 'egern']:
            with self.subTest(format=format), patch.object(
                    self.app, 'build_subscription_config',
                    side_effect=RuntimeError('fixture-sensitive-canary https://private.example/token')):
                self.assert_safe_failure(format, 'RuntimeError')

    def test_real_yaml_parser_errors_do_not_log_template_tags_or_snippets(self):
        for content, error_type in [('!<tag:fixture-sensitive-canary> value\n', 'ConstructorError'),
                                    ('proxies: [fixture-sensitive-canary', 'ParserError')]:
            for format in ['clash', 'egern']:
                with self.subTest(format=format, error_type=error_type), patch.object(
                        self.app, 'load_template_content', return_value=content):
                    self.assert_safe_failure(format, error_type)

    def test_serialization_failure_does_not_log_private_paths(self):
        for format in ['clash', 'egern']:
            with self.subTest(format=format), patch.object(
                    self.app.yaml, 'safe_dump', side_effect=OSError('/private/fixture-sensitive-canary')):
                self.assert_safe_failure(format, 'OSError')

    def test_egern_conversion_and_provider_failure_keep_separate_boundaries(self):
        with patch.object(self.app, 'build_egern_config',
                          side_effect=RuntimeError('fixture-sensitive-canary')):
            self.assert_safe_failure('egern', 'RuntimeError')
        with patch.object(self.app, 'resolve_provider_nodes',
                          side_effect=OSError('fixture-sensitive-canary')), patch.object(
                          self.app.logger, 'error') as error_log:
            with self.assertLogs(self.app.logger, level='WARNING') as captured:
                result = self.request('egern')
            self.assertEqual(result.status_code, 502)
            self.assertEqual(result.json(), {'detail': 'Egern 节点来源暂时不可用，请稍后重试'})
            self.assertEqual([record.getMessage() for record in captured.records],
                             ['Egern provider 请求失败（OSError）'])
            error_log.assert_not_called()

    def test_exception_string_is_never_evaluated_by_generic_handler(self):
        stringify = Mock(side_effect=AssertionError('must not stringify'))

        class UnprintableError(Exception):
            def __str__(self):
                return stringify()

        for format in ['clash', 'egern']:
            with self.subTest(format=format), patch.object(
                    self.app, 'build_subscription_config', side_effect=UnprintableError()):
                self.assert_safe_failure(format, 'UnprintableError')
        stringify.assert_not_called()

    def test_validation_http_and_auth_errors_preserve_original_responses(self):
        with patch.object(self.app.logger, 'error') as error_log:
            for format in ['clash', 'egern']:
                with self.subTest(format=format), patch.object(
                        self.app, 'build_subscription_config',
                        side_effect=self.app.ConfigValidationError(['fixture-invalid-config'])):
                    result = self.request(format)
                    self.assertEqual(result.status_code, 422)
                    self.assertEqual(result.text, '订阅配置校验失败:\n- fixture-invalid-config')
                with patch.object(self.app, 'build_subscription_config',
                                  side_effect=HTTPException(503, detail={'code': 'storage_unavailable'})):
                    result = self.request(format)
                    self.assertEqual(result.status_code, 503)
                    self.assertEqual(result.json(), {'detail': {'code': 'storage_unavailable'}})
            with patch.object(self.app, 'build_subscription_config') as build:
                result = self.request(token='invalid-token')
                self.assertEqual(result.status_code, 401)
                self.assertEqual(result.json(), {'detail': 'Unauthorized'})
                result = self.request(format='unsupported')
                self.assertEqual(result.status_code, 400)
                self.assertEqual(result.json(), {'detail': '不支持的订阅格式'})
                build.assert_not_called()
            error_log.assert_not_called()

    def test_cancellation_and_exit_signals_propagate_without_error_logs(self):
        request = Request({'type': 'http', 'method': 'GET', 'scheme': 'https',
                           'server': ('testserver', 443), 'path': '/sub', 'root_path': '',
                           'query_string': b'', 'headers': []})
        for format in ['clash', 'egern']:
            for error_type in [KeyboardInterrupt, SystemExit, asyncio.CancelledError, GeneratorExit]:
                signal = error_type()
                with self.subTest(format=format, signal=error_type.__name__), patch.object(
                        self.app, 'build_subscription_config', side_effect=signal), patch.object(
                        self.app.logger, 'error') as error_log:
                    with self.assertRaises(error_type) as caught:
                        self.app.get_subscription(request, TEST_SUBSCRIPTION_TOKEN, 'fixture', format)
                    self.assertIs(caught.exception, signal)
                    error_log.assert_not_called()

    def test_both_success_formats_keep_unicode_headers_and_yaml(self):
        name = '测试订阅 / Fixture'
        for format in ['clash', 'egern']:
            with self.subTest(format=format), patch.object(self.app.logger, 'error') as error_log:
                result = self.request(format, name=name)
                self.assertEqual(result.status_code, 200, result.text)
                self.assertIsInstance(yaml.safe_load(result.text), dict)
                self.assertEqual(result.headers['profile-title'], urllib.parse.quote(name))
                self.assertEqual(result.headers['content-disposition'],
                                 f"attachment; filename*=UTF-8''{urllib.parse.quote(name)}")
                self.assertEqual(result.headers['cache-control'], 'no-store')
                self.assertEqual(result.headers['proxyforge-skipped-nodes'], '0')
                error_log.assert_not_called()
