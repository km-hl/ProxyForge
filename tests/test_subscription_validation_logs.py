"""订阅校验警告只记数量；真实字段错误及原 HTTP 422 详情保留。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import yaml

from test_api_integration import load_isolated_application, TEST_SUBSCRIPTION_TOKEN


CANARY = 'fixture-sensitive-canary'


def node():
    return {'name': 'Fixture', 'type': 'ss', 'server': 'node.example',
            'port': 8388, 'cipher': 'aes-256-gcm', 'password': 'fixture'}


class SubscriptionValidationLogsTest(unittest.TestCase):
    def setUp(self):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        self.app = load_isolated_application(Path(runtime.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.nodes = Path(self.app.CUSTOM_NODES_PATH)
        self.nodes.write_text('[]\n', encoding='utf-8')
        Path(self.app.AIRPORTS_PATH).write_text('[]\n', encoding='utf-8')
        Path(self.app.TEMPLATE_PATH).write_text('proxy-groups: []\nrules: []\n', encoding='utf-8')
        self.enterContext(patch.object(self.app, 'subscription_airports', return_value=([], [])))

    def assert_private_warning(self, format, expected_body=None):
        before = self.nodes.read_bytes()
        with self.assertLogs(self.app.logger, level='WARNING') as captured:
            result = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN, 'format': format})
        self.assertEqual(result.status_code, 422)
        self.assertTrue(result.headers['content-type'].startswith('text/plain'))
        self.assertIn(CANARY, result.text)  # 已授权订阅请求保留原校验详情。
        if expected_body is not None:
            self.assertEqual(result.text, expected_body)
        count = result.text.count('\n- ')
        self.assertGreater(count, 0)
        self.assertEqual([r.getMessage() for r in captured.records], [f'订阅配置校验失败（{count} 项错误）'])
        self.assertEqual(captured.records[0].levelname, 'WARNING')
        self.assertIsNone(captured.records[0].exc_info)
        self.assertIsNone(captured.records[0].exc_text)
        self.assertIsNone(captured.records[0].stack_info)
        self.assertEqual(self.nodes.read_bytes(), before)

    def test_real_manual_node_field_does_not_leak_into_warning(self):
        invalid = {**node(), 'port': 'https://private.example/sub?token=' + CANARY}
        self.nodes.write_text(yaml.safe_dump([invalid]), encoding='utf-8')
        for format in ['clash', 'egern']:
            with self.subTest(format=format):
                self.assert_private_warning(format)

    def test_real_airport_validation_does_not_leak_into_warning(self):
        invalid = {**node(), 'port': CANARY}
        with patch.object(self.app, 'subscription_airports', return_value=([], [invalid])):
            for format in ['clash', 'egern']:
                with self.subTest(format=format):
                    self.assert_private_warning(format)

    def test_multiple_and_provider_validation_errors_keep_original_response(self):
        errors = [CANARY + ' private URL', CANARY + ' private-key field', CANARY + ' node credential']
        body = '订阅配置校验失败:\n- ' + '\n- '.join(errors)
        for format in ['clash', 'egern']:
            with self.subTest(format=format), patch.object(self.app, 'build_subscription_config',
                    side_effect=self.app.ConfigValidationError(errors)):
                self.assert_private_warning(format, body)
        with patch.object(self.app, 'resolve_provider_nodes', side_effect=self.app.ConfigValidationError(errors)):
            self.assert_private_warning('egern', body)

    def test_successful_exports_do_not_emit_validation_warnings(self):
        self.nodes.write_text(yaml.safe_dump([node()]), encoding='utf-8')
        for format in ['clash', 'egern']:
            with self.subTest(format=format), patch.object(self.app.logger, 'warning') as warning:
                result = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN, 'format': format})
                self.assertEqual(result.status_code, 200, result.text)
                warning.assert_not_called()
