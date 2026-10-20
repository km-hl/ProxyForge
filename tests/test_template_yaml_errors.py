"""模板写入只把真实 YAML 数据错误归为 400，内部故障使用安全 500。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN


TARGET = 'proxy-groups: []\nrules: []\n# fixture-target\n'
CANARY = 'fixture-sensitive-canary'
INTERNAL_DETAIL = '模板校验时发生内部错误，请查看服务端日志。'


class TemplateYamlErrorsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = load_isolated_application(self.root)
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        Path(self.app.CUSTOM_NODES_PATH).write_text('[]\n', encoding='utf-8')
        Path(self.app.AIRPORTS_PATH).write_text('[]\n', encoding='utf-8')
        self.app.validate_saved_template(TARGET, [], [])
        store = self.app.template_store()
        store.commit({'template.yaml': TARGET}, source='fixture')
        store.commit({'template.yaml': TARGET + '# current\n'}, source='fixture')
        self.snapshot = store.snapshot()
        self.entry_id = next(entry['id'] for entry in store.list_history()
                             if store.history_entry(entry['id'])['content'] == TARGET)

    def files(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob('*') if path.is_file()}

    def failing_yaml(self, error):
        original = self.app.yaml.safe_load
        def load(value):
            if isinstance(value, str) and value == TARGET:
                raise error
            return original(value)
        return patch.object(self.app.yaml, 'safe_load', side_effect=load)

    def test_real_yaml_errors_keep_400_original_detail_and_files(self):
        before = self.files()
        for content in ['[fixture', '!<tag:fixture> value', "!!int ''", "!!float ''",
                        '!!bool maybe', "!!timestamp ''", '[2026-99-99]',
                        '[' * 1100 + '0' + ']' * 1100]:
            with self.subTest(prefix=content[:20]), patch.object(self.app.logger, 'error') as log:
                with self.assertRaises(HTTPException) as caught:
                    self.app.validate_saved_template(content, [], [])
                self.assertEqual(caught.exception.status_code, 400)
                self.assertTrue(caught.exception.detail.startswith('YAML 格式错误: '))
                log.assert_not_called()
            self.assertEqual(self.files(), before)

    def test_unexpected_yaml_fault_has_fixed_500_type_only_log_and_no_write(self):
        before = self.files()
        for kind in [RuntimeError, MemoryError, AssertionError, TypeError]:
            with self.subTest(kind=kind.__name__), self.failing_yaml(kind(CANARY)):
                with self.assertLogs(self.app.logger, level='ERROR') as captured:
                    with self.assertRaises(HTTPException) as caught:
                        self.app.validate_saved_template(TARGET, [], [])
            self.assertEqual(caught.exception.status_code, 500)
            self.assertEqual(caught.exception.detail, INTERNAL_DETAIL)
            self.assertEqual([r.getMessage() for r in captured.records], [f'模板 YAML 校验失败（{kind.__name__}）'])
            self.assertIsNone(captured.records[0].exc_info)
            self.assertNotIn(CANARY, repr(captured.records[0].args))
            self.assertEqual(self.files(), before)

    def test_save_import_and_restore_share_the_safe_failure_and_keep_revision(self):
        revision = self.snapshot['revision']
        operations = [('/api/template', {'content': TARGET, 'expected_revision': revision}),
                      ('/api/template/import', {'content': TARGET, 'expected_revision': revision,
                                                'nodes': [], 'urls': []}),
                      ('/api/template/history/' + self.entry_id + '/restore', {'expected_revision': revision})]
        before = self.files()
        for path, body in operations:
            with self.subTest(path=path), self.failing_yaml(RuntimeError(CANARY)):
                with self.assertLogs(self.app.logger, level='ERROR') as captured:
                    result = self.client.post(path, headers=self.headers, json=body)
            self.assertEqual(result.status_code, 500, result.text)
            self.assertEqual(result.json(), {'detail': INTERNAL_DETAIL})
            self.assertEqual([r.getMessage() for r in captured.records], ['模板 YAML 校验失败（RuntimeError）'])
            self.assertIsNone(captured.records[0].exc_info)
            self.assertEqual(self.files(), before)
            self.assertEqual(self.app.template_store().snapshot(), self.snapshot)

    def test_unstringifiable_fault_and_control_signals_are_not_mislabeled_as_yaml(self):
        class Unstringifiable(RuntimeError):
            def __str__(self):
                raise AssertionError('must not stringify')
        with self.failing_yaml(Unstringifiable(CANARY)), patch.object(self.app.logger, 'error') as log:
            with self.assertRaises(HTTPException) as caught:
                self.app.validate_saved_template(TARGET, [], [])
            self.assertEqual(caught.exception.status_code, 500)
            log.assert_called_once_with('模板 YAML 校验失败（%s）', 'Unstringifiable')
        for kind in [KeyboardInterrupt, SystemExit]:
            error = kind(CANARY)
            with self.subTest(kind=kind.__name__), self.failing_yaml(error), \
                    patch.object(self.app.logger, 'error') as log:
                with self.assertRaises(kind) as caught:
                    self.app.validate_saved_template(TARGET, [], [])
                self.assertIs(caught.exception, error)
                log.assert_not_called()

    def test_success_size_and_semantic_validation_keep_the_original_contract(self):
        before = self.files()
        with patch.object(self.app.logger, 'error') as log:
            self.assertIsNone(self.app.validate_saved_template(TARGET, [], []))
            for content, expected in [('x' * (1024 * 1024 + 1), 413), ('proxy-groups: invalid\nrules: []', 400)]:
                with self.subTest(expected=expected), self.assertRaises(HTTPException) as caught:
                    self.app.validate_saved_template(content, [], [])
                self.assertEqual(caught.exception.status_code, expected)
            log.assert_not_called()
        self.assertEqual(self.files(), before)
