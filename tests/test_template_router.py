"""模板 Router 的依赖隔离、鉴权、版本冲突与三文件事务恢复。"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
import yaml

from proxyforge.config import template_store
from proxyforge.templates import api as template_api
from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN


def node(name='Manual'):
    return {'name': name, 'type': 'ss', 'server': 'node.example', 'port': 8388,
            'cipher': 'aes-256-gcm', 'password': 'fixture'}


class TemplateRouterAssemblyTest(unittest.TestCase):
    def assemble(self, label):
        def verify(x_manager: str = Header(None)):
            if x_manager != label:
                raise HTTPException(status_code=401, detail='unauthorized')

        store = Mock()
        store.snapshot.return_value = {'content': label, 'revision': 'a' * 64}
        dependencies = dict(
            verify_management=verify, configuration_lock=Mock(side_effect=nullcontext),
            template_store=Mock(return_value=store), revision_required=Mock(),
            template_writer=Mock(return_value={'content': label, 'revision': 'b' * 64}),
            manual_nodes_reader=Mock(return_value=[]), nodes_reader=Mock(return_value=[node(label)]),
            managed_nodes_reader=Mock(return_value=[]), managed_names_reader=Mock(return_value=[]),
            sources_reader=Mock(return_value=[]), manual_input=Mock(side_effect=lambda nodes: nodes),
            validate_saved=Mock(), validate_sources=Mock(), airport_service=Mock(),
        )
        return template_api.create_template_router(**dependencies), dependencies

    def test_assembly_does_not_read_storage_or_create_services(self):
        api, dependencies = self.assemble('unused')
        self.assertEqual(len(api.router.routes), 7)
        for name, callback in dependencies.items():
            if name != 'verify_management':
                self.assertEqual(callback.mock_calls, [], name)

    def test_two_apps_keep_their_own_auth_storage_and_validation_callbacks(self):
        for label in ['first', 'second']:
            api, dependencies = self.assemble(label)
            app = FastAPI()
            app.include_router(api.router)
            with TestClient(app) as client:
                headers = {'X-Manager': label}
                self.assertEqual(client.get('/api/template', headers=headers).json()['content'], label)
                result = client.post('/api/template', headers=headers,
                                     json={'content': 'rules: []', 'expected_revision': 'a' * 64})
                self.assertEqual(result.status_code, 200, result.text)
                self.assertEqual(result.json()['content'], label)
                other = 'second' if label == 'first' else 'first'
                self.assertEqual(client.get('/api/template', headers={'X-Manager': other}).status_code, 401)
            dependencies['validate_saved'].assert_called_once_with('rules: []', [node(label)], [])
            dependencies['revision_required'].assert_called_once_with('a' * 64)
            dependencies['airport_service'].invalidate_airport_cache.assert_not_called()


class TemplateRouterIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}

    def snapshot(self):
        return self.client.get('/api/template', headers=self.headers).json()

    def save(self, content, revision=None):
        return self.client.post('/api/template', headers=self.headers, json={
            'content': content, 'expected_revision': revision or self.snapshot()['revision'],
        })

    def import_all(self, **values):
        payload = {'content': 'rules: []\n# import\n', 'nodes': [], 'urls': [],
                   'expected_revision': self.snapshot()['revision']}
        payload.update(values)
        return self.client.post('/api/template/import', headers=self.headers, json=payload)

    def files(self):
        return {name: (Path(self.app.DATA_DIR) / name).read_bytes()
                if (Path(self.app.DATA_DIR) / name).exists() else None
                for name in ['template.yaml', 'custom_nodes.yaml', 'airports.yaml']}

    def requests(self, revision):
        entry = '0' * 32
        return [('GET', '/api/template', None),
                ('POST', '/api/template/validate', {'content': 'rules: []'}),
                ('POST', '/api/template', {'content': 'rules: []', 'expected_revision': revision}),
                ('GET', '/api/template/history', None),
                ('GET', '/api/template/history/' + entry, None),
                ('POST', '/api/template/history/' + entry + '/restore', {'expected_revision': revision}),
                ('POST', '/api/template/import', {'content': 'rules: []', 'nodes': [], 'urls': [],
                                                  'expected_revision': revision})]

    def test_handlers_and_all_four_models_keep_existing_python_bindings(self):
        api = self.app.template_api
        for name in ['TemplateModel', 'TemplateSaveModel', 'TemplateRestoreModel', 'ImportModel']:
            self.assertIs(getattr(self.app, name), getattr(template_api, name))
        names = ['get_template', 'validate_template', 'update_template', 'template_history',
                 'template_history_entry', 'restore_template', 'import_template']
        for (method, path, _), name in zip(self.requests('a' * 64), names):
            path = path.replace('0' * 32, '{entry_id}')
            handler = getattr(api, name)
            self.assertIs(getattr(self.app, name), handler)
            routes = [route for route in api.router.routes if route.path == path and method in route.methods]
            self.assertEqual(len(routes), 1)
            self.assertIs(routes[0].endpoint, handler)

    def test_all_seven_routes_reject_anonymous_and_subscription_credentials_before_work(self):
        with patch.object(self.app, 'template_store', side_effect=AssertionError('must not access storage')), \
                patch.object(self.app, 'load_manual_nodes', side_effect=AssertionError('must not read nodes')):
            for token in [None, TEST_SUBSCRIPTION_TOKEN]:
                headers = {} if token is None else {'Authorization': 'Bearer ' + token}
                for method, path, body in self.requests('a' * 64):
                    result = self.client.request(method, path, headers=headers,
                                                 **({'json': body} if body is not None else {}))
                    self.assertEqual(result.status_code, 401, result.text)

    def test_all_four_cookie_write_routes_require_same_origin(self):
        self.assertEqual(self.save('rules: []\n# history').status_code, 200)
        entries = self.client.get('/api/template/history', headers=self.headers).json()['entries']
        entry = entries[-1]['id']
        self.assertEqual(self.client.post('/api/auth', json={'token': TEST_ADMIN_TOKEN}).status_code, 200)
        for path in ['/api/template/validate', '/api/template',
                     '/api/template/history/' + entry + '/restore', '/api/template/import']:
            body = {'content': 'rules: []', 'expected_revision': self.snapshot()['revision'], 'nodes': [], 'urls': []}
            for origin in [None, 'https://foreign.example']:
                result = self.client.post(path, json=body, headers={} if origin is None else {'Origin': origin})
                self.assertEqual(result.status_code, 403, result.text)
            result = self.client.post(path, json=body, headers={'Origin': 'http://testserver'})
            self.assertEqual(result.status_code, 200, result.text)

    def test_validation_statuses_and_failures_preserve_files_and_cache(self):
        before = self.files()
        revision = self.snapshot()['revision']
        requests = [({'content': 'rules: []'}, 428),
                    ({'content': 'rules: []', 'expected_revision': 'invalid'}, 422),
                    ({'content': 'rules: []', 'expected_revision': 'f' * 64}, 409),
                    ({'content': 'rules: [', 'expected_revision': revision}, 400),
                    ({'content': '#' * (self.app.MAX_TEMPLATE_BYTES + 1), 'expected_revision': revision}, 413),
                    ({'content': None, 'expected_revision': revision}, 422)]
        with patch.object(self.app.airport_service, 'invalidate_airport_cache') as invalidate:
            for payload, status in requests:
                result = self.client.post('/api/template', headers=self.headers, json=payload)
                self.assertEqual(result.status_code, status, result.text)
                self.assertEqual(self.files(), before)
            for values in [{'urls': ['http://127.0.0.1/sub']}, {'nodes': [{'name': 'broken', 'type': 'ss'}]},
                           {'content': 'rules: ['}]:
                result = self.import_all(**values)
                self.assertEqual(result.status_code, 400, result.text)
                self.assertEqual(self.files(), before)
            invalidate.assert_not_called()

    def test_history_missing_entry_and_restore_keep_current_version_contract(self):
        before = self.snapshot()
        saved = self.save('rules: []\n# saved').json()
        entries = self.client.get('/api/template/history', headers=self.headers).json()['entries']
        self.assertNotIn('content', entries[0])
        entry_id = entries[-1]['id']
        entry = self.client.get('/api/template/history/' + entry_id, headers=self.headers)
        self.assertEqual(entry.json()['content'], before['content'])
        for identifier in ['missing', '0' * 32]:
            path = '/api/template/history/' + identifier
            self.assertEqual(self.client.get(path, headers=self.headers).status_code, 404)
            result = self.client.post(path + '/restore', headers=self.headers,
                                      json={'expected_revision': saved['revision']})
            self.assertEqual(result.status_code, 404, result.text)
        path = '/api/template/history/' + entry_id + '/restore'
        conflict = self.client.post(path, headers=self.headers, json={'expected_revision': before['revision']})
        self.assertEqual(conflict.status_code, 409)
        restored = self.client.post(path, headers=self.headers, json={'expected_revision': saved['revision']})
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertEqual(restored.json()['content'], before['content'])

    def test_import_keeps_managed_nodes_readonly_and_out_of_manual_storage(self):
        managed = {**node('Agent [pf:fixture]'), '_managed_by': {'deployment_id': 'fixture'},
                   '_airport_name': self.app.CUSTOM_NODES_SOURCE}
        original = deepcopy(managed)
        with patch.object(self.app, 'managed_nodes', return_value=[managed]), \
                patch.object(self.app.airport_service, 'invalidate_airport_cache',
                             wraps=self.app.airport_service.invalidate_airport_cache) as invalidate:
            result = self.import_all(nodes=[node(), managed])
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(yaml.safe_load(Path(self.app.CUSTOM_NODES_PATH).read_text(encoding='utf-8')), [node()])
            before = self.files()
            changed = {**managed, 'port': 9443}
            for value in [changed, {key: value for key, value in changed.items() if key != '_managed_by'}]:
                result = self.import_all(nodes=[value])
                self.assertEqual(result.status_code, 409, result.text)
                self.assertEqual(self.files(), before)
            self.assertEqual(invalidate.call_count, 1)
            self.assertEqual(self.import_all().status_code, 200)
            nodes = self.client.get('/api/nodes', headers=self.headers).json()['nodes']
            self.assertEqual(nodes, [managed])
        self.assertEqual(managed, original)

    def test_import_invalidates_shared_cache_by_complete_original_source_values(self):
        sources = [{'name': 'A', 'url': 'https://airport.example/sub', 'extension': {'keep': True}}]
        self.assertEqual(self.import_all(urls=sources).status_code, 200)
        paths = [self.app.airport_service.cache_path, self.app.airport_service.info_cache_path]
        for path in paths:
            path.write_text('[]\n', encoding='utf-8')
        with patch.object(self.app.airport_service, 'invalidate_airport_cache',
                          wraps=self.app.airport_service.invalidate_airport_cache) as invalidate:
            self.assertEqual(self.import_all(urls=deepcopy(sources)).status_code, 200)
            invalidate.assert_called_once_with(clear_disk=False)
            self.assertTrue(all(path.exists() for path in paths))
            sources[0]['extension']['keep'] = False
            self.assertEqual(self.import_all(urls=sources).status_code, 200)
            self.assertEqual(invalidate.call_args.kwargs, {'clear_disk': True})
            self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(yaml.safe_load(Path(self.app.AIRPORTS_PATH).read_text(encoding='utf-8')), sources)

    def test_interrupted_import_recovers_all_three_files_before_next_read(self):
        write = template_store.atomic_write

        def interrupted(path, content):
            if Path(path).name == 'airports.yaml':
                raise OSError('fixture private storage diagnostic')
            return write(path, content)

        sources = [{'name': 'A', 'url': 'https://airport.example/sub'}]
        with patch.object(template_store, 'atomic_write', side_effect=interrupted):
            result = self.import_all(nodes=[node()], urls=sources)
        self.assertEqual(result.status_code, 503, result.text)
        self.assertNotIn('fixture private', result.text)
        self.assertTrue(self.app.template_store().journal.exists())
        recovered = self.snapshot()
        self.assertEqual(recovered['content'], 'rules: []\n# import\n')
        self.assertEqual(yaml.safe_load(Path(self.app.CUSTOM_NODES_PATH).read_text(encoding='utf-8')), [node()])
        self.assertEqual(yaml.safe_load(Path(self.app.AIRPORTS_PATH).read_text(encoding='utf-8')), sources)
        self.assertFalse(self.app.template_store().journal.exists())

    def test_concurrent_save_checks_revision_and_commits_inside_one_outer_lock(self):
        revision = self.snapshot()['revision']
        entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
        validate = self.app.validate_saved_template

        def hold_first(*args):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('fixture validator release')
            return validate(*args)

        def second():
            second_started.set()
            return self.save('rules: []\n# second', revision)

        with patch.object(self.app, 'validate_saved_template', side_effect=hold_first) as validator, \
                ThreadPoolExecutor(2) as pool:
            first = pool.submit(self.save, 'rules: []\n# first', revision)
            try:
                self.assertTrue(entered.wait(5))
                later = pool.submit(second)
                self.assertTrue(second_started.wait(5))
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5).status_code, 200)
            self.assertEqual(later.result(timeout=5).status_code, 409)
            self.assertEqual(validator.call_count, 1)
        self.assertEqual(self.snapshot()['content'], 'rules: []\n# first')

    def test_storage_failures_keep_existing_503_and_history_500_responses(self):
        revision = self.snapshot()['revision']

        @contextmanager
        def unavailable(*args, **kwargs):
            raise OSError('fixture private storage diagnostic')
            yield

        with patch.object(self.app.TemplateStore, 'locked', unavailable):
            for method, path, body in self.requests(revision):
                result = self.client.request(method, path, headers=self.headers,
                                             **({'json': body} if body is not None else {}))
                status = 500 if method == 'GET' and '/history' in path else 503
                self.assertEqual(result.status_code, status, result.text)
                self.assertNotIn('fixture private', result.text)
