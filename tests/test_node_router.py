"""节点 Router 的依赖隔离、管理边界、托管只读和事务恢复。"""
import base64
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
import yaml

from proxyforge.config import template_store
from proxyforge.nodes.api import NodesModel, ParseLinksModel, create_node_router
from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN


def node(name='Manual'):
    return {'name': name, 'type': 'ss', 'server': 'node.example', 'port': 8388,
            'cipher': 'aes-256-gcm', 'password': 'fixture'}


class NodeRouterAssemblyTest(unittest.TestCase):
    def assemble(self, label):
        def verify(x_manager: str = Header(None)):
            if x_manager != label:
                raise HTTPException(status_code=401, detail='unauthorized')

        settings = dict(
            verify_management=verify, configuration_lock=Mock(side_effect=lambda: nullcontext()),
            nodes_reader=Mock(return_value=[node(label)]),
            airport_proxy_reader=Mock(return_value=[node(label + ' airport')]),
            manual_input=Mock(side_effect=lambda nodes: nodes), manual_nodes_reader=Mock(return_value=[]),
            template_reader=Mock(return_value='proxy-groups: []\nrules: []\n'), template_store=Mock(),
        )
        return create_node_router(**settings), settings

    def test_assembly_does_not_read_files_databases_or_start_fetches(self):
        api, dependencies = self.assemble('first')
        self.assertEqual(len(api.router.routes), 4)
        for name, callback in dependencies.items():
            if name != 'verify_management':
                callback.assert_not_called()

    def test_separate_apps_preserve_their_own_auth_and_proxy_order(self):
        for label in ['first', 'second']:
            api, dependencies = self.assemble(label)
            app = FastAPI()
            app.include_router(api.router)
            with TestClient(app) as client:
                headers = {'X-Manager': label}
                self.assertEqual(client.get('/api/nodes', headers=headers).json(), {'nodes': [node(label)]})
                self.assertEqual(client.get('/api/proxies', headers=headers).json(),
                                 {'proxies': [node(label), node(label + ' airport')]})
                other = 'second' if label == 'first' else 'first'
                self.assertEqual(client.get('/api/proxies', headers={'X-Manager': other}).status_code, 401)
            dependencies['airport_proxy_reader'].assert_called_once()


class NodeRouterIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        self.path = Path(self.app.CUSTOM_NODES_PATH)

    def post(self, nodes):
        return self.client.post('/api/nodes', headers=self.headers, json={'nodes': nodes})

    def test_route_handlers_and_request_models_keep_existing_python_bindings(self):
        api = self.app.node_api
        self.assertIs(self.app.NodesModel, NodesModel)
        self.assertIs(self.app.ParseLinksModel, ParseLinksModel)
        expected = [('/api/parse-links', 'POST', 'parse_links_api'), ('/api/nodes', 'GET', 'get_nodes'),
                    ('/api/proxies', 'GET', 'get_all_proxies'), ('/api/nodes', 'POST', 'update_nodes')]
        for path, method, name in expected:
            handler = getattr(api, name)
            self.assertIs(getattr(self.app, name), handler)
            routes = [route for route in api.router.routes if route.path == path and method in route.methods]
            self.assertEqual(len(routes), 1)
            self.assertIs(routes[0].endpoint, handler)
            self.assertEqual(handler.__module__, 'proxyforge.nodes.api')

    def test_all_routes_reject_anonymous_and_subscription_identity_before_work(self):
        requests = [('GET', '/api/nodes', None), ('GET', '/api/proxies', None),
                    ('POST', '/api/nodes', {'nodes': []}), ('POST', '/api/parse-links', {'links': ['bad']})]
        with patch.object(self.app, 'load_custom_nodes', side_effect=AssertionError('must not read')), \
                patch.object(self.app, 'manual_node_input', side_effect=AssertionError('must not inspect managed')), \
                patch('proxyforge.nodes.api.parse_share_link', side_effect=AssertionError('must not parse')):
            for token in [None, TEST_SUBSCRIPTION_TOKEN]:
                headers = {} if token is None else {'Authorization': 'Bearer ' + token}
                for method, path, body in requests:
                    result = self.client.request(method, path, headers=headers,
                                                 **({'json': body} if body is not None else {}))
                    self.assertEqual(result.status_code, 401, result.text)

    def test_both_cookie_write_routes_require_same_origin(self):
        self.assertEqual(self.client.post('/api/auth', json={'token': TEST_ADMIN_TOKEN}).status_code, 200)
        for path, body in [('/api/nodes', {'nodes': []}), ('/api/parse-links', {'links': []})]:
            for origin in [None, 'https://foreign.example']:
                result = self.client.post(path, json=body, headers={} if origin is None else {'Origin': origin})
                self.assertEqual(result.status_code, 403, result.text)
            result = self.client.post(path, json=body, headers={'Origin': 'http://testserver'})
            self.assertEqual(result.status_code, 200, result.text)

    def test_managed_roundtrip_is_not_persisted_or_editable_as_manual_node(self):
        managed = {**node('Agent [pf:fixture]'), '_managed_by': {'deployment_id': 'fixture'},
                   '_airport_name': self.app.CUSTOM_NODES_SOURCE}
        original = deepcopy(managed)
        with patch.object(self.app, 'managed_nodes', return_value=[managed]):
            self.assertEqual(self.post([node(), managed]).status_code, 200)
            self.assertEqual(yaml.safe_load(self.path.read_text(encoding='utf-8')), [node()])
            saved = self.path.read_bytes()
            changed = {**managed, 'port': 9443}
            for value in [changed, {key: value for key, value in changed.items() if key != '_managed_by'}]:
                result = self.post([value])
                self.assertEqual(result.status_code, 409, result.text)
                self.assertEqual(self.path.read_bytes(), saved)
            self.assertEqual(self.post([]).status_code, 200)
            self.assertEqual(self.client.get('/api/nodes', headers=self.headers).json()['nodes'], [managed])
        self.assertEqual(managed, original)

    def test_validation_and_partial_parse_failures_never_write_node_or_template_files(self):
        self.assertEqual(self.post([node()]).status_code, 200)
        template_path = Path(self.app.TEMPLATE_PATH)
        before = (self.path.read_bytes(), template_path.read_bytes())
        for body, status in [({'nodes': [{'name': 'broken', 'type': 'ss'}]}, 400),
                             ({'nodes': 'wrong'}, 422), ({'nodes': [None]}, 422)]:
            result = self.client.post('/api/nodes', headers=self.headers, json=body)
            self.assertEqual(result.status_code, status, result.text)
        link = 'ss://' + base64.b64encode(b'aes-256-gcm:fixture').decode() + '@node.example:8388#fixture'
        result = self.client.post('/api/parse-links', headers=self.headers,
                                  json={'links': [link, 'unsupported://fixture']})
        self.assertEqual(result.status_code, 400, result.text)
        self.assertNotIn('nodes', result.json())
        self.assertIn('links[2]', result.json()['detail']['errors'][0])
        self.assertEqual((self.path.read_bytes(), template_path.read_bytes()), before)

    def test_storage_errors_keep_existing_503_and_parse_stays_storage_independent(self):
        @contextmanager
        def unavailable(*args, **kwargs):
            raise OSError('fixture-private-storage-diagnostic')
            yield

        with patch.object(self.app.TemplateStore, 'locked', unavailable):
            for method, path in [('GET', '/api/nodes'), ('GET', '/api/proxies'), ('POST', '/api/nodes')]:
                result = self.client.request(method, path, headers=self.headers,
                                             **({'json': {'nodes': []}} if method == 'POST' else {}))
                self.assertEqual(result.status_code, 503, result.text)
                self.assertEqual(result.json()['detail']['code'], 'storage_unavailable')
                self.assertNotIn('fixture-private-storage-diagnostic', result.text)
            result = self.client.post('/api/parse-links', headers=self.headers, json={'links': []})
            self.assertEqual(result.status_code, 200, result.text)

    def test_interrupted_node_and_template_commit_recovers_both_on_next_read(self):
        self.assertEqual(self.post([node()]).status_code, 200)
        self.app.save_template_content(yaml.safe_dump({
            'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'proxies': ['Manual', 'DIRECT']}],
            'rules': ['MATCH,Proxy'],
        }))
        old_revision = self.app.template_store().snapshot()['revision']
        write = template_store.atomic_write

        def interrupted(path, content):
            if Path(path).name == 'custom_nodes.yaml':
                raise OSError('simulated commit interruption')
            return write(path, content)

        with patch.object(template_store, 'atomic_write', side_effect=interrupted):
            result = self.post([])
        self.assertEqual(result.status_code, 503, result.text)
        self.assertEqual(self.client.get('/api/nodes', headers=self.headers).json(), {'nodes': []})
        current = self.app.template_store().snapshot()
        self.assertNotEqual(current['revision'], old_revision)
        self.assertEqual(yaml.safe_load(current['content'])['proxy-groups'][0]['proxies'], ['DIRECT'])
