"""机场 Router 的显式依赖、路由绑定和管理安全边界。"""
from contextlib import contextmanager, nullcontext
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

from proxyforge.airports.api import AirportsModel, check_airport_urls, create_airport_router
from proxyforge.config.template_store import ConfigurationTooLarge, TemplateConflict
from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN


class AirportRouterAssemblyTest(unittest.TestCase):
    def assemble(self, label, **overrides):
        def verify(x_manager: str = Header(None)):
            if x_manager != label:
                raise HTTPException(status_code=401, detail='unauthorized')

        service = SimpleNamespace(get_airports_info=Mock(return_value={'info': [label]}))
        settings = dict(
            verify_management=verify, configuration_lock=lambda: nullcontext(),
            sources_reader=Mock(return_value=['https://' + label + '.example/sub']),
            template_reader=Mock(return_value='proxy-groups: []\nrules: []\n'),
            template_store=Mock(), airport_service=service, service_errors=lambda function: function,
        )
        settings.update(overrides)
        api = create_airport_router(**settings)
        return api, settings

    def test_assembly_does_not_read_configuration_or_start_service_work(self):
        reader = Mock(side_effect=AssertionError('unexpected source read'))
        lock = Mock(side_effect=AssertionError('unexpected lock'))
        api, dependencies = self.assemble('first', sources_reader=reader, configuration_lock=lock)
        self.assertEqual(len(api.router.routes), 3)
        for callback in [reader, lock, dependencies['template_reader'], dependencies['template_store'],
                         dependencies['airport_service'].get_airports_info]:
            callback.assert_not_called()

    def test_separate_applications_use_their_own_auth_sources_and_service(self):
        first, first_deps = self.assemble('first')
        second, second_deps = self.assemble('second')
        for label, api in [('first', first), ('second', second)]:
            app = FastAPI()
            app.include_router(api.router)
            with TestClient(app) as client:
                result = client.get('/api/airports', headers={'X-Manager': label})
                self.assertEqual(result.json(), {'urls': ['https://' + label + '.example/sub']})
                other = 'second' if label == 'first' else 'first'
                self.assertEqual(client.get('/api/airports', headers={'X-Manager': other}).status_code, 401)
                result = client.get('/api/airports/info?force_indices=all', headers={'X-Manager': label})
                self.assertEqual(result.json(), {'info': [label]})
        first_deps['airport_service'].get_airports_info.assert_called_once_with('all')
        second_deps['airport_service'].get_airports_info.assert_called_once_with('all')


class AirportRouterIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}

    def test_routes_and_existing_python_names_share_one_set_of_handlers(self):
        api = self.app.airport_api
        self.assertIs(self.app.get_airports, api.get_airports)
        self.assertIs(self.app.update_airports, api.update_airports)
        self.assertIs(self.app.get_airports_info, api.get_airports_info)
        self.assertIs(self.app.AirportsModel, AirportsModel)
        self.assertIs(self.app.check_airport_urls, check_airport_urls)
        expected = {('/api/airports', 'GET'): api.get_airports,
                    ('/api/airports', 'POST'): api.update_airports,
                    ('/api/airports/info', 'GET'): api.get_airports_info}
        for (path, method), handler in expected.items():
            routes = [route for route in api.router.routes if getattr(route, 'path', None) == path
                      and method in getattr(route, 'methods', set())]
            self.assertEqual(len(routes), 1)
            self.assertIs(routes[0].endpoint, handler)
            self.assertEqual(handler.__module__, 'proxyforge.airports.api')

    def test_all_airport_management_routes_require_admin_identity_before_work(self):
        with patch.object(self.app, 'load_airports', side_effect=AssertionError('must not read')), \
                patch.object(self.app.airport_service, 'get_airports_info', side_effect=AssertionError('must not fetch')):
            for token in [None, TEST_SUBSCRIPTION_TOKEN]:
                headers = {} if token is None else {'Authorization': 'Bearer ' + token}
                for method, path in [('GET', '/api/airports'), ('POST', '/api/airports'),
                                     ('GET', '/api/airports/info')]:
                    result = self.client.request(method, path, headers=headers,
                                                 **({'json': {'urls': []}} if method == 'POST' else {}))
                    self.assertEqual(result.status_code, 401, result.text)

    def test_airport_cookie_write_requires_matching_origin(self):
        login = self.client.post('/api/auth', json={'token': TEST_ADMIN_TOKEN})
        self.assertEqual(login.status_code, 200, login.text)
        path = Path(self.app.AIRPORTS_PATH)
        for origin in [None, 'https://foreign.example']:
            headers = {} if origin is None else {'Origin': origin}
            result = self.client.post('/api/airports', json={'urls': []}, headers=headers)
            self.assertEqual(result.status_code, 403, result.text)
            self.assertFalse(path.exists())
        result = self.client.post('/api/airports', json={'urls': []}, headers={'Origin': 'http://testserver'})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(set(result.json()), {'status', 'cleanedReferences', 'template_revision'})

    def test_storage_unavailable_maps_to_existing_503_without_private_error(self):
        @contextmanager
        def unavailable(*args, **kwargs):
            raise OSError('fixture-private-storage-diagnostic')
            yield

        with patch.object(self.app.TemplateStore, 'locked', unavailable):
            for method, path in [('GET', '/api/airports'), ('POST', '/api/airports'),
                                 ('GET', '/api/airports/info')]:
                result = self.client.request(method, path, headers=self.headers,
                                             **({'json': {'urls': []}} if method == 'POST' else {}))
                self.assertEqual(result.status_code, 503, result.text)
                self.assertEqual(result.json()['detail']['code'], 'storage_unavailable')
                self.assertNotIn('fixture-private-storage-diagnostic', result.text)

    def test_router_uses_application_conflict_and_size_exception_handlers(self):
        current = self.app.template_store().snapshot()
        for error, status in [(TemplateConflict(current), 409), (ConfigurationTooLarge(), 413)]:
            with self.subTest(status=status), patch.object(self.app.TemplateStore, 'commit', side_effect=error):
                result = self.client.post('/api/airports', json={'urls': []}, headers=self.headers)
                self.assertEqual(result.status_code, status, result.text)
                if status == 409:
                    self.assertEqual(result.json()['detail']['code'], 'template_conflict')
                    self.assertEqual(result.json()['detail']['current_revision'], current['revision'])
                else:
                    self.assertEqual(result.json()['detail'], 'Configuration exceeds 1 MiB')
