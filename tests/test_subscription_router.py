"""公开订阅 Router 的隔离装配、动态依赖和 HTTP 兼容边界。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml

from proxyforge.airports.service import AirportSourcesChanged
from proxyforge.subscription.api import create_subscription_router
from proxyforge.subscription.builder import build_subscription_config
from proxyforge.subscription.egern import build_egern_config
from proxyforge.subscription.validation import ConfigValidationError
from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN


def node(label='Fixture'):
    return {'name': label, 'type': 'ss', 'server': 'node.example', 'port': 8388,
            'cipher': 'aes-256-gcm', 'password': 'fixture'}


class SubscriptionRouterAssemblyTest(unittest.TestCase):
    def assemble(self, label):
        state = {'token': label}
        dependencies = dict(
            token_reader=Mock(side_effect=lambda: state['token']),
            template_reader=Mock(return_value='proxy-groups: []\nrules: []\n'),
            sources_reader=Mock(return_value=['https://source.example/sub']),
            nodes_reader=Mock(return_value=[node(label)]), managed_names_reader=Mock(return_value=[]),
            references_cleaner=Mock(), subscription_reader=Mock(return_value=([], [])),
            airport_service=Mock(), service_errors=Mock(side_effect=lambda function: function),
            rule_loader=Mock(return_value='domain_suffix_set: [example.com]\n'),
            config_builder=Mock(wraps=build_subscription_config), provider_resolver=Mock(return_value={}),
            egern_builder=Mock(wraps=build_egern_config), ca_bundle_reader=Mock(return_value=None),
            logger=Mock(),
        )
        dependencies['airport_service'].fetch_airport_item.return_value = [node(label)]
        api = create_subscription_router(**dependencies)
        app = FastAPI()
        app.include_router(api.router)
        return api, app, dependencies, state

    def test_assembly_only_applies_error_adapter_without_reading_or_building(self):
        api, _, dependencies, _ = self.assemble('unused')
        self.assertEqual(len(api.router.routes), 3)
        for name, callback in dependencies.items():
            if name == 'service_errors':
                callback.assert_called_once()
            else:
                self.assertEqual(callback.mock_calls, [], name)

    def test_two_apps_keep_separate_tokens_sources_nodes_and_services(self):
        for label in ['first', 'second']:
            _, app, dependencies, _ = self.assemble(label)
            with TestClient(app) as client:
                for path in ['/sub', '/provider/0', '/egern/ruleset/geosite?value=cn']:
                    separator = '&' if '?' in path else '?'
                    self.assertEqual(client.get(path + separator + 'token=other').status_code, 401)
                    response = client.get(path + separator + 'token=' + label)
                    self.assertEqual(response.status_code, 200, response.text)
                self.assertIn(label, client.get('/sub', params={'token': label}).text)
                self.assertEqual(dependencies['airport_service'].fetch_airport_item.call_args.args,
                                 ('https://source.example/sub', 0))
            dependencies['nodes_reader'].assert_called()
            dependencies['logger'].error.assert_not_called()

    def test_rotated_token_is_read_on_every_public_endpoint(self):
        _, app, dependencies, state = self.assemble('before')
        state['token'] = 'after'
        with TestClient(app) as client:
            for path, extra in [('/sub', {}), ('/provider/0', {}),
                                ('/egern/ruleset/geosite', {'value': 'cn'})]:
                self.assertEqual(client.get(path, params={'token': 'before', **extra}).status_code, 401)
                self.assertEqual(client.get(path, params={'token': 'after', **extra}).status_code, 200)
        self.assertEqual(dependencies['token_reader'].call_count, 6)

    def test_request_root_and_current_ca_reach_existing_builders(self):
        _, app, dependencies, _ = self.assemble('fixture')
        dependencies['ca_bundle_reader'].return_value = '/fixture/ca.pem'
        with TestClient(app, base_url='https://export.example', root_path='/edge') as client:
            response = client.get('/sub', params={'token': 'fixture', 'format': 'egern', 'name': '中文订阅'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(dependencies['config_builder'].call_args.args[3:5],
                         ('https://export.example/edge', 'fixture'))
        args, kwargs = dependencies['provider_resolver'].call_args
        self.assertEqual(args[3:5], ('https://export.example/edge', 'fixture'))
        self.assertEqual(kwargs, {'template_providers': None, 'ca_bundle': '/fixture/ca.pem'})
        self.assertEqual(dependencies['egern_builder'].call_args.args[2:4],
                         ('https://export.example/edge/', 'fixture'))
        self.assertEqual(response.headers['profile-title'], '%E4%B8%AD%E6%96%87%E8%AE%A2%E9%98%85')
        self.assertEqual(response.headers['cache-control'], 'no-store')

    def test_invalid_identity_and_query_do_not_touch_sources_or_resources(self):
        _, app, dependencies, _ = self.assemble('fixture')
        with TestClient(app) as client:
            for path, extra in [('/sub', {}), ('/provider/0', {}),
                                ('/egern/ruleset/geosite', {'value': 'cn'})]:
                self.assertEqual(client.get(path, params=extra).status_code, 422)
                self.assertEqual(client.get(path, params={'token': 'other', **extra}).status_code, 401)
            self.assertEqual(client.get('/sub', params={'token': 'fixture', 'format': 'other'}).status_code, 400)
            self.assertEqual(client.get('/egern/ruleset/geosite',
                                        params={'token': 'fixture', 'value': 'x' * 129}).status_code, 422)
            self.assertEqual(client.get('/egern/ruleset/geosite',
                                        params={'token': 'fixture', 'value': 'cn',
                                                'revision': 'x' * 65}).status_code, 422)
        for name in ['sources_reader', 'nodes_reader', 'template_reader', 'subscription_reader',
                     'references_cleaner', 'rule_loader', 'provider_resolver']:
            dependencies[name].assert_not_called()


class SubscriptionRouterIntegrationTest(unittest.TestCase):
    def setUp(self):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        self.app = load_isolated_application(Path(runtime.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)

    def test_main_names_are_actual_endpoints_and_routes_only_mounted_once(self):
        def endpoints(router):
            for route in router.routes:
                included = getattr(route, 'original_router', None)
                if included is not None:
                    yield from endpoints(included)
                else:
                    yield route

        for path, name in [('/sub', 'get_subscription'), ('/provider/{airport_index}', 'get_airport_provider'),
                           ('/egern/ruleset/{kind}', 'get_egern_rule_set')]:
            routes = [route for route in endpoints(self.app.app) if getattr(route, 'path', None) == path]
            self.assertEqual(len(routes), 1)
            self.assertIs(routes[0].endpoint, getattr(self.app, name))
            self.assertIs(getattr(self.app, name), getattr(self.app.subscription_api, name))

    def test_runtime_token_rotation_and_admin_identity_stay_separate(self):
        self.app.SUBSCRIPTION_TOKEN = 'fixture-rotated-token'
        with patch.object(self.app, 'load_template_content', return_value='proxy-groups: []\nrules: []\n'), \
                patch.object(self.app, 'load_airports', return_value=['https://source.example/sub']), \
                patch.object(self.app.airport_service, 'fetch_airport_item', return_value=[node()]), \
                patch.object(self.app, 'load_rule_resource', return_value='domain_set: []\n'):
            for path, extra in [('/provider/0', {}), ('/egern/ruleset/geosite', {'value': 'cn'})]:
                for invalid in [TEST_SUBSCRIPTION_TOKEN, TEST_ADMIN_TOKEN]:
                    self.assertEqual(self.client.get(path, params={'token': invalid, **extra}).status_code, 401)
                response = self.client.get(path, params={'token': 'fixture-rotated-token', **extra},
                                           headers={'Origin': 'https://unrelated.example'})
                self.assertEqual(response.status_code, 200, response.text)

    def test_provider_cache_fallback_matches_source_name_and_keeps_input_unchanged(self):
        source = {'name': 'Fixture source', 'url': 'https://source.example/sub', 'extension': {'a': 1}}
        cached = [{**node('cached'), '_airport_name': 'FIXTURE SOURCE'},
                  {**node('other'), '_airport_name': 'Other source'}]
        before = yaml.safe_dump(cached)
        with patch.object(self.app, 'load_airports', return_value=[source]), \
                patch.object(self.app.airport_service, 'fetch_airport_item', return_value=[]) as fetch, \
                patch.object(self.app.airport_service, 'load_cache_from_file', return_value=cached):
            response = self.client.get('/provider/0', params={'token': TEST_SUBSCRIPTION_TOKEN})
        self.assertEqual(response.status_code, 200, response.text)
        proxies = yaml.safe_load(response.text)['proxies']
        self.assertEqual(len(proxies), 1)
        self.assertIn('cached', proxies[0]['name'])
        self.assertNotIn('_airport_name', proxies[0])
        self.assertEqual(yaml.safe_dump(cached), before)
        fetch.assert_called_once_with(source, 0)

    def test_provider_original_not_found_unavailable_validation_and_storage_statuses(self):
        with patch.object(self.app, 'load_airports', return_value=['https://source.example/sub']), \
                patch.object(self.app.airport_service, 'fetch_airport_item', return_value=[]), \
                patch.object(self.app.airport_service, 'load_cache_from_file', return_value=[]):
            for index in [-1, 1]:
                self.assertEqual(self.client.get(f'/provider/{index}',
                                                 params={'token': TEST_SUBSCRIPTION_TOKEN}).status_code, 404)
            self.assertEqual(self.client.get('/provider/0', params={'token': TEST_SUBSCRIPTION_TOKEN}).status_code, 502)
        with patch.object(self.app, 'load_airports', return_value=['https://source.example/sub']):
            with patch.object(self.app.airport_service, 'fetch_airport_item', return_value=[{'name': 'bad'}]):
                self.assertEqual(self.client.get('/provider/0', params={'token': TEST_SUBSCRIPTION_TOKEN}).status_code, 422)
            for exception in [AirportSourcesChanged(), OSError('fixture-sensitive-canary')]:
                with patch.object(self.app.airport_service, 'fetch_airport_item', side_effect=exception):
                    response = self.client.get('/provider/0', params={'token': TEST_SUBSCRIPTION_TOKEN})
                self.assertEqual(response.status_code, 503)
                self.assertNotIn('fixture-sensitive-canary', response.text)

    def test_rule_resource_callback_arguments_headers_and_error_contract(self):
        with patch.object(self.app, 'load_template_content',
                          return_value='rule-providers: {fixture: {type: http}}\n'):
            with patch.object(self.app, 'load_rule_resource', return_value='domain_set: []\n') as load:
                result = self.client.get('/egern/ruleset/provider', params={
                    'token': TEST_SUBSCRIPTION_TOKEN, 'value': 'fixture', 'revision': 'a' * 64, 'no_resolve': 'true'})
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.text, 'domain_set: []\n')
                self.assertEqual(result.headers['cache-control'], 'no-store')
                load.assert_called_once_with('provider', 'fixture', {'fixture': {'type': 'http'}}, 'a' * 64, True)
            with patch.object(self.app, 'load_rule_resource', side_effect=ConfigValidationError(['fixture error'])):
                result = self.client.get('/egern/ruleset/provider',
                                         params={'token': TEST_SUBSCRIPTION_TOKEN, 'value': 'fixture'})
                self.assertEqual(result.status_code, 422)
                self.assertEqual(result.text, '规则集转换失败:\n- fixture error')
            with patch.object(self.app, 'load_rule_resource', side_effect=RuntimeError('fixture-sensitive-canary')):
                with self.assertLogs(self.app.logger, level='WARNING') as captured:
                    result = self.client.get('/egern/ruleset/provider',
                                             params={'token': TEST_SUBSCRIPTION_TOKEN, 'value': 'fixture'})
                self.assertEqual(result.status_code, 502)
                self.assertEqual(result.text, '规则集暂时不可用，请稍后重试')
                self.assertEqual([r.getMessage() for r in captured.records], ['Egern 规则集请求失败（RuntimeError）'])
