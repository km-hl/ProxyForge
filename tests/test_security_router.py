"""管理鉴权 Router 的依赖隔离、凭据提交和实际会话行为。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

from proxyforge.security.api import ConfigModel, AdminTokenModel, create_security_router
from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN


class SecurityRouterAssemblyTest(unittest.TestCase):
    def assemble(self, label):
        state = {'token': 'fixture-subscription-before', 'cookie': label, 'minimum': 16,
                 'insecure': {'fixture-insecure-token'}}
        store = Mock()
        store.verify_admin_token.side_effect = lambda token: token == label
        limiter = Mock()
        limiter.retry_after.return_value = 0
        state.update(store=store, limiter=limiter)

        def verify(authorization: str = Header(None)):
            if authorization != 'Bearer ' + label:
                raise HTTPException(401, detail='Invalid management credentials')

        def write_session(response, request):
            response.set_cookie(state['cookie'], label, httponly=True, samesite='strict')

        dependencies = dict(
            verify_management=verify, store_reader=Mock(side_effect=lambda: state['store']),
            limiter_reader=Mock(side_effect=lambda: state['limiter']),
            session_writer=Mock(side_effect=write_session),
            cookie_name_reader=Mock(side_effect=lambda: state['cookie']),
            subscription_token_reader=Mock(side_effect=lambda: state['token']),
            subscription_token_writer=Mock(side_effect=lambda token: state.update(token=token)),
            admin_minimum_reader=Mock(side_effect=lambda: state['minimum']),
            insecure_tokens_reader=Mock(side_effect=lambda: state['insecure']),
        )
        api = create_security_router(**dependencies)
        app = FastAPI()
        app.include_router(api.router)
        return api, app, dependencies, state

    def test_factory_does_not_read_create_or_mutate_security_state(self):
        api, _, dependencies, state = self.assemble('fixture')
        self.assertEqual(len(api.router.routes), 6)
        for name, callback in dependencies.items():
            if name != 'verify_management':
                self.assertEqual(callback.mock_calls, [], name)
        self.assertEqual(state['store'].mock_calls, [])
        self.assertEqual(state['limiter'].mock_calls, [])

    def test_two_apps_keep_auth_sessions_config_and_limiters_separate(self):
        for label in ['first', 'second']:
            _, app, dependencies, state = self.assemble(label)
            with TestClient(app) as client:
                self.assertEqual(client.post('/api/auth', json={'token': 'other'}).status_code, 401)
                response = client.post('/api/auth', json={'token': label})
                self.assertEqual(response.status_code, 200)
                self.assertIn(label + '=', response.headers['set-cookie'])
                self.assertEqual(client.get('/api/config', headers={'Authorization': 'Bearer other'}).status_code, 401)
                headers = {'Authorization': 'Bearer ' + label}
                self.assertEqual(client.get('/api/auth', headers=headers).json(), {'status': 'ok'})
                value = 'fixture-token-' + label
                self.assertEqual(client.post('/api/config', headers=headers,
                                             json={'SUBSCRIPTION_TOKEN': value}).status_code, 200)
                self.assertEqual(client.get('/api/config', headers=headers).json(), {'SUBSCRIPTION_TOKEN': value})
            state['store'].update_subscription_token.assert_called_once_with(value)
            state['limiter'].record_failure.assert_called_once_with('testclient')
            state['limiter'].reset.assert_called_once_with('testclient')
            dependencies['session_writer'].assert_called_once()

    def test_live_limiter_and_store_callbacks_preserve_429_and_login_order(self):
        _, app, dependencies, state = self.assemble('fixture')
        state['limiter'].retry_after.return_value = 7
        with TestClient(app) as client:
            result = client.post('/api/auth', json={'token': 'fixture'})
            self.assertEqual(result.status_code, 429)
            self.assertEqual(result.headers['retry-after'], '7')
            self.assertEqual(result.json(), {'detail': '登录失败次数过多，请稍后重试'})
            state['store'].verify_admin_token.assert_not_called()
            dependencies['session_writer'].assert_not_called()
            old_store, old_limiter = state['store'], state['limiter']
            state['store'] = Mock()
            state['store'].verify_admin_token.return_value = True
            state['limiter'] = Mock()
            state['limiter'].retry_after.return_value = 0
            self.assertEqual(client.post('/api/auth', json={'token': 'fixture'}).status_code, 200)
        old_store.verify_admin_token.assert_not_called()
        old_limiter.reset.assert_not_called()
        state['store'].verify_admin_token.assert_called_once_with('fixture')
        state['limiter'].reset.assert_called_once_with('testclient')

    def test_subscription_state_changes_only_after_successful_persistence(self):
        _, app, dependencies, state = self.assemble('fixture')
        headers = {'Authorization': 'Bearer fixture'}
        with TestClient(app, raise_server_exceptions=False) as client:
            for value in ['short', 'fixture-insecure-token']:
                self.assertEqual(client.post('/api/config', headers=headers,
                                             json={'SUBSCRIPTION_TOKEN': value}).status_code, 400)
            state['store'].update_subscription_token.assert_not_called()
            for error, status in [(ValueError('fixture rejection'), 400), (OSError('fixture IO'), 500)]:
                state['store'].update_subscription_token.side_effect = error
                result = client.post('/api/config', headers=headers,
                                     json={'SUBSCRIPTION_TOKEN': 'fixture-subscription-after'})
                self.assertEqual(result.status_code, status)
                self.assertEqual(state['token'], 'fixture-subscription-before')
                dependencies['subscription_token_writer'].assert_not_called()
            events = []
            state['store'].update_subscription_token.side_effect = lambda value: events.append(('persist', value))
            dependencies['subscription_token_writer'].side_effect = lambda value: events.append(('apply', value))
            result = client.post('/api/config', headers=headers,
                                 json={'SUBSCRIPTION_TOKEN': '  fixture-subscription-after  '})
            self.assertEqual(result.json(), {'status': 'ok'})
            self.assertEqual(events, [('persist', 'fixture-subscription-after'), ('apply', 'fixture-subscription-after')])

    def test_admin_validation_errors_and_commit_preserve_session_boundary(self):
        _, app, dependencies, state = self.assemble('fixture')
        headers = {'Authorization': 'Bearer fixture'}
        state['minimum'] = 24
        with TestClient(app) as client:
            self.assertEqual(client.post('/api/admin-token', headers=headers,
                                         json={'ADMIN_TOKEN': 'fixture-token-too-short'}).status_code, 400)
            insecure = 'fixture-insecure-admin-token'
            state['insecure'].add(insecure)
            self.assertEqual(client.post('/api/admin-token', headers=headers,
                                         json={'ADMIN_TOKEN': insecure}).status_code, 400)
            state['store'].update_admin_token.assert_not_called()
            value = 'fixture-new-management-token'
            state['store'].update_admin_token.side_effect = ValueError('fixture rejection')
            result = client.post('/api/admin-token', headers=headers, json={'ADMIN_TOKEN': value})
            self.assertEqual(result.status_code, 400)
            self.assertEqual(result.json(), {'detail': 'fixture rejection'})
            dependencies['session_writer'].assert_not_called()
            state['store'].update_admin_token.side_effect = None
            result = client.post('/api/admin-token', headers=headers, json={'ADMIN_TOKEN': ' ' + value + ' '})
            self.assertEqual(result.json(), {'status': 'ok'})
            state['store'].update_admin_token.assert_called_with(value)
            dependencies['session_writer'].assert_called_once()

    def test_logout_reads_current_cookie_name_and_preserves_cookie_flags(self):
        _, app, dependencies, state = self.assemble('fixture')
        state['cookie'] = 'fixture-current-cookie'
        with TestClient(app) as client:
            result = client.post('/api/logout', headers={'Authorization': 'Bearer fixture'})
        self.assertEqual(result.json(), {'status': 'ok'})
        cookie = result.headers['set-cookie'].lower()
        for expected in ['fixture-current-cookie=', 'max-age=0', 'path=/', 'httponly', 'samesite=strict']:
            self.assertIn(expected, cookie)
        dependencies['store_reader'].assert_not_called()


class SecurityRouterIntegrationTest(unittest.TestCase):
    def setUp(self):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        self.app = load_isolated_application(Path(runtime.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}

    def test_main_models_and_six_actual_handlers_keep_the_same_bindings(self):
        self.assertIs(self.app.ConfigModel, ConfigModel)
        self.assertIs(self.app.AdminTokenModel, AdminTokenModel)
        api = self.app.security_api
        for method, path, name in [('POST', '/api/auth', 'auth_login'), ('GET', '/api/auth', 'auth_status'),
                                   ('POST', '/api/logout', 'auth_logout'), ('GET', '/api/config', 'get_config'),
                                   ('POST', '/api/config', 'update_config'),
                                   ('POST', '/api/admin-token', 'update_admin_token')]:
            routes = [route for route in api.router.routes if route.path == path and method in route.methods]
            self.assertEqual(len(routes), 1)
            self.assertIs(routes[0].endpoint, getattr(self.app, name))
            self.assertIs(getattr(api, name), getattr(self.app, name))

    def test_persisted_subscription_rotation_immediately_reaches_all_public_routes(self):
        value = 'fixture-rotated-subscription-token'
        result = self.client.post('/api/config', headers=self.headers, json={'SUBSCRIPTION_TOKEN': ' ' + value + ' '})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.app.SUBSCRIPTION_TOKEN, value)
        self.assertEqual(self.app.RUNTIME_STORE.subscription_token, value)
        with patch.object(self.app, 'load_rule_resource', return_value='domain_set: []\n'), \
                patch.object(self.app, 'load_airports', return_value=[]):
            for path, extra, status in [('/sub', {}, 200), ('/provider/0', {}, 404),
                                        ('/egern/ruleset/geosite', {'value': 'cn'}, 200)]:
                self.assertEqual(self.client.get(path, params={'token': TEST_SUBSCRIPTION_TOKEN, **extra}).status_code, 401)
                self.assertEqual(self.client.get(path, params={'token': value, **extra}).status_code, status)

    def test_admin_rotation_invalidates_old_identity_and_renews_session(self):
        self.assertEqual(self.client.post('/api/auth', json={'token': TEST_ADMIN_TOKEN}).status_code, 200)
        old_cookie = self.client.cookies.get(self.app.SESSION_COOKIE_NAME)
        value = 'fixture-new-management-token'
        result = self.client.post('/api/admin-token', json={'ADMIN_TOKEN': value}, headers={'Origin': 'http://testserver'})
        self.assertEqual(result.status_code, 200)
        self.assertNotEqual(self.client.cookies.get(self.app.SESSION_COOKIE_NAME), old_cookie)
        self.assertEqual(self.client.get('/api/config').status_code, 200)
        self.assertEqual(self.client.get('/api/config', headers={
            'Cookie': self.app.SESSION_COOKIE_NAME + '=' + old_cookie}).status_code, 401)
        with TestClient(self.app.app) as bearer_client:
            self.assertEqual(bearer_client.get('/api/config', headers=self.headers).status_code, 401)
            self.assertEqual(bearer_client.get('/api/config', headers={
                'Authorization': 'Bearer ' + value}).status_code, 200)

    def test_cookie_write_same_origin_and_bearer_policy_remain_shared(self):
        self.assertEqual(self.client.post('/api/auth', json={'token': TEST_ADMIN_TOKEN}).status_code, 200)
        cookie = self.client.cookies.get(self.app.SESSION_COOKIE_NAME)
        for path, body in [('/api/logout', {}), ('/api/config', {'SUBSCRIPTION_TOKEN': 'fixture-rejected-token'}),
                           ('/api/admin-token', {'ADMIN_TOKEN': 'fixture-rejected-admin-token'})]:
            result = self.client.post(path, json=body, headers={'Origin': 'https://unrelated.example',
                                                               'Cookie': self.app.SESSION_COOKIE_NAME + '=' + cookie})
            self.assertEqual(result.status_code, 403)
        self.assertEqual(self.app.SUBSCRIPTION_TOKEN, TEST_SUBSCRIPTION_TOKEN)
        self.assertTrue(self.app.RUNTIME_STORE.verify_admin_token(TEST_ADMIN_TOKEN))
        with TestClient(self.app.app) as bearer_client:
            result = bearer_client.post('/api/logout', headers={**self.headers, 'Origin': 'https://unrelated.example'})
            self.assertEqual(result.status_code, 200)
