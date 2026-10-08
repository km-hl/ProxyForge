import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
import yaml

from scripts.generate_ci_config import isolated_application
from proxyforge.subscription.builder import build_subscription_config
from proxyforge.subscription.egern import (
    build_egern_config, convert_proxy, convert_rule_set, provider_revision, UnsupportedNode,
)
from proxyforge.subscription import egern_resources as resources
from proxyforge.subscription.validation import ConfigValidationError


def node(kind='vless', **extra):
    return {'name': 'HK Node', 'type': kind, 'server': 'proxy.example', 'port': 443,
            'uuid': '11111111-1111-4111-8111-111111111111', 'password': 'public-password',
            'tls': True, 'udp': True, **extra}


class EgernExportTests(unittest.TestCase):
    def config(self, proxies=None, rules=None):
        return {'proxies': proxies or [], 'proxy-groups': [
            {'name': 'Proxy', 'type': 'select', 'proxies': ['HK Node']}],
            'rules': rules or ['MATCH,Proxy']}

    def test_reality_ws_grpc_preserve_tls_identity_and_do_not_mutate(self):
        original = node(flow='xtls-rprx-vision', servername='tls.example',
                        **{'reality-opts': {'public-key': 'public-key', 'short-id': '0123'}})
        before = copy.deepcopy(original)
        reality = convert_proxy(original)['vless']
        self.assertEqual(reality['transport']['tls']['reality'], {'public_key': 'public-key', 'short_id': '0123'})
        self.assertEqual(reality['flow'], 'xtls-rprx-vision')
        self.assertFalse(reality['transport']['tls']['skip_tls_verify'])
        self.assertEqual(original, before)
        ws = convert_proxy(node('vmess', network='ws', **{'ws-opts': {
            'path': '/test', 'headers': {'Host': 'ws.example'}}}))['vmess']
        self.assertEqual(ws['transport']['wss']['headers']['Host'], 'ws.example')
        self.assertEqual(ws['security'], 'auto')
        grpc = convert_proxy(node(network='grpc', **{'grpc-opts': {'grpc-service-name': 'service'}}))['vless']
        self.assertEqual(grpc['transport']['grpc']['service_name'], 'service')
        with self.assertRaises(UnsupportedNode):
            convert_proxy(node(network='grpc', tls=False))

    def test_hy2_anytls_ss_tuic_socks_and_wireguard_fields(self):
        hy2 = convert_proxy(node('hysteria2', sni='tls.example', ports='20000-30000', up='50 Mbps',
                                 **{'obfs': 'salamander', 'obfs-password': 'obfs-password'}))['hysteria2']
        self.assertEqual(hy2['auth'], 'public-password')
        self.assertEqual(hy2['obfs_password'], 'obfs-password')
        self.assertEqual(hy2['bandwidth'], 50)
        self.assertEqual(hy2['port_hopping'], '20000-30000')
        self.assertFalse(convert_proxy(node('anytls'))['anytls']['skip_tls_verify'])
        ss = convert_proxy(node('ss', cipher='aes-128-gcm', plugin='obfs',
                                **{'plugin-opts': {'mode': 'tls', 'host': 'obfs.example'}}))['shadowsocks']
        self.assertEqual(ss['method'], 'aes-128-gcm')
        self.assertEqual(ss['obfs_host'], 'obfs.example')
        self.assertEqual(convert_proxy(node('tuic', alpn=['h3']))['tuic']['alpn'], ['h3'])
        self.assertIn('socks5_tls', convert_proxy(node('socks5')))
        self.assertIn('https', convert_proxy(node('http')))
        wireguard = convert_proxy(node('wireguard', ip='10.0.0.2', **{
            'private-key': 'private-placeholder', 'public-key': 'public-placeholder'}))['wireguard']
        self.assertEqual(wireguard['local_ipv4'], '10.0.0.2/32')

    def test_unsupported_transport_is_withheld_and_references_blocked(self):
        bad = node(network='xhttp')
        good = node('hysteria2', name='Fallback')
        config = self.config([bad, good], ['DOMAIN,private.example,HK Node', 'MATCH,Proxy'])
        before = copy.deepcopy(config)
        output, skipped = build_egern_config(config, {}, 'https://example.com', 'test-token')
        self.assertEqual(skipped, 1)
        self.assertEqual(output['policy_groups'][0]['select']['policies'], ['REJECT'])
        self.assertEqual(output['rules'][0]['domain']['policy'], 'REJECT')
        self.assertEqual(config, before)
        self.assertNotIn('xhttp', yaml.safe_dump(output))
        with self.assertRaises(ConfigValidationError):
            build_egern_config(self.config([bad]), {}, 'https://example.com', 'test-token')

    def test_provider_filter_order_and_empty_group_fail_closed(self):
        config = self.config([node()])
        config['proxy-groups'] = [
            {'name': 'Proxy', 'type': 'url-test', 'proxies': ['HK Node'], 'use': ['Airport'],
             'filter': 'JP', 'timeout': 2500, 'interval': 300},
            {'name': 'Empty', 'type': 'select', 'use': ['Airport'], 'filter': 'never-match'}]
        output, _ = build_egern_config(config, {'Airport': [node(name='Airport | JP'), node(name='Airport | HK')]},
                                        'https://example.com', 'test-token')
        self.assertEqual(output['policy_groups'][0]['auto_test']['policies'], ['HK Node', 'Airport | JP'])
        self.assertEqual(output['policy_groups'][0]['auto_test']['timeout'], 3)
        self.assertEqual(output['policy_groups'][1]['select']['policies'], ['REJECT'])

    def test_rules_preserve_order_logical_conditions_and_remote_revision(self):
        rules = ['DOMAIN-SUFFIX,example.com,Proxy', 'GEOIP,cn,DIRECT,no-resolve',
                 'GEOSITE,google,Proxy', 'GEOIP,private,DIRECT,no-resolve',
                 'RULE-SET,Example,REJECT', 'AND,((DOMAIN,a.example),(NETWORK,UDP)),Proxy', 'MATCH,Proxy']
        config = self.config([node()], rules)
        config['rule-providers'] = {'Example': {'type': 'http', 'url': 'https://rules.example/list.yaml',
                                             'behavior': 'classical'}}
        output, _ = build_egern_config(config, {}, 'https://example.com', 'test&token')
        self.assertEqual([next(iter(r)) for r in output['rules']],
                         ['domain_suffix', 'geoip', 'rule_set', 'rule_set', 'rule_set', 'and', 'default'])
        self.assertTrue(output['rules'][1]['geoip']['no_resolve'])
        self.assertEqual(output['rules'][1]['geoip']['match'], 'CN')
        params = parse_qs(urlsplit(output['rules'][3]['rule_set']['match']).query)
        self.assertEqual(params['no_resolve'], ['true'])
        params = parse_qs(urlsplit(output['rules'][4]['rule_set']['match']).query)
        self.assertEqual(params['token'], ['test&token'])
        self.assertEqual(params['revision'], [provider_revision(config['rule-providers']['Example'])])
        self.assertEqual(output['rules'][5]['and']['match'][1]['protocol']['match'], 'udp')
        for invalid in ('PROCESS-NAME,secret-canary,Proxy', 'DOMAIN,example.com,Proxy,unsupported'):
            with self.assertRaises(ConfigValidationError) as error:
                build_egern_config(self.config([node()], [invalid]), {}, 'https://example.com', 'test-token')
            self.assertNotIn('secret-canary', str(error.exception))

    def test_rule_set_domain_cidr_and_classical_conversion(self):
        domain = convert_rule_set('payload: ["+.example.com", "*.example.net", "exact.example"]', 'domain')
        self.assertEqual(domain['domain_suffix_set'], ['example.com'])
        self.assertEqual(domain['domain_wildcard_set'], ['*.example.net'])
        self.assertEqual(domain['domain_set'], ['exact.example'])
        cidr = convert_rule_set('10.0.0.0/8\n2001:db8::/32\n', 'ipcidr', 'text')
        self.assertIn('ip_cidr6_set', cidr)
        classical = convert_rule_set('payload: ["DOMAIN,a.example", "IP-CIDR,10.0.0.0/8,no-resolve"]')
        self.assertTrue(classical['or_set'][0][0]['ip_cidr']['no_resolve'])
        with self.assertRaises(ConfigValidationError):
            convert_rule_set('payload: ["PROCESS-NAME,secret-canary"]')

    def test_airport_provider_expansion_uses_namespaced_decorated_snapshot(self):
        airports = [{'name': 'Airport', 'url': 'https://airport.example/sub'}]
        template = {'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'include-all': True}], 'rules': ['MATCH,Proxy']}
        built = build_subscription_config(template, [], airports, 'https://example.com', 'test-token')
        with patch.object(resources, 'safe_get', side_effect=AssertionError('must reuse airport snapshot')):
            providers = resources.resolve_provider_nodes(built, airports,
                [node(name='HK', _airport_name='Airport')], 'https://example.com', 'test-token')
        output, _ = build_egern_config(built, providers, 'https://example.com', 'test-token')
        name = output['proxies'][0]['vless']['name']
        self.assertTrue(name.startswith('Airport | '))
        self.assertEqual(output['policy_groups'][0]['select']['policies'], [name])


class EgernResourceTests(unittest.TestCase):
    def setUp(self):
        with resources._lock:
            resources._cache.clear()

    def test_geosite_download_is_bounded_pinned_and_cached(self):
        response = SimpleNamespace(content=b'payload: ["+.example.com"]', raise_for_status=lambda: None)
        with patch.object(resources, 'safe_get', return_value=response) as get:
            first = resources.load_rule_resource('geosite', 'google', {})
            self.assertEqual(first, resources.load_rule_resource('geosite', 'google', {}))
            self.assertEqual(get.call_count, 1)
            self.assertEqual(get.call_args.kwargs['total_timeout'], 30)
            self.assertEqual(get.call_args.kwargs['max_response_bytes'], 8 * 1024 * 1024)
            self.assertTrue(get.call_args.args[0].startswith('https://raw.githubusercontent.com/MetaCubeX/'))
        for category in ('../secret', 'https://127.0.0.1', 'google/../../secret'):
            with patch.object(resources, 'safe_get', side_effect=AssertionError('must not fetch')):
                with self.assertRaises(ConfigValidationError):
                    resources.load_rule_resource('geosite', category, {})

    def test_changed_provider_and_mrs_are_rejected_before_network(self):
        provider = {'type': 'http', 'url': 'https://example.com/rules', 'behavior': 'domain', 'format': 'mrs'}
        with patch.object(resources, 'safe_get', side_effect=AssertionError('must not fetch')):
            for revision in ('wrong', provider_revision(provider)):
                with self.assertRaises(ConfigValidationError):
                    resources.load_rule_resource('provider', 'Example', {'Example': provider}, revision)


    def test_legacy_lan_uses_private_ip_resource_and_preserves_no_resolve(self):
        response = SimpleNamespace(content=b'payload: ["10.0.0.0/8", "fc00::/7"]', raise_for_status=lambda: None)
        with patch.object(resources, 'safe_get', return_value=response) as get:
            result = yaml.safe_load(resources.load_rule_resource('geoip', 'lan', {}, no_resolve=True))
            self.assertTrue(get.call_args.args[0].endswith('/geoip/private.yaml'))
            self.assertEqual(result['ip_cidr_set'], ['10.0.0.0/8'])
            self.assertTrue(result['no_resolve'])


class EgernApiTests(unittest.TestCase):
    def test_native_and_legacy_exports_and_auth_without_touching_local_data(self):
        template = {'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'use': ['_custom_nodes_']}],
                    'rules': ['DOMAIN-SUFFIX,example.com,Proxy', 'MATCH,Proxy'],
                    'dns': {'enable': False}, 'tun': {'enable': False}}
        with isolated_application() as application, \
                patch.object(application, 'cleanup_runtime_template_references'), \
                patch.object(application, 'subscription_airports', return_value=([], [])), \
                patch.object(application, 'load_custom_nodes', return_value=[node(), node(name='Unsupported', network='xhttp')]), \
                patch.object(application, 'load_template_content', return_value=yaml.safe_dump(template)), \
                patch.object(application, 'managed_node_names', return_value=[]):
            client = TestClient(application.app)
            token = application.SUBSCRIPTION_TOKEN
            self.assertEqual(client.get('/sub', params={'token': 'bad', 'format': 'egern'}).status_code, 401)
            self.assertEqual(client.get('/egern/ruleset/geosite', params={'token': 'bad', 'value': 'google'}).status_code, 401)
            self.assertEqual(client.get('/sub', params={'token': token, 'format': 'invalid'}).status_code, 400)
            legacy = client.get('/sub', params={'token': token})
            self.assertEqual(legacy.status_code, 200)
            self.assertIn('proxy-groups', yaml.safe_load(legacy.text))
            native = client.get('/sub', params={'token': token, 'format': 'egern'})
            self.assertEqual(native.status_code, 200, native.text)
            result = yaml.safe_load(native.text)
            self.assertEqual(set(result), {'proxies', 'policy_groups', 'rules'})
            self.assertEqual(native.headers['ProxyForge-Skipped-Nodes'], '1')
            self.assertEqual(native.headers['Cache-Control'], 'no-store')
            self.assertNotIn('_managed_by', native.text)
            with patch.object(application, 'resolve_provider_nodes', side_effect=RuntimeError('secret-canary')), \
                    patch.object(application.logger, 'warning') as warning, \
                    patch.object(application.logger, 'error') as error:
                response = client.get('/sub', params={'token': token, 'format': 'egern'})
                self.assertEqual(response.status_code, 502)
                self.assertNotIn('secret-canary', response.text)
                self.assertNotIn('secret-canary', str(warning.call_args))
                error.assert_not_called()
            with patch.object(application, 'load_rule_resource', return_value='domain_suffix_set: [example.com]\n'):
                response = client.get('/egern/ruleset/geosite', params={'token': token, 'value': 'google'})
                self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
