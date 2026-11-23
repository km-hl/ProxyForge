"""Tests for unified subscription node ordering persistence and APIs."""
from contextlib import contextmanager, nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import yaml

from proxyforge.nodes.ordering import (
    apply_node_order,
    load_node_order,
    node_sort_key,
    save_node_order,
    sync_manual_nodes_file_order,
    sync_manual_order_in_saved_order,
)
from test_api_integration import TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN, load_isolated_application


class NodeOrderingUnitTests(unittest.TestCase):
    def test_sort_keys_and_apply_node_order(self):
        manual_a = {'name': 'Manual-A', 'type': 'ss', 'server': 'a.example', 'port': 8388}
        manual_b = {'name': 'Manual-B', 'type': 'ss', 'server': 'b.example', 'port': 8388}
        managed = {
            'name': 'HK-Managed',
            'type': 'vless',
            'server': '1.2.3.4',
            'port': 443,
            '_managed_by': {'type': 'agent', 'agent_id': 'a1', 'deployment_id': 'dep1'},
        }
        chain = {
            'name': 'SG-Chain',
            'type': 'vless',
            'server': '5.6.7.8',
            'port': 443,
            '_managed_by': {'type': 'agent', 'agent_id': 'a1', 'chain_id': 'ch1'},
        }
        adopted = {
            'name': 'Adopted-1',
            'type': 'trojan',
            'server': '9.9.9.9',
            'port': 443,
            '_managed_by': {'type': 'adopted', 'agent_id': 'a2', 'adoption_id': 'ad1'},
        }

        self.assertEqual(node_sort_key(manual_a), 'manual:Manual-A')
        self.assertEqual(node_sort_key(managed), 'agent:dep1')
        self.assertEqual(node_sort_key(chain), 'chain:ch1')
        self.assertEqual(node_sort_key(adopted), 'adopted:ad1')

        nodes = [manual_a, manual_b, managed, chain, adopted]
        ordered = apply_node_order(nodes, ['chain:ch1', 'manual:Manual-B', 'agent:dep1'])
        self.assertEqual([n['name'] for n in ordered], ['SG-Chain', 'Manual-B', 'HK-Managed', 'Manual-A', 'Adopted-1'])
        # Empty order preserves input order untouched.
        self.assertEqual(apply_node_order(nodes, []), nodes)

    def test_sync_manual_order_in_saved_order_and_file_order(self):
        saved = ['agent:dep1', 'manual:M1', 'chain:ch1', 'manual:M2']
        self.assertEqual(
            sync_manual_order_in_saved_order(saved, ['M2', 'M1', 'M3']),
            ['agent:dep1', 'manual:M2', 'chain:ch1', 'manual:M1', 'manual:M3'],
        )
        self.assertEqual(sync_manual_order_in_saved_order([], ['M2', 'M1']), [])

        manual = [{'name': 'M1'}, {'name': 'M2'}, {'name': 'M3'}]
        self.assertEqual(
            [n['name'] for n in sync_manual_nodes_file_order(manual, ['agent:dep1', 'manual:M2', 'manual:M1'])],
            ['M2', 'M1', 'M3'],
        )

    def test_load_and_save_node_order_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'node_order.json'
            self.assertEqual(load_node_order(path), [])
            saved = save_node_order(path, ['agent:dep1', 'manual:A', 'agent:dep1', ''])
            self.assertEqual(saved, ['agent:dep1', 'manual:A'])
            self.assertEqual(load_node_order(path), ['agent:dep1', 'manual:A'])


class NodeOrderingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}

    def test_auth_and_same_origin_enforcement(self):
        self.assertEqual(self.client.get('/api/nodes/order').status_code, 401)
        self.assertEqual(
            self.client.get('/api/nodes/order', headers={'Authorization': 'Bearer ' + TEST_SUBSCRIPTION_TOKEN}).status_code,
            401,
        )
        self.assertEqual(
            self.client.put('/api/nodes/order', json={'order': []}).status_code,
            401,
        )

        self.assertEqual(self.client.post('/api/auth', json={'token': TEST_ADMIN_TOKEN}).status_code, 200)
        self.assertEqual(
            self.client.put('/api/nodes/order', json={'order': []}, headers={'Origin': 'https://foreign.example'}).status_code,
            403,
        )
        self.assertEqual(
            self.client.put('/api/nodes/order', json={'order': []}, headers={'Origin': 'http://testserver'}).status_code,
            200,
        )

    def test_storage_unavailable_returns_sanitized_503(self):
        @contextmanager
        def unavailable(*args, **kwargs):
            raise OSError('secret-disk-detail')
            yield

        with patch.object(self.app.TemplateStore, 'locked', unavailable):
            for method, body in [('GET', None), ('PUT', {'order': []})]:
                res = self.client.request(method, '/api/nodes/order', headers=self.headers,
                                          **({'json': body} if body is not None else {}))
                self.assertEqual(res.status_code, 503)
                self.assertEqual(res.json()['detail']['code'], 'storage_unavailable')
                self.assertNotIn('secret-disk-detail', res.text)

    def test_mixed_order_persists_into_subscriptions_and_syncs_manual_order(self):
        manual_1 = {'name': 'Alpha Manual', 'type': 'ss', 'server': '1.2.3.4', 'port': 8388,
                    'cipher': 'aes-256-gcm', 'password': 'pw1'}
        manual_2 = {'name': 'Zulu Manual', 'type': 'ss', 'server': '5.6.7.8', 'port': 8388,
                    'cipher': 'aes-256-gcm', 'password': 'pw2'}
        self.assertEqual(
            self.client.post('/api/nodes', headers=self.headers, json={'nodes': [manual_1, manual_2]}).status_code,
            200,
        )

        managed_hk = {
            'name': 'HK Node',
            'type': 'ss',
            'server': '18.167.252.31',
            'port': 12201,
            'cipher': '2022-blake3-aes-256-gcm',
            'password': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            'udp': True,
            '_managed_by': {'type': 'agent', 'agent_id': 'a1', 'deployment_id': 'dep-hk'},
        }
        managed_jp = {
            'name': 'JP Node',
            'type': 'ss',
            'server': '3.114.222.104',
            'port': 12003,
            'cipher': '2022-blake3-aes-256-gcm',
            'password': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
            'udp': True,
            '_managed_by': {'type': 'agent', 'agent_id': 'a2', 'deployment_id': 'dep-jp'},
        }

        self.app.save_template_content(yaml.safe_dump({
            'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'include-all': True}],
            'rules': ['MATCH,Proxy'],
        }, allow_unicode=True, sort_keys=False))

        with patch.object(self.app, 'managed_nodes', return_value=[managed_hk, managed_jp]):
            initial = self.client.get('/api/nodes/order', headers=self.headers).json()
            self.assertEqual(initial['has_custom_order'], False)
            self.assertEqual(
                [item['key'] for item in initial['items']],
                ['manual:Alpha Manual', 'manual:Zulu Manual', 'agent:dep-hk', 'agent:dep-jp'],
            )
            # Ensure no secrets leak into /api/nodes/order
            self.assertNotIn('password', str(initial))

            new_order = ['agent:dep-jp', 'manual:Zulu Manual', 'agent:dep-hk', 'manual:Alpha Manual']
            put_res = self.client.put('/api/nodes/order', headers=self.headers, json={'order': new_order})
            self.assertEqual(put_res.status_code, 200, put_res.text)
            self.assertEqual(put_res.json()['order'], new_order)
            self.assertEqual(put_res.json()['has_custom_order'], True)

            # Subscription output (Mihomo YAML + group expansion) follows exact custom order.
            sub_res = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN})
            self.assertEqual(sub_res.status_code, 200)
            cfg = yaml.safe_load(sub_res.text)
            expected_names = ['🇯🇵 JP Node', 'Zulu Manual', '🇭🇰 HK Node', 'Alpha Manual']
            self.assertEqual([p['name'] for p in cfg['proxies']], expected_names)
            self.assertEqual(cfg['proxy-groups'][0]['proxies'], expected_names)

            # Renaming a managed node keeps its position because ordering keys by deployment_id.
            managed_jp['name'] = 'TYO Renamed'
            sub_res_renamed = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN})
            cfg_renamed = yaml.safe_load(sub_res_renamed.text)
            self.assertEqual([p['name'] for p in cfg_renamed['proxies']],
                             ['TYO Renamed', 'Zulu Manual', '🇭🇰 HK Node', 'Alpha Manual'])

            # Dragging manual nodes via POST /api/nodes updates manual slots without scrambling agent positions.
            self.assertEqual(
                self.client.post('/api/nodes', headers=self.headers, json={'nodes': [manual_1, manual_2]}).status_code,
                200,
            )
            after_manual_reorder = self.client.get('/api/nodes/order', headers=self.headers).json()
            self.assertEqual(
                after_manual_reorder['order'],
                ['agent:dep-jp', 'manual:Alpha Manual', 'agent:dep-hk', 'manual:Zulu Manual'],
            )

            # Reset restores default order (manual first, then managed).
            reset_res = self.client.put('/api/nodes/order', headers=self.headers, json={'order': []})
            self.assertEqual(reset_res.status_code, 200)
            self.assertEqual(reset_res.json()['has_custom_order'], False)
            self.assertEqual(
                reset_res.json()['order'],
                ['manual:Alpha Manual', 'manual:Zulu Manual', 'agent:dep-jp', 'agent:dep-hk']
                if False else ['manual:Alpha Manual', 'manual:Zulu Manual', 'agent:dep-hk', 'agent:dep-jp'],
            )


if __name__ == '__main__':
    unittest.main()
