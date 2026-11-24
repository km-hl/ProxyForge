"""Tests for Phase 3 multi-user subscription quota/cutoff, prefer_relay, and multi-client renderers."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from fastapi.testclient import TestClient
import yaml

from proxyforge.subscription.builder import build_subscription_config
from proxyforge.subscription.links import parse_share_link, render_proxy_uri, render_uri_subscription
from proxyforge.subscription.singbox import build_singbox_config
from proxyforge.subscription.surge import build_surge_config
from test_agent_control import metadata
from test_api_integration import TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN, load_isolated_application


SAMPLE_PROXIES = [
    {
        'name': 'HK Reality',
        'type': 'vless',
        'server': '203.0.113.10',
        'port': 443,
        'uuid': '11111111-2222-3333-4444-555555555555',
        'tls': True,
        'servername': 'www.microsoft.com',
        'client-fingerprint': 'chrome',
        'flow': 'xtls-rprx-vision',
        'reality-opts': {'public-key': 'A' * 43, 'short-id': '0123456789abcdef'},
        'udp': True,
    },
    {
        'name': 'SG Trojan',
        'type': 'trojan',
        'server': '203.0.113.20',
        'port': 8443,
        'password': 'trojan-secret-password',
        'sni': 'sg.example.com',
        'network': 'ws',
        'ws-opts': {'path': '/ws', 'headers': {'Host': 'sg.example.com'}},
        'udp': True,
    },
    {
        'name': 'JP SS',
        'type': 'ss',
        'server': '192.0.2.50',
        'port': 8388,
        'cipher': 'aes-256-gcm',
        'password': 'ss-secret-password',
        'udp': True,
    },
    {
        'name': 'US Hy2',
        'type': 'hysteria2',
        'server': '198.51.100.40',
        'port': 4433,
        'password': 'hy2-secret-password',
        'sni': 'us.example.com',
        'obfs': 'salamander',
        'obfs-password': 'obfs-secret-password',
        'udp': True,
    },
]

SAMPLE_TEMPLATE = {
    'proxy-groups': [
        {'name': 'Proxy', 'type': 'select', 'use': ['_custom_nodes_']},
        {'name': 'Media', 'type': 'select', 'use': ['_custom_nodes_'], 'filter': 'SG|JP'},
    ],
    'rules': [
        'DOMAIN-SUFFIX,openai.com,Proxy',
        'DOMAIN-KEYWORD,netflix,Media',
        'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
        'MATCH,Proxy',
    ],
}


class Phase3ExportersUnitTest(unittest.TestCase):
    def test_singbox_surge_and_uri_exporters_and_round_trip(self):
        cfg = build_subscription_config(SAMPLE_TEMPLATE, SAMPLE_PROXIES, [], 'https://sub.example', 'tok')

        sb_doc, sb_skipped = build_singbox_config(cfg)
        self.assertEqual(sb_skipped, 0)
        types = {o['type'] for o in sb_doc['outbounds']}
        self.assertTrue({'selector', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'direct'}.issubset(types))
        vless_ob = next(o for o in sb_doc['outbounds'] if o['type'] == 'vless')
        self.assertTrue(vless_ob['tls']['reality']['enabled'])
        self.assertEqual(sb_doc['route']['final'], 'Proxy')

        surge_ini, surge_skipped = build_surge_config(cfg)
        self.assertEqual(surge_skipped, 1)  # VLESS Reality skipped cleanly in Surge INI
        self.assertIn('[General]', surge_ini)
        self.assertIn('= trojan, 203.0.113.20, 8443', surge_ini)
        self.assertIn('= ss, 192.0.2.50, 8388', surge_ini)
        self.assertIn('= hysteria2, 198.51.100.40, 4433', surge_ini)
        self.assertIn('FINAL,Proxy', surge_ini)

        b64_text, uri_skipped = render_uri_subscription(cfg['proxies'], encode_base64=True)
        self.assertEqual(uri_skipped, 0)
        raw_lines = base64.b64decode(b64_text).decode('utf-8').splitlines()
        self.assertEqual(len(raw_lines), 4)
        for line, orig in zip(raw_lines, cfg['proxies']):
            parsed = parse_share_link(line)
            self.assertIsNotNone(parsed, line)
            self.assertEqual(parsed['server'], orig['server'])
            self.assertEqual(parsed['port'], orig['port'])


class Phase3MultiUserAndPreferRelayIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = 2000000.0
        self.app = load_isolated_application(self.root)
        # Seed template and manual custom nodes
        (self.root / 'data' / 'template.yaml').write_text(yaml.safe_dump(SAMPLE_TEMPLATE, allow_unicode=True, sort_keys=False), encoding='utf-8')
        (self.root / 'data' / 'custom_nodes.yaml').write_text(yaml.safe_dump(SAMPLE_PROXIES, allow_unicode=True, sort_keys=False), encoding='utf-8')
        self.store = self.app.control_store()
        self.store.clock = lambda: self.now
        self.app.control_store = lambda: self.store
        self.admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        self.client = TestClient(self.app.app)

        reg = self.store.issue_registration('entry-hk')['registration_token']
        info = {
            **metadata('a' * 32),
            'job_protocol_version': 1,
            'runtime_protocol_version': 1,
            'gost_protocol_version': 1,
        }
        self.entry = self.store.register(reg, info, '198.51.100.7')
        self.store.heartbeat(self.entry['agent_token'], info, '198.51.100.7')
        self.entry_agent = {'agent_id': self.entry['agent_id'], 'token': self.entry['agent_token'], 'instance_id': 'a' * 32}

    def test_sub_user_quota_cutoff_userinfo_prefer_relay_and_formats(self):
        # Create two relay forward rules targeting HK Reality (203.0.113.10:443)
        f1 = self.client.post(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'relay30005',
            'listen_port': 30005,
            'targets': [{'addr': '203.0.113.10:443'}],
        }).json()
        f2 = self.client.post(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'relay30006',
            'listen_port': 30006,
            'targets': [{'addr': '203.0.113.10:443'}],
        }).json()
        # Drain all initial pending gost jobs so later cutoff sync job stands out clearly
        while True:
            j = self.store.claim_job(self.entry['agent_token'], 'a' * 32)
            if not j:
                break
            self.store.report_job(self.entry['agent_token'], j['id'], j['lease_token'])
            self.store.report_job(self.entry['agent_token'], j['id'], j['lease_token'], {
                'status': 'success', 'output': {'installed': True, 'running': True, 'version': '3.3.3', 'status': 'running'}, 'error': None,
            })

        # Unauthenticated /api/sub-users blocked
        self.assertEqual(self.client.get('/api/sub-users').status_code, 401)

        # Create multi-user bound to forward rule f1 with 5000 byte quota & allowed group Proxy
        user_resp = self.client.post('/api/sub-users', headers=self.admin, json={
            'username': 'alice',
            'quota_bytes': 5000,
            'expire_at': self.now + 3600,
            'prefer_relay': True,
            'allowed_groups': ['Proxy'],
            'forward_rule_ids': [f1['id']],
        })
        self.assertEqual(user_resp.status_code, 200, user_resp.text)
        user_data = user_resp.json()
        user_id = user_data['id']
        user_token = user_data['token']
        self.assertTrue(user_token.startswith('pfsub_'))

        # List endpoint never leaks plaintext user token; token revealed only via admin endpoint
        listed = self.client.get('/api/sub-users', headers=self.admin).text
        self.assertNotIn(user_token, listed)
        revealed = self.client.get(f'/api/sub-users/{user_id}/token', headers=self.admin).json()
        self.assertEqual(revealed['token'], user_token)

        # Fetch all 5 client targets with /sub/{user_token} -> verifies Subscription-Userinfo & prefer_relay
        res_mihomo = self.client.get(f'/sub/{user_token}?target=mihomo')
        self.assertEqual(res_mihomo.status_code, 200, res_mihomo.text)
        self.assertEqual(
            res_mihomo.headers['Subscription-Userinfo'],
            f'upload=0; download=0; total=5000; expire={int(self.now + 3600)}',
        )
        doc_mihomo = yaml.safe_load(res_mihomo.text)
        self.assertEqual([g['name'] for g in doc_mihomo['proxy-groups']], ['Proxy'])
        servers_ports = {(p['server'], p['port']) for p in doc_mihomo['proxies']}
        self.assertIn(('198.51.100.7', 30005), servers_ports)
        self.assertIn(('198.51.100.7', 30006), servers_ports)
        self.assertNotIn(('203.0.113.10', 443), servers_ports)

        res_sb = self.client.get(f'/sub/{user_token}?target=singbox')
        self.assertEqual(res_sb.status_code, 200)
        self.assertIn('30005', res_sb.text)
        self.assertIn('30006', res_sb.text)

        res_surge = self.client.get(f'/sub/{user_token}?target=surge')
        self.assertEqual(res_surge.status_code, 200)
        self.assertIn('[Proxy Group]', res_surge.text)

        res_uri = self.client.get(f'/sub/{user_token}?target=uri&raw=1')
        self.assertEqual(res_uri.status_code, 200)
        self.assertIn('@198.51.100.7:30005?', res_uri.text)
        self.assertIn('@198.51.100.7:30006?', res_uri.text)

        res_egern = self.client.get(f'/sub/{user_token}?target=egern')
        self.assertEqual(res_egern.status_code, 200)

        # Agent reports 6000 bytes on bound forward rule f1 -> crosses 5000 quota -> auto-disables user & f1 port
        upload_resp = self.client.post(
            '/api/agent/traffic',
            headers={'Authorization': 'Bearer ' + self.entry['agent_token']},
            json={
                'instance_id': 'a' * 32,
                'batch_id': uuid.uuid4().hex,
                'sequence': 1,
                'items': [{
                    'resource_key': f"forward:{f1['id']}",
                    'forward_rule_id': f1['id'],
                    'rx_delta': 2500,
                    'tx_delta': 3500,
                    'raw_rx': 2500,
                    'raw_tx': 3500,
                    'epoch': 'e1',
                }],
            },
        )
        self.assertEqual(upload_resp.status_code, 200)

        # Verify forward rule f1 disabled + Agent job queued without f1
        fwds = self.client.get(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin).json()['forwards']
        f1_now = next(item for item in fwds if item['id'] == f1['id'])
        f2_now = next(item for item in fwds if item['id'] == f2['id'])
        self.assertFalse(f1_now['enabled'])
        self.assertTrue(f2_now['enabled'])

        cutoff_job = self.store.claim_job(self.entry['agent_token'], 'a' * 32)
        self.assertIsNotNone(cutoff_job)
        self.assertEqual([f['id'] for f in cutoff_job['deployment']['forwards']], [f2['id']])

        # User subscription /sub/{user_token} now returns HTTP 200 placeholder notice (no real nodes) with updated Subscription-Userinfo
        denied = self.client.get(f'/sub/{user_token}')
        self.assertEqual(denied.status_code, 200)
        self.assertIn('upload=2500; download=3500; total=5000', denied.headers['Subscription-Userinfo'])
        self.assertIn('流量已用尽', denied.text)
        self.assertNotIn('198.51.100.7', denied.text)
        self.assertNotIn('203.0.113.10', denied.text)

        # Reset traffic re-enables user cleanly
        reset = self.client.post(f'/api/sub-users/{user_id}/reset-traffic', headers=self.admin)
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(reset.json()['used_bytes'], 0)
        self.assertTrue(reset.json()['enabled'])

        # Expiration triggers HTTP 200 expired notice (no real nodes) + port disable on next check
        self.now += 4000
        expired_denied = self.client.get(f'/sub/{user_token}')
        self.assertEqual(expired_denied.status_code, 200)
        self.assertIn('订阅已过期', expired_denied.text)
        self.assertNotIn('198.51.100.7', expired_denied.text)

        # Global token still works backward compatibly
        global_res = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN, 'prefer_relay': 'false'})
        self.assertEqual(global_res.status_code, 200)


if __name__ == '__main__':
    unittest.main()
