"""Tests for Phase 10.4 minimal multi-user subscription, anti-leak DNS, UA detection, and notice nodes."""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from fastapi.testclient import TestClient
import yaml

from proxyforge.subscription.minimal_profile import (
    build_disabled_notice,
    build_info_notices,
    detect_target_from_user_agent,
    format_notice_bytes,
)
from test_agent_control import metadata
from test_api_integration import TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN, load_isolated_application


class MinimalProfileUnitTest(unittest.TestCase):
    def test_ua_detection_across_clients(self):
        self.assertEqual(detect_target_from_user_agent('Clash-Verge/2.0.0'), 'mihomo')
        self.assertEqual(detect_target_from_user_agent('mihomo/1.19'), 'mihomo')
        self.assertEqual(detect_target_from_user_agent('Stash/2.6'), 'mihomo')
        self.assertEqual(detect_target_from_user_agent('sing-box 1.12.0'), 'singbox')
        self.assertEqual(detect_target_from_user_agent('SFA/1.12.0'), 'singbox')
        self.assertEqual(detect_target_from_user_agent('SFI/1.12.0'), 'singbox')
        self.assertEqual(detect_target_from_user_agent('SFM/1.12.0'), 'singbox')
        self.assertEqual(detect_target_from_user_agent('HiddifyNext/2.5'), 'singbox')
        self.assertEqual(detect_target_from_user_agent('Surge/5.8.0'), 'surge')
        self.assertEqual(detect_target_from_user_agent('Egern/2.14.0'), 'egern')
        self.assertEqual(detect_target_from_user_agent('Shadowrocket/2.2.50'), 'uri')
        self.assertEqual(detect_target_from_user_agent('v2rayN/6.50'), 'uri')
        # Safari must NOT match SFA
        self.assertEqual(detect_target_from_user_agent('Mozilla/5.0 AppleWebKit/605 Safari/605.1'), 'mihomo')
        self.assertEqual(detect_target_from_user_agent(''), 'mihomo')

    def test_notice_formatting_avoids_space_before_gb(self):
        self.assertEqual(format_notice_bytes(0), '0B')
        self.assertEqual(format_notice_bytes(70 * 1024 ** 3), '70.00GB')
        self.assertNotIn(' GB', format_notice_bytes(70 * 1024 ** 3))

        exp_ts = datetime(2026, 12, 31, 0, 0, tzinfo=timezone.utc).timestamp()
        notices = build_info_notices({
            'expire_at': exp_ts,
            'quota_bytes': 100 * 1024 ** 3,
            'upload_bytes': 10 * 1024 ** 3,
            'download_bytes': 20 * 1024 ** 3,
        })
        self.assertEqual(notices[0], '⏳ 到期 2026-12-31')
        self.assertEqual(notices[1], '📊 剩余 70.00GB/100.00GB')
        self.assertEqual(build_disabled_notice('expired'), '⚠️ 订阅已过期')
        self.assertEqual(build_disabled_notice('quota_exceeded'), '⚠️ 流量已用尽')
        self.assertEqual(build_disabled_notice('disabled'), '⚠️ 订阅已停用')


class MinimalSubscriptionIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc).timestamp()
        self.app = load_isolated_application(self.root)
        (self.root / 'data' / 'custom_nodes.yaml').write_text(
            yaml.safe_dump(
                [{
                    'name': 'Manual-SG',
                    'type': 'ss',
                    'server': '198.51.100.99',
                    'port': 8388,
                    'cipher': 'aes-256-gcm',
                    'password': 'manual-shared-password',
                }],
                allow_unicode=True,
                sort_keys=False,
            ),
            encoding='utf-8',
        )
        self.store = self.app.control_store()
        self.store.clock = lambda: self.now
        self.app.control_store = lambda: self.store
        self.admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        self.client = TestClient(self.app.app)

        reg = self.store.issue_registration('jp-node')['registration_token']
        info = {
            **metadata('c' * 32),
            'job_protocol_version': 1,
            'runtime_protocol_version': 1,
            'deployment_protocol_version': 1,
            'landing_protocol_version': 1,
            'gost_protocol_version': 1,
            'self_upgrade_protocol_version': 1,
            'nftables_capable': True,
        }
        self.agent = self.store.register(reg, info, '203.0.113.60')
        self.store.heartbeat(self.agent['agent_token'], info, '203.0.113.60')

    def _drain_jobs(self):
        out = []
        while True:
            job = self.store.claim_job(self.agent['agent_token'], 'c' * 32)
            if not job:
                break
            self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'])
            self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'], {
                'status': 'success',
                'output': {'installed': True, 'running': True, 'version': '1.14.0', 'status': 'running'},
                'error': None,
            })
            out.append(job)
        return out

    def test_minimal_subscription_5_formats_ua_creds_relay_and_disabled_notice(self):
        aid = self.agent['agent_id']
        r_rel = self.client.post(f'/api/agents/{aid}/nodes', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'protocol': 'reality',
            'settings': {
                'name': 'JP-Reality',
                'server': '203.0.113.60',
                'listen_port': 443,
                'tls_mode': 'reality',
                'domain': 'www.amazon.com',
            },
        })
        self.assertEqual(r_rel.status_code, 200, r_rel.text)
        rel_id = r_rel.json()['node_id']
        self._drain_jobs()

        r_tr = self.client.post(f'/api/agents/{aid}/nodes', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'protocol': 'trojan',
            'settings': {
                'name': 'JP-Trojan',
                'server': '203.0.113.60',
                'listen_port': 8443,
                'tls_mode': 'acme_http',
                'domain': 'jp.example.com',
            },
        })
        self.assertEqual(r_tr.status_code, 200, r_tr.text)
        tr_id = r_tr.json()['node_id']
        self._drain_jobs()

        # Add relay with rewrite_subscription=True targeting JP-Reality (203.0.113.60:443)
        fwd = self.client.post(f'/api/agents/{aid}/forwards', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'relay-jp',
            'listen_port': 21443,
            'targets': [{'addr': '203.0.113.60:443'}],
            'rewrite_subscription': True,
        })
        self.assertEqual(fwd.status_code, 200, fwd.text)
        self._drain_jobs()

        # Capture admin credentials from managed_nodes() to prove user gets independent ones
        admin_nodes = self.store.managed_nodes()
        admin_vless = next(n for n in admin_nodes if n['type'] == 'vless')
        admin_trojan = next(n for n in admin_nodes if n['type'] == 'trojan')

        exp_ts = datetime(2026, 6, 30, 0, 0, tzinfo=timezone.utc).timestamp()
        u_resp = self.client.post('/api/sub-users', headers=self.admin, json={
            'username': 'charlie',
            'quota_bytes': 100 * 1024 ** 3,
            'expire_at': exp_ts,
            'allowed_nodes': [f'agent::{aid}::{rel_id}', f'agent::{aid}::{tr_id}', 'manual::Manual-SG'],
            'info_nodes': True,
            'reset_day': 1,
        })
        self.assertEqual(u_resp.status_code, 200, u_resp.text)
        user = u_resp.json()
        tok = user['token']
        pushed_jobs = self._drain_jobs()
        pushed_uuid = pushed_jobs[0]['deployment']['sub_users'][0]['uuid']
        pushed_pw = next(e for e in pushed_jobs[0]['deployment']['extra_nodes'] if e['node_id'] == tr_id)['sub_users'][0]['password']

        # 1. Mihomo (auto-detected via Clash-Verge UA)
        res_m = self.client.get(f'/sub/{tok}', headers={'User-Agent': 'Clash-Verge/2.0'})
        self.assertEqual(res_m.status_code, 200, res_m.text)
        self.assertIn('Subscription-Userinfo', res_m.headers)
        doc_m = yaml.safe_load(res_m.text)
        self.assertEqual([g['name'] for g in doc_m['proxy-groups']], ['节点选择', '自动选择'])
        self.assertEqual(doc_m['dns']['enhanced-mode'], 'fake-ip')
        self.assertTrue(doc_m['dns']['respect-rules'])
        self.assertTrue(doc_m['sniffer']['enable'])
        self.assertIn('geosite:private,cn', doc_m['dns']['nameserver-policy'])
        self.assertEqual(doc_m['rules'], [
            'GEOIP,LAN,DIRECT,no-resolve',
            'GEOSITE,private,DIRECT',
            'GEOSITE,cn,DIRECT',
            'GEOIP,cn,DIRECT,no-resolve',
            'MATCH,节点选择',
        ])

        # Verify info notice nodes are in 节点选择 only, NOT 自动选择
        select_members = doc_m['proxy-groups'][0]['proxies']
        auto_members = doc_m['proxy-groups'][1]['proxies']
        self.assertTrue(any('⏳ 到期 2026-06-30' in m for m in select_members))
        self.assertTrue(any('📊 剩余 100.00GB/100.00GB' in m for m in select_members))
        self.assertFalse(any('⏳' in m or '📊' in m for m in auto_members))

        # Verify independent credentials substituted & relay rewrite applied automatically!
        vless_p = next(p for p in doc_m['proxies'] if p['type'] == 'vless')
        trojan_p = next(p for p in doc_m['proxies'] if p['type'] == 'trojan')
        manual_p = next(p for p in doc_m['proxies'] if p['type'] == 'ss' and p['port'] == 8388)
        self.assertEqual(vless_p['uuid'], pushed_uuid)
        self.assertNotEqual(vless_p['uuid'], admin_vless['uuid'])
        self.assertEqual(vless_p['port'], 21443)  # auto-rewritten by rewrite_subscription relay!
        self.assertEqual(trojan_p['password'], pushed_pw)
        self.assertNotEqual(trojan_p['password'], admin_trojan['password'])
        self.assertEqual(manual_p['password'], 'manual-shared-password')

        # 2. Sing-box (auto-detected via SFA UA) — verify domestic DNS split rule!
        res_sb = self.client.get(f'/sub/{tok}', headers={'User-Agent': 'SFA/1.12.0'})
        self.assertEqual(res_sb.status_code, 200, res_sb.text)
        sb = json.loads(res_sb.text)
        dns_rule_sets = [r.get('rule_set') for r in sb['dns']['rules'] if 'rule_set' in r]
        self.assertTrue(any('geosite-cn' in rs and 'geosite-private' in rs for rs in dns_rule_sets))
        sb_vless = next(o for o in sb['outbounds'] if o['type'] == 'vless')
        self.assertEqual(sb_vless['uuid'], pushed_uuid)

        # 3. Surge (auto-detected via Surge UA)
        res_sg = self.client.get(f'/sub/{tok}', headers={'User-Agent': 'Surge/5.8.0'})
        self.assertEqual(res_sg.status_code, 200, res_sg.text)
        self.assertIn('[Proxy Group]', res_sg.text)
        self.assertIn('节点选择 = select', res_sg.text)
        self.assertIn(pushed_pw, res_sg.text)
        self.assertIn('FINAL,节点选择', res_sg.text)

        # 4. Egern (auto-detected via Egern UA)
        res_eg = self.client.get(f'/sub/{tok}', headers={'User-Agent': 'Egern/2.14'})
        self.assertEqual(res_eg.status_code, 200, res_eg.text)
        self.assertIn('policy_groups:', res_eg.text)
        self.assertIn(pushed_uuid, res_eg.text)

        # 5. URI (auto-detected via Shadowrocket UA)
        res_uri = self.client.get(f'/sub/{tok}', headers={'User-Agent': 'Shadowrocket/2.2'})
        self.assertEqual(res_uri.status_code, 200, res_uri.text)
        decoded_uri = base64.b64decode(res_uri.text.strip()).decode('utf-8')
        self.assertIn(pushed_uuid, decoded_uri)
        self.assertIn(pushed_pw, decoded_uri)

        # Disable info_nodes -> no ⏳/📊 placeholders
        self.client.patch(f"/api/sub-users/{user['id']}", headers=self.admin, json={'info_nodes': False})
        res_no_info = self.client.get(f'/sub/{tok}?target=mihomo')
        self.assertNotIn('⏳', res_no_info.text)
        self.assertNotIn('📊', res_no_info.text)

        # Disable user -> HTTP 200 placeholder notice across ALL 5 formats, ZERO real servers or creds!
        self.client.patch(f"/api/sub-users/{user['id']}", headers=self.admin, json={'enabled': False})
        self._drain_jobs()
        for fmt in ('mihomo', 'singbox', 'surge', 'egern', 'uri'):
            r_dis = self.client.get(f'/sub/{tok}?target={fmt}&raw=1')
            self.assertEqual(r_dis.status_code, 200, f'{fmt}: {r_dis.text}')
            self.assertIn('Subscription-Userinfo', r_dis.headers)
            self.assertNotIn(pushed_uuid, r_dis.text)
            self.assertNotIn(pushed_pw, r_dis.text)
            self.assertNotIn('203.0.113.60', r_dis.text)
            self.assertNotIn('198.51.100.99', r_dis.text)
            if fmt != 'uri':
                self.assertIn('订阅已停用', r_dis.text)

        # Unknown token -> 401
        self.assertEqual(self.client.get('/sub/pfsub_invalid_token_1234567890').status_code, 401)

        # Admin main subscription still uses admin's own credentials (not charlie's!)
        admin_sub = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN})
        self.assertEqual(admin_sub.status_code, 200)
        self.assertIn(admin_vless['uuid'], admin_sub.text)
        self.assertNotIn(pushed_uuid, admin_sub.text)


if __name__ == '__main__':
    unittest.main()
