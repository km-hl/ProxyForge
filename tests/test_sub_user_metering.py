"""Integration tests for Phase 10.3 per-user credentials, nftables metering, cutoff, and monthly reset."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
import uuid

from fastapi.testclient import TestClient
import yaml

from proxyforge.subscription.users import derive_user_node_credentials
from test_agent_control import metadata
from test_api_integration import TEST_ADMIN_TOKEN, load_isolated_application


class SubUserMeteringIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc).timestamp()
        self.app = load_isolated_application(self.root)
        (self.root / 'data' / 'custom_nodes.yaml').write_text(
            yaml.safe_dump(
                [{'name': 'Manual-JP', 'type': 'ss', 'server': '198.51.100.88', 'port': 8388, 'cipher': 'aes-256-gcm', 'password': 'pw'}],
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

        reg = self.store.issue_registration('hk-edge')['registration_token']
        self.agent_meta = {
            **metadata('b' * 32),
            'job_protocol_version': 1,
            'runtime_protocol_version': 1,
            'deployment_protocol_version': 1,
            'landing_protocol_version': 1,
            'gost_protocol_version': 1,
            'self_upgrade_protocol_version': 1,
            'nftables_capable': True,
        }
        self.agent = self.store.register(reg, self.agent_meta, '203.0.113.50')
        self.store.heartbeat(self.agent['agent_token'], self.agent_meta, '203.0.113.50')

    def _drain_jobs(self):
        jobs = []
        while True:
            job = self.store.claim_job(self.agent['agent_token'], 'b' * 32)
            if not job:
                break
            self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'])
            self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'], {
                'status': 'success',
                'output': {'installed': True, 'running': True, 'version': '1.14.0', 'status': 'running'},
                'error': None,
            })
            jobs.append(job)
        return jobs

    def test_derive_credentials_deterministic_and_unique_per_node(self):
        seed = 'a1' * 32
        c1 = derive_user_node_credentials(seed, 'agent::aaa::node1')
        c2 = derive_user_node_credentials(seed, 'agent::aaa::node2')
        c1_again = derive_user_node_credentials(seed, 'agent::aaa::node1')
        self.assertEqual(c1, c1_again)
        self.assertNotEqual(c1['uuid'], c2['uuid'])
        self.assertNotEqual(c1['password'], c2['password'])
        self.assertEqual(uuid.UUID(c1['uuid']).version, 4)
        self.assertEqual(len(c1['password']), 32)

    def test_full_per_user_creds_metering_cutoff_no_restart_on_meta_and_reset(self):
        aid = self.agent['agent_id']
        # Deploy primary Reality + extra Trojan + extra SS2022 (published) on the Agent.
        r_primary = self.client.post(f'/api/agents/{aid}/nodes', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'protocol': 'reality',
            'settings': {
                'name': 'HK-Reality',
                'server': '203.0.113.50',
                'listen_port': 443,
                'tls_mode': 'reality',
                'domain': 'www.amazon.com',
            },
        })
        self.assertEqual(r_primary.status_code, 200, r_primary.text)
        primary_id = r_primary.json()['node_id']
        self._drain_jobs()

        r_trojan = self.client.post(f'/api/agents/{aid}/nodes', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'protocol': 'trojan',
            'settings': {
                'name': 'HK-Trojan',
                'server': '203.0.113.50',
                'listen_port': 8443,
                'tls_mode': 'acme_http',
                'domain': 'hk.example.com',
            },
        })
        self.assertEqual(r_trojan.status_code, 200, r_trojan.text)
        trojan_id = r_trojan.json()['node_id']
        self._drain_jobs()

        self.now += 1
        r_ss = self.client.post(f'/api/agents/{aid}/nodes', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'protocol': 'ss2022',
            'settings': {
                'name': 'HK-SS',
                'server': '203.0.113.50',
                'listen_port': 8388,
                'method': '2022-blake3-aes-256-gcm',
                'publish_to_subscription': True,
            },
        })
        self.assertEqual(r_ss.status_code, 200, r_ss.text)
        ss_id = r_ss.json()['node_id']
        self._drain_jobs()

        # Create a relay forward with rewrite_subscription targeting Reality 203.0.113.50:443
        fwd = self.client.post(f'/api/agents/{aid}/forwards', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'relay-hk',
            'listen_port': 20443,
            'targets': [{'addr': '203.0.113.50:443'}],
            'rewrite_subscription': True,
        })
        self.assertEqual(fwd.status_code, 200, fwd.text)
        self._drain_jobs()

        # Check available-nodes endpoint enumerates managed + manual with correct flags
        avail = self.client.get('/api/sub-users/available-nodes', headers=self.admin)
        self.assertEqual(avail.status_code, 200, avail.text)
        by_key = {n['key']: n for n in avail.json()['nodes']}
        reality_key = f'agent::{aid}::{primary_id}'
        trojan_key = f'agent::{aid}::{trojan_id}'
        ss_key = f'agent::{aid}::{ss_id}'
        self.assertTrue(by_key[reality_key]['supports_independent_creds'])
        self.assertTrue(by_key[reality_key]['has_relay_rewrite'])
        self.assertTrue(by_key[trojan_key]['supports_independent_creds'])
        self.assertFalse(by_key[ss_key]['supports_independent_creds'])
        self.assertFalse(by_key['manual::Manual-JP']['supports_independent_creds'])

        # Create user bob authorized on Reality + Trojan + Manual-JP
        u_resp = self.client.post('/api/sub-users', headers=self.admin, json={
            'username': 'bob',
            'quota_bytes': 10000,
            'expire_at': self.now + 90 * 86400,
            'allowed_nodes': [reality_key, trojan_key, 'manual::Manual-JP'],
            'info_nodes': True,
            'reset_day': 15,
        })
        self.assertEqual(u_resp.status_code, 200, u_resp.text)
        bob = u_resp.json()
        self.assertGreaterEqual(bob['mark_id'], 1)
        self.assertNotIn('cred_seed_enc', bob)
        self.assertNotIn('cred_seed', bob)

        # Agent immediately receives landing.apply job with bob's independent sub_users!
        jobs = self._drain_jobs()
        self.assertEqual(len(jobs), 1)
        spec = jobs[0]['deployment']
        self.assertEqual(len(spec['sub_users']), 1)
        self.assertEqual(spec['sub_users'][0]['mark_id'], bob['mark_id'])
        bob_uuid_v1 = spec['sub_users'][0]['uuid']
        trojan_spec = next(e for e in spec['extra_nodes'] if e['node_id'] == trojan_id)
        self.assertEqual(trojan_spec['sub_users'][0]['mark_id'], bob['mark_id'])
        bob_pw_v1 = trojan_spec['sub_users'][0]['password']
        self.assertNotIn('no_user_marks', spec)

        # Pure metadata edit (info_nodes, reset_day, future expire_at, higher quota) triggers ZERO Agent restarts!
        patch_meta = self.client.patch(f"/api/sub-users/{bob['id']}", headers=self.admin, json={
            'info_nodes': False,
            'reset_day': 12,
            'quota_bytes': 12000,
            'expire_at': self.now + 120 * 86400,
        })
        self.assertEqual(patch_meta.status_code, 200)
        self.assertEqual(self._drain_jobs(), [])

        # Agent uploads nftables traffic deltas for subuser:<mark_id> crossing 12000 quota
        traffic = self.client.post(
            '/api/agent/traffic',
            headers={'Authorization': 'Bearer ' + self.agent['agent_token']},
            json={
                'instance_id': 'b' * 32,
                'batch_id': uuid.uuid4().hex,
                'sequence': 1,
                'items': [{
                    'resource_key': f"subuser:{bob['mark_id']}",
                    'forward_rule_id': '',
                    'rx_delta': 9000,
                    'tx_delta': 4000,
                    'raw_rx': 9000,
                    'raw_tx': 4000,
                    'epoch': 'nft-1',
                }],
            },
        )
        self.assertEqual(traffic.status_code, 200, traffic.text)

        # Verify bob is auto-disabled with tx->upload and rx->download AND removed from sing-box!
        listed = self.client.get('/api/sub-users', headers=self.admin).json()['users']
        bob_now = next(u for u in listed if u['id'] == bob['id'])
        self.assertFalse(bob_now['enabled'])
        self.assertEqual(bob_now['disabled_reason'], 'quota_exceeded')
        self.assertEqual(bob_now['upload_bytes'], 4000)
        self.assertEqual(bob_now['download_bytes'], 9000)

        cutoff_jobs = self._drain_jobs()
        self.assertEqual(len(cutoff_jobs), 1)
        self.assertNotIn('sub_users', cutoff_jobs[0]['deployment'])
        trojan_after = next(e for e in cutoff_jobs[0]['deployment']['extra_nodes'] if e['node_id'] == trojan_id)
        self.assertNotIn('sub_users', trojan_after)

        # Advance clock to March 12 (reset_day=12) -> reconcile_sub_users resets usage, re-enables bob, re-syncs Agent!
        self.now = datetime(2026, 3, 12, 1, 0, tzinfo=timezone.utc).timestamp()
        rec = self.store.reconcile_sub_users()
        self.assertIn(bob['id'], rec['reset_users'])
        restored_jobs = self._drain_jobs()
        self.assertEqual(len(restored_jobs), 1)
        self.assertEqual(restored_jobs[0]['deployment']['sub_users'][0]['uuid'], bob_uuid_v1)

        # Rotate token & cred_seed -> new UUID and new password pushed to Agent!
        rot = self.client.post(f"/api/sub-users/{bob['id']}/rotate", headers=self.admin)
        self.assertEqual(rot.status_code, 200)
        rot_jobs = self._drain_jobs()
        self.assertEqual(len(rot_jobs), 1)
        bob_uuid_v2 = rot_jobs[0]['deployment']['sub_users'][0]['uuid']
        trojan_rot = next(e for e in rot_jobs[0]['deployment']['extra_nodes'] if e['node_id'] == trojan_id)
        bob_pw_v2 = trojan_rot['sub_users'][0]['password']
        self.assertNotEqual(bob_uuid_v1, bob_uuid_v2)
        self.assertNotEqual(bob_pw_v1, bob_pw_v2)

        # Simulate unprivileged container reporting nftables_capable=False -> reconcile adds no_user_marks=True
        self.store.heartbeat(self.agent['agent_token'], {**self.agent_meta, 'nftables_capable': False}, '203.0.113.50')
        rec_degrade = self.store.reconcile_sub_users()
        self.assertIn(aid, rec_degrade['synced_agents'])
        degrade_jobs = self._drain_jobs()
        self.assertEqual(len(degrade_jobs), 1)
        self.assertTrue(degrade_jobs[0]['deployment'].get('no_user_marks'))

        # Deleting primary Reality node promotes Trojan into primary_id and remaps bob's allowed_nodes cleanly
        del_p = self.client.request(
            'DELETE',
            f'/api/agents/{aid}/nodes/{primary_id}',
            headers=self.admin,
            json={'request_id': uuid.uuid4().hex},
        )
        self.assertEqual(del_p.status_code, 200, del_p.text)
        bob_after_del = next(u for u in self.client.get('/api/sub-users', headers=self.admin).json()['users'] if u['id'] == bob['id'])
        self.assertIn(f'agent::{aid}::{primary_id}', bob_after_del['allowed_nodes'])
        self.assertNotIn(f'agent::{aid}::{trojan_id}', bob_after_del['allowed_nodes'])


if __name__ == '__main__':
    unittest.main()
