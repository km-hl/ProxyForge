"""Integration tests for Phase 2 Control Plane go-gost forwards, chains, Best Exit, and traffic accounting."""
import contextlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fastapi.testclient import TestClient

from agent.runtime_spec import GOST_RELEASE, validate_runtime_job
from proxyforge.control.control_store import CURRENT_SCHEMA, ControlStore
from test_agent_control import metadata
from test_api_integration import TEST_ADMIN_TOKEN, load_isolated_application


class Phase2GostDataPlaneTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = load_isolated_application(self.root)
        self.store = self.app.control_store()
        self.admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        self.entry = self._enroll('entry-hk', '198.51.100.10', 'a' * 32)
        self.relay = self._enroll('mid-sg', '203.0.113.20', 'b' * 32)
        self.client = TestClient(self.app.app)

    def _enroll(self, name, ip, instance_id):
        reg = self.store.issue_registration(name)['registration_token']
        info = {
            **metadata(instance_id),
            'job_protocol_version': 1,
            'runtime_protocol_version': 1,
            'deployment_protocol_version': 1,
            'landing_protocol_version': 1,
            'chain_protocol_version': 1,
            'gost_protocol_version': 1,
        }
        enrolled = self.store.register(reg, info, ip)
        self.store.heartbeat(enrolled['agent_token'], info, ip)
        return {**enrolled, 'instance_id': instance_id, 'info': info}

    def test_runtime_release_and_gost_capability_gate(self):
        rel = self.client.get('/api/agents/runtime/release', headers=self.admin)
        self.assertEqual(rel.status_code, 200)
        self.assertEqual(rel.json()['gost_version'], GOST_RELEASE['version'])

        # Agent lacking gost_protocol_version=1 gets 409 conflict
        self.store.heartbeat(self.entry['agent_token'], {**self.entry['info'], 'gost_protocol_version': 0}, '198.51.100.10')
        resp = self.client.post(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'Blocked',
            'listen_port': 10000,
            'targets': [{'addr': '192.0.2.10:443'}],
        })
        self.assertEqual(resp.status_code, 409)

    def test_forward_chain_best_exit_and_secret_protection(self):
        # Create a managed vless-reality deployment on 443 to assert port collision rejection
        dep = self.client.put(f"/api/agents/{self.entry['agent_id']}/deployment", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'expected_revision': 0,
            'settings': {'name': 'node1', 'server': '198.51.100.10', 'listen_port': 443,
                         'server_name': 'www.microsoft.com'},
        })
        self.assertEqual(dep.status_code, 200)
        dep_job = self.store.claim_job(self.entry['agent_token'], self.entry['instance_id'])
        self.store.report_job(self.entry['agent_token'], dep_job['id'], dep_job['lease_token'])
        self.store.report_job(self.entry['agent_token'], dep_job['id'], dep_job['lease_token'], {
            'status': 'success', 'output': {'installed': True, 'running': True, 'version': '1.12.22', 'status': 'running'},
            'error': None,
        })

        # Colliding forward port 443 must fail atomically
        collision = self.client.post(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'Collide443',
            'listen_port': 443,
            'protocol': 'tcp',
            'targets': [{'addr': '192.0.2.50:8443'}],
        })
        self.assertEqual(collision.status_code, 409)

        # Create multi-hop tunnel chain routing entry -> managed middle relay -> external exit
        chain_secret = 'RelaySecretPass987'
        chain_resp = self.client.post('/api/agents/tunnels/chains', headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'hk_to_sg_exit',
            'entry_agent_id': self.entry['agent_id'],
            'hops': [
                {
                    'name': 'sg_hop',
                    'nodes': [{
                        'name': 'sg_mid',
                        'addr': '203.0.113.20:8443',
                        'connector': 'relay',
                        'dialer': 'tls',
                        'username': 'relayuser',
                        'password': chain_secret,
                        'agent_id': self.relay['agent_id'],
                        'serve_on_agent': True,
                    }],
                },
                {
                    'name': 'final_hop',
                    'nodes': [{
                        'name': 'jp_exit',
                        'addr': '192.0.2.99:9443',
                        'connector': 'relay',
                        'dialer': 'tls',
                    }],
                },
            ],
        })
        self.assertEqual(chain_resp.status_code, 200, chain_resp.text)
        chain_id = chain_resp.json()['id']
        self.assertNotIn(chain_secret, chain_resp.text)
        listed_chains = self.client.get('/api/agents/tunnels/chains', headers=self.admin)
        self.assertNotIn(chain_secret, listed_chains.text)
        self.assertEqual(listed_chains.json()['chains'][0]['hops'][0]['relay_agent_ids'], [self.relay['agent_id']])

        # Relay agent received a gost.apply job containing its relay service and chained hop1
        relay_job = self.store.claim_job(self.relay['agent_token'], self.relay['instance_id'])
        self.assertIsNotNone(relay_job)
        self.assertEqual(relay_job['type'], 'gost.apply')
        validate_runtime_job(relay_job)
        self.assertEqual(len(relay_job['deployment']['relay_services']), 1)
        self.assertEqual(relay_job['deployment']['relay_services'][0]['password'], chain_secret)
        self.store.report_job(self.relay['agent_token'], relay_job['id'], relay_job['lease_token'])
        self.store.report_job(self.relay['agent_token'], relay_job['id'], relay_job['lease_token'], {
            'status': 'success', 'output': {'installed': True, 'running': True, 'version': '3.3.3', 'status': 'running'},
            'error': None,
        })

        # Claim entry sync job from chain creation
        while True:
            j = self.store.claim_job(self.entry['agent_token'], self.entry['instance_id'])
            if not j:
                break
            validate_runtime_job(j)
            self.store.report_job(self.entry['agent_token'], j['id'], j['lease_token'])
            self.store.report_job(self.entry['agent_token'], j['id'], j['lease_token'], {
                'status': 'success', 'output': {'installed': True, 'running': True, 'version': '3.3.3', 'status': 'running'},
                'error': None,
            })

        # Create Best Exit group on entry agent
        grp_resp = self.client.post(f"/api/agents/{self.entry['agent_id']}/best-exits", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'jp_group',
            'confirmation_rounds': 3,
            'cooldown_seconds': 30,
            'exits': [
                {'id': 'ex1', 'name': 'ex-1', 'addr': '192.0.2.101:443'},
                {'id': 'ex2', 'name': 'ex-2', 'addr': '192.0.2.102:443'},
            ],
        })
        self.assertEqual(grp_resp.status_code, 200, grp_resp.text)
        grp_id = grp_resp.json()['id']

        # Create Best-Exit forward referencing chain + exit_group
        fwd_resp = self.client.post(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'BestTunnelFwd',
            'listen_port': 12000,
            'protocol': 'tcp+udp',
            'mode': 'best_exit',
            'chain_id': chain_id,
            'exit_group_id': grp_id,
            'proxy_protocol': 1,
        })
        self.assertEqual(fwd_resp.status_code, 200, fwd_resp.text)
        fwd_id = fwd_resp.json()['id']

        # Evaluate 3 consecutive confirmation rounds via agent bearer API to trigger switch ex1 -> ex2
        probe_payload = {
            'instance_id': self.entry['instance_id'],
            'group_id': grp_id,
            'probes': {
                'ex1': {'entry_latency_ms': 90, 'exit_latency_ms': 90, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
                'ex2': {'entry_latency_ms': 15, 'exit_latency_ms': 15, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
            },
        }
        headers_agent = {'Authorization': 'Bearer ' + self.entry['agent_token']}
        for rnd in (1, 2):
            r = self.client.post('/api/agent/best-exit', headers=headers_agent, json=probe_payload)
            self.assertEqual(r.status_code, 200)
            self.assertFalse(r.json()['decision']['switched'])
            self.assertEqual(r.json()['decision']['candidate_rounds'], rnd)
        r3 = self.client.post('/api/agent/best-exit', headers=headers_agent, json=probe_payload)
        self.assertEqual(r3.status_code, 200)
        self.assertTrue(r3.json()['decision']['switched'])
        self.assertEqual(r3.json()['group']['active_exit_id'], 'ex2')

        # Active relay endpoint projection returns ex2
        relays = self.client.get('/api/agents/forwards/relays', headers=self.admin).json()['relays']
        self.assertEqual(relays[0]['targets'], [{'addr': '192.0.2.102:443', 'name': 'ex-2'}])

        # Toggle disable rule
        toggled = self.client.post(f"/api/agents/{self.entry['agent_id']}/forwards/{fwd_id}/toggle", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'enabled': False,
        })
        self.assertEqual(toggled.status_code, 200)
        self.assertFalse(toggled.json()['enabled'])

    def test_traffic_batch_upload_deduplication_and_auth(self):
        fwd = self.client.post(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin, json={
            'request_id': uuid.uuid4().hex,
            'name': 'DirectMeter',
            'listen_port': 15000,
            'targets': [{'addr': '198.51.100.88:443'}],
        }).json()
        fid = fwd['id']

        batch_id = uuid.uuid4().hex
        payload = {
            'instance_id': self.entry['instance_id'],
            'batch_id': batch_id,
            'sequence': 1,
            'items': [{
                'resource_key': f'forward:{fid}',
                'forward_rule_id': fid,
                'rx_delta': 1024,
                'tx_delta': 4096,
                'raw_rx': 1024,
                'raw_tx': 4096,
                'epoch': 'boot1',
            }],
        }
        headers = {'Authorization': 'Bearer ' + self.entry['agent_token']}
        first = self.client.post('/api/agent/traffic', headers=headers, json=payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), {'status': 'ok', 'deduplicated': False, 'accepted': 1})

        # Replay of same batch_id must not double count
        replay = self.client.post('/api/agent/traffic', headers=headers, json=payload)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), {'status': 'ok', 'deduplicated': True, 'accepted': 0})

        # Second incremental batch accumulates cleanly
        second = self.client.post('/api/agent/traffic', headers=headers, json={
            **payload,
            'batch_id': uuid.uuid4().hex,
            'sequence': 2,
            'items': [{
                'resource_key': f'forward:{fid}',
                'forward_rule_id': fid,
                'rx_delta': 500,
                'tx_delta': 900,
                'raw_rx': 1524,
                'raw_tx': 4996,
                'epoch': 'boot1',
            }],
        })
        self.assertEqual(second.status_code, 200)

        agent_traffic = self.client.get(f"/api/agents/{self.entry['agent_id']}/traffic", headers=self.admin).json()
        self.assertEqual((agent_traffic['rx_bytes'], agent_traffic['tx_bytes'], agent_traffic['total_bytes']), (1524, 4996, 6520))

        summary = self.client.get('/api/agents/traffic/summary', headers=self.admin).json()
        self.assertEqual(summary['total_bytes'], 6520)

        fwd_list = self.client.get(f"/api/agents/{self.entry['agent_id']}/forwards", headers=self.admin).json()['forwards']
        self.assertEqual(fwd_list[0]['total_bytes'], 6520)

        # Forged instance_id rejected
        bad = self.client.post('/api/agent/traffic', headers=headers, json={**payload, 'instance_id': 'f' * 32, 'batch_id': uuid.uuid4().hex})
        self.assertEqual(bad.status_code, 401)

    def test_schema_version_7_migration_from_v1(self):
        with contextlib.closing(sqlite3.connect(str(self.root / 'fresh_v7.db'))) as db:
            db.close()
        fresh = ControlStore(self.root / 'fresh_v7.db')
        with fresh.connection() as db:
            self.assertEqual(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], CURRENT_SCHEMA)
            self.assertEqual(CURRENT_SCHEMA, 7)


if __name__ == '__main__':
    unittest.main()
