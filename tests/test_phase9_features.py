"""Phase 9 integration and unit tests:
9.1 Zero-downtime metadata-only node updates, template rename ref sync, & agent config-diff skip
9.2 Per-forward go-gost rewrite_subscription & automatic prefer_relay rewrite compatibility
9.3 GEOSITE / GEOIP / DOMAIN-REGEX / no-resolve export in Sing-box & Surge
"""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from fastapi.testclient import TestClient
import yaml

from agent.runtime_engine import RuntimeEngine
from agent.runtime_spec import revision
from proxyforge.control.control_store import ControlStore
from proxyforge.subscription.builder import build_subscription_config, rename_proxy_references
from proxyforge.subscription.singbox import build_singbox_config
from proxyforge.subscription.surge import build_surge_config
from test_agent_control import metadata
from test_agent_jobs import capable
from test_api_integration import TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN, load_isolated_application

DEPLOY_RESULT = {
    'status': 'success',
    'output': {'installed': True, 'running': True, 'version': '1.14.2', 'status': 'running'},
    'error': None,
}

HY2_SETTINGS = {
    'name': 'HK Hy2',
    'server': '198.51.100.20',
    'domain': 'hy2.example.com',
    'listen_port': 443,
    'tls_mode': 'acme_http',
    'outbound_mode': 'direct',
}

REALITY_SETTINGS = {
    'name': 'SG Reality',
    'server': '198.51.100.10',
    'domain': 'www.amazon.com',
    'listen_port': 8443,
    'tls_mode': 'reality',
    'fingerprint': 'chrome',
    'outbound_mode': 'direct',
}


class Phase9StoreAndExportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = 2000
        self.store = ControlStore(self.root / 'control.db', clock=lambda: self.now)
        self.info = {
            **capable(),
            'runtime_protocol_version': 1,
            'deployment_protocol_version': 1,
            'landing_protocol_version': 1,
            'gost_protocol_version': 1,
        }
        self.agent = self.store.register(
            self.store.issue_registration('Phase9-VPS')['registration_token'],
            self.info,
            '198.51.100.10',
        )
        self.agent_id = self.agent['agent_id']
        self.agent_token = self.agent['agent_token']

    def _claim_and_complete(self, result=None):
        job = self.store.claim_job(self.agent_token, self.info['instance_id'])
        self.assertIsNotNone(job)
        self.store.report_job(self.agent_token, job['id'], job['lease_token'])
        self.store.report_job(self.agent_token, job['id'], job['lease_token'], result or DEPLOY_RESULT)
        return job

    def test_metadata_only_updates_skip_job_and_runtime_changes_enqueue_job(self):
        created = self.store.upsert_agent_node(
            self.agent_id,
            uuid.uuid4().hex,
            'reality',
            REALITY_SETTINGS,
        )
        self.assertEqual(created['applied'], 'runtime_job')
        self.assertTrue(created['restarted'])
        self._claim_and_complete()
        jobs_before = len(self.store.list_jobs(self.agent_id))

        # Pure metadata edits on existing node must NOT enqueue any job or restart runtime.
        updated_meta = self.store.upsert_agent_node(
            self.agent_id,
            uuid.uuid4().hex,
            'reality',
            {
                **REALITY_SETTINGS,
                'name': 'SG Reality Renamed',
                'server': 'sg.cdn.example.com',
                'region': 'SG',
                'fingerprint': 'firefox',
                'publish_to_subscription': True,
            },
            node_id=created['id'],
        )
        self.assertEqual(updated_meta['applied'], 'metadata_only')
        self.assertFalse(updated_meta['restarted'])
        self.assertEqual(updated_meta['renamed_from'], 'SG Reality')
        self.assertEqual(updated_meta['renamed_to'], 'SG Reality Renamed')
        self.assertEqual(len(self.store.list_jobs(self.agent_id)), jobs_before)
        self.assertIsNone(self.store.claim_job(self.agent_token, self.info['instance_id']))

        nodes = self.store.managed_nodes()
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]['name'], 'SG Reality Renamed')
        self.assertEqual(nodes[0]['server'], 'sg.cdn.example.com')
        self.assertEqual(nodes[0]['client-fingerprint'], 'firefox')

        # Create Hysteria2 extra node and update mport / hop_interval without restart.
        hy2_created = self.store.upsert_agent_node(
            self.agent_id,
            uuid.uuid4().hex,
            'hysteria2',
            HY2_SETTINGS,
        )
        self._claim_and_complete()
        hy2_jobs = len(self.store.list_jobs(self.agent_id))
        hy2_meta = self.store.upsert_agent_node(
            self.agent_id,
            uuid.uuid4().hex,
            'hysteria2',
            {**HY2_SETTINGS, 'mport': '20000-20500', 'hop_interval': 45},
            node_id=hy2_created['node_id'],
        )
        self.assertEqual(hy2_meta['applied'], 'metadata_only')
        self.assertFalse(hy2_meta['restarted'])
        self.assertEqual(len(self.store.list_jobs(self.agent_id)), hy2_jobs)
        hy2_node = next(n for n in self.store.managed_nodes() if n['name'] == 'HK Hy2')
        self.assertEqual(hy2_node['ports'], '20000-20500')
        self.assertEqual(hy2_node['hop-interval'], 45)

        # Runtime field change MUST enqueue landing.apply and require restart.
        runtime_edit = self.store.upsert_agent_node(
            self.agent_id,
            uuid.uuid4().hex,
            'reality',
            {
                **REALITY_SETTINGS,
                'name': 'SG Reality Renamed',
                'listen_port': 9443,
            },
            node_id=created['id'],
        )
        self.assertEqual(runtime_edit['applied'], 'runtime_job')
        self.assertTrue(runtime_edit['restarted'])
        self.assertGreater(len(self.store.list_jobs(self.agent_id)), hy2_jobs)

    def test_rename_proxy_references_updates_groups_and_rules(self):
        cfg = {
            'proxy-groups': [
                {'name': 'Proxy', 'type': 'select', 'default': 'Old Node', 'proxies': ['Old Node', 'Backup', 'Old Node']},
                {'name': 'Stream', 'type': 'select', 'proxies': ['Old Node']},
            ],
            'rules': [
                'DOMAIN-SUFFIX,example.com,Old Node',
                'IP-CIDR,1.1.1.1/32,Old Node,no-resolve',
                'MATCH,Proxy',
            ],
        }
        counts = rename_proxy_references(cfg, 'Old Node', 'New Node')
        self.assertEqual(counts['groupReferences'], 3)
        self.assertEqual(counts['ruleReferences'], 2)
        self.assertEqual(counts['total'], 5)
        self.assertEqual(cfg['proxy-groups'][0]['default'], 'New Node')
        self.assertEqual(cfg['proxy-groups'][0]['proxies'], ['New Node', 'Backup'])
        self.assertEqual(cfg['proxy-groups'][1]['proxies'], ['New Node'])
        self.assertEqual(
            cfg['rules'],
            [
                'DOMAIN-SUFFIX,example.com,New Node',
                'IP-CIDR,1.1.1.1/32,New Node,no-resolve',
                'MATCH,Proxy',
            ],
        )

    def test_forward_rewrite_subscription_toggle_and_active_relays(self):
        created = self.store.create_forward(
            self.agent_id,
            uuid.uuid4().hex,
            {
                'name': 'cn-relay-443',
                'listen_port': 20443,
                'protocol': 'tcp+udp',
                'mode': 'direct',
                'targets': [{'name': 'sg', 'addr': '198.51.100.10:443'}],
                'rewrite_subscription': True,
            },
        )
        self.assertTrue(created['rewrite_subscription'])
        self._claim_and_complete(DEPLOY_RESULT)

        relays = self.store.list_active_relays()
        self.assertEqual(len(relays), 1)
        self.assertTrue(relays[0]['rewrite_subscription'])
        self.assertEqual(relays[0]['listen_port'], 20443)

        toggled = self.store.set_forward_rewrite_subscription(created['id'], False, agent_id=self.agent_id)
        self.assertFalse(toggled['rewrite_subscription'])
        self.assertFalse(self.store.list_active_relays()[0]['rewrite_subscription'])

    def test_singbox_and_surge_export_geosite_geoip_domain_regex_and_no_resolve(self):
        cfg = build_subscription_config(
            {
                'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'use': ['_custom_nodes_']}],
                'rules': [
                    'DOMAIN-REGEX,^foo.*bar\\.example$,Proxy',
                    'GEOSITE,openai,Proxy',
                    'GEOSITE,cn,DIRECT',
                    'GEOSITE,openai,Proxy',  # duplicate rule_set tag check
                    'GEOIP,cn,DIRECT,no-resolve',
                    'MATCH,Proxy',
                ],
            },
            [
                {
                    'name': 'SS Node',
                    'type': 'ss',
                    'server': '192.0.2.50',
                    'port': 8388,
                    'cipher': 'aes-256-gcm',
                    'password': 'pw',
                }
            ],
            [],
            'https://sub.example',
            'tok',
        )

        sb_doc, sb_skipped = build_singbox_config(cfg)
        self.assertEqual(sb_skipped, 0)
        rule_sets = sb_doc['route']['rule_set']
        tags = [rs['tag'] for rs in rule_sets]
        self.assertEqual(tags, ['geosite-openai', 'geosite-cn', 'geoip-cn'])
        self.assertTrue(all(rs['type'] == 'remote' and rs['format'] == 'binary' for rs in rule_sets))
        self.assertEqual(
            rule_sets[0]['url'],
            'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.srs',
        )
        self.assertEqual(
            rule_sets[2]['url'],
            'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.srs',
        )
        sb_rules = sb_doc['route']['rules']
        self.assertTrue(any(r.get('domain_regex') == [r'^foo.*bar\.example$'] for r in sb_rules))
        self.assertEqual(sum(1 for r in sb_rules if r.get('rule_set') == ['geosite-openai']), 2)
        self.assertTrue(any(r.get('rule_set') == ['geoip-cn'] and r.get('outbound') == 'direct' for r in sb_rules))

        surge_text, _ = build_surge_config(cfg)
        self.assertIn(
            'RULE-SET,https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.list,Proxy',
            surge_text,
        )
        self.assertIn(
            'RULE-SET,https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list,DIRECT',
            surge_text,
        )
        self.assertIn('GEOIP,cn,DIRECT,no-resolve', surge_text)


@unittest.skipUnless(os.name == 'posix', 'Runtime requires Linux filesystem semantics')
class Phase9RuntimeDiffTest(unittest.TestCase):
    def test_runtime_engine_skips_restart_when_config_unchanged(self):
        class TrackBackend:
            running = None
            activate_calls = 0

            def active(self):
                return self.running is not None

            def matches(self, release):
                return self.running == release

            def check(self, release):
                json.loads((release / 'config.json').read_text(encoding='utf-8'))

            def activate(self, release):
                self.running = release
                self.activate_calls += 1

            def stop(self):
                self.running = None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = TrackBackend()

            def download(directory, arch, guard):
                guard()
                (directory / 'sing-box').write_bytes(b'bin')

            engine = RuntimeEngine(root, backend, 'amd64', download)
            spec = {
                'protocol': 'ss2022',
                'name': 'SS-Node',
                'server': '198.51.100.10',
                'listen_port': 8388,
                'method': '2022-blake3-aes-256-gcm',
                'psk': 'dGVzdHBza3Rlc3Rwc2t0ZXN0cHNrdGVzdHBza3Rlc3Q=',
            }
            payload = {'node_id': 'n1', 'revision': 1}
            job1 = {
                'id': uuid.uuid4().hex,
                'type': 'landing.apply',
                'payload': payload,
                'deployment': spec,
                'deployment_revision': revision('1' * 32, 'landing.apply', payload),
            }
            engine.apply(job1)
            self.assertEqual(backend.activate_calls, 1)

            job2_id = uuid.uuid4().hex
            job2 = {
                'id': job2_id,
                'type': 'landing.apply',
                'payload': payload,
                'deployment': {**spec, 'name': 'RenamedOnly', 'server': 'other.example.com'},
                'deployment_revision': revision(job2_id, 'landing.apply', payload),
            }
            engine.apply(job2)
            self.assertEqual(backend.activate_calls, 1)


class Phase9ApiIntegrationTest(unittest.TestCase):
    def test_api_node_rename_syncs_template_and_forward_rewrite_subscription(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            app_module = load_isolated_application(Path(tmpdir))
            with TestClient(app_module.app) as client:
                admin = {'Authorization': f'Bearer {TEST_ADMIN_TOKEN}'}

                # 1. Register two agents: landing + relay
                reg_land = client.post('/api/agents/registration-tokens', headers=admin, json={'name': 'SG-Landing'}).json()
                land_inst = 'a' * 32
                land_info = {
                    **capable(land_inst),
                    'runtime_protocol_version': 1,
                    'deployment_protocol_version': 1,
                    'landing_protocol_version': 1,
                    'gost_protocol_version': 1,
                }
                land_reg = client.post(
                    '/api/agent/register',
                    json={'registration_token': reg_land['registration_token'], **land_info},
                ).json()
                land_id = land_reg['agent_id']
                land_hdr = {'Authorization': f"Bearer {land_reg['agent_token']}"}

                reg_relay = client.post('/api/agents/registration-tokens', headers=admin, json={'name': 'CN-Relay'}).json()
                relay_inst = 'b' * 32
                relay_info = {
                    **capable(relay_inst),
                    'runtime_protocol_version': 1,
                    'deployment_protocol_version': 1,
                    'landing_protocol_version': 1,
                    'gost_protocol_version': 1,
                    'addresses': ['203.0.113.88'],
                }
                relay_reg = client.post(
                    '/api/agent/register',
                    json={'registration_token': reg_relay['registration_token'], **relay_info},
                ).json()
                relay_id = relay_reg['agent_id']
                relay_hdr = {'Authorization': f"Bearer {relay_reg['agent_token']}"}

                # 2. Deploy landing node named 'Old SG' and complete job
                created_node = client.post(
                    f'/api/agents/{land_id}/nodes',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'Old SG',
                            'server': '198.51.100.10',
                            'domain': 'www.amazon.com',
                            'listen_port': 443,
                            'tls_mode': 'reality',
                        },
                    },
                ).json()
                node_id = created_node['id']
                claimed = client.post(
                    '/api/agent/jobs/claim',
                    headers=land_hdr,
                    json={'instance_id': land_inst},
                ).json()['job']
                client.post(
                    f"/api/agent/jobs/{claimed['id']}/start",
                    headers=land_hdr,
                    json={'lease_token': claimed['lease_token']},
                )
                client.post(
                    f"/api/agent/jobs/{claimed['id']}/result",
                    headers=land_hdr,
                    json={'lease_token': claimed['lease_token'], 'result': DEPLOY_RESULT},
                )

                tpl_get = client.get('/api/template', headers=admin).json()
                cur_rev = tpl_get['revision']
                base_template = yaml.safe_load(tpl_get['content'])
                base_template['proxy-groups'].insert(
                    0,
                    {'name': 'CustomDirect', 'type': 'select', 'default': 'Old SG', 'proxies': ['Old SG', 'DIRECT']},
                )
                base_template['rules'] = [
                    'GEOSITE,openai,Old SG',
                    'MATCH,CustomDirect',
                ]
                tpl_save = client.post(
                    '/api/template',
                    headers=admin,
                    json={
                        'content': yaml.safe_dump(base_template, allow_unicode=True, sort_keys=False),
                        'expected_revision': cur_rev,
                    },
                )
                self.assertEqual(tpl_save.status_code, 200, tpl_save.text)

                # 3. Metadata-only rename via API updates node in place without restart & syncs template.yaml
                renamed = client.put(
                    f'/api/agents/{land_id}/nodes/{node_id}',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'New SG',
                            'server': '198.51.100.10',
                            'domain': 'www.amazon.com',
                            'listen_port': 443,
                            'tls_mode': 'reality',
                        },
                    },
                )
                self.assertEqual(renamed.status_code, 200)
                renamed_data = renamed.json()
                self.assertEqual(renamed_data['applied'], 'metadata_only')
                self.assertFalse(renamed_data['restarted'])

                tpl_res = client.get('/api/template', headers=admin).json()
                tpl = yaml.safe_load(tpl_res['content'])
                self.assertEqual(tpl['proxy-groups'][0]['default'], 'New SG')
                self.assertEqual(tpl['proxy-groups'][0]['proxies'], ['New SG', 'DIRECT'])
                self.assertIn('GEOSITE,openai,New SG', tpl['rules'])

                # 4. Create go-gost forward with rewrite_subscription=False, complete job
                fwd_res = client.post(
                    f'/api/agents/{relay_id}/forwards',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'name': 'sg-relay',
                        'listen_port': 30443,
                        'protocol': 'tcp+udp',
                        'mode': 'direct',
                        'targets': [{'name': 'sg', 'addr': '198.51.100.10:443'}],
                        'rewrite_subscription': False,
                    },
                )
                self.assertEqual(fwd_res.status_code, 200)
                fwd_id = fwd_res.json()['id']
                rjob = client.post(
                    '/api/agent/jobs/claim',
                    headers=relay_hdr,
                    json={'instance_id': relay_inst},
                ).json()['job']
                client.post(
                    f"/api/agent/jobs/{rjob['id']}/start",
                    headers=relay_hdr,
                    json={'lease_token': rjob['lease_token']},
                )
                client.post(
                    f"/api/agent/jobs/{rjob['id']}/result",
                    headers=relay_hdr,
                    json={'lease_token': rjob['lease_token'], 'result': DEPLOY_RESULT},
                )

                # Without rewrite_subscription or ?prefer_relay=1, subscription keeps direct 198.51.100.10:443
                sub_direct = yaml.safe_load(client.get(f'/sub?token={TEST_SUBSCRIPTION_TOKEN}').text)
                sg_proxy = next(p for p in sub_direct['proxies'] if p['name'].endswith('New SG'))
                self.assertEqual(sg_proxy['server'], '198.51.100.10')
                self.assertEqual(sg_proxy['port'], 443)

                relay_agent = client.get(f'/api/agents/{relay_id}', headers=admin).json()
                expected_relay_host = relay_agent.get('public_ipv4') or relay_agent.get('observed_ip')

                # Explicit ?prefer_relay=1 still works for compatibility
                sub_compat = yaml.safe_load(client.get(f'/sub?token={TEST_SUBSCRIPTION_TOKEN}&prefer_relay=1').text)
                sg_compat = next(p for p in sub_compat['proxies'] if p['name'].endswith('New SG'))
                self.assertEqual(sg_compat['server'], expected_relay_host)
                self.assertEqual(sg_compat['port'], 30443)

                # Enable rewrite_subscription on the forward rule -> subscription auto-rewrites without ?prefer_relay=1
                toggle = client.post(
                    f'/api/agents/{relay_id}/forwards/{fwd_id}/subscription',
                    headers=admin,
                    json={'rewrite_subscription': True},
                )
                self.assertEqual(toggle.status_code, 200)
                self.assertTrue(toggle.json()['rewrite_subscription'])

                sub_auto = yaml.safe_load(client.get(f'/sub?token={TEST_SUBSCRIPTION_TOKEN}').text)
                sg_auto = next(p for p in sub_auto['proxies'] if p['name'].endswith('New SG'))
                self.assertEqual(sg_auto['server'], expected_relay_host)
                self.assertEqual(sg_auto['port'], 30443)


if __name__ == '__main__':
    unittest.main()
