"""Integration tests for Phase 1 landing protocols, server key helper, and host adoption."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from agent.adoption import scan_host, valid_adopt_output
from agent.jobs import process_job, validate_job, validate_journal
from agent.landing_spec import (
    client_node,
    deployment_tls_plan,
    runtime_config,
    validate_settings,
    validate_spec,
)
from agent.runtime_spec import validate_runtime_job
from fastapi.testclient import TestClient

from proxyforge.control.deployment_store import new_landing_spec
from proxyforge.subscription.validation import validate_proxy_nodes
from test_agent_jobs import capable
from test_api_integration import TEST_ADMIN_TOKEN, load_isolated_application
from test_deployments import RESULT


class Phase1LandingSpecsAndHelperTests(unittest.TestCase):
    def test_extended_landing_protocols_validate_render_and_pass_mihomo(self):
        cases = [
            (
                'reality',
                {
                    'name': 'HK Reality',
                    'server': '203.0.113.10',
                    'listen_port': 443,
                    'protocol': 'reality',
                    'domain': 'cdn.example.com',
                    'tls_mode': 'reality',
                    'camouflage_url': 'https://www.apple.com',
                },
            ),
            (
                'trojan',
                {
                    'name': 'JP Trojan',
                    'server': 'jp.example.com',
                    'listen_port': 8443,
                    'protocol': 'trojan',
                    'domain': 'jp.example.com',
                    'tls_mode': 'acme_http',
                    'camouflage_url': 'https://example.org',
                },
            ),
            (
                'vless-ws',
                {
                    'name': 'SG WS TLS',
                    'server': 'sg.example.com',
                    'listen_port': 2053,
                    'protocol': 'vless-ws',
                    'domain': 'sg.example.com',
                    'tls_mode': 'acme_dns',
                    'ws_path': '/tunnel',
                    'dns_provider': 'cloudflare',
                    'dns_zone_id': '0123456789abcdef0123456789abcdef',
                    'dns_propagation_seconds': 30,
                },
                {'dns_api_token': 'cf_secret_token_0123456789ABCDEF'},
            ),
            (
                'hysteria2',
                {
                    'name': 'US HY2',
                    'server': 'us.example.com',
                    'listen_port': 3443,
                    'protocol': 'hysteria2',
                    'domain': 'us.example.com',
                    'tls_mode': 'acme_http',
                    'up_mbps': 100,
                    'down_mbps': 500,
                    'obfs': 'salamander',
                    'camouflage_url': 'https://example.com',
                },
            ),
        ]

        projected_nodes = []
        for entry in cases:
            protocol, settings = entry[0], entry[1]
            secrets_in = entry[2] if len(entry) > 2 else None
            validate_settings(settings, protocol=protocol)
            spec = new_landing_spec(settings, protocol=protocol, secrets_input=secrets_in)
            validate_spec('landing.apply', spec)

            sb = runtime_config(spec)
            self.assertEqual(len(sb['inbounds']), 1)
            if protocol == 'vless-ws':
                self.assertEqual(sb['inbounds'][0]['listen'], '127.0.0.1')
                self.assertEqual(sb['inbounds'][0]['transport']['path'], '/tunnel')
            elif protocol == 'hysteria2':
                self.assertEqual(sb['inbounds'][0]['obfs']['type'], 'salamander')
                self.assertEqual(sb['inbounds'][0]['masquerade'], 'https://example.com')

            plan = deployment_tls_plan(spec)
            self.assertEqual(plan['tls_mode'], settings['tls_mode'])
            node = client_node('f' * 32, 'a' * 32, spec)
            self.assertIsNotNone(node)
            projected_nodes.append(node)

        self.assertEqual(validate_proxy_nodes(projected_nodes), [])

    def test_deployment_api_server_key_helper_and_secret_non_leakage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = load_isolated_application(root)
            store = app.control_store()
            info = {**capable(), 'runtime_protocol_version': 1, 'landing_protocol_version': 1}
            agent = store.register(store.issue_registration('LandingVPS')['registration_token'], info, '198.51.100.5')
            admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            agent_id = agent['agent_id']

            with TestClient(app.app) as client:
                helper_resp = client.post(
                    '/api/agents/deployments/generate-keys',
                    headers=admin,
                    json={'protocol': 'reality'},
                )
                self.assertEqual(helper_resp.status_code, 200, helper_resp.text)
                helper_data = helper_resp.json()
                self.assertIn('reality_public_key', helper_data)
                self.assertIn('key_ref', helper_data)
                self.assertNotIn('reality_private_key', helper_resp.text)
                self.assertNotIn('private_key', helper_data)

                deploy_resp = client.put(
                    f'/api/agents/{agent_id}/deployment',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'expected_revision': 0,
                        'protocol': 'reality',
                        'key_ref': helper_data['key_ref'],
                        'settings': {
                            'name': 'Node1 Reality',
                            'server': '198.51.100.5',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'domain': 'cdn.example.com',
                            'tls_mode': 'reality',
                            'camouflage_url': 'https://www.apple.com',
                            'reality_public_key': helper_data['reality_public_key'],
                            'reality_short_ids': helper_data['reality_short_ids'],
                        },
                    },
                )
                self.assertEqual(deploy_resp.status_code, 200, deploy_resp.text)
                self.assertEqual(deploy_resp.json()['protocol'], 'reality')

                # Reject plaintext private key in settings cleanly without echoing it.
                bad_secret = client.put(
                    f'/api/agents/{agent_id}/deployment',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'expected_revision': 1,
                        'protocol': 'trojan',
                        'settings': {
                            'name': 'Bad',
                            'server': 'bad.example.com',
                            'listen_port': 443,
                            'password': 'leaked-password-canary',
                        },
                    },
                )
                self.assertEqual(bad_secret.status_code, 422)
                self.assertNotIn('leaked-password-canary', bad_secret.text)

            job = store.claim_job(agent['agent_token'], info['instance_id'])
            validate_runtime_job(job)
            self.assertEqual(job['deployment']['reality_public_key'], helper_data['reality_public_key'])
            store.report_job(agent['agent_token'], job['id'], job['lease_token'])
            store.report_job(agent['agent_token'], job['id'], job['lease_token'], RESULT)
            self.assertEqual(len(store.managed_nodes()), 1)
            self.assertEqual(store.managed_nodes()[0]['reality-opts']['public-key'], helper_data['reality_public_key'])

            # DNS-01 secret stays encrypted only inside secret_spec / secret_payload.
            agent2 = store.register(store.issue_registration('DnsVPS')['registration_token'], {**info, 'instance_id': 'd' * 32}, '')
            secret_token = 'cf-dns-secret-token-canary-9876543210'
            with TestClient(app.app) as client:
                dns_resp = client.put(
                    f"/api/agents/{agent2['agent_id']}/deployment",
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'expected_revision': 0,
                        'protocol': 'vless-ws',
                        'secrets': {'dns_api_token': secret_token},
                        'settings': {
                            'name': 'WS DNS Node',
                            'server': 'ws.example.com',
                            'listen_port': 443,
                            'protocol': 'vless-ws',
                            'domain': 'ws.example.com',
                            'tls_mode': 'acme_dns',
                            'ws_path': '/ws',
                            'dns_provider': 'cloudflare',
                            'dns_zone_id': '0123456789abcdef0123456789abcdef',
                        },
                    },
                )
                self.assertEqual(dns_resp.status_code, 200, dns_resp.text)
                self.assertNotIn(secret_token, dns_resp.text)
            with store.connection() as db:
                self.assertNotIn(secret_token, '\n'.join(db.iterdump()))


class Phase1AdoptionScanTests(unittest.TestCase):
    def test_scan_host_parses_singbox_xray_caddy_without_exposing_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sb_cfg = root / 'singbox.json'
            sb_cfg.write_text(
                '// jsonc comment\n'
                + json.dumps({
                    'inbounds': [{
                        'type': 'vless',
                        'tag': 'vless-in',
                        'listen': '::',
                        'listen_port': 1443,
                        'users': [{'uuid': '11111111-1111-4111-8111-111111111111', 'flow': 'xtls-rprx-vision'}],
                        'tls': {
                            'enabled': True,
                            'server_name': 'reality.example.com',
                            'reality': {'enabled': True, 'private_key': 'TOP_SECRET_REALITY_KEY', 'short_id': ['abcd']},
                        },
                    }],
                }),
                encoding='utf-8',
            )
            xray_cfg = root / 'xray.json'
            xray_cfg.write_text(
                json.dumps({
                    'inbounds': [{
                        'tag': 'xray-ws',
                        'protocol': 'vless',
                        'port': 10443,
                        'settings': {'clients': [{'id': '22222222-2222-4222-8222-222222222222'}]},
                        'streamSettings': {
                            'network': 'ws',
                            'security': 'tls',
                            'tlsSettings': {'serverName': 'ws.example.com'},
                            'wsSettings': {'path': '/xws'},
                        },
                    }],
                }),
                encoding='utf-8',
            )
            caddy_cfg = root / 'Caddyfile'
            caddy_cfg.write_text('https://camo.example.com:8443 {\n\tbind 127.0.0.1\n\trespond "ok" 200\n}\n', encoding='utf-8')

            scan = scan_host(
                proc=root / 'no-proc',
                extra_configs=[
                    {'core': 'sing-box', 'config_path': str(sb_cfg), 'service_name': 'sing-box.service', 'pid': 101},
                    {'core': 'xray', 'config_path': str(xray_cfg), 'service_name': 'xray.service', 'pid': 102},
                    {'core': 'caddy', 'config_path': str(caddy_cfg), 'service_name': 'caddy.service', 'pid': 103},
                ],
            )
            self.assertTrue(valid_adopt_output(scan))
            self.assertEqual(len(scan['services']), 3)
            self.assertEqual(len(scan['endpoints']), 3)
            serialized = json.dumps(scan)
            for secret in ('TOP_SECRET_REALITY_KEY', '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'):
                self.assertNotIn(secret, serialized)

            # Direct Agent job loop process_job() handles adopt_scan without runtime_helper.
            agent_cfg_dir = root / 'agent-proc'
            agent_cfg_dir.mkdir()
            adopt_job = {
                'id': uuid.uuid4().hex,
                'type': 'adopt_scan',
                'payload': {},
                'job_protocol_version': 1,
                'lease_token': 'x' * 43,
                'deployment_revision': None,
            }
            validate_job(adopt_job)
            mock_client = Mock()
            mock_client.post.side_effect = [{'job': adopt_job}, {'status': 'running'}, {'status': 'success'}]
            agent_cfg = {
                'controller': 'https://controller.example',
                'agent_id': 'a' * 32,
                'instance_id': capable()['instance_id'],
                'token': 'agent-tok',
            }
            with patch('agent.jobs.scan_host', return_value=scan):
                process_job(mock_client, agent_cfg, agent_cfg_dir / 'config.json')
            saved_journal = json.loads((agent_cfg_dir / 'job-results.json').read_text(encoding='utf-8'))
            validate_journal(saved_journal, {k: agent_cfg[k] for k in ('controller', 'agent_id', 'instance_id')})
            self.assertEqual(mock_client.post.call_args_list[-1].args[1]['result']['output'], scan)

            # End-to-end Controller job + /api/agent/adoptions -> managed_inventory().
            ctrl_root = root / 'ctrl'
            ctrl_root.mkdir()
            app = load_isolated_application(ctrl_root)
            store = app.control_store()
            agent = store.register(store.issue_registration('AdoptVPS')['registration_token'], capable(), '198.51.100.77')
            with TestClient(app.app) as client:
                admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
                req_resp = client.post(
                    f"/api/agents/{agent['agent_id']}/adopt-scan",
                    headers=admin,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(req_resp.status_code, 200, req_resp.text)

            with patch('agent.jobs.scan_host', return_value=scan):
                job = store.claim_job(agent['agent_token'], capable()['instance_id'])
                validate_job(job)
                store.report_job(agent['agent_token'], job['id'], job['lease_token'])
                res = store.report_job(
                    agent['agent_token'],
                    job['id'],
                    job['lease_token'],
                    {'status': 'success', 'output': scan, 'error': None},
                )
                self.assertEqual(res['status'], 'success')

            inventory = store.managed_inventory()
            adopted = [item for item in inventory if item['kind'] == 'adopted']
            self.assertEqual(len(adopted), 3)
            self.assertTrue(all(not item['publishable'] for item in adopted))
            self.assertEqual({item['core'] for item in adopted}, {'sing-box', 'xray', 'caddy'})
            self.assertEqual(len(store.list_adopted_nodes(agent['agent_id'])), 3)

            # Direct Agent POST /api/agent/adoptions works idempotently too.
            with TestClient(app.app) as client:
                post_resp = client.post(
                    '/api/agent/adoptions',
                    headers={'Authorization': 'Bearer ' + agent['agent_token']},
                    json={**scan, 'instance_id': capable()['instance_id']},
                )
                self.assertEqual(post_resp.status_code, 200, post_resp.text)
                self.assertEqual(post_resp.json()['adopted_count'], 3)


if __name__ == '__main__':
    unittest.main()
