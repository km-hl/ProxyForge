"""Phase 7 regression & integration tests:
- Case-sensitive ambiguous ISO flag fix (in-3 / reality-in no longer match India)
- Managed inventory separation (hide un-adopted/auxiliary items from managed nodes panel)
- Adoption ignore/unignore & disable/restore host service lifecycle (with empty singbox skip)
- Manual node duplicate matching (credential & endpoint) + atomic replace & template group migration
- Caddy camouflage upgrade (4 built-in templates, reverse proxy, validated static_dir)
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid
import yaml

from fastapi.testclient import TestClient

from agent.caddy_manager import (
    CaddyError,
    CaddyManager,
    render_caddyfile,
    render_camouflage_html,
    validate_camouflage_dir,
)
from agent.landing_spec import build_caddy_site_for_landing, validate_settings, validate_spec
from agent.runtime_engine import RuntimeCoordinator
from agent.runtime_spec import SERVICE_SINGBOX, revision
from agent.deployment_spec import spec_hash
from proxyforge.control.deployment_store import new_landing_spec
from proxyforge.subscription.nodes import add_flag_to_proxy_name
from test_agent_jobs import capable
from test_api_integration import TEST_ADMIN_TOKEN, load_isolated_application
from test_deployments import RESULT


class Phase7FlagAndCamouflageTests(unittest.TestCase):
    def test_ambiguous_short_codes_do_not_false_match_lowercase_names(self):
        self.assertEqual(add_flag_to_proxy_name('in-3 [sing-box:8443]'), 'in-3 [sing-box:8443]')
        self.assertEqual(add_flag_to_proxy_name('reality-in [xray:4431]'), 'reality-in [xray:4431]')
        self.assertEqual(add_flag_to_proxy_name('node-id-01'), 'node-id-01')
        self.assertEqual(add_flag_to_proxy_name('no-tls-edge'), 'no-tls-edge')
        self.assertEqual(add_flag_to_proxy_name('at-home'), 'at-home')
        self.assertEqual(add_flag_to_proxy_name('it-ops'), 'it-ops')
        # Uppercase ISO code and explicit region names still match
        self.assertTrue(add_flag_to_proxy_name('IN 01').startswith('\U0001F1EE\U0001F1F3'))
        self.assertTrue(add_flag_to_proxy_name('Mumbai 02').startswith('\U0001F1EE\U0001F1F3'))
        self.assertTrue(add_flag_to_proxy_name('印度节点').startswith('\U0001F1EE\U0001F1F3'))
        self.assertTrue(add_flag_to_proxy_name('Evoxt MY').startswith('\U0001F1F2\U0001F1FE'))

    def test_caddy_camouflage_templates_static_dir_validation_and_staging(self):
        self.assertEqual(validate_camouflage_dir('/var/www/site'), '/var/www/site')
        self.assertEqual(validate_camouflage_dir('/srv/landing/'), '/srv/landing')
        for bad in (
            'relative/path',
            '/',
            '/etc/nginx',
            '/root/site',
            '/var/lib/proxyforge-runtime/secrets',
            '/opt/proxyforge-agent/agent',
            '/var/www/../etc',
            '/var/www/bad;inject',
        ):
            with self.assertRaises(CaddyError, msg=f'should reject {bad}'):
                validate_camouflage_dir(bad)

        for tpl in ('corporate', 'blog', 'status', 'nginx'):
            doc = render_camouflage_html(tpl, domain='edge.example.com')
            self.assertIn('<!doctype html>', doc.lower())
            self.assertIn('edge.example.com', doc)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert = root / 'c.crt'
            key = root / 'c.key'
            cert.write_text('CERT', encoding='utf-8')
            key.write_text('KEY', encoding='utf-8')

            mgr = CaddyManager(state_dir=root / 'caddy' / 'state')
            # 1. Template mode stages index.html and configures file_server
            cf_tpl = mgr.upsert_site({
                'site_id': 'landing',
                'domain': 'camo.example.com',
                'listen_port': 28443,
                'bind_host': '127.0.0.1',
                'tls_mode': 'custom',
                'cert_path': cert.as_posix(),
                'key_path': key.as_posix(),
                'camouflage_mode': 'template',
                'camouflage_template': 'status',
            })
            staged_index = mgr.www_dir / 'landing' / 'index.html'
            self.assertTrue(staged_index.is_file())
            self.assertIn('All Systems Operational', staged_index.read_text(encoding='utf-8'))
            self.assertIn('file_server', cf_tpl)
            self.assertIn(f'root * {(mgr.www_dir / "landing").as_posix()}', cf_tpl)

            # 2. Static dir mode renders root * <dir> + file_server
            cf_dir = mgr.upsert_site({
                'site_id': 'landing',
                'domain': 'camo.example.com',
                'listen_port': 28443,
                'bind_host': '127.0.0.1',
                'tls_mode': 'custom',
                'cert_path': cert.as_posix(),
                'key_path': key.as_posix(),
                'camouflage_mode': 'static_dir',
                'camouflage_dir': '/var/www/custom-site',
            })
            self.assertIn('root * /var/www/custom-site', cf_dir)
            self.assertIn('file_server', cf_dir)

            # 3. remove_site cleans up staged www directory
            mgr.remove_site('landing')
            self.assertFalse((mgr.www_dir / 'landing').exists())

        # Verify landing_spec validates and forwards camouflage fields to Caddy site spec
        real_settings = {
            'name': 'Reality Camo',
            'server': 'real.example.com',
            'listen_port': 443,
            'protocol': 'reality',
            'domain': 'real.example.com',
            'tls_mode': 'acme_http',
            'camouflage_mode': 'template',
            'camouflage_template': 'blog',
        }
        validate_settings(real_settings, protocol='reality')
        real_spec = new_landing_spec(real_settings, protocol='reality')
        site = build_caddy_site_for_landing(real_spec, listen_port=28443)
        self.assertEqual(site['camouflage_mode'], 'template')
        self.assertEqual(site['camouflage_template'], 'blog')
        self.assertIn('protocols h1 h2', render_caddyfile([site], cert_pairs={'landing': ('/tmp/c.crt', '/tmp/c.key')}))

        # Reject invalid camouflage_dir in landing_spec
        bad_settings = dict(real_settings)
        bad_settings['camouflage_mode'] = 'static_dir'
        bad_settings['camouflage_dir'] = '/etc/shadow'
        with self.assertRaises(ValueError):
            validate_settings(bad_settings, protocol='reality')


class Phase7AdoptionLifecycleAndManualDedupTests(unittest.TestCase):
    def _register(self, store, name, public_ipv4):
        info = {
            **capable(),
            'runtime_protocol_version': 1,
            'landing_protocol_version': 1,
            'addresses': [public_ipv4],
        }
        reg = store.register(store.issue_registration(name)['registration_token'], info, public_ipv4)
        return reg['agent_id'], reg['agent_token'], info['instance_id']

    def test_disable_adoption_skips_empty_singbox_and_calls_adopt_host_service(self):
        skey = 'adopt-' + 'a' * 16
        dep_spec = {
            'adopted_only': True,
            'disabled_adoptions': [{
                'source_key': skey,
                'original_service': 'nodepilot-n-1.service',
                'original_config_path': '/etc/nodepilot/nodes/n1/current/config.json',
            }],
        }
        validate_spec('landing.apply', dep_spec)
        mock_sb = Mock()
        mock_sb.pointer.return_value = None
        mock_sb.status.return_value = {'installed': False, 'active': False}
        coord = RuntimeCoordinator({SERVICE_SINGBOX: mock_sb})
        job_id = 'b' * 32
        payload = {'deployment_id': 'c' * 32, 'revision': 1, 'spec_hash': spec_hash(dep_spec)}
        with patch('agent.adoption.adopt_host_service') as m_adopt:
            res = coord.apply(
                {
                    'id': job_id,
                    'type': 'landing.apply',
                    'payload': payload,
                    'deployment_revision': revision(job_id, 'landing.apply', payload),
                    'deployment': dep_spec,
                },
                lambda: None,
            )
        self.assertEqual(res['status'], 'success')
        m_adopt.assert_called_once_with(
            'nodepilot-n-1.service',
            '/etc/nodepilot/nodes/n1/current/config.json',
            skey,
        )
        mock_sb.apply.assert_not_called()

    def test_managed_panel_filter_ignore_disable_restore_and_manual_replace(self):
        headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_mod = load_isolated_application(root)
            store = app_mod.control_store()
            aid, atok, inst = self._register(store, 'MY-VPS', '1.2.3.4')

            # Seed a manual node in custom_nodes.yaml (simulating SNI-gate on :443 forwarding to :4431)
            # and reference it in template.yaml proxy-groups.
            uid = str(uuid.uuid4())
            rpub = 'A' * 43
            manual_name = 'MY Reality Manual'
            (root / 'data' / 'custom_nodes.yaml').write_text(
                yaml.safe_dump([{
                    'name': manual_name,
                    'type': 'vless',
                    'server': '1.2.3.4',
                    'port': 443,
                    'uuid': uid,
                    'network': 'tcp',
                    'tls': True,
                    'udp': True,
                    'flow': 'xtls-rprx-vision',
                    'servername': 'reality.example.com',
                    'reality-opts': {'public-key': rpub, 'short-id': 'a1b2c3d4'},
                }], allow_unicode=True, sort_keys=False),
                encoding='utf-8',
            )
            tpl_path = root / 'data' / 'template.yaml'
            tpl_obj = yaml.safe_load(tpl_path.read_text(encoding='utf-8'))
            tpl_obj['proxy-groups'] = [{
                'name': 'ManualGroup',
                'type': 'select',
                'proxies': ['DIRECT', manual_name],
            }]
            tpl_path.write_text(yaml.safe_dump(tpl_obj, allow_unicode=True, sort_keys=False), encoding='utf-8')

            sk_vless = 'adopt-' + '1' * 16
            sk_gate = 'adopt-' + '2' * 16
            sk_caddy = 'adopt-' + '3' * 16
            scan_payload = {
                'scanned_at': 1700000000,
                'services': [
                    {'core': 'xray', 'pid': 100, 'service_name': 'xray-old.service', 'config_path': '/etc/xray/c.json', 'config_sha256': 'a' * 64},
                    {'core': 'caddy', 'pid': 101, 'service_name': 'caddy-old.service', 'config_path': '/etc/caddy/c.json', 'config_sha256': 'b' * 64},
                ],
                'endpoints': [
                    {
                        'source_key': sk_vless, 'core': 'xray', 'service_name': 'xray-old.service',
                        'config_path': '/etc/xray/c.json', 'config_sha256': 'a' * 64,
                        'tag': 'reality-in', 'protocol': 'vless', 'listen': '0.0.0.0', 'listen_port': 4431,
                        'tls_mode': 'reality', 'sni': 'reality.example.com', 'network': 'tcp', 'ws_path': '', 'adoptable': True,
                    },
                    {
                        'source_key': sk_gate, 'core': 'xray', 'service_name': 'xray-old.service',
                        'config_path': '/etc/xray/c.json', 'config_sha256': 'a' * 64,
                        'tag': 'sni-gate', 'protocol': 'dokodemo-door', 'listen': '0.0.0.0', 'listen_port': 443,
                        'tls_mode': 'none', 'sni': '', 'network': 'tcp', 'ws_path': '', 'adoptable': False,
                    },
                    {
                        'source_key': sk_caddy, 'core': 'caddy', 'service_name': 'caddy-old.service',
                        'config_path': '/etc/caddy/c.json', 'config_sha256': 'b' * 64,
                        'tag': 'caddy-1', 'protocol': 'caddy-site', 'listen': '127.0.0.1', 'listen_port': 8003,
                        'tls_mode': 'tls', 'sni': 'reality.example.com', 'network': 'http', 'ws_path': '', 'adoptable': False,
                    },
                ],
            }
            store.record_adoption_scan(atok, inst, scan_payload)
            store.record_adoption_secrets(atok, inst, [{
                'source_key': sk_vless,
                'credentials': {
                    'protocol': 'vless', 'listen_port': 4431, 'uuid': uid,
                    'reality_private_key': 'B' * 43, 'reality_public_key': rpub, 'reality_short_id': 'a1b2c3d4',
                },
                'inbound': {'type': 'vless', 'tag': 'adopted-1', 'listen': '::', 'listen_port': 4431},
            }])

            with TestClient(app_mod.app) as client:
                # 1. Managed nodes API must NOT include un-adopted scan items by default
                m_resp = client.get('/api/agents/managed/nodes', headers=headers)
                self.assertEqual(m_resp.status_code, 200)
                self.assertEqual(m_resp.json()['nodes'], [])

                # Loopback caddy endpoint uses real listen address when include_discovered=True
                m_all = store.managed_inventory(include_discovered=True)
                caddy_inv = next(x for x in m_all if x['source_key'] == sk_caddy)
                self.assertEqual(caddy_inv['server'], '127.0.0.1')

                # 2. GET /adoptions detects manual duplicate behind sni-gate via credential fingerprint and flags auxiliaries
                ad_list = client.get(f'/api/agents/{aid}/adoptions', headers=headers).json()['adoptions']
                by_sk = {x['source_key']: x for x in ad_list}
                self.assertTrue(by_sk[sk_gate]['is_auxiliary'])
                self.assertTrue(by_sk[sk_caddy]['is_auxiliary'])
                self.assertFalse(by_sk[sk_vless]['is_auxiliary'])
                self.assertEqual(by_sk[sk_vless]['matched_manual_name'], manual_name)
                self.assertEqual(by_sk[sk_vless]['matched_manual_reason'], 'credential')
                self.assertNotIn('B' * 43, json.dumps(ad_list))

                # 3. Ignore & unignore lifecycle
                r_ign = client.post(f'/api/agents/{aid}/adoptions/{sk_vless}/ignore', headers=headers, json={'ignored': True})
                self.assertEqual(r_ign.status_code, 200)
                self.assertEqual(r_ign.json()['adopted_status'], 'ignored')
                r_unign = client.post(f'/api/agents/{aid}/adoptions/{sk_vless}/ignore', headers=headers, json={'ignored': False})
                self.assertEqual(r_unign.status_code, 200)
                self.assertEqual(r_unign.json()['adopted_status'], 'discovered')

                # 4. Disable host service -> marks siblings disabled, enqueues disabled_adoptions, survives rescan, then restore
                r_dis = client.post(
                    f'/api/agents/{aid}/adoptions/{sk_vless}/disable',
                    headers=headers,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(r_dis.status_code, 200, r_dis.text)
                job_dis = store.claim_job(atok, inst)
                self.assertTrue(job_dis['deployment']['adopted_only'])
                self.assertEqual(len(job_dis['deployment']['disabled_adoptions']), 1)
                self.assertEqual(job_dis['deployment']['disabled_adoptions'][0]['original_service'], 'xray-old.service')
                store.report_job(atok, job_dis['id'], job_dis['lease_token'])
                store.report_job(atok, job_dis['id'], job_dis['lease_token'], RESULT)

                # Re-scan without xray running must keep disabled records so user can restore
                store.record_adoption_scan(atok, inst, {'scanned_at': 1700000100, 'services': [], 'endpoints': []})
                ad_after_dis = {x['source_key']: x for x in store.list_adopted_nodes(aid)}
                self.assertEqual(ad_after_dis[sk_vless]['adopted_status'], 'disabled')
                self.assertEqual(ad_after_dis[sk_gate]['adopted_status'], 'disabled')

                # Restore original service
                r_ret = client.post(
                    f'/api/agents/{aid}/adoptions/{sk_vless}/return',
                    headers=headers,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(r_ret.status_code, 200, r_ret.text)
                job_ret = store.claim_job(atok, inst)
                self.assertIn(sk_vless, job_ret['deployment']['returned_adoptions'])
                store.report_job(atok, job_ret['id'], job_ret['lease_token'])
                store.report_job(atok, job_ret['id'], job_ret['lease_token'], RESULT)

                # 5. Re-upload scan + adopt with replace_manual=True -> removes duplicate manual node & migrates template group!
                store.record_adoption_scan(atok, inst, scan_payload)
                r_adopt = client.post(
                    f'/api/agents/{aid}/adoptions/{sk_vless}/adopt',
                    headers=headers,
                    json={'request_id': uuid.uuid4().hex, 'replace_manual': True},
                )
                self.assertEqual(r_adopt.status_code, 200, r_adopt.text)
                adopt_body = r_adopt.json()
                self.assertTrue(adopt_body['manual_replacement']['replaced'])
                self.assertEqual(adopt_body['manual_replacement']['migrated_groups'], 1)
                new_disp = adopt_body['adopted_display_name']
                self.assertIn(manual_name, new_disp)

                # Verify custom_nodes.yaml no longer has duplicate manual node
                remaining_manual = yaml.safe_load((root / 'data' / 'custom_nodes.yaml').read_text(encoding='utf-8'))
                self.assertEqual(remaining_manual, [])
                # Verify template.yaml proxy-group migrated seamlessly to new adopted name
                updated_tpl = yaml.safe_load(tpl_path.read_text(encoding='utf-8'))
                self.assertEqual(updated_tpl['proxy-groups'][0]['proxies'], ['DIRECT', new_disp])

                # Now managed nodes panel shows ONLY the 1 actively adopted node!
                m_after = client.get('/api/agents/managed/nodes', headers=headers).json()['nodes']
                self.assertEqual(len(m_after), 1)
                self.assertEqual(m_after[0]['source_key'], sk_vless)
                self.assertEqual(m_after[0]['adopted_status'], 'adopted')


if __name__ == '__main__':
    unittest.main()
