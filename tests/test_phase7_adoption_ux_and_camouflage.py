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
from proxyforge.control.job_store import JobConflict
from proxyforge.subscription.nodes import add_flag_to_proxy_name
from test_agent_jobs import capable
from test_api_integration import TEST_ADMIN_TOKEN, load_isolated_application
from test_deployments import RESULT

NOT_INSTALLED_RESULT = {
    'status': 'success',
    'output': {'installed': False, 'running': False, 'version': '', 'status': 'not_installed'},
    'error': None,
}


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

    def test_acme_root_inside_runtime_dir_and_runtime_error_classification(self):
        from agent.acme_manager import AcmeError
        from agent.runtime_helper import _classify_runtime_error
        from agent.runtime_spec import RUNTIME_ERRORS
        from proxyforge.control.job_api import JobResult

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'proxyforge-runtime'
            root.mkdir()
            mock_sb = Mock()
            mock_sb.root = root
            coord = RuntimeCoordinator({SERVICE_SINGBOX: mock_sb})
            # Must stay INSIDE /var/lib/proxyforge-runtime (ReadWritePaths), never .parent/acme!
            self.assertEqual(coord._get_acme_manager().state_dir, root / 'acme')

        cases = [
            (AcmeError('certbot is required on the host for ACME issuance'), 'acme_certbot_missing'),
            (CaddyError('certbot is required on the host for ACME issuance'), 'acme_certbot_missing'),
            (CaddyError('Missing certbot plugin: dns-cloudflare'), 'acme_dns_plugin_missing'),
            (CaddyError('Port 0.0.0.0:80/tcp is already in use or unavailable'), 'acme_port80_in_use'),
            (AcmeError('Domain DNS A/AAAA records do not match host public IP addresses'), 'acme_dns_mismatch'),
            (AcmeError('Other failure with secret-token-123'), 'acme_failed'),
            (CaddyError('Caddyfile syntax error'), 'caddy_failed'),
            (ValueError('Port conflict with sing-box'), 'port_conflict'),
            (ValueError('Runtime configuration check failed'), 'config_check_failed'),
            (ValueError('Runtime failed health verification'), 'health_check_failed'),
            (ValueError('Unauthorized local peer'), 'runtime_failed'),
        ]
        for exc, expected in cases:
            code = _classify_runtime_error(exc)
            self.assertEqual(code, expected)
            self.assertIn(code, RUNTIME_ERRORS)
            parsed = JobResult(status='failed', output=None, error=code)
            self.assertEqual(parsed.error, expected)
        # Arbitrary secret error strings remain rejected by JobResult
        with self.assertRaises(ValueError):
            JobResult(status='failed', output=None, error='raw-secret-stderr')


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
                # Real agent returns not_installed when adopted_only has no active adopted nodes
                rep_dis = store.report_job(atok, job_dis['id'], job_dis['lease_token'], NOT_INSTALLED_RESULT)
                self.assertEqual(rep_dis['status'], 'success')

                # Re-scan without xray running must keep disabled records so user can restore
                store.record_adoption_scan(atok, inst, {'scanned_at': 1700000100, 'services': [], 'endpoints': []})
                ad_after_dis = {x['source_key']: x for x in store.list_adopted_nodes(aid)}
                self.assertEqual(ad_after_dis[sk_vless]['adopted_status'], 'disabled')
                self.assertEqual(ad_after_dis[sk_gate]['adopted_status'], 'disabled')

                # Restore original service (also succeeds with not_installed report)
                r_ret = client.post(
                    f'/api/agents/{aid}/adoptions/{sk_vless}/return',
                    headers=headers,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(r_ret.status_code, 200, r_ret.text)
                job_ret = store.claim_job(atok, inst)
                self.assertIn(sk_vless, job_ret['deployment']['returned_adoptions'])
                store.report_job(atok, job_ret['id'], job_ret['lease_token'])
                rep_ret = store.report_job(atok, job_ret['id'], job_ret['lease_token'], NOT_INSTALLED_RESULT)
                self.assertEqual(rep_ret['status'], 'success')

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

                # Complete adopt job so we can test subsequent node creation + overview
                job_ad = store.claim_job(atok, inst)
                store.report_job(atok, job_ad['id'], job_ad['lease_token'])
                # Adopted job HAS active adopted_nodes -> must STILL reject not_installed!
                with self.assertRaises(JobConflict):
                    store.report_job(atok, job_ad['id'], job_ad['lease_token'], NOT_INSTALLED_RESULT)
                store.report_job(atok, job_ad['id'], job_ad['lease_token'], RESULT)

                # Now managed nodes panel shows ONLY the 1 actively adopted node with clean name!
                m_after = client.get('/api/agents/managed/nodes', headers=headers).json()['nodes']
                self.assertEqual(len(m_after), 1)
                self.assertEqual(m_after[0]['name'], manual_name)
                self.assertNotIn('[pf:', m_after[0]['name'])
                self.assertEqual(m_after[0]['source_key'], sk_vless)
                self.assertEqual(m_after[0]['adopted_status'], 'adopted')

    def test_disable_report_unblocks_new_node_and_overview_exposes_per_agent_inventory(self):
        headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_mod = load_isolated_application(root)
            store = app_mod.control_store()
            info = {
                **capable(),
                'runtime_protocol_version': 1,
                'landing_protocol_version': 1,
                'gost_protocol_version': 1,
                'addresses': ['189.24.84.212'],
            }
            reg = store.register(store.issue_registration('DE-9929')['registration_token'], info, '189.24.84.212')
            aid, atok, inst = reg['agent_id'], reg['agent_token'], info['instance_id']

            sk_old = 'adopt-' + '9' * 16
            sk_aux = 'adopt-' + '8' * 16
            store.record_adoption_scan(atok, inst, {
                'scanned_at': 1700000000,
                'services': [
                    {'core': 'xray', 'pid': 200, 'service_name': 'nodepilot-n-1.service', 'config_path': '/etc/np/c.json', 'config_sha256': 'a' * 64},
                    {'core': 'caddy', 'pid': 201, 'service_name': 'nodepilot-caddy.service', 'config_path': '/etc/np/caddy.json', 'config_sha256': 'b' * 64},
                ],
                'endpoints': [
                    {
                        'source_key': sk_old, 'core': 'xray', 'service_name': 'nodepilot-n-1.service',
                        'config_path': '/etc/np/c.json', 'config_sha256': 'a' * 64,
                        'tag': 'old-vless', 'protocol': 'vless', 'listen': '0.0.0.0', 'listen_port': 443,
                        'tls_mode': 'reality', 'sni': 'old.example.com', 'network': 'tcp', 'ws_path': '', 'adoptable': True,
                    },
                    {
                        'source_key': sk_aux, 'core': 'caddy', 'service_name': 'nodepilot-caddy.service',
                        'config_path': '/etc/np/caddy.json', 'config_sha256': 'b' * 64,
                        'tag': 'caddy-1', 'protocol': 'caddy-site', 'listen': '127.0.0.1', 'listen_port': 8003,
                        'tls_mode': 'tls', 'sni': 'old.example.com', 'network': 'http', 'ws_path': '', 'adoptable': False,
                    },
                ],
            })

            with TestClient(app_mod.app) as client:
                # 1. Disable old service and report real not_installed output -> job succeeds immediately
                r_dis = client.post(
                    f'/api/agents/{aid}/adoptions/{sk_old}/disable',
                    headers=headers,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(r_dis.status_code, 200)
                j_dis = store.claim_job(atok, inst)
                store.report_job(atok, j_dis['id'], j_dis['lease_token'])
                store.report_job(atok, j_dis['id'], j_dis['lease_token'], NOT_INSTALLED_RESULT)

                # 2. Immediately create internal SS2022 node (must NOT hit 409 JobConflict!)
                r_ss = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'ss2022',
                        'settings': {
                            'name': 'DE Internal SS',
                            'server': '189.24.84.212',
                            'listen_port': 8388,
                            'protocol': 'ss2022',
                            'tls_mode': 'none',
                            'method': '2022-blake3-aes-256-gcm',
                            'publish_to_subscription': False,
                        },
                    },
                )
                self.assertEqual(r_ss.status_code, 200, r_ss.text)
                j_ss = store.claim_job(atok, inst)
                store.report_job(atok, j_ss['id'], j_ss['lease_token'])
                # Normal landing deployment must STILL reject not_installed!
                with self.assertRaises(JobConflict):
                    store.report_job(atok, j_ss['id'], j_ss['lease_token'], NOT_INSTALLED_RESULT)
                store.report_job(atok, j_ss['id'], j_ss['lease_token'], RESULT)

                # 3. Add a coexisting Reality node on :8443
                r_real = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'DE Reality',
                            'server': '189.24.84.212',
                            'listen_port': 8443,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                        },
                    },
                )
                self.assertEqual(r_real.status_code, 200, r_real.text)
                j_real = store.claim_job(atok, inst)
                store.report_job(atok, j_real['id'], j_real['lease_token'])
                store.report_job(atok, j_real['id'], j_real['lease_token'], RESULT)

                # 4. Add a go-gost forward rule on :10001
                r_fw = client.post(
                    f'/api/agents/{aid}/forwards',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'name': 'Relay-HK',
                        'listen_port': 10001,
                        'protocol': 'tcp+udp',
                        'mode': 'direct',
                        'targets': [{'name': 'hk', 'addr': '1.2.3.4:8388'}],
                    },
                )
                self.assertEqual(r_fw.status_code, 200, r_fw.text)

                # 5. Fetch per-agent overview and verify ALL nodes (including internal SS2022), forwards, adoptions & zero secrets!
                ov_resp = client.get('/api/agents/deployments/overview', headers=headers)
                self.assertEqual(ov_resp.status_code, 200, ov_resp.text)
                ov_body = ov_resp.json()
                ov = ov_body['agents'][aid]
                self.assertEqual(len(ov['nodes']), 2)
                by_port = {n['port']: n for n in ov['nodes']}
                self.assertEqual(by_port[8388]['kind'], 'ss2022_internal')
                self.assertEqual(by_port[8388]['name'], 'DE Internal SS')
                self.assertFalse(by_port[8388]['publishable'])
                self.assertEqual(by_port[8443]['kind'], 'direct')
                self.assertEqual(by_port[8443]['protocol'], 'reality')
                self.assertTrue(by_port[8443]['publishable'])
                self.assertEqual(len(ov['forwards']), 1)
                self.assertEqual(ov['forwards'][0]['listen_port'], 10001)
                self.assertEqual(ov['adoptions']['disabled'], 1)
                self.assertEqual(ov['adoptions']['auxiliary'], 1)
                self.assertEqual(ov['adoptions']['discovered'], 0)
                self.assertIsNotNone(ov['active_job'])
                self.assertEqual(ov['active_job']['type'], 'gost.apply')
                serialized = json.dumps(ov_body)
                self.assertNotIn('private_key', serialized)
                self.assertNotIn('password', serialized)
                self.assertNotIn('secret_spec', serialized)


if __name__ == '__main__':
    unittest.main()
