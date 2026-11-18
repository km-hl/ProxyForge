"""Phase 5 regression & integration tests: 5 protocols, dual-stack/Socks5 outbounds,
multi-node coexistence, public IP detection, full adoption, flags, and subscription linkage.
"""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from agent import adoption, main as agent_main, system_info
from agent.caddy_manager import render_caddyfile
from agent.landing_spec import (
    build_caddy_site_for_landing,
    client_node,
    deployment_tls_plan,
    runtime_config,
    validate_settings,
    validate_spec,
)
from agent.runtime_engine import RuntimeCoordinator, RuntimeEngine
from agent.runtime_spec import SERVICE_CADDY, SERVICE_SINGBOX, revision
from agent.deployment_spec import spec_hash
from fastapi.testclient import TestClient

from proxyforge.control.deployment_store import new_landing_spec
from proxyforge.subscription.links import parse_share_link, render_proxy_uri
from proxyforge.subscription.nodes import add_flag_to_proxy_name, has_country_flag, keyword_matches_name
from proxyforge.subscription.singbox import build_singbox_config, convert_proxy_to_singbox
from proxyforge.subscription.surge import build_surge_config, convert_proxy_to_surge
from proxyforge.subscription.validation import validate_proxy_nodes
from test_agent_jobs import capable
from test_api_integration import TEST_ADMIN_TOKEN, load_isolated_application
from test_deployments import RESULT


class Phase5ProtocolAndOutboundTests(unittest.TestCase):
    def test_anytls_spec_render_client_and_exports(self):
        spec = new_landing_spec(
            {
                'name': 'AnyTLS SG',
                'server': 'anytls.example.com',
                'listen_port': 443,
                'protocol': 'anytls',
                'domain': 'anytls.example.com',
                'tls_mode': 'acme_http',
                'padding_scheme': ['stop=8', '0=30-30'],
            },
            protocol='anytls',
        )
        validate_spec('landing.apply', spec)
        plan = deployment_tls_plan(spec)
        self.assertTrue(plan['needs_cert'])
        self.assertFalse(plan['needs_caddy'])
        self.assertEqual(plan['tls_mode'], 'acme_http')

        cfg = runtime_config(spec, cert_path='/tmp/cert.pem', key_path='/tmp/key.pem')
        inbound = cfg['inbounds'][0]
        self.assertEqual(inbound['type'], 'anytls')
        self.assertEqual(inbound['listen_port'], 443)
        self.assertEqual(inbound['padding_scheme'], ['stop=8', '0=30-30'])
        self.assertEqual(inbound['users'][0]['password'], spec['password'])
        self.assertTrue(inbound['tls']['enabled'])

        node = client_node('n1' * 16, 'a1' * 16, spec)
        self.assertEqual(node['type'], 'anytls')
        self.assertEqual(node['password'], spec['password'])
        self.assertEqual(node['sni'], 'anytls.example.com')
        self.assertEqual(validate_proxy_nodes([node]), [])

        sb_out = convert_proxy_to_singbox(node)
        self.assertEqual(sb_out['type'], 'anytls')
        self.assertEqual(sb_out['password'], spec['password'])

        uri = render_proxy_uri(node)
        self.assertTrue(uri.startswith('anytls://'))
        parsed = parse_share_link(uri)
        self.assertEqual(parsed['type'], 'anytls')
        self.assertEqual(parsed['port'], 443)

    def test_reality_self_steal_trojan_fallback_and_hy2_mport(self):
        # 1. VLESS Reality self-steal mode + max_time_difference
        real_spec = new_landing_spec(
            {
                'name': 'Reality Self',
                'server': 'real.example.com',
                'listen_port': 443,
                'protocol': 'reality',
                'domain': 'real.example.com',
                'tls_mode': 'acme_http',
                'fingerprint': 'firefox',
            },
            protocol='reality',
        )
        validate_spec('landing.apply', real_spec)
        real_plan = deployment_tls_plan(real_spec)
        self.assertEqual(real_plan['caddy_role'], 'loopback_camouflage')
        real_site = build_caddy_site_for_landing(real_spec, listen_port=28443)
        self.assertIsNotNone(real_site)
        rendered_caddy = render_caddyfile([real_site], cert_pairs={'landing': ('/tmp/c.crt', '/tmp/c.key')})
        self.assertIn('protocols h1 h2', rendered_caddy)

        real_cfg = runtime_config(real_spec, caddy_port=28443)
        real_tls = real_cfg['inbounds'][0]['tls']
        self.assertEqual(real_tls['reality']['handshake'], {'server': '127.0.0.1', 'server_port': 28443})
        self.assertEqual(real_tls['reality']['max_time_difference'], '1m')
        self.assertEqual(real_cfg['inbounds'][0]['users'][0]['flow'], 'xtls-rprx-vision')

        # 2. Trojan + loopback Caddy fallback
        trojan_spec = new_landing_spec(
            {
                'name': 'Trojan Fallback',
                'server': 'trojan.example.com',
                'listen_port': 8443,
                'protocol': 'trojan',
                'domain': 'trojan.example.com',
                'tls_mode': 'acme_http',
                'camouflage_url': 'https://example.org',
            },
            protocol='trojan',
        )
        validate_spec('landing.apply', trojan_spec)
        tr_plan = deployment_tls_plan(trojan_spec)
        self.assertEqual(tr_plan['caddy_role'], 'trojan_fallback')
        tr_site = build_caddy_site_for_landing(trojan_spec, listen_port=28080)
        self.assertEqual(tr_site['tls_mode'], 'none')
        self.assertEqual(tr_site['bind_host'], '127.0.0.1')
        tr_cfg = runtime_config(trojan_spec, caddy_port=28080, cert_path='/tmp/c.pem', key_path='/tmp/k.pem')
        self.assertEqual(tr_cfg['inbounds'][0]['fallback'], {'server': '127.0.0.1', 'server_port': 28080})

        # 3. Hysteria2 + mport + hop_interval across client_node / singbox / surge / URI
        hy2_spec = new_landing_spec(
            {
                'name': 'Hy2 Jump',
                'server': 'hy2.example.com',
                'listen_port': 443,
                'protocol': 'hysteria2',
                'domain': 'hy2.example.com',
                'tls_mode': 'acme_http',
                'mport': '20000-20099,25000',
                'hop_interval': 30,
                'obfs': 'salamander',
            },
            protocol='hysteria2',
        )
        validate_spec('landing.apply', hy2_spec)
        hy2_node = client_node('h1' * 16, 'a2' * 16, hy2_spec)
        self.assertEqual(hy2_node['ports'], '20000-20099,25000')
        self.assertEqual(hy2_node['hop-interval'], 30)
        sb_hy2 = convert_proxy_to_singbox(hy2_node)
        self.assertEqual(sb_hy2['server_ports'], ['20000:20099', '25000'])
        self.assertEqual(sb_hy2['hop_interval'], '30s')
        surge_hy2 = convert_proxy_to_surge(hy2_node)
        self.assertIn('port-hopping=20000-20099,25000', surge_hy2)
        self.assertIn('port-hopping-interval=30', surge_hy2)
        hy2_uri = render_proxy_uri(hy2_node)
        self.assertIn('mport=20000-20099%2C25000', hy2_uri.replace('mport=20000-20099,25000', 'mport=20000-20099%2C25000'))

    def test_outbound_strategies_and_external_socks5_ss_detour(self):
        for strategy in ('prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only'):
            spec = new_landing_spec(
                {
                    'name': f'Strat-{strategy}',
                    'server': '198.51.100.11',
                    'listen_port': 443,
                    'protocol': 'reality',
                    'domain': 'www.amazon.com',
                    'tls_mode': 'reality',
                    'outbound_strategy': strategy,
                },
                protocol='reality',
            )
            cfg = runtime_config(spec)
            self.assertEqual(cfg['outbounds'][0]['domain_strategy'], strategy)

        socks_spec = new_landing_spec(
            {
                'name': 'ISP Unlock',
                'server': '198.51.100.12',
                'listen_port': 8443,
                'protocol': 'anytls',
                'domain': 'unlock.example.com',
                'tls_mode': 'acme_http',
                'outbound_mode': 'socks5',
                'outbound_server': '192.0.2.55',
                'outbound_port': 1080,
                'outbound_username': 'ispuser',
                'outbound_strategy': 'prefer_ipv4',
            },
            protocol='anytls',
            secrets_input={'outbound_password': 'isp-secret-password'},
        )
        validate_spec('landing.apply', socks_spec)
        cfg = runtime_config(socks_spec, cert_path='/tmp/c.pem', key_path='/tmp/k.pem')
        tags = {o['tag']: o for o in cfg['outbounds']}
        self.assertIn('out-primary', tags)
        self.assertEqual(tags['out-primary']['type'], 'socks')
        self.assertEqual(tags['out-primary']['server'], '192.0.2.55')
        self.assertEqual(tags['out-primary']['password'], 'isp-secret-password')
        self.assertIn({'inbound': ['managed-landing'], 'outbound': 'out-primary'}, cfg['route']['rules'])

        with tempfile.TemporaryDirectory() as temp:
            module = load_isolated_application(Path(temp))
            store = module.control_store()
            admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            reg = store.register(store.issue_registration('IspVPS')['registration_token'], {**capable(), 'runtime_protocol_version': 1, 'landing_protocol_version': 1}, '198.51.100.12')
            with TestClient(module.app) as client:
                gen = client.post('/api/agents/deployments/generate-keys', headers=admin, json={'protocol': 'anytls'})
                self.assertEqual(gen.status_code, 200)
                kref = gen.json()['key_ref']
                created = client.post(
                    f"/api/agents/{reg['agent_id']}/nodes",
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'anytls',
                        'key_ref': kref,
                        'secrets': {'outbound_password': 'super-secret-socks-pw'},
                        'settings': {
                            'name': 'ISP Relay',
                            'server': '198.51.100.12',
                            'listen_port': 443,
                            'protocol': 'anytls',
                            'domain': 'anytls.example.com',
                            'tls_mode': 'acme_http',
                            'outbound_mode': 'socks5',
                            'outbound_server': '192.0.2.99',
                            'outbound_port': 1080,
                            'outbound_username': 'isp',
                        },
                    },
                )
                self.assertEqual(created.status_code, 200, created.text)
                self.assertNotIn('super-secret-socks-pw', created.text)
                listed = client.get(f"/api/agents/{reg['agent_id']}/nodes", headers=admin)
                self.assertEqual(listed.status_code, 200)
                self.assertNotIn('super-secret-socks-pw', listed.text)
            with store.connection() as db:
                self.assertNotIn('super-secret-socks-pw', '\n'.join(db.iterdump()))


class Phase5MultiNodeAndKomariTests(unittest.TestCase):
    def test_multinode_crud_port_conflict_and_komari_metadata(self):
        # Test public IP detector cleanly offline via mocks
        system_info._PUBLIC_IP_CACHE.update({'at': 0.0, 'ipv4': '', 'ipv6': ''})
        with patch.object(system_info, '_local_route_global_ips', return_value={'ipv4': '1.2.3.4', 'ipv6': '2606:4700::1234'}):
            addrs = system_info.detect_public_addresses(
                allow_network=True,
                ip_reader=lambda: {'ipv4': '8.8.8.8', 'ipv6': ''},
            )
        self.assertEqual(addrs, ['1.2.3.4', '2606:4700::1234'])

        system_info._PUBLIC_IP_CACHE.update({'at': 0.0, 'ipv4': '', 'ipv6': ''})
        with patch.object(system_info, '_local_route_global_ips', return_value={'ipv4': '', 'ipv6': ''}):
            addrs_net = system_info.detect_public_addresses(
                allow_network=True,
                ip_reader=lambda: {'ipv4': '8.8.8.8', 'ipv6': '2606:4700::2222'},
            )
        self.assertEqual(addrs_net, ['8.8.8.8', '2606:4700::2222'])

        with tempfile.TemporaryDirectory() as temp:
            module = load_isolated_application(Path(temp))
            store = module.control_store()
            admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            info = {**capable(), 'runtime_protocol_version': 1, 'landing_protocol_version': 1}
            info['addresses'] = ['8.8.8.8', '2606:4700::1234']
            reg = store.register(store.issue_registration('US-VPS')['registration_token'], info, '172.17.0.1')
            aid = reg['agent_id']

            with TestClient(module.app) as client:
                # Komari PATCH fields + public IPs exposed in GET /api/agents
                patch_resp = client.patch(
                    f'/api/agents/{aid}',
                    headers=admin,
                    json={
                        'name': '🇺🇸 ExampleVPS - LA',
                        'tags': ['传家宝', '2TB 双向'],
                        'region': 'us',
                        'expire_at': 1893456000,
                        'quota_bytes': 2 * 1024 ** 4,
                        'billing_label': '$6.75 / 年付',
                    },
                )
                self.assertEqual(patch_resp.status_code, 200, patch_resp.text)
                view = patch_resp.json()
                self.assertEqual(view['public_ipv4'], '8.8.8.8')
                self.assertEqual(view['public_ipv6'], '2606:4700::1234')
                self.assertEqual(view['billing_label'], '$6.75 / 年付')
                self.assertEqual(view['region'], 'us')

                # 1. Create primary Reality TCP 443
                r1 = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': '🇺🇸 LA Reality',
                            'server': '203.0.113.20',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'domain': 'www.amazon.com',
                            'tls_mode': 'reality',
                        },
                    },
                )
                self.assertEqual(r1.status_code, 200, r1.text)
                nodes1 = client.get(f'/api/agents/{aid}/nodes', headers=admin).json()['nodes']
                primary_id = nodes1[0]['id']

                job1 = store.claim_job(reg['agent_token'], info['instance_id'])
                store.report_job(reg['agent_token'], job1['id'], job1['lease_token'])
                store.report_job(reg['agent_token'], job1['id'], job1['lease_token'], RESULT)

                # 2. Reject TCP conflict on port 443 (Trojan uses TCP)
                conflict = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'trojan',
                        'settings': {
                            'name': 'Conflict Trojan',
                            'server': 'trojan.example.com',
                            'listen_port': 443,
                            'protocol': 'trojan',
                            'domain': 'trojan.example.com',
                            'tls_mode': 'acme_http',
                        },
                    },
                )
                self.assertEqual(conflict.status_code, 422)

                # 3. Allow UDP 443 Hysteria2 alongside TCP 443 Reality
                r2 = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=admin,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'hysteria2',
                        'settings': {
                            'name': '🇺🇸 LA Hy2',
                            'server': 'hy2.example.com',
                            'listen_port': 443,
                            'protocol': 'hysteria2',
                            'domain': 'hy2.example.com',
                            'tls_mode': 'acme_http',
                            'mport': '30000-30100',
                        },
                    },
                )
                self.assertEqual(r2.status_code, 200, r2.text)

                job2 = store.claim_job(reg['agent_token'], info['instance_id'])
                self.assertEqual(len(job2['deployment']['extra_nodes']), 1)
                store.report_job(reg['agent_token'], job2['id'], job2['lease_token'])
                store.report_job(reg['agent_token'], job2['id'], job2['lease_token'], RESULT)

                self.assertEqual(len(store.managed_nodes()), 2)

                # 4. Delete primary -> promotes Hy2 to primary cleanly (Bug 3 regression check)
                del1 = client.request(
                    'DELETE',
                    f'/api/agents/{aid}/nodes/{primary_id}',
                    headers=admin,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(del1.status_code, 200, del1.text)
                job3 = store.claim_job(reg['agent_token'], info['instance_id'])
                store.report_job(reg['agent_token'], job3['id'], job3['lease_token'])
                store.report_job(reg['agent_token'], job3['id'], job3['lease_token'], RESULT)
                remaining = client.get(f'/api/agents/{aid}/nodes', headers=admin).json()['nodes']
                self.assertEqual(len(remaining), 1)
                self.assertEqual(remaining[0]['protocol'], 'hysteria2')

                # 5. Delete remaining primary -> triggers landing.remove without cipher error
                del2 = client.request(
                    'DELETE',
                    f'/api/agents/{aid}/nodes/{remaining[0]["id"]}',
                    headers=admin,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(del2.status_code, 200, del2.text)
                self.assertEqual(del2.json()['action'], 'landing.remove')


class Phase5FullAdoptionTests(unittest.TestCase):
    def test_scan_secrets_upload_adopt_project_and_return_lifecycle(self):
        fake_pub = 'PubKeyForRealityTest0123456789abcdefABCDEF'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sb_cfg = root / 'sing-box.json'
            sb_cfg.write_text(
                json.dumps({
                    'inbounds': [{
                        'type': 'vless',
                        'tag': 'existing-reality',
                        'listen': '::',
                        'listen_port': 1443,
                        'users': [{'uuid': '11111111-1111-4111-8111-111111111111', 'flow': 'xtls-rprx-vision'}],
                        'tls': {
                            'enabled': True,
                            'server_name': 'www.apple.com',
                            'reality': {
                                'enabled': True,
                                'handshake': {'server': 'www.apple.com', 'server_port': 443},
                                'private_key': 'PRIV_KEY_SECRET_001',
                                'short_id': ['1a2b3c4d'],
                            },
                        },
                    }],
                }),
                encoding='utf-8',
            )
            with patch('agent.adoption.derive_reality_public_key', return_value=fake_pub):
                scan = adoption.scan_host(
                    proc=root / 'empty-proc',
                    extra_configs=[{'core': 'sing-box', 'config_path': str(sb_cfg), 'service_name': 'sing-box.service', 'pid': 200}],
                )
                extracted = adoption.last_extracted_credentials()
            self.assertEqual(len(scan['endpoints']), 1)
            skey = scan['endpoints'][0]['source_key']
            self.assertIn(skey, extracted)
            self.assertEqual(extracted[skey]['credentials']['reality_public_key'], fake_pub)
            self.assertEqual(extracted[skey]['credentials']['reality_short_id'], '1a2b3c4d')
            self.assertEqual(extracted[skey]['inbound']['listen_port'], 1443)
            self.assertNotIn('PRIV_KEY_SECRET_001', json.dumps(scan))

            # Verify RuntimeCoordinator calls adopt_host_service with correct positional args (Bug 1)
            backup_dir = root / 'adoptions'
            cmds = []
            meta = adoption.adopt_host_service(
                'sing-box.service', str(sb_cfg), skey, backup_root=backup_dir, runner=cmds.append
            )
            self.assertEqual(cmds[-1], ['/usr/bin/systemctl', 'disable', '--now', 'sing-box.service'])
            self.assertTrue((backup_dir / skey / 'config.bak').is_file())
            ret = adoption.return_host_service(skey, backup_root=backup_dir, runner=cmds.append)
            self.assertTrue(ret['returned'])
            self.assertEqual(cmds[-1], ['/usr/bin/systemctl', 'enable', '--now', 'sing-box.service'])

            mock_sb_engine = Mock()
            mock_sb_engine.apply.return_value = {'status': 'success', 'output': {'active': True}, 'error': None}
            coord = RuntimeCoordinator({SERVICE_SINGBOX: mock_sb_engine})
            dep_spec = {
                'adopted_only': True,
                'adopted_nodes': [{'source_key': skey, 'original_service': 'sing-box.service', 'original_config_path': str(sb_cfg), 'inbound': extracted[skey]['inbound']}],
                'returned_adoptions': [skey],
            }
            job_id = 'a' * 32
            payload = {'deployment_id': 'c' * 32, 'revision': 1, 'spec_hash': spec_hash(dep_spec)}
            with patch('agent.adoption.adopt_host_service') as m_adopt, patch('agent.adoption.return_host_service') as m_ret:
                coord.apply(
                    {
                        'id': job_id,
                        'type': 'landing.apply',
                        'payload': payload,
                        'deployment_revision': revision(job_id, 'landing.apply', payload),
                        'deployment': dep_spec,
                    },
                    lambda: None,
                )
            m_adopt.assert_called_once_with('sing-box.service', str(sb_cfg), skey)
            m_ret.assert_called_once_with(skey)

            # End-to-end Controller upload via agent_main._flush_adopted_credentials + adopt & return APIs
            ctrl_root = root / 'ctrl'
            ctrl_root.mkdir()
            module = load_isolated_application(ctrl_root)
            store = module.control_store()
            admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            info = {**capable(), 'runtime_protocol_version': 1, 'landing_protocol_version': 1, 'addresses': ['198.51.100.77']}
            reg = store.register(store.issue_registration('AdoptFullVPS')['registration_token'], info, '198.51.100.77')
            aid = reg['agent_id']

            with TestClient(module.app) as client:
                self.assertEqual(
                    client.post('/api/agent/adoptions', headers={'Authorization': 'Bearer ' + reg['agent_token']}, json={**scan, 'instance_id': info['instance_id']}).status_code,
                    200,
                )
                class _ClientAdapter:
                    def post(self, path, data, token):
                        resp = client.post(path, json=data, headers={'Authorization': 'Bearer ' + token})
                        if resp.status_code >= 400:
                            raise AssertionError(resp.text)
                        return resp.json()

                adoption._LAST_EXTRACTED_CREDENTIALS = dict(extracted)
                agent_main._flush_adopted_credentials(_ClientAdapter(), {'instance_id': info['instance_id'], 'token': reg['agent_token']})
                self.assertEqual(adoption.last_extracted_credentials(), {})

                ad_list = client.get(f'/api/agents/{aid}/adoptions', headers=admin).json()['adoptions']
                self.assertTrue(ad_list[0]['has_credentials'])
                self.assertEqual(ad_list[0]['adopted_status'], 'discovered')

                adopt_resp = client.post(
                    f'/api/agents/{aid}/adoptions/{skey}/adopt',
                    headers=admin,
                    json={'request_id': uuid.uuid4().hex, 'custom_name': '🇯🇵 Migrated Reality', 'server_override': '198.51.100.77'},
                )
                self.assertEqual(adopt_resp.status_code, 200, adopt_resp.text)
                job = store.claim_job(reg['agent_token'], info['instance_id'])
                self.assertTrue(job['deployment']['adopted_only'])
                self.assertEqual(len(job['deployment']['adopted_nodes']), 1)
                store.report_job(reg['agent_token'], job['id'], job['lease_token'])
                store.report_job(reg['agent_token'], job['id'], job['lease_token'], RESULT)

                projected = store.managed_nodes()
                self.assertEqual(len(projected), 1)
                self.assertEqual(projected[0]['reality-opts']['public-key'], fake_pub)
                self.assertEqual(projected[0]['reality-opts']['short-id'], '1a2b3c4d')
                self.assertIn('Migrated Reality', projected[0]['name'])

                ret_resp = client.post(
                    f'/api/agents/{aid}/adoptions/{skey}/return',
                    headers=admin,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(ret_resp.status_code, 200, ret_resp.text)
                self.assertEqual(store.managed_nodes(), [])


class Phase5FlagsAndSubscriptionLinkageTests(unittest.TestCase):
    def test_flag_word_boundary_and_singbox_surge_linkage(self):
        self.assertFalse(has_country_flag('New Node'))
        self.assertFalse(keyword_matches_name('New Node', 'de'))
        self.assertFalse(keyword_matches_name('Landing', 'in'))
        self.assertFalse(keyword_matches_name('Custom', 'us'))
        self.assertEqual(add_flag_to_proxy_name('New Node'), 'New Node')
        self.assertEqual(add_flag_to_proxy_name('Landing'), 'Landing')
        self.assertEqual(add_flag_to_proxy_name('Tokyo 01'), '🇯🇵 Tokyo 01')
        self.assertEqual(add_flag_to_proxy_name('DE 01'), '🇩🇪 DE 01')

        tpl = {
            'ipv6': False,
            'dns': {
                'enable': True,
                'ipv6': False,
                'enhanced-mode': 'fake-ip',
                'fake-ip-range': '198.18.0.1/16',
                'default-nameserver': ['223.5.5.5'],
                'nameserver': ['https://dns.alidns.com/dns-query'],
                'fallback': ['https://cloudflare-dns.com/dns-query'],
            },
            'tun': {
                'enable': True,
                'stack': 'mixed',
                'mtu': 1400,
                'auto-route': True,
                'strict-route': True,
            },
            'proxy-groups': [{'name': '🚀 Proxy', 'type': 'select', 'proxies': ['🇯🇵 Node 1']}],
            'rules': ['MATCH,🚀 Proxy'],
        }
        proxies = [{'name': '🇯🇵 Node 1', 'type': 'trojan', 'server': 'example.com', 'port': 443, 'password': 'pw'}]
        sb, sb_skipped = build_singbox_config({**tpl, 'proxies': proxies})
        self.assertEqual(sb_skipped, 0)
        self.assertEqual(sb['dns']['strategy'], 'ipv4_only')
        self.assertEqual(sb['inbounds'][0]['mtu'], 1400)
        self.assertEqual(sb['inbounds'][0]['stack'], 'mixed')

        surge_ini, surge_skipped = build_surge_config({**tpl, 'proxies': proxies})
        self.assertEqual(surge_skipped, 0)
        self.assertIn('ipv6 = false', surge_ini)
        self.assertIn('223.5.5.5', surge_ini)
        self.assertIn('https://dns.alidns.com/dns-query', surge_ini)


if __name__ == '__main__':
    unittest.main()
