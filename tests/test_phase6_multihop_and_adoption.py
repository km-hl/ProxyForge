"""Phase 6 regression & integration tests:
- NodePilot Xray `-config` / auto-core adoption & read-only Caddy camouflage handling
- Multi-hop `sing-box` `detour` chains (1..4 hops, managed SS2022 + external SS/Socks5)
- Single-entry multi-landing chaining via `agent_nodes` + `GET /api/agents/deployments/ss-landings`
- `go-gost` `public_ipv4` relay preference and recursive multi-hop `apply_prefer_relay`
"""
import base64
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi.testclient import TestClient

from agent import adoption
from agent.landing_spec import runtime_config, validate_settings, validate_spec
from proxyforge.control.deployment_store import new_landing_spec
from proxyforge.subscription.nodes import apply_prefer_relay
from test_agent_jobs import capable
from test_api_integration import TEST_ADMIN_TOKEN, load_isolated_application
from test_deployments import RESULT


def _b64url_raw(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _generate_x25519_pair():
    priv = x25519.X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64url_raw(priv_raw), _b64url_raw(pub_raw)


class Phase6AdoptionFixesTests(unittest.TestCase):
    def test_extract_config_paths_supports_single_dash_config_and_equals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg1 = root / 'nodepilot.json'
            cfg2 = root / 'custom.json'
            rel_dir = root / 'app' / 'rel'
            rel_dir.mkdir(parents=True)
            cfg3 = rel_dir / 'config.json'
            for f in (cfg1, cfg2, cfg3):
                f.write_text('{}', encoding='utf-8')

            argv1 = ['/opt/nodepilot/cores/xray/current/xray', 'run', '-config', str(cfg1)]
            argv2 = ['/usr/local/bin/xray', 'run', f'-config={cfg2}']
            argv3 = ['/usr/local/bin/xray', '-config', 'rel/config.json']
            self.assertEqual(adoption._extract_config_paths_from_argv('xray', argv1), [cfg1])
            self.assertEqual(adoption._extract_config_paths_from_argv('xray', argv2), [cfg2])
            self.assertEqual(adoption._extract_config_paths_from_argv('xray', argv3, cwd=root / 'app'), [cfg3])

    def test_nodepilot_xray_auto_detect_xver_and_caddy_readonly(self):
        priv_b64, expected_pub_b64 = _generate_x25519_pair()
        uid = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray_cfg_path = root / 'nodepilot_xray.json'
            xray_cfg = {
                'inbounds': [{
                    'tag': 'nodepilot-vless',
                    'listen': '0.0.0.0',
                    'port': 443,
                    'protocol': 'vless',
                    'settings': {
                        'clients': [{'id': uid, 'flow': 'xtls-rprx-vision'}],
                        'decryption': 'none',
                    },
                    'streamSettings': {
                        'network': 'tcp',
                        'security': 'reality',
                        'realitySettings': {
                            'target': '127.0.0.1:8003',
                            'xver': 1,
                            'serverNames': ['reality.example.com'],
                            'privateKey': priv_b64,
                            'shortIds': ['a1b2c3d4'],
                        },
                    },
                }],
            }
            xray_cfg_path.write_text(json.dumps(xray_cfg), encoding='utf-8')

            sb_cfg_path = root / 'nodepilot_sb.json'
            sb_cfg = {
                'inbounds': [{
                    'type': 'shadowsocks',
                    'tag': 'sb-ss',
                    'listen': '::',
                    'listen_port': 8388,
                    'method': '2022-blake3-aes-256-gcm',
                    'password': base64.b64encode(b'k' * 32).decode('ascii'),
                }],
            }
            sb_cfg_path.write_text(json.dumps(sb_cfg), encoding='utf-8')

            caddy_cfg_path = root / 'caddy.json'
            caddy_cfg = {
                'apps': {
                    'http': {
                        'servers': {
                            'srv0': {
                                'listen': ['127.0.0.1:8003'],
                                'routes': [{'match': [{'host': ['reality.example.com']}]}],
                            },
                            'srv1': {
                                'listen': ['0.0.0.0:80'],
                                'routes': [{'match': [{'host': ['reality.example.com']}]}],
                            },
                        },
                    },
                },
            }
            caddy_cfg_path.write_text(json.dumps(caddy_cfg), encoding='utf-8')

            self.assertEqual(adoption._detect_json_core(xray_cfg), 'xray')
            self.assertEqual(adoption._detect_json_core(sb_cfg), 'sing-box')

            extra = [
                {'core': 'auto', 'service_name': 'nodepilot-n-1.service', 'config_path': str(xray_cfg_path), 'pid': 101},
                {'core': 'auto', 'service_name': 'nodepilot-n-2.service', 'config_path': str(sb_cfg_path), 'pid': 102},
                {'core': 'caddy', 'service_name': 'nodepilot-caddy.service', 'config_path': str(caddy_cfg_path), 'pid': 103},
            ]
            scan = adoption.scan_host(proc=root / 'empty-proc', extra_configs=extra)
            extracted = adoption.extract_host_credentials(
                proc=root / 'empty-proc',
                extra_configs=extra,
                pubkey_deriver=lambda _priv: expected_pub_b64,
            )

            self.assertTrue(adoption.valid_adopt_output(scan))
            eps = scan['endpoints']
            xray_ep = next(ep for ep in eps if ep['protocol'] == 'vless')
            sb_ep = next(ep for ep in eps if ep['protocol'] == 'shadowsocks')
            caddy_eps = [ep for ep in eps if ep['core'] == 'caddy']

            self.assertEqual(xray_ep['core'], 'xray')
            self.assertTrue(xray_ep['adoptable'])
            self.assertEqual(sb_ep['core'], 'sing-box')
            self.assertTrue(sb_ep['adoptable'])
            self.assertEqual(len(caddy_eps), 2)
            for cep in caddy_eps:
                self.assertEqual(cep['protocol'], 'caddy-site')
                self.assertFalse(cep['adoptable'])

            xray_cred_item = extracted[xray_ep['source_key']]
            creds = xray_cred_item['credentials']
            self.assertEqual(creds['uuid'], uid)
            self.assertEqual(creds['reality_public_key'], expected_pub_b64)
            self.assertEqual(creds['xray_xver'], 1)
            sb_inb = xray_cred_item['inbound']
            self.assertEqual(sb_inb['type'], 'vless')
            self.assertEqual(sb_inb['tls']['reality']['max_time_difference'], '1m')
            self.assertEqual(sb_inb['tls']['reality']['handshake'], {'server': '127.0.0.1', 'server_port': 8003})
            # Caddy must not emit extractable credentials
            for cep in caddy_eps:
                self.assertNotIn(cep['source_key'], extracted)


class Phase6MultiHopDetourSpecTests(unittest.TestCase):
    def test_multihop_chain_validation_and_detour_compilation(self):
        base = {
            'name': 'IX MultiHop',
            'server': '1.2.3.4',
            'listen_port': 20001,
            'protocol': 'reality',
            'tls_mode': 'reality',
            'domain': 'www.amazon.com',
            'outbound_strategy': 'prefer_ipv4',
            'outbound_mode': 'chain',
            'outbound_hops': [
                {'kind': 'managed_ss', 'agent_id': 'a' * 32, 'node_id': 'n1'},
                {'kind': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': '2022-blake3-aes-256-gcm'},
                {'kind': 'socks5', 'server': '1.1.1.1', 'port': 1080, 'username': 'ispuser'},
            ],
        }
        validate_settings(base, protocol='reality')

        # Reject plaintext password inside outbound_hops
        bad_pw = dict(base)
        bad_pw['outbound_hops'] = [{'kind': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': 'aes-256-gcm', 'password': 'leak'}]
        with self.assertRaises(ValueError):
            validate_settings(bad_pw, protocol='reality')

        # Reject > 4 hops
        too_many = dict(base)
        too_many['outbound_hops'] = [{'kind': 'managed_ss', 'agent_id': 'a' * 32, 'node_id': f'n{i}'} for i in range(5)]
        with self.assertRaises(ValueError):
            validate_settings(too_many, protocol='reality')

        # Compile resolved 3-hop detour chain into sing-box config
        spec = new_landing_spec(base, protocol='reality')
        spec['resolved_outbound_hops'] = [
            {'type': 'ss', 'server': '8.8.4.4', 'port': 8388, 'method': '2022-blake3-aes-256-gcm', 'password': 'p1'},
            {'type': 'ss', 'server': '8.8.8.8', 'port': 9388, 'method': '2022-blake3-aes-256-gcm', 'password': 'p2'},
            {'type': 'socks5', 'server': '1.1.1.1', 'port': 1080, 'username': 'ispuser', 'password': 'p3'},
        ]
        validate_spec('landing.apply', spec)
        cfg = runtime_config(spec)
        outbounds_by_tag = {o['tag']: o for o in cfg['outbounds']}
        self.assertIn('out-primary-h1', outbounds_by_tag)
        self.assertIn('out-primary-h2', outbounds_by_tag)
        self.assertIn('out-primary-h3', outbounds_by_tag)

        h1 = outbounds_by_tag['out-primary-h1']
        h2 = outbounds_by_tag['out-primary-h2']
        h3 = outbounds_by_tag['out-primary-h3']
        self.assertEqual(h1['type'], 'shadowsocks')
        self.assertEqual(h1['domain_strategy'], 'prefer_ipv4')
        self.assertNotIn('detour', h1)
        self.assertEqual(h2['type'], 'shadowsocks')
        self.assertEqual(h2['detour'], 'out-primary-h1')
        self.assertEqual(h3['type'], 'socks')
        self.assertEqual(h3['detour'], 'out-primary-h2')
        self.assertEqual(h3['username'], 'ispuser')
        self.assertEqual(h3['password'], 'p3')

        rules = cfg['route']['rules']
        self.assertTrue(any(r.get('inbound') == ['managed-landing'] and r.get('outbound') == 'out-primary-h3' for r in rules))


class Phase6ControlPlaneAndRelayTests(unittest.TestCase):
    def _register(self, store, name, public_ipv4, observed_ip='10.0.0.2', gost=True):
        info = {
            **capable(),
            'runtime_protocol_version': 1,
            'landing_protocol_version': 1,
            'chain_protocol_version': 1,
            'addresses': [public_ipv4],
        }
        if gost:
            info['gost_protocol_version'] = 1
        reg = store.register(store.issue_registration(name)['registration_token'], info, observed_ip)
        return reg['agent_id'], reg['agent_token'], info['instance_id']

    def _complete_pending_job(self, store, agent_token, instance_id):
        job = store.claim_job(agent_token, instance_id)
        self.assertIsNotNone(job)
        store.report_job(agent_token, job['id'], job['lease_token'])
        store.report_job(agent_token, job['id'], job['lease_token'], RESULT)
        return job

    def test_single_entry_multi_landing_chaining_ss_landings_and_secret_hygiene(self):
        headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            app_mod = load_isolated_application(Path(tmp))
            store = app_mod.control_store()
            entry_id, entry_tok, entry_inst = self._register(store, 'IX-Entry', '1.2.3.4')
            sg_id, sg_tok, sg_inst = self._register(store, 'SG-Landing', '8.8.8.8')
            jp_id, jp_tok, jp_inst = self._register(store, 'JP-Landing', '1.1.1.1')

            with TestClient(app_mod.app) as client:
                # 1. Deploy primary SS2022 on SG-Landing
                r_sg = client.post(
                    f'/api/agents/{sg_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'ss2022',
                        'settings': {
                            'name': 'SG SS2022 Primary',
                            'server': '8.8.8.8',
                            'listen_port': 8388,
                            'protocol': 'ss2022',
                            'tls_mode': 'none',
                            'method': '2022-blake3-aes-256-gcm',
                        },
                    },
                )
                self.assertEqual(r_sg.status_code, 200, r_sg.text)
                sg_node_id = r_sg.json()['node_id']
                self._complete_pending_job(store, sg_tok, sg_inst)

                # 2. Deploy Reality primary + SS2022 EXTRA node on JP-Landing
                r_jp1 = client.post(
                    f'/api/agents/{jp_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'JP Reality Primary',
                            'server': '1.1.1.1',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                        },
                    },
                )
                self.assertEqual(r_jp1.status_code, 200, r_jp1.text)
                self._complete_pending_job(store, jp_tok, jp_inst)

                r_jp2 = client.post(
                    f'/api/agents/{jp_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'ss2022',
                        'settings': {
                            'name': 'JP SS2022 Coexist',
                            'server': '1.1.1.1',
                            'listen_port': 9388,
                            'protocol': 'ss2022',
                            'tls_mode': 'none',
                            'method': '2022-blake3-aes-128-gcm',
                        },
                    },
                )
                self.assertEqual(r_jp2.status_code, 200, r_jp2.text)
                jp_ss_node_id = r_jp2.json()['node_id']
                self._complete_pending_job(store, jp_tok, jp_inst)

                # 3. GET /api/agents/deployments/ss-landings must discover BOTH primary and extra SS2022 without leaking passwords
                landings_res = client.get('/api/agents/deployments/ss-landings', headers=headers)
                self.assertEqual(landings_res.status_code, 200)
                landings = landings_res.json()['landings']
                self.assertEqual(len(landings), 2)
                by_pair = {(l['agent_id'], l['node_id']): l for l in landings}
                self.assertIn((sg_id, sg_node_id), by_pair)
                self.assertIn((jp_id, jp_ss_node_id), by_pair)
                self.assertEqual(by_pair[(jp_id, jp_ss_node_id)]['listen_port'], 9388)
                for l in landings:
                    self.assertNotIn('password', l)
                    self.assertNotIn('secret_spec', l)

                # 4. On IX-Entry, deploy 3 concurrent nodes: Direct(:443), Chain1(:20001 -> SG), Chain2(:20002 -> SG -> JP -> ExtSocks5)
                r_e1 = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'IX Direct',
                            'server': '1.2.3.4',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                        },
                    },
                )
                self.assertEqual(r_e1.status_code, 200, r_e1.text)
                self._complete_pending_job(store, entry_tok, entry_inst)

                r_e2 = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'IX to SG',
                            'server': '1.2.3.4',
                            'listen_port': 20001,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                            'outbound_mode': 'chain',
                            'outbound_hops': [{'kind': 'managed_ss', 'agent_id': sg_id, 'node_id': sg_node_id}],
                        },
                    },
                )
                self.assertEqual(r_e2.status_code, 200, r_e2.text)
                self._complete_pending_job(store, entry_tok, entry_inst)

                r_e3 = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'IX to SG to JP to ISP',
                            'server': '1.2.3.4',
                            'listen_port': 20002,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                            'outbound_mode': 'chain',
                            'outbound_hops': [
                                {'kind': 'managed_ss', 'agent_id': sg_id, 'node_id': sg_node_id},
                                {'kind': 'managed_ss', 'agent_id': jp_id, 'node_id': jp_ss_node_id},
                                {'kind': 'socks5', 'server': '9.9.9.9', 'port': 1080, 'username': 'isp_u'},
                            ],
                        },
                        'secrets': {'hop_passwords': {'2': 'super-secret-isp-pw'}},
                    },
                )
                self.assertEqual(r_e3.status_code, 200, r_e3.text)
                chain2_id = r_e3.json()['node_id']
                job_e3 = self._complete_pending_job(store, entry_tok, entry_inst)

                # Verify compiled Agent job payload resolves all 3 hops cleanly and compiles into valid sing-box detour config
                spec = job_e3['deployment']
                self.assertEqual(len(spec['extra_nodes']), 2)
                extra2 = next(n for n in spec['extra_nodes'] if n['listen_port'] == 20002)
                self.assertNotIn('hop_passwords', extra2)
                self.assertEqual(len(extra2['resolved_outbound_hops']), 3)
                self.assertEqual(extra2['resolved_outbound_hops'][0]['server'], '8.8.8.8')
                self.assertEqual(extra2['resolved_outbound_hops'][1]['server'], '1.1.1.1')
                self.assertEqual(extra2['resolved_outbound_hops'][1]['port'], 9388)
                self.assertEqual(extra2['resolved_outbound_hops'][2]['password'], 'super-secret-isp-pw')

                compiled_sb = runtime_config(spec)
                self.assertEqual(len(compiled_sb['inbounds']), 3)
                out_tags = {o['tag']: o for o in compiled_sb['outbounds']}
                h3_list = [o for t, o in out_tags.items() if t.endswith('-h3')]
                self.assertEqual(len(h3_list), 1)
                self.assertEqual(h3_list[0]['type'], 'socks')
                self.assertTrue(h3_list[0]['detour'].endswith('-h2'))

                # Verify API response NEVER leaks hop passwords
                nodes_resp = client.get(f'/api/agents/{entry_id}/nodes', headers=headers)
                self.assertEqual(nodes_resp.status_code, 200)
                self.assertNotIn('super-secret-isp-pw', nodes_resp.text)
                self.assertNotIn('resolved_outbound_hops', nodes_resp.text)

                # Verify self-chaining is rejected
                r_self = client.post(
                    f'/api/agents/{sg_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'Self Loop',
                            'server': '8.8.8.8',
                            'listen_port': 20099,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                            'outbound_mode': 'chain',
                            'outbound_hops': [{'kind': 'managed_ss', 'agent_id': sg_id, 'node_id': sg_node_id}],
                        },
                    },
                )
                self.assertEqual(r_self.status_code, 422)

                # Verify switching chain2 back to direct cleans outbound_hops
                r_upd = client.put(
                    f'/api/agents/{entry_id}/nodes/{chain2_id}',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'IX Direct 2',
                            'server': '1.2.3.4',
                            'listen_port': 20002,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                            'outbound_mode': 'direct',
                        },
                    },
                )
                self.assertEqual(r_upd.status_code, 200, r_upd.text)
                job_upd = self._complete_pending_job(store, entry_tok, entry_inst)
                updated_extra = next(n for n in job_upd['deployment']['extra_nodes'] if n['listen_port'] == 20002)
                self.assertNotIn('outbound_hops', updated_extra)
                self.assertNotIn('resolved_outbound_hops', updated_extra)

    def test_list_active_relays_prefers_public_ipv4_and_adoption_exposes_has_xray_xver(self):
        headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            app_mod = load_isolated_application(Path(tmp))
            store = app_mod.control_store()
            cn_id, cn_tok, cn_inst = self._register(store, 'CN-Entry', '1.2.3.4', observed_ip='10.0.0.2')

            with TestClient(app_mod.app) as client:
                res = client.post(
                    f'/api/agents/{cn_id}/forwards',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'name': 'cn-to-sg',
                        'listen_port': 10001,
                        'protocol': 'tcp+udp',
                        'mode': 'direct',
                        'targets': [{'addr': '8.8.8.8:443', 'name': 'sg'}],
                    },
                )
                self.assertEqual(res.status_code, 200, res.text)
                relays = store.list_active_relays()
                self.assertEqual(len(relays), 1)
                # Observed IP is private 10.0.0.2; reported public_ipv4 '1.2.3.4' must win!
                self.assertEqual(relays[0]['listen_host'], '1.2.3.4')

                # Test adoption xver boolean exposure without leaking private keys
                skey = 'adopt-' + '1' * 16
                scan_payload = {
                    'scanned_at': 1700000000,
                    'services': [{
                        'core': 'xray',
                        'pid': 397,
                        'service_name': 'nodepilot-n-1.service',
                        'config_path': '/etc/nodepilot/n1.json',
                        'config_sha256': 'a' * 64,
                    }],
                    'endpoints': [{
                        'source_key': skey,
                        'core': 'xray',
                        'service_name': 'nodepilot-n-1.service',
                        'config_path': '/etc/nodepilot/n1.json',
                        'config_sha256': 'a' * 64,
                        'tag': 'vless-in',
                        'protocol': 'vless',
                        'listen': '0.0.0.0',
                        'listen_port': 443,
                        'tls_mode': 'reality',
                        'sni': 'reality.example.com',
                        'network': 'tcp',
                        'ws_path': '',
                        'adoptable': True,
                    }],
                }
                store.record_adoption_scan(cn_tok, cn_inst, scan_payload)
                store.record_adoption_secrets(cn_tok, cn_inst, [{
                    'source_key': skey,
                    'core': 'xray',
                    'service_name': 'nodepilot-n-1.service',
                    'config_path': '/etc/nodepilot/n1.json',
                    'protocol': 'vless',
                    'listen_port': 443,
                    'credentials': {'uuid': 'u-1234', 'reality_private_key': 'secret-priv', 'reality_public_key': 'pub-1', 'xray_xver': 1},
                    'inbound': {'type': 'vless', 'tag': 'adopted', 'listen': '::', 'listen_port': 443},
                }])
                adoptions = client.get(f'/api/agents/{cn_id}/adoptions', headers=headers).json()['adoptions']
                self.assertEqual(len(adoptions), 1)
                self.assertTrue(adoptions[0]['has_credentials'])
                self.assertTrue(adoptions[0]['has_xray_xver'])
                self.assertNotIn('secret-priv', json.dumps(adoptions))

    def test_recursive_prefer_relay_multihop_branching_and_cycle_guard(self):
        proxies = [
            {'name': 'SG-01', 'type': 'vless', 'server': '8.8.8.8', 'port': 443},
            {'name': 'US-01', 'type': 'vless', 'server': '9.9.9.9', 'port': 443},
        ]
        # 3-hop chain: SG(8.8.8.8:443) <- HK(4.4.4.4:30001) <- IX(2.2.2.2:20001) <- CN(1.2.3.4:10001)
        relays_3hop = [
            {'id': 'r1', 'name': 'hk-sg', 'listen_host': '4.4.4.4', 'listen_port': 30001, 'targets': [{'addr': '8.8.8.8:443'}]},
            {'id': 'r2', 'name': 'ix-hk', 'listen_host': '2.2.2.2', 'listen_port': 20001, 'targets': [{'addr': '4.4.4.4:30001'}]},
            {'id': 'r3', 'name': 'cn-ix', 'listen_host': '1.2.3.4', 'listen_port': 10001, 'targets': [{'addr': '2.2.2.2:20001'}]},
        ]
        out, _ = apply_prefer_relay(proxies, relays_3hop, prefer_relay=True)
        sg = next(p for p in out if p['name'] == 'SG-01')
        us = next(p for p in out if p['name'] == 'US-01')
        self.assertEqual((sg['server'], sg['port']), ('1.2.3.4', 10001))
        self.assertEqual((us['server'], us['port']), ('9.9.9.9', 443))

        # Branching: SG targeted by IX-A (which has CN-GZ upstream) AND IX-B (terminal)
        relays_branch = [
            {'id': 'b1', 'name': 'ix-a', 'listen_host': '2.2.2.2', 'listen_port': 20001, 'targets': [{'addr': '8.8.8.8:443'}]},
            {'id': 'b2', 'name': 'cn-gz', 'listen_host': '1.2.3.4', 'listen_port': 10001, 'targets': [{'addr': '2.2.2.2:20001'}]},
            {'id': 'b3', 'name': 'ix-b', 'listen_host': '3.3.3.3', 'listen_port': 20002, 'targets': [{'addr': '8.8.8.8:443'}]},
        ]
        out_b, exp_b = apply_prefer_relay([proxies[0]], relays_branch, prefer_relay=True)
        endpoints_b = {(p['server'], p['port']) for p in out_b}
        self.assertEqual(endpoints_b, {('1.2.3.4', 10001), ('3.3.3.3', 20002)})
        self.assertEqual(len(exp_b['SG-01']), 2)

        # Cycle guard: A -> SG, B -> A, A -> B
        relays_cycle = [
            {'id': 'c1', 'name': 'a', 'listen_host': '1.1.1.1', 'listen_port': 1000, 'targets': [{'addr': '8.8.8.8:443'}, {'addr': '2.2.2.2:2000'}]},
            {'id': 'c2', 'name': 'b', 'listen_host': '2.2.2.2', 'listen_port': 2000, 'targets': [{'addr': '1.1.1.1:1000'}]},
        ]
        out_c, _ = apply_prefer_relay([proxies[0]], relays_cycle, prefer_relay=True)
        self.assertEqual(len(out_c), 1)
        self.assertEqual((out_c[0]['server'], out_c[0]['port']), ('2.2.2.2', 2000))


if __name__ == '__main__':
    unittest.main()
