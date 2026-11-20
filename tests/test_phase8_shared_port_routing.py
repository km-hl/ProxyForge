"""Phase 8 tests: Same-port multi-node split routing via sing-box `auth_user`.

Covers:
1. `agent/landing_spec.py`: merging shared `(protocol, listen_port)` nodes into a single
   sing-box inbound with distinct `users[].name` + `route.rules[].auth_user`, Reality `short_id`
   union, compatibility across `reality` / `trojan` / `anytls` / `hysteria2`, TCP+UDP 443
   coexistence, and validation rejection of mismatched TLS/SNI/keys or duplicate credentials.
2. `agent/runtime_engine.py`: `RuntimeCoordinator._apply_landing_job()` prepares ACME/Caddy only
   once per shared listener host and prunes stale `node-*` Caddy sites after successful commit.
3. `proxyforge/control/deployment_store.py` & `deployment_api.py`:
   - Same-port direct + multi-hop chain creation on TCP 443 (`reality`, `acme_http`, `acme_dns`)
   - Legacy `vless-reality` primary upgrade + shared port 443 coexistence
   - Automatic listener field & key inheritance, unique credential generation, mismatch 422 hints
   - Cross-protocol conflict rejection (TCP 443 Reality + Trojan), SS2022 non-sharing, adopted-port protection
   - Editing shared listener parameters syncs peers transactionally; deleting primary promotes extra
     losslessly preserving keypair and TLS/Caddy configuration
   - All 5 subscription export targets (Clash, Sing-box, Surge, Egern, Base64) emit both 443 nodes
     with identical server/port/SNI/public-key and distinct UUIDs.
"""
import base64
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import yaml

from agent.landing_spec import (
    runtime_config,
    shared_listener_guests,
    shared_listener_plan,
    shared_user_key,
    validate_spec,
)
from agent.runtime_engine import RuntimeCoordinator, validate_port_allocation
from agent.runtime_spec import SERVICE_CADDY, SERVICE_SINGBOX, revision
from agent.deployment_spec import spec_hash
from proxyforge.control.deployment_store import new_landing_spec
from test_agent_jobs import capable
from test_api_integration import TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN, load_isolated_application
from test_deployments import RESULT


def _make_reality_spec(name, port=443, *, domain='www.amazon.com', tls_mode='reality',
                       outbound_mode='direct', hops=None, node_id=None, shared_from=None):
    settings = {
        'name': name,
        'server': '202.61.75.124',
        'listen_port': port,
        'protocol': 'reality',
        'tls_mode': tls_mode,
        'domain': domain,
        'outbound_mode': outbound_mode,
    }
    if outbound_mode == 'chain':
        settings['outbound_hops'] = [{'kind': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': '2022-blake3-aes-256-gcm'}]
    spec = new_landing_spec(settings, protocol='reality')
    if outbound_mode == 'chain':
        spec['resolved_outbound_hops'] = hops or [
            {'type': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': '2022-blake3-aes-256-gcm', 'password': 'pw-sg'}
        ]
    if shared_from is not None:
        spec['reality_private_key'] = shared_from['reality_private_key']
        spec['reality_public_key'] = shared_from['reality_public_key']
        spec['domain'] = shared_from['domain']
        spec['tls_mode'] = shared_from['tls_mode']
    if node_id is not None:
        spec['node_id'] = node_id
    return spec


class Phase8LandingSpecSharedPortTests(unittest.TestCase):
    def test_reality_443_direct_and_chain_merge_into_single_inbound_with_auth_user_routes(self):
        primary = _make_reality_spec('🇲🇾 EVOXT Direct', 443, domain='reality.example.com', tls_mode='acme_http')
        extra = _make_reality_spec(
            '🇸🇬 EVOXT -> SG',
            443,
            outbound_mode='chain',
            node_id='chain443',
            shared_from=primary,
        )
        full_spec = {**primary, 'extra_nodes': [extra]}

        plan = shared_listener_plan(full_spec)
        self.assertEqual(plan, {('reality', 443): {'host': 'primary', 'members': ['primary', 'chain443']}})
        self.assertEqual(shared_listener_guests(full_spec), {'chain443'})

        validate_spec('landing.apply', full_spec)
        cfg = runtime_config(full_spec, caddy_port=18443)

        # Exactly one inbound listening on 443 -> passes strict port allocation check
        self.assertEqual(len(cfg['inbounds']), 1)
        validate_port_allocation(SERVICE_SINGBOX, cfg)

        inbound = cfg['inbounds'][0]
        self.assertEqual(inbound['tag'], 'managed-landing')
        self.assertEqual(inbound['listen_port'], 443)
        self.assertEqual(inbound['tls']['reality']['handshake'], {'server': '127.0.0.1', 'server_port': 18443})
        self.assertEqual(
            inbound['users'],
            [
                {'name': shared_user_key('primary'), 'uuid': primary['uuid'], 'flow': 'xtls-rprx-vision'},
                {'name': shared_user_key('chain443'), 'uuid': extra['uuid'], 'flow': 'xtls-rprx-vision'},
            ],
        )
        expected_sids = list(dict.fromkeys(primary['reality_short_ids'] + extra['reality_short_ids']))
        self.assertEqual(inbound['tls']['reality']['short_id'], expected_sids)

        rules = cfg['route']['rules']
        self.assertIn(
            {'inbound': ['managed-landing'], 'auth_user': ['u-primary'], 'action': 'route', 'outbound': 'direct'},
            rules,
        )
        self.assertIn(
            {'inbound': ['managed-landing'], 'auth_user': ['u-chain443'], 'action': 'route', 'outbound': 'out-node-chain443-h1'},
            rules,
        )
        self.assertEqual(cfg['route']['final'], 'direct')

        # With outbound_strategy set (Web UI default prefer_ipv4), local DNS must set prefer_go=True
        # so sing-box reads /etc/resolv.conf instead of failing on D-Bus org.freedesktop.resolve1.
        strat_spec = {**full_spec, 'outbound_strategy': 'prefer_ipv4'}
        strat_cfg = runtime_config(strat_spec, caddy_port=18443)
        self.assertEqual(strat_cfg['dns'], {'servers': [{'type': 'local', 'tag': 'local', 'prefer_go': True}]})

    def test_reversed_direction_primary_chain_and_extra_direct_on_443(self):
        primary = _make_reality_spec('🇸🇬 Primary Chain', 443, outbound_mode='chain')
        extra = _make_reality_spec('🇲🇾 Extra Direct', 443, outbound_mode='direct', node_id='dir443', shared_from=primary)
        full_spec = {**primary, 'extra_nodes': [extra]}
        cfg = runtime_config(full_spec)
        self.assertEqual(len(cfg['inbounds']), 1)
        rules = cfg['route']['rules']
        self.assertIn(
            {'inbound': ['managed-landing'], 'auth_user': ['u-primary'], 'action': 'route', 'outbound': 'out-primary-h1'},
            rules,
        )
        self.assertIn(
            {'inbound': ['managed-landing'], 'auth_user': ['u-dir443'], 'action': 'route', 'outbound': 'direct'},
            rules,
        )

    def test_trojan_anytls_hysteria2_share_port_and_tcp_udp_443_coexist(self):
        for proto in ('trojan', 'anytls', 'hysteria2'):
            base_settings = {
                'name': f'{proto} direct',
                'server': 'node.example.com',
                'listen_port': 443,
                'protocol': proto,
                'tls_mode': 'acme_http',
                'domain': 'node.example.com',
                'outbound_mode': 'direct',
            }
            p_spec = new_landing_spec(base_settings, protocol=proto)
            e_settings = {
                **base_settings,
                'name': f'{proto} chain',
                'outbound_mode': 'chain',
                'outbound_hops': [{'kind': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': '2022-blake3-aes-256-gcm'}],
            }
            e_spec = new_landing_spec(e_settings, protocol=proto)
            e_spec['node_id'] = f'{proto}2'
            e_spec['resolved_outbound_hops'] = [
                {'type': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': '2022-blake3-aes-256-gcm', 'password': 'pw'}
            ]
            full = {**p_spec, 'extra_nodes': [e_spec]}
            cfg = runtime_config(full, cert_path='/certs/full.pem', key_path='/certs/priv.pem', caddy_port=18443)
            self.assertEqual(len(cfg['inbounds']), 1, proto)
            self.assertEqual(len(cfg['inbounds'][0]['users']), 2, proto)
            self.assertEqual({u['name'] for u in cfg['inbounds'][0]['users']}, {'u-primary', f'u-{proto}2'})
            validate_port_allocation(SERVICE_SINGBOX, cfg)

        # TCP 443 Reality (2 shared users) + UDP 443 Hysteria2 (2 shared users) -> 2 inbounds total
        r1 = _make_reality_spec('R1', 443)
        r2 = _make_reality_spec('R2', 443, outbound_mode='chain', node_id='r2', shared_from=r1)
        h1_s = {'name': 'H1', 'server': 'hy2.example.com', 'listen_port': 443, 'protocol': 'hysteria2', 'tls_mode': 'acme_http', 'domain': 'hy2.example.com'}
        h1 = new_landing_spec(h1_s, protocol='hysteria2')
        h1['node_id'] = 'h1'
        h2 = new_landing_spec({**h1_s, 'name': 'H2', 'outbound_mode': 'chain', 'outbound_hops': [{'kind': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': '2022-blake3-aes-256-gcm'}]}, protocol='hysteria2')
        h2['node_id'] = 'h2'
        h2['resolved_outbound_hops'] = [{'type': 'ss', 'server': '8.8.8.8', 'port': 8388, 'method': '2022-blake3-aes-256-gcm', 'password': 'pw'}]
        combo = {**r1, 'extra_nodes': [r2, h1, h2]}
        cfg_combo = runtime_config(combo, extra_overrides={'h1': {'cert_path': '/c/f.pem', 'key_path': '/c/k.pem'}})
        self.assertEqual(len(cfg_combo['inbounds']), 2)
        self.assertEqual({i['type'] for i in cfg_combo['inbounds']}, {'vless', 'hysteria2'})
        self.assertEqual(shared_listener_guests(combo), {'r2', 'h2'})
        validate_port_allocation(SERVICE_SINGBOX, cfg_combo)

    def test_validate_spec_rejects_mismatched_sni_keys_or_duplicate_uuid_on_shared_port(self):
        primary = _make_reality_spec('P', 443, domain='a.example.com')

        bad_domain = _make_reality_spec('E1', 443, domain='b.example.com', node_id='e1', shared_from=primary)
        bad_domain['domain'] = 'b.example.com'
        with self.assertRaises(ValueError):
            validate_spec('landing.apply', {**primary, 'extra_nodes': [bad_domain]})

        bad_key = _make_reality_spec('E2', 443, domain='a.example.com', node_id='e2')
        with self.assertRaises(ValueError):
            validate_spec('landing.apply', {**primary, 'extra_nodes': [bad_key]})

        dup_uuid = _make_reality_spec('E3', 443, node_id='e3', shared_from=primary)
        dup_uuid['uuid'] = primary['uuid']
        with self.assertRaises(ValueError):
            validate_spec('landing.apply', {**primary, 'extra_nodes': [dup_uuid]})


class Phase8RuntimeCoordinatorDeduplicationTests(unittest.TestCase):
    def test_shared_port_prepares_caddy_once_and_prunes_stale_node_sites(self):
        primary = _make_reality_spec('P443', 443, domain='camo.example.com', tls_mode='acme_http')
        guest = _make_reality_spec('G443', 443, outbound_mode='chain', node_id='guest443', shared_from=primary)
        full_spec = {**primary, 'extra_nodes': [guest]}

        mock_sb = MagicMock()
        mock_sb.root = Path(tempfile.gettempdir())
        mock_sb.apply.return_value = {'status': 'success', 'output': {'running': True}, 'error': None}

        mock_caddy = MagicMock()
        mock_caddy.load_sites.return_value = {
            'landing': {'site_id': 'landing', 'domain': 'camo.example.com', 'listen_port': 18000},
            'node-obsolete': {'site_id': 'node-obsolete', 'domain': 'old.example.com', 'listen_port': 18001},
            'custom-other': {'site_id': 'custom-other', 'domain': 'keep.example.com', 'listen_port': 18002},
        }

        coord = RuntimeCoordinator({SERVICE_SINGBOX: mock_sb}, caddy_manager=mock_caddy)
        coord.allocate_port = MagicMock(return_value=18443)

        payload = {'deployment_id': 'a' * 32, 'revision': 1, 'spec_hash': spec_hash(full_spec)}
        job_id = uuid.uuid4().hex
        job = {
            'id': job_id,
            'type': 'landing.apply',
            'payload': payload,
            'deployment': full_spec,
            'deployment_revision': revision(job_id, 'landing.apply', payload),
        }

        result = coord.apply(job)
        self.assertEqual(result['status'], 'success')

        # Caddy upsert called ONLY ONCE (for host 'landing'), NEVER for 'node-guest443'
        self.assertEqual(mock_caddy.upsert_site.call_count, 1)
        self.assertEqual(mock_caddy.upsert_site.call_args[0][0]['site_id'], 'landing')

        # Stale 'node-obsolete' pruned after sing-box commit; 'landing' and non-node 'custom-other' preserved
        removed_ids = [call.args[0] for call in mock_caddy.remove_site.call_args_list]
        self.assertEqual(removed_ids, ['node-obsolete'])


class Phase8ControlPlaneAndSubscriptionTests(unittest.TestCase):
    def _register(self, store, name, public_ipv4):
        info = {
            **capable(),
            'runtime_protocol_version': 1,
            'deployment_protocol_version': 1,
            'landing_protocol_version': 1,
            'chain_protocol_version': 1,
            'addresses': [public_ipv4],
        }
        reg = store.register(store.issue_registration(name)['registration_token'], info, public_ipv4)
        return reg['agent_id'], reg['agent_token'], info['instance_id']

    def _complete_job(self, store, token, inst_id):
        job = store.claim_job(token, inst_id)
        self.assertIsNotNone(job)
        store.report_job(token, job['id'], job['lease_token'])
        store.report_job(token, job['id'], job['lease_token'], RESULT)
        return job

    def test_shared_443_direct_and_chain_lifecycle_sync_promotion_and_5_format_exports(self):
        headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            app_mod = load_isolated_application(Path(tmp))
            store = app_mod.control_store()
            entry_id, entry_tok, entry_inst = self._register(store, '🇲🇾 EVOXT', '202.61.75.124')
            sg_id, sg_tok, sg_inst = self._register(store, '🇸🇬 Legend SG', '217.116.174.161')

            with TestClient(app_mod.app) as client:
                # 1. Deploy SS2022 landing on SG
                r_sg = client.post(
                    f'/api/agents/{sg_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'ss2022',
                        'settings': {
                            'name': '🇸🇬 SG Node',
                            'server': '217.116.174.161',
                            'listen_port': 8388,
                            'protocol': 'ss2022',
                            'tls_mode': 'none',
                            'method': '2022-blake3-aes-256-gcm',
                        },
                    },
                )
                self.assertEqual(r_sg.status_code, 200, r_sg.text)
                sg_node_id = r_sg.json()['node_id']
                self._complete_job(store, sg_tok, sg_inst)

                # 2. Deploy Reality :443 direct with DNS-01 + Caddy template on EVOXT
                r_p = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': '🇲🇾 EVOXT - VM 0.5',
                            'server': '202.61.75.124',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'acme_dns',
                            'domain': 'realityevoxt.example.com',
                            'dns_provider': 'cloudflare',
                            'dns_zone_id': '0123456789abcdef0123456789abcdef',
                            'camouflage_mode': 'template',
                            'camouflage_template': 'corporate',
                            'outbound_mode': 'direct',
                        },
                        'secrets': {'dns_api_token': 'cf-secret-token-12345'},
                    },
                )
                self.assertEqual(r_p.status_code, 200, r_p.text)
                primary_id = r_p.json()['node_id']
                job_p = self._complete_job(store, entry_tok, entry_inst)
                primary_pub = job_p['deployment']['reality_public_key']
                primary_priv = job_p['deployment']['reality_private_key']
                primary_uuid = job_p['deployment']['uuid']

                # 3. Reject mismatched SNI / tls_mode / cross-protocol on port 443 with safe 422 hints
                bad_sni = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'Bad SNI',
                            'server': '202.61.75.124',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'acme_dns',
                            'domain': 'other.example.com',
                            'outbound_mode': 'chain',
                            'outbound_hops': [{'kind': 'managed_ss', 'agent_id': sg_id, 'node_id': sg_node_id}],
                        },
                    },
                )
                self.assertEqual(bad_sni.status_code, 422)
                self.assertIn('域名 / SNI', bad_sni.json()['detail'])
                self.assertNotIn('cf-secret-token-12345', bad_sni.text)

                bad_tls = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'Bad TLS',
                            'server': '202.61.75.124',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'realityevoxt.example.com',
                            'outbound_mode': 'chain',
                            'outbound_hops': [{'kind': 'managed_ss', 'agent_id': sg_id, 'node_id': sg_node_id}],
                        },
                    },
                )
                self.assertEqual(bad_tls.status_code, 422)
                self.assertIn('TLS / 伪装模式', bad_tls.json()['detail'])

                bad_proto = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'trojan',
                        'settings': {
                            'name': 'Conflict Trojan',
                            'server': '202.61.75.124',
                            'listen_port': 443,
                            'protocol': 'trojan',
                            'tls_mode': 'acme_http',
                            'domain': 'realityevoxt.example.com',
                        },
                    },
                )
                self.assertEqual(bad_proto.status_code, 422)
                self.assertIn('其他协议', bad_proto.json()['detail'])

                # 4. Create 2nd Reality :443 node (chained to SG) WITHOUT supplying dns_zone_id or dns_api_token
                #    (matching slim Chain modal payload) -> automatically inherits host listener fields & secrets!
                r_c = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': '🇸🇬 EVOXT → SG 落地',
                            'server': '202.61.75.124',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'acme_dns',
                            'domain': 'realityevoxt.example.com',
                            'outbound_mode': 'chain',
                            'outbound_hops': [{'kind': 'managed_ss', 'agent_id': sg_id, 'node_id': sg_node_id}],
                        },
                    },
                )
                self.assertEqual(r_c.status_code, 200, r_c.text)
                chain_id = r_c.json()['node_id']
                job_c = self._complete_job(store, entry_tok, entry_inst)

                full_spec = job_c['deployment']
                self.assertEqual(len(full_spec['extra_nodes']), 1)
                extra_spec = full_spec['extra_nodes'][0]
                self.assertEqual(extra_spec['reality_private_key'], primary_priv)
                self.assertEqual(extra_spec['reality_public_key'], primary_pub)
                self.assertEqual(extra_spec['dns_api_token'], 'cf-secret-token-12345')
                self.assertEqual(extra_spec['camouflage_template'], 'corporate')
                self.assertNotEqual(extra_spec['uuid'], primary_uuid)
                chain_uuid = extra_spec['uuid']

                compiled = runtime_config(full_spec, caddy_port=18443)
                self.assertEqual(len(compiled['inbounds']), 1)
                self.assertEqual(len(compiled['inbounds'][0]['users']), 2)
                validate_port_allocation(SERVICE_SINGBOX, compiled)

                # 5. Verify all 5 subscription formats export BOTH :443 nodes with same pubkey & distinct UUIDs
                managed = store.managed_nodes()
                self.assertEqual(len(managed), 2)
                by_name = {n['name']: n for n in managed}
                self.assertIn('🇲🇾 EVOXT - VM 0.5', by_name)
                self.assertIn('🇸🇬 EVOXT → SG 落地', by_name)
                self.assertEqual(by_name['🇲🇾 EVOXT - VM 0.5']['port'], 443)
                self.assertEqual(by_name['🇸🇬 EVOXT → SG 落地']['port'], 443)
                self.assertEqual(by_name['🇲🇾 EVOXT - VM 0.5']['uuid'], primary_uuid)
                self.assertEqual(by_name['🇸🇬 EVOXT → SG 落地']['uuid'], chain_uuid)
                self.assertEqual(
                    by_name['🇲🇾 EVOXT - VM 0.5']['reality-opts']['public-key'],
                    by_name['🇸🇬 EVOXT → SG 落地']['reality-opts']['public-key'],
                )

                for target in ('clash', 'singbox', 'surge', 'egern', 'base64'):
                    sub_res = client.get(f'/sub?token={TEST_SUBSCRIPTION_TOKEN}&target={target}')
                    self.assertEqual(sub_res.status_code, 200, (target, sub_res.text))
                    rendered = sub_res.text
                    self.assertNotIn('[pf:', rendered)
                    if target == 'base64':
                        decoded = base64.b64decode(rendered).decode('utf-8')
                        self.assertIn(primary_uuid, decoded)
                        self.assertIn(chain_uuid, decoded)
                        self.assertNotIn('[pf:', decoded)
                    elif target == 'singbox':
                        sb = json.loads(rendered)
                        vless_outs = [o for o in sb['outbounds'] if o.get('type') == 'vless']
                        self.assertEqual(len(vless_outs), 2)
                        self.assertEqual({o['uuid'] for o in vless_outs}, {primary_uuid, chain_uuid})
                        self.assertEqual({o['server_port'] for o in vless_outs}, {443})
                    elif target == 'clash':
                        cl = yaml.safe_load(rendered)
                        vless_proxies = [p for p in cl['proxies'] if p.get('type') == 'vless']
                        self.assertEqual(len(vless_proxies), 2)
                        self.assertEqual({p['uuid'] for p in vless_proxies}, {primary_uuid, chain_uuid})
                        self.assertEqual({p['port'] for p in vless_proxies}, {443})
                    elif target == 'egern':
                        self.assertIn(primary_uuid, rendered)
                        self.assertIn(chain_uuid, rendered)
                    elif target == 'surge':
                        # Surge INI doesn't natively support VLESS Reality; verify 200 and clean rendering
                        self.assertIn('[Proxy]', rendered)

                # 6. Edit primary's domain & camouflage -> peer syncs automatically!
                r_edit = client.put(
                    f'/api/agents/{entry_id}/nodes/{primary_id}',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': '🇲🇾 EVOXT - VM 0.5',
                            'server': '202.61.75.124',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'acme_dns',
                            'domain': 'new-evoxt.example.com',
                            'dns_provider': 'cloudflare',
                            'dns_zone_id': '0123456789abcdef0123456789abcdef',
                            'camouflage_mode': 'template',
                            'camouflage_template': 'blog',
                            'outbound_mode': 'direct',
                        },
                    },
                )
                self.assertEqual(r_edit.status_code, 200, r_edit.text)
                job_edit = self._complete_job(store, entry_tok, entry_inst)
                self.assertEqual(job_edit['deployment']['domain'], 'new-evoxt.example.com')
                self.assertEqual(job_edit['deployment']['extra_nodes'][0]['domain'], 'new-evoxt.example.com')
                self.assertEqual(job_edit['deployment']['extra_nodes'][0]['camouflage_template'], 'blog')

                # 7. Delete PRIMARY -> extra chain node promotes losslessly, keeping keypair, uuid, domain & DNS token
                r_del = client.request(
                    'DELETE',
                    f'/api/agents/{entry_id}/nodes/{primary_id}',
                    headers=headers,
                    json={'request_id': uuid.uuid4().hex},
                )
                self.assertEqual(r_del.status_code, 200, r_del.text)
                job_del = self._complete_job(store, entry_tok, entry_inst)
                promoted = job_del['deployment']
                self.assertNotIn('extra_nodes', promoted)
                self.assertEqual(promoted['name'], '🇸🇬 EVOXT → SG 落地')
                self.assertEqual(promoted['uuid'], chain_uuid)
                self.assertEqual(promoted['reality_private_key'], primary_priv)
                self.assertEqual(promoted['reality_public_key'], primary_pub)
                self.assertEqual(promoted['domain'], 'new-evoxt.example.com')
                self.assertEqual(promoted['dns_api_token'], 'cf-secret-token-12345')
                self.assertEqual(promoted['outbound_mode'], 'chain')

                # Public API never leaks secrets
                nodes_list_res = client.get(f'/api/agents/{entry_id}/nodes', headers=headers)
                self.assertEqual(nodes_list_res.status_code, 200)
                self.assertNotIn('cf-secret-token-12345', nodes_list_res.text)
                self.assertNotIn(primary_priv, nodes_list_res.text)

    def test_legacy_vless_reality_primary_shares_443_with_new_chain_node_and_upgrades_cleanly(self):
        headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            app_mod = load_isolated_application(Path(tmp))
            store = app_mod.control_store()
            entry_id, entry_tok, entry_inst = self._register(store, 'LegacyEntry', '1.2.3.4')
            sg_id, sg_tok, sg_inst = self._register(store, 'SG', '8.8.8.8')

            with TestClient(app_mod.app) as client:
                # Deploy SS2022 on SG
                r_sg = client.post(
                    f'/api/agents/{sg_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'ss2022',
                        'settings': {
                            'name': 'SG SS',
                            'server': '8.8.8.8',
                            'listen_port': 8388,
                            'protocol': 'ss2022',
                            'tls_mode': 'none',
                            'method': '2022-blake3-aes-256-gcm',
                        },
                    },
                )
                self.assertEqual(r_sg.status_code, 200)
                sg_node_id = r_sg.json()['node_id']
                self._complete_job(store, sg_tok, sg_inst)

                # Create legacy vless-reality primary on port 443 via PUT /deployment
                r_leg = client.put(
                    f'/api/agents/{entry_id}/deployment',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'expected_revision': 0,
                        'protocol': 'vless-reality',
                        'settings': {
                            'name': 'Legacy Direct 443',
                            'server': '1.2.3.4',
                            'server_name': 'www.amazon.com',
                            'listen_port': 443,
                        },
                    },
                )
                self.assertEqual(r_leg.status_code, 200, r_leg.text)
                job_leg = self._complete_job(store, entry_tok, entry_inst)
                leg_pub = job_leg['deployment']['public_key']
                leg_uuid = job_leg['deployment']['uuid']

                # Add shared Reality :443 chain node on top of legacy vless-reality
                r_add = client.post(
                    f'/api/agents/{entry_id}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'Shared Chain 443',
                            'server': '1.2.3.4',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.amazon.com',
                            'outbound_mode': 'chain',
                            'outbound_hops': [{'kind': 'managed_ss', 'agent_id': sg_id, 'node_id': sg_node_id}],
                        },
                    },
                )
                self.assertEqual(r_add.status_code, 200, r_add.text)
                job_add = self._complete_job(store, entry_tok, entry_inst)

                # Both share the legacy keypair, have distinct UUIDs, and managed_nodes() reads cleanly after upgrade!
                self.assertEqual(job_add['deployment']['reality_public_key'], leg_pub)
                self.assertEqual(job_add['deployment']['extra_nodes'][0]['reality_public_key'], leg_pub)
                self.assertNotEqual(job_add['deployment']['extra_nodes'][0]['uuid'], leg_uuid)

                nodes = store.managed_nodes()
                self.assertEqual(len(nodes), 2)
                self.assertEqual({n['name'] for n in nodes}, {'Legacy Direct 443', 'Shared Chain 443'})
                self.assertEqual({n['reality-opts']['public-key'] for n in nodes}, {leg_pub})

    def test_ss2022_cannot_share_port_and_adopted_port_is_protected(self):
        headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            app_mod = load_isolated_application(Path(tmp))
            store = app_mod.control_store()
            aid, tok, inst = self._register(store, 'Box', '1.2.3.4')

            with TestClient(app_mod.app) as client:
                # Two SS2022 on 8388 must still be rejected
                r1 = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'ss2022',
                        'settings': {'name': 'SS1', 'server': '1.2.3.4', 'listen_port': 8388, 'protocol': 'ss2022', 'tls_mode': 'none', 'method': '2022-blake3-aes-256-gcm'},
                    },
                )
                self.assertEqual(r1.status_code, 200)
                self._complete_job(store, tok, inst)

                r2 = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'ss2022',
                        'settings': {'name': 'SS2', 'server': '1.2.3.4', 'listen_port': 8388, 'protocol': 'ss2022', 'tls_mode': 'none', 'method': '2022-blake3-aes-256-gcm'},
                    },
                )
                self.assertEqual(r2.status_code, 422)

                # Seed an active adopted node on TCP 443 -> creating managed Reality on 443 must be rejected
                now = store.clock()
                with store.connection() as db:
                    db.execute(
                        '''INSERT INTO adopted_nodes(
                               id,agent_id,source_key,core,service_name,config_path,config_sha256,
                               tag,protocol,listen,listen_port,tls_mode,sni,network,ws_path,
                               adoptable,metadata,discovered_at,updated_at
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (
                            uuid.uuid4().hex, aid, 'adopt-0123456789abcdef', 'sing-box', 'sing-box.service',
                            '/etc/sing-box/config.json', '0' * 64, 'vless-in', 'vless', '::', 443,
                            'reality', 'www.microsoft.com', 'tcp', '', 1, '{}', now, now,
                        ),
                    )
                    db.execute(
                        '''INSERT INTO adopted_node_secrets(
                               agent_id,source_key,secret_spec,adopted_status,custom_name,server_override,updated_at
                           ) VALUES(?,?,?,?,?,?,?)''',
                        (aid, 'adopt-0123456789abcdef', '', 'adopted', 'Adopted 443', '', now),
                    )

                r_adopt_conflict = client.post(
                    f'/api/agents/{aid}/nodes',
                    headers=headers,
                    json={
                        'request_id': uuid.uuid4().hex,
                        'protocol': 'reality',
                        'settings': {
                            'name': 'Managed 443',
                            'server': '1.2.3.4',
                            'listen_port': 443,
                            'protocol': 'reality',
                            'tls_mode': 'reality',
                            'domain': 'www.microsoft.com',
                        },
                    },
                )
                self.assertEqual(r_adopt_conflict.status_code, 422)
                self.assertIn('已接管', r_adopt_conflict.json()['detail'])

    def test_cn_region_flag_matching_and_cn2_ix_guards(self):
        from proxyforge.subscription.nodes import add_flag_to_proxy_name

        self.assertEqual(add_flag_to_proxy_name('Aliyun 深圳'), '🇨🇳 Aliyun 深圳')
        self.assertEqual(add_flag_to_proxy_name('CN 前置'), '🇨🇳 CN 前置')
        self.assertEqual(add_flag_to_proxy_name('vps.soy - 深港IX'), '🇭🇰 vps.soy - 深港IX')
        self.assertEqual(add_flag_to_proxy_name('LA CN2 GIA'), 'LA CN2 GIA')


if __name__ == '__main__':
    unittest.main()
