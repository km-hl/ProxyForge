"""Unit tests for agent/nft_users.py, landing_spec sub_users/routing_mark, and mixed-epoch traffic spooling."""
import base64
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid

from agent.landing_spec import (
    collect_spec_user_marks,
    runtime_config,
    sub_user_auth_key,
    validate_spec,
)
from agent.nft_users import (
    USER_MARK_BASE,
    NftUserCounters,
    mark_from_value,
    parse_user_counters,
    render_user_nft_script,
    user_mark,
)
from agent.traffic_collector import ReliableTrafficSpool, flush_gost_traffic


REALITY_PRIV = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
REALITY_PUB = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip('=')


def _reality_node(**overrides):
    base = {
        'protocol': 'reality',
        'name': 'HK-Reality',
        'server': '203.0.113.10',
        'listen_port': 443,
        'tls_mode': 'reality',
        'domain': 'www.amazon.com',
        'uuid': '11111111-2222-4333-8444-555555555555',
        'reality_private_key': REALITY_PRIV,
        'reality_public_key': REALITY_PUB,
        'reality_short_ids': ['0123456789abcdef'],
    }
    base.update(overrides)
    return base


class NftUsersModuleTest(unittest.TestCase):
    def test_user_mark_roundtrip_and_bounds(self):
        self.assertEqual(user_mark(1), USER_MARK_BASE | 1)
        self.assertEqual(user_mark(65535), USER_MARK_BASE | 0xFFFF)
        self.assertEqual(user_mark(0), 0)
        self.assertEqual(user_mark(65536), 0)
        self.assertEqual(user_mark(True), 0)
        self.assertEqual(mark_from_value(USER_MARK_BASE | 42), 42)
        self.assertEqual(mark_from_value(0x12340042), 0)

    def test_render_and_parse_nft_counters(self):
        script = render_user_nft_script([5, 2, 5])
        self.assertIn('table inet proxyforge_users {}', script)
        self.assertIn('delete table inet proxyforge_users', script)
        self.assertIn('counter uup_2 {}', script)
        self.assertIn('counter udown_5 {}', script)
        self.assertIn(f'meta mark 0x{user_mark(2):08x} ct mark set meta mark counter name uup_2', script)
        self.assertIn(f'ct mark 0x{user_mark(5):08x} counter name udown_5', script)

        empty_script = render_user_nft_script([])
        self.assertNotIn('counter uup_', empty_script)
        self.assertIn('delete table inet proxyforge_users', empty_script)

        sample_output = """table inet proxyforge_users {
        counter uup_2 {
                packets 12 bytes 4096
        }
        counter udown_2 {
                packets 34 bytes 102400
        }
        counter uup_5 {
                packets 1 bytes 512
        }
}
table inet other_table {
        counter uup_2 {
                packets 99 bytes 999999
        }
}
"""
        parsed = parse_user_counters(sample_output)
        self.assertEqual(parsed['subuser:2']['tx_bytes'], 4096)
        self.assertEqual(parsed['subuser:2']['rx_bytes'], 102400)
        self.assertEqual(parsed['subuser:5']['tx_bytes'], 512)
        self.assertEqual(parsed['subuser:5']['rx_bytes'], 0)

    def test_nft_user_counters_sync_idempotency_and_degradation(self):
        with tempfile.TemporaryDirectory() as td:
            calls = []
            table_present = [False]

            def fake_runner(args, stdin_text=None):
                calls.append((tuple(args), stdin_text))
                if args == ['list', 'tables']:
                    out = 'table inet proxyforge_users\n' if table_present[0] else ''
                    return SimpleNamespace(returncode=0, stdout=out, stderr='')
                if args == ['-f', '-']:
                    table_present[0] = 'counter uup_' in (stdin_text or '')
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                if args[:2] == ['list', 'counters']:
                    return SimpleNamespace(
                        returncode=0,
                        stdout='table inet proxyforge_users {\n\tcounter uup_7 {\n\t\tpackets 5 bytes 1200\n\t}\n\tcounter udown_7 {\n\t\tpackets 8 bytes 3400\n\t}\n}\n',
                        stderr='',
                    )
                return SimpleNamespace(returncode=1, stdout='', stderr='unexpected')

            mgr = NftUserCounters(Path(td), runner=fake_runner)
            r1 = mgr.sync([7])
            self.assertTrue(r1['ok'])
            self.assertTrue(r1['changed'])
            self.assertEqual((Path(td) / 'nft-capable').read_text(encoding='utf-8').strip(), '1')

            # Identical set must not reload nftables or rotate epoch.
            r2 = mgr.sync([7])
            self.assertTrue(r2['ok'])
            self.assertFalse(r2['changed'])
            self.assertEqual(r2['epoch'], r1['epoch'])

            # Reading attaches persistent epoch.
            snap = mgr.read()
            self.assertEqual(snap['epoch'], r1['epoch'])
            self.assertEqual(snap['totals']['subuser:7']['tx_bytes'], 1200)
            self.assertEqual(snap['totals']['subuser:7']['rx_bytes'], 3400)
            self.assertEqual(snap['totals']['subuser:7']['epoch'], r1['epoch'])

            # Unprivileged failure records nft-capable=0 gracefully.
            unpriv = NftUserCounters(
                Path(td),
                runner=lambda args, stdin_text=None: SimpleNamespace(returncode=1, stdout='', stderr='Operation not permitted'),
            )
            r3 = unpriv.sync([7])
            self.assertFalse(r3['ok'])
            self.assertFalse(r3['capable'])
            self.assertEqual((Path(td) / 'nft-capable').read_text(encoding='utf-8').strip(), '0')


class LandingSpecSubUsersTest(unittest.TestCase):
    def test_direct_and_chained_routing_mark_and_shared_port_users(self):
        u1_primary = str(uuid.uuid4())
        u1_extra = str(uuid.uuid4())
        spec = _reality_node(
            sub_users=[{'mark_id': 3, 'uuid': u1_primary}],
            extra_nodes=[
                _reality_node(
                    node_id='chain1',
                    name='HK-Chain',
                    uuid='22222222-3333-4444-8555-666666666666',
                    outbound_mode='chain',
                    outbound_hops=[
                        {'kind': 'ss', 'server': '198.51.100.1', 'port': 8388, 'method': '2022-blake3-aes-256-gcm'},
                        {'kind': 'socks5', 'server': '198.51.100.2', 'port': 1080},
                    ],
                    resolved_outbound_hops=[
                        {'type': 'ss', 'server': '198.51.100.1', 'port': 8388, 'method': '2022-blake3-aes-256-gcm', 'password': 'A' * 32},
                        {'type': 'socks5', 'server': '198.51.100.2', 'port': 1080},
                    ],
                    sub_users=[{'mark_id': 3, 'uuid': u1_extra}],
                )
            ],
        )
        validate_spec('landing.apply', spec)
        self.assertEqual(collect_spec_user_marks(spec), [3])

        cfg = runtime_config(spec)
        # Single shared VLESS inbound containing both admin + both sub-user UUIDs.
        self.assertEqual(len(cfg['inbounds']), 1)
        users = cfg['inbounds'][0]['users']
        user_by_name = {u['name']: u for u in users}
        self.assertEqual(user_by_name[sub_user_auth_key(3, 'primary')]['uuid'], u1_primary)
        self.assertEqual(user_by_name[sub_user_auth_key(3, 'chain1')]['uuid'], u1_extra)
        self.assertEqual(user_by_name[sub_user_auth_key(3, 'primary')]['flow'], 'xtls-rprx-vision')

        out_by_tag = {o['tag']: o for o in cfg['outbounds']}
        # Direct sub-user outbound carries routing_mark.
        self.assertEqual(out_by_tag['pf-u-3']['routing_mark'], user_mark(3))
        # Chain sub-user hop 1 carries routing_mark, hop 2 detours via hop 1 without mark.
        self.assertEqual(out_by_tag['out-node-chain1-u3-h1']['routing_mark'], user_mark(3))
        self.assertNotIn('routing_mark', out_by_tag['out-node-chain1-u3-h2'])
        self.assertEqual(out_by_tag['out-node-chain1-u3-h2']['detour'], 'out-node-chain1-u3-h1')

        # Route rules match per-user auth_user to their marked outbounds.
        route_map = {tuple(r.get('auth_user') or ()): r['outbound'] for r in cfg['route']['rules']}
        self.assertEqual(route_map[(sub_user_auth_key(3, 'primary'),)], 'pf-u-3')
        self.assertEqual(route_map[(sub_user_auth_key(3, 'chain1'),)], 'out-node-chain1-u3-h2')

    def test_no_user_marks_degradation_keeps_credentials_without_marks(self):
        u1 = str(uuid.uuid4())
        spec = _reality_node(
            no_user_marks=True,
            sub_users=[{'mark_id': 9, 'uuid': u1}],
        )
        validate_spec('landing.apply', spec)
        self.assertEqual(collect_spec_user_marks(spec), [])
        cfg = runtime_config(spec)
        uuids = [u['uuid'] for u in cfg['inbounds'][0]['users']]
        self.assertIn(u1, uuids)
        for out in cfg['outbounds']:
            self.assertNotIn('routing_mark', out)

    def test_ss2022_rejects_sub_users(self):
        spec = {
            'protocol': 'ss2022',
            'name': 'SS-Node',
            'server': '203.0.113.10',
            'listen_port': 8388,
            'method': '2022-blake3-aes-256-gcm',
            'password': 'A' * 44,
            'sub_users': [{'mark_id': 1, 'password': 'B' * 32}],
        }
        with self.assertRaises(ValueError):
            validate_spec('landing.apply', spec)


class MixedEpochTrafficSpoolTest(unittest.TestCase):
    def test_independent_epochs_for_gost_and_nft_users(self):
        with tempfile.TemporaryDirectory() as td:
            spool = ReliableTrafficSpool(Path(td) / 'traffic-state.json')
            b1 = spool.compute_deltas(
                {
                    'forward:abc': {'forward_rule_id': 'abc', 'rx_bytes': 100, 'tx_bytes': 200},
                    'subuser:4': {'forward_rule_id': '', 'rx_bytes': 500, 'tx_bytes': 300, 'epoch': 'nft-1'},
                },
                epoch='gost-1',
            )
            self.assertEqual(len(b1), 1)
            spool.ack(b1[0]['batch_id'])

            # Rotating nft epoch does NOT cause gost baseline reset.
            b2 = spool.compute_deltas(
                {
                    'forward:abc': {'forward_rule_id': 'abc', 'rx_bytes': 150, 'tx_bytes': 250},
                    'subuser:4': {'forward_rule_id': '', 'rx_bytes': 80, 'tx_bytes': 40, 'epoch': 'nft-2'},
                },
                epoch='gost-1',
            )
            items = {i['resource_key']: i for i in b2[0]['items']}
            self.assertEqual(items['forward:abc']['rx_delta'], 50)
            self.assertEqual(items['forward:abc']['tx_delta'], 50)
            self.assertEqual(items['subuser:4']['rx_delta'], 80)
            self.assertEqual(items['subuser:4']['tx_delta'], 40)

    def test_flush_gost_traffic_uploads_nft_user_counters_without_gost(self):
        with tempfile.TemporaryDirectory() as td:
            posted = []

            class DummyClient:
                def post(self, path, payload, token):
                    posted.append((path, payload, token))
                    return {'status': 'ok'}

            cfg = {'instance_id': 'a' * 32, 'token': 'pfagt_test'}
            cfg_path = Path(td) / 'config.json'
            count = flush_gost_traffic(
                DummyClient(),
                cfg,
                cfg_path,
                metrics_meta_path=Path(td) / 'nonexistent-metrics.json',
                nft_user_reader=lambda: {
                    'epoch': 'nft-abc',
                    'totals': {
                        'subuser:12': {
                            'resource_key': 'subuser:12',
                            'forward_rule_id': '',
                            'rx_bytes': 2048,
                            'tx_bytes': 1024,
                            'epoch': 'nft-abc',
                        }
                    },
                },
            )
            self.assertEqual(count, 1)
            self.assertEqual(len(posted), 1)
            self.assertEqual(posted[0][0], '/api/agent/traffic')
            item = posted[0][1]['items'][0]
            self.assertEqual(item['resource_key'], 'subuser:12')
            self.assertEqual(item['rx_delta'], 2048)
            self.assertEqual(item['tx_delta'], 1024)


if __name__ == '__main__':
    unittest.main()
