"""Pure standard-library unit tests for Phase 2 go-gost manager and Best Exit."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import uuid

from agent.gost_manager import (
    BestExitManager,
    combine_loss_percent,
    compute_exit_score,
    render_gost_config,
    validate_spec,
)
from agent.runtime_download import extract_gost_binary
from agent.runtime_engine import (
    GOST_PROFILE,
    PortBinding,
    RuntimeCoordinator,
    RuntimeEngine,
    SINGBOX_PROFILE,
    extract_config_bindings,
)
from agent.runtime_spec import (
    GOST_RELEASE,
    RELEASE,
    SERVICE_GOST,
    SERVICE_SINGBOX,
    job_service,
    revision,
    validate_runtime_job,
)


class FakeBackend:
    def __init__(self, profile):
        self.profile = profile
        self.running = None
        self.gid = None

    def active(self):
        return self.running is not None

    def matches(self, release):
        return self.running == release

    def check(self, release):
        data = json.loads((release / self.profile.config_filename).read_text(encoding='utf-8'))
        if not isinstance(data, dict) or 'services' not in data:
            raise ValueError('bad config')

    def activate(self, release):
        self.running = release

    def stop(self):
        self.running = None


def gost_job(action, deployment=None, payload=None):
    jid = uuid.uuid4().hex
    if action in ('gost.apply', 'gost.remove'):
        from agent.deployment_spec import spec_hash
        body = {'deployment_id': 'a' * 32, 'revision': 1, 'spec_hash': spec_hash(deployment)}
        job = {
            'id': jid,
            'type': action,
            'payload': body,
            'deployment_revision': revision(jid, action, body),
            'deployment': deployment,
        }
        return job
    body = {'version': GOST_RELEASE['version']} if action == 'gost.install' else (payload or {})
    return {
        'id': jid,
        'type': action,
        'payload': body,
        'deployment_revision': revision(jid, action, body),
    }


def tar_with(member_name, data):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        info = tarfile.TarInfo(member_name)
        info.size = len(data)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class GostManagerTest(unittest.TestCase):
    def test_manifest_extraction_and_sha256_verification(self):
        self.assertEqual(GOST_RELEASE['version'], '3.3.3')
        binary = b'#!/bin/sh\necho gost v3.3.3\n'
        digest = hashlib.sha256(tar_with('gost', binary)).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'gost.tar.gz'
            archive.write_bytes(tar_with('./gost', binary))
            dest = root / 'gost'
            with self.assertRaisesRegex(ValueError, 'checksum'):
                extract_gost_binary(archive, dest, 'amd64')
            saved = tar_with('./gost', binary)
            archive.write_bytes(saved)
            real_digest = hashlib.sha256(saved).hexdigest()
            patched = {**GOST_RELEASE, 'assets': {**GOST_RELEASE['assets'], 'amd64': {'name': 'g.tgz', 'sha256': real_digest}}}
            with mock.patch('agent.runtime_download.GOST_RELEASE', patched):
                extract_gost_binary(archive, dest, 'amd64')
            self.assertEqual(dest.read_bytes(), binary)
            self.assertNotEqual(digest, real_digest)

    def test_validate_and_render_forward_chain_and_best_exit(self):
        spec = {
            'forwards': [
                {
                    'id': 'f1',
                    'name': 'HK Direct',
                    'listen': '::',
                    'listen_port': 10000,
                    'protocol': 'tcp+udp',
                    'targets': [{'addr': '198.51.100.1:443', 'name': 'hk-node'}],
                    'proxy_protocol': 2,
                    'strategy': 'round',
                    'max_fails': 2,
                    'fail_timeout': 15,
                },
                {
                    'id': 'f2',
                    'name': 'Cascade Best',
                    'listen': '0.0.0.0',
                    'listen_port': 10001,
                    'protocol': 'tcp',
                    'chain': 'c1',
                    'exit_group': 'g1',
                    'targets': [],
                },
            ],
            'chains': [
                {
                    'id': 'c1',
                    'name': 'c1',
                    'hops': [
                        {
                            'name': 'hop0',
                            'nodes': [
                                {
                                    'name': 'mid1',
                                    'addr': '203.0.113.10:8443',
                                    'connector': 'relay',
                                    'dialer': 'tls',
                                    'username': 'u1',
                                    'password': 'secret-relay-password',
                                    'server_name': 'relay.example.com',
                                    'nodelay': True,
                                }
                            ],
                        }
                    ],
                }
            ],
            'relay_services': [
                {
                    'id': 'r1',
                    'name': 'mid_in',
                    'listen': '::',
                    'listen_port': 8443,
                    'handler': 'relay',
                    'listener': 'tls',
                    'username': 'u1',
                    'password': 'secret-relay-password',
                    'nodelay': True,
                }
            ],
            'best_exit_groups': [
                {
                    'id': 'g1',
                    'name': 'hk-exits',
                    'confirmation_rounds': 3,
                    'exits': [
                        {'id': 'e1', 'name': 'exit-a', 'addr': '198.51.100.10:443', 'weight': 100},
                        {'id': 'e2', 'name': 'exit-b', 'addr': '198.51.100.11:443', 'weight': 90},
                    ],
                    'selected_exit_id': 'e2',
                }
            ],
        }
        validate_spec('gost.apply', spec)
        rendered = render_gost_config(spec, metrics_addr='127.0.0.1:18123')
        svc_names = [s['name'] for s in rendered['services']]
        self.assertEqual(svc_names, ['fwd_f1_tcp', 'fwd_f1_udp', 'fwd_f2_tcp', 'relay_r1'])
        self.assertEqual(rendered['metrics'], {'addr': '127.0.0.1:18123', 'path': '/metrics'})
        self.assertEqual(rendered['services'][0]['listener']['metadata'], {'proxyProtocol': 2})
        self.assertEqual(rendered['services'][1]['handler']['metadata'], {'keepAlive': True, 'ttl': '60s'})
        # e2 selected first via fifo despite lower weight
        f2_nodes = rendered['services'][2]['forwarder']['nodes']
        self.assertEqual([n['name'] for n in f2_nodes], ['exit-b', 'exit-a'])
        self.assertEqual(rendered['chains'][0]['hops'][0]['nodes'][0]['dialer'], {'type': 'tls', 'tls': {'serverName': 'relay.example.com'}})

        for bad in [
            {**spec, 'metrics_addr': '0.0.0.0:9090'},
            {**spec, 'forwards': [{**spec['forwards'][0], 'chain': 'missing'}]},
            {**spec, 'forwards': [{**spec['forwards'][0], 'exit_group': 'missing'}]},
            {**spec, 'forwards': [{**spec['forwards'][0], 'listen_port': 0}]},
        ]:
            with self.assertRaises(ValueError):
                validate_spec('gost.apply', bad)

        with self.assertRaises(ValueError):
            validate_spec('gost.remove', spec)
        self.assertEqual(render_gost_config({'forwards': [], 'chains': [], 'relay_services': [], 'best_exit_groups': []}),
                         {'services': []})

    def test_best_exit_anti_flap_confirmation_and_cooldown(self):
        self.assertAlmostEqual(combine_loss_percent(10.0, 20.0), 28.0)
        self.assertEqual(compute_exit_score(50.0, 2.0), 250.0)
        manager = BestExitManager()
        group = {
            'id': 'grp1',
            'confirmation_rounds': 3,
            'cooldown_seconds': 30,
            'min_advantage_ms': 20.0,
            'min_advantage_ratio': 0.15,
            'selected_exit_id': 'e1',
            'exits': [
                {'id': 'e1', 'addr': '198.51.100.1:443'},
                {'id': 'e2', 'addr': '198.51.100.2:443'},
            ],
        }
        # Minor gain (< 15%) stays on e1
        minor = {
            'e1': {'entry_latency_ms': 50, 'exit_latency_ms': 50, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
            'e2': {'entry_latency_ms': 46, 'exit_latency_ms': 45, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
        }
        res = manager.evaluate(group, minor, now=100.0)
        self.assertFalse(res['switched'])
        self.assertEqual(res['reason'], 'below_advantage_threshold')

        # Significant improvement requires 3 consecutive confirmations
        better = {
            'e1': {'entry_latency_ms': 80, 'exit_latency_ms': 80, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
            'e2': {'entry_latency_ms': 20, 'exit_latency_ms': 20, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
        }
        r1 = manager.evaluate(group, better, now=105.0)
        r2 = manager.evaluate(group, better, now=110.0)
        self.assertFalse(r1['switched'])
        self.assertFalse(r2['switched'])
        self.assertEqual(r2['candidate_rounds'], 2)
        r3 = manager.evaluate(group, better, now=115.0)
        self.assertTrue(r3['switched'])
        self.assertEqual(r3['selected_exit_id'], 'e2')

        # Cooldown blocks immediate reverse switch for 30s
        flip_back = {
            'e1': {'entry_latency_ms': 10, 'exit_latency_ms': 10, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
            'e2': {'entry_latency_ms': 80, 'exit_latency_ms': 80, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
        }
        manager.evaluate(group, flip_back, now=120.0)
        manager.evaluate(group, flip_back, now=125.0)
        blocked = manager.evaluate(group, flip_back, now=130.0)
        self.assertFalse(blocked['switched'])
        self.assertEqual(blocked['reason'], 'cooldown')

        # After cooldown elapses, switch commits immediately
        unblocked = manager.evaluate(group, flip_back, now=150.0)
        self.assertTrue(unblocked['switched'])
        self.assertEqual(unblocked['selected_exit_id'], 'e1')

        # Unreachable active exit triggers immediate failover without waiting 3 rounds
        down = {
            'e1': {'entry_latency_ms': 0, 'exit_latency_ms': 0, 'entry_loss_pct': 100, 'exit_loss_pct': 0},
            'e2': {'entry_latency_ms': 50, 'exit_latency_ms': 50, 'entry_loss_pct': 0, 'exit_loss_pct': 0},
        }
        failover = manager.evaluate(group, down, now=151.0)
        self.assertTrue(failover['switched'])
        self.assertEqual(failover['selected_exit_id'], 'e2')
        self.assertEqual(failover['reason'], 'current_unreachable_failover')

    def test_metrics_addr_allocation_avoids_conflicts_cross_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sb_root = root / 'singbox'
            gost_root = root / 'services' / SERVICE_GOST
            sb_rel = sb_root / 'releases' / ('a' * 32)
            sb_rel.mkdir(parents=True)
            (sb_rel / 'config.json').write_text(
                json.dumps({'inbounds': [{'type': 'vless', 'listen': '127.0.0.1', 'listen_port': 18000}]}),
                encoding='utf-8',
            )
            (sb_root / 'current').mkdir(parents=True)
            (sb_root / 'current' / 'config.json').write_text((sb_rel / 'config.json').read_text(encoding='utf-8'), encoding='utf-8')
            gost_root.mkdir(parents=True)
            engines = {
                SERVICE_SINGBOX: RuntimeEngine(sb_root, FakeBackend(SINGBOX_PROFILE), 'amd64', profile=SINGBOX_PROFILE),
                SERVICE_GOST: RuntimeEngine(gost_root, FakeBackend(GOST_PROFILE), 'amd64', profile=GOST_PROFILE),
            }
            coord = RuntimeCoordinator(engines)
            spec = {
                'forwards': [{'id': 'f1', 'name': 'fwd', 'listen': '127.0.0.1', 'listen_port': 18001, 'protocol': 'tcp', 'targets': [{'addr': '198.51.100.1:443'}]}],
                'chains': [],
                'relay_services': [],
                'best_exit_groups': [],
            }
            chosen = coord._resolve_gost_metrics_addr(engines[SERVICE_GOST], spec)
            self.assertEqual(chosen, '127.0.0.1:18002')
            coord._write_gost_metrics_meta(engines[SERVICE_GOST], chosen, 'abc123')
            self.assertEqual(json.loads((gost_root / 'metrics.json').read_text(encoding='utf-8'))['metrics_addr'], chosen)
            coord._write_gost_metrics_meta(engines[SERVICE_GOST], '', '')
            self.assertFalse((gost_root / 'metrics.json').exists())

    @unittest.skipUnless(os.name == 'posix', 'Runtime coordinator requires POSIX filesystem semantics')
    def test_runtime_coordinator_gost_install_apply_metrics_and_port_guards(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            if os.name != 'posix':
                stack.enter_context(mock.patch('agent.runtime_engine.os.fsync'))
            root = Path(tmp)
            sb_root = root / 'singbox'
            gost_root = root / 'services' / SERVICE_GOST
            sb_root.mkdir(parents=True)
            gost_root.mkdir(parents=True)
            engines = {
                SERVICE_SINGBOX: RuntimeEngine(sb_root, FakeBackend(SINGBOX_PROFILE), 'amd64',
                                               downloader=lambda cand, arch, guard: (cand / 'sing-box').write_bytes(b'sb'),
                                               profile=SINGBOX_PROFILE),
                SERVICE_GOST: RuntimeEngine(gost_root, FakeBackend(GOST_PROFILE), 'amd64',
                                            downloader=lambda cand, arch, guard: (cand / 'gost').write_bytes(b'gost'),
                                            profile=GOST_PROFILE),
            }
            coord = RuntimeCoordinator(engines)
            self.assertEqual(job_service('gost.apply'), SERVICE_GOST)
            self.assertEqual(job_service('gost.install'), SERVICE_GOST)

            install_job = gost_job('gost.install')
            validate_runtime_job(install_job)
            coord.apply(install_job)

            spec = {
                'forwards': [{
                    'id': 'f1',
                    'name': 'fwd',
                    'listen': '::',
                    'listen_port': 12000,
                    'protocol': 'tcp',
                    'targets': [{'addr': '198.51.100.1:443'}],
                }],
                'chains': [],
                'relay_services': [],
                'best_exit_groups': [],
            }
            apply_job = gost_job('gost.apply', spec)
            validate_runtime_job(apply_job)
            coord.apply(apply_job)

            meta = json.loads((gost_root / 'metrics.json').read_text(encoding='utf-8'))
            self.assertTrue(meta['metrics_addr'].startswith('127.0.0.1:'))
            cfg = json.loads((gost_root / 'current' / 'config.json').read_text(encoding='utf-8'))
            self.assertEqual(cfg['metrics']['addr'], meta['metrics_addr'])
            bindings = extract_config_bindings(SERVICE_GOST, cfg)
            self.assertEqual(len(bindings), 2)  # forward tcp 12000 + metrics loopback tcp
            self.assertEqual(bindings[0], PortBinding(SERVICE_GOST, 'tcp', '::', 12000))

            # Updating forwards reuses the stable loopback metrics port
            spec2 = {
                **spec,
                'forwards': [{**spec['forwards'][0], 'listen_port': 12001}],
            }
            coord.apply(gost_job('gost.apply', spec2))
            meta2 = json.loads((gost_root / 'metrics.json').read_text(encoding='utf-8'))
            self.assertEqual(meta2['metrics_addr'], meta['metrics_addr'])

            # Removing gost forwards clears metrics.json cleanly
            coord.apply(gost_job('gost.remove', {'forwards': [], 'chains': [], 'relay_services': [], 'best_exit_groups': []}))
            self.assertFalse((gost_root / 'metrics.json').exists())


if __name__ == '__main__':
    unittest.main()
