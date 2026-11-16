"""Unit tests for Phase 0 multi-service runtime foundation and port coordination."""
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tarfile
import tempfile
import unittest
import uuid

from agent.runtime_download import download_release_binary, extract_release_binary
from agent.runtime_engine import (
    CADDY_PROFILE,
    GOST_PROFILE,
    PortBinding,
    RuntimeCoordinator,
    RuntimeEngine,
    SINGBOX_PROFILE,
    addresses_conflict,
    allocate_loopback_port,
    extract_config_bindings,
    validate_port_allocation,
)
from agent.runtime_helper import build_coordinator, serve_connection
from agent.runtime_spec import RELEASE, SERVICE_CADDY, SERVICE_GOST, SERVICE_SINGBOX, job_service, revision


def singbox_job(action='singbox.install'):
    identifier = uuid.uuid4().hex
    payload = {'version': RELEASE['version']} if action == 'singbox.install' else {}
    return {
        'id': identifier,
        'type': action,
        'payload': payload,
        'deployment_revision': revision(identifier, action, payload),
    }


class FakeServiceBackend:
    def __init__(self, profile):
        self.profile = profile
        self.running = None
        self.checked = []

    def active(self):
        return self.running is not None

    def matches(self, release):
        return self.running == release

    def check(self, release):
        self.checked.append(release)

    def activate(self, release):
        self.running = release

    def stop(self):
        self.running = None


class PortCoordinationTest(unittest.TestCase):
    def test_address_conflict_matrix_for_wildcards_and_loopbacks(self):
        self.assertTrue(addresses_conflict('::', '127.0.0.1'))
        self.assertTrue(addresses_conflict('::', '::1'))
        self.assertTrue(addresses_conflict('0.0.0.0', '127.0.0.1'))
        self.assertFalse(addresses_conflict('0.0.0.0', '::1'))
        self.assertFalse(addresses_conflict('127.0.0.1', '::1'))
        self.assertTrue(addresses_conflict('[::1]', '::1'))

    def test_extracts_bindings_for_singbox_caddy_and_gost(self):
        singbox_cfg = {
            'inbounds': [
                {'type': 'vless', 'listen': '::', 'listen_port': 443},
                {'type': 'shadowsocks', 'listen': '::', 'listen_port': 8388},
                {'type': 'hysteria2', 'listen': '::', 'listen_port': 443},
            ],
            'endpoints': [
                {'type': 'wireguard', 'listen_port': 51820},
            ],
        }
        sb_bindings = extract_config_bindings(SERVICE_SINGBOX, singbox_cfg)
        self.assertEqual(
            sb_bindings,
            [
                PortBinding(SERVICE_SINGBOX, 'tcp', '::', 443),
                PortBinding(SERVICE_SINGBOX, 'tcp', '::', 8388),
                PortBinding(SERVICE_SINGBOX, 'udp', '::', 8388),
                PortBinding(SERVICE_SINGBOX, 'udp', '::', 443),
                PortBinding(SERVICE_SINGBOX, 'udp', '::', 51820),
            ],
        )

        caddyfile = (
            '{\n'
            '    auto_https off\n'
            '}\n'
            'a.example.com:8443, b.example.com:8443 {\n'
            '    bind 127.0.0.1\n'
            '    respond "ok"\n'
            '}\n'
            'http://:80 {\n'
            '    respond "http"\n'
            '}\n'
        )
        self.assertEqual(extract_config_bindings(SERVICE_CADDY, CADDY_PROFILE.empty_config), [])
        self.assertEqual(
            extract_config_bindings(SERVICE_CADDY, caddyfile),
            [
                PortBinding(SERVICE_CADDY, 'tcp', '127.0.0.1', 8443),
                PortBinding(SERVICE_CADDY, 'tcp', '::', 80),
            ],
        )

        caddy_json = {
            'apps': {
                'http': {
                    'servers': {
                        'srv0': {'listen': ['127.0.0.1:18443'], 'protocols': ['h1', 'h2']},
                        'srv1': {'listen': ['[::]:9443'], 'protocols': ['h1', 'h2', 'h3']},
                    }
                }
            }
        }
        self.assertEqual(
            extract_config_bindings(SERVICE_CADDY, caddy_json),
            [
                PortBinding(SERVICE_CADDY, 'tcp', '127.0.0.1', 18443),
                PortBinding(SERVICE_CADDY, 'tcp', '::', 9443),
                PortBinding(SERVICE_CADDY, 'udp', '::', 9443),
            ],
        )

        gost_cfg = {
            'services': [
                {'name': 'fwd_tcp', 'addr': ':10000', 'listener': {'type': 'tcp'}},
                {'name': 'fwd_udp', 'addr': ':10000', 'listener': {'type': 'udp'}},
                {'name': 'relay', 'addr': '127.0.0.1:10001', 'listener': {'type': 'tls'}},
            ]
        }
        self.assertEqual(
            extract_config_bindings(SERVICE_GOST, gost_cfg),
            [
                PortBinding(SERVICE_GOST, 'tcp', '::', 10000),
                PortBinding(SERVICE_GOST, 'udp', '::', 10000),
                PortBinding(SERVICE_GOST, 'tcp', '127.0.0.1', 10001),
            ],
        )

    def test_cross_service_conflict_detected_and_self_update_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sb_root = root
            caddy_root = root / 'services' / SERVICE_CADDY
            gost_root = root / 'services' / SERVICE_GOST
            for sub, fname, content in [
                (sb_root, 'config.json', json.dumps({'inbounds': [{'type': 'vless', 'listen': '::', 'listen_port': 443}]})),
                (caddy_root, 'Caddyfile', ':8443 {\n    bind 127.0.0.1\n}\n'),
            ]:
                if os.name == 'posix':
                    rel = sub / 'releases' / ('a' * 32)
                    rel.mkdir(parents=True)
                    (rel / fname).write_text(content, encoding='utf-8')
                    os.symlink('releases/' + 'a' * 32, sub / 'current')
                else:
                    cur = sub / 'current'
                    cur.mkdir(parents=True)
                    (cur / fname).write_text(content, encoding='utf-8')

            roots = {SERVICE_SINGBOX: sb_root, SERVICE_CADDY: caddy_root, SERVICE_GOST: gost_root}

            # Same service updating its own port 443 must succeed.
            validate_port_allocation(
                SERVICE_SINGBOX,
                {'inbounds': [{'type': 'vless', 'listen': '::', 'listen_port': 443}]},
                service_roots=roots,
            )

            # go-gost trying to bind TCP 443 (held by sing-box) or TCP 8443 on 127.0.0.1 (held by caddy) must fail.
            with self.assertRaisesRegex(ValueError, 'conflicts with sing-box'):
                validate_port_allocation(
                    SERVICE_GOST,
                    {'services': [{'name': 's1', 'addr': '0.0.0.0:443', 'listener': {'type': 'tcp'}}]},
                    service_roots=roots,
                )
            with self.assertRaisesRegex(ValueError, 'conflicts with caddy'):
                validate_port_allocation(
                    SERVICE_GOST,
                    {'services': [{'name': 's2', 'addr': ':8443', 'listener': {'type': 'tcp'}}]},
                    service_roots=roots,
                )

            # go-gost binding UDP 443 does NOT conflict with sing-box VLESS TCP 443.
            validate_port_allocation(
                SERVICE_GOST,
                {'services': [{'name': 's3', 'addr': ':443', 'listener': {'type': 'udp'}}]},
                service_roots=roots,
            )

            # Intra-config duplicate is rejected.
            with self.assertRaisesRegex(ValueError, 'Duplicate listening port'):
                validate_port_allocation(
                    SERVICE_GOST,
                    {
                        'services': [
                            {'name': 'a', 'addr': ':10000', 'listener': {'type': 'tcp'}},
                            {'name': 'b', 'addr': '127.0.0.1:10000', 'listener': {'type': 'tcp'}},
                        ]
                    },
                    service_roots=roots,
                )

    def test_allocate_loopback_port_skips_reserved_and_bound_ports(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            bound_port = occupied.getsockname()[1]
            reserved = [
                PortBinding(SERVICE_SINGBOX, 'tcp', '::', bound_port + 1),
                PortBinding(SERVICE_CADDY, 'tcp', '127.0.0.1', bound_port + 2),
            ]
            chosen = allocate_loopback_port(
                reserved,
                start=bound_port,
                end=bound_port + 10,
                host='127.0.0.1',
                probe_host=True,
            )
            self.assertGreaterEqual(chosen, bound_port + 3)

        with self.assertRaises(ValueError):
            allocate_loopback_port(
                [PortBinding(SERVICE_GOST, 'tcp', '127.0.0.1', 18000)],
                start=18000,
                end=18000,
                probe_host=False,
            )


class MultiServiceCoordinatorAndDownloadTest(unittest.TestCase):
    def test_generic_release_extraction_and_untrusted_url_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / 'caddy.tar.gz'
            with tarfile.open(archive, 'w:gz') as package:
                for name, data in [('README.md', b'readme'), ('caddy', b'caddy-elf')]:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    package.addfile(member, io.BytesIO(data))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            extract_release_binary(archive, root / 'caddy', digest, ('caddy', 'bin/caddy'))
            self.assertEqual((root / 'caddy').read_bytes(), b'caddy-elf')
            with self.assertRaises(ValueError):
                download_release_binary(root, 'https://evil.example/caddy.tar.gz', digest, 'caddy', 'caddy')

    @unittest.skipUnless(os.name == 'posix', 'Runtime coordinator requires POSIX filesystem semantics')
    def test_build_coordinator_and_helper_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def fake_downloader(directory, arch, guard):
                guard()
                (directory / 'sing-box').write_bytes(b'test-binary')

            coordinator = build_coordinator(
                root,
                'amd64',
                backend_factory=FakeServiceBackend,
                downloaders={SERVICE_SINGBOX: fake_downloader},
                services=(SERVICE_SINGBOX, SERVICE_CADDY, SERVICE_GOST),
            )
            self.assertEqual(coordinator.engines[SERVICE_SINGBOX].root, root)
            self.assertEqual(coordinator.engines[SERVICE_CADDY].root, root / 'services' / SERVICE_CADDY)
            self.assertEqual(coordinator.engines[SERVICE_GOST].root, root / 'services' / SERVICE_GOST)
            self.assertEqual(job_service('singbox.install'), SERVICE_SINGBOX)
            with self.assertRaises(ValueError):
                job_service('unknown.action')

            server, client = socket.socketpair()
            with server, client:
                request = singbox_job('singbox.install')
                client.sendall(json.dumps(request).encode() + b'\n')
                serve_connection(server, coordinator, os.getuid())
                reply = json.loads(client.recv(8192))
                self.assertEqual(reply['status'], 'success')
                self.assertTrue(reply['output']['running'])

            bad_server, bad_client = socket.socketpair()
            with bad_server, bad_client:
                bad_client.sendall(json.dumps(singbox_job('singbox.status')).encode() + b'\n')
                serve_connection(bad_server, coordinator, os.getuid() + 1)
                bad_reply = json.loads(bad_client.recv(8192))
                self.assertEqual(bad_reply['error'], 'runtime_failed')

            coordinator.recover()
            self.assertEqual(coordinator.status(SERVICE_SINGBOX)['status'], 'running')
            self.assertEqual(coordinator.status(SERVICE_CADDY)['status'], 'not_installed')

    @unittest.skipUnless(os.name == 'posix', 'Runtime engine conflict requires POSIX filesystem semantics')
    def test_runtime_engine_rejects_sibling_port_conflict_before_publishing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def fake_sb_download(directory, arch, guard):
                guard()
                (directory / 'sing-box').write_bytes(b'sb')

            def fake_gost_download(directory, arch, guard):
                guard()
                (directory / 'gost').write_bytes(b'gost')

            coordinator = build_coordinator(
                root,
                'amd64',
                backend_factory=FakeServiceBackend,
                downloaders={SERVICE_SINGBOX: fake_sb_download, SERVICE_GOST: fake_gost_download},
                services=(SERVICE_SINGBOX, SERVICE_GOST),
            )
            gost_rel = coordinator.engines[SERVICE_GOST].root / 'releases' / ('b' * 32)
            gost_rel.mkdir(parents=True)
            (gost_rel / 'config.json').write_text(
                json.dumps({'services': [{'name': 'taken', 'addr': ':443', 'listener': {'type': 'tcp'}}]}),
                encoding='utf-8',
            )
            os.symlink('releases/' + 'b' * 32, coordinator.engines[SERVICE_GOST].root / 'current')

            import base64
            from agent.deployment_spec import spec_hash

            key_b64 = base64.urlsafe_b64encode(b'\x01' * 32).decode().rstrip('=')
            spec = {
                'name': 'Conflict',
                'server': 'vps.example.com',
                'server_name': 'www.example.com',
                'listen_port': 443,
                'uuid': str(uuid.uuid4()),
                'private_key': key_b64,
                'public_key': key_b64,
                'short_id': '0123456789abcdef',
            }
            payload = {'deployment_id': 'a' * 32, 'revision': 1, 'spec_hash': spec_hash(spec)}
            identifier = uuid.uuid4().hex
            job = {
                'id': identifier,
                'type': 'deployment.apply',
                'payload': payload,
                'deployment': spec,
                'deployment_revision': revision(identifier, 'deployment.apply', payload),
            }
            with self.assertRaisesRegex(ValueError, 'conflicts with go-gost'):
                coordinator.apply(job)
            self.assertIsNone(coordinator.engines[SERVICE_SINGBOX].pointer('current'))

    def test_profiles_defined_for_all_managed_services(self):
        self.assertEqual(SINGBOX_PROFILE.unit, 'proxyforge-singbox.service')
        self.assertEqual(CADDY_PROFILE.unit, 'proxyforge-caddy.service')
        self.assertEqual(GOST_PROFILE.unit, 'proxyforge-gost.service')


if __name__ == '__main__':
    unittest.main()
