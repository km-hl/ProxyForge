"""Pure-stdlib unit tests for agent/caddy_manager.py and multi-service Caddy/sing-box checks."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from agent.acme_manager import AcmeManager
from agent.caddy_manager import (
    CaddyError,
    CaddyManager,
    render_caddyfile,
    validate_camouflage_url,
    validate_site_spec,
)
from agent.deployment_spec import spec_hash
from agent.runtime_engine import (
    CADDY_PROFILE,
    SINGBOX_PROFILE,
    PortBinding,
    extract_config_bindings,
    validate_port_allocation,
)
from agent.runtime_helper import build_coordinator
from agent.runtime_spec import revision


class _FakeCoordinatorBackend:
    def __init__(self, profile):
        self.profile = profile
        self.uid = None
        self.gid = None
        self.current = None
        self.running = False

    def check(self, release):
        content = (release / self.profile.config_filename).read_text(encoding='utf-8')
        if self.profile.config_format == 'json':
            json.loads(content)

    def active(self, *, deadline=None):
        return self.running

    def matches(self, release, *, deadline=None):
        return self.running and self.current == release

    def activate(self, release):
        self.current = release
        self.running = True

    def stop(self):
        self.running = False


class CaddyRenderingAndSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_rejects_caddyfile_injection_and_ssrf_camouflage(self):
        for bad_url in (
            'http://example.com',
            'https://user:pass@example.com',
            'https://127.0.0.1',
            'https://10.0.0.1:8443',
            'https://localhost',
            'https://example.com/path?x=1',
            'https://example.com\n{\nreverse_proxy 127.0.0.1:9000\n}',
        ):
            with self.subTest(bad_url=bad_url), self.assertRaises(CaddyError):
                validate_camouflage_url(bad_url)

        for bad_path in ('ws', '/ws\nrespond 200', '/ws{evil}', '/ws;rm', '/ws?a=1'):
            with self.subTest(bad_path=bad_path), self.assertRaises(CaddyError):
                validate_site_spec({
                    'site_id': 's1',
                    'domain': 'edge.example.com',
                    'listen_port': 443,
                    'backend_port': 18001,
                    'ws_path': bad_path,
                    'tls_mode': 'acme_http',
                })

    def test_renders_loopback_camouflage_and_frontdoor_ws_caddyfiles(self):
        caddyfile = render_caddyfile(
            [
                {
                    'site_id': 'reality-camo',
                    'domain': 'reality.example.com',
                    'listen_port': 18443,
                    'bind_host': '127.0.0.1',
                    'tls_mode': 'acme_http',
                    'camouflage_url': 'https://www.wikipedia.org',
                },
                {
                    'site_id': 'ws-front',
                    'domain': 'ws.example.com',
                    'listen_port': 8443,
                    'bind_host': '::',
                    'backend_port': 18002,
                    'ws_path': '/ray',
                    'tls_mode': 'acme_dns',
                    'dns_zone_id': '0' * 32,
                },
            ],
            cert_pairs={
                'reality-camo': ('/certs/reality.crt', '/certs/reality.key'),
                'ws-front': ('/certs/ws.crt', '/certs/ws.key'),
            },
            storage_dir='/var/lib/proxyforge-runtime/services/caddy/state/storage',
        )
        self.assertIn('auto_https off', caddyfile)
        self.assertIn('https://reality.example.com:18443 {', caddyfile)
        self.assertIn('bind 127.0.0.1', caddyfile)
        self.assertIn('reverse_proxy https://www.wikipedia.org', caddyfile)
        self.assertIn('path /ray', caddyfile)
        self.assertIn('reverse_proxy 127.0.0.1:18002', caddyfile)

        bindings = extract_config_bindings('caddy', caddyfile)
        self.assertEqual(
            set(bindings),
            {
                PortBinding('caddy', 'tcp', '127.0.0.1', 18443),
                PortBinding('caddy', 'tcp', '::', 8443),
            },
        )

    def test_caddy_manager_stages_certs_and_detects_singbox_port_conflict(self):
        acme_dir = self.root / 'acme'
        cert_live = acme_dir / 'live' / 'caddy-site1'
        cert_live.mkdir(parents=True)
        (cert_live / 'fullchain.pem').write_text('CERT', encoding='utf-8')
        (cert_live / 'privkey.pem').write_text('KEY', encoding='utf-8')

        singbox_root = self.root / 'singbox'
        rel = singbox_root / 'releases' / ('a' * 32)
        rel.mkdir(parents=True)
        (rel / 'config.json').write_text(
            json.dumps({'inbounds': [{'type': 'vless', 'listen': '::', 'listen_port': 443}], 'outbounds': []}),
            encoding='utf-8',
        )
        (singbox_root / 'current').mkdir()
        (singbox_root / 'current' / 'config.json').write_text((rel / 'config.json').read_text(encoding='utf-8'), encoding='utf-8')

        fake_acme = AcmeManager(acme_dir, runner=lambda args, **kw: 'MATCH')
        caddy_mgr = CaddyManager(
            self.root / 'caddy' / 'state',
            acme_manager=fake_acme,
            service_roots={'sing-box': singbox_root},
        )

        # Port 443 conflicts with active sing-box on :: -> must reject before touching Caddy sites.json.
        with self.assertRaisesRegex(ValueError, 'conflicts with sing-box'):
            caddy_mgr.upsert_site({
                'site_id': 'site1',
                'domain': 'ws.example.com',
                'listen_port': 443,
                'bind_host': '::',
                'backend_port': 18010,
                'ws_path': '/ws',
                'tls_mode': 'acme_http',
            })

        # Port 8443 does not conflict -> renders Caddyfile & stages certs cleanly.
        caddyfile = caddy_mgr.upsert_site({
            'site_id': 'site1',
            'domain': 'ws.example.com',
            'listen_port': 8443,
            'bind_host': '::',
            'backend_port': 18010,
            'ws_path': '/ws',
            'tls_mode': 'acme_http',
        })
        self.assertIn('https://ws.example.com:8443', caddyfile)
        self.assertTrue((self.root / 'caddy' / 'certs' / 'site1.crt').is_file())
        self.assertTrue((self.root / 'caddy' / 'certs' / 'site1.key').is_file())
        validate_port_allocation('caddy', caddyfile, service_roots={'sing-box': singbox_root})

        removed = caddy_mgr.remove_site('site1')
        self.assertEqual(removed, CADDY_PROFILE.empty_config)
        self.assertFalse((self.root / 'caddy' / 'certs' / 'site1.crt').exists())


@unittest.skipUnless(os.name == 'posix', 'Coordinator multi-service runtime requires POSIX symlinks')
class CaddyCoordinatorOrchestrationTests(unittest.TestCase):
    def test_vless_ws_tls_coordinates_acme_singbox_caddy_and_removal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            acme_dir = root / 'acme'
            live = acme_dir / 'live' / 'caddy-landing'
            live.mkdir(parents=True)
            (live / 'fullchain.pem').write_text('CERT-PEM', encoding='utf-8')
            (live / 'privkey.pem').write_text('KEY-PEM', encoding='utf-8')

            coordinator = build_coordinator(
                root / 'runtime',
                'amd64',
                backend_factory=_FakeCoordinatorBackend,
                downloaders={
                    'sing-box': lambda p, arch, guard: (p / 'sing-box').write_bytes(b'sb'),
                    'caddy': lambda p, arch, guard: (p / 'caddy').write_bytes(b'cd'),
                },
                services=('sing-box', 'caddy'),
            )
            coordinator._acme_manager = AcmeManager(acme_dir, runner=lambda args, **kw: 'MATCH')

            spec = {
                'name': 'WS Edge',
                'server': 'edge.example.com',
                'listen_port': 443,
                'protocol': 'vless-ws',
                'domain': 'edge.example.com',
                'tls_mode': 'acme_http',
                'ws_path': '/ws',
                'camouflage_url': 'https://www.wikipedia.org',
                'uuid': str(uuid.uuid4()),
            }
            payload = {'deployment_id': 'f' * 32, 'revision': 1, 'spec_hash': spec_hash(spec)}
            job_id = uuid.uuid4().hex
            job = {
                'id': job_id,
                'type': 'landing.apply',
                'payload': payload,
                'deployment': spec,
                'deployment_revision': revision(job_id, 'landing.apply', payload),
            }
            result = coordinator.apply(job)
            self.assertEqual(result['status'], 'success')

            sb_cfg = json.loads((root / 'runtime' / 'current' / SINGBOX_PROFILE.config_filename).read_text(encoding='utf-8'))
            self.assertEqual(sb_cfg['inbounds'][0]['listen'], '127.0.0.1')
            backend_port = sb_cfg['inbounds'][0]['listen_port']
            caddyfile = (root / 'runtime' / 'services' / 'caddy' / 'current' / CADDY_PROFILE.config_filename).read_text(encoding='utf-8')
            self.assertIn(f'reverse_proxy 127.0.0.1:{backend_port}', caddyfile)
            self.assertIn('reverse_proxy https://www.wikipedia.org', caddyfile)

            rm_payload = {'deployment_id': 'f' * 32, 'revision': 2, 'spec_hash': spec_hash({})}
            rm_id = uuid.uuid4().hex
            remove_job = {
                'id': rm_id,
                'type': 'landing.remove',
                'payload': rm_payload,
                'deployment': {},
                'deployment_revision': revision(rm_id, 'landing.remove', rm_payload),
            }
            coordinator.apply(remove_job)
            caddy_after = (root / 'runtime' / 'services' / 'caddy' / 'current' / CADDY_PROFILE.config_filename).read_text(encoding='utf-8')
            self.assertEqual(caddy_after, CADDY_PROFILE.empty_config)


if __name__ == '__main__':
    unittest.main()
