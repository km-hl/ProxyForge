"""Pure-stdlib unit tests for agent/acme_manager.py."""
import io
import json
import logging
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent.acme_manager import (
    AcmeError,
    AcmeManager,
    _read_credential_secret,
    audit_credentials,
    cleanup_orphan_credentials,
    commit_dns_credential,
    discard_pending_credential,
    dns_matches,
    http01_bindings,
    make_log_record_factory,
    recover_pending_credentials,
    stage_cloudflare_token,
    store_dns_token,
    validate_pair,
    verify_cloudflare_zone,
)


class _FakeOpener:
    def __init__(self, payload, url=None):
        self.payload = payload
        self.url = url
        self.last_headers = {}

    def open(self, request, timeout=10):
        self.last_headers = dict(request.header_items())
        encoded = json.dumps(self.payload).encode('utf-8')
        actual_url = self.url or request.full_url

        class _Resp:
            def __init__(self, data, target_url):
                self._bio = io.BytesIO(data)
                self._url = target_url

            def geturl(self):
                return self._url

            def read(self, size=-1):
                return self._bio.read(size)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Resp(encoded, actual_url)


class AcmeCredentialsAndValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'acme'
        self.valid_token = 'cf_token_AbCdEf0123456789_XYZ'
        self.zone_id = '0123456789abcdef0123456789abcdef'

    def test_cloudflare_stage_verify_commit_redaction_and_orphan_cleanup(self):
        opener = _FakeOpener({'success': True, 'result': {'id': self.zone_id, 'name': 'example.com'}})
        staged = stage_cloudflare_token(
            self.state,
            self.valid_token,
            {'zone_id': self.zone_id, 'propagation_seconds': 30},
            'sub.example.com',
            opener=opener,
        )
        profile_id = staged['credential_id']
        self.assertTrue(profile_id.startswith('cf-'))
        committed = commit_dns_credential(self.state, profile_id)
        self.assertEqual(committed, self.state / 'credentials' / (profile_id + '.ini'))
        if os.name == 'posix':
            self.assertEqual(committed.stat().st_mode & 0o777, 0o600)
        self.assertEqual(_read_credential_secret(committed, 'cloudflare'), self.valid_token)

        # Redacted logger factory scrubs API secrets from logs and exception text.
        factory = make_log_record_factory((self.valid_token,))
        with patch.object(logging, 'getLogRecordFactory', return_value=logging.LogRecord):
            record = factory('test', logging.ERROR, 'file.py', 1, f'failed auth token={self.valid_token}', (), None)
            self.assertNotIn(self.valid_token, record.msg)
            self.assertIn('[REDACTED]', record.msg)

        # Wrong zone or domain failure never leaks the raw secret in exception messages.
        bad_opener = _FakeOpener({'success': True, 'result': {'id': self.zone_id, 'name': 'other.org'}})
        with self.assertRaises(AcmeError) as ctx:
            verify_cloudflare_zone(self.state, staged, 'sub.example.com', opener=bad_opener)
        self.assertNotIn(self.valid_token, str(ctx.exception))

        # Audit + unconfirmed vs confirmed orphan cleanup.
        records = audit_credentials(self.state, active_references=())
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]['orphan'])
        with self.assertRaises(AcmeError):
            cleanup_orphan_credentials(self.state, [profile_id], confirmed=False)
        cleanup_orphan_credentials(self.state, [profile_id], confirmed=True)
        self.assertFalse(committed.exists())

    def test_pending_recovery_and_discard(self):
        pid = store_dns_token(self.state, self.valid_token, pending=True)
        marker = self.state / 'credentials' / 'pending' / (pid + '.json')
        data = json.loads(marker.read_text(encoding='utf-8'))
        data['owner'] = [999999, 'dead-boot', '0']
        marker.write_text(json.dumps(data), encoding='utf-8')
        removed = recover_pending_credentials(self.state)
        self.assertEqual(removed, [pid])
        discard_pending_credential(self.state, pid)

    def test_http01_dns_matching_and_pair_validation(self):
        resolver = lambda host, port, type=None: [(2, 1, 6, '', ('8.8.8.8', 0)), (10, 1, 6, '', ('2606:4700:4700::1111', 0))]
        ips = {'ipv4': '8.8.8.8', 'ipv6': '2606:4700:4700::1111'}
        answers = dns_matches('node.example.com', ips, resolver=resolver)
        self.assertEqual(http01_bindings(answers), ['0.0.0.0', '::'])

        with self.assertRaises(AcmeError):
            dns_matches('node.example.com', {'ipv4': '1.1.1.1', 'ipv6': ''}, resolver=resolver)

        cert = Path(self.temp.name) / 'cert.pem'
        key = Path(self.temp.name) / 'key.pem'
        cert.write_text('CERT', encoding='utf-8')
        key.write_text('KEY', encoding='utf-8')

        def fake_runner(args, **kwargs):
            if '-pubkey' in args or '-pubout' in args:
                return 'PUBKEY-PEM'
            if '-checkhost' in args:
                return 'Verified OK'
            return ''

        validate_pair(cert, key, 'node.example.com', runner=fake_runner)

        def mismatch_runner(args, **kwargs):
            if '-checkhost' in args:
                return 'Hostname does NOT match'
            return 'PUBKEY'

        with self.assertRaises(AcmeError):
            validate_pair(cert, key, 'node.example.com', runner=mismatch_runner)


class AcmeManagerWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'acme'

    def test_issue_and_due_renewal_preserves_existing_live_files_on_failure(self):
        def fake_runner(args, **kwargs):
            if args[0] == 'certbot' and args[1] == 'plugins':
                return '* dns-cloudflare'
            if args[0] == 'certbot' and args[1] == 'certonly':
                idx = args.index('--cert-name')
                name = args[idx + 1]
                lineage = self.state / 'acme' / name / 'config' / 'live' / name
                lineage.mkdir(parents=True, exist_ok=True)
                (lineage / 'fullchain.pem').write_text('VALID-CERT-V1', encoding='utf-8')
                (lineage / 'privkey.pem').write_text('VALID-KEY-V1', encoding='utf-8')
                return 'ok'
            if '-pubkey' in args or '-pubout' in args:
                return 'MATCHING-KEY'
            return 'Verified OK'

        resolver = lambda host, port, type=None: [(2, 1, 6, '', ('8.8.8.8', 0))]
        mgr = AcmeManager(
            self.state,
            runner=fake_runner,
            ip_reader=lambda: {'ipv4': '8.8.8.8', 'ipv6': ''},
            resolver=resolver,
            port_checker=lambda *args, **kwargs: None,
            which=lambda name: '/usr/bin/' + name,
        )
        cert, key = mgr.ensure_certificate('node1', 'vpn.example.com', tls_mode='acme_http', email='ops@example.com')
        self.assertEqual(cert.read_text(encoding='utf-8'), 'VALID-CERT-V1')
        self.assertEqual(key.read_text(encoding='utf-8'), 'VALID-KEY-V1')

        # Simulate expiry + failing certbot renewal -> old live certs must remain untouched!
        def failing_runner(args, **kwargs):
            if args[0] == 'certbot':
                raise AcmeError('rate limited')
            if '-checkend' in args and '2592000' in args:
                raise AcmeError('expiring')
            return 'MATCHING-KEY'

        failing_mgr = AcmeManager(
            self.state,
            runner=failing_runner,
            ip_reader=lambda: {'ipv4': '8.8.8.8', 'ipv6': ''},
            resolver=resolver,
            port_checker=lambda *args, **kwargs: None,
            which=lambda name: '/usr/bin/' + name,
        )
        results = failing_mgr.renew_due_certificates()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['status'], 'failed')
        self.assertEqual(cert.read_text(encoding='utf-8'), 'VALID-CERT-V1')
        self.assertEqual(key.read_text(encoding='utf-8'), 'VALID-KEY-V1')

    @unittest.skipUnless(os.name == 'posix', 'Certbot archive symlinks test requires POSIX symlink privileges')
    def test_certbot_archive_symlinks_accepted_inside_lineage_root_and_escaped_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as outer:
            outside_file = Path(outer) / 'outside.pem'
            outside_file.write_text('OUTSIDE-SECRET', encoding='utf-8')

            def symlink_runner(args, **kwargs):
                if args[0] == 'certbot' and args[1] == 'certonly':
                    name = args[args.index('--cert-name') + 1]
                    cfg_dir = self.state / 'acme' / name / 'config'
                    archive = cfg_dir / 'archive' / name
                    lineage = cfg_dir / 'live' / name
                    archive.mkdir(parents=True, exist_ok=True)
                    lineage.mkdir(parents=True, exist_ok=True)
                    (archive / 'fullchain1.pem').write_text('ARCHIVED-CERT', encoding='utf-8')
                    (archive / 'privkey1.pem').write_text('ARCHIVED-KEY', encoding='utf-8')
                    # Real certbot layout uses relative symlinks live/<name>/*.pem -> ../../archive/<name>/*1.pem
                    os.symlink(f'../../archive/{name}/fullchain1.pem', lineage / 'fullchain.pem')
                    os.symlink(f'../../archive/{name}/privkey1.pem', lineage / 'privkey.pem')
                    return 'ok'
                if '-pubkey' in args or '-pubout' in args:
                    return 'MATCHING-KEY'
                return 'Verified OK'

            resolver = lambda host, port, type=None: [(2, 1, 6, '', ('8.8.8.8', 0))]
            mgr = AcmeManager(
                self.state,
                runner=symlink_runner,
                ip_reader=lambda: {'ipv4': '8.8.8.8', 'ipv6': ''},
                resolver=resolver,
                port_checker=lambda *args, **kwargs: None,
                which=lambda name: '/usr/bin/' + name,
            )
            cert, key = mgr.ensure_certificate('node-sym', 'sym.example.com', tls_mode='acme_http')
            self.assertFalse(cert.is_symlink())
            self.assertFalse(key.is_symlink())
            self.assertEqual(cert.read_text(encoding='utf-8'), 'ARCHIVED-CERT')
            self.assertEqual(key.read_text(encoding='utf-8'), 'ARCHIVED-KEY')

            # Escape symlink pointing outside isolated config_dir must still be rejected
            def escaped_runner(args, **kwargs):
                if args[0] == 'certbot' and args[1] == 'certonly':
                    name = args[args.index('--cert-name') + 1]
                    lineage = self.state / 'acme' / name / 'config' / 'live' / name
                    lineage.mkdir(parents=True, exist_ok=True)
                    os.symlink(outside_file, lineage / 'fullchain.pem')
                    os.symlink(outside_file, lineage / 'privkey.pem')
                    return 'ok'
                return 'Verified OK'

            bad_mgr = AcmeManager(
                self.state,
                runner=escaped_runner,
                ip_reader=lambda: {'ipv4': '8.8.8.8', 'ipv6': ''},
                resolver=resolver,
                port_checker=lambda *args, **kwargs: None,
                which=lambda name: '/usr/bin/' + name,
            )
            with self.assertRaises(AcmeError):
                bad_mgr.ensure_certificate('node-bad', 'bad.example.com', tls_mode='acme_http')


if __name__ == '__main__':
    unittest.main()
