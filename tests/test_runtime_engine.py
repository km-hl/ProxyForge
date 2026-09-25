import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import uuid

from agent.runtime_engine import RuntimeEngine, RuntimeCancelled, RollbackFailed, EMPTY_CONFIG
from agent.runtime_spec import RELEASE, revision, validate_runtime_job
from agent.runtime_download import extract_binary, ReleaseRedirect


def job(action='singbox.install'):
    identifier = uuid.uuid4().hex
    payload = {'version': RELEASE['version']} if action == 'singbox.install' else {}
    return {'id': identifier, 'type': action, 'payload': payload,
            'deployment_revision': revision(identifier, action, payload)}


class FakeBackend:
    running = None
    fail_once = False
    activation_count = 0

    def active(self):
        return self.running is not None

    def matches(self, release):
        return self.running == release

    def check(self, release):
        if json.loads((release / 'config.json').read_text()) != EMPTY_CONFIG:
            raise ValueError('Invalid configuration')

    def activate(self, release):
        self.running = release
        self.activation_count += 1
        if self.fail_once:
            self.fail_once = False
            raise ValueError('Unhealthy service')

    def stop(self):
        self.running = None


@unittest.skipUnless(os.name == 'posix', 'Runtime requires Linux filesystem semantics')
class RuntimeEngineTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backend = FakeBackend()
        def download(directory, arch, guard):
            guard()
            (directory / 'sing-box').write_bytes(b'verified test binary')
        self.engine = RuntimeEngine(self.root, self.backend, 'amd64', download)

    def test_install_start_stop_restart_rollback_and_duplicate_job(self):
        initial = job()
        first = self.engine.apply(initial)
        self.assertTrue(first['output']['running'])
        self.assertEqual(self.engine.apply(initial), first)
        self.assertEqual(self.backend.activation_count, 1)
        self.engine.apply(job())  # Same pinned version is a no-op while healthy.
        self.assertEqual(self.backend.activation_count, 1)
        self.engine.apply(job('singbox.start'))
        self.assertEqual(self.backend.activation_count, 1)
        self.engine.apply(job('singbox.restart'))
        self.assertNotEqual(self.engine.pointer('current'), 'releases/' + initial['id'])
        self.assertEqual(self.engine.pointer('previous'), 'releases/' + initial['id'])
        self.engine.apply(job('singbox.rollback'))
        self.assertEqual(len(list((self.root / 'releases').iterdir())), 2)
        self.assertFalse(self.engine.apply(job('singbox.stop'))['output']['running'])
        self.assertTrue(self.engine.apply(job('singbox.start'))['output']['running'])

    def test_activation_failure_restores_old_files_and_running_process(self):
        self.engine.apply(job())
        before = self.engine.pointer('current')
        self.backend.fail_once = True
        with self.assertRaises(ValueError):
            self.engine.apply(job('singbox.restart'))
        self.assertEqual(self.engine.pointer('current'), before)
        self.assertEqual(self.backend.running, self.root / before)
        self.assertFalse((self.root / 'transaction.json').exists())
        self.assertEqual(len(list((self.root / 'releases').iterdir())), 1)

    def test_failed_download_does_not_publish_or_leave_partial_release(self):
        def fail(directory, arch, guard):
            (directory / 'sing-box').write_bytes(b'partial')
            raise ValueError('download failed')
        self.engine.downloader = fail
        with self.assertRaises(ValueError):
            self.engine.apply(job())
        self.assertIsNone(self.engine.pointer('current'))
        self.assertEqual(list((self.root / 'releases').iterdir()), [])

    def test_lost_health_before_receipt_rolls_back_instead_of_caching_success(self):
        self.engine.apply(job())
        before = self.engine.pointer('current')
        change = job('singbox.restart')
        stopped = {'installed': True, 'running': False, 'version': RELEASE['version'], 'status': 'stopped'}
        with patch.object(self.engine, 'status', return_value=stopped), self.assertRaises(ValueError):
            self.engine.apply(change)
        self.assertNotIn(change['id'], self.engine.receipts())
        self.assertEqual(self.engine.pointer('current'), before)
        self.assertEqual(self.backend.running, self.root / before)

    def test_lease_loss_before_activation_retains_old_generation(self):
        self.engine.apply(job())
        before = self.engine.pointer('current')
        calls = []
        def guard():
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeCancelled()
        with self.assertRaises(RuntimeCancelled):
            self.engine.apply(job('singbox.restart'), guard)
        self.assertEqual(self.engine.pointer('current'), before)
        self.assertEqual(self.backend.activation_count, 1)

    def test_crash_after_activation_is_reconciled_without_duplicate_restart(self):
        current_job = job()
        with patch.object(self.engine, 'finish', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.apply(current_job)
        self.assertTrue((self.root / 'transaction.json').exists())
        self.engine.recover()
        self.engine.apply(current_job)
        self.assertEqual(self.backend.activation_count, 1)
        self.assertFalse((self.root / 'transaction.json').exists())

    def test_crash_before_activation_rolls_back_on_recovery(self):
        self.engine.apply(job())
        before = self.engine.pointer('current')
        with patch.object(self.backend, 'activate', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.apply(job('singbox.restart'))
        self.engine.recover()
        self.assertEqual(self.engine.pointer('current'), before)
        self.assertEqual(self.backend.running, self.root / before)

    def test_failed_rollback_preserves_intent_for_local_repair(self):
        self.engine.apply(job())
        with patch.object(self.backend, 'activate', side_effect=ValueError):
            with self.assertRaises(RollbackFailed):
                self.engine.apply(job('singbox.restart'))
        self.assertTrue((self.root / 'transaction.json').exists())
        self.engine.recover()
        self.assertFalse((self.root / 'transaction.json').exists())

    def test_changed_revision_and_outside_pointer_are_rejected(self):
        value = job()
        value['payload']['version'] = 'unreviewed'
        with self.assertRaises(ValueError):
            self.engine.apply(value)
        os.symlink('/etc', self.root / 'current')
        with self.assertRaises(ValueError):
            self.engine.status()

    def test_helper_rejects_other_local_uid_and_extra_payload(self):
        from agent.runtime_helper import serve_connection
        from unittest.mock import Mock
        for wrong_uid in (True, False):
            server, client = socket.socketpair()
            with server, client:
                value = job()
                if not wrong_uid:
                    value['command'] = 'id'
                client.sendall(json.dumps(value).encode() + b'\n')
                engine = Mock()
                serve_connection(server, engine, os.getuid() + 1 if wrong_uid else os.getuid())
                reply = json.loads(client.recv(8192))
                self.assertEqual(reply['error'], 'runtime_failed')
                engine.apply.assert_not_called()


class ReleaseTest(unittest.TestCase):
    def test_binary_only_extraction_and_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / 'test.tar.gz'
            with tarfile.open(archive, 'w:gz') as package:
                for name, content in [('../../escape', b'bad'),
                    ('sing-box-' + RELEASE['version'] + '-linux-amd64/sing-box', b'binary')]:
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    package.addfile(member, io.BytesIO(content))
            with self.assertRaises(ValueError):
                extract_binary(archive, root / 'binary', 'amd64')
            with patch.dict(RELEASE['assets']['amd64'], sha256=hashlib.sha256(archive.read_bytes()).hexdigest()):
                extract_binary(archive, root / 'binary', 'amd64')
            self.assertEqual((root / 'binary').read_bytes(), b'binary')
            self.assertEqual({path.name for path in root.iterdir()}, {'test.tar.gz', 'binary'})

    def test_symlink_binary_is_never_extracted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / 'test.tar.gz'
            with tarfile.open(archive, 'w:gz') as package:
                member = tarfile.TarInfo('sing-box-' + RELEASE['version'] + '-linux-amd64/sing-box')
                member.type, member.linkname = tarfile.SYMTYPE, '/bin/sh'
                package.addfile(member)
            with patch.dict(RELEASE['assets']['amd64'], sha256=hashlib.sha256(archive.read_bytes()).hexdigest()):
                with self.assertRaises(ValueError):
                    extract_binary(archive, root / 'binary', 'amd64')
            self.assertFalse((root / 'binary').exists())

    def test_arbitrary_versions_urls_and_revisions_are_rejected(self):
        original = job()
        for value in [{**original, 'deployment_revision': 'a' * 64},
                      {**original, 'payload': {'version': RELEASE['version'], 'url': 'https://evil.example'}},
                      {**original, 'id': '../../escape'}]:
            with self.assertRaises(ValueError):
                validate_runtime_job(value)
        for url in ['http://github.com/asset', 'https://evil.example/asset', 'https://github.com:8443/asset',
                    'https://user:pass@github.com/asset']:
            with self.assertRaises(ValueError):
                ReleaseRedirect().redirect_request(None, None, 302, '', {}, url)
