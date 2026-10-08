"""公网 operator 驱动的信任锚点、归属、备份和脱敏边界。"""
import hashlib
import contextlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('agent_public', ROOT / 'scripts/check_agent_public.py')
PUBLIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLIC)


class AgentPublicTests(unittest.TestCase):
    def test_api_cannot_select_arbitrary_root_installation_code(self):
        base = 'https://controller.example'
        for source, (commit, digest) in PUBLIC.ANCHORS.items():
            commands = {action: PUBLIC.render(commit, digest, action=action,
                                             server=base if action == 'install' else None)
                        for action in ('install', 'runtime', 'check')}
            info = {'available': True, 'controller_url': base, 'agent_version': '0.6.0',
                    'source_commit': source, 'bootstrap_commit': commit, 'bootstrap_sha256': digest,
                    'commands': commands}
            self.assertEqual(PUBLIC.verified_commands(info, base, source), commands)
            for key, value in [('controller_url', 'https://other.example'), ('bootstrap_sha256', '0' * 64),
                               ('source_commit', '0' * 40), ('commands', {**commands, 'runtime': 'sudo arbitrary'}),
                               ('available', False)]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    PUBLIC.verified_commands({**info, key: value}, base, source)

    def test_fixture_cleanup_refuses_other_or_repurposed_agent(self):
        item = {'id': 'a' * 32, 'name': 'own fixture', 'role': 'unassigned', 'instance_id': 'b' * 32}
        self.assertEqual(PUBLIC.owned(item, 'own fixture', 'b' * 32), 'a' * 32)
        for key, value in [('id', '../another'), ('name', 'business Agent'), ('role', 'node'), ('instance_id', 'c' * 32)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                PUBLIC.owned({**item, key: value}, 'own fixture', 'b' * 32)

    def test_windows_and_missing_kvm_stop_before_host_operations(self):
        with patch.object(PUBLIC.platform, 'system', return_value='Windows'), \
                patch.object(PUBLIC.subprocess, 'run') as operation:
            with self.assertRaises(ValueError):
                PUBLIC.host_guard()
            operation.assert_not_called()
        with patch.object(PUBLIC.platform, 'system', return_value='Linux'), \
                patch.object(PUBLIC.platform, 'machine', return_value='x86_64'), \
                patch.object(PUBLIC.os, 'geteuid', return_value=0, create=True), \
                patch.object(PUBLIC.os, 'access', return_value=False), \
                patch.object(PUBLIC.subprocess, 'run') as operation:
            with self.assertRaisesRegex(ValueError, 'requires KVM'):
                PUBLIC.host_guard()
            operation.assert_not_called()

    def test_subprocess_error_does_not_disclose_private_output(self):
        result = subprocess.CompletedProcess(['operator'], 1, b'private credential output', b'private config error')
        with patch.object(PUBLIC.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as raised:
                PUBLIC.quiet(['operator'])
        self.assertNotIn('credential', str(raised.exception))
        self.assertNotIn('config', str(raised.exception))

    def test_online_backup_is_readable_and_does_not_modify_live_database(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            data = work / 'live'
            data.mkdir()
            (data / 'config.json').write_text('{"private":"fixture"}')
            (data / 'history').mkdir()
            (data / 'empty').mkdir()
            (data / 'history' / 'old.yaml').write_text('fixture history')
            with contextlib.closing(sqlite3.connect(data / 'proxyforge.db')) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE schema_migrations(version INTEGER)')
                db.execute('INSERT INTO schema_migrations VALUES(5)')
                for table in PUBLIC.TABLES:
                    db.execute('CREATE TABLE ' + table + '(id TEXT)')
                db.execute('INSERT INTO agents VALUES(?)', ('existing fixture',))
                db.commit()
            before = hashlib.sha256((data / 'proxyforge.db').read_bytes()).hexdigest()
            _, counts, digest = PUBLIC.backup(data, work / 'backup')
            self.assertEqual(counts['agents'], 1)
            self.assertEqual(hashlib.sha256((data / 'proxyforge.db').read_bytes()).hexdigest(), before)
            manifest = json.loads((work / 'backup/manifest.json').read_text())
            self.assertEqual(manifest['archive_sha256'], digest)
            with tarfile.open(work / 'backup/data.tar') as archive:
                self.assertTrue(archive.getmember('data/empty').isdir())
                self.assertEqual(archive.getmember('data').mode, PUBLIC.stat.S_IMODE(data.stat().st_mode))
                self.assertEqual(archive.extractfile('data/history/old.yaml').read(), b'fixture history')
                for name, info in manifest['files'].items():
                    self.assertEqual(hashlib.sha256(archive.extractfile('data/' + name).read()).hexdigest(), info['sha256'])
            self.assertEqual(PUBLIC.database_counts(work / 'backup/data/proxyforge.db'), counts)

    def test_backup_refuses_hard_links_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            data = work / 'live'
            data.mkdir()
            (data / 'config.json').write_text('fixture')
            try:
                PUBLIC.os.link(data / 'config.json', data / 'linked.json')
            except OSError:
                self.skipTest('Filesystem does not support hard links')
            with self.assertRaisesRegex(ValueError, 'hard link'):
                PUBLIC.backup(data, work / 'backup')
            self.assertFalse((work / 'backup').exists())

    def test_private_backups_refuse_mutable_output_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o777)
            with self.assertRaisesRegex(ValueError, 'root-owned'):
                PUBLIC.private_parent(parent)

    def test_live_backup_never_opens_host_sqlite_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            data = work / 'live'
            data.mkdir()
            with contextlib.closing(sqlite3.connect(data / 'proxyforge.db')) as db:
                db.execute('CREATE TABLE schema_migrations(version INTEGER)')
                db.execute('INSERT INTO schema_migrations VALUES(5)')
                for table in PUBLIC.TABLES:
                    db.execute('CREATE TABLE ' + table + '(id TEXT)')
                db.commit()
            exported = (data / 'proxyforge.db').read_bytes()
            connect = sqlite3.connect

            def protected_connect(path, *args, **kwargs):
                if str(path).startswith((data / 'proxyforge.db').as_uri()):
                    raise AssertionError('Host must not open the live WAL database')
                return connect(path, *args, **kwargs)

            with patch.object(PUBLIC, 'quiet', return_value=exported) as transport, \
                    patch.object(PUBLIC.sqlite3, 'connect', side_effect=protected_connect):
                _, counts, _ = PUBLIC.backup(data, work / 'backup', container='test-controller')
            self.assertFalse(any(counts.values()))
            self.assertEqual(transport.call_args.args[0][:6], ['docker', 'exec', '-i', 'test-controller', 'python', '-I'])
            self.assertEqual(json.loads(transport.call_args.kwargs['payload']), {'operation': 'backup'})

    def test_live_counts_use_container_transport(self):
        counts = {table: 0 for table in PUBLIC.TABLES}
        with patch.object(PUBLIC, 'quiet', return_value=json.dumps(counts).encode()) as transport, \
                patch.object(PUBLIC.sqlite3, 'connect') as host_connect:
            self.assertEqual(PUBLIC.live_counts('test-controller'), counts)
            host_connect.assert_not_called()
            self.assertEqual(json.loads(transport.call_args.kwargs['payload']), {'operation': 'counts'})

    def test_database_export_rejects_wrong_data_user_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'copy.db'
            fixture.write_bytes(b'not opened')
            program = PUBLIC.DATABASE.replace('/app/data/proxyforge.db', fixture.as_posix())
            info = fixture.stat()
            with patch.object(PUBLIC.os, 'geteuid', return_value=info.st_uid + 1, create=True), \
                    patch.object(PUBLIC.os, 'getegid', return_value=info.st_gid, create=True), \
                    patch.object(PUBLIC.sqlite3, 'connect') as connect:
                with self.assertRaisesRegex(ValueError, 'configured data user'):
                    exec(program, {})
                connect.assert_not_called()


@unittest.skipIf(sys.platform == 'win32', 'Real controlling TTY requires Linux')
class PublicGuestTTYTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('agent_public_guest', ROOT / 'scripts/agent_public_guest.py')
        cls.guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.guest)

    def test_hidden_prompt_receives_input_without_echo(self):
        code = "import getpass; value=getpass.getpass('One-time registration token (hidden): '); raise SystemExit(0 if value=='fixture-token' else 2)"
        command = '/usr/bin/python3 -c ' + PUBLIC.shlex.quote(code)
        status, output, sent = self.guest.command_pty(command, 'fixture-token')
        self.assertEqual(status, 0)
        self.assertTrue(sent)
        self.assertNotIn(b'fixture-token', output)

    def test_echoing_prompt_refuses_to_send_credential(self):
        code = "print('One-time registration token (hidden): ', end='', flush=True); input()"
        command = '/usr/bin/python3 -c ' + PUBLIC.shlex.quote(code)
        with self.assertRaisesRegex(ValueError, 'unsafe_prompt'):
            self.guest.command_pty(command, 'fixture-token')


if __name__ == '__main__':
    unittest.main()
