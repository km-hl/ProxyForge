"""Release rehearsals using synthetic data only; no production paths or services."""
import json
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from proxyforge.control.control_store import ControlStore, UnauthorizedAgent
from proxyforge.control.deployment_store import DeploymentKeyError
from proxyforge.control.job_store import JobConflict
from proxyforge.security.runtime_security import RuntimeConfigStore
from proxyforge.config.template_store import TemplateStore
from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN
import test_chains as chain_tests
from test_deployments import RESULT


class LegacyReleaseTest(unittest.TestCase):
    def test_file_only_installation_preserves_configuration_on_first_control_plane_use(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = root / 'data'
            data.mkdir()
            RuntimeConfigStore(data / 'config.json', data / 'admin_token.txt', environ={
                'SECRET_TOKEN': TEST_SUBSCRIPTION_TOKEN, 'ADMIN_TOKEN': TEST_ADMIN_TOKEN,
            }).load_or_create()
            (data / 'template.yaml').write_bytes(b'proxy-groups: []\nrules:\n  - MATCH,DIRECT\n')
            (data / 'airports.yaml').write_bytes(b'[]\n')
            manual = {'name': 'manual', 'type': 'ss', 'server': 'manual.example.com', 'port': 8388,
                      'cipher': 'aes-128-gcm', 'password': 'synthetic-test-password'}
            (data / 'custom_nodes.yaml').write_text(json.dumps([manual]), encoding='utf-8')
            before = {path.name: path.read_bytes() for path in data.iterdir() if path.is_file()}
            app = load_isolated_application(root)
            self.assertFalse((data / 'proxyforge.db').exists())
            headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            with TestClient(app.app) as client:
                self.assertEqual(client.get('/api/agents', headers=headers).json(), {'agents': []})
                self.assertEqual(client.get('/api/agents/managed/nodes', headers=headers).json(), {'nodes': []})
                self.assertEqual(client.get('/api/nodes', headers=headers).json()['nodes'],
                                 [{**manual, '_airport_name': '_custom_nodes_'}])
                self.assertEqual(client.get('/api/template', headers=headers).json()['content'],
                                 before['template.yaml'].decode())
                self.assertEqual(client.get('/api/config').status_code, 401)
                self.assertEqual(client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN}).status_code, 200)
            for name, content in before.items():
                self.assertEqual((data / name).read_bytes(), content, name)
            self.assertFalse((data / 'deployment.key').exists())
            with closing(sqlite3.connect(str(data / 'proxyforge.db'))) as db:
                self.assertEqual(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 5)


class RecoveryReleaseTest(unittest.TestCase):
    enroll = chain_tests.ChainStoreTest.enroll
    complete = chain_tests.ChainStoreTest.complete
    put = chain_tests.ChainStoreTest.put

    def setUp(self):
        chain_tests.ChainStoreTest.setUp(self)
        self.now = self.store.clock()
        self.store.clock = lambda: self.now
        self.root = self.store.path.parent
        self.restore_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.restore_temp.cleanup)
        self.restored_root = Path(self.restore_temp.name) / 'restored'

    def cold_restore(self):
        # All connections/writers are closed. Never use copytree as an online backup.
        shutil.copytree(self.root, self.restored_root)
        return ControlStore(self.restored_root / self.store.path.name, clock=lambda: self.now)

    def test_cold_restore_preserves_nodes_history_credentials_and_revocations(self):
        self.put()
        self.complete(self.entry)
        revoked = self.enroll()
        self.store.revoke(revoked['agent_id'])
        template = self.root / 'template.yaml'
        template.write_bytes(b'proxy-groups: []\nrules: []\n')
        history = TemplateStore(template)
        history.commit({'template.yaml': 'proxy-groups: []\nrules: ["MATCH,DIRECT"]\n',
                        'custom_nodes.yaml': '[]\n', 'airports.yaml': '[]\n'})
        RuntimeConfigStore(self.root / 'config.json', self.root / 'admin_token.txt', environ={
            'SECRET_TOKEN': TEST_SUBSCRIPTION_TOKEN, 'ADMIN_TOKEN': TEST_ADMIN_TOKEN,
        }).load_or_create()
        files = {path.relative_to(self.root): path.read_bytes() for path in self.root.rglob('*')
                 if path.is_file() and not path.name.startswith(self.store.path.name)}
        original_nodes = self.store.managed_nodes()
        original_inventory = self.store.managed_inventory()
        restored = self.cold_restore()
        self.assertEqual(restored.managed_nodes(), original_nodes)
        self.assertEqual(restored.managed_inventory(), original_inventory)
        restored_history = TemplateStore(self.restored_root / 'template.yaml')
        self.assertEqual(restored_history.snapshot(), history.snapshot())
        self.assertEqual(restored_history.list_history(), history.list_history())
        for name, content in files.items():
            self.assertEqual((self.restored_root / name).read_bytes(), content, str(name))
        restored.heartbeat(self.entry['agent_token'], self.info, '')
        with self.assertRaises(UnauthorizedAgent):
            restored.heartbeat(revoked['agent_token'], self.info, '')
        with restored.connection() as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_restored_inflight_job_reclaims_same_snapshot_and_fences_old_lease(self):
        self.put()
        original = self.store.claim_job(self.entry['agent_token'], self.info['instance_id'])
        self.store.report_job(self.entry['agent_token'], original['id'], original['lease_token'])
        restored = self.cold_restore()
        self.now += 61  # Lease expires, but the one-hour job deadline has not passed.
        replacement = restored.claim_job(self.entry['agent_token'], self.info['instance_id'])
        for field in ('id', 'deployment_revision', 'payload', 'deployment'):
            self.assertEqual(replacement[field], original[field])
        self.assertNotEqual(replacement['lease_token'], original['lease_token'])
        with self.assertRaises(JobConflict):
            restored.report_job(self.entry['agent_token'], original['id'], original['lease_token'], RESULT)
        restored.report_job(self.entry['agent_token'], replacement['id'], replacement['lease_token'])
        restored.report_job(self.entry['agent_token'], replacement['id'], replacement['lease_token'], RESULT)
        self.assertEqual(len(restored.managed_nodes()), 2)
        # A lost result acknowledgement remains safe to replay after recovery.
        self.assertEqual(restored.report_job(self.entry['agent_token'], replacement['id'],
                                            replacement['lease_token'], RESULT), {'status': 'success'})

    def test_missing_or_wrong_restore_key_fails_closed_without_replacing_it(self):
        self.put()
        self.complete(self.entry)
        restored = self.cold_restore()
        key_path = self.restored_root / 'deployment.key'
        original_key = key_path.read_bytes()
        for key in (None, Fernet.generate_key()):
            with self.subTest(missing=key is None):
                if key is None:
                    key_path.unlink()
                else:
                    key_path.write_bytes(key)
                    key_path.chmod(0o600)
                self.assertEqual(len(restored.managed_inventory()), 2)
                with self.assertRaises(DeploymentKeyError):
                    restored.managed_nodes()
                self.assertEqual(key_path.read_bytes() if key_path.exists() else None, key)
        key_path.write_bytes(original_key)
        key_path.chmod(0o600)
        self.assertEqual(restored.managed_nodes(), self.store.managed_nodes())

    def test_sqlite_backup_includes_committed_wal_state_and_excludes_uncommitted_changes(self):
        # This proves only the DB snapshot, not consistency with concurrently written YAML/key files.
        self.restored_root.mkdir()
        target = self.restored_root / self.store.path.name
        with self.store.connection() as writer:
            writer.execute('PRAGMA wal_autocheckpoint=0')
            writer.execute('SELECT COUNT(*) FROM agents').fetchone()
            self.put()
            self.complete(self.entry)
            self.assertGreater(Path(str(self.store.path) + '-wal').stat().st_size, 0)
            writer.execute("UPDATE agents SET name='uncommitted' WHERE id=?", (self.entry['agent_id'],))
            with closing(sqlite3.connect(str(self.store.path))) as source, closing(sqlite3.connect(str(target))) as destination:
                source.backup(destination)
            writer.rollback()
        shutil.copy2(self.root / 'deployment.key', self.restored_root / 'deployment.key')
        restored = ControlStore(target, clock=lambda: self.now)
        self.assertEqual(restored.managed_nodes(), self.store.managed_nodes())
        self.assertEqual(restored.get_agent(self.entry['agent_id'])['name'], 'VPS')
