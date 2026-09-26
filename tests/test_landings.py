import base64
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from agent.landing_spec import METHOD, runtime_config, validate_spec
from agent.runtime_spec import validate_runtime_job
from control_store import ControlStore
from deployment_store import new_landing_spec, migrate_deployments
from job_store import JobConflict
from test_agent_jobs import capable
from test_deployments import SETTINGS as REALITY, RESULT, deployment_job

SETTINGS = {'name': 'Landing', 'server': 'landing.example.com', 'listen_port': 8388, 'method': METHOD}


class LandingStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ControlStore(Path(self.temp.name) / 'control.db')
        self.info = {**capable(), 'runtime_protocol_version': 1, 'deployment_protocol_version': 1, 'landing_protocol_version': 1}
        self.agent = self.enroll()
        self.identifier, self.token = self.agent['agent_id'], self.agent['agent_token']

    def enroll(self, info=None):
        return self.store.register(self.store.issue_registration('VPS')['registration_token'], info or self.info, '')

    def put(self, expected=0, settings=None, remove=False, request_id=None):
        return self.store.put_deployment(self.identifier, request_id or uuid.uuid4().hex, expected, settings or SETTINGS, remove, 'ss2022')

    def claim(self):
        job = self.store.claim_job(self.token, self.info['instance_id'])
        self.store.report_job(self.token, job['id'], job['lease_token'])
        return job

    def complete(self, job, result=RESULT):
        self.store.report_job(self.token, job['id'], job['lease_token'], result)

    def test_secret_isolated_snapshot_stable_password_and_no_client_projection(self):
        request_id = uuid.uuid4().hex
        first = self.put(request_id=request_id)
        self.assertEqual(self.put(request_id=request_id), first)
        self.assertEqual((first['type'], first['protocol']), ('singbox_landing', 'ss2022'))
        job = self.claim()
        validate_runtime_job(job)
        secret = job['deployment']['password']
        self.assertEqual(len(base64.b64decode(secret)), 32)
        self.complete(job)
        self.assertEqual(self.store.managed_nodes(), [])
        self.assertEqual(self.store.managed_node_names(), [])
        for item in [first, self.store.list_jobs(self.identifier), self.store.list_agents()]:
            self.assertNotIn(secret, json.dumps(item))
        with self.store.connection() as db:
            self.assertNotIn(secret, '\n'.join(db.iterdump()))
        self.put(1, {**SETTINGS, 'listen_port': 9443})
        updated = self.claim()
        self.assertEqual(updated['deployment']['password'], secret)
        self.assertEqual(updated['deployment']['listen_port'], 9443)
        self.complete(updated)
        self.put(2, remove=True)
        removal = self.claim()
        self.assertEqual(removal['type'], 'landing.remove')
        self.assertEqual(removal['deployment'], {})
        self.complete(removal)
        self.put(3)
        self.assertEqual(self.claim()['deployment']['password'], secret)

    def test_dedicated_capability_protocol_ownership_and_generic_job_gate(self):
        self.store.heartbeat(self.token, {**self.info, 'landing_protocol_version': 0}, '')
        with self.assertRaises(JobConflict):
            self.put()
        self.store.heartbeat(self.token, self.info, '')
        self.put()
        with self.assertRaises(JobConflict):
            self.store.create_job(self.identifier, uuid.uuid4().hex, 'landing.remove', {})
        with self.assertRaises(JobConflict):
            self.store.put_deployment(self.identifier, uuid.uuid4().hex, 1, REALITY)
        job = self.claim()
        self.complete(job)
        self.store.heartbeat(self.token, {**self.info, 'landing_protocol_version': 0}, '')
        with self.assertRaises(JobConflict):
            self.put(1)

    def test_other_agent_cannot_claim_landing_and_reality_remains_unchanged(self):
        other = self.enroll({**self.info, 'instance_id': 'b' * 32})
        self.store.put_deployment(other['agent_id'], uuid.uuid4().hex, 0, REALITY)
        other_job = self.store.claim_job(other['agent_token'], 'b' * 32)
        self.store.report_job(other['agent_token'], other_job['id'], other_job['lease_token'])
        self.store.report_job(other['agent_token'], other_job['id'], other_job['lease_token'], RESULT)
        original = self.store.managed_nodes()
        self.put()
        self.assertIsNone(self.store.claim_job(other['agent_token'], 'b' * 32))
        self.complete(self.claim())
        self.assertEqual(self.store.managed_nodes(), original)
        with self.assertRaises(JobConflict):
            self.store.put_deployment(other['agent_id'], uuid.uuid4().hex, 1, SETTINGS, protocol='ss2022')

    def test_cancel_and_capability_loss_fence_claim_and_result(self):
        created = self.put()
        self.store.heartbeat(self.token, {**self.info, 'landing_protocol_version': 0}, '')
        with self.assertRaises(JobConflict):
            self.store.claim_job(self.token, self.info['instance_id'])
        self.store.heartbeat(self.token, self.info, '')
        job = self.claim()
        self.store.cancel_job(self.identifier, created['job_id'])
        with self.assertRaises(JobConflict):
            self.complete(job)

    def test_schema3_migration_preserves_existing_snapshot_and_rolls_back_failure(self):
        path = Path(self.temp.name) / 'v3.db'
        # Construct the actual previous schema without relying on a downgraded version number.
        with contextlib.closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY)')
            db.execute('CREATE TABLE agents(id TEXT PRIMARY KEY)')
            db.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY)')
            migrate_deployments(db)
            db.execute("INSERT INTO agents VALUES('agent')")
            db.execute("INSERT INTO deployments VALUES('id','agent',?,3,'ciphertext','job',1)", (json.dumps(REALITY),))
        def broken(db):
            db.execute("ALTER TABLE deployments ADD COLUMN protocol TEXT DEFAULT 'vless-reality'")
            raise sqlite3.OperationalError('interrupted')
        with patch('control_store.migrate_landings', broken), self.assertRaises(sqlite3.OperationalError):
            ControlStore(path)
        with contextlib.closing(sqlite3.connect(path)) as db, db:
            self.assertEqual(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 3)
            self.assertNotIn('protocol', [r[1] for r in db.execute('PRAGMA table_info(deployments)')])
        migrated = ControlStore(path)
        with migrated.connection() as db:
            row = db.execute('SELECT * FROM deployments').fetchone()
            self.assertEqual((row['protocol'], row['secret_spec'], row['revision']), ('vless-reality', 'ciphertext', 3))


class LandingProtocolTest(unittest.TestCase):
    def test_strict_key_and_snapshot_binding(self):
        spec = new_landing_spec(SETTINGS)
        validate_spec('landing.apply', spec)
        job = deployment_job(spec, 'landing.apply')
        validate_runtime_job(job)
        for changed in [{**spec, 'password': 'bad'}, {**spec, 'method': 'aes-256-gcm'},
                        {**spec, 'password': base64.b64encode(bytes(16)).decode()}, {**spec, 'path': '/etc/passwd'}]:
            with self.assertRaises(ValueError):
                validate_spec('landing.apply', changed)
        job['deployment']['listen_port'] += 1
        with self.assertRaises(ValueError):
            validate_runtime_job(job)

    def test_agent_durable_replay_excludes_password(self):
        from agent.jobs import process_job
        from agent.client import AgentConnectionError
        spec = new_landing_spec(SETTINGS)
        job = {**deployment_job(spec, 'landing.apply'), 'job_protocol_version': 1, 'lease_token': 'x' * 43}
        config = {'controller': 'https://controller.example', 'agent_id': 'a' * 32, 'instance_id': 'b' * 32, 'token': 'test'}
        client = Mock()
        with tempfile.TemporaryDirectory() as temp, patch('agent.jobs.JobLease') as lease, patch('agent.jobs.execute_runtime', return_value=RESULT) as helper:
            lease.return_value.__enter__.return_value = lambda: None
            client.post.side_effect = [{'job': job}, {}, AgentConnectionError('lost acknowledgment')]
            path = Path(temp) / 'config.json'
            with self.assertRaises(AgentConnectionError):
                process_job(client, config, path)
            self.assertNotIn(spec['password'], path.with_name('job-results.json').read_text())
            client.post.side_effect = [{'job': {**job, 'lease_token': 'y' * 43}}, {}, {}]
            process_job(client, config, path)
            self.assertEqual(helper.call_count, 1)

    def test_management_api_does_not_accept_secret_or_agent_token(self):
        from fastapi.testclient import TestClient
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN
        with tempfile.TemporaryDirectory() as temp:
            app = load_isolated_application(Path(temp))
            store = app.control_store()
            info = {**capable(), 'runtime_protocol_version': 1, 'landing_protocol_version': 1}
            agent = store.register(store.issue_registration('landing')['registration_token'], info, '')
            url = '/api/agents/' + agent['agent_id'] + '/deployment'
            data = {'protocol': 'ss2022', 'expected_revision': 0, 'settings': SETTINGS, 'request_id': uuid.uuid4().hex}
            admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            with TestClient(app.app) as client:
                self.assertEqual(client.put(url, json=data).status_code, 401)
                self.assertEqual(client.put(url, json=data, headers={'Authorization': 'Bearer ' + agent['agent_token']}).status_code, 401)
                invalid = client.put(url, json={**data, 'settings': {**SETTINGS, 'password': 'secret-canary'}}, headers=admin)
                self.assertEqual(invalid.status_code, 422)
                self.assertNotIn('secret-canary', invalid.text)
                response = client.put(url, json=data, headers=admin)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()['protocol'], 'ss2022')


@unittest.skipUnless(os.name == 'posix', 'Linux runtime')
class LandingEngineTest(unittest.TestCase):
    def test_initial_install_recovery_failed_update_and_removal(self):
        from agent.runtime_engine import RuntimeEngine, EMPTY_CONFIG
        from test_runtime_engine import FakeBackend
        with tempfile.TemporaryDirectory() as temp:
            backend = FakeBackend()
            backend.check = lambda path: json.loads((path / 'config.json').read_text())
            def download(path, arch, guard):
                (path / 'sing-box').write_bytes(b'test')
            engine = RuntimeEngine(temp, backend, 'amd64', download)
            spec = new_landing_spec(SETTINGS)
            job = deployment_job(spec, 'landing.apply')
            with patch.object(engine, 'finish', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                engine.apply(job)
            engine.recover()
            count = backend.activation_count
            self.assertTrue(engine.apply(job)['output']['running'])
            self.assertEqual(backend.activation_count, count)
            previous = engine.pointer('current')
            self.assertEqual(json.loads((Path(temp) / previous / 'config.json').read_text()), runtime_config(spec))
            backend.fail_once = True
            with self.assertRaises(ValueError):
                engine.apply(deployment_job({**spec, 'listen_port': 9443}, 'landing.apply', 2))
            self.assertEqual(engine.pointer('current'), previous)
            engine.apply(deployment_job({}, 'landing.remove', 3))
            self.assertEqual(json.loads((Path(temp) / engine.pointer('current') / 'config.json').read_text()), EMPTY_CONFIG)
