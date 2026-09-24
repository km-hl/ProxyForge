import concurrent.futures
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from control_store import ControlStore, UnauthorizedAgent, CapacityExceeded
from job_store import JobConflict, JobNotFound
from agent.client import AgentConnectionError, CredentialRejected, JobRejected
from agent.jobs import process_job, runner_lock, validate_job
from agent.main import load_config, save_config
from test_agent_control import metadata


def capable(instance='a' * 32):
    return {**metadata(instance), 'job_protocol_version': 1}


OUTPUT = {'installed': False, 'running': False, 'version': '', 'status': 'not_installed'}
RESULT = {'status': 'success', 'output': OUTPUT, 'error': None}


class QueueTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'control.db'
        self.now = 1000
        self.store = ControlStore(self.path, clock=lambda: self.now)
        self.first = self.enroll()

    def enroll(self, info=None):
        registration = self.store.issue_registration('jobs')['registration_token']
        return self.store.register(registration, info or capable(), '')

    def create(self, enrolled=None, request=None):
        return self.store.create_job((enrolled or self.first)['agent_id'], request or uuid.uuid4().hex)

    def claim(self, enrolled=None):
        return self.store.claim_job((enrolled or self.first)['agent_token'], 'a' * 32)

    def report(self, job, result=None, enrolled=None):
        return self.store.report_job((enrolled or self.first)['agent_token'], job['id'], job['lease_token'], result)

    def test_idempotent_creation_and_atomic_single_claim(self):
        request = uuid.uuid4().hex
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            created = list(pool.map(lambda _: self.create(request=request), range(8)))
        self.assertEqual(len({j['id'] for j in created}), 1)
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            claimed = list(pool.map(lambda _: self.claim(), range(8)))
        self.assertEqual(sum(j is not None for j in claimed), 1)
        job = next(j for j in claimed if j)
        with self.store.connection() as db:
            self.assertNotIn(job['lease_token'], repr(tuple(db.execute('SELECT * FROM jobs').fetchone())))
        self.assertNotIn('lease_hash', json.dumps(self.store.list_jobs(self.first['agent_id'])))
        self.assertNotIn('lease_token', json.dumps(self.store.list_jobs(self.first['agent_id'])))

    def test_completion_ack_loss_replay_and_forged_changed_result(self):
        self.create()
        job = self.claim()
        with self.assertRaises(JobConflict):
            self.report(job, RESULT)  # Must acknowledge start first.
        self.assertEqual(self.report(job)['status'], 'running')
        self.report(job)
        self.assertEqual(self.report(job, RESULT)['status'], 'success')
        self.now += 3601
        self.assertEqual(self.report(job, RESULT)['status'], 'success')
        with self.assertRaises(JobConflict):
            self.report(job, {**RESULT, 'status': 'failed'})

    def test_expired_attempt_never_finishes_new_attempt_and_retry_cap(self):
        self.create()
        first = self.claim()
        self.report(first)
        self.now += 60
        with self.assertRaises(JobConflict):
            self.report(first, RESULT)
        second = self.claim()
        self.assertEqual(second['attempts'], 2)
        with self.assertRaises(JobConflict):
            self.report(first, RESULT)
        self.now += 60
        third = self.claim()
        self.assertEqual(third['attempts'], 3)
        self.now += 60
        self.assertIsNone(self.claim())
        self.assertEqual(self.store.list_jobs(self.first['agent_id'])[0]['error'], 'lease_expired')

    def test_agent_ownership_instance_and_revocation(self):
        self.create()
        job = self.claim()
        second = self.enroll()
        with self.assertRaises(JobNotFound):
            self.report(job, enrolled=second)
        with self.assertRaises(UnauthorizedAgent):
            self.store.claim_job(self.first['agent_token'], 'b' * 32)
        self.store.revoke(self.first['agent_id'])
        with self.assertRaises(UnauthorizedAgent):
            self.claim()
        with self.assertRaises(UnauthorizedAgent):
            self.report(job, RESULT)
        self.assertEqual(self.store.list_jobs(self.first['agent_id'])[0]['status'], 'cancelled')

    def test_cancel_pending_running_and_deadline(self):
        pending = self.create()
        self.store.cancel_job(self.first['agent_id'], pending['id'])
        self.store.cancel_job(self.first['agent_id'], pending['id'])
        self.create()
        job = self.claim()
        self.report(job)
        self.store.cancel_job(self.first['agent_id'], job['id'])
        with self.assertRaises(JobConflict):
            self.report(job, RESULT)
        self.create()
        self.now += 3600
        self.assertIsNone(self.claim())
        self.assertEqual(self.store.list_jobs(self.first['agent_id'])[0]['error'], 'deadline_exceeded')

    def test_reported_failure_is_terminal_and_revocation_rejects_replayed_success(self):
        self.create()
        job = self.claim()
        self.report(job)
        failed = {'status': 'failed', 'output': None, 'error': 'probe_failed'}
        self.assertEqual(self.report(job, failed), {'status': 'failed'})
        self.assertEqual(self.report(job, failed), {'status': 'failed'})
        self.assertIsNone(self.claim())
        self.create()
        second = self.claim()
        self.report(second)
        self.report(second, RESULT)
        self.store.revoke(self.first['agent_id'])
        with self.assertRaises(UnauthorizedAgent):
            self.report(second, RESULT)

    def test_old_or_future_agent_never_receives_jobs(self):
        for info in [metadata(), {**capable(), 'job_protocol_version': 2}, {**capable(), 'protocol_version': 2}]:
            agent = self.enroll(info)
            with self.assertRaises(JobConflict):
                self.create(agent)
            with self.assertRaises(JobConflict):
                self.claim(agent)
        self.create()
        self.store.heartbeat(self.first['agent_token'], metadata(), '')
        with self.assertRaises(JobConflict):
            self.claim()

    def test_backpressure_retention_and_delete_cascade(self):
        for _ in range(20):
            self.create()
        with self.assertRaises(CapacityExceeded):
            self.create()
        self.now += 8 * 86400
        # First reconcile timeouts, then move beyond retention.
        self.store.list_jobs(self.first['agent_id'])
        self.now += 8 * 86400
        self.create()
        self.assertEqual(len(self.store.list_jobs(self.first['agent_id'])), 1)
        self.store.revoke(self.first['agent_id'], remove=True)
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 0)

    def test_v1_migration_preserves_credentials_and_inventory(self):
        with self.store.connection() as db:
            db.execute('DROP TABLE jobs')
            db.execute('DELETE FROM schema_migrations WHERE version=2')
        reopened = ControlStore(self.path)
        reopened.heartbeat(self.first['agent_token'], capable(), '')
        self.assertEqual(reopened.get_agent(self.first['agent_id'])['name'], 'jobs')
        self.assertEqual(reopened.list_jobs(self.first['agent_id']), [])
        with reopened.connection() as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_migration_failure_rolls_back_schema(self):
        with self.store.connection() as db:
            db.execute('DROP TABLE jobs')
            db.execute('DELETE FROM schema_migrations WHERE version=2')
        def fail(db):
            db.execute('CREATE TABLE incomplete(x TEXT)')
            raise sqlite3.OperationalError('test interrupted migration')
        with patch('control_store.migrate_jobs', fail), self.assertRaises(sqlite3.OperationalError):
            ControlStore(self.path)
        with self.store.connection() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='incomplete'").fetchone())
            self.assertEqual(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 1)


class JobApiTest(unittest.TestCase):
    def setUp(self):
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN
        from fastapi.testclient import TestClient
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app)
        self.addCleanup(self.client.close)
        self.admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        token = self.client.post('/api/agents/registration-tokens', headers=self.admin,
                                 json={'name': 'jobs'}).json()['registration_token']
        self.agent = self.client.post('/api/agent/register', json={**capable(), 'registration_token': token}).json()
        self.auth = {'Authorization': 'Bearer ' + self.agent['agent_token']}
        self.url = '/api/agents/' + self.agent['agent_id'] + '/jobs'

    def create(self, **changes):
        return self.client.post(self.url, headers=self.admin, json={
            'request_id': uuid.uuid4().hex, 'type': 'singbox.status', 'payload': {}, **changes})

    def test_schema_and_admin_boundaries(self):
        for changes in [{'type': 'shell'}, {'payload': {'command': 'id'}}, {'deployment_revision': 'abc'},
                        {'request_id': 'invalid'}, {'path': '/etc/passwd'}]:
            response = self.create(**changes)
            self.assertEqual(response.status_code, 422, response.text)
            self.assertNotIn('passwd', response.text)
        self.assertEqual(self.client.post(self.url, headers=self.auth, json={}).status_code, 401)
        self.assertEqual(self.client.get(self.url, headers=self.auth).status_code, 401)
        self.assertEqual(self.client.post('/api/agent/jobs/claim', headers=self.admin,
                                          json={'instance_id': 'a' * 32}).status_code, 401)

    def test_start_result_schema_and_no_secret_in_lists(self):
        self.assertEqual(self.create().status_code, 200)
        job = self.client.post('/api/agent/jobs/claim', headers=self.auth,
                               json={'instance_id': 'a' * 32}).json()['job']
        path = '/api/agent/jobs/' + job['id']
        lease = {'lease_token': job['lease_token']}
        self.assertEqual(self.client.post(path + '/start', headers=self.auth, json=lease).status_code, 200)
        for result in [{'status': 'success'}, {'status': 'failed', 'error': 'arbitrary secret'},
                       {**RESULT, 'stderr': 'private'}, {**RESULT, 'output': {**OUTPUT, 'token': 'private'}}]:
            response = self.client.post(path + '/result', headers=self.auth, json={**lease, 'result': result})
            self.assertEqual(response.status_code, 422)
            self.assertNotIn('private', response.text)
        response = self.client.post(path + '/result', headers=self.auth, json={**lease, 'result': RESULT})
        self.assertEqual(response.json(), {'status': 'success'})
        jobs = self.client.get(self.url, headers=self.admin)
        self.assertNotIn(job['lease_token'], jobs.text)
        self.assertNotIn(self.agent['agent_token'], jobs.text)
        self.assertEqual(jobs.json()['jobs'][0]['result'], RESULT)

    def test_actual_runner_replays_local_result_after_upload_loss(self):
        self.create()
        config = {'controller': 'https://controller.example', 'agent_id': self.agent['agent_id'],
                  'instance_id': 'a' * 32, 'token': self.agent['agent_token']}
        path = Path(self.temp.name) / 'agent/config.json'
        save_config(path, config)
        test = self
        class Transport:
            lose = True
            def post(self, endpoint, payload, token):
                if endpoint.endswith('/result') and self.lose:
                    self.lose = False
                    raise AgentConnectionError('simulated lost upload')
                response = test.client.post(endpoint, headers={'Authorization': 'Bearer ' + token}, json=payload)
                test.assertEqual(response.status_code, 200, response.text)
                return response.json()
        transport = Transport()
        with patch('agent.jobs.singbox_status', return_value=OUTPUT) as probe:
            with self.assertRaises(AgentConnectionError):
                process_job(transport, config, path)
            store = self.app.control_store()
            with store.connection() as db:
                db.execute('UPDATE jobs SET lease_until=0')
            process_job(transport, config, path)
            self.assertEqual(probe.call_count, 1)
        self.assertEqual(self.client.get(self.url, headers=self.admin).json()['jobs'][0]['status'], 'success')
        journal = path.with_name('job-results.json').read_text()
        self.assertNotIn(config['token'], journal)
        self.assertNotIn('lease_token', journal)
        self.assertEqual(len(load_config(path.with_name('job-results.json'))['entries']), 1)


class RunnerTest(unittest.TestCase):
    def test_rejects_unknown_actions_revision_and_injected_payload(self):
        job = {'id': 'a' * 32, 'type': 'singbox.status', 'deployment_revision': None,
               'payload': {}, 'job_protocol_version': 1, 'lease_token': 'b' * 43}
        validate_job(job)
        for changes in [{'id': '../../evil'}, {'payload': {'command': 'reboot'}}, {'type': 'singbox.restart'},
                        {'deployment_revision': 'abc'}, {'job_protocol_version': 2}, {'lease_token': 'short'}]:
            with self.assertRaises(AgentConnectionError):
                validate_job({**job, **changes})

    def test_local_daemon_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            with runner_lock(path):
                with self.assertRaises(ValueError):
                    with runner_lock(path):
                        self.fail('second runner entered')
            with runner_lock(path):
                pass

    def test_revocation_propagates_and_cancellation_is_recoverable(self):
        config = {'controller': 'https://controller.example', 'agent_id': 'a' * 32,
                  'instance_id': 'b' * 32, 'token': 'local-test-token'}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            from unittest.mock import Mock
            client = Mock()
            client.post.side_effect = CredentialRejected()
            with self.assertRaises(CredentialRejected):
                process_job(client, config, path)
            client.post.side_effect = JobRejected()
            process_job(client, config, path)

    def test_corrupt_or_wrong_identity_journal_fails_closed(self):
        config = {'controller': 'https://controller.example', 'agent_id': 'a' * 32,
                  'instance_id': 'b' * 32, 'token': 'local-test-token'}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            save_config(path.with_name('job-results.json'), {'binding': {}, 'entries': []})
            from unittest.mock import Mock
            client = Mock()
            with self.assertRaises(ValueError):
                process_job(client, config, path)
            client.post.assert_not_called()
