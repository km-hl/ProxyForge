import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from agent.client import AgentConnectionError, CredentialRejected, JobRejected
from agent.job_lease import JobLease
from agent.jobs import process_job, validate_journal
from agent.runtime_spec import RELEASE, revision
from control_store import ControlStore
from job_store import JobConflict
from test_agent_jobs import capable, OUTPUT


class RuntimeQueueTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000
        self.store = ControlStore(Path(self.temp.name) / 'control.db', clock=lambda: self.now)
        self.metadata = {**capable(), 'runtime_protocol_version': 1}
        token = self.store.issue_registration('runtime')['registration_token']
        self.agent = self.store.register(token, self.metadata, '')

    def test_runtime_capability_revision_and_request_identity(self):
        request_id = 'c' * 32
        job = self.store.create_job(self.agent['agent_id'], request_id, 'singbox.install', {'version': RELEASE['version']})
        self.assertEqual(job['deployment_revision'], revision(job['id'], job['type'], job['payload']))
        with self.assertRaises(JobConflict):
            self.store.create_job(self.agent['agent_id'], request_id, 'singbox.stop', {})
        self.store.heartbeat(self.agent['agent_token'], capable(), '')
        with self.assertRaises(JobConflict):
            self.store.claim_job(self.agent['agent_token'], self.metadata['instance_id'])
        with self.assertRaises(JobConflict):
            self.store.create_job(self.agent['agent_id'], 'd' * 32, 'singbox.start', {})

    def test_renewal_retains_attempt_but_stale_and_cancelled_leases_fail(self):
        created = self.store.create_job(self.agent['agent_id'], 'c' * 32, 'singbox.restart', {})
        job = self.store.claim_job(self.agent['agent_token'], self.metadata['instance_id'])
        self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'])
        for _ in range(10):
            self.now += 30
            self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'], renew=True)
            self.assertIsNone(self.store.claim_job(self.agent['agent_token'], self.metadata['instance_id']))
        self.assertEqual(self.store.list_jobs(self.agent['agent_id'])[0]['attempts'], 1)
        self.store.cancel_job(self.agent['agent_id'], created['id'])
        with self.assertRaises(JobConflict):
            self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'], renew=True)

    def test_renewal_never_extends_deadline_or_revives_expiry(self):
        self.store.create_job(self.agent['agent_id'], 'c' * 32, 'singbox.stop', {})
        self.now += 3590
        job = self.store.claim_job(self.agent['agent_token'], self.metadata['instance_id'])
        self.assertEqual(self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'], renew=True)['lease_until'], 4600)
        self.now = 4600
        with self.assertRaises(JobConflict):
            self.store.report_job(self.agent['agent_token'], job['id'], job['lease_token'], renew=True)


class RuntimeLeaseTest(unittest.TestCase):
    def test_revocation_during_renewal_fences_helper_and_timeout_fails_closed(self):
        config = {'controller': 'https://controller.example', 'instance_id': 'a' * 32, 'token': 'test'}
        lease = JobLease(config, {'id': 'b' * 32, 'lease_token': 'c' * 43})
        lease.stop.wait = Mock(return_value=False)
        with patch('agent.job_lease.Client') as client:
            client.return_value.post.side_effect = CredentialRejected()
            lease.maintain()
        with self.assertRaises(CredentialRejected):
            lease.guard()
        lease.error = None
        lease.last_success = time.monotonic() - 41
        with self.assertRaises(AgentConnectionError):
            lease.guard()

    def test_runtime_result_journal_accepts_fixed_errors_and_rejects_revision_loss(self):
        binding = {'controller': 'https://controller.example', 'agent_id': 'a' * 32, 'instance_id': 'b' * 32}
        identity = {'id': 'c' * 32, 'type': 'singbox.install', 'deployment_revision': 'd' * 64}
        journal = {'binding': binding, 'entries': [{'identity': identity,
                   'result': {'status': 'failed', 'output': None, 'error': 'rollback_failed'}}]}
        validate_journal(journal, binding)
        identity['deployment_revision'] = None
        with self.assertRaises(ValueError):
            validate_journal(journal, binding)

    def test_cancelled_lease_closes_runtime_path_without_saving_success(self):
        config = {'controller': 'https://controller.example', 'agent_id': 'a' * 32,
                  'instance_id': 'b' * 32, 'token': 'test'}
        job = {'id': 'c' * 32, 'type': 'singbox.restart', 'payload': {}, 'job_protocol_version': 1,
               'lease_token': 'e' * 43, 'deployment_revision': revision('c' * 32, 'singbox.restart', {})}
        client = Mock()
        client.post.side_effect = [{'job': job}, {'status': 'running'}]
        with tempfile.TemporaryDirectory() as temp, patch('agent.jobs.JobLease') as lease, patch('agent.jobs.execute_runtime') as helper:
            lease.return_value.__enter__.return_value = Mock(side_effect=JobRejected())
            helper.return_value = {'status': 'success', 'output': OUTPUT, 'error': None}
            process_job(client, config, Path(temp) / 'config.json')
            self.assertFalse((Path(temp) / 'job-results.json').exists())
            self.assertEqual(client.post.call_count, 2)


class RuntimeApiTest(unittest.TestCase):
    def test_pinned_payload_and_renewal_authentication(self):
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN
        from fastapi.testclient import TestClient
        with tempfile.TemporaryDirectory() as temp:
            application = load_isolated_application(Path(temp))
            with TestClient(application.app) as client:
                admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
                info = {**capable(), 'runtime_protocol_version': 1}
                registration = client.post('/api/agents/registration-tokens', headers=admin, json={'name': 'runtime'}).json()
                agent = client.post('/api/agent/register', json={**info, 'registration_token': registration['registration_token']}).json()
                token = {'Authorization': 'Bearer ' + agent['agent_token']}
                url = '/api/agents/' + agent['agent_id'] + '/jobs'
                self.assertEqual(client.get('/api/agents/runtime/release', headers=admin).json()['version'], RELEASE['version'])
                for payload in [{'version': 'latest'}, {'version': RELEASE['version'], 'url': 'https://private.example'},
                                {'command': 'reboot'}, {}]:
                    response = client.post(url, headers=admin, json={'request_id': 'c' * 32, 'type': 'singbox.install', 'payload': payload})
                    self.assertEqual(response.status_code, 422)
                    self.assertNotIn('private', response.text)
                response = client.post(url, headers=admin, json={'request_id': 'c' * 32, 'type': 'singbox.install',
                                                               'payload': {'version': RELEASE['version']}})
                self.assertEqual(response.status_code, 200, response.text)
                claimed = client.post('/api/agent/jobs/claim', headers=token, json={'instance_id': info['instance_id']}).json()['job']
                renew = '/api/agent/jobs/' + claimed['id'] + '/renew'
                data = {'lease_token': claimed['lease_token']}
                self.assertEqual(client.post(renew, headers=admin, json=data).status_code, 401)
                self.assertEqual(client.post(renew, headers=token, json=data).status_code, 200)
                client.post('/api/agents/' + agent['agent_id'] + '/revoke', headers=admin)
                self.assertEqual(client.post(renew, headers=token, json=data).status_code, 401)
