import copy
import concurrent.futures
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from agent.deployment_spec import client_node, runtime_config, spec_hash, validate_spec
from agent.runtime_spec import revision, validate_runtime_job
from control_store import ControlStore
from deployment_store import DeploymentKeyError, new_spec
from job_store import JobConflict
from test_agent_jobs import capable

SETTINGS = {'name': 'Direct node', 'server': 'vps.example.com', 'server_name': 'www.example.com', 'listen_port': 443}
RESULT = {'status': 'success', 'output': {'installed': True, 'running': True, 'version': '1.14.2', 'status': 'running'}, 'error': None}


def deployment_job(spec, action='deployment.apply', number=1):
    payload = {'deployment_id': 'f' * 32, 'revision': number, 'spec_hash': spec_hash(spec)}
    identifier = uuid.uuid4().hex
    return {'id': identifier, 'type': action, 'payload': payload, 'deployment': spec,
            'deployment_revision': revision(identifier, action, payload)}


class DeploymentStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = 1000
        self.store = ControlStore(self.root / 'control.db', clock=lambda: self.now)
        self.info = {**capable(), 'runtime_protocol_version': 1, 'deployment_protocol_version': 1}
        self.agent = self.store.register(self.store.issue_registration('VPS')['registration_token'], self.info, '')
        self.identifier, self.token = self.agent['agent_id'], self.agent['agent_token']

    def put(self, expected=0, settings=None, remove=False, request_id=None):
        return self.store.put_deployment(self.identifier, request_id or uuid.uuid4().hex, expected, settings or SETTINGS, remove)

    def claim(self):
        job = self.store.claim_job(self.token, self.info['instance_id'])
        self.store.report_job(self.token, job['id'], job['lease_token'])
        return job

    def complete(self, job, result=RESULT):
        self.store.report_job(self.token, job['id'], job['lease_token'], result)

    def test_success_projection_encryption_and_admin_redaction(self):
        created = self.put()
        self.assertEqual(self.store.managed_nodes(), [])
        job = self.claim()
        validate_runtime_job(job)
        secret = job['deployment']['private_key']
        self.assertEqual(runtime_config(job['deployment'])['inbounds'][0]['listen_port'], 443)
        for data in [created, self.store.list_jobs(self.identifier), self.store.list_agents()]:
            self.assertNotIn(secret, json.dumps(data))
            self.assertNotIn('secret_payload', json.dumps(data))
        with self.store.connection() as db:
            raw = '\n'.join(db.iterdump())
            self.assertNotIn(secret, raw)
            self.assertNotIn(job['deployment']['uuid'], raw)
        self.complete(job)
        self.complete(job)  # Lost acknowledgment replay.
        node = self.store.managed_nodes()[0]
        self.assertNotIn(secret, json.dumps(node))
        self.assertEqual(node['uuid'], job['deployment']['uuid'])
        self.assertEqual(node['_managed_by']['deployment_id'], created['id'])
        if os.name == 'posix':
            self.assertEqual((self.root / 'deployment.key').stat().st_mode & 0o777, 0o600)

    def test_conflicts_retries_revision_fencing_and_remove(self):
        request = uuid.uuid4().hex
        first = self.put(request_id=request)
        self.assertEqual(self.put(request_id=request), first)
        with self.assertRaises(JobConflict):
            self.put(1)
        job = self.claim()
        self.complete(job)
        with self.assertRaises(JobConflict):
            self.put(0)
        with self.assertRaises(JobConflict):
            self.store.create_job(self.identifier, uuid.uuid4().hex, 'singbox.rollback')
        edited = {**SETTINGS, 'listen_port': 8443}
        self.put(1, edited)
        self.assertEqual(self.store.managed_nodes(), [])
        next_job = self.claim()
        self.assertEqual(next_job['deployment']['uuid'], job['deployment']['uuid'])
        self.assertEqual(next_job['deployment']['private_key'], job['deployment']['private_key'])
        self.complete(next_job)
        self.assertEqual(self.store.managed_nodes()[0]['port'], 8443)
        self.put(2, edited, remove=True)
        removal = self.claim()
        self.assertEqual(removal['deployment'], {})
        self.complete(removal)
        self.assertEqual(self.store.managed_nodes(), [])
        self.put(3, edited)  # Re-enable with the same credentials.
        self.assertEqual(self.claim()['deployment']['uuid'], job['deployment']['uuid'])

    def test_old_capability_other_agent_cancel_and_missing_key(self):
        self.store.heartbeat(self.token, {**self.info, 'deployment_protocol_version': 0}, '')
        with self.assertRaises(JobConflict):
            self.put()
        self.store.heartbeat(self.token, self.info, '')
        created = self.put()
        other = self.store.register(self.store.issue_registration('other')['registration_token'], {**self.info, 'instance_id': 'b' * 32}, '')
        self.assertIsNone(self.store.claim_job(other['agent_token'], 'b' * 32))
        job = self.claim()
        self.store.cancel_job(self.identifier, created['job_id'])
        with self.assertRaises(JobConflict):
            self.complete(job)
        self.assertEqual(self.store.managed_nodes(), [])
        (self.root / 'deployment.key').unlink()
        with self.assertRaises(DeploymentKeyError):
            self.put(1)
        self.assertFalse((self.root / 'deployment.key').exists())

    def test_failure_does_not_publish_and_expired_jobs_keep_current_deployment(self):
        created = self.put()
        job = self.claim()
        with self.assertRaises(JobConflict):
            self.complete(job, {**RESULT, 'output': {**RESULT['output'], 'running': False}})
        self.complete(job, {'status': 'failed', 'output': None, 'error': 'runtime_failed'})
        self.assertEqual(self.store.managed_nodes(), [])
        self.now += 8 * 86400
        self.store.create_job(self.identifier, uuid.uuid4().hex)
        self.assertEqual(self.store.get_deployment(self.identifier)['job_id'], created['job_id'])

    def test_pending_mutation_prevents_new_owner_and_revoke_withdraws_node(self):
        job = self.store.create_job(self.identifier, uuid.uuid4().hex, 'singbox.restart')
        with self.assertRaises(JobConflict):
            self.put()
        self.store.cancel_job(self.identifier, job['id'])
        self.put()
        self.complete(self.claim())
        self.assertEqual(len(self.store.managed_nodes()), 1)
        self.store.revoke(self.identifier)
        self.assertEqual(self.store.managed_nodes(), [])

    def test_concurrent_create_has_one_owner_and_one_job(self):
        def attempt(_):
            try:
                return self.put()
            except JobConflict:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(attempt, range(4)))
        self.assertEqual(sum(item is not None for item in results), 1)
        self.assertEqual(len(self.store.list_jobs(self.identifier)), 1)
        validate_runtime_job(self.claim())

    def test_v2_migration_and_atomic_failure(self):
        path = self.root / 'v2.db'
        with patch('control_store.migrate_deployments'):
            old = ControlStore(path)
        registered = old.register(old.issue_registration('old')['registration_token'], capable(), '')
        def broken(db):
            db.execute('ALTER TABLE jobs ADD COLUMN secret_payload TEXT')
            raise sqlite3.OperationalError('interrupted')
        with patch('control_store.migrate_deployments', broken), self.assertRaises(sqlite3.OperationalError):
            ControlStore(path)
        with old.connection() as db:
            self.assertEqual(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 2)
            self.assertNotIn('secret_payload', [r['name'] for r in db.execute('PRAGMA table_info(jobs)')])
        upgraded = ControlStore(path)
        self.assertEqual(upgraded.get_agent(registered['agent_id'])['name'], 'old')
        self.assertIsNone(upgraded.get_deployment(registered['agent_id']))


class DeploymentSpecTest(unittest.TestCase):
    def test_agent_replays_result_without_persisting_secrets(self):
        from agent.jobs import process_job
        from agent.client import AgentConnectionError
        spec = new_spec(SETTINGS)
        job = {**deployment_job(spec), 'job_protocol_version': 1, 'lease_token': 'x' * 43}
        config = {'controller': 'https://controller.example', 'agent_id': 'a' * 32, 'instance_id': 'b' * 32, 'token': 'test'}
        client = Mock()
        with tempfile.TemporaryDirectory() as temp, patch('agent.jobs.JobLease') as lease, patch('agent.jobs.execute_runtime', return_value=RESULT) as helper:
            lease.return_value.__enter__.return_value = lambda: None
            path = Path(temp) / 'config.json'
            client.post.side_effect = [{'job': job}, {}, AgentConnectionError('lost acknowledgment')]
            with self.assertRaises(AgentConnectionError):
                process_job(client, config, path)
            journal = path.with_name('job-results.json').read_text()
            for secret in (spec['private_key'], spec['uuid'], job['lease_token']):
                self.assertNotIn(secret, journal)
            client.post.side_effect = [{'job': {**job, 'lease_token': 'y' * 43}}, {}, {}]
            process_job(client, config, path)
            self.assertEqual(helper.call_count, 1)

    def test_key_pair_and_strict_reference_and_configuration(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        import base64
        spec = new_spec(SETTINGS)
        validate_spec('deployment.apply', spec)
        key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(spec['private_key'] + '='))
        self.assertEqual(base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('='), spec['public_key'])
        job = deployment_job(spec)
        validate_runtime_job(job)
        job['deployment']['listen_port'] += 1
        with self.assertRaises(ValueError):
            validate_runtime_job(job)
        for field, value in [('command', 'reboot'), ('server_name', 'https://example.com/path'), ('listen_port', True),
                             ('private_key', 'bad'), ('short_id', 'x'), ('uuid', 'not-a-uuid')]:
            changed = {**spec, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_spec('deployment.apply', changed)


class DeploymentApiTest(unittest.TestCase):
    def test_unpublished_deployment_keeps_template_references_and_blocks_output(self):
        import yaml
        from fastapi.testclient import TestClient
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN
        with tempfile.TemporaryDirectory() as temp:
            app = load_isolated_application(Path(temp))
            store = app.control_store()
            info = {**capable(), 'runtime_protocol_version': 1, 'deployment_protocol_version': 1}
            agent = store.register(store.issue_registration('VPS')['registration_token'], info, '')
            def apply(expected):
                return store.put_deployment(agent['agent_id'], uuid.uuid4().hex, expected, SETTINGS)
            def complete(result):
                job = store.claim_job(agent['agent_token'], info['instance_id'])
                store.report_job(agent['agent_token'], job['id'], job['lease_token'])
                store.report_job(agent['agent_token'], job['id'], job['lease_token'], result)
            apply(0)
            complete(RESULT)
            name = store.managed_nodes()[0]['name']
            template = {'proxy-groups': [
                {'name': 'Selected', 'type': 'select', 'proxies': [name], 'default': name},
                {'name': 'Pool', 'type': 'select', 'use': ['_custom_nodes_']}],
                'rules': ['DOMAIN,example.com,' + name, 'MATCH,Selected']}
            content = yaml.safe_dump(template, allow_unicode=True, sort_keys=False)
            app.save_template_content(content)
            admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            with TestClient(app.app) as client, patch.object(app, 'get_airport_proxies_cached', return_value=[]):
                before = app.template_store().snapshot()
                apply(1)
                for state in ('pending', 'failed'):
                    with self.subTest(state=state):
                        response = client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN})
                        self.assertEqual(app.template_store().snapshot(), before)
                        self.assertEqual(response.status_code, 200, response.text)
                        output = yaml.safe_load(response.text)
                        self.assertEqual(output['proxy-groups'][0]['proxies'], ['REJECT'])
                        self.assertEqual(output['proxy-groups'][1]['proxies'], ['REJECT'])
                        self.assertEqual(output['rules'][0], 'DOMAIN,example.com,REJECT')
                        validation = client.post('/api/template/validate', headers=admin, json={'content': content})
                        self.assertEqual(validation.json()['errors'], [])
                        app.validate_saved_template(content, app.load_custom_nodes(), [])
                    if state == 'pending':
                        complete({'status': 'failed', 'output': None, 'error': 'runtime_failed'})
                apply(2)
                complete(RESULT)
                restored = client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN})
                self.assertEqual(restored.status_code, 200, restored.text)
                self.assertEqual(yaml.safe_load(restored.text)['proxy-groups'][0]['proxies'], [name])
                self.assertEqual(app.template_store().snapshot(), before)

    def test_auth_validation_and_automatic_readonly_nodes(self):
        from fastapi.testclient import TestClient
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN
        with tempfile.TemporaryDirectory() as temp:
            app = load_isolated_application(Path(temp))
            store = app.control_store()
            info = {**capable(), 'runtime_protocol_version': 1, 'deployment_protocol_version': 1}
            agent = store.register(store.issue_registration('VPS')['registration_token'], info, '')
            url = '/api/agents/' + agent['agent_id'] + '/deployment'
            admin = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            data = {'request_id': uuid.uuid4().hex, 'expected_revision': 0, 'settings': SETTINGS}
            with TestClient(app.app) as client:
                self.assertEqual(client.put(url, json=data).status_code, 401)
                self.assertEqual(client.put(url, json=data, headers={'Authorization': 'Bearer ' + agent['agent_token']}).status_code, 401)
                invalid = client.put(url, json={**data, 'private_key': 'secret-marker'}, headers=admin)
                self.assertEqual(invalid.status_code, 422)
                self.assertNotIn('secret-marker', invalid.text)
                self.assertEqual(client.put(url, json=data, headers=admin).status_code, 200)
                self.assertEqual(client.put(url, json=data, headers=admin).status_code, 200)
                job = store.claim_job(agent['agent_token'], info['instance_id'])
                store.report_job(agent['agent_token'], job['id'], job['lease_token'])
                store.report_job(agent['agent_token'], job['id'], job['lease_token'], RESULT)
                node = client.get('/api/nodes', headers=admin).json()['nodes'][0]
                self.assertEqual(app.validate_proxy_nodes([node]), [])
                self.assertNotIn('_managed_by', app.strip_internal_proxy_fields(node))
                self.assertEqual(client.post('/api/nodes', headers=admin, json={'nodes': [node]}).status_code, 200)
                self.assertEqual(app.load_manual_nodes(), [])
                changed = copy.deepcopy(node)
                changed['port'] += 1
                self.assertEqual(client.post('/api/nodes', headers=admin, json={'nodes': [changed]}).status_code, 409)
                changed.pop('_managed_by')
                self.assertEqual(client.post('/api/nodes', headers=admin, json={'nodes': [changed]}).status_code, 409)
                self.assertEqual(client.post('/api/nodes', headers=admin, json={'nodes': []}).status_code, 200)
                self.assertEqual(len(client.get('/api/nodes', headers=admin).json()['nodes']), 1)


@unittest.skipUnless(os.name == 'posix', 'Linux runtime')
class DeploymentEngineTest(unittest.TestCase):
    def test_apply_rollback_replay_recovery_and_remove(self):
        from agent.runtime_engine import RuntimeEngine, EMPTY_CONFIG
        from test_runtime_engine import FakeBackend
        with tempfile.TemporaryDirectory() as temp:
            backend = FakeBackend()
            backend.check = lambda path: json.loads((path / 'config.json').read_text())
            def download(path, arch, guard):
                (path / 'sing-box').write_bytes(b'test')
            engine = RuntimeEngine(temp, backend, 'amd64', download)
            spec = new_spec(SETTINGS)
            apply = deployment_job(spec)
            with patch.object(engine, 'finish', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                engine.apply(apply)
            engine.recover()
            count = backend.activation_count
            engine.apply(apply)
            self.assertEqual(backend.activation_count, count)
            previous = engine.pointer('current')
            backend.fail_once = True
            with self.assertRaises(ValueError):
                engine.apply(deployment_job({**spec, 'listen_port': 8443}, number=2))
            self.assertEqual(engine.pointer('current'), previous)
            config = json.loads((Path(temp) / previous / 'config.json').read_text())
            self.assertEqual(config['inbounds'][0]['listen_port'], 443)
            engine.apply(deployment_job({}, 'deployment.remove', 3))
            config = json.loads((Path(temp) / engine.pointer('current') / 'config.json').read_text())
            self.assertEqual(config, EMPTY_CONFIG)
