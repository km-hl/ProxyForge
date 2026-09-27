import concurrent.futures
import copy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from agent.chain_spec import runtime_config, validate_spec
from agent.deployment_spec import runtime_config as direct_config
from agent.runtime_spec import validate_runtime_job
from proxyforge.control.control_store import ControlStore
from proxyforge.control.job_store import JobConflict
from test_agent_jobs import capable
from test_deployments import SETTINGS as DIRECT, RESULT, deployment_job
from test_landings import SETTINGS as LANDING

SETTINGS = {'name': 'Via landing', 'listen_port': 8443}


class ChainStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ControlStore(Path(self.temp.name) / 'control.db')
        self.info = {**capable(), 'runtime_protocol_version': 1, 'deployment_protocol_version': 1,
                     'landing_protocol_version': 1, 'chain_protocol_version': 1}
        self.entry = self.enroll()
        self.landing = self.enroll()
        self.store.put_deployment(self.entry['agent_id'], uuid.uuid4().hex, 0, DIRECT)
        self.direct_job = self.complete(self.entry)
        self.store.put_deployment(self.landing['agent_id'], uuid.uuid4().hex, 0, LANDING, protocol='ss2022')
        self.landing_job = self.complete(self.landing)

    def enroll(self):
        return self.store.register(self.store.issue_registration('VPS')['registration_token'], self.info, '')

    def complete(self, agent, result=RESULT):
        job = self.store.claim_job(agent['agent_token'], self.info['instance_id'])
        self.store.report_job(agent['agent_token'], job['id'], job['lease_token'])
        self.store.report_job(agent['agent_token'], job['id'], job['lease_token'], result)
        return job

    def put(self, revision=0, remove=False, settings=None, request_id=None):
        return self.store.put_chain(self.entry['agent_id'], request_id or uuid.uuid4().hex, revision,
                                    self.landing['agent_id'], settings or SETTINGS, remove)

    def test_direct_and_chain_coexist_secrets_redacted_and_removal_preserves_direct(self):
        original = self.store.managed_nodes()
        created = self.put()
        self.assertEqual(self.store.managed_nodes(), original)
        self.assertEqual(len(self.store.managed_node_names()), 2)
        job = self.complete(self.entry)
        validate_runtime_job(job)
        spec = job['deployment']
        self.assertEqual(spec['direct'], self.direct_job['deployment'])
        self.assertEqual(spec['chain']['landing'], self.landing_job['deployment'])
        self.assertNotEqual(spec['direct']['uuid'], spec['chain']['entry']['uuid'])
        config = runtime_config(spec)
        self.assertEqual(config['inbounds'][0], direct_config(spec['direct'])['inbounds'][0])
        self.assertEqual(config['route']['rules'][0]['outbound'], 'landing')
        nodes = self.store.managed_nodes()
        self.assertEqual(nodes[0], original[0])
        self.assertEqual(nodes[1]['port'], 8443)
        for public in [created, self.store.get_chain(self.entry['agent_id']), self.store.list_jobs(self.entry['agent_id']), nodes]:
            for secret in [spec['chain']['landing']['password'], spec['direct']['private_key'], spec['chain']['entry']['private_key']]:
                self.assertNotIn(secret, json.dumps(public))
        with self.store.connection() as db:
            raw = '\n'.join(db.iterdump())
            self.assertNotIn(spec['chain']['landing']['password'], raw)
        self.put(1, remove=True)
        self.assertEqual(self.store.managed_nodes(), original)
        removed = self.complete(self.entry)
        self.assertEqual(runtime_config(removed['deployment']), direct_config(spec['direct']))
        self.put(2)
        again = self.complete(self.entry)
        self.assertEqual(again['deployment'], spec)

    def test_dependency_locks_survive_cancel_failure_and_only_successful_remove_releases(self):
        created = self.put()
        def blocked():
            for agent, settings, protocol in [(self.entry, DIRECT, 'vless-reality'), (self.landing, LANDING, 'ss2022')]:
                with self.assertRaises(JobConflict):
                    self.store.put_deployment(agent['agent_id'], uuid.uuid4().hex, 1, settings, True, protocol)
                with self.assertRaises(JobConflict):
                    self.store.revoke(agent['agent_id'], remove=True)
        blocked()
        self.store.cancel_job(self.entry['agent_id'], created['job_id'])
        blocked()
        self.put(1, remove=True)
        self.complete(self.entry, {'status': 'failed', 'output': None, 'error': 'runtime_failed'})
        blocked()
        self.put(2, remove=True)
        self.complete(self.entry)
        self.store.put_deployment(self.landing['agent_id'], uuid.uuid4().hex, 1, LANDING, True, 'ss2022')
        self.store.put_deployment(self.entry['agent_id'], uuid.uuid4().hex, 1, DIRECT)

    def test_capability_readiness_isolation_and_revocation_recovery(self):
        self.store.heartbeat(self.entry['agent_token'], {**self.info, 'chain_protocol_version': 0}, '')
        with self.assertRaises(JobConflict):
            self.put()
        self.store.heartbeat(self.entry['agent_token'], self.info, '')
        created = self.put()
        self.assertIsNone(self.store.claim_job(self.landing['agent_token'], self.info['instance_id']))
        self.complete(self.entry)
        self.store.revoke(self.landing['agent_id'])  # Revocation must always remain available.
        self.assertEqual(len(self.store.managed_nodes()), 1)
        with self.assertRaises(JobConflict):
            self.put(1)
        self.put(1, remove=True)
        self.complete(self.entry)
        self.store.revoke(self.landing['agent_id'], remove=True)
        self.assertIsNone(self.store.get_chain(self.entry['agent_id']))
        self.assertNotIn(created['id'], json.dumps(self.store.managed_node_names()))

    def test_idempotency_cas_port_conflict_and_immutable_binding(self):
        with self.assertRaises(JobConflict):
            self.put(settings={**SETTINGS, 'listen_port': DIRECT['listen_port']})
        request = uuid.uuid4().hex
        first = self.put(request_id=request)
        self.assertEqual(self.put(request_id=request), first)
        self.complete(self.entry)
        with self.assertRaises(JobConflict):
            self.put()
        with self.assertRaises(JobConflict):
            self.store.put_chain(self.entry['agent_id'], uuid.uuid4().hex, 1, self.entry['agent_id'], SETTINGS)
        with self.assertRaises(JobConflict):
            self.put(1, settings={**SETTINGS, 'name': 'renamed'})
        self.put(1, settings={**SETTINGS, 'listen_port': 9443})
        self.assertEqual(len(self.store.managed_nodes()), 1)
        self.assertEqual(len(self.store.managed_node_names()), 2)

    def test_concurrent_landing_mutation_or_chain_creation_has_only_one_winner(self):
        def mutate(chain):
            try:
                if chain:
                    self.put()
                else:
                    self.store.put_deployment(self.landing['agent_id'], uuid.uuid4().hex, 1, LANDING, True, 'ss2022')
                return True
            except JobConflict:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(mutate, [True, False])), 1)

    def test_current_chain_job_survives_retention(self):
        self.put()
        self.complete(self.entry)
        self.store.clock = lambda: 9999999999
        self.store.create_job(self.entry['agent_id'], uuid.uuid4().hex)
        self.assertEqual(self.store.get_chain(self.entry['agent_id'])['status'], 'success')

    def test_protocol_rejects_cross_port_and_unknown_fields(self):
        self.put()
        spec = self.complete(self.entry)['deployment']
        for mutate in [lambda s: s.update(command='bad'),
                       lambda s: s['chain']['entry'].update(listen_port=DIRECT['listen_port']),
                       lambda s: s['chain']['landing'].update(password='bad')]:
            changed = copy.deepcopy(spec)
            mutate(changed)
            with self.assertRaises(ValueError):
                validate_spec('chain.apply', changed)
        with self.assertRaises(ValueError):
            validate_spec('chain.remove', spec)

    def test_schema4_upgrade_and_atomic_failure_preserve_ciphertext(self):
        with self.store.connection() as db:
            before = [tuple(row) for row in db.execute('SELECT * FROM deployments')]
            db.execute('DROP TABLE chains')
            db.execute('DELETE FROM schema_migrations WHERE version=5')
        def fail(db):
            db.execute('CREATE TABLE chains(x TEXT)')
            raise sqlite3.OperationalError('interrupted')
        with patch('proxyforge.control.control_store.migrate_chains', fail), self.assertRaises(sqlite3.OperationalError):
            ControlStore(self.store.path)
        reopened = ControlStore(self.store.path)
        with reopened.connection() as db:
            self.assertEqual(before, [tuple(row) for row in db.execute('SELECT * FROM deployments')])
            self.assertEqual(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 5)

    def test_api_authentication_conflicts_candidates_and_secret_rejection(self):
        from fastapi.testclient import TestClient
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN
        with tempfile.TemporaryDirectory() as temp:
            app = load_isolated_application(Path(temp))
            app.control_store()  # Preserve the production on-disk DB existence gate.
            app.ControlStore = lambda path: self.store
            headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
            url = '/api/agents/' + self.entry['agent_id'] + '/chain'
            data = {'request_id': uuid.uuid4().hex, 'expected_revision': 0,
                    'landing_agent_id': self.landing['agent_id'], 'settings': SETTINGS}
            with TestClient(app.app) as client:
                self.assertEqual(client.put(url, json=data).status_code, 401)
                self.assertEqual(client.get(url, headers={'Authorization': 'Bearer ' + self.entry['agent_token']}).status_code, 401)
                response = client.get('/api/agents/deployments/landings', headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['landings'][0]['agent_id'], self.landing['agent_id'])
                bad = client.put(url, headers=headers, json={**data, 'settings': {**SETTINGS, 'password': 'secret-canary'}})
                self.assertEqual(bad.status_code, 422)
                self.assertNotIn('secret-canary', bad.text)
                conflict = client.put(url, headers=headers, json={**data, 'settings': {**SETTINGS, 'listen_port': DIRECT['listen_port']}})
                self.assertEqual(conflict.status_code, 409)
                created = client.put(url, headers=headers, json=data)
                self.assertEqual(created.status_code, 200, created.text)
                self.assertEqual(client.put(url, headers=headers, json=data).json(), created.json())


    def test_subscription_failure_blocks_chain_keeps_direct_and_preserves_template(self):
        import yaml
        from fastapi.testclient import TestClient
        from test_api_integration import load_isolated_application, TEST_SUBSCRIPTION_TOKEN
        self.put()
        spec = self.complete(self.entry)['deployment']
        direct, chain = self.store.managed_nodes()
        with tempfile.TemporaryDirectory() as temp:
            app = load_isolated_application(Path(temp))
            app.control_store()  # Match the DB existence gate before replacing its provider.
            app.ControlStore = lambda path: self.store
            template = {'proxy-groups': [{'name': 'Via', 'type': 'select', 'proxies': [chain['name']]}],
                        'rules': ['DOMAIN,example.com,' + chain['name'], 'MATCH,Via']}
            app.save_template_content(yaml.safe_dump(template, allow_unicode=True, sort_keys=False))
            before = app.template_store().snapshot()
            self.put(1)
            with TestClient(app.app) as client, patch.object(app, 'get_airport_proxies_cached', return_value=[]):
                for status in ('pending', 'failed'):
                    response = client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN})
                    self.assertEqual(response.status_code, 200, response.text)
                    config = yaml.safe_load(response.text)
                    self.assertEqual(config['proxy-groups'][0]['proxies'], ['REJECT'])
                    self.assertEqual(config['rules'][0], 'DOMAIN,example.com,REJECT')
                    self.assertIn(direct['name'], [node['name'] for node in config['proxies']])
                    self.assertEqual(app.template_store().snapshot(), before)
                    self.assertNotIn(spec['chain']['landing']['password'], response.text)
                    if status == 'pending':
                        self.complete(self.entry, {'status': 'failed', 'output': None, 'error': 'runtime_failed'})
                self.put(2)
                self.complete(self.entry)
                response = client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN})
                self.assertEqual(yaml.safe_load(response.text)['proxy-groups'][0]['proxies'], [chain['name']])
                self.assertEqual(app.template_store().snapshot(), before)


@unittest.skipUnless(os.name == 'posix', 'Linux runtime')
class ChainEngineTest(unittest.TestCase):
    def test_multi_inbound_rollback_recovery_replay_and_removal(self):
        from agent.runtime_engine import RuntimeEngine
        from test_runtime_engine import FakeBackend
        from proxyforge.control.deployment_store import new_spec, new_landing_spec
        with tempfile.TemporaryDirectory() as temp:
            backend = FakeBackend()
            backend.check = lambda path: json.loads((path / 'config.json').read_text())
            def download(path, arch, guard):
                (path / 'sing-box').write_bytes(b'test')
            engine = RuntimeEngine(temp, backend, 'amd64', download)
            direct = new_spec(DIRECT)
            engine.apply(deployment_job(direct))
            original = engine.pointer('current')
            spec = {'direct': direct, 'chain': {'entry': new_spec({**DIRECT, **SETTINGS}), 'landing': new_landing_spec(LANDING)}}
            backend.fail_once = True
            with self.assertRaises(ValueError):
                engine.apply(deployment_job(spec, 'chain.apply'))
            self.assertEqual(engine.pointer('current'), original)
            job = deployment_job(spec, 'chain.apply')
            with patch.object(engine, 'finish', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                engine.apply(job)
            engine.recover()
            count = backend.activation_count
            engine.apply(job)
            self.assertEqual(backend.activation_count, count)
            engine.apply(deployment_job({'direct': direct, 'chain': None}, 'chain.remove'))
            self.assertEqual(json.loads((Path(temp) / engine.pointer('current') / 'config.json').read_text()), direct_config(direct))
