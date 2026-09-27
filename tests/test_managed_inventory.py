import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_chains as chain_tests


class ManagedInventoryTest(unittest.TestCase):
    setUp = chain_tests.ChainStoreTest.setUp
    enroll = chain_tests.ChainStoreTest.enroll
    complete = chain_tests.ChainStoreTest.complete
    put = chain_tests.ChainStoreTest.put

    def test_all_states_and_dependencies_are_visible_without_secrets(self):
        created = self.put()
        items = self.store.managed_inventory()
        self.assertEqual([item['kind'] for item in items], ['direct', 'chain'])
        direct, chain = items
        self.assertTrue(direct['publishable'])
        self.assertFalse(chain['publishable'])
        self.assertEqual(chain['status'], 'pending')
        self.assertEqual(direct['blocked_by'][0]['id'], created['id'])
        self.assertEqual(chain['landing']['id'], self.landing['agent_id'])
        job = self.complete(self.entry)
        self.assertTrue(self.store.managed_inventory()[1]['publishable'])
        self.put(1, remove=True)
        self.complete(self.entry)
        direct, chain = self.store.managed_inventory()
        self.assertTrue(chain['removed'])
        self.assertFalse(chain['publishable'])
        self.assertEqual(direct['blocked_by'], [])
        public = json.dumps(self.store.managed_inventory())
        for secret in [job['deployment']['chain']['landing']['password'], job['deployment']['direct']['private_key'],
                       job['deployment']['chain']['entry']['uuid'], self.entry['agent_token']]:
            self.assertNotIn(secret, public)
        self.assertNotIn('secret_spec', public)
        self.store.path.with_name('deployment.key').unlink()
        self.assertEqual(len(self.store.managed_inventory()), 2)

    def test_deadline_and_revocation_are_reflected_without_other_page_visits(self):
        self.put()
        with self.store.connection() as db:
            db.execute("UPDATE jobs SET deadline=0 WHERE type='chain.apply'")
        node = self.store.managed_inventory()[1]
        self.assertEqual((node['status'], node['error']), ('failed', 'deadline_exceeded'))
        self.put(1)
        self.complete(self.entry)
        self.store.revoke(self.landing['agent_id'])
        direct, chain = self.store.managed_inventory()
        self.assertTrue(direct['publishable'])
        self.assertFalse(chain['publishable'])
        self.assertEqual(chain['landing']['status'], 'revoked')
        self.store.revoke(self.entry['agent_id'])
        self.assertTrue(all(not node['publishable'] for node in self.store.managed_inventory()))

    def test_management_api_auth_and_no_secret_key_dependency(self):
        from fastapi.testclient import TestClient
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN
        with tempfile.TemporaryDirectory() as temp:
            app = load_isolated_application(Path(temp))
            app.ControlStore = lambda path: self.store
            url = '/api/agents/managed/nodes'
            with TestClient(app.app) as client:
                for token in ('', self.entry['agent_token'], TEST_SUBSCRIPTION_TOKEN):
                    self.assertEqual(client.get(url, headers={'Authorization': 'Bearer ' + token}).status_code, 401)
                with patch.object(self.store, '_decrypt_spec', side_effect=AssertionError('must not decrypt')):
                    response = client.get(url, headers={'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['nodes'][0]['agent']['id'], self.entry['agent_id'])
