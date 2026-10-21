import contextlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import installation_heartbeat as heartbeat


class InstallationHeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.agent_id = 'a' * 32
        self.clock = SimpleNamespace(now=0.0, sleeps=[])
        def sleep(seconds):
            self.clock.sleeps.append(seconds)
            self.clock.now += seconds
        self.patches = [patch.object(heartbeat, 'time', SimpleNamespace(monotonic=lambda: self.clock.now, sleep=sleep)),
                        patch.object(heartbeat, 'service_summary', return_value={'properties': {'ActiveState': 'active'}})]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.headers = {'Authorization': 'Bearer synthetic-private-header'}

    def snapshot(self, seen=0, *, running=True, agent_id=None, extra=None):
        metadata = {name: 1 for name in heartbeat.CAPABILITIES}
        metadata['singbox'] = {'installed': True, 'running': running, 'status': 'running' if running else 'stopped'}
        if extra:
            metadata.update(extra)
        payload = {'agents': [{'id': agent_id or self.agent_id, 'last_seen': seen, 'metadata': metadata}]}
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: payload)

    def test_later_normal_cycle_is_observed_without_replaying_actions(self):
        client = Mock()
        client.get.side_effect = lambda *a, **kw: self.snapshot(1 if self.clock.now >= 50 else 0,
                                                               running=self.clock.now >= 50)
        metadata = heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id)
        self.assertTrue(metadata['singbox']['running'])
        self.assertEqual(self.clock.now, 50)
        self.assertTrue(all(call.args == ('/api/agents',) and call.kwargs == {'headers': self.headers}
                            for call in client.get.call_args_list))
        client.post.assert_not_called()

    def test_stale_healthy_snapshot_cannot_replace_new_heartbeat(self):
        client = Mock()
        client.get.return_value = self.snapshot(1)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), self.assertRaises(AssertionError):
            heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id, budget=2.5)
        self.assertEqual(self.clock.now, 2.5)
        self.assertLessEqual(max(self.clock.sleeps), 1)
        summary = json.loads(stream.getvalue().splitlines()[0].split(': ', 1)[1])
        self.assertFalse(summary['new_heartbeat_observed'])
        self.assertTrue(summary['running'])

    def test_other_agent_cannot_satisfy_expected_identity(self):
        client = Mock()
        client.get.side_effect = lambda *a, **kw: self.snapshot(self.clock.now, agent_id='b' * 32)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(AssertionError):
            heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id, budget=2)

    def test_all_capabilities_and_true_runtime_state_remain_required(self):
        client = Mock()
        client.get.side_effect = lambda *a, **kw: self.snapshot(self.clock.now, extra={'chain_protocol_version': 0})
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(AssertionError):
            heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id, budget=2)

    def test_late_positive_api_result_is_rejected_after_deadline(self):
        client = Mock()
        calls = 0
        def get(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return self.snapshot(0)
            self.clock.now = 5
            return self.snapshot(1)
        client.get.side_effect = get
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(AssertionError):
            heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id, budget=2)

    def test_timeout_summary_excludes_tokens_config_and_unknown_fields(self):
        client = Mock()
        secret = 'private-body-or-hostname'
        client.get.side_effect = lambda *a, **kw: self.snapshot(self.clock.now, running=False,
            extra={'hostname': secret, 'version': secret, 'runtime_protocol_version': [secret]})
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), self.assertRaises(AssertionError):
            heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id, budget=2)
        self.assertNotIn(secret, stream.getvalue())
        self.assertNotIn(self.headers['Authorization'], stream.getvalue())
        summary = json.loads(stream.getvalue().splitlines()[0].split(': ', 1)[1])
        self.assertTrue(summary['new_heartbeat_observed'])
        self.assertIsNone(summary['capabilities']['runtime_protocol_version'])

    def test_invalid_budget_and_api_failure_stop_without_poll_replay(self):
        client = Mock()
        for budget in (0, -1, 91, float('inf'), float('nan')):
            with self.assertRaises(ValueError):
                heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id, budget=budget)
        client.get.assert_not_called()
        client.get.side_effect = RuntimeError('synthetic API failure')
        with self.assertRaises(RuntimeError):
            heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id)
        self.assertEqual(client.get.call_count, 1)

    def test_non_timestamp_fields_cannot_forge_a_new_heartbeat(self):
        for seen in (True, 'private-timestamp-value', float('nan'), float('inf'), {}):
            with self.subTest(kind=type(seen).__name__):
                client = Mock()
                client.get.return_value = self.snapshot(seen)
                with self.assertRaisesRegex(ValueError, 'Invalid Agent heartbeat timestamp'):
                    heartbeat.wait_for_helper_heartbeat(client, self.headers, self.agent_id)
                self.assertEqual(client.get.call_count, 1)


if __name__ == '__main__':
    unittest.main()
