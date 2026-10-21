import json
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import Mock, patch

from agent import runtime_engine


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class RuntimeReadinessTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.backend = object.__new__(runtime_engine.SystemBackend)
        self.release = Path('/synthetic/release')
        self.time_patch = patch.object(runtime_engine, 'time', self.clock)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        self.run_patch = patch.object(runtime_engine.subprocess, 'run',
                                      return_value=types.SimpleNamespace(returncode=0))
        self.run = self.run_patch.start()
        self.addCleanup(self.run_patch.stop)

    def assert_one_restart(self):
        self.assertEqual([call.args[0][1] for call in self.run.call_args_list], ['reset-failed', 'restart'])

    def test_delayed_start_waits_then_requires_three_healthy_observations(self):
        observations = []
        def matches(release, **options):
            observations.append((self.clock.now, options))
            return self.clock.now >= 0.8
        self.backend.matches = matches
        self.backend.activate(self.release)
        self.assertEqual([time for time, _ in observations], [0, 0.5, 1, 1.5, 2])
        self.assertTrue(all(options == {'deadline': 20} for _, options in observations[1:]))
        self.assert_one_restart()

    def test_existing_exact_release_is_unchanged(self):
        self.backend.matches = Mock(return_value=True)
        self.backend.activate(self.release)
        self.run.assert_not_called()
        self.assertEqual(self.clock.sleeps, [])

    def test_permanently_unready_service_exhausts_one_bounded_grace(self):
        self.backend.matches = Mock(return_value=False)
        with self.assertRaisesRegex(ValueError, 'Runtime failed health verification'):
            self.backend.activate(self.release)
        self.assertEqual(self.clock.now, 20)
        self.assertLessEqual(max(self.clock.sleeps), 0.5)
        self.assert_one_restart()

    def test_read_only_probe_timeout_before_first_ready_can_retry(self):
        def matches(release, **options):
            if self.clock.now == 0:
                return False
            if self.clock.now == 0.5:
                self.clock.now += 5
                raise subprocess.TimeoutExpired(['systemctl', 'show'], 5)
            return True
        self.backend.matches = matches
        self.backend.activate(self.release)
        self.assertEqual(self.clock.now, 7)
        self.assert_one_restart()

    def test_health_loss_after_first_ready_is_not_hidden_by_grace(self):
        self.backend.matches = Mock(side_effect=[False, False, True, False, True, True, True])
        with self.assertRaisesRegex(ValueError, 'Runtime failed health verification'):
            self.backend.activate(self.release)
        self.assertEqual(self.clock.now, 1.5)
        self.assertEqual(self.backend.matches.call_count, 4)
        self.assert_one_restart()

    def test_post_ready_probe_timeout_still_fails_health_verification(self):
        self.backend.matches = Mock(side_effect=[False, True, subprocess.TimeoutExpired(['systemctl'], 5)])
        with self.assertRaisesRegex(ValueError, 'Runtime failed health verification'):
            self.backend.activate(self.release)
        self.assert_one_restart()

    def test_late_positive_probe_cannot_commit_after_deadline(self):
        def matches(release, **options):
            if not options:
                return False
            self.clock.now = 20.1
            return True
        self.backend.matches = matches
        with self.assertRaisesRegex(ValueError, 'Runtime failed health verification'):
            self.backend.activate(self.release)
        self.assert_one_restart()

    def test_control_signals_and_unexpected_faults_are_not_retried(self):
        for error in (KeyboardInterrupt(), SystemExit(), RuntimeError('unexpected')):
            with self.subTest(kind=type(error).__name__):
                self.clock.now = 0
                self.run.reset_mock()
                self.backend.matches = Mock(side_effect=[False, error])
                with self.assertRaises(type(error)):
                    self.backend.activate(self.release)
                self.assert_one_restart()

    def test_systemctl_and_socket_probes_share_remaining_deadline(self):
        calls = []
        def run(args, **options):
            calls.append((args, options))
            self.clock.now += 0.1 if args[1] == 'is-active' else 0.3
            return types.SimpleNamespace(returncode=0, stdout='42\n')
        self.run.side_effect = run
        target = self.release / 'sing-box'
        def connect(address, **options):
            self.clock.now += 0.2
            return Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
        with patch.object(Path, 'resolve', return_value=target), \
                patch.object(Path, 'read_text', return_value=json.dumps({'inbounds': [{'listen_port': 1234}, {'listen_port': 1235}]})), \
                patch.object(runtime_engine.socket, 'create_connection', side_effect=connect) as sockets:
            self.assertTrue(self.backend.matches(self.release, deadline=1))
        self.assertAlmostEqual(calls[0][1]['timeout'], 1)
        self.assertAlmostEqual(calls[1][1]['timeout'], 0.9)
        self.assertAlmostEqual(sockets.call_args_list[0].kwargs['timeout'], 0.6)
        self.assertAlmostEqual(sockets.call_args_list[1].kwargs['timeout'], 0.4)

    def test_exhausted_deadline_does_not_start_another_probe(self):
        with self.assertRaises(TimeoutError):
            self.backend.active(deadline=0)
        self.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
