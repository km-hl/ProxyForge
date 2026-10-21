import contextlib
import io
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import check_debian_vm_installation as vm


class VMPreparationBudgetTests(unittest.TestCase):
    def setUp(self):
        self.clock = SimpleNamespace(now=0)
        self.patch_time = patch.object(vm, 'time', SimpleNamespace(monotonic=lambda: self.clock.now))
        self.patch_time.start()
        self.addCleanup(self.patch_time.stop)
        self.ssh = ['ssh', '-o', 'StrictHostKeyChecking=yes', 'ci@127.0.0.1']

    def test_security_update_venv_and_wheels_fit_one_measured_preparation_window(self):
        durations = iter([420, 120, 120])
        calls = []
        def run(args, **options):
            calls.append((args, options))
            self.clock.now += next(durations)
        stream = io.StringIO()
        with patch.object(vm.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(stream):
            vm.prepare_guest(self.ssh)
        self.assertEqual(self.clock.now, 660)
        self.assertEqual([options['timeout'] for _, options in calls], [900, 480, 360])
        self.assertIn('apt-get update', calls[0][0][-1])
        self.assertIn('python3-venv ca-certificates sudo', calls[0][0][-1])
        self.assertIn('sudo python3 -m venv', calls[1][0][-1])
        self.assertIn('--require-hashes --only-binary=:all:', calls[2][0][-1])
        self.assertIn('requirements-dev.txt', calls[2][0][-1])
        self.assertIn('pip check', calls[2][0][-1])
        self.assertTrue(all(args[:-1] == self.ssh and options['check'] for args, options in calls))
        for name in ('system-packages', 'controller-venv', 'locked-wheels'):
            self.assertIn('phase elapsed: ' + name, stream.getvalue())

    def test_custom_budget_is_shared_not_restarted_for_each_phase(self):
        durations = iter([10, 20, 30])
        def run(args, **options):
            self.clock.now += next(durations)
        with patch.object(vm.subprocess, 'run', side_effect=run) as run, contextlib.redirect_stdout(io.StringIO()):
            vm.prepare_guest(self.ssh, budget=90)
        self.assertEqual([call.kwargs['timeout'] for call in run.call_args_list], [90, 80, 60])

    def test_failed_or_timed_out_phase_is_not_replayed_or_followed_by_installation(self):
        errors = [subprocess.CalledProcessError(1, ['apt']), subprocess.TimeoutExpired(['apt'], 900)]
        for error in errors:
            with self.subTest(kind=type(error).__name__), \
                    patch.object(vm.subprocess, 'run', side_effect=error) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(type(error)):
                    vm.prepare_guest(self.ssh)
                self.assertEqual(run.call_count, 1)

    def test_invalid_or_unbounded_budget_fails_before_any_guest_operation(self):
        for budget in (0, -1, 901, float('inf'), float('nan')):
            with self.subTest(budget=budget), patch.object(vm.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    vm.prepare_guest(self.ssh, budget=budget)
                run.assert_not_called()

    def test_no_next_phase_after_preparation_deadline(self):
        def run(args, **options):
            self.clock.now = 91
        with patch.object(vm.subprocess, 'run', side_effect=run) as run, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(TimeoutError, 'Guest preparation deadline exceeded'):
                vm.prepare_guest(self.ssh, budget=90)
        self.assertEqual(run.call_count, 1)

    def test_time_spent_reporting_phase_cannot_start_an_expired_operation(self):
        def print_phase(*args, **kwargs):
            self.clock.now = 91
        with patch.object(vm, 'print', side_effect=print_phase, create=True), \
                patch.object(vm.subprocess, 'run') as run:
            with self.assertRaisesRegex(TimeoutError, 'Guest preparation deadline exceeded'):
                vm.prepare_guest(self.ssh, budget=90)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
