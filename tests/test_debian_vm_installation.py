"""Protect the CI VM's provenance and refuse unverified images before boot."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    'debian_vm_installation', Path(__file__).resolve().parents[1] / 'scripts/check_debian_vm_installation.py')
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)


class DebianVMInstallationTests(unittest.TestCase):
    def ssh_clock(self):
        clock = SimpleNamespace(now=0)

        def advance(seconds):
            clock.now += seconds

        return clock, SimpleNamespace(monotonic=lambda: clock.now, sleep=Mock(side_effect=advance))

    def test_ssh_probe_retries_timeout_and_nonzero_before_success(self):
        clock, timer = self.ssh_clock()
        ssh = ['ssh', '-o', 'StrictHostKeyChecking=yes', 'ci@127.0.0.1']
        vm = Mock()
        vm.poll.return_value = None

        def probe(command, **kwargs):
            self.assertEqual(command, [*ssh, 'true'])
            self.assertEqual(kwargs, {'capture_output': True, 'timeout': 15})
            if clock.now == 0:
                clock.now += 15
                raise VM.subprocess.TimeoutExpired(command, 15)
            return Mock(returncode=255 if clock.now == 20 else 0)

        with patch.object(VM, 'time', timer), patch.object(VM.subprocess, 'run', side_effect=probe) as run:
            VM.wait_ssh_ready(ssh, vm)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(clock.now, 25)

    def test_ssh_timeouts_remain_within_original_deadline(self):
        clock, timer = self.ssh_clock()
        vm = Mock()
        vm.poll.return_value = None

        def timeout(command, **kwargs):
            clock.now += kwargs['timeout']
            raise VM.subprocess.TimeoutExpired(command, kwargs['timeout'])

        with patch.object(VM, 'time', timer), patch.object(VM.subprocess, 'run', side_effect=timeout) as run:
            with self.assertRaisesRegex(TimeoutError, 'SSH readiness exceeded'):
                VM.wait_ssh_ready(['ssh'], vm, budget=31)
        self.assertEqual([call.kwargs['timeout'] for call in run.call_args_list], [15, 11])
        self.assertEqual(clock.now, 31)

    def test_ssh_failure_never_becomes_ready_at_budget_expiry(self):
        clock, timer = self.ssh_clock()
        vm = Mock()
        vm.poll.return_value = None
        with patch.object(VM, 'time', timer), patch.object(VM.subprocess, 'run', return_value=Mock(returncode=255)) as run:
            with self.assertRaises(TimeoutError):
                VM.wait_ssh_ready(['ssh'], vm, budget=7)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(clock.now, 7)

    def test_ssh_wait_stops_if_qemu_exits(self):
        vm = Mock()
        vm.poll.return_value = 1
        with patch.object(VM.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'QEMU exited'):
                VM.wait_ssh_ready(['ssh'], vm)
            run.assert_not_called()

    def test_ssh_wait_does_not_swallow_other_failures_or_control_signals(self):
        vm = Mock()
        vm.poll.return_value = None
        for error in (OSError, RuntimeError, KeyboardInterrupt, SystemExit):
            with self.subTest(error=error), patch.object(VM.subprocess, 'run', side_effect=error), \
                    patch.object(VM.time, 'sleep') as sleep:
                with self.assertRaises(error):
                    VM.wait_ssh_ready(['ssh'], vm)
                sleep.assert_not_called()

    def test_wrong_platform_or_non_ci_refuses_before_host_operations(self):
        for system, machine, ci in [('Windows', 'x86_64', 'true'), ('Linux', 'aarch64', 'true'),
                                    ('Linux', 'x86_64', 'false')]:
            with self.subTest(system=system, machine=machine, ci=ci), \
                    patch.object(VM.platform, 'system', return_value=system), \
                    patch.object(VM.platform, 'machine', return_value=machine), \
                    patch.dict(VM.os.environ, {'GITHUB_ACTIONS': ci}), \
                    patch.object(VM.subprocess, 'run') as operation:
                with self.assertRaises(SystemExit):
                    VM.verify_host('amd64')
                operation.assert_not_called()

    def test_hash_mismatch_discards_image(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(VM.urllib.request, 'urlopen', return_value=io.BytesIO(b'changed official image')):
            target = Path(directory) / 'image.qcow2'
            with self.assertRaisesRegex(ValueError, 'SHA512 mismatch'):
                VM.download_image('https://cloud.debian.org/example', hashlib.sha512(b'expected').hexdigest(), target)
            self.assertFalse(target.exists())

    def test_existing_image_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(VM.urllib.request, 'urlopen', return_value=io.BytesIO(b'new')):
            target = Path(directory) / 'image.qcow2'
            target.write_bytes(b'existing')
            with self.assertRaises(FileExistsError):
                VM.download_image('https://cloud.debian.org/example', '0' * 128, target)
            self.assertEqual(target.read_bytes(), b'existing')

    def test_exact_image_is_retained(self):
        data = b'verified test image'
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(VM.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            target = Path(directory) / 'image.qcow2'
            VM.download_image('https://cloud.debian.org/example', hashlib.sha512(data).hexdigest(), target)
            self.assertEqual(target.read_bytes(), data)

    def test_download_deadline_discards_partial_image(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(VM.urllib.request, 'urlopen', return_value=io.BytesIO(b'image')), \
                patch.object(VM.time, 'monotonic', side_effect=[0, 601]):
            target = Path(directory) / 'image.qcow2'
            with self.assertRaises(TimeoutError):
                VM.download_image('https://cloud.debian.org/example', '0' * 128, target)
            self.assertFalse(target.exists())

    def test_cloud_init_retries_only_transport_reset(self):
        vm = Mock()
        vm.poll.return_value = None
        with patch.object(VM.subprocess, 'run', side_effect=[Mock(returncode=255, stderr=b'Connection reset by peer'), Mock(returncode=0)]) as wait, \
                patch.object(VM.time, 'sleep'):
            VM.wait_cloud_init(['ssh'], vm)
            self.assertEqual(wait.call_count, 2)
        for error in (1, 2):
            with self.subTest(status=error), patch.object(VM.subprocess, 'run', return_value=Mock(returncode=error)) as wait:
                with self.assertRaisesRegex(RuntimeError, 'cloud-init failed'):
                    VM.wait_cloud_init(['ssh'], vm)
                self.assertEqual(wait.call_count, 1)

    def test_cloud_init_does_not_retry_host_key_failure(self):
        vm = Mock()
        vm.poll.return_value = None
        with patch.object(VM.subprocess, 'run', return_value=Mock(returncode=255, stderr=b'Host key verification failed.')) as wait:
            with self.assertRaisesRegex(RuntimeError, 'host key checks'):
                VM.wait_cloud_init(['ssh'], vm)
            self.assertEqual(wait.call_count, 1)

    def test_cloud_init_wait_has_deadline(self):
        with patch.object(VM.time, 'monotonic', side_effect=[0, 181]), \
                patch.object(VM.subprocess, 'run') as operation:
            with self.assertRaises(TimeoutError):
                VM.wait_cloud_init(['ssh'], Mock())
            operation.assert_not_called()

    def test_guest_rejects_shared_kernel_container_and_unowned_vm(self):
        evidence = {'os': {'ID': 'debian', 'VERSION_ID': '12'}, 'machine': 'aarch64',
                    'kernel': '6.1.0-deb12-arm64', 'kernel_version': 'Linux version Debian 6.1.0',
                    'marker': 'our-new-vm', 'pid1': 'systemd', 'virtualization': 'qemu'}
        VM.verify_guest(evidence, '12', 'arm64', 'our-new-vm', '6.8.0-ubuntu')
        for field, value in [('virtualization', 'docker'), ('marker', 'another-vm'),
                             ('kernel_version', 'Ubuntu kernel'), ('kernel', '6.8.0-ubuntu'),
                             ('pid1', 'bash'), ('machine', 'x86_64')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                VM.verify_guest({**evidence, field: value}, '12', 'arm64', 'our-new-vm', '6.8.0-ubuntu')


if __name__ == '__main__':
    unittest.main()
