"""Protect the CI VM's provenance and refuse unverified images before boot."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'debian_vm_installation', Path(__file__).resolve().parents[1] / 'scripts/check_debian_vm_installation.py')
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)


class DebianVMInstallationTests(unittest.TestCase):
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
