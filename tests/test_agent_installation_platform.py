"""Read-only checks of the privileged fixture's matrix guard; never install."""
import contextlib
import io
import json
import sys
import unittest
from unittest.mock import patch

if sys.platform == 'linux':
    from scripts import check_agent_installation as installation


@unittest.skipUnless(sys.platform == 'linux', 'Installation fixture requires Linux')
class InstallationPlatformTests(unittest.TestCase):
    def verify(self, expected_version='22.04', expected_arch='arm64', *,
               system='ubuntu', version='22.04', machine='aarch64', python=None, expected_os='ubuntu'):
        if python is None:
            python = [[3, 10, 12], machine]
        with patch.object(installation.platform, 'freedesktop_os_release',
                          return_value={'ID': system, 'VERSION_ID': version}), \
                patch.object(installation.platform, 'machine', return_value=machine), \
                patch.object(installation.subprocess, 'check_output', return_value=json.dumps(python)) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            installation.verify_platform(expected_version, expected_arch, expected_os)
            self.assertEqual(run.call_args.args[0][:2], ['/usr/bin/python3', '-I'])

    def test_all_native_ubuntu_combinations_use_system_python(self):
        for version, minor in [('22.04', 10), ('24.04', 12)]:
            for arch, machine in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
                with self.subTest(version=version, arch=arch):
                    self.verify(version, arch, version=version, machine=machine,
                                python=[[3, minor, 12], machine])

    def test_debian_combinations_use_their_system_python(self):
        for version, minor in [('12', 11), ('13', 13)]:
            for arch, machine in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
                with self.subTest(version=version, arch=arch):
                    self.verify(version, arch, expected_os='debian', system='debian', version=version,
                                machine=machine, python=[[3, minor, 1], machine])

    def test_debian_cannot_be_replaced_by_ubuntu_or_setup_python(self):
        for changes in ({'system': 'ubuntu'}, {'python': [[3, 12, 1], 'aarch64']}, {'version': '12'}):
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                self.verify('13', 'arm64', expected_os='debian', system=changes.get('system', 'debian'),
                            version=changes.get('version', '13'), python=changes.get('python', [[3, 13, 1], 'aarch64']))

    def test_wrong_os_release_or_architecture_rejected(self):
        for changes in ({'system': 'debian'}, {'version': '24.04'}, {'machine': 'x86_64'},
                        {'machine': 'riscv64'}):
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                self.verify(**changes)

    def test_setup_python_or_wrong_arch_cannot_substitute_for_system_python(self):
        for python in ([[3, 12, 1], 'aarch64'], [[3, 10, 12], 'x86_64']):
            with self.subTest(python=python), self.assertRaises(SystemExit):
                self.verify(python=python)


if __name__ == '__main__':
    unittest.main()
