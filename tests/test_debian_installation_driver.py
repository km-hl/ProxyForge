"""The Debian privileged driver must reject mismatched hosts before Docker writes."""
import unittest
from unittest.mock import patch

from scripts import check_debian_installation as driver


class DebianInstallationDriverTests(unittest.TestCase):
    def test_native_matching_disposable_root_runner_is_required(self):
        for machine, arch in [('x86_64', 'amd64'), ('aarch64', 'arm64')]:
            with self.subTest(machine=machine), patch.object(driver.platform, 'machine', return_value=machine), \
                    patch.object(driver.os, 'geteuid', create=True, return_value=0), \
                    patch.dict(driver.os.environ, {'GITHUB_ACTIONS': 'true'}):
                driver.verify_host(arch)

    def test_wrong_arch_root_or_runner_rejected_before_docker(self):
        for machine, uid, actions in [('aarch64', 0, 'true'), ('x86_64', 1000, 'true'), ('x86_64', 0, 'false')]:
            with self.subTest(machine=machine, uid=uid, actions=actions), \
                    patch.object(driver.platform, 'machine', return_value=machine), \
                    patch.object(driver.os, 'geteuid', create=True, return_value=uid), \
                    patch.dict(driver.os.environ, {'GITHUB_ACTIONS': actions}), \
                    patch.object(driver.subprocess, 'run') as run, \
                    self.assertRaises(SystemExit):
                driver.verify_host('amd64')
            run.assert_not_called()
