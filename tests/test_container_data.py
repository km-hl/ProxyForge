"""Permission checks operate only on disposable directories, never repository data."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import container_data


@unittest.skipUnless(os.name == 'posix', 'Container permissions require POSIX descriptors')
class ContainerDataTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'data'
        self.root.mkdir(mode=0o700)
        for name, value in [('DATA', self.root), ('UID', os.geteuid()), ('GID', os.getegid())]:
            patcher = patch.object(container_data, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_migration_preserves_bytes_and_runtime_probe_leaves_no_files(self):
        child = self.root / 'history'
        child.mkdir(mode=0o755)
        secret = child / 'config.json'
        secret.write_bytes(b'synthetic-private-data')
        secret.chmod(0o644)
        container_data.inspect_data(apply=True)
        self.assertEqual(secret.read_bytes(), b'synthetic-private-data')
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)
        container_data.inspect_data(runtime=True)
        self.assertEqual(list(self.root.iterdir()), [child])

    def test_symlink_rejected_before_any_migration(self):
        outside = Path(self.temp.name) / 'outside'
        outside.write_bytes(b'do-not-touch')
        outside.chmod(0o644)
        (self.root / 'link').symlink_to(outside)
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            container_data.inspect_data(apply=True)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)
        self.assertEqual(outside.read_bytes(), b'do-not-touch')

    def test_directory_symlink_and_root_symlink_rejected(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (self.root / 'link').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            container_data.inspect_data(apply=True)
        with patch.object(container_data, 'DATA', self.root / 'link'):
            with self.assertRaises(OSError):
                container_data.inspect_data(apply=True)

    def test_hardlink_and_fifo_rejected(self):
        outside = Path(self.temp.name) / 'outside'
        outside.write_bytes(b'do-not-touch')
        os.link(outside, self.root / 'hardlink')
        with self.assertRaises(ValueError):
            container_data.inspect_data(apply=True)
        (self.root / 'hardlink').unlink()
        os.mkfifo(self.root / 'fifo')
        with self.assertRaises(ValueError):
            container_data.inspect_data(apply=True)

    def test_readonly_files_rejected_without_widening(self):
        secret = self.root / 'readonly'
        secret.write_bytes(b'private')
        secret.chmod(0o400)
        with self.assertRaises(ValueError):
            container_data.inspect_data(apply=True)
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o400)

    def test_runtime_rejects_wrong_owner_or_broad_permissions(self):
        with patch.object(container_data, 'UID', os.geteuid() + 1):
            with self.assertRaises(ValueError):
                container_data.inspect_data(runtime=True)
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            container_data.inspect_data(runtime=True)


if __name__ == '__main__':
    unittest.main()
