"""Unit tests for Agent silent auto-upgrade, bundle safety, and CAP_NET_ADMIN unit."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock

from agent import self_upgrade
from proxyforge.control.agent_installation import build_agent_bundle, render_quick_install_script


def _make_tar_gz(entries):
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for arcname, content in entries:
            if isinstance(content, tuple) and content[0] == 'symlink':
                info = tarfile.TarInfo(arcname)
                info.type = tarfile.SYMTYPE
                info.linkname = content[1]
                archive.addfile(info)
                continue
            raw = content.encode('utf-8') if isinstance(content, str) else content
            info = tarfile.TarInfo(arcname)
            info.size = len(raw)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(raw))
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode='wb', mtime=0) as gz:
        gz.write(tar_buf.getvalue())
    payload = gz_buf.getvalue()
    return payload, hashlib.sha256(payload).hexdigest()


class AgentSelfUpgradeTests(unittest.TestCase):
    def test_singbox_service_grants_cap_net_admin(self):
        unit = (Path(__file__).resolve().parents[1] / 'agent' / 'proxyforge-singbox.service').read_text(encoding='utf-8')
        self.assertIn('CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN', unit)
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN', unit)

    def test_quick_install_persists_bundle_sha_and_restarts_singbox_on_upgrade(self):
        _, digest = build_agent_bundle()
        script = render_quick_install_script('https://panel.example.com', bundle_sha256=digest)
        self.assertIn('/opt/proxyforge-agent/bundle-sha256', script)
        self.assertIn('self-upgrade-protocol', script)
        self.assertIn('systemctl restart proxyforge-singbox.service', script)

    def test_apply_bundle_rejects_hash_mismatch_traversal_and_symlinks(self):
        payload, digest = build_agent_bundle()
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self_upgrade.verify_and_extract_bundle(payload, '0' * 64)

        bad_path, bad_sha = _make_tar_gz([
            ('agent/../evil.py', 'print(1)'),
            ('agent/__init__.py', ''),
            ('agent/main.py', ''),
            ('agent/client.py', ''),
            ('agent/system_info.py', ''),
            ('agent/runtime_helper.py', ''),
            ('agent/self_upgrade.py', ''),
        ])
        with self.assertRaisesRegex(ValueError, 'Path traversal'):
            self_upgrade.verify_and_extract_bundle(bad_path, bad_sha)

        sym_tar, sym_sha = _make_tar_gz([
            ('agent/link.py', ('symlink', '/etc/passwd')),
        ])
        with self.assertRaisesRegex(ValueError, 'non-file'):
            self_upgrade.verify_and_extract_bundle(sym_tar, sym_sha)

        outside, out_sha = _make_tar_gz([('etc/shadow', 'nope')])
        with self.assertRaisesRegex(ValueError, 'outside agent/'):
            self_upgrade.verify_and_extract_bundle(outside, out_sha)

    def test_apply_bundle_installs_files_and_only_restarts_changed_active_units(self):
        payload, digest = build_agent_bundle()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'opt'
            systemd = Path(tmp) / 'systemd'
            systemd.mkdir(parents=True)
            # Pre-seed old singbox unit (different) and unchanged agent unit
            (systemd / 'proxyforge-singbox.service').write_text('[Service]\nOld=1\n', encoding='utf-8')
            extracted = self_upgrade.verify_and_extract_bundle(payload, digest)
            (systemd / 'proxyforge-agent.service').write_bytes(extracted['proxyforge-agent.service'])

            calls = []
            def fake_ctl(args):
                calls.append(list(args))
                res = MagicMock()
                res.returncode = 0
                return res

            result = self_upgrade.apply_bundle(
                payload,
                digest,
                install_root=root,
                systemd_dir=systemd,
                systemctl_runner=fake_ctl,
                chown_root=False,
            )
            self.assertTrue(result['upgraded'])
            self.assertEqual(result['sha256'], digest)
            self.assertEqual(result['changed_units'], ['proxyforge-singbox.service'])
            self.assertEqual(result['restarted_dataplane'], ['proxyforge-singbox.service'])
            self.assertTrue((root / 'agent' / 'self_upgrade.py').is_file())
            self.assertEqual((root / 'bundle-sha256').read_text(encoding='utf-8').strip(), digest)
            self.assertEqual((root / 'self-upgrade-protocol').read_text(encoding='utf-8').strip(), '1')
            self.assertIn(['daemon-reload'], calls)
            self.assertIn(['restart', 'proxyforge-singbox.service'], calls)

            # Second apply with identical bundle must NOT reload or restart dataplane units
            calls.clear()
            result2 = self_upgrade.apply_bundle(
                payload,
                digest,
                install_root=root,
                systemd_dir=systemd,
                systemctl_runner=fake_ctl,
                chown_root=False,
            )
            self.assertEqual(result2['changed_units'], [])
            self.assertEqual(result2['restarted_dataplane'], [])
            self.assertEqual(calls, [])

    def test_maybe_auto_upgrade_downloads_verifies_and_applies_cooldown(self):
        payload, digest = build_agent_bundle()
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / 'config.json'
            sha_path = Path(tmp) / 'bundle-sha256'
            sha_path.write_text('a' * 64 + '\n', encoding='utf-8')

            client = MagicMock()
            client.get_bytes.return_value = payload
            executor = MagicMock(return_value={'status': 'success', 'output': {'upgraded': True}})
            clock = [1000.0]

            # Matching hash -> no-op
            self.assertFalse(
                self_upgrade.maybe_auto_upgrade(
                    client, {'token': 'pfagt_x'}, cfg_path,
                    {'latest_bundle_sha256': 'a' * 64},
                    installed_sha_path=sha_path,
                    capability_check=lambda: True,
                    executor=executor,
                    now_fn=lambda: clock[0],
                )
            )
            client.get_bytes.assert_not_called()

            # Failed attempt enters cooldown
            executor.return_value = {'status': 'failed', 'error': 'runtime_failed'}
            self.assertFalse(
                self_upgrade.maybe_auto_upgrade(
                    client, {'token': 'pfagt_x'}, cfg_path,
                    {'latest_bundle_sha256': digest},
                    installed_sha_path=sha_path,
                    capability_check=lambda: True,
                    executor=executor,
                    now_fn=lambda: clock[0],
                )
            )
            self.assertEqual(client.get_bytes.call_count, 1)

            # Within cooldown -> skipped
            clock[0] += 60.0
            self.assertFalse(
                self_upgrade.maybe_auto_upgrade(
                    client, {'token': 'pfagt_x'}, cfg_path,
                    {'latest_bundle_sha256': digest},
                    installed_sha_path=sha_path,
                    capability_check=lambda: True,
                    executor=executor,
                    now_fn=lambda: clock[0],
                )
            )
            self.assertEqual(client.get_bytes.call_count, 1)

            # After cooldown -> retries and succeeds
            clock[0] += self_upgrade.COOLDOWN_SECONDS + 5.0
            executor.return_value = {'status': 'success', 'output': {'upgraded': True}}
            self.assertTrue(
                self_upgrade.maybe_auto_upgrade(
                    client, {'token': 'pfagt_x'}, cfg_path,
                    {'latest_bundle_sha256': digest},
                    installed_sha_path=sha_path,
                    capability_check=lambda: True,
                    executor=executor,
                    now_fn=lambda: clock[0],
                )
            )
            self.assertEqual(client.get_bytes.call_count, 2)
            state = json.loads(cfg_path.with_name('upgrade-state.json').read_text(encoding='utf-8'))
            self.assertEqual(state['last_upgraded_sha256'], digest)


if __name__ == '__main__':
    unittest.main()
