"""Controller 发布版本须由调用方独立固定，不能相信清单中的自报版本。"""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import agent_artifacts as artifacts


class ControllerReleaseMetadataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {path: (artifacts.ROOT / path).read_bytes() for path in artifacts.FILES}
        cls.commit = 'a' * 40
        cls.archive = artifacts.archive_bytes(cls.files)

    def verify(self, manifest, expected):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, metadata = root / 'agent.tar', root / 'manifest.json'
            archive.write_bytes(self.archive)
            encoded = artifacts.canonical_json(manifest)
            metadata.write_bytes(encoded)
            return artifacts.verify(archive, metadata, self.commit, artifacts.sha256(encoded),
                                    controller_release_version=expected)

    def test_versions_and_protocols_remain_independent_and_repeatable(self):
        for version in ['0.7.0', '1.0.0', '1.0.0-rc.1', '1.0.0+build.001', '1.0.0-0.x-y+001']:
            with self.subTest(version=version):
                manifest = artifacts.manifest_for(self.commit, self.files, self.archive,
                                                 controller_release_version=version)
                self.assertEqual(self.verify(manifest, version), manifest)
                self.assertEqual(manifest['controller_release_version'], version)
                self.assertEqual(manifest['agent_version'], '0.6.0')
                self.assertEqual(manifest['compatibility']['controller_schema_baseline'], 5)
                self.assertEqual(manifest['controller_source_commit'], self.commit)
                repeated = artifacts.manifest_for(self.commit, self.files, self.archive,
                                                 controller_release_version=version)
                self.assertEqual(artifacts.canonical_json(manifest), artifacts.canonical_json(repeated))

    def test_null_default_and_explicit_version_cannot_substitute_for_each_other(self):
        ordinary = artifacts.manifest_for(self.commit, self.files, self.archive)
        self.assertIsNone(ordinary['controller_release_version'])
        self.assertEqual(self.verify(ordinary, None), ordinary)
        released = artifacts.manifest_for(self.commit, self.files, self.archive,
                                         controller_release_version='1.2.3')
        self.assertEqual(released['archive'], ordinary['archive'])
        self.assertNotEqual(artifacts.canonical_json(released), artifacts.canonical_json(ordinary))
        for manifest, expected in [(released, None), (ordinary, '1.2.3'), (released, '1.2.4')]:
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                self.verify(manifest, expected)

    def test_manifest_cannot_relabel_compatibility_or_agent_version(self):
        manifest = artifacts.manifest_for(self.commit, self.files, self.archive,
                                         controller_release_version='1.2.3')
        for field, value in [('agent_version', '1.2.3'), ('compatibility', {}),
                             ('controller_source_commit', 'b' * 40), ('unknown', 'extra')]:
            changed = copy.deepcopy(manifest)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(changed, '1.2.3')

    def test_invalid_semver_is_rejected_before_reading_source_or_creating_output(self):
        invalid = ['', True, 7, 'v1.2.3', '01.2.3', '1.02.3', '1.2.03', '1.2', '1.2.3.4',
                   '1.2.3-01', '1.2.3-rc..1', '1.2.3+', '1.2.3-a_', '１.2.3',
                   '1.2.3\n', ' 1.2.3', '1.2.3/../../path', '1.2.3+' + 'a' * 128]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for version in invalid:
                with self.subTest(version=repr(version)):
                    with self.assertRaises(ValueError):
                        artifacts.manifest_for(self.commit, self.files, self.archive,
                                              controller_release_version=version)
                    with self.assertRaises(ValueError):
                        artifacts.build(root / 'missing-repo', self.commit, root / 'output',
                                        controller_release_version=version)
                    self.assertFalse((root / 'output').exists())

    def test_cli_invalid_version_fails_without_echoing_input_or_touching_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'output'
            run = subprocess.run([sys.executable, '-S', str(artifacts.ROOT / 'scripts/agent_artifacts.py'),
                                  'build', '--commit', self.commit, '--output-dir', str(output),
                                  '--controller-release-version', 'fixture-sensitive-canary'],
                                 capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 1)
            self.assertNotIn(b'fixture-sensitive-canary', run.stdout + run.stderr)
            self.assertFalse(output.exists())
