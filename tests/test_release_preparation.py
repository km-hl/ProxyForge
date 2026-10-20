"""固定提交、中文说明、隐私检查与候选包校验的集成回归。"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import agent_artifacts as artifacts
from scripts import prepare_release as releases


VERSION = '0.0.0-fixture.1'


def notes(version=VERSION):
    return (f'# ProxyForge Controller {version} 发布说明\n\n' +
            '\n'.join(f'## {heading}\n\n合成测试说明，不代表已发布或生产验收。\n'
                      for heading in releases.SECTIONS)).encode('utf-8')


class ReleasePreparationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '--quiet')
        for path in artifacts.FILES:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((artifacts.ROOT / path).read_bytes())
        self.notes_path = self.repo / f'docs/releases/{VERSION}.md'
        self.notes_path.parent.mkdir(parents=True, exist_ok=True)
        self.notes_path.write_bytes(notes())
        self.commit = self.save()
        self.output = self.root / 'candidate'

    def git(self, *args):
        return artifacts.git(self.repo, '-c', 'user.name=Release Fixture', '-c',
            'user.email=release@example.invalid', '-c', 'core.autocrlf=false', '-c',
            'commit.gpgsign=false', *args)

    def save(self):
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'synthetic release fixture')
        return self.git('rev-parse', 'HEAD').decode().strip()

    def build(self):
        return releases.prepare(self.repo, self.commit, VERSION, self.output)

    def tool_command(self):
        scripts = self.repo / 'scripts'
        scripts.mkdir(exist_ok=True)
        for name in ['prepare_release.py', 'agent_artifacts.py', 'check_repository_privacy.py']:
            (scripts / name).write_bytes((releases.ROOT / 'scripts' / name).read_bytes())
        return [sys.executable, '-S', str(scripts / 'prepare_release.py')]

    def test_repeatable_release_uses_only_selected_git_objects_and_verifies(self):
        first = self.build()
        self.notes_path.write_text('dirty working tree', encoding='utf-8')
        (self.repo / 'agent/main.py').write_text('dirty working tree', encoding='utf-8')
        self.git('add', '.')
        second_dir = self.root / 'second'
        second = releases.prepare(self.repo, self.commit, VERSION, second_dir)
        self.assertEqual(first, second)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()},
                         {p.name: p.read_bytes() for p in second_dir.iterdir()})
        metadata = releases.verify(self.output, self.commit, VERSION, first)
        self.assertEqual(metadata['tag'], 'v' + VERSION)
        self.assertEqual(metadata['controller_version'], VERSION)
        self.assertEqual(metadata['source_commit'], self.commit)
        self.assertEqual(metadata['agent_version'], '0.6.0')
        self.assertEqual(metadata['compatibility']['controller_schema_baseline'], 5)
        self.assertEqual((self.output / 'RELEASE_NOTES.zh-CN.md').read_bytes(), notes())
        self.assertEqual(len(list(self.output.iterdir())), 5)
        with self.assertRaises(FileExistsError):
            self.build()

    def test_missing_linked_and_unfinished_notes_fail_before_output(self):
        self.git('update-index', '--force-remove', f'docs/releases/{VERSION}.md')
        self.git('commit', '--quiet', '-m', 'missing fixture notes')
        missing = self.git('rev-parse', 'HEAD').decode().strip()
        with self.assertRaises(ValueError):
            releases.prepare(self.repo, missing, VERSION, self.output)
        self.assertFalse(self.output.exists())
        oid = self.git('rev-parse', self.commit + f':docs/releases/{VERSION}.md').decode().strip()
        self.git('update-index', '--add', '--cacheinfo', '120000', oid, f'docs/releases/{VERSION}.md')
        self.git('commit', '--quiet', '-m', 'linked fixture notes')
        linked = self.git('rev-parse', 'HEAD').decode().strip()
        with self.assertRaises(ValueError):
            releases.prepare(self.repo, linked, VERSION, self.output)
        self.assertFalse(self.output.exists())
        for invalid in [notes().replace('合成'.encode(), '待填写'.encode()),
                        notes().replace(b'## ', b'### ', 1), notes('9.9.9'),
                        notes().replace('合成测试说明，不代表已发布或生产验收。'.encode(), b'', 1),
                        notes().replace('合成测试说明，不代表已发布或生产验收。'.encode(), b'English only', 1)]:
            with self.subTest(prefix=invalid[:50]), self.assertRaises(ValueError):
                releases.validate_notes(invalid, VERSION)
        with patch.object(releases, 'MAX_NOTES', 10), self.assertRaises(ValueError):
            releases.validate_notes(notes(), VERSION)

    def test_selected_commit_privacy_is_checked_even_if_worktree_is_cleaned(self):
        for path, content in [('.env', b'private fixture'),
                              ('private.txt', b'https://private.example/sub?token=' + b'fixture')]:
            target = self.repo / path
            target.write_bytes(content)
            private_commit = self.save()
            target.write_bytes(b'clean working tree')
            with self.subTest(path=path), self.assertRaises(ValueError):
                releases.prepare(self.repo, private_commit, VERSION, self.output)
            self.assertFalse(self.output.exists())
            self.git('rm', '--force', path)
            self.git('commit', '--quiet', '-m', 'remove private fixture')

    def test_metadata_pin_checked_before_json_and_expected_identity_is_required(self):
        digest = self.build()
        with patch.object(releases.json, 'loads', side_effect=AssertionError('must not parse')):
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                releases.verify(self.output, self.commit, VERSION, '0' * 64)
        for commit, version in [('b' * 40, VERSION), (self.commit, '0.0.0-fixture.2')]:
            with self.subTest(commit=commit, version=version), self.assertRaises(ValueError):
                releases.verify(self.output, commit, version, digest)

    def test_lf_crlf_and_utf8_bom_preserve_committed_notes_bytes(self):
        for content in [notes(), notes().replace(b'\n', b'\r\n'), b'\xef\xbb\xbf' + notes()]:
            with self.subTest(prefix=content[:20]):
                self.assertEqual(releases.validate_notes(content, VERSION), content)
        with self.assertRaises(ValueError):
            releases.validate_notes(b'\xff', VERSION)

    def test_rehashed_metadata_cannot_relabel_or_add_fields(self):
        self.build()
        path = self.output / 'release.json'
        original = json.loads(path.read_bytes())
        for field, value in [('source_commit', 'b' * 40), ('controller_version', '9.9.9'),
                             ('tag', 'latest'), ('agent_version', '9.9.9'), ('compatibility', {}),
                             ('notes', {}), ('unknown', True)]:
            changed = copy.deepcopy(original)
            changed[field] = value
            encoded = artifacts.canonical_json(changed)
            path.write_bytes(encoded)
            with self.subTest(field=field), self.assertRaises(ValueError):
                releases.verify(self.output, self.commit, VERSION, artifacts.sha256(encoded))

    def test_corrupt_missing_extra_and_noncanonical_assets_are_rejected(self):
        digest = self.build()
        for path in self.output.iterdir():
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            with self.subTest(asset=path.name), self.assertRaises(ValueError):
                releases.verify(self.output, self.commit, VERSION, digest)
            path.write_bytes(original)
        extra = self.output / 'unexpected.txt'
        extra.write_bytes(b'fixture')
        with self.assertRaises(ValueError):
            releases.verify(self.output, self.commit, VERSION, digest)
        extra.unlink()
        (self.output / 'SHA256SUMS').unlink()
        with self.assertRaises(ValueError):
            releases.verify(self.output, self.commit, VERSION, digest)

    def test_invalid_version_and_cli_failure_do_not_echo_input_or_create_output(self):
        for version in [None, '', 'v1.2.3', '1.2.3\n', '../outside', '1.2.3-foo.lock']:
            with self.subTest(version=version), self.assertRaises(ValueError):
                releases.prepare(self.repo, self.commit, version, self.output)
            self.assertFalse(self.output.exists())
        run = subprocess.run([sys.executable, '-S', str(releases.ROOT / 'scripts/prepare_release.py'),
            'build', '--commit', self.commit, '--version', 'fixture-sensitive-canary',
            '--directory', str(self.output)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertNotIn(b'fixture-sensitive-canary', run.stdout + run.stderr)
        self.assertFalse(self.output.exists())

    def test_cli_round_trip_from_trusted_tool_copy_does_not_create_git_refs(self):
        command = self.tool_command()
        before = self.git('for-each-ref')
        arguments = ['--commit', self.commit, '--version', VERSION, '--directory', str(self.output)]
        built = subprocess.run(command + ['build'] + arguments, capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
        digest = artifacts.sha256((self.output / 'release.json').read_bytes())
        self.assertIn(digest.encode(), built.stdout)
        verified = subprocess.run(command + ['verify'] + arguments + ['--metadata-sha256', digest],
                                  capture_output=True, timeout=30)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode(errors='replace'))
        self.assertEqual(self.git('for-each-ref'), before)

    def test_cli_deep_metadata_reports_generic_failure_without_echo_or_traceback(self):
        self.build()
        encoded = b'[' * 20000 + b'"fixture-sensitive-canary"' + b']' * 20000
        (self.output / 'release.json').write_bytes(encoded)
        run = subprocess.run(self.tool_command() + ['verify', '--commit', self.commit,
            '--version', VERSION, '--directory', str(self.output),
            '--metadata-sha256', artifacts.sha256(encoded)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertNotIn(b'fixture-sensitive-canary', run.stdout + run.stderr)
        self.assertNotIn(b'Traceback', run.stdout + run.stderr)
