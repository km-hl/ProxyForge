import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import agent_artifacts as artifacts


class AgentArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {path: (artifacts.ROOT / path).read_bytes() for path in artifacts.FILES}
        cls.commit = "a" * 40
        cls.archive = artifacts.archive_bytes(cls.files)
        cls.manifest = artifacts.manifest_for(cls.commit, cls.files, cls.archive)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive_path = self.root / "package.tar"
        self.manifest_path = self.root / "manifest.json"

    def verify(self, archive=None, manifest=None, commit=None, digest=None):
        archive = self.archive if archive is None else archive
        manifest = self.manifest if manifest is None else manifest
        encoded = artifacts.canonical_json(manifest) if isinstance(manifest, dict) else manifest
        self.archive_path.write_bytes(archive)
        self.manifest_path.write_bytes(encoded)
        return artifacts.verify(self.archive_path, self.manifest_path, commit or self.commit,
                                digest or artifacts.sha256(encoded))

    def trusted_bad_archive(self, archive):
        manifest = copy.deepcopy(self.manifest)
        manifest["archive"].update(size=len(archive), sha256=artifacts.sha256(archive))
        return self.verify(archive, manifest)

    def altered_tar(self, *, extra=None, omit=None, mutate=None, tar_format=tarfile.USTAR_FORMAT):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tar_format) as target:
            with tarfile.open(fileobj=io.BytesIO(self.archive), mode="r:") as source:
                for member in source:
                    data = source.extractfile(member).read()
                    if member.name == omit:
                        continue
                    if mutate:
                        mutate(member)
                    target.addfile(member, io.BytesIO(data))
            if extra:
                target.addfile(extra, io.BytesIO(b"X" * extra.size))
        return output.getvalue()

    def test_valid_package_and_isolated_agent_entrypoint(self):
        result = self.verify()
        self.assertEqual(result["agent_version"], "0.6.0")
        self.assertIsNone(result["controller_release_version"])
        extracted = self.root / "isolated"
        # Test-only extraction of already verified fixture bytes; no privileged
        # installation. Running outside the checkout detects missing imports.
        for path, data in self.files.items():
            destination = extracted / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        run = subprocess.run([sys.executable, "-S", "-m", "agent.main", "--help"],
                             cwd=extracted, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertIn(b"register", run.stdout)

    def test_manifest_pin_checked_before_json_or_tar(self):
        with patch.object(artifacts.json, "loads", side_effect=AssertionError("must not parse")):
            with self.assertRaisesRegex(ValueError, "Manifest SHA256"):
                self.verify(archive=b"not tar", manifest=b"not JSON", digest="0" * 64)

    def test_archive_corruption_checked_before_tar_parsing(self):
        changed = bytearray(self.archive)
        changed[1024] ^= 1
        with patch.object(artifacts.tarfile, "open", side_effect=AssertionError("must not parse")):
            with self.assertRaisesRegex(ValueError, "Archive SHA256"):
                self.verify(archive=changed)

    def test_complete_commit_and_expected_identity_required(self):
        for value in ("master", "latest", "a" * 39, "A" * 40, "../path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verify(commit=value)
        with self.assertRaisesRegex(ValueError, "source commit"):
            self.verify(commit="b" * 40)
        with self.assertRaises(ValueError):
            self.verify(digest="bad")

    def test_all_manifest_metadata_and_member_hashes_are_bound(self):
        changes = [
            ("format", 2), ("format", True), ("agent_version", "9.0.0"),
            ("controller_source_commit", "b" * 40), ("controller_release_version", "v9.0.0"),
            ("compatibility", {}), ("files", {}), ("unknown", "untrusted"),
        ]
        for key, value in changes:
            manifest = copy.deepcopy(self.manifest)
            manifest[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.verify(manifest=manifest)
        for key, value in (("sha256", "0" * 64), ("size", 1), ("mode", "0777")):
            manifest = copy.deepcopy(self.manifest)
            manifest["files"]["agent/main.py"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(manifest=manifest)
        for key, value in (("name", "../different.tar"), ("size", 0)):
            manifest = copy.deepcopy(self.manifest)
            manifest["archive"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(manifest=manifest)

    def test_duplicate_noncanonical_or_nonobject_json_rejected(self):
        encoded = artifacts.canonical_json(self.manifest)
        variants = [b"[]", encoded + b" ", b'{"format":1,' + encoded[1:]]
        for variant in variants:
            with self.subTest(variant=variant[:20]), self.assertRaises(ValueError):
                self.verify(manifest=variant)

    def test_missing_extra_duplicate_and_path_escape_members_rejected(self):
        with self.assertRaises(ValueError):
            self.trusted_bad_archive(self.altered_tar(omit="agent/runtime_helper.py"))
        for name in ("agent/main.py", "unexpected", "../escape", "/absolute", "C:/escape",
                     "agent/../../escape", "agent\\main.py"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.trusted_bad_archive(self.altered_tar(extra=tarfile.TarInfo(name)))
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["manifest.json", "package.tar"])

    def test_links_devices_directories_and_pax_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                     tarfile.FIFOTYPE, tarfile.DIRTYPE):
            member = tarfile.TarInfo("agent/main.py")
            member.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "../../outside"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.trusted_bad_archive(self.altered_tar(omit=member.name, extra=member))
        with self.assertRaises(ValueError):
            self.trusted_bad_archive(self.altered_tar(
                mutate=lambda member: member.pax_headers.update(comment="extension"),
                tar_format=tarfile.PAX_FORMAT))

    def test_permissions_owners_time_and_trailing_payload_rejected(self):
        for attr, value in (("mode", 0o4755), ("uid", 1000), ("gid", 1000),
                            ("mtime", 1), ("uname", "untrusted")):
            with self.subTest(attr=attr), self.assertRaises(ValueError):
                self.trusted_bad_archive(self.altered_tar(mutate=lambda m: setattr(m, attr, value)))
        for suffix in (b"payload", self.archive, b"\0" * 10240):
            with self.subTest(size=len(suffix)), self.assertRaises(ValueError):
                self.trusted_bad_archive(self.archive + suffix)

    def test_size_limits_and_truncated_tar(self):
        with patch.object(artifacts, "MAX_MANIFEST", 10), self.assertRaises(ValueError):
            self.verify()
        with patch.object(artifacts, "MAX_ARCHIVE", 100), self.assertRaises(ValueError):
            self.verify()
        with patch.object(artifacts, "MAX_FILE", 10), self.assertRaises(ValueError):
            self.verify()
        with self.assertRaises((ValueError, tarfile.TarError)):
            self.trusted_bad_archive(self.archive[:100])

    def test_version_parsed_without_executing_source(self):
        files = dict(self.files)
        files["agent/__init__.py"] += b'\nraise RuntimeError("must not execute")\n'
        self.assertEqual(artifacts.package_metadata(files)[0], "0.6.0")
        files["agent/__init__.py"] = b'VERSION = get_version()\nPROTOCOL_VERSION = 1\n'
        with self.assertRaises(ValueError):
            artifacts.package_metadata(files)

    def test_compatibility_matches_agent_capabilities_and_package_inputs(self):
        from agent import system_info
        with patch.object(system_info, "runtime_available", return_value=True), \
                patch.object(system_info, "deployment_available", return_value=True), \
                patch.object(system_info, "landing_available", return_value=True), \
                patch.object(system_info, "chain_available", return_value=True), \
                patch.object(system_info, "singbox_status", return_value={}):
            inventory = system_info.collect("artifact-test")
        compatibility = self.manifest["compatibility"]
        for capability, version in compatibility["protocols"].items():
            name = {"inventory": "protocol_version", "jobs": "job_protocol_version"}.get(
                capability, capability + "_protocol_version")
            self.assertEqual(inventory[name], version)
        self.assertEqual(system_info.SUPPORTED, {(os, version) for os, versions in
                         compatibility["platforms"].items() for version in versions})
        inputs = {"agent/" + path.name for path in (artifacts.ROOT / "agent").iterdir() if path.is_file()}
        self.assertEqual(inputs, {path for path in artifacts.FILES if path.startswith("agent/")})

    def git(self, repo, *args):
        return artifacts.git(repo, "-c", "user.name=Artifact Test", "-c",
                             "user.email=artifact@example.invalid", "-c", "core.autocrlf=false",
                             "-c", "commit.gpgsign=false", *args)

    def repository(self):
        repo = self.root / "repo"
        repo.mkdir()
        self.git(repo, "init", "--quiet")
        for path, data in self.files.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        # Even tracked unrelated material must never enter the allowlisted tar.
        (repo / "not-for-package.txt").write_text("private fixture", encoding="utf-8")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "--quiet", "-m", "synthetic artifact fixture")
        return repo, self.git(repo, "rev-parse", "HEAD").decode().strip()

    def test_build_is_repeatable_and_ignores_worktree_and_index_changes(self):
        repo, commit = self.repository()
        first = artifacts.build(repo, commit, self.root / "first")
        (repo / "agent/main.py").write_text("dirty working copy", encoding="utf-8")
        self.git(repo, "add", "agent/main.py")
        (repo / "agent/local.env").write_text("untracked fixture", encoding="utf-8")
        second = artifacts.build(repo, commit, self.root / "second")
        self.assertEqual(first[0].read_bytes(), second[0].read_bytes())
        self.assertEqual(first[1].read_bytes(), second[1].read_bytes())
        self.assertEqual(first[2], second[2])
        self.assertEqual(artifacts.verify(first[0], first[1], commit, first[2])["source_commit"], commit)
        self.assertNotIn(b"private fixture", first[0].read_bytes())
        self.assertNotIn(b"dirty working copy", first[0].read_bytes())
        self.assertNotIn(b"untracked fixture", first[0].read_bytes())
        with self.assertRaises(FileExistsError):
            artifacts.build(repo, commit, self.root / "first")
        self.assertEqual(first[0].read_bytes(), second[0].read_bytes())

    def test_missing_or_git_symlink_input_fails_before_output_creation(self):
        repo, _ = self.repository()
        # Set a symbolic-link mode in Git directly, also exercising Windows.
        self.git(repo, "update-index", "--add", "--cacheinfo", "120000",
                 self.git(repo, "rev-parse", "HEAD:agent/main.py").decode().strip(), "agent/main.py")
        self.git(repo, "commit", "--quiet", "-m", "synthetic symlink")
        bad_commit = self.git(repo, "rev-parse", "HEAD").decode().strip()
        with self.assertRaises(ValueError):
            artifacts.build(repo, bad_commit, self.root / "bad")
        self.assertFalse((self.root / "bad").exists())
        self.git(repo, "update-index", "--force-remove", "agent/main.py")
        self.git(repo, "commit", "--quiet", "-m", "synthetic missing file")
        bad_commit = self.git(repo, "rev-parse", "HEAD").decode().strip()
        with self.assertRaises(ValueError):
            artifacts.build(repo, bad_commit, self.root / "bad")
        self.assertFalse((self.root / "bad").exists())

    def test_git_replace_objects_do_not_change_source_identity(self):
        repo, original = self.repository()
        (repo / "agent/main.py").write_bytes(b"replacement source")
        self.git(repo, "add", "agent/main.py")
        self.git(repo, "commit", "--quiet", "-m", "replacement fixture")
        replacement = self.git(repo, "rev-parse", "HEAD").decode().strip()
        self.git(repo, "replace", original, replacement)
        self.assertEqual(artifacts.source_files(repo, original)["agent/main.py"], self.files["agent/main.py"])

    def test_cli_failure_has_nonzero_exit_and_does_not_echo_input(self):
        run = subprocess.run([sys.executable, "-S", str(artifacts.ROOT / "scripts/agent_artifacts.py"),
                              "build", "--commit", "bad-fixture-value", "--output-dir", str(self.root / "bad")],
                             capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertNotIn(b"bad-fixture-value", run.stdout + run.stderr)
        self.assertFalse((self.root / "bad").exists())


if __name__ == "__main__":
    unittest.main()
