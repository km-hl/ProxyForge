import gzip
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import agent_bootstrap as bootstrap


class AgentBootstrapTests(unittest.TestCase):
    def archive(self, *, extra=None, omit=None, kind=None, pax=None):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name in sorted(bootstrap.FILES):
                if name == omit:
                    continue
                member = tarfile.TarInfo(bootstrap.PREFIX + "/agent/" + name)
                member.pax_headers = {"comment": bootstrap.SOURCE_COMMIT} if pax is None else pax
                data = ("fixture " + name).encode()
                member.size = len(data)
                if kind and name == "main.py":
                    member.type, member.linkname, member.size = kind, "../../outside", 0
                archive.addfile(member, io.BytesIO(data))
            if extra:
                archive.addfile(extra, io.BytesIO(b""))
        return gzip.compress(content.getvalue())

    def verified(self, data):
        with patch.object(bootstrap, "SOURCE_SHA256", hashlib.sha256(data).hexdigest()):
            return bootstrap.verified_files(data)

    def test_valid_archive_selects_only_complete_agent_package(self):
        other = tarfile.TarInfo(bootstrap.PREFIX + "/unrelated.txt")
        files = self.verified(self.archive(extra=other))
        self.assertEqual(set(files), bootstrap.FILES)
        self.assertEqual(files["main.py"], b"fixture main.py")

    def test_hash_checked_before_gzip_or_archive_parse(self):
        with patch.object(bootstrap.gzip, "GzipFile", side_effect=AssertionError("must not parse")):
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.verified_files(b"untrusted data")

    def test_rejects_paths_duplicates_links_and_devices(self):
        for name in ("/absolute", "../escape", bootstrap.PREFIX + "/../escape",
                     bootstrap.PREFIX + "/agent/main.py", bootstrap.PREFIX + "/agent\\outside",
                     bootstrap.PREFIX + "/C:/outside", "other/agent/main.py",
                     bootstrap.PREFIX + "/./outside", bootstrap.PREFIX + "//outside"):
            with self.subTest(name=name), self.assertRaises(bootstrap.InstallError):
                self.verified(self.archive(extra=tarfile.TarInfo(name)))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaises(bootstrap.InstallError):
                self.verified(self.archive(kind=kind))

    def test_missing_member_pax_override_and_expansion_limits(self):
        with self.assertRaises(bootstrap.InstallError):
            self.verified(self.archive(omit="runtime_helper.py"))
        with self.assertRaises(bootstrap.InstallError):
            self.verified(self.archive(pax={"mtime": "100"}))
        data = self.archive()
        with patch.object(bootstrap, "MAX_DOWNLOAD", 10), self.assertRaises(bootstrap.InstallError):
            self.verified(data)
        with patch.object(bootstrap, "MAX_EXPANDED", 100), self.assertRaises(bootstrap.InstallError):
            self.verified(data)
        with patch.object(bootstrap, "MAX_FILE", 1), self.assertRaises(bootstrap.InstallError):
            self.verified(data)

    def test_controller_url_accepts_root_https_and_rejects_injection_credentials(self):
        for value in ("https://controller.example", "https://controller.example:8443/",
                      "https://8.8.8.8", "https://[2606:4700:4700::1111]"):
            self.assertEqual(bootstrap.controller_url(value), value.rstrip("/"))
        for value in ("http://controller.example", "https://user:secret@controller.example",
                      "https://controller.example/?token=test-token", "https://controller.example/#",
                      "https://controller.example/path", "https://controller.example:0",
                      "https://controller.example:99999", "https://controller.example:bad", "https://controller.example:",
                      "https://localhost", "https://127.0.0.1", "https://10.0.0.1",
                      "https://[::1]", "https://a.example\n", "https://a.example;id",
                      "https://$(id).example", "https://a.example\\evil", "https://a..example",
                      "https://a.example/?", "https://2130706433", "https://0177.0.0.1"):
            with self.subTest(value=value), self.assertRaises(bootstrap.InstallError):
                bootstrap.controller_url(value)

    def test_download_rejects_redirect_status_oversize_and_timeout(self):
        with self.assertRaises(bootstrap.InstallError):
            bootstrap.NoRedirect().redirect_request(None, None, 302, None, None, "http://other")
        for status, size, times in ((503, 0, [0]), (200, 20, [0, 0]), (200, 1, [0, 61])):
            response = SimpleNamespace(status=status, read1=io.BytesIO(b"x" * size).read1)
            manager = unittest.mock.MagicMock()
            manager.__enter__.return_value = response
            opener = unittest.mock.Mock()
            opener.open.return_value = manager
            with self.subTest(status=status, size=size), \
                    patch.object(bootstrap.urllib.request, "build_opener", return_value=opener), \
                    patch.object(bootstrap, "MAX_DOWNLOAD", 10), \
                    patch.object(bootstrap.time, "monotonic", side_effect=times), \
                    self.assertRaises(bootstrap.InstallError):
                bootstrap.download()

    def test_failed_preflight_and_bad_download_never_execute_installer(self):
        with patch.object(bootstrap, "preflight", side_effect=bootstrap.InstallError("blocked")), \
                patch.object(bootstrap, "download") as download, patch.object(bootstrap.subprocess, "run") as run:
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.install("install", "https://controller.example")
            download.assert_not_called()
            run.assert_not_called()
        with patch.object(bootstrap, "preflight"), patch.object(bootstrap, "download", return_value=b"bad"), \
                patch.object(bootstrap.subprocess, "run") as run:
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.install("install", "https://controller.example")
            run.assert_not_called()

    def test_staging_uses_verified_bytes_and_clean_environment_and_cleans_only_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "stage"
            stage.mkdir()
            sentinel = Path(directory) / "keep-config"
            sentinel.write_text("keep", encoding="utf-8")
            files = {"install.sh": b"never execute this fixture", "main.py": b"verified bytes"}

            def inspect(args, **kwargs):
                self.assertEqual(args, ["/bin/bash", "-p", str(stage / "agent/install.sh"),
                                        "https://controller.example"])
                self.assertEqual((stage / "agent/main.py").read_bytes(), b"verified bytes")
                self.assertEqual(kwargs["env"], bootstrap.SAFE_ENV)
                self.assertNotIn("BASH_ENV", kwargs["env"])
                self.assertNotIn("PYTHONPATH", kwargs["env"])
                raise subprocess.CalledProcessError(1, args)

            with patch.object(bootstrap, "preflight") as check, patch.object(bootstrap, "download"), \
                    patch.object(bootstrap, "verified_files", return_value=files), \
                    patch.object(bootstrap, "trusted_directory"), patch.object(bootstrap, "trusted_file"), \
                    patch.object(bootstrap.tempfile, "mkdtemp", return_value=str(stage)), \
                    patch.object(bootstrap.subprocess, "run", side_effect=inspect):
                with self.assertRaises(subprocess.CalledProcessError):
                    bootstrap.install("install", "https://controller.example/")
                self.assertEqual(check.call_count, 2)
            self.assertFalse(stage.exists())
            self.assertEqual(sentinel.read_text(), "keep")

    def test_runtime_requires_matching_installed_package_before_staging(self):
        with patch.object(bootstrap, "preflight"), patch.object(bootstrap, "download"), \
                patch.object(bootstrap, "verified_files", return_value={}), \
                patch.object(bootstrap, "check_installed_agent", side_effect=bootstrap.InstallError("mismatch")), \
                patch.object(bootstrap.tempfile, "mkdtemp") as create:
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.install("runtime")
            create.assert_not_called()

    def test_existing_or_dangling_target_rejected_before_download(self):
        fake_os = SimpleNamespace(name="posix", geteuid=lambda: 0,
                                  path=SimpleNamespace(lexists=lambda path: path == bootstrap.AGENT_TARGETS[0]))
        with patch.object(bootstrap, "os", fake_os), patch.object(bootstrap.platform, "system", return_value="Linux"), \
                patch.object(bootstrap.platform, "machine", return_value="x86_64"), \
                patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="24.04"'), \
                patch.object(Path, "is_dir", return_value=True), patch.object(bootstrap, "trusted_directory"), \
                patch.object(bootstrap, "download") as download:
            with self.assertRaisesRegex(bootstrap.InstallError, "已有安装"):
                bootstrap.install("install", "https://controller.example")
            download.assert_not_called()

    def test_installed_agent_must_match_every_pinned_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {name: name.encode() for name in bootstrap.INSTALLED_FILES}
            for name, data in files.items():
                (root / name).write_bytes(data)
            with patch.object(bootstrap, "Path", return_value=root), \
                    patch.object(bootstrap, "trusted_directory"), patch.object(bootstrap, "trusted_file"):
                bootstrap.check_installed_agent(files)
                (root / "client.py").write_bytes(b"different installed version")
                with self.assertRaisesRegex(bootstrap.InstallError, "版本不同"):
                    bootstrap.check_installed_agent(files)

    def test_root_ownership_links_writable_parents_and_hardlinks_rejected(self):
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_nlink=1)
        with patch.object(Path, "lstat", return_value=directory):
            bootstrap.trusted_directory("/var/lib")
        for mode, uid in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFDIR | 0o777, 0),
                          (stat.S_IFDIR | 0o755, 1000)):
            info = SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=1)
            with self.subTest(mode=mode, uid=uid), patch.object(Path, "lstat", return_value=info), \
                    self.assertRaises(bootstrap.InstallError):
                bootstrap.trusted_directory("/var/lib")
        for mode, uid, links in ((stat.S_IFLNK | 0o777, 0, 1), (stat.S_IFREG | 0o666, 0, 1),
                                (stat.S_IFREG | 0o644, 1000, 1), (stat.S_IFREG | 0o644, 0, 2)):
            info = SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)
            with self.subTest(mode=mode, uid=uid, links=links), \
                    patch.object(bootstrap, "trusted_directory"), patch.object(Path, "lstat", return_value=info), \
                    self.assertRaises(bootstrap.InstallError):
                bootstrap.trusted_file(Path("/var/lib/file"))

    @unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "real root path checks require disposable Linux runner")
    def test_real_root_paths_reject_symlink_writable_directory_and_hardlink(self):
        with tempfile.TemporaryDirectory(prefix="proxyforge-bootstrap-test-", dir="/var/lib") as directory:
            root = Path(directory)
            bootstrap.trusted_directory(root)
            file = root / "file"
            file.write_bytes(b"fixture")
            file.chmod(0o644)
            bootstrap.trusted_file(file)
            link = root / "link"
            link.symlink_to(file)
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.trusted_file(link)
            hardlink = root / "hardlink"
            os.link(file, hardlink)
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.trusted_file(file)
            hardlink.unlink()
            os.chown(file, 12345, 12345)
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.trusted_file(file)
            os.chown(file, 0, 0)
            root.chmod(0o777)
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.trusted_directory(root)
            root.chmod(0o700)

    def test_cli_check_only_needs_isolation_not_root(self):
        with patch.object(sys, "argv", ["bootstrap", "check"]), \
                patch.object(bootstrap.sys, "flags", SimpleNamespace(isolated=True)), \
                patch.object(bootstrap, "download"), patch.object(bootstrap, "verified_files", return_value={}), \
                patch.object(bootstrap, "install") as install:
            bootstrap.main()
            install.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires Linux controlling PTY")
    def test_preflight_accepts_real_controlling_tty(self):
        fixture = Path(__file__).parent / "fixtures" / "agent_tty_preflight.py"
        result = subprocess.run([sys.executable, "-S", str(fixture), "pty"],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b"preflight accepted real TTY", result.stdout)

    @unittest.skipUnless(os.name == "posix", "requires Linux session semantics")
    def test_preflight_rejects_missing_controlling_tty(self):
        fixture = Path(__file__).parent / "fixtures" / "agent_tty_preflight.py"
        result = subprocess.run([sys.executable, "-S", str(fixture), "no-tty"],
                                capture_output=True, timeout=15, start_new_session=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b"preflight rejected absent TTY", result.stdout)


if __name__ == "__main__":
    unittest.main()
