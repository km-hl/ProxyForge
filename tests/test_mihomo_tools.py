"""Test harness failure handling without downloading or executing Mihomo."""

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_mihomo, download_mihomo


class MihomoToolsTest(unittest.TestCase):
    def test_checked_in_manifest_covers_all_fixtures(self):
        cases = check_mihomo.load_cases(check_mihomo.FIXTURES)
        self.assertTrue(any(case["exit_code"] == 0 for case in cases))
        self.assertTrue(any(case["exit_code"] == 1 for case in cases))

    def test_missing_unlisted_and_duplicate_fixtures_fail_closed(self):
        case = {"file": "valid.yaml", "exit_code": 0}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "cases.json"
            manifest.write_text(json.dumps([case]), encoding="utf-8")
            with self.assertRaises(ValueError):
                check_mihomo.load_cases(root)
            (root / "valid.yaml").write_text("{}", encoding="utf-8")
            (root / "unlisted.yaml").write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                check_mihomo.load_cases(root)
            manifest.write_text(json.dumps([case, case]), encoding="utf-8")
            with self.assertRaises(ValueError):
                check_mihomo.load_cases(root)

    def test_negative_case_requires_specific_parser_error(self):
        case = {"exit_code": 1, "error_contains": "NameServer cannot be empty"}
        self.assertTrue(check_mihomo.matches(case, 1, "NameServer cannot be empty\ntest failed"))
        for code, output in ((1, "download failed\ntest failed"), (2, "panic"),
                             (None, "TIMEOUT"), (0, "test is successful")):
            self.assertFalse(check_mihomo.matches(case, code, output))

    def test_success_requires_parser_success_marker(self):
        self.assertTrue(check_mihomo.matches({"exit_code": 0}, 0, "configuration file test is successful"))
        self.assertFalse(check_mihomo.matches({"exit_code": 0}, 0, ""))

    def test_timeout_and_missing_executable_are_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            code, output = check_mihomo.invoke(
                [sys.executable, "-c", "import time; time.sleep(10)"], directory, 0.25)
            self.assertIsNone(code)
            self.assertIn("TIMEOUT", output)
            code, output = check_mihomo.invoke([str(Path(directory) / "missing")], directory, 1)
            self.assertIsNone(code)
            self.assertIn("Unable to launch", output)

    def test_developer_config_overrides_are_removed(self):
        with patch.dict(os.environ, {"CLASH_CONFIG_STRING": "unrelated", "CLASH_OVERRIDE_SECRET": "test"}):
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ok")) as run:
                check_mihomo.invoke(["mihomo", "-t"], ".", 5)
                env = run.call_args.kwargs["env"]
                self.assertNotIn("CLASH_CONFIG_STRING", env)
                self.assertNotIn("CLASH_OVERRIDE_SECRET", env)

    def test_checksum_mismatch_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "archive.gz"
            archive.write_bytes(b"corrupted download")
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                download_mihomo.verify_archive(archive, "0" * 64)
            download_mihomo.verify_archive(archive, hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_wrong_binary_version_aborts_before_fixtures(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            with patch.object(check_mihomo, "invoke", return_value=(0, "Mihomo Meta v1.19.310 linux amd64")) as invoke:
                result = check_mihomo.check(Path("mihomo"), check_mihomo.FIXTURES, Path(directory), 5)
                self.assertEqual(result, 1)
                self.assertEqual(invoke.call_count, 1)
                self.assertTrue((Path(directory) / "version.log").is_file())

    def test_all_cases_run_and_failures_leave_logs(self):
        cases = check_mihomo.load_cases(check_mihomo.FIXTURES)
        version = json.loads((check_mihomo.FIXTURES / "release.json").read_text())["version"]
        replies = [(0, f"Mihomo Meta {version} linux amd64")]
        replies += [(1, "unexpected parser error\ntest failed") for _ in cases]
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            with patch.object(check_mihomo, "invoke", side_effect=replies) as invoke:
                result = check_mihomo.check(Path("mihomo"), check_mihomo.FIXTURES, Path(directory), 5)
                self.assertEqual(result, 1)
                self.assertEqual(invoke.call_count, len(cases) + 1)
                homes = [call.args[1] for call in invoke.call_args_list[1:]]
                self.assertEqual(len(set(homes)), len(cases))
                results = json.loads((Path(directory) / "results.json").read_text())
                self.assertEqual(len(results), len(cases))
                self.assertTrue(all(not item["passed"] for item in results))
                for case in cases:
                    self.assertTrue((Path(directory) / (Path(case["file"]).stem + ".log")).is_file())


if __name__ == "__main__":
    unittest.main()
