import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import installation_diagnostics as diagnostics


class InstallationDiagnosticsTests(unittest.TestCase):
    def collect(self, root, run, result=None, **kwargs):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            summary = diagnostics.helper_failure_summary(
                'singbox.restart', result or {'error': 'runtime_failed'}, root=root, run=run, **kwargs)
        self.assertEqual(json.loads(stream.getvalue().split(': ', 1)[1]), summary)
        return summary, stream.getvalue()

    def test_selected_properties_and_protocol_error_are_preserved_without_raw_output(self):
        calls = []
        secret = 'private-config-body-and-token'
        def run(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0,
                'ActiveState=active\nSubState=running\nResult=success\nMainPID=42\nNRestarts=1\n'
                'ExecMainStatus=0\nEnvironment=' + secret + '\nResult=' + secret, secret)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'transaction.json').write_text(secret)
            summary, output = self.collect(root, run)
        self.assertNotIn(secret, output)
        self.assertTrue(summary['transaction_present'])
        self.assertEqual(summary['error'], 'runtime_failed')
        self.assertEqual(summary['services']['proxyforge-singbox.service']['properties']['MainPID'], 42)
        self.assertEqual(summary['services']['proxyforge-singbox.service']['properties']['Result'], 'unknown')
        self.assertTrue(all(args[1] == 'show' for args in calls))

    def test_probe_failures_never_format_exception_text_and_do_not_hide_original_failure(self):
        def run(args, **kwargs):
            if 'runtime.service' in args[2]:
                raise subprocess.TimeoutExpired(args, 10, output='private-timeout-output')
            raise OSError('private-error-text')
        with tempfile.TemporaryDirectory() as folder:
            summary, output = self.collect(Path(folder), run, {'error': 'rollback_failed'})
        self.assertNotIn('private-', output)
        self.assertTrue(summary['services']['proxyforge-runtime.service']['timed_out'])
        self.assertTrue(summary['services']['proxyforge-singbox.service']['unavailable'])
        self.assertEqual(summary['error'], 'rollback_failed')

    def test_unknown_error_fields_are_not_logged(self):
        def run(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, '', 'private-stderr')
        with tempfile.TemporaryDirectory() as folder:
            summary, output = self.collect(Path(folder), run, {'error': ['private-list'], 'output': 'private-output'})
        self.assertEqual(summary['error'], 'unknown')
        self.assertNotIn('private-', output)

    def test_binary_diagnostics_use_original_budgets_and_runtime_uid_without_service_mutation(self):
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs))
            if args[-1] == 'version':
                raise subprocess.TimeoutExpired(args, 5, output='private-version-output')
            return subprocess.CompletedProcess(args, 0, 'private-config-output', '')
        root = Path('/fixture')
        info = type('Info', (), {'st_mode': 0o100640, 'st_uid': 0})()
        with patch.object(diagnostics.os, 'readlink', return_value='releases/' + 'a' * 32), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'lstat', return_value=info):
            summary = diagnostics.current_binary_summary(root, run, lambda: (123, 456))
        self.assertTrue(summary['version_probe']['timed_out'])
        self.assertEqual(summary['config_probe']['returncode'], 0)
        self.assertEqual([entry[1]['timeout'] for entry in calls], [5, 20])
        self.assertTrue(all(options['user'] == 123 and options['group'] == 456 and options['extra_groups'] == []
                            for _, options in calls))
        self.assertEqual([args[1] for args, _ in calls], ['version', 'check'])

    def test_invalid_generation_pointer_does_not_execute_binary(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(diagnostics.os, 'readlink', return_value='../../private'), \
                patch.object(diagnostics.subprocess, 'run') as run:
            result = diagnostics.current_binary_summary(Path(folder), run, lambda: (123, 456))
        self.assertEqual(result, {'valid_pointer': False})
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
