"""Keep Controller library imports safe and the standalone Agent distributable."""
import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackageBoundariesTest(unittest.TestCase):
    def test_controller_libraries_import_without_loading_app_or_creating_runtime_files(self):
        # Fresh process catches circular imports and dependencies hidden by other tests.
        modules = sorted('.'.join(path.relative_to(ROOT).with_suffix('').parts)
                         for path in (ROOT / 'proxyforge').rglob('*.py') if path.name != '__init__.py')
        code = ('import importlib, sys; '
                'sys.path.insert(0, sys.argv[1]); '
                '[importlib.import_module(name) for name in sys.argv[2:]]; '
                'assert "main" not in sys.modules')
        with tempfile.TemporaryDirectory() as directory:
            canary = Path(directory) / '.env'
            canary.write_text('ADMIN_TOKEN=invalid-import-canary\n', encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', '-c', code, str(ROOT), *modules],
                                    cwd=directory, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ['.env'])
            self.assertEqual(canary.read_text(), 'ADMIN_TOKEN=invalid-import-canary\n')

    def test_agent_does_not_depend_on_controller_package(self):
        # Installer only copies agent/, so even a lazy Controller import would break it.
        for path in (ROOT / 'agent').glob('*.py'):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or '']
                else:
                    continue
                self.assertTrue(all(name.split('.')[0] not in {'proxyforge', 'main'} for name in names),
                                f'{path.name}:{node.lineno}: Agent must remain independent')
