import ast
import json
import logging
import os
import secrets
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load_runtime_config_functions():
    source = Path(__file__).resolve().parents[1] / "main.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    wanted = {
        "get_env_var",
        "save_runtime_config",
        "load_or_create_secret_token",
    }
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    namespace = {
        "json": json,
        "logger": logging.getLogger("runtime-config-test"),
        "os": os,
        "secrets": secrets,
        "RUNTIME_CONFIG_PATH": "",
        "INSECURE_DEFAULT_TOKENS": {"", "my_secret_token"},
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace


class RuntimeConfigTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.temp_dir.name) / "data" / "config.json"
        self.functions = load_runtime_config_functions()
        for name in ("save_runtime_config", "load_or_create_secret_token"):
            self.functions[name].__globals__.update({
                "RUNTIME_CONFIG_PATH": str(self.config_path),
                "INSECURE_DEFAULT_TOKENS": {"", "my_secret_token"},
            })

    def tearDown(self):
        self.temp_dir.cleanup()

    def read_token(self):
        return json.loads(self.config_path.read_text(encoding="utf-8"))["secret_token"]

    def test_environment_token_is_migrated_once(self):
        with patch.dict(os.environ, {"SECRET_TOKEN": "existing-secure-token"}, clear=False):
            token = self.functions["load_or_create_secret_token"]()

        self.assertEqual(token, "existing-secure-token")
        self.assertEqual(self.read_token(), token)

    def test_persisted_token_wins_over_stale_environment(self):
        self.functions["save_runtime_config"]("persisted-secure-token")

        with patch.dict(os.environ, {"SECRET_TOKEN": "stale-environment-token"}, clear=False):
            token = self.functions["load_or_create_secret_token"]()

        self.assertEqual(token, "persisted-secure-token")

    def test_missing_token_generates_and_persists_strong_random_value(self):
        with patch.dict(os.environ, {}, clear=True):
            token = self.functions["load_or_create_secret_token"]()

        self.assertGreaterEqual(len(token), 32)
        self.assertNotEqual(token, "my_secret_token")
        self.assertEqual(self.read_token(), token)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o600)

    def test_public_default_token_is_rotated(self):
        with patch.dict(os.environ, {"SECRET_TOKEN": "my_secret_token"}, clear=False):
            token = self.functions["load_or_create_secret_token"]()

        self.assertNotEqual(token, "my_secret_token")
        self.assertEqual(self.read_token(), token)

    def test_persisted_public_default_token_is_rotated(self):
        self.functions["save_runtime_config"]("my_secret_token")

        token = self.functions["load_or_create_secret_token"]()

        self.assertNotEqual(token, "my_secret_token")
        self.assertEqual(self.read_token(), token)

    def test_corrupt_persisted_config_fails_closed_without_using_stale_environment(self):
        self.config_path.parent.mkdir(parents=True)
        self.config_path.write_text("{not-json", encoding="utf-8")

        with patch.dict(os.environ, {"SECRET_TOKEN": "stale-environment-token"}, clear=False):
            with self.assertRaises(RuntimeError):
                self.functions["load_or_create_secret_token"]()

        self.assertEqual(self.config_path.read_text(encoding="utf-8"), "{not-json")


if __name__ == "__main__":
    unittest.main()
