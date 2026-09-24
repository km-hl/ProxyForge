"""Verify the CI sample exercises real generation without local runtime data."""

import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import generate_ci_config as generator


class CiGenerationTest(unittest.TestCase):
    def test_real_builder_and_both_static_gates_are_exercised(self):
        template = yaml.safe_load((generator.INPUTS / "sample-template.yaml").read_text())
        nodes = yaml.safe_load((generator.INPUTS / "nodes.yaml").read_text())
        with generator.isolated_application() as application:
            self.assertEqual(Path(application.build_subscription_config.__code__.co_filename), generator.ROOT / "main.py")
            with patch.object(application, "build_subscription_config", wraps=application.build_subscription_config) as build, \
                    patch.object(application, "assert_valid_mihomo_config", wraps=application.assert_valid_mihomo_config) as validate:
                config = generator.build_sample(application)
                self.assertEqual(build.call_count, 1)
                self.assertEqual(validate.call_count, 2)
                self.assertEqual(build.call_args.args[:3], (template, nodes, []))
        self.assertEqual(config["proxies"][0]["name"], "🇭🇰 HK CI SOCKS")
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["🇭🇰 HK CI SOCKS", "DIRECT"])
        self.assertNotIn("use", config["proxy-groups"][0])
        self.assertNotIn("default", config["proxy-groups"][0])
        self.assertNotIn("proxy-providers", config)
        self.assertEqual(config["rules"][0], "DOMAIN,proxy-check.test,🇭🇰 HK CI SOCKS")
        for key in ("dns", "tun", "hosts", "profile", "rule-providers"):
            self.assertEqual(config[key], template[key])

    def test_cli_ignores_caller_env_and_data_and_emits_only_yaml(self):
        script = generator.ROOT / "scripts/generate_ci_config.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            canaries = {".env": "ADMIN_TOKEN=caller-private-canary\n",
                        "data/config.json": "invalid caller runtime data must not be read",
                        "template.yaml": "invalid: [caller template"}
            for name, content in canaries.items():
                (root / name).write_text(content, encoding="utf-8")
            env = {**os.environ, "ADMIN_TOKEN": "short", "SECRET_TOKEN": "caller-private-canary"}
            first = subprocess.run([sys.executable, str(script)], cwd=root, env=env,
                                   capture_output=True, text=True, encoding="utf-8", timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            config = yaml.safe_load(first.stdout)
            self.assertIsInstance(config, dict)
            self.assertTrue(config["dns"]["enable"])
            self.assertNotIn("caller-private-canary", first.stdout + first.stderr)
            second = subprocess.run([sys.executable, str(script), "--output", "generated.yaml"], cwd=root,
                                    env=env, capture_output=True, text=True, encoding="utf-8", timeout=30)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(second.stdout, "")
            self.assertEqual((root / "generated.yaml").read_text(encoding="utf-8"), first.stdout)
            for name, content in canaries.items():
                self.assertEqual((root / name).read_text(encoding="utf-8"), content)
            self.assertEqual({p.name for p in (root / "data").iterdir()}, {"config.json"})
            self.assertFalse((root / "static").exists())

    def test_isolation_restores_process_state_even_when_generation_fails(self):
        previous_cwd, previous_path = Path.cwd(), sys.path[:]
        with patch.dict(os.environ, {"ADMIN_TOKEN": "caller-admin", "SECRET_TOKEN": "caller-subscription"}):
            before = dict(os.environ)
            with self.assertRaisesRegex(RuntimeError, "test failure"):
                with generator.isolated_application():
                    runtime = Path.cwd()
                    self.assertNotEqual(runtime, previous_cwd)
                    raise RuntimeError("test failure")
            self.assertEqual(dict(os.environ), before)
        self.assertEqual(Path.cwd(), previous_cwd)
        self.assertEqual(sys.path, previous_path)
        self.assertNotIn(generator.MODULE_NAME, sys.modules)
        self.assertFalse(runtime.exists())

    def test_invalid_template_still_fails_real_static_validation(self):
        template = yaml.safe_load((generator.INPUTS / "sample-template.yaml").read_text())
        template = copy.deepcopy(template)
        template["dns"]["nameserver"] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample-template.yaml").write_text(yaml.safe_dump(template), encoding="utf-8")
            (root / "nodes.yaml").write_text((generator.INPUTS / "nodes.yaml").read_text(), encoding="utf-8")
            with patch.object(generator, "INPUTS", root), generator.isolated_application() as application:
                with self.assertRaises(application.ConfigValidationError):
                    generator.build_sample(application)


if __name__ == "__main__":
    unittest.main()
