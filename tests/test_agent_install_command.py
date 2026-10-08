import hashlib
import io
from pathlib import Path
import re
import unittest
from unittest.mock import MagicMock, patch

from scripts.agent_install_command import render


class AgentInstallCommandTests(unittest.TestCase):
    commit = "a" * 40

    def test_console_pins_and_validation_match_standalone_bootstrap(self):
        from proxyforge.control.agent_installation import installation_info, controller_url
        from scripts.agent_bootstrap import controller_url as bootstrap_url
        document = Path('docs/AGENT_INSTALL.md').read_text(encoding='utf-8')
        info = installation_info('https://your-controller.example')
        for command in info['commands'].values():
            self.assertIn(command, document)
        for value in ('https://example.com/', 'https://example.com:8443', 'https://[2606:4700:4700::1111]',
                      None, '', 'http://example.com', 'https://localhost', 'https://a.example:0',
                      'https://a.example/path', 'https://a.example/#', 'https://a.example/?',
                      'https://a.example\\evil', 'https://a.example\n', 'https://10.0.0.1'):
            try:
                expected = bootstrap_url(value)
            except ValueError:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    controller_url(value)
            else:
                self.assertEqual(controller_url(value), expected)

    def command(self, code, **kwargs):
        return render(self.commit, hashlib.sha256(code).hexdigest(), **kwargs)

    def execute_wrapper(self, command, payload):
        response = MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read = io.BytesIO(payload).read
        opener = MagicMock()
        opener.open.return_value = response
        wrapper = command.split("\n", 1)[1].rsplit("PROXYFORGE_BOOTSTRAP", 1)[0]
        with patch("urllib.request.build_opener", return_value=opener), patch("sys.argv", ["-", "check"]):
            exec(compile(wrapper, "<wrapper-test>", "exec"), {})

    def test_fixed_source_hash_clean_environment_and_no_token_argument(self):
        command = self.command(b"print('fixture')", server="https://controller.example:8443/")
        self.assertIn("sudo /usr/bin/env -i PATH=", command)
        self.assertIn("/usr/bin/python3 -I - install --server https://controller.example:8443", command)
        self.assertIn("/" + self.commit + "/scripts/agent_bootstrap.py", command)
        self.assertNotIn("token", command.lower())
        self.assertNotIn("latest", command)
        self.assertNotIn("master", command)

    def test_wrapper_executes_only_exact_verified_bytes(self):
        payload = b"raise RuntimeError('verified fixture executed')"
        command = self.command(payload, action="check")
        self.assertNotIn("sudo", command)
        with self.assertRaisesRegex(RuntimeError, "verified fixture executed"):
            self.execute_wrapper(command, payload)
        with self.assertRaisesRegex(SystemExit, "SHA256 mismatch"):
            self.execute_wrapper(command, payload + b"\n")
        with self.assertRaisesRegex(SystemExit, "SHA256 mismatch"):
            self.execute_wrapper(command, b"X" * 65537)

    def test_runtime_is_explicit_and_does_not_include_server_or_credentials(self):
        command = self.command(b"pass", action="runtime")
        self.assertIn("/usr/bin/python3 -I - runtime", command)
        self.assertNotIn("--server", command)
        with self.assertRaises(ValueError):
            self.command(b"pass", action="runtime", server="https://controller.example")

    def test_invalid_pin_and_shell_inputs_rejected(self):
        for commit, digest in (("master", "b" * 64), ("a" * 40, "bad;id")):
            with self.assertRaises(ValueError):
                render(commit, digest, server="https://controller.example")
        for server in ("https://x.example;id", "https://$(id).example", "https://x.example/'",
                       "https://x.example\nEOF\nid", "https://x.example/?token=test-token"):
            with self.subTest(server=server), self.assertRaises(ValueError):
                self.command(b"pass", server=server)

    def test_documented_commands_match_renderer_and_bootstrap_bytes(self):
        root = Path(__file__).resolve().parents[1]
        document = (root / "docs/AGENT_INSTALL.md").read_text(encoding="utf-8")
        commands = [block for block in re.findall(r"```bash\n(.*?)```", document, re.S)
                    if "PROXYFORGE_BOOTSTRAP" in block]
        self.assertEqual(len(commands), 3)
        source = (root / "scripts/agent_bootstrap.py").read_text(encoding="utf-8").encode("utf-8")
        digest = hashlib.sha256(source).hexdigest()
        for mode, command in zip(("install", "runtime", "check"), commands):
            commit = re.search(r"/ProxyForge/([0-9a-f]{40})/scripts/agent_bootstrap.py", command).group(1)
            expected = render(commit, digest, action=mode,
                              server="https://your-controller.example" if mode == "install" else None)
            self.assertEqual(command, expected)


if __name__ == "__main__":
    unittest.main()
