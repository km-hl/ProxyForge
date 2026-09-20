import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LoggingPrivacyTest(unittest.TestCase):
    def test_all_server_entrypoints_disable_query_string_access_logs(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        service = (ROOT / "proxyforge.service").read_text(encoding="utf-8")
        main = (ROOT / "main.py").read_text(encoding="utf-8")

        self.assertIn("--no-access-log", dockerfile)
        self.assertIn("--no-access-log", service)
        self.assertIn("access_log=False", main)


if __name__ == "__main__":
    unittest.main()
