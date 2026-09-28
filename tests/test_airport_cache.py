import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from test_api_integration import load_isolated_application


class AirportCacheFallbackTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = load_isolated_application(Path(self.temp_dir.name))
        self.cache_path = Path(self.app.CACHE_FILE_PATH)

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_cache(self, proxies):
        self.cache_path.write_text(
            yaml.safe_dump(proxies, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

    @staticmethod
    def node(name, airport):
        return {
            "name": name,
            "type": "ss",
            "server": "node.example.com",
            "port": 8388,
            "_airport_name": airport,
        }

    def test_restart_first_request_uses_disk_cache_when_all_airports_fail(self):
        airports = [
            {"name": "Airport A", "url": "https://a.invalid/sub"},
            {"name": "Airport B", "url": "https://b.invalid/sub"},
        ]
        cached = [self.node("A cached", "Airport A"), self.node("B cached", "Airport B")]
        self.write_cache(cached)

        merged, missing = self.app.merge_airport_proxies_with_cache([], airports)

        self.assertEqual(merged, cached)
        self.assertEqual(missing, [])

    def test_partial_outage_only_fills_the_missing_airport(self):
        airports = [
            {"name": "Airport A", "url": "https://a.invalid/sub"},
            {"name": "Airport B", "url": "https://b.invalid/sub"},
        ]
        fresh = [self.node("A fresh", "Airport A")]
        self.write_cache([self.node("A old", "Airport A"), self.node("B cached", "Airport B")])

        merged, missing = self.app.merge_airport_proxies_with_cache(fresh, airports)

        self.assertEqual([node["name"] for node in merged], ["A fresh", "B cached"])
        self.assertEqual(missing, [])

    def test_missing_cache_is_reported_instead_of_silently_publishing_empty_data(self):
        airports = [{"name": "Airport A", "url": "https://a.invalid/sub"}]

        merged, missing = self.app.merge_airport_proxies_with_cache([], airports)

        self.assertEqual(merged, [])
        self.assertEqual(missing, ["Airport A"])

    def test_fetch_failure_does_not_log_subscription_url(self):
        secret_url = "https://private-user:private-pass@airport.invalid/sub?token=test-token"
        messages = []

        class CapturingLogger:
            @staticmethod
            def info(message):
                messages.append(message)

            @staticmethod
            def warning(message):
                messages.append(message)

            @staticmethod
            def error(message):
                messages.append(message)

        class FailingRequests:
            @staticmethod
            def get(url, **kwargs):
                raise RuntimeError(f"failed to reach {url}")

        with patch.object(self.app, "logger", CapturingLogger()), \
             patch.object(self.app, "safe_get", side_effect=FailingRequests.get):
            proxies = self.app.fetch_airport_item(secret_url)

        self.assertEqual(proxies, [])
        combined_logs = "\n".join(messages)
        self.assertIn("airport.invalid", combined_logs)
        self.assertNotIn(secret_url, combined_logs)
        self.assertNotIn("test-token", combined_logs)
        self.assertNotIn("private-user", combined_logs)
        self.assertNotIn("private-pass", combined_logs)


if __name__ == "__main__":
    unittest.main()
