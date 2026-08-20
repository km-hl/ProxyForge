import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # Local lightweight environments may only have PyYAML.
    TestClient = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_TOKEN = "integration-test-token"


def load_isolated_application(runtime_root: Path):
    """Import main.py without reading or writing the repository's runtime data."""
    (runtime_root / "static").mkdir()
    (runtime_root / "template.example.yaml").write_text(
        "proxy-groups: []\nrules: []\n",
        encoding="utf-8",
    )

    module_name = "proxyforge_api_integration_main"
    spec = importlib.util.spec_from_file_location(module_name, PROJECT_ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    previous_cwd = Path.cwd()
    previous_token = os.environ.get("SECRET_TOKEN")
    try:
        os.chdir(runtime_root)
        os.environ["SECRET_TOKEN"] = TEST_TOKEN
        sys.modules[module_name] = module
        # Never let python-dotenv discover a developer's real repository .env
        # while importing the application for tests.
        with patch("dotenv.load_dotenv", return_value=False):
            spec.loader.exec_module(module)
    finally:
        os.chdir(previous_cwd)
        if previous_token is None:
            os.environ.pop("SECRET_TOKEN", None)
        else:
            os.environ["SECRET_TOKEN"] = previous_token

    data_dir = runtime_root / "data"
    module.DATA_DIR = str(data_dir)
    module.TEMPLATE_PATH = str(data_dir / "template.yaml")
    module.CUSTOM_NODES_PATH = str(data_dir / "custom_nodes.yaml")
    module.CACHE_FILE_PATH = str(data_dir / "airport_cache.yaml")
    module.AIRPORTS_PATH = str(data_dir / "airports.yaml")
    module.ENV_FILE = str(runtime_root / ".env")
    module.SECRET_TOKEN = TEST_TOKEN
    return module


@unittest.skipIf(TestClient is None, "FastAPI test dependencies are not installed")
class ApiIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = tempfile.TemporaryDirectory()
        cls.app_module = load_isolated_application(Path(cls.runtime.name))
        cls.client = TestClient(cls.app_module.app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        sys.modules.pop("proxyforge_api_integration_main", None)
        cls.runtime.cleanup()

    def test_management_api_rejects_invalid_bearer_token(self):
        response = self.client.get(
            "/api/airports",
            headers={"Authorization": "Bearer invalid-token"},
        )

        self.assertEqual(response.status_code, 401)

    def test_provider_returns_mihomo_http_provider_document(self):
        airport = {"name": "Example Airport", "url": "https://airport.invalid/sub"}
        proxies = [{
            "name": "Example Node",
            "type": "ss",
            "server": "node.example.com",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "fixture-password",
            "_airport_name": "Example Airport",
        }]

        with (
            patch.object(self.app_module, "load_airports", return_value=[airport]),
            patch.object(self.app_module, "fetch_airport_item", return_value=proxies),
        ):
            response = self.client.get(f"/provider/0?token={TEST_TOKEN}")

        self.assertEqual(response.status_code, 200)
        document = yaml.safe_load(response.text)
        self.assertEqual(list(document), ["proxies"])
        self.assertEqual(document["proxies"][0]["name"], "Example Node")
        self.assertNotIn("_airport_name", document["proxies"][0])

    def test_subscription_builds_provider_without_exposing_upstream_url(self):
        airport = {"name": "Example Airport", "url": "https://airport.invalid/private"}
        proxies = [{
            "name": "Example Node",
            "type": "ss",
            "server": "node.example.com",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "fixture-password",
            "_airport_name": "Example Airport",
        }]
        template = yaml.safe_dump(
            {
                "proxy-groups": [{
                    "name": "Proxy",
                    "type": "select",
                    "use": ["Example Airport"],
                }],
                "rules": ["MATCH,Proxy"],
            },
            allow_unicode=True,
            sort_keys=False,
        )

        with (
            patch.object(
                self.app_module,
                "cleanup_runtime_template_references",
                return_value={"proxyReferences": [], "providerReferences": [], "total": 0},
            ),
            patch.object(self.app_module, "get_airport_proxies_cached", return_value=proxies),
            patch.object(
                self.app_module,
                "merge_airport_proxies_with_cache",
                return_value=(proxies, []),
            ),
            patch.object(self.app_module, "save_cache_to_file"),
            patch.object(self.app_module, "load_airports", return_value=[airport]),
            patch.object(self.app_module, "load_custom_nodes", return_value=[]),
            patch.object(self.app_module, "load_template_content", return_value=template),
        ):
            response = self.client.get(f"/sub?token={TEST_TOKEN}&name=Integration")

        self.assertEqual(response.status_code, 200)
        document = yaml.safe_load(response.text)
        provider = document["proxy-providers"]["Example Airport"]
        self.assertEqual(provider["url"], f"http://testserver/provider/0?token={TEST_TOKEN}")
        self.assertNotIn(airport["url"], response.text)
        self.assertEqual(document["proxy-groups"][0]["use"], ["Example Airport"])


if __name__ == "__main__":
    unittest.main()
