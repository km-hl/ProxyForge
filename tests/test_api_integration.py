import importlib.util
import json
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
TEST_SUBSCRIPTION_TOKEN = "integration-subscription-token"
TEST_ADMIN_TOKEN = "integration-management-token"


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
    previous_subscription_token = os.environ.get("SECRET_TOKEN")
    previous_admin_token = os.environ.get("ADMIN_TOKEN")
    try:
        os.chdir(runtime_root)
        os.environ["SECRET_TOKEN"] = TEST_SUBSCRIPTION_TOKEN
        os.environ["ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
        sys.modules[module_name] = module
        # Never let python-dotenv discover a developer's real repository .env
        # while importing the application for tests.
        with patch("dotenv.load_dotenv", return_value=False):
            spec.loader.exec_module(module)
    finally:
        os.chdir(previous_cwd)
        if previous_subscription_token is None:
            os.environ.pop("SECRET_TOKEN", None)
        else:
            os.environ["SECRET_TOKEN"] = previous_subscription_token
        if previous_admin_token is None:
            os.environ.pop("ADMIN_TOKEN", None)
        else:
            os.environ["ADMIN_TOKEN"] = previous_admin_token

    data_dir = runtime_root / "data"
    module.DATA_DIR = str(data_dir)
    module.TEMPLATE_PATH = str(data_dir / "template.yaml")
    module.CUSTOM_NODES_PATH = str(data_dir / "custom_nodes.yaml")
    module.CACHE_FILE_PATH = str(data_dir / "airport_cache.yaml")
    module.AIRPORTS_PATH = str(data_dir / "airports.yaml")
    module.RUNTIME_CONFIG_PATH = str(data_dir / "config.json")
    module.SUBSCRIPTION_TOKEN = TEST_SUBSCRIPTION_TOKEN
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

    def setUp(self):
        self.client.cookies.clear()

    def test_management_api_rejects_invalid_bearer_token(self):
        response = self.client.get(
            "/api/airports",
            headers={"Authorization": "Bearer invalid-token"},
        )

        self.assertEqual(response.status_code, 401)

    def test_subscription_token_does_not_grant_management_access(self):
        response = self.client.get(
            "/api/airports",
            headers={"Authorization": f"Bearer {TEST_SUBSCRIPTION_TOKEN}"},
        )

        self.assertEqual(response.status_code, 401)

    def test_admin_login_issues_http_only_session_cookie(self):
        response = self.client.post("/api/auth", json={"token": TEST_ADMIN_TOKEN})

        self.assertEqual(response.status_code, 200)
        self.assertIn("httponly", response.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", response.headers["set-cookie"].lower())
        self.assertEqual(self.client.get("/api/airports").status_code, 200)

    def test_https_reverse_proxy_marks_session_cookie_secure(self):
        response = self.client.post(
            "/api/auth",
            headers={"X-Forwarded-Proto": "https"},
            json={"token": TEST_ADMIN_TOKEN},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("secure", response.headers["set-cookie"].lower())
        self.assertEqual(
            response.headers["strict-transport-security"],
            "max-age=31536000",
        )

    def test_https_reverse_proxy_accepts_same_origin_cookie_write(self):
        login = self.client.post(
            "/api/auth",
            headers={"X-Forwarded-Proto": "https"},
            json={"token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(login.status_code, 200)
        session_token = login.cookies.get(self.app_module.SESSION_COOKIE_NAME)
        self.client.cookies.clear()

        response = self.client.post(
            "/api/logout",
            headers={
                "Origin": "https://testserver",
                "X-Forwarded-Proto": "https",
                "Cookie": (
                    f"{self.app_module.SESSION_COOKIE_NAME}={session_token}"
                ),
            },
        )

        self.assertEqual(response.status_code, 200)

    def test_cookie_authenticated_writes_require_same_origin(self):
        login = self.client.post("/api/auth", json={"token": TEST_ADMIN_TOKEN})
        self.assertEqual(login.status_code, 200)

        rejected = self.client.post("/api/logout")
        accepted = self.client.post(
            "/api/logout",
            headers={"Origin": "http://testserver"},
        )

        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(accepted.status_code, 200)

    def test_management_responses_include_security_headers(self):
        response = self.client.get(
            "/api/airports",
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
        )

        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_subscription_token_cannot_log_in_to_admin_console(self):
        response = self.client.post(
            "/api/auth",
            json={"token": TEST_SUBSCRIPTION_TOKEN},
        )

        self.assertEqual(response.status_code, 401)

    def test_private_network_airport_url_is_rejected_before_save(self):
        response = self.client.post(
            "/api/airports",
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
            json={"urls": [{"name": "unsafe", "url": "http://127.0.0.1/sub"}]},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("不安全", response.json()["detail"])

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
            response = self.client.get(
                f"/provider/0?token={TEST_SUBSCRIPTION_TOKEN}"
            )

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
            response = self.client.get(
                f"/sub?token={TEST_SUBSCRIPTION_TOKEN}&name=Integration"
            )

        self.assertEqual(response.status_code, 200)
        document = yaml.safe_load(response.text)
        provider = document["proxy-providers"]["Example Airport"]
        self.assertEqual(
            provider["url"],
            f"http://testserver/provider/0?token={TEST_SUBSCRIPTION_TOKEN}",
        )
        self.assertNotIn(airport["url"], response.text)
        self.assertEqual(document["proxy-groups"][0]["use"], ["Example Airport"])

    def test_template_update_accepts_custom_nodes_source_and_direct_rule(self):
        template = yaml.safe_dump(
            {
                "proxy-groups": [{
                    "name": "Proxy",
                    "type": "select",
                    "use": ["_custom_nodes_"],
                }],
                "rules": [
                    "DOMAIN-SUFFIX,example.com,DIRECT",
                    "MATCH,Proxy",
                ],
            },
            allow_unicode=True,
            sort_keys=False,
        )

        with (
            patch.object(self.app_module, "load_airports", return_value=[]),
            patch.object(self.app_module, "load_custom_nodes", return_value=[]),
            patch.object(self.app_module, "save_template_content") as save_template,
        ):
            response = self.client.post(
                "/api/template",
                headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
                json={"content": template},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        save_template.assert_called_once_with(template)

    def test_config_update_rejects_short_token(self):
        response = self.client.post(
            "/api/config",
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
            json={"SUBSCRIPTION_TOKEN": "too-short"},
        )

        self.assertEqual(response.status_code, 400)

    def test_config_updates_reject_credential_reuse(self):
        subscription_response = self.client.post(
            "/api/config",
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
            json={"SUBSCRIPTION_TOKEN": TEST_ADMIN_TOKEN},
        )
        admin_response = self.client.post(
            "/api/admin-token",
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
            json={"ADMIN_TOKEN": TEST_SUBSCRIPTION_TOKEN},
        )

        self.assertEqual(subscription_response.status_code, 400)
        self.assertEqual(admin_response.status_code, 400)

    def test_token_update_is_persisted_outside_the_container_env_file(self):
        new_token = "updated-integration-token"
        try:
            response = self.client.post(
                "/api/config",
                headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
                json={"SUBSCRIPTION_TOKEN": new_token},
            )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"status": "ok"})
            config = json.loads(
                Path(self.app_module.RUNTIME_CONFIG_PATH).read_text(encoding="utf-8")
            )
            self.assertEqual(config["subscription_token"], new_token)
            self.assertNotIn("admin_token", config)
            self.assertFalse((Path(self.runtime.name) / ".env").exists())
        finally:
            self.app_module.RUNTIME_STORE.update_subscription_token(
                TEST_SUBSCRIPTION_TOKEN
            )
            self.app_module.SUBSCRIPTION_TOKEN = TEST_SUBSCRIPTION_TOKEN


if __name__ == "__main__":
    unittest.main()
