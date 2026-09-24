import concurrent.futures
import io
import json
import logging
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from control_store import ControlStore, InvalidRegistration, UnauthorizedAgent, online_status
from agent.client import Client, AgentConnectionError, CredentialRejected, controller_url
from agent.main import register, run, load_config
from agent.system_info import collect


def metadata(instance="a" * 32):
    return {"instance_id": instance, "hostname": "test-host", "machine_id": "machine-hint",
            "os": "debian", "os_version": "12", "arch": "amd64", "agent_version": "0.1.0",
            "protocol_version": 1, "uptime": 10, "addresses": [], "supported": True,
            "singbox": {"installed": False, "running": False, "version": "", "status": "not_installed"}}


class ControlStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000
        self.path = Path(self.temp.name) / "proxyforge.db"
        self.store = ControlStore(self.path, clock=lambda: self.now)

    def enroll(self):
        token = self.store.issue_registration("server")["registration_token"]
        return self.store.register(token, metadata(), "192.0.2.1")

    def test_registration_consumption_is_atomic_and_hash_only(self):
        token = self.store.issue_registration("server")["registration_token"]
        def claim(_):
            try:
                return self.store.register(token, metadata(), "192.0.2.1")
            except InvalidRegistration:
                return None
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(claim, [1, 2]))
        accepted = [r for r in results if r]
        self.assertEqual(len(accepted), 1)
        with self.store.connection() as db:
            serialized = repr([list(db.execute("SELECT * FROM " + table)) for table in
                               ["registration_tokens", "agents", "agent_credentials"]])
            values = repr([tuple(row) for table in ["registration_tokens", "agents", "agent_credentials"]
                           for row in db.execute("SELECT * FROM " + table)])
            self.assertNotIn(token, serialized + values)
            self.assertNotIn(accepted[0]["agent_token"], values)

    def test_expired_token_never_creates_an_agent(self):
        token = self.store.issue_registration("expired")["registration_token"]
        self.now += 600
        with self.assertRaises(InvalidRegistration):
            self.store.register(token, metadata(), "192.0.2.1")
        self.assertEqual(self.store.list_agents(), [])

    def test_revocation_persists_and_rejects_heartbeat(self):
        enrolled = self.enroll()
        self.store.heartbeat(enrolled["agent_token"], metadata(), "192.0.2.1")
        self.assertEqual(self.store.get_agent(enrolled["agent_id"])["status"], "online")
        self.store.revoke(enrolled["agent_id"])
        reopened = ControlStore(self.path, clock=lambda: self.now)
        with self.assertRaises(UnauthorizedAgent):
            reopened.heartbeat(enrolled["agent_token"], metadata(), "192.0.2.1")
        self.assertEqual(reopened.get_agent(enrolled["agent_id"])["status"], "revoked")

    def test_clock_thresholds_and_never_seen(self):
        self.assertEqual(online_status(None, self.now), "never_seen")
        for age, expected in [(89, "online"), (90, "degraded"), (299, "degraded"), (300, "offline")]:
            self.assertEqual(online_status(self.now - age, self.now), expected)
        self.assertEqual(online_status(self.now + 5, self.now), "online")

    def test_heartbeat_cannot_switch_instance(self):
        enrolled = self.enroll()
        with self.assertRaises(UnauthorizedAgent):
            self.store.heartbeat(enrolled["agent_token"], metadata("b" * 32), "192.0.2.1")

    def test_newer_schema_is_rejected_and_delete_revokes(self):
        enrolled = self.enroll()
        self.store.revoke(enrolled["agent_id"], remove=True)
        with self.assertRaises(UnauthorizedAgent):
            self.store.heartbeat(enrolled["agent_token"], metadata(), "")
        with self.store.connection() as db:
            db.execute("INSERT INTO schema_migrations VALUES(3)")
        with self.assertRaisesRegex(RuntimeError, "newer"):
            ControlStore(self.path)


class AgentApiTest(unittest.TestCase):
    def setUp(self):
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN
        from fastapi.testclient import TestClient
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app)
        self.addCleanup(self.client.close)
        self.admin = {"Authorization": "Bearer " + TEST_ADMIN_TOKEN}
        self.subscription = {"Authorization": "Bearer " + TEST_SUBSCRIPTION_TOKEN}

    def enroll(self):
        token = self.client.post("/api/agents/registration-tokens", headers=self.admin,
                                 json={"name": "test"}).json()["registration_token"]
        response = self.client.post("/api/agent/register", json={**metadata(), "registration_token": token})
        self.assertEqual(response.status_code, 200, response.text)
        return token, response.json()

    def test_all_credential_boundaries_and_removal(self):
        registration, first = self.enroll()
        _, second = self.enroll()
        header = {"Authorization": "Bearer " + first["agent_token"]}
        for forbidden in [header, self.subscription, {"Authorization": "Bearer " + registration}, {}]:
            for path in ["/api/agents", "/api/config", "/api/template"]:
                self.assertEqual(self.client.get(path, headers=forbidden).status_code, 401)
        self.assertEqual(self.client.get("/api/agents/" + second["agent_id"], headers=header).status_code, 401)
        self.assertEqual(self.client.delete("/api/agents/" + second["agent_id"], headers=header).status_code, 401)
        for forbidden in [self.admin, self.subscription, {}, {"Authorization": "Bearer " + registration}]:
            self.assertEqual(self.client.post("/api/agent/heartbeat", json=metadata(), headers=forbidden).status_code, 401)
        response = self.client.post("/api/agent/heartbeat", json=metadata(), headers=header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.delete("/api/agents/" + first["agent_id"], headers=self.admin).status_code, 204)
        self.assertEqual(self.client.post("/api/agent/heartbeat", json=metadata(), headers=header).status_code, 401)
        self.assertEqual(len(self.client.get("/api/agents", headers=self.admin).json()["agents"]), 1)

    def test_cookie_admin_is_not_agent_identity_and_job_api_absent(self):
        from test_api_integration import TEST_ADMIN_TOKEN
        self.client.post("/api/auth", json={"token": TEST_ADMIN_TOKEN})
        self.assertEqual(self.client.post("/api/agent/heartbeat", json=metadata()).status_code, 401)
        for path in ["/api/agent/exec", "/api/agent/jobs/next"]:
            self.assertEqual(self.client.post(path, json={}).status_code, 404)

    def test_unknown_fields_size_limit_and_secret_redaction(self):
        capture = io.StringIO()
        handler = logging.StreamHandler(capture)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        token, enrolled = self.enroll()
        header = {"Authorization": "Bearer " + enrolled["agent_token"]}
        response = self.client.post("/api/agent/heartbeat", headers=header,
                                    json={**metadata(), "agent_id": enrolled["agent_id"], "private_key": token})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(token, response.text)
        self.assertNotIn(token, capture.getvalue())
        self.assertNotIn(enrolled["agent_token"], capture.getvalue())
        oversized = {**metadata(), "hostname": "x" * 17000}
        self.assertEqual(self.client.post("/api/agent/heartbeat", json=oversized, headers=header).status_code, 413)

    def test_protocol_mismatch_is_visible_without_allowing_execution(self):
        _, enrolled = self.enroll()
        header = {"Authorization": "Bearer " + enrolled["agent_token"]}
        response = self.client.post("/api/agent/heartbeat", headers=header,
                                    json={**metadata(), "protocol_version": 2})
        self.assertFalse(response.json()["compatible"])
        view = self.client.get("/api/agents/" + enrolled["agent_id"], headers=self.admin).json()
        self.assertFalse(view["compatible"])
        self.assertEqual(view["status"], "online")
        self.assertNotIn("token_hash", json.dumps(view))

    def test_real_reference_agent_enrolls_and_heartbeats_over_http_development_transport(self):
        import uvicorn
        token = self.client.post("/api/agents/registration-tokens", headers=self.admin,
                                 json={"name": "real client"}).json()["registration_token"]
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(self.app.app, log_level="error", access_log=False, lifespan="off"))
        thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
        thread.start()
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.02)
            self.assertTrue(server.started)
            config = Path(self.temp.name) / "agent/config.json"
            with patch("agent.main.collect", side_effect=lambda instance: {**metadata(instance), 'job_protocol_version': 1}):
                register(config, "http://127.0.0.1:" + str(port), token, allow_insecure=True)
                stored = load_config(config)
                self.assertNotIn(token, config.read_text())
                if os.name != "nt":
                    self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                self.assertEqual(run(config, once=True), 0)
                view = self.client.get("/api/agents/" + stored["agent_id"], headers=self.admin).json()
                self.assertEqual(view["status"], "online")
                job_url = "/api/agents/" + stored["agent_id"] + "/jobs"
                created = self.client.post(job_url, headers=self.admin, json={
                    "request_id": "c" * 32, "type": "singbox.status", "payload": {}})
                self.assertEqual(created.status_code, 200, created.text)
                with patch("agent.jobs.singbox_status", return_value=metadata()["singbox"]):
                    self.assertEqual(run(config, once=True), 0)
                jobs = self.client.get(job_url, headers=self.admin).json()["jobs"]
                self.assertEqual(jobs[0]["status"], "success")
                self.assertEqual(jobs[0]["attempts"], 1)
                self.client.post("/api/agents/" + stored["agent_id"] + "/revoke", headers=self.admin)
                self.assertEqual(run(config, once=True), 4)
        finally:
            server.should_exit = True
            thread.join(10)
            sock.close()

    def test_registration_response_loss_leaves_no_local_long_term_secret(self):
        token = self.client.post("/api/agents/registration-tokens", headers=self.admin,
                                 json={"name": "lost"}).json()["registration_token"]
        def lost_response(client, path, payload, token=None):
            response = self.client.post(path, json=payload)
            self.assertEqual(response.status_code, 200)
            raise AgentConnectionError("lost")
        config = Path(self.temp.name) / "agent/config.json"
        with patch.object(Client, "post", lost_response):
            with self.assertRaises(AgentConnectionError):
                register(config, "https://controller.example", token)
        self.assertNotIn("token", load_config(config))
        self.assertNotIn(token, config.read_text())
        with self.assertRaises(ValueError):
            run(config, once=True)
        self.assertEqual(len(self.client.get("/api/agents", headers=self.admin).json()["agents"]), 1)


class AgentTransportTest(unittest.TestCase):
    def test_https_default_and_explicit_http_development(self):
        for url in ["http://example.com", "https://user:secret@example.com", "https://example.com?token=example",
                    "file:///etc/passwd", "https://example.com/path"]:
            with self.assertRaises(ValueError):
                controller_url(url)
        self.assertEqual(controller_url("http://127.0.0.1:8000", True), "http://127.0.0.1:8000")

    def test_redirect_and_http_errors_do_not_expose_body_or_token(self):
        import urllib.error
        from agent.client import NoRedirect
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example"))
        client = Client("https://controller.example")
        for code, expected in [(302, AgentConnectionError), (401, CredentialRejected), (500, AgentConnectionError)]:
            error = urllib.error.HTTPError("https://secret.example", code, "sensitive-body", {}, None)
            with patch.object(client.opener, "open", side_effect=error):
                with self.assertRaises(expected) as raised:
                    client.post("/api/agent/heartbeat", metadata(), "private-token")
                self.assertNotIn("secret", str(raised.exception))
                self.assertNotIn("sensitive", str(raised.exception))
                self.assertNotIn("private-token", str(raised.exception))

    def test_inventory_has_bounded_readonly_shape(self):
        value = collect("a" * 32)
        self.assertEqual(value["protocol_version"], 1)
        self.assertIn("singbox", value)
        self.assertNotIn("registration_token", value)
