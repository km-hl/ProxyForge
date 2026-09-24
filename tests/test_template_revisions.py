import concurrent.futures
import multiprocessing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from template_store import TemplateStore, TemplateConflict, revision, atomic_write


def compete(path, expected, content, start, results):
    store = TemplateStore(path)
    start.wait(10)
    try:
        with store.locked():
            store.expect(expected)
            store.commit({"template.yaml": content})
        results.put("saved")
    except TemplateConflict:
        results.put("conflict")


class RevisionStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "template.yaml"
        self.path.write_bytes(b"rules: []\r\n")
        self.store = TemplateStore(self.path, history_limit=3)

    def test_exact_bytes_noop_and_bounded_history(self):
        self.assertEqual(self.store.snapshot()["revision"], revision("rules: []\r\n"))
        self.store.commit({"template.yaml": "rules: []\r\n"})
        self.assertEqual(self.store.list_history(), [])
        self.store.commit({"template.yaml": "rules: []\n"})
        entries = self.store.list_history()
        self.assertEqual(len(entries), 2)
        self.assertEqual(self.store.history_entry(entries[-1]["id"])["content"], "rules: []\r\n")
        for i in range(8):
            self.store.commit({"template.yaml": "rules: []\n# " + str(i)})
        self.assertEqual(len(self.store.list_history()), 3)

    def test_cross_process_compare_and_swap_has_one_winner(self):
        ctx = multiprocessing.get_context("spawn")
        start, results = ctx.Event(), ctx.Queue()
        expected = self.store.snapshot()["revision"]
        workers = [ctx.Process(target=compete, args=(str(self.path), expected, str(i), start, results))
                   for i in range(2)]
        for worker in workers:
            worker.start()
        start.set()
        outcomes = [results.get(timeout=20) for _ in workers]
        for worker in workers:
            worker.join(20)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(sorted(outcomes), ["conflict", "saved"])

    def test_interrupted_import_recovers_before_any_next_read(self):
        real = atomic_write
        def interrupted(path, content):
            if Path(path).name == "airports.yaml":
                raise OSError("simulated disk failure")
            return real(path, content)
        with patch("template_store.atomic_write", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.store.commit({"template.yaml": "new", "airports.yaml": "[]"})
        snapshot = TemplateStore(self.path).snapshot()
        self.assertEqual(snapshot["content"], "new")
        self.assertEqual((self.path.parent / "airports.yaml").read_text(), "[]")
        self.assertEqual(len(self.store.list_history()), 2)
        self.assertFalse(self.store.journal.exists())

    def test_failure_before_commit_preserves_template_and_history(self):
        with patch("template_store.atomic_write", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                self.store.commit({"template.yaml": "new"})
        self.assertEqual(self.path.read_bytes(), b"rules: []\r\n")
        self.assertEqual(self.store.list_history(), [])

    def test_history_path_traversal_rejected(self):
        with self.assertRaises(FileNotFoundError):
            self.store.history_entry("../../config")


class RevisionApiTest(unittest.TestCase):
    def setUp(self):
        from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN
        from fastapi.testclient import TestClient
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app)
        self.addCleanup(self.client.close)
        self.headers = {"Authorization": "Bearer " + TEST_ADMIN_TOKEN}

    def snapshot(self):
        return self.client.get("/api/template", headers=self.headers).json()

    def save(self, content, expected):
        return self.client.post("/api/template", headers=self.headers,
                                json={"content": content, "expected_revision": expected})

    def test_missing_revision_conflict_and_restore(self):
        before = self.snapshot()
        self.assertEqual(self.client.post("/api/template", headers=self.headers,
                         json={"content": "rules: []"}).status_code, 428)
        saved = self.save("rules: []\n# changed", before["revision"])
        self.assertEqual(saved.status_code, 200)
        conflict = self.save("rules: []", before["revision"])
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["detail"]["current_revision"], saved.json()["revision"])
        history = self.client.get("/api/template/history", headers=self.headers).json()["entries"]
        self.assertNotIn("content", history[0])
        self.assertEqual(self.client.get("/api/template/history").status_code, 401)
        url = "/api/template/history/" + history[-1]["id"] + "/restore"
        self.assertEqual(self.client.post(url, headers=self.headers,
                         json={"expected_revision": before["revision"]}).status_code, 409)
        restored = self.client.post(url, headers=self.headers,
                                   json={"expected_revision": saved.json()["revision"]})
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.json()["content"], before["content"])

    def test_two_concurrent_api_saves_have_one_conflict(self):
        rev = self.snapshot()["revision"]
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda x: self.save("rules: []\n# " + str(x), rev).status_code, [1, 2]))
        self.assertEqual(sorted(results), [200, 409])

    def test_import_conflict_or_invalid_input_changes_nothing(self):
        before = self.snapshot()
        payload = {"content": "rules: []", "nodes": [], "urls": ["http://127.0.0.1"],
                   "expected_revision": before["revision"]}
        response = self.client.post("/api/template/import", headers=self.headers, json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((Path(self.temp.name) / "data/airports.yaml").exists())
        payload.update(urls=[], content="rules: []\n# import")
        self.assertEqual(self.client.post("/api/template/import", headers=self.headers,
                         json=payload).status_code, 200)
        self.assertEqual(self.client.post("/api/template/import", headers=self.headers,
                         json=payload).status_code, 409)

    def test_node_cleanup_invalidates_old_template_revision(self):
        node = {"name": "local", "type": "socks5", "server": "127.0.0.1", "port": 1080}
        self.client.post("/api/nodes", headers=self.headers, json={"nodes": [node]})
        saved = self.save("proxy-groups:\n- name: Proxy\n  type: select\n  proxies: [local]\nrules: []",
                          self.snapshot()["revision"]).json()
        response = self.client.post("/api/nodes", headers=self.headers, json={"nodes": []})
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json()["template_revision"], saved["revision"])
        self.assertEqual(self.save(saved["content"], saved["revision"]).status_code, 409)
