import concurrent.futures
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

from test_api_integration import (
    load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN,
)


class AirportConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.client = TestClient(self.app.app)
        self.addCleanup(self.client.close)
        self.headers = {"Authorization": "Bearer " + TEST_ADMIN_TOKEN}
        self.old = {"name": "Airport", "url": "https://old.invalid/sub"}
        self.new = {"name": "Airport", "url": "https://new.invalid/sub"}
        self.set_sources([self.old])

    def set_sources(self, sources, use_import=False):
        if use_import:
            template = self.client.get("/api/template", headers=self.headers).json()
            result = self.client.post("/api/template/import", headers=self.headers, json={
                "content": template["content"], "expected_revision": template["revision"],
                "nodes": [], "urls": sources,
            })
        else:
            result = self.client.post("/api/airports", headers=self.headers, json={"urls": sources})
        self.assertEqual(result.status_code, 200, result.text)

    @staticmethod
    def node(name):
        return {"name": name, "type": "ss", "server": "node.example.com", "port": 8388,
                "cipher": "aes-256-gcm", "password": "fixture-password", "_airport_name": "Airport"}

    def test_inflight_fetch_cannot_refill_cache_after_source_update_or_import(self):
        for use_import in (False, True):
            with self.subTest(use_import=use_import):
                self.set_sources([self.old])
                started, release = threading.Event(), threading.Event()

                def fetch(item, index=0, **kwargs):
                    if item == self.old:
                        started.set()
                        self.assertTrue(release.wait(10))
                        return [self.node("old")]
                    return [self.node("new")]

                with patch.object(self.app, "fetch_airport_item", side_effect=fetch):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pending = pool.submit(self.app.get_airport_proxies_cached)
                        try:
                            self.assertTrue(started.wait(10))
                            self.set_sources([self.new], use_import=use_import)
                        finally:
                            release.set()
                        try:
                            pending.result(timeout=10)
                        except Exception as exc:
                            # A rejected old snapshot may be retried by its HTTP caller.
                            self.assertEqual(type(exc).__name__, "AirportSourcesChanged")
                    current = self.app.get_airport_proxies_cached()
                self.assertEqual([node["name"] for node in current], ["new"])

    def test_subscription_does_not_persist_inflight_results_after_airport_removal(self):
        started, release = threading.Event(), threading.Event()

        def fetch(item, index=0, **kwargs):
            started.set()
            self.assertTrue(release.wait(10))
            return [self.node("removed")]

        with patch.object(self.app, "fetch_airport_item", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.client.get, "/sub", params={"token": TEST_SUBSCRIPTION_TOKEN})
                try:
                    self.assertTrue(started.wait(10))
                    self.set_sources([])
                finally:
                    release.set()
                response = pending.result(timeout=10)
        self.assertEqual(response.status_code, 200, response.text)
        cache_path = Path(self.app.CACHE_FILE_PATH)
        cached = yaml.safe_load(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else []
        self.assertEqual(cached, [])

    def test_same_name_new_url_removes_persistent_fallback(self):
        Path(self.app.CACHE_FILE_PATH).write_text(yaml.safe_dump([self.node("old")]), encoding="utf-8")
        self.set_sources([self.new])
        self.assertEqual(self.app.load_cache_from_file(), [])

    def test_cached_results_are_not_mutable_shared_objects(self):
        with patch.object(self.app, "fetch_airport_item", return_value=[self.node("original")]) as fetch:
            first = self.app.get_airport_proxies_cached()
            first[0]["name"] = "mutated"
            second = self.app.get_airport_proxies_cached()
        self.assertEqual(second[0]["name"], "original")
        self.assertEqual(fetch.call_count, 1)

    def test_background_result_is_discarded_after_source_change(self):
        started, release = threading.Event(), threading.Event()

        def fetch(item, index=0, **kwargs):
            started.set()
            self.assertTrue(release.wait(10))
            return [self.node("old background")]

        with patch.object(self.app, "fetch_airport_item", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.app.refresh_airport_cache)
                try:
                    self.assertTrue(started.wait(10))
                    self.set_sources([self.new])
                finally:
                    release.set()
                pending.result(timeout=10)
        self.assertEqual(self.app.load_cache_from_file(), [])
        with patch.object(self.app, "fetch_airport_item", return_value=[self.node("new")]):
            self.assertEqual(self.app.get_airport_proxies_cached()[0]["name"], "new")

    def test_background_warm_cannot_be_overwritten_by_older_subscription(self):
        started, release = threading.Event(), threading.Event()

        def fetch(item, index=0, **kwargs):
            if not started.is_set():
                started.set()
                self.assertTrue(release.wait(10))
                return [self.node("old foreground")]
            return [self.node("new background")]

        with patch.object(self.app, "fetch_airport_item", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.app.subscription_airports)
                try:
                    self.assertTrue(started.wait(10))
                    self.app.refresh_airport_cache()
                finally:
                    release.set()
                sources, proxies = pending.result(timeout=10)
        self.assertEqual(sources, [self.old])
        self.assertEqual(proxies[0]["name"], "new background")
        self.assertEqual(self.app.load_cache_from_file()[0]["name"], "new background")
        self.assertEqual(self.app.get_airport_proxies_cached()[0]["name"], "new background")

    def test_generation_rejects_a_to_b_to_a_and_same_source_import(self):
        for change_back in (False, True):
            with self.subTest(change_back=change_back):
                snapshot = self.app.airport_cache_snapshot()
                if change_back:
                    self.set_sources([self.new])
                self.set_sources([self.old], use_import=True)
                with self.assertRaises(self.app.AirportSourcesChanged):
                    self.app.save_cache_to_file([self.node("stale")], snapshot)

    def test_repeated_changes_have_bounded_retry_and_safe_503(self):
        calls = []

        def fetch(item, index=0, **kwargs):
            calls.append(item)
            self.set_sources([self.new] if item == self.old else [self.old])
            return [self.node("stale")]

        with patch.object(self.app, "fetch_airport_item", side_effect=fetch):
            response = self.client.get("/sub", params={"token": TEST_SUBSCRIPTION_TOKEN})
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.app.load_cache_from_file(), [])

    def test_memory_ttl_and_empty_result_caching_are_preserved(self):
        from cachetools import TTLCache
        now = [0]
        # Controlled clock: exercise the public fetch path without long sleeps.
        with self.app._subscription_cache_lock:
            ttl = self.app._subscription_cache.ttl
            size = self.app._subscription_cache.maxsize
            self.assertEqual((size, ttl), (1, 12 * 60 * 60))
            self.app._subscription_cache = TTLCache(maxsize=size, ttl=ttl, timer=lambda: now[0])
        with patch.object(self.app, "fetch_airport_item", return_value=[]) as fetch:
            self.assertEqual(self.app.get_airport_proxies_cached(), [])
            now[0] = ttl - 1
            self.assertEqual(self.app.get_airport_proxies_cached(), [])
            self.assertEqual(fetch.call_count, 1)
            now[0] = ttl
            self.assertEqual(self.app.get_airport_proxies_cached(), [])
            self.assertEqual(fetch.call_count, 2)

    def test_noop_source_save_preserves_disk_fallback(self):
        Path(self.app.CACHE_FILE_PATH).write_text(yaml.safe_dump([self.node("cached")]), encoding="utf-8")
        self.app.airport_cache_snapshot()
        self.set_sources([self.old])
        with patch.object(self.app, "fetch_airport_item", return_value=[]):
            sources, nodes = self.app.subscription_airports()
        self.assertEqual(sources, [self.old])
        self.assertEqual(nodes[0]["name"], "cached")

    def test_source_change_stops_before_commit_if_disk_invalidation_fails(self):
        self.app.airport_cache_snapshot()
        with patch.object(Path, "unlink", side_effect=PermissionError("fixture")):
            response = self.client.post("/api/airports", headers=self.headers, json={"urls": [self.new]})
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(self.app.load_airports(), [self.old])

    def test_concurrent_cache_misses_return_independent_consistent_results(self):
        barrier = threading.Barrier(6)
        counter = iter(range(6))
        counter_lock = threading.Lock()

        def fetch(item, index=0, **kwargs):
            with counter_lock:
                name = str(next(counter))
            barrier.wait(10)
            return [self.node(name)]

        with patch.object(self.app, "fetch_airport_item", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                futures = [pool.submit(self.app.get_airport_proxies_cached) for _ in range(6)]
                results = [future.result(timeout=15) for future in futures]
        self.assertEqual(len({nodes[0]["name"] for nodes in results}), 1)
        results[0][0]["name"] = "mutated"
        self.assertNotEqual(results[1][0]["name"], "mutated")

    def test_redo_recovery_does_not_reuse_previous_source_cache(self):
        with patch.object(self.app, "fetch_airport_item", return_value=[self.node("old")]):
            self.app.get_airport_proxies_cached()
        from proxyforge.config import template_store
        real_write = template_store.atomic_write

        def interrupt(path, content):
            if Path(path).name == "airports.yaml":
                raise OSError("simulated commit interruption")
            return real_write(path, content)

        with patch.object(template_store, "atomic_write", side_effect=interrupt):
            response = self.client.post("/api/airports", headers=self.headers, json={"urls": [self.new]})
        self.assertEqual(response.status_code, 503)
        with patch.object(self.app, "fetch_airport_item", return_value=[self.node("recovered")]):
            self.assertEqual(self.app.get_airport_proxies_cached()[0]["name"], "recovered")
        self.assertEqual(self.app.load_airports(), [self.new])
