import concurrent.futures
import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from test_api_integration import load_isolated_application


def response(upload):
    return type("Response", (), {
        "headers": {"subscription-userinfo": "upload=" + str(upload)},
        "text": "proxies: []", "raise_for_status": lambda self: None,
    })()


class AirportInfoConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.sources = [{"name": name, "url": "https://" + name.lower() + ".invalid/sub"}
                        for name in ("A", "B")]
        self.app.save_airports(self.sources)
        self.cache = Path(self.app.DATA_DIR) / "airports_info_cache.json"

    def read(self):
        return json.loads(self.cache.read_text(encoding="utf-8"))

    def seed(self):
        now = time.time()
        entries = {}
        for source in self.sources:
            info = dict(url=source["url"], name=source["name"], nodesCount=0,
                        upload=0, download=0, total=0, expire=0, error=None, _timestamp=now)
            entries[source["url"]] = {"info": info, "_timestamp": now}
        self.cache.write_text(json.dumps(entries), encoding="utf-8")

    def test_workers_do_not_lose_other_airports_in_same_batch(self):
        barrier = threading.Barrier(2)

        def fetch(url, **kwargs):
            barrier.wait(10)
            return response(1)

        with patch.object(self.app, "safe_get", side_effect=fetch):
            result = self.app.get_airports_info("all")
        self.assertEqual(len(result["info"]), 2)
        self.assertEqual(set(self.read()), {source["url"] for source in self.sources})

    def test_concurrent_selective_refresh_merges_latest_file(self):
        self.seed()
        barrier = threading.Barrier(2)

        def fetch(url, **kwargs):
            barrier.wait(10)
            return response(10 if url == self.sources[0]["url"] else 20)

        with patch.object(self.app, "safe_get", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.app.get_airports_info, str(i)) for i in range(2)]
                for future in futures:
                    future.result(timeout=15)
        cached = self.read()
        self.assertEqual([cached[source["url"]]["info"]["upload"] for source in self.sources], [10, 20])

    def test_older_request_finishing_last_cannot_overwrite_newer_refresh(self):
        self.app.save_airports(self.sources[:1])
        started, release = threading.Event(), threading.Event()

        def fetch(url, **kwargs):
            if not started.is_set():
                started.set()
                self.assertTrue(release.wait(10))
                return response(1)
            return response(2)

        with patch.object(self.app, "safe_get", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.app.get_airports_info, "all")
                try:
                    self.assertTrue(started.wait(10))
                    self.app.get_airports_info("all")
                finally:
                    release.set()
                pending.result(timeout=10)
        self.assertEqual(self.read()[self.sources[0]["url"]]["info"]["upload"], 2)

    def test_one_write_per_batch_and_no_write_for_all_cache_hits(self):
        with patch.object(self.app, "safe_get", return_value=response(1)), \
             patch.object(self.app, "atomic_write", wraps=self.app.atomic_write) as write:
            self.app.get_airports_info("all")
            self.assertEqual(write.call_count, 1)
            self.assertEqual(Path(write.call_args.args[0]), self.cache)
            self.app.get_airports_info()
            self.assertEqual(write.call_count, 1)

    def test_worker_never_reads_or_writes_cache(self):
        self.seed()
        original = self.cache.read_bytes()
        with patch.object(self.app, "safe_get", return_value=response(9)), \
             patch.object(self.app, "load_airport_info_cache", side_effect=AssertionError("cache read")), \
             patch.object(self.app, "atomic_write", side_effect=AssertionError("cache write")):
            info = self.app.fetch_single_airport_info(self.sources[0]["url"])
        self.assertEqual(info["upload"], 9)
        self.assertEqual(self.cache.read_bytes(), original)

    def test_http_route_preserves_auth_shape_and_source_order(self):
        from fastapi.testclient import TestClient
        from test_api_integration import TEST_ADMIN_TOKEN
        client = TestClient(self.app.app)
        self.addCleanup(client.close)
        with patch.object(self.app, "safe_get", return_value=response(7)) as fetch:
            self.assertEqual(client.get("/api/airports/info").status_code, 401)
            fetch.assert_not_called()
            result = client.get("/api/airports/info", params={"force_indices": "all"},
                                headers={"Authorization": "Bearer " + TEST_ADMIN_TOKEN})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(set(result.json()), {"info"})
        infos = result.json()["info"]
        self.assertEqual([info["url"] for info in infos], [item["url"] for item in self.sources])
        self.assertEqual(set(infos[0]), {"url", "name", "nodesCount", "upload", "download", "total",
                                         "expire", "error", "_timestamp"})

    def test_storage_lock_failures_return_safe_503_before_fetch_and_commit(self):
        from fastapi.testclient import TestClient
        from test_api_integration import TEST_ADMIN_TOKEN
        self.app.save_airports(self.sources[:1])
        original = self.app.TemplateStore.locked
        with TestClient(self.app.app, raise_server_exceptions=False) as client:
            for stage in ("read", "commit"):
                with self.subTest(stage=stage):
                    fetched = threading.Event()

                    @contextmanager
                    def failing_lock(store):
                        if stage == "read" or fetched.is_set():
                            raise PermissionError("private-storage-path")
                        with original(store):
                            yield

                    def fetch(url, **kwargs):
                        fetched.set()
                        return response(7)

                    with patch.object(self.app.TemplateStore, "locked", failing_lock), \
                         patch.object(self.app, "safe_get", side_effect=fetch) as network:
                        result = client.get("/api/airports/info", params={"force_indices": "all"},
                                            headers={"Authorization": "Bearer " + TEST_ADMIN_TOKEN})
                    self.assertEqual(result.status_code, 503, result.text)
                    self.assertEqual(result.json()["detail"]["code"], "storage_unavailable")
                    self.assertNotIn("private-storage-path", result.text)
                    self.assertEqual(network.call_count, int(stage == "commit"))
                    self.assertFalse(self.cache.exists())

    def test_duplicate_urls_preserve_aliases_order_and_fetch_once(self):
        url = self.sources[0]["url"]
        sources = [{"name": "第一机场", "url": url}, {"name": "第二机场", "url": url}, url]
        self.app.save_airports(sources)
        remote = response(4)
        remote.headers["content-disposition"] = 'attachment; filename="Upstream"'
        with patch.object(self.app, "safe_get", return_value=remote) as fetch:
            first = self.app.get_airports_info("all")["info"]
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual([info["name"] for info in first], ["第一机场", "第二机场", "Upstream"])
            first[0]["name"] = "mutated"
            second = self.app.get_airports_info()["info"]
            self.assertEqual(second[0]["name"], "第一机场")
            self.app.get_airports_info("1")
            self.assertEqual(fetch.call_count, 2)
        self.assertEqual(self.read()[url]["info"]["name"], "Upstream")

    def test_legacy_cache_and_force_indices_remain_compatible(self):
        self.seed()
        legacy = self.read()
        for entry in legacy.values():
            entry["info"].pop("_timestamp")
        self.cache.write_text(json.dumps(legacy), encoding="utf-8")
        with patch.object(self.app, "safe_get", return_value=response(5)) as fetch:
            result = self.app.get_airports_info("bad,0")["info"]
            fetch.assert_not_called()
            self.assertEqual([info["upload"] for info in result], [0, 0])
            self.assertTrue(all("_timestamp" in info for info in result))
            result = self.app.get_airports_info(" 1, , -1, 20 ")["info"]
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(fetch.call_args.args[0], self.sources[1]["url"])
            self.assertEqual([info["upload"] for info in result], [0, 5])

    def test_error_results_keep_24_hour_ttl_and_force_can_retry(self):
        self.app.save_airports(self.sources[:1])
        with patch.object(self.app.time, "time", return_value=100000), \
             patch.object(self.app, "safe_get", side_effect=TimeoutError("fixture")) as fetch:
            first = self.app.get_airports_info()["info"][0]
            self.assertEqual(first["error"], "TimeoutError")
            self.app.get_airports_info()
            self.assertEqual(fetch.call_count, 1)
        with patch.object(self.app.time, "time", return_value=100000 + 86400 - 1), \
             patch.object(self.app, "safe_get", return_value=response(8)) as fetch:
            self.assertEqual(self.app.get_airports_info()["info"][0], first)
            fetch.assert_not_called()
        with patch.object(self.app.time, "time", return_value=100000 + 86400), \
             patch.object(self.app, "safe_get", return_value=response(8)) as fetch:
            self.assertIsNone(self.app.get_airports_info()["info"][0]["error"])
            self.assertEqual(fetch.call_count, 1)
            self.app.get_airports_info("all")
            self.assertEqual(fetch.call_count, 2)

    def test_invalid_json_and_invalid_entries_refetch_without_leaking_content(self):
        for damaged in ('{"secret":', '[]', '{"secret-url": {"info": [], "_timestamp": "broken"}}'):
            with self.subTest(damaged=damaged):
                self.cache.write_text(damaged, encoding="utf-8")
                with patch.object(self.app, "safe_get", return_value=response(3)), \
                     self.assertLogs(self.app.logger, level="WARNING") as logs:
                    result = self.app.get_airports_info()
                self.assertEqual(len(result["info"]), 2)
                self.assertNotIn("secret", " ".join(logs.output))
                self.assertEqual(set(self.read()), {item["url"] for item in self.sources})

    def test_invalid_single_entry_does_not_discard_other_cached_airport(self):
        self.seed()
        data = self.read()
        data[self.sources[0]["url"]]["_timestamp"] = float("nan")
        self.cache.write_text(json.dumps(data), encoding="utf-8")
        with patch.object(self.app, "safe_get", return_value=response(6)) as fetch:
            self.app.get_airports_info()
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(fetch.call_args.args[0], self.sources[0]["url"])

    def test_configuration_change_retries_without_restoring_removed_cache(self):
        for operation in ("save", "import"):
            with self.subTest(operation=operation):
                self.app.save_airports(self.sources[:1])
                started, release = threading.Event(), threading.Event()

                def fetch(url, **kwargs):
                    started.set()
                    self.assertTrue(release.wait(10))
                    return response(1)

                with patch.object(self.app, "safe_get", side_effect=fetch):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pending = pool.submit(self.app.get_airports_info, "all")
                        try:
                            self.assertTrue(started.wait(10))
                            if operation == "save":
                                self.app.update_airports(self.app.AirportsModel(urls=[]))
                            else:
                                template = self.app.template_store().snapshot()
                                self.app.import_template(self.app.ImportModel(
                                    content=template["content"], expected_revision=template["revision"],
                                    nodes=[], urls=[]))
                        finally:
                            release.set()
                        self.assertEqual(pending.result(timeout=10), {"info": []})
                self.assertFalse(self.cache.exists())

    def test_source_a_to_b_to_a_rejects_original_inflight_refresh(self):
        self.app.save_airports(self.sources[:1])
        started, release = threading.Event(), threading.Event()

        def fetch(url, **kwargs):
            if not started.is_set():
                started.set()
                self.assertTrue(release.wait(10))
                return response(1)
            return response(2)

        with patch.object(self.app, "safe_get", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.app.get_airports_info, "all")
                try:
                    self.assertTrue(started.wait(10))
                    self.app.update_airports(self.app.AirportsModel(urls=self.sources[1:]))
                    self.app.update_airports(self.app.AirportsModel(urls=self.sources[:1]))
                    self.app.get_airports_info("all")
                finally:
                    release.set()
                self.assertEqual(pending.result(timeout=10)["info"][0]["upload"], 2)
        self.assertEqual(self.read()[self.sources[0]["url"]]["info"]["upload"], 2)

    def test_continuously_changing_sources_stop_after_two_attempts(self):
        self.app.save_airports(self.sources[:1])

        def fetch(url, **kwargs):
            new_sources = self.sources[1:] if url == self.sources[0]["url"] else self.sources[:1]
            self.app.update_airports(self.app.AirportsModel(urls=new_sources))
            return response(1)

        from fastapi import HTTPException
        with patch.object(self.app, "safe_get", side_effect=fetch) as fetch_mock:
            with self.assertRaises(HTTPException) as error:
                self.app.get_airports_info("all")
        self.assertEqual(error.exception.status_code, 503)
        self.assertEqual(fetch_mock.call_count, 2)
        self.assertFalse(self.cache.exists())

    def test_node_background_warm_does_not_discard_info_refresh(self):
        self.app.save_airports(self.sources[:1])
        started, release = threading.Event(), threading.Event()

        def fetch(url, **kwargs):
            started.set()
            self.assertTrue(release.wait(10))
            return response(1)

        with patch.object(self.app, "safe_get", side_effect=fetch) as fetch_mock, \
             patch.object(self.app, "fetch_airport_proxies", return_value=[{"name": "n", "_airport_name": "A"}]):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.app.get_airports_info, "all")
                try:
                    self.assertTrue(started.wait(10))
                    self.app.refresh_airport_cache()
                finally:
                    release.set()
                pending.result(timeout=10)
        self.assertEqual(fetch_mock.call_count, 1)

    def test_write_failure_returns_results_and_blocks_older_overwrite(self):
        self.app.save_airports(self.sources[:1])
        started, release = threading.Event(), threading.Event()

        def fetch(url, **kwargs):
            if not started.is_set():
                started.set()
                self.assertTrue(release.wait(10))
                return response(1)
            return response(2)

        with patch.object(self.app, "safe_get", side_effect=fetch):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.app.get_airports_info, "all")
                try:
                    self.assertTrue(started.wait(10))
                    with patch.object(self.app, "atomic_write", side_effect=OSError("fixture")):
                        result = self.app.get_airports_info("all")
                    self.assertEqual(result["info"][0]["upload"], 2)
                finally:
                    release.set()
                pending.result(timeout=10)
        self.assertFalse(self.cache.exists())
