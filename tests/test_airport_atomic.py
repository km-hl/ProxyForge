import concurrent.futures
import contextlib
import json
import multiprocessing
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from proxyforge.config import template_store
from test_api_integration import load_isolated_application


def interrupted_cache_writer(root, kind, ready):
    """Run a real application writer; the parent kills it before replace."""
    app = load_isolated_application(Path(root))
    source = {"name": "fixture", "url": "https://airport.invalid/sub"}
    app.save_airports([source])
    snapshot = app.airport_cache_snapshot()
    path = Path(app.CACHE_FILE_PATH) if kind == "nodes" else Path(app.DATA_DIR) / "airports_info_cache.json"
    path.write_bytes(b"[]\n" if kind == "nodes" else b"{}\n")

    def pause_before_replace(src, dst):
        ready.set()
        threading.Event().wait(30)
        raise RuntimeError("parent did not terminate writer")

    with patch.object(template_store.os, "replace", side_effect=pause_before_replace):
        if kind == "nodes":
            app.save_cache_to_file([{"name": "new"}], snapshot)
        else:
            response = type("Response", (), {
                "headers": {}, "text": "proxies: []", "raise_for_status": lambda self: None,
            })()
            with patch.object(app, "safe_get", return_value=response):
                app.get_airports_info("all")["info"][0]


class AirportAtomicWriteTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.source = {"name": "示例机场", "url": "https://airport.invalid/sub"}
        self.app.save_airports([self.source])
        self.snapshot = self.app.airport_cache_snapshot()
        self.proxies = [{"name": "新节点", "_airport_name": "示例机场"}]
        self.response = type("Response", (), {
            "headers": {}, "text": "proxies: []", "raise_for_status": lambda self: None,
        })()

    def target(self, kind):
        name = "airport_cache.yaml" if kind == "nodes" else "airports_info_cache.json"
        return Path(self.app.DATA_DIR) / name

    def seed(self, kind):
        path = self.target(kind)
        content = b"- name: old\n" if kind == "nodes" else b'{"old": {"info": {}, "_timestamp": 0}}\n'
        path.write_bytes(content)
        return content

    def write(self, kind):
        if kind == "nodes":
            return self.app.save_cache_to_file(self.proxies, self.snapshot)
        with patch.object(self.app, "safe_get", return_value=self.response):
            return self.app.get_airports_info("all")["info"][0]

    def assert_no_temporaries(self, kind):
        path = self.target(kind)
        self.assertEqual(list(path.parent.glob("." + path.name + ".*")), [])

    def test_serialization_failure_preserves_original_file(self):
        def broken_yaml(value, stream=None, **kwargs):
            if stream is not None:
                stream.write("partial: [")
            raise ValueError("serialization interrupted")

        def broken_json(self, value, **kwargs):
            yield '{"partial":'
            raise ValueError("serialization interrupted")

        for kind in ("nodes", "info"):
            with self.subTest(kind=kind):
                original = self.seed(kind)
                serializer = patch.object(yaml, "dump", side_effect=broken_yaml) if kind == "nodes" else \
                    patch.object(json.JSONEncoder, "iterencode", broken_json)
                with serializer:
                    self.write(kind)
                self.assertEqual(self.target(kind).read_bytes(), original)
                self.assert_no_temporaries(kind)

    def test_fsync_or_replace_failure_preserves_original_and_cleans_temporary(self):
        for kind in ("nodes", "info"):
            for operation in ("fsync", "replace"):
                with self.subTest(kind=kind, operation=operation):
                    original = self.seed(kind)
                    with patch.object(template_store.os, operation, side_effect=OSError("fixture")) as failing:
                        result = self.write(kind)
                    self.assertTrue(failing.called)
                    self.assertEqual(self.target(kind).read_bytes(), original)
                    self.assert_no_temporaries(kind)
                    if kind == "info":
                        self.assertEqual(result["name"], "示例机场")
                        self.assertIsNone(result["error"])

    def test_partial_write_and_flush_failure_preserve_original(self):
        real_fdopen = os.fdopen
        for kind in ("nodes", "info"):
            for operation in ("write", "flush"):
                with self.subTest(kind=kind, operation=operation):
                    original = self.seed(kind)

                    @contextlib.contextmanager
                    def broken_stream(fd, mode, *args, **kwargs):
                        with real_fdopen(fd, mode, *args, **kwargs) as stream:
                            if mode != "w":
                                yield stream
                            else:
                                class Writer:
                                    def write(self, content):
                                        stream.write(content[:5] if operation == "write" else content)
                                        if operation == "write":
                                            raise OSError("partial write")

                                    def flush(self):
                                        raise OSError("flush interrupted")

                                yield Writer()

                    with patch.object(template_store.os, "fdopen", side_effect=broken_stream):
                        self.write(kind)
                    self.assertEqual(self.target(kind).read_bytes(), original)
                    self.assert_no_temporaries(kind)

    def test_directory_sync_failure_leaves_complete_new_file(self):
        for kind in ("nodes", "info"):
            with self.subTest(kind=kind):
                self.seed(kind)
                with patch.object(template_store, "sync_directory", side_effect=OSError("fixture")) as failing:
                    self.write(kind)
                self.assertTrue(failing.called)
                content = self.target(kind).read_text(encoding="utf-8")
                if kind == "nodes":
                    self.assertEqual(yaml.safe_load(content), self.proxies)
                else:
                    self.assertEqual(json.loads(content)[self.source["url"]]["info"]["name"], "airport.invalid")
                self.assert_no_temporaries(kind)

    def test_reader_sees_complete_old_then_new_file_at_replace(self):
        real_replace = os.replace
        for kind in ("nodes", "info"):
            with self.subTest(kind=kind):
                original = self.seed(kind)
                ready, release = threading.Event(), threading.Event()
                temporary_paths = []

                def held_replace(src, dst):
                    temporary_paths.append(Path(src))
                    self.assertEqual(Path(src).parent, Path(dst).parent)
                    ready.set()
                    if not release.wait(10):
                        raise TimeoutError("reader did not release writer")
                    return real_replace(src, dst)

                with patch.object(template_store.os, "replace", side_effect=held_replace):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pending = pool.submit(self.write, kind)
                        try:
                            self.assertTrue(ready.wait(10))
                            for _ in range(20):
                                self.assertEqual(self.target(kind).read_bytes(), original)
                            self.assertTrue(temporary_paths[0].is_file())
                        finally:
                            release.set()
                        pending.result(timeout=10)
                content = self.target(kind).read_text(encoding="utf-8")
                if kind == "nodes":
                    self.assertEqual(yaml.safe_load(content), self.proxies)
                else:
                    self.assertIn(self.source["url"], json.loads(content))
                self.assert_no_temporaries(kind)

    def test_crash_remnant_is_never_read_as_cache(self):
        for kind in ("nodes", "info"):
            with self.subTest(kind=kind):
                original = self.seed(kind)
                path = self.target(kind)
                remnant = path.with_name("." + path.name + "." + "a" * 32)
                remnant.write_text("partial: [", encoding="utf-8")
                if kind == "nodes":
                    self.assertEqual(self.app.load_cache_from_file(), [{"name": "old"}])
                else:
                    self.write(kind)
                    self.assertIn(self.source["url"], json.loads(path.read_text(encoding="utf-8")))
                self.assertTrue(remnant.exists())
                if kind == "nodes":
                    self.assertEqual(path.read_bytes(), original)

    def test_process_termination_keeps_original_and_isolates_remnant(self):
        ctx = multiprocessing.get_context("spawn")
        for kind in ("nodes", "info"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                ready = ctx.Event()
                process = ctx.Process(target=interrupted_cache_writer, args=(root, kind, ready))
                process.start()
                try:
                    self.assertTrue(ready.wait(15))
                    process.terminate()
                    process.join(10)
                    self.assertFalse(process.is_alive())
                    self.assertNotEqual(process.exitcode, 0)
                    name = "airport_cache.yaml" if kind == "nodes" else "airports_info_cache.json"
                    path = Path(root) / "data" / name
                    self.assertEqual(path.read_bytes(), b"[]\n" if kind == "nodes" else b"{}\n")
                    remnants = list(path.parent.glob("." + path.name + ".*"))
                    self.assertEqual(len(remnants), 1)
                    # Explicitly stopped writer: it is now safe to remove only
                    # its exact temporary path, never a live-writer wildcard.
                    remnants[0].unlink()
                    self.assertTrue(path.exists())
                finally:
                    if process.is_alive():
                        process.terminate()
                        process.join(10)
                    process.close()

    def test_failed_node_persistence_still_returns_fetched_subscription_nodes(self):
        original = self.seed("nodes")
        with patch.object(self.app, "fetch_airport_item", return_value=self.proxies), \
             patch.object(template_store.os, "replace", side_effect=OSError("fixture")):
            sources, proxies = self.app.subscription_airports()
        self.assertEqual(sources, [self.source])
        self.assertEqual(proxies, self.proxies)
        self.assertEqual(self.target("nodes").read_bytes(), original)

    def test_info_cache_write_error_does_not_log_secret_url(self):
        original = self.seed("info")
        secret = "https://airport.invalid/sub?token=test-token"
        with self.assertLogs(self.app.logger, level="WARNING") as logs, \
             patch.object(template_store.os, "replace", side_effect=OSError(secret)):
            result = self.write("info")
        self.assertIsNone(result["error"])
        self.assertIn("OSError", " ".join(logs.output))
        self.assertNotIn(secret, " ".join(logs.output))
        self.assertEqual(self.target("info").read_bytes(), original)

    def test_written_info_preserves_cached_response_shape_and_force_behavior(self):
        first = self.write("info")
        with patch.object(self.app, "safe_get", return_value=self.response) as fetch:
            self.assertEqual(self.app.get_airports_info()["info"][0], first)
            fetch.assert_not_called()
            forced = self.app.get_airports_info("all")["info"][0]
            fetch.assert_called_once()
        saved = json.loads(self.target("info").read_text(encoding="utf-8"))
        self.assertEqual(saved[self.source["url"]], {"info": dict(forced, name="airport.invalid"), "_timestamp": forced["_timestamp"]})

    @unittest.skipIf(os.name == "nt", "POSIX file permission bits")
    def test_new_cache_files_are_private(self):
        for kind in ("nodes", "info"):
            with self.subTest(kind=kind):
                self.seed(kind)
                self.target(kind).chmod(0o644)
                self.write(kind)
                self.assertEqual(self.target(kind).stat().st_mode & 0o777, 0o600)
