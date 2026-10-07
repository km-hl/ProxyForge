import asyncio
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml

from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN


class AirportBackgroundTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))

    async def test_refresh_runs_off_event_loop_and_keeps_schedule(self):
        loop_thread = threading.get_ident()
        refresh_threads, delays, tasks = [], [], []
        create_task = asyncio.create_task

        def record_task(coroutine, **kwargs):
            task = create_task(coroutine, **kwargs)
            tasks.append(task)
            return task

        async def sleep(delay):
            delays.append(delay)
            if len(delays) > 1:
                raise asyncio.CancelledError

        with patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app.asyncio, "sleep", side_effect=sleep), \
             patch.object(self.app.asyncio, "create_task", side_effect=record_task), \
             patch.object(self.app, "refresh_airport_cache", side_effect=lambda *args: refresh_threads.append(threading.get_ident())):
            await self.app.startup_event()
            await asyncio.gather(*tasks, return_exceptions=True)
        self.assertEqual(delays, [300, 4 * 3600])
        self.assertEqual(len(refresh_threads), 1)
        self.assertNotEqual(refresh_threads[0], loop_thread)

    async def wait(self, event):
        self.assertTrue(await asyncio.to_thread(event.wait, 5), "worker did not reach checkpoint")

    def sources(self):
        sources = [{"name": name, "url": "https://" + name.lower() + ".invalid/sub"} for name in ("A", "B")]
        self.app.save_airports(sources)
        return sources

    @staticmethod
    def node(name, airport="A"):
        return {"name": name, "type": "ss", "server": "node.example.com", "port": 8388,
                "cipher": "aes-256-gcm", "password": "fixture", "_airport_name": airport}

    async def test_shutdown_during_initial_delay_and_repeated_lifecycle(self):
        with patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app, "refresh_airport_cache") as refresh:
            for _ in range(2):
                await self.app.startup_event()
                state = self.app.app.state.airport_updater
                await self.app.startup_event()
                self.assertIs(self.app.app.state.airport_updater, state)
                await asyncio.wait_for(self.app.shutdown_event(), 1)
                self.assertTrue(state.stop.is_set())
                self.assertTrue(state.task.done())
                self.assertIsNone(state.worker)
            refresh.assert_not_called()

    async def test_api_responds_while_network_or_cache_read_is_blocked(self):
        self.sources()
        for stage in ("network", "disk"):
            with self.subTest(stage=stage):
                started, release = threading.Event(), threading.Event()

                def block(*args, **kwargs):
                    started.set()
                    if not release.wait(5):
                        raise TimeoutError("test worker release")
                    return []

                with patch.object(self.app, "AIRPORT_REFRESH_START_DELAY", 0), \
                     patch.object(self.app, "cleanup_runtime_template_references"), \
                     patch.object(self.app, "fetch_airport_proxies", side_effect=block if stage == "network" else None,
                                  return_value=[]), \
                     patch.object(self.app, "load_cache_from_file", side_effect=block if stage == "disk" else None,
                                  return_value=[]):
                    await self.app.startup_event()
                    try:
                        await self.wait(started)
                        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app.app),
                                                    base_url="http://testserver") as client:
                            result = await asyncio.wait_for(client.get("/api/auth", headers={
                                "Authorization": "Bearer " + TEST_ADMIN_TOKEN}), 2)
                        self.assertEqual(result.status_code, 200)
                        self.assertFalse(release.is_set())
                    finally:
                        release.set()
                        await self.app.shutdown_event()

    async def test_shutdown_is_bounded_and_late_network_result_cannot_commit(self):
        self.sources()
        started, release = threading.Event(), threading.Event()

        def fetch(*args, **kwargs):
            started.set()
            if not release.wait(5):
                raise TimeoutError("test worker release")
            return [self.node("late", "A"), self.node("late B", "B")]

        with patch.object(self.app, "AIRPORT_REFRESH_START_DELAY", 0), \
             patch.object(self.app, "AIRPORT_REFRESH_SHUTDOWN_TIMEOUT", 0), \
             patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app, "fetch_airport_proxies", side_effect=fetch), \
             patch.object(self.app, "save_cache_to_file", wraps=self.app.save_cache_to_file) as save:
            await self.app.startup_event()
            state = self.app.app.state.airport_updater
            try:
                await self.wait(started)
                await asyncio.wait_for(self.app.shutdown_event(), 1)
                self.assertFalse(state.worker.done())
                self.assertFalse(state.thread_done.is_set())
                with self.assertRaisesRegex(RuntimeError, "still stopping"):
                    await self.app.startup_event()
            finally:
                release.set()
                await asyncio.wait_for(asyncio.shield(state.worker), 5)
            save.assert_not_called()
            self.assertTrue(state.thread_done.is_set())
            self.assertEqual(self.app.load_cache_from_file(), [])
            with self.app._subscription_cache_lock:
                self.assertEqual(len(self.app._subscription_cache), 0)

    async def test_shutdown_waits_for_worker_without_cancelling_it(self):
        self.sources()
        started, release = threading.Event(), threading.Event()

        def fetch(*args, **kwargs):
            started.set()
            if not release.wait(5):
                raise TimeoutError("test worker release")
            return []

        with patch.object(self.app, "AIRPORT_REFRESH_START_DELAY", 0), \
             patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app, "fetch_airport_proxies", side_effect=fetch):
            await self.app.startup_event()
            state = self.app.app.state.airport_updater
            try:
                await self.wait(started)
                shutdown = asyncio.create_task(self.app.shutdown_event())
                await self.wait(state.stop)
                self.assertFalse(shutdown.done())
                self.assertFalse(state.worker.cancelled())
            finally:
                release.set()
                await asyncio.wait_for(shutdown, 5)
            self.assertTrue(state.worker.done())
            self.assertTrue(state.thread_done.is_set())

    async def test_worker_failure_is_redacted_and_next_round_recovers(self):
        delays, calls = [], []
        retry, recovered = asyncio.Event(), asyncio.Event()
        waiting = asyncio.Event()

        async def sleep(delay):
            delays.append(delay)
            if len(delays) == 2:
                waiting.set()
                await retry.wait()
            elif len(delays) == 3:
                recovered.set()
                await asyncio.Event().wait()

        def refresh(*args):
            calls.append(1)
            if len(calls) == 1:
                raise OSError("private-subscription-token")

        with patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app.asyncio, "sleep", side_effect=sleep), \
             patch.object(self.app, "refresh_airport_cache", side_effect=refresh), \
             self.assertLogs(self.app.logger, "ERROR") as logs:
            await self.app.startup_event()
            try:
                await asyncio.wait_for(waiting.wait(), 5)
                self.assertEqual(len(calls), 1)
                retry.set()
                await asyncio.wait_for(recovered.wait(), 5)
                self.assertEqual(len(calls), 2)
            finally:
                await self.app.shutdown_event()
        self.assertEqual(delays, [300, 14400, 14400])
        self.assertIn("OSError", " ".join(logs.output))
        self.assertNotIn("private-subscription-token", " ".join(logs.output))

    async def test_stopping_skips_queued_airports_and_keeps_five_worker_limit(self):
        stop, started, release = threading.Event(), threading.Event(), threading.Event()
        count_lock = threading.Lock()
        calls = []

        def fetch(item, index, **kwargs):
            with count_lock:
                calls.append(index)
                if len(calls) == 5:
                    started.set()
            if not release.wait(5):
                raise TimeoutError("test worker release")
            return []

        with patch.object(self.app, "fetch_airport_item", side_effect=fetch):
            worker = asyncio.create_task(asyncio.to_thread(self.app.fetch_airport_proxies, ["fixture"] * 12, stop))
            try:
                await self.wait(started)
                stop.set()
            finally:
                release.set()
                await asyncio.wait_for(worker, 5)
        self.assertEqual(sorted(calls), list(range(5)))

    async def test_stop_during_cache_merge_prevents_commit(self):
        self.sources()
        stop = threading.Event()

        def merge(*args):
            stop.set()
            return [self.node("late")], []

        with patch.object(self.app, "fetch_airport_proxies", return_value=[]), \
             patch.object(self.app, "merge_airport_proxies_with_cache", side_effect=merge), \
             patch.object(self.app, "save_cache_to_file") as save:
            await asyncio.to_thread(self.app.refresh_airport_cache, stop)
        save.assert_not_called()

    async def test_background_merges_fallback_and_keeps_old_cache_when_incomplete(self):
        self.sources()
        cache = Path(self.app.CACHE_FILE_PATH)
        old = [self.node("A old"), self.node("B cached", "B")]
        cache.write_text(yaml.safe_dump(old), encoding="utf-8")
        with patch.object(self.app, "fetch_airport_proxies", return_value=[self.node("A fresh")]):
            await asyncio.to_thread(self.app.refresh_airport_cache, threading.Event())
        self.assertEqual([item["name"] for item in self.app.load_cache_from_file()], ["A fresh", "B cached"])
        cache.write_text(yaml.safe_dump([self.node("A only")]), encoding="utf-8")
        original = cache.read_bytes()
        with patch.object(self.app, "fetch_airport_proxies", return_value=[]):
            await asyncio.to_thread(self.app.refresh_airport_cache, threading.Event())
        self.assertEqual(cache.read_bytes(), original)

    async def test_cancelled_scheduler_signals_worker_to_stop(self):
        self.sources()
        started, release = threading.Event(), threading.Event()

        def fetch(*args, **kwargs):
            started.set()
            if not release.wait(5):
                raise TimeoutError("test worker release")
            return [self.node("late")]

        with patch.object(self.app, "AIRPORT_REFRESH_START_DELAY", 0), \
             patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app, "fetch_airport_proxies", side_effect=fetch), \
             patch.object(self.app, "save_cache_to_file") as save:
            await self.app.startup_event()
            state = self.app.app.state.airport_updater
            try:
                await self.wait(started)
                state.task.cancel()
                await asyncio.gather(state.task, return_exceptions=True)
                self.assertTrue(state.stop.is_set())
                self.assertFalse(state.worker.done())
            finally:
                release.set()
                await asyncio.wait_for(state.worker, 5)
                await self.app.shutdown_event()
        save.assert_not_called()

    async def test_rounds_do_not_overlap_even_with_zero_interval(self):
        started, release, second = threading.Event(), threading.Event(), threading.Event()
        active, maximum, calls = 0, 0, 0
        guard = threading.Lock()

        def refresh(stop):
            nonlocal active, maximum, calls
            with guard:
                active += 1
                calls += 1
                maximum = max(maximum, active)
                current = calls
            try:
                if current == 1:
                    started.set()
                    if not release.wait(5):
                        raise TimeoutError("test worker release")
                else:
                    stop.set()
                    second.set()
            finally:
                with guard:
                    active -= 1

        with patch.object(self.app, "AIRPORT_REFRESH_START_DELAY", 0), \
             patch.object(self.app, "AIRPORT_REFRESH_INTERVAL", 0), \
             patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app, "refresh_airport_cache", side_effect=refresh):
            await self.app.startup_event()
            try:
                await self.wait(started)
                await self.app.startup_event()
                self.assertEqual(calls, 1)
                release.set()
                await self.wait(second)
            finally:
                release.set()
                await self.app.shutdown_event()
        self.assertEqual((calls, maximum), (2, 1))

    async def test_source_update_during_scheduled_refresh_rejects_result(self):
        self.sources()
        started, release = threading.Event(), threading.Event()

        def fetch(*args, **kwargs):
            started.set()
            if not release.wait(5):
                raise TimeoutError("test worker release")
            return [self.node("removed A"), self.node("removed B", "B")]

        with patch.object(self.app, "AIRPORT_REFRESH_START_DELAY", 0), \
             patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app, "fetch_airport_proxies", side_effect=fetch), \
             patch.object(self.app, "save_cache_to_file") as save:
            await self.app.startup_event()
            state = self.app.app.state.airport_updater
            try:
                await self.wait(started)
                await asyncio.to_thread(self.app.update_airports, self.app.AirportsModel(urls=[]))
                release.set()
                await asyncio.wait_for(asyncio.shield(state.worker), 5)
            finally:
                release.set()
                await self.app.shutdown_event()
        save.assert_not_called()

    async def test_cancelled_worker_future_does_not_allow_restart_before_thread_exits(self):
        started, release = threading.Event(), threading.Event()

        def refresh(stop):
            started.set()
            if not release.wait(5):
                raise TimeoutError("test worker release")

        with patch.object(self.app, "AIRPORT_REFRESH_START_DELAY", 0), \
             patch.object(self.app, "cleanup_runtime_template_references"), \
             patch.object(self.app, "refresh_airport_cache", side_effect=refresh):
            await self.app.startup_event()
            state = self.app.app.state.airport_updater
            try:
                await self.wait(started)
                state.worker.cancel()
                await asyncio.gather(state.task, return_exceptions=True)
                self.assertTrue(state.worker.done())
                self.assertFalse(state.thread_done.is_set())
                with self.assertRaisesRegex(RuntimeError, "still stopping"):
                    await self.app.startup_event()
            finally:
                release.set()
                await self.wait(state.thread_done)
                await self.app.shutdown_event()

    async def test_pre_stopped_refresh_does_not_read_or_fetch(self):
        stop = threading.Event()
        stop.set()
        with patch.object(self.app, "airport_cache_snapshot") as snapshot, \
             patch.object(self.app, "fetch_airport_proxies") as fetch:
            await asyncio.to_thread(self.app.refresh_airport_cache, stop)
        snapshot.assert_not_called()
        fetch.assert_not_called()

    async def test_executor_submission_failure_clears_active_thread_marker(self):
        state = self.app.AirportUpdaterState()
        state.thread_done.clear()
        with patch.object(self.app.asyncio, "to_thread", side_effect=RuntimeError("private-executor-path")), \
             self.assertLogs(self.app.logger, "ERROR") as logs:
            await self.app.run_airport_refresh(state)
        self.assertTrue(state.thread_done.is_set())
        self.assertNotIn("private-executor-path", " ".join(logs.output))

    async def test_registered_http_lifecycle_cleans_up_scheduler(self):
        from fastapi.testclient import TestClient

        def lifecycle():
            with TestClient(self.app.app) as client:
                self.assertEqual(client.get("/api/auth", headers={
                    "Authorization": "Bearer " + TEST_ADMIN_TOKEN}).status_code, 200)
                state = self.app.app.state.airport_updater
                self.assertFalse(state.task.done())
            self.assertTrue(state.stop.is_set())
            self.assertTrue(state.task.done())

        await asyncio.to_thread(lifecycle)
