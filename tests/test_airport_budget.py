import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from proxyforge.security.network_security import safe_get
from test_api_integration import load_isolated_application
from test_airport_info_concurrency import response
from test_outbound_budget import slow_server


class AirportBudgetTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))

    def test_nodes_batch_bounds_active_requests_and_skips_expired_queue(self):
        with slow_server() as (url, _), patch.object(self.app, "AIRPORT_BATCH_TIMEOUT", 0.4), \
                patch.object(self.app, "safe_get", wraps=safe_get) as fetch:
            started = time.monotonic()
            result = self.app.fetch_airport_proxies([url + "?source=" + str(i) for i in range(12)])
            self.assertEqual(result, [])
            self.assertLess(time.monotonic() - started, 2)
            self.assertGreater(fetch.call_count, 0)
            self.assertLessEqual(fetch.call_count, 5)
            self.assertEqual(len({call.kwargs["deadline"] for call in fetch.call_args_list}), 1)

    def test_info_batch_returns_timeout_for_active_and_skipped_sources(self):
        with slow_server() as (url, _), patch.object(self.app, "AIRPORT_BATCH_TIMEOUT", 0.4), \
                patch.object(self.app, "safe_get", wraps=safe_get) as fetch:
            urls = [url + "?source=" + str(i) for i in range(12)]
            self.app.save_airports(urls)
            started = time.monotonic()
            result = self.app.get_airports_info("all")["info"]
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual([info["url"] for info in result], urls)
            self.assertEqual({info["error"] for info in result}, {"OutboundTimeout"})
            self.assertGreater(fetch.call_count, 0)
            self.assertLessEqual(fetch.call_count, 5)
            self.assertEqual(len({call.kwargs["deadline"] for call in fetch.call_args_list}), 1)

    def test_info_generation_retry_keeps_original_deadline(self):
        self.app.save_airports(["https://first.example/sub"])

        def fetch(url, **kwargs):
            self.app.save_airports(["https://second.example/sub"])
            threading.Event().wait(max(0, kwargs["deadline"] - time.monotonic()) + 0.03)
            return response(1)

        with patch.object(self.app, "AIRPORT_BATCH_TIMEOUT", 0.5), patch.object(self.app, "safe_get", side_effect=fetch) as network:
            result = self.app.get_airports_info("all")["info"]
        network.assert_called_once()
        self.assertEqual(result[0]["url"], "https://second.example/sub")
        self.assertEqual(result[0]["error"], "OutboundTimeout")

    def test_stop_reaches_active_node_request_and_discards_it(self):
        stop = threading.Event()
        with slow_server(stop_request=stop) as (url, _), patch.object(self.app, "safe_get", wraps=safe_get) as fetch:
            started = time.monotonic()
            self.assertEqual(self.app.fetch_airport_proxies([url] * 12, stop), [])
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertTrue(all(call.kwargs["stop_event"] is stop for call in fetch.call_args_list))
            self.assertLessEqual(fetch.call_count, 5)

    def test_stopped_or_expired_parsing_result_is_discarded(self):
        stop = threading.Event()

        def parse(text):
            stop.set()
            return [{"name": "late node"}]

        with patch.object(self.app, "safe_get", return_value=response(1)), \
                patch.object(self.app, "parse_airport_response", side_effect=parse):
            self.assertEqual(self.app.fetch_airport_item("https://source.example/sub", stop_event=stop), [])
        with patch.object(self.app, "safe_get") as network:
            past = time.monotonic() - 1
            self.assertEqual(self.app.fetch_airport_item("https://source.example/sub", deadline=past), [])
            info = self.app.fetch_single_airport_info("https://source.example/sub", deadline=past)
            self.assertEqual(info["error"], "OutboundTimeout")
            network.assert_not_called()
