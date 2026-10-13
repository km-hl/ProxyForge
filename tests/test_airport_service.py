"""服务可独立装配；不借助 main/FastAPI 验证显式依赖和实例隔离。"""
import base64
from contextlib import contextmanager
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import yaml

from proxyforge.airports.parser import parse_airport_response
from proxyforge.airports.service import AirportService, AirportSourcesChanged


def response(name='node'):
    return SimpleNamespace(headers={}, text=yaml.safe_dump({'proxies': [
        {'name': name, 'type': 'ss', 'server': 'node.example', 'port': 8388,
         'cipher': 'aes-256-gcm', 'password': 'fixture'},
    ]}), raise_for_status=lambda: None)


class AirportServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = ['https://old.example/sub', {
            'name': '自定义', 'url': 'https://new.example/sub', 'extension': {'keep': True},
        }]

    def service(self, name, **overrides):
        settings = dict(
            sources_reader=lambda: self.sources, cache_path=self.root / (name + '.yaml'),
            info_cache_path=self.root / (name + '.json'), http_get=Mock(return_value=response(name)),
            clock=time.time, monotonic=time.monotonic, configuration_lock=threading.RLock(),
        )
        # A context-manager factory, as used by TemplateStore.locked in the app.
        lock = settings['configuration_lock']
        settings['configuration_lock'] = lambda: lock
        settings.update(overrides)
        return AirportService(**settings)

    def test_constructing_service_does_not_read_sources_or_create_cache_files(self):
        reader = Mock(side_effect=AssertionError('unexpected source read'))
        fetch = Mock(side_effect=AssertionError('unexpected network'))
        service = self.service('unused', sources_reader=reader, http_get=fetch)
        self.assertEqual(list(self.root.iterdir()), [])
        reader.assert_not_called()
        fetch.assert_not_called()
        # First explicit operation receives the reader dependency, without Web setup.
        with self.assertRaisesRegex(AssertionError, 'unexpected source read'):
            service.airport_cache_snapshot()

    def test_instances_keep_separate_identity_cache_and_invalidation(self):
        first, second = self.service('first'), self.service('second')
        sources, nodes = first.subscription_airports()
        self.assertEqual(sources, self.sources)
        sources[1]['extension']['keep'] = False
        nodes[0]['name'] = 'mutated response'
        second_nodes = second.get_airport_proxies_cached()
        self.assertEqual(second_nodes[0]['name'], 'second')
        self.assertEqual(first.get_airport_proxies_cached()[0]['name'], 'first')
        self.assertTrue(self.sources[1]['extension']['keep'])
        first.invalidate_airport_cache(clear_disk=True)
        self.assertFalse((self.root / 'first.yaml').exists())
        self.assertEqual(second.get_airport_proxies_cached(), second_nodes)
        self.assertEqual(second.http_get.call_count, 2)
        first.get_airport_proxies_cached()
        self.assertEqual(first.http_get.call_count, 4)

    def test_metadata_clock_ca_and_batch_deadline_are_explicit_dependencies(self):
        clock = [100000]
        network = Mock(return_value=response())
        service = self.service('info', clock=lambda: clock[0], http_get=network,
                               ca_bundle='fixture-ca.pem', batch_timeout=17)
        first = service.get_airports_info()['info']
        self.assertEqual([item['_timestamp'] for item in first], [100000, 100000])
        calls = network.call_args_list
        self.assertTrue(all(call.kwargs['ca_bundle'] == 'fixture-ca.pem' for call in calls))
        self.assertEqual(calls[0].kwargs['deadline'], calls[1].kwargs['deadline'])
        clock[0] += 86400 - 1
        self.assertEqual(service.get_airports_info()['info'], first)
        self.assertEqual(network.call_count, 2)
        clock[0] += 1
        service.get_airports_info()
        self.assertEqual(network.call_count, 4)

    def test_service_reports_source_conflict_without_http_error(self):
        service = self.service('conflict')

        def changing_source(*args, **kwargs):
            service.invalidate_airport_cache()
            return response()

        service.http_get.side_effect = changing_source
        with self.assertRaises(AirportSourcesChanged):
            service.get_airport_proxies_cached()
        self.assertEqual(service.http_get.call_count, 4)

    def test_service_propagates_storage_error_for_adapter_to_map(self):
        @contextmanager
        def unavailable():
            raise OSError('fixture storage')
            yield

        service = self.service('storage', configuration_lock=unavailable)
        with self.assertRaisesRegex(OSError, 'fixture storage'):
            service.get_airports_info()
        service.http_get.assert_not_called()

    def test_parser_preserves_yaml_then_base64_share_link_fallback(self):
        self.assertEqual(parse_airport_response('proxies: [{name: fixture}]'), [{'name': 'fixture'}])
        link = 'ss://' + base64.b64encode(b'aes-256-gcm:fixture').decode() + '@node.example:8388#fixture'
        encoded = base64.b64encode(link.encode()).decode().rstrip('=')
        parsed = parse_airport_response(encoded)
        self.assertEqual(len(parsed), 1)
        self.assertEqual((parsed[0]['type'], parsed[0]['server'], parsed[0]['password']),
                         ('ss', 'node.example', 'fixture'))
        self.assertEqual(parse_airport_response('not a subscription'), [])
