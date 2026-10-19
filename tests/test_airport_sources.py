"""内部来源类型的旧配置/API/订阅兼容性与失效边界。"""
from dataclasses import FrozenInstanceError
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import yaml

from proxyforge.airports.sources import AirportSource, AirportSnapshot, normalize_sources
from proxyforge.airports.service import AirportSourcesChanged
from test_airport_service import response
from test_api_integration import load_isolated_application, TEST_ADMIN_TOKEN, TEST_SUBSCRIPTION_TOKEN


class AirportSourceModelTest(unittest.TestCase):
    def test_mixed_sources_keep_order_duplicates_and_unknown_nested_fields(self):
        url = '  https://airport.example/sub?token=test-token  '
        raw = [url, {'url': url, 'name': ' 第一 ', 'extension': {'tags': ['original']}},
               {'url': url, 'name': '第二'}]
        sources = normalize_sources(raw)
        self.assertTrue(all(isinstance(source, AirportSource) for source in sources))
        self.assertEqual([source.index for source in sources], [0, 1, 2])
        self.assertEqual([source.url for source in sources], [url.strip()] * 3)
        self.assertEqual([source.name for source in sources], ['airport.example', '第一', '第二'])
        self.assertEqual([source.to_legacy() for source in sources], raw)
        raw[1]['extension']['tags'].append('caller mutation')
        exported = sources[1].to_legacy()
        exported['extension']['tags'].append('export mutation')
        self.assertEqual(sources[1].to_legacy()['extension'], {'tags': ['original']})

    def test_node_name_and_info_alias_keep_distinct_legacy_rules(self):
        for alias, name in [('  ', 'airport.example'), (' 名称 ', '名称'),
                            (None, 'None'), (0, '0'), (False, 'False'), (['legacy'], "['legacy']")]:
            with self.subTest(alias=alias):
                source = AirportSource.from_legacy({'url': 'https://airport.example/sub', 'name': alias})
                self.assertEqual(source.name, name)
                self.assertEqual(source.info_alias, alias)
        alias = ['legacy']
        source = AirportSource.from_legacy({'url': 'https://airport.example/sub', 'name': alias})
        source.info_alias.append('changed')
        self.assertEqual(source.info_alias, ['legacy'])

    def test_model_does_not_coerce_invalid_urls_or_introduce_external_validation(self):
        for raw in [None, False, 10, {'url': None}, {'url': 10}, {}, '  ']:
            with self.subTest(raw=raw):
                source = AirportSource.from_legacy(raw, 4)
                self.assertIsNone(source.url)
                self.assertEqual(source.to_legacy(), raw)
        with self.assertRaises(AttributeError):
            AirportSource.from_legacy({'url': None}).info_url
        # 这里不替代现有的 API / safe_get 安全校验，不将 URL 转为 Pydantic URL。
        source = AirportSource.from_legacy('HTTP://localhost/sub?x=%2f')
        self.assertEqual(source.url, 'HTTP://localhost/sub?x=%2f')
        self.assertEqual(AirportSource.from_legacy('').name, 'Airport-1')

    def test_snapshot_is_detached_and_repr_does_not_disclose_url_or_extensions(self):
        raw = [{'url': 'https://airport.example/sub?token=test-token',
                'name': '别名', 'extension': {'secret': 'fixture-private'}}]
        snapshot = AirportSnapshot(normalize_sources(raw), 7)
        exported = snapshot.to_legacy()
        exported[0]['url'] = 'https://changed.example/sub'
        exported[0]['extension']['secret'] = 'changed'
        self.assertEqual(snapshot.to_legacy(), raw)
        self.assertNotIn('fixture-private', repr(snapshot))
        self.assertNotIn('test-token', repr(snapshot))
        self.assertNotIn('airport.example', repr(snapshot))
        with self.assertRaises(FrozenInstanceError):
            snapshot.generation = 8
        with self.assertRaises(FrozenInstanceError):
            snapshot.sources[0].index = 8

    def test_extensions_and_raw_whitespace_participate_in_snapshot_identity(self):
        original = normalize_sources([{'url': 'https://airport.example/sub', 'extra': {'v': 1}}])
        changed = normalize_sources([{'url': 'https://airport.example/sub', 'extra': {'v': 2}}])
        self.assertNotEqual(original, changed)
        trimmed = normalize_sources(['https://airport.example/sub'])
        padded = normalize_sources([' https://airport.example/sub '])
        self.assertEqual(trimmed[0].url, padded[0].url)
        self.assertNotEqual(trimmed, padded)


class AirportSourceCompatibilityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = load_isolated_application(Path(self.temp.name))
        self.service = self.app.airport_service
        self.client = TestClient(self.app.app)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + TEST_ADMIN_TOKEN}
        url = 'https://airport.example/sub?token=test-token'
        self.sources = [url, {'url': url, 'name': ' 第一 ', 'extra': {'nested': [1, 2]}},
                        {'url': url, 'name': '  ', 'legacy': True}]

    def save(self, sources):
        result = self.client.post('/api/airports', json={'urls': sources}, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)

    def test_api_save_read_and_global_import_keep_legacy_shapes_and_extensions(self):
        self.save(self.sources)
        self.assertEqual(self.client.get('/api/airports', headers=self.headers).json()['urls'], self.sources)
        path = Path(self.app.AIRPORTS_PATH)
        self.assertEqual(yaml.safe_load(path.read_text(encoding='utf-8')), self.sources)
        template = self.client.get('/api/template', headers=self.headers).json()
        imported = self.client.post('/api/template/import', json={
            'content': template['content'], 'expected_revision': template['revision'],
            'nodes': [], 'urls': self.sources,
        }, headers=self.headers)
        self.assertEqual(imported.status_code, 200, imported.text)
        self.assertEqual(self.app.load_airports(), self.sources)
        self.assertEqual(yaml.safe_load(path.read_text(encoding='utf-8')), self.sources)

    def test_reads_fetches_and_metadata_do_not_rewrite_source_yaml(self):
        path = Path(self.app.AIRPORTS_PATH)
        original = ('# keep this comment and original formatting\n'
                    '- https://airport.example/sub\n'
                    '- url: https://airport.example/sub\n'
                    '  name: " 自定义 "\n'
                    '  extension: {keep: [true, false]}\n').encode()
        path.write_bytes(original)
        with patch.object(self.service, 'http_get', return_value=response()):
            snapshot = self.service.airport_cache_snapshot()
            self.assertIsInstance(snapshot, AirportSnapshot)
            self.assertTrue(all(isinstance(source, AirportSource) for source in snapshot.sources))
            sources, nodes = self.app.subscription_airports()
            self.assertEqual(sources, yaml.safe_load(original))
            self.assertEqual([node['_airport_name'] for node in nodes], ['airport.example', '自定义'])
            self.app.get_airports_info('all')
        self.assertEqual(path.read_bytes(), original)

    def test_duplicate_url_info_aliases_and_provider_indexes_remain_compatible(self):
        self.save(self.sources)
        remote = response()
        remote.headers['content-disposition'] = 'attachment; filename="Upstream"'
        with patch.object(self.service, 'http_get', return_value=remote) as network:
            info = self.client.get('/api/airports/info?force_indices=all', headers=self.headers)
            self.assertEqual(info.status_code, 200, info.text)
            self.assertEqual([item['name'] for item in info.json()['info']], ['Upstream', ' 第一 ', '  '])
            network.assert_called_once()
            for index in range(3):
                result = self.client.get('/provider/' + str(index), params={'token': TEST_SUBSCRIPTION_TOKEN})
                self.assertEqual(result.status_code, 200, result.text)
            for kind in ['clash', 'egern']:
                result = self.client.get('/sub', params={'token': TEST_SUBSCRIPTION_TOKEN, 'format': kind})
                self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(self.app.load_airports(), self.sources)

    def test_extension_only_change_invalidates_memory_disk_and_previous_snapshot(self):
        self.save(self.sources)
        snapshot = self.service.airport_cache_snapshot()
        with patch.object(self.service, 'http_get', return_value=response()):
            self.app.subscription_airports()
            self.app.get_airports_info('all')
        changed = snapshot.to_legacy()
        changed[1]['extra']['nested'].append(3)
        self.save(changed)
        with self.assertRaises(AirportSourcesChanged):
            self.service.save_cache_to_file([], snapshot)
        self.assertFalse(self.service.cache_path.exists())
        self.assertFalse(self.service.info_cache_path.exists())
        current = self.service.airport_cache_snapshot()
        self.assertGreater(current.generation, snapshot.generation)
        self.assertEqual(current.to_legacy(), changed)

    def test_invalid_api_status_and_no_write_boundaries_remain_compatible(self):
        self.save(self.sources)
        path = Path(self.app.AIRPORTS_PATH)
        original = path.read_bytes()
        for urls, status in [([None], 400), ([{'url': 123}], 400), ([''], 400),
                             (['http://127.0.0.1/sub'], 400), ('not-a-list', 422)]:
            with self.subTest(urls=urls):
                result = self.client.post('/api/airports', json={'urls': urls}, headers=self.headers)
                self.assertEqual(result.status_code, status, result.text)
                self.assertEqual(path.read_bytes(), original)
