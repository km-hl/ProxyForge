import os
from pathlib import Path
import shutil
import tempfile
import unittest
from html.parser import HTMLParser
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
from test_api_integration import load_isolated_application, PROJECT_ROOT


class AssetLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        url = values.get('src') if tag == 'script' else values.get('href') if tag == 'link' else None
        if url and url.startswith('/static/'):
            self.urls.append(url)


class ConsoleAssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        module = load_isolated_application(self.runtime)
        shutil.copytree(PROJECT_ROOT / 'static', self.runtime / 'static', dirs_exist_ok=True)
        previous = Path.cwd()
        os.chdir(self.runtime)
        self.addCleanup(os.chdir, previous)
        self.client = TestClient(module.app)
        self.addCleanup(self.client.close)

    def test_fresh_dashboard_escapes_old_unversioned_asset_cache(self):
        home = self.client.get('/')
        self.assertEqual(home.status_code, 200)
        self.assertEqual(home.headers.get('cache-control'), 'no-cache')
        links = AssetLinks()
        links.feed(home.text)
        self.assertGreaterEqual(len(links.urls), 10)
        for url in links.urls:
            with self.subTest(url=url):
                self.assertTrue(urlsplit(url).query, 'Old unversioned browser cache must be bypassed')
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers.get('cache-control'), 'no-cache')
        self.assertEqual(self.client.get('/static/index.html').headers.get('cache-control'), 'no-cache')
        self.assertEqual(self.client.get('/api/config').headers.get('cache-control'), 'no-store')

    def test_unchanged_asset_revalidates_but_changed_bytes_replace_cached_body(self):
        url = '/static/style.css?v=mobile-20261021-2'
        before = self.client.get(url)
        cached = self.client.get(url, headers={'If-None-Match': before.headers['etag']})
        self.assertEqual(cached.status_code, 304)
        self.assertEqual(cached.headers.get('cache-control'), 'no-cache')
        path = self.runtime / 'static/style.css'
        replacement = path.read_bytes() + b'\n/* changed deployment fixture */\n'
        path.write_bytes(replacement)
        changed = self.client.get(url, headers={'If-None-Match': before.headers['etag']})
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(changed.content, replacement)
        self.assertNotEqual(changed.headers['etag'], before.headers['etag'])
        self.assertEqual(changed.headers.get('cache-control'), 'no-cache')
