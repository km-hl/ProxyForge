const test = require('node:test');
const assert = require('node:assert/strict');
const { buildUrl, buildUserUrl, encodeQrMatrix, renderQrSvg } = require('../static/subscription-utils.js');

test('Egern and multi-client formats preserve credentials, prefer_relay and escaping', () => {
    const url = new URL(buildUrl('https://example.com', 'public-test&canary=1', ' 中文名称 ', 'egern'));
    assert.equal(url.pathname, '/sub');
    assert.equal(url.searchParams.get('token'), 'public-test&canary=1');
    assert.equal(url.searchParams.has('canary'), false);
    assert.equal(url.searchParams.get('name'), '中文名称');
    assert.equal(url.searchParams.get('format'), 'egern');

    const legacy = new URL(buildUrl(url.origin, 'replacement', '', 'clash'));
    assert.equal(legacy.searchParams.has('format'), false);
    assert.equal(legacy.searchParams.get('name'), 'ProxyForge');
    assert.equal(legacy.searchParams.get('token'), 'replacement');

    for (const fmt of ['singbox', 'surge', 'uri']) {
        const targetUrl = new URL(buildUrl(url.origin, 'tok', 'MySub', fmt, { preferRelay: true }));
        assert.equal(targetUrl.searchParams.get('target'), fmt);
        assert.equal(targetUrl.searchParams.get('prefer_relay'), 'true');
        assert.equal(targetUrl.searchParams.has('format'), false);
    }

    const userUrl = new URL(buildUserUrl('https://example.com', 'usr/tok+1', 'Alice', 'singbox', { preferRelay: true }));
    assert.equal(userUrl.pathname, '/sub/usr%2Ftok%2B1');
    assert.equal(userUrl.searchParams.get('target'), 'singbox');
    assert.equal(userUrl.searchParams.get('prefer_relay'), 'true');
    assert.equal(userUrl.searchParams.get('name'), 'Alice');

    assert.throws(() => buildUrl(url.origin, 'test', 'test', 'invalid'));
    assert.throws(() => buildUserUrl(url.origin, 'test', 'test', 'invalid'));
});

test('self-contained QR SVG encoder builds ISO matrix with valid bounds', () => {
    const matrix = encodeQrMatrix('https://example.com/sub/test-token');
    assert.ok(matrix.length >= 25);
    assert.equal(matrix.length, matrix[0].length);
    const svg = renderQrSvg('https://example.com/sub/test-token');
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 \d+ \d+"/);
    assert.match(svg, /<path d="[^"]+"/);
    assert.throws(() => renderQrSvg('x'.repeat(300)));
});
