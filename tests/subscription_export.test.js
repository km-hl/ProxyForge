const test = require('node:test');
const assert = require('node:assert/strict');
const { buildUrl } = require('../static/subscription-utils.js');

test('Egern format and credential escaping survive name/format changes', () => {
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
    assert.throws(() => buildUrl(url.origin, 'test', 'test', 'invalid'));
});
