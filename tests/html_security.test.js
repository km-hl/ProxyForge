const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { escapeHtml } = require('../static/html-utils.js');

test('HTML escaping neutralizes tags, event attributes, and quotes', () => {
    const payload = '<img src=x onerror="steal()">\'&';

    assert.equal(
        escapeHtml(payload),
        '&lt;img src=x onerror=&quot;steal()&quot;&gt;&#39;&amp;'
    );
});

test('HTML escaping handles nullish and scalar values', () => {
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
    assert.equal(escapeHtml(1234), '1234');
});

test('management credentials are not persisted in browser storage', () => {
    const appSource = fs.readFileSync(
        path.join(__dirname, '..', 'static', 'app.js'),
        'utf8'
    );

    assert.doesNotMatch(appSource, /localStorage|sessionStorage/);
});

test('node import recognizes TUIC and AnyTLS share links', () => {
    const appSource = fs.readFileSync(
        path.join(__dirname, '..', 'static', 'app.js'),
        'utf8'
    );

    assert.match(appSource, /SHARE_LINK_PATTERN[^\n]+tuic\|anytls/);
});

test('third-party scripts are pinned with subresource integrity', () => {
    const indexSource = fs.readFileSync(
        path.join(__dirname, '..', 'static', 'index.html'),
        'utf8'
    );
    const thirdPartyScripts = [...indexSource.matchAll(
        /<script[^>]+src="https:\/\/[^\"]+"[^>]*><\/script>/g
    )];

    assert.ok(thirdPartyScripts.length > 0);
    thirdPartyScripts.forEach(([tag]) => {
        assert.match(tag, /integrity="sha384-[^"]+"/);
        assert.match(tag, /crossorigin="anonymous"/);
    });
});

test('stored subscription and template fields are escaped before HTML insertion', () => {
    const appSource = fs.readFileSync(
        path.join(__dirname, '..', 'static', 'app.js'),
        'utf8'
    );

    for (const unsafeInterpolation of [
        '${displayName}',
        '${emojiName}',
        '${n.server || \'\'}',
        '${parts.slice(1, -1).join(\',\')}',
        '${isNew ? \'\' : keyToEdit}',
        '${yamlStr}',
    ]) {
        assert.equal(
            appSource.includes(unsafeInterpolation),
            false,
            `unescaped interpolation remains: ${unsafeInterpolation}`
        );
    }
});
