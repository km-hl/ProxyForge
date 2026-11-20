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

test('management credentials and sub tokens are not persisted in browser storage', () => {
    for (const file of ['app.js', 'agents.js', 'icons.js', 'managed-nodes.js', 'subscription-utils.js']) {
        const src = fs.readFileSync(path.join(__dirname, '..', 'static', file), 'utf8');
        assert.doesNotMatch(src, /localStorage|sessionStorage/, `browser storage used in ${file}`);
    }
});

test('static index has unique Phase 9 subscription controls, merged panel, and zero static hints', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');
    assert.equal((html.match(/id="sub-users-list"/g) || []).length, 1);
    assert.equal((html.match(/id="copy-btn"/g) || []).length, 1);
    assert.equal((html.match(/id="sub-qr-btn"/g) || []).length, 1);
    assert.equal((html.match(/id="sub-prefer-relay"/g) || []).length, 0);
    assert.equal((html.match(/id="managed-nodes-section"/g) || []).length, 0);
    assert.equal((html.match(/id="manual-nodes-section"/g) || []).length, 1);
    assert.equal((html.match(/id="agent-tunnels-btn"/g) || []).length, 1);
    assert.ok(html.includes('icons.js?v=phase9-'));
    assert.doesNotMatch(html, /class="hint"|class="panel-subtitle"/);
});

test('node import recognizes TUIC, AnyTLS, and WireGuard share links', () => {
    const appSource = fs.readFileSync(
        path.join(__dirname, '..', 'static', 'app.js'),
        'utf8'
    );

    assert.match(appSource, /SHARE_LINK_PATTERN[^\n]+tuic\|anytls\|wireguard/);
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
