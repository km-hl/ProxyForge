const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
    decodeBase64Utf8,
    parseSsLink,
    parseSocks5Link,
    isStatusPlaceholderNode,
    expandShareLinkInput,
    parseExternalOutboundInput,
    splitImportInput,
} = require('../static/share-link-utils.js');

function b64(text, urlSafe = false) {
    let encoded = Buffer.from(text, 'utf8').toString('base64');
    if (urlSafe) {
        encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }
    return encoded;
}

test('parses SS2022 EIH plaintext userinfo with URL-encoded slashes, padding, and second colon', () => {
    const uri = 'ss://2022-blake3-aes-128-gcm:KvwXW%2Fq%2F77N%2FBRRBvaaKDg%3D%3D%3AvkVwd4yC5%2Bx66r550EhVZQ%3D%3D@isp.example.com:28388#HK-ISP';
    const parsed = parseSsLink(uri);
    assert.deepEqual(parsed, {
        kind: 'ss',
        name: 'HK-ISP',
        server: 'isp.example.com',
        port: 28388,
        method: '2022-blake3-aes-128-gcm',
        password: 'KvwXW/q/77N/BRRBvaaKDg==:vkVwd4yC5+x66r550EhVZQ==',
        plugin: '',
    });
});

test('parses SIP002 Base64 userinfo, legacy full-Base64, IPv6, and plugin query', () => {
    const sip002 = `ss://${b64('aes-256-gcm:my:sec@ret', true)}@[2001:db8::1]:8388/?plugin=obfs-local%3Bobfs%3Dtls#IPv6Node`;
    assert.deepEqual(parseSsLink(sip002), {
        kind: 'ss',
        name: 'IPv6Node',
        server: '2001:db8::1',
        port: 8388,
        method: 'aes-256-gcm',
        password: 'my:sec@ret',
        plugin: 'obfs-local;obfs=tls',
    });

    const legacy = `ss://${b64('aes-128-gcm:legacyPass@198.51.100.2:443')}#LegacySS`;
    assert.deepEqual(parseSsLink(legacy), {
        kind: 'ss',
        name: 'LegacySS',
        server: '198.51.100.2',
        port: 443,
        method: 'aes-128-gcm',
        password: 'legacyPass',
        plugin: '',
    });
});

test('filters multi-line status/expiry/traffic nodes and extracts real SS landing', () => {
    const multiLine = [
        'ss://YWVzLTEyOC1nY206bm90aWNl@127.0.0.1:1#%E2%8F%B3%20%E5%88%B0%E6%9C%9F%202026-12-23',
        'ss://YWVzLTEyOC1nY206bm90aWNl@127.0.0.1:1#%F0%9F%93%8A%20%E5%89%A9%E4%BD%99%201000.00GB',
        'ss://2022-blake3-aes-128-gcm:KvwXW%2Fq%2F77N%2FBRRBvaaKDg%3D%3D%3AvkVwd4yC5%2Bx66r550EhVZQ%3D%3D@home.example.net:30001#%E5%AE%B6%E5%AE%BD%E8%90%BD%E5%9C%B0',
    ].join('\n');

    const res = parseExternalOutboundInput(multiLine);
    assert.equal(res.decodedFromBase64, false);
    assert.deepEqual(res.notices, ['⏳ 到期 2026-12-23', '📊 剩余 1000.00GB']);
    assert.equal(res.nodes.length, 1);
    assert.deepEqual(res.nodes[0], {
        kind: 'ss',
        name: '家宽落地',
        server: 'home.example.net',
        port: 30001,
        method: '2022-blake3-aes-128-gcm',
        password: 'KvwXW/q/77N/BRRBvaaKDg==:vkVwd4yC5+x66r550EhVZQ==',
        plugin: '',
    });
});

test('decodes Base64 subscription block (including URL-safe unpadded) with UTF-8 status lines', () => {
    const rawBlock = [
        'ss://YWVzLTEyOC1nY206bm90aWNl@127.0.0.1:1#%E2%8F%B3%20%E5%88%B0%E6%9C%9F%202026-12-23',
        'ss://YWVzLTEyOC1nY206bm90aWNl@127.0.0.1:1#%F0%9F%93%8A%20%E5%89%A9%E4%BD%99%201000.00GB',
        'ss://2022-blake3-aes-128-gcm:KvwXW%2Fq%2F77N%2FBRRBvaaKDg%3D%3D%3AvkVwd4yC5%2Bx66r550EhVZQ%3D%3D@home.example.net:30001#ISP-1',
        'socks5://user1:pass1@isp-socks.example.net:1080#ISP-Socks',
    ].join('\n');

    const encodedUrlSafe = b64(rawBlock, true);
    const decoded = decodeBase64Utf8(encodedUrlSafe);
    assert.ok(decoded.includes('ss://2022-blake3-aes-128-gcm:'));

    const res = parseExternalOutboundInput(encodedUrlSafe);
    assert.equal(res.decodedFromBase64, true);
    assert.deepEqual(res.notices, ['⏳ 到期 2026-12-23', '📊 剩余 1000.00GB']);
    assert.equal(res.nodes.length, 2);
    assert.equal(res.nodes[0].kind, 'ss');
    assert.equal(res.nodes[0].server, 'home.example.net');
    assert.equal(res.nodes[1].kind, 'socks5');
    assert.equal(res.nodes[1].username, 'user1');
    assert.equal(res.nodes[1].password, 'pass1');
});

test('parses socks5:// and socks:// links and classifies status placeholders accurately', () => {
    assert.deepEqual(parseSocks5Link('socks5://u%3Aa:p%40w@1.2.3.4:1080#Residential'), {
        kind: 'socks5',
        name: 'Residential',
        server: '1.2.3.4',
        port: 1080,
        username: 'u:a',
        password: 'p@w',
    });
    assert.equal(isStatusPlaceholderNode({ server: '127.0.0.1', port: 1, name: 'Normal' }), true);
    assert.equal(isStatusPlaceholderNode({ server: 'example.com', port: 1, name: '⏳ 到期 2026-12-23' }), true);
    assert.equal(isStatusPlaceholderNode({ server: '1.2.3.4', port: 8388, name: 'HK-SS' }), false);
});

test('splitImportInput expands Base64 subscription blocks and skips dummy status lines for batch import', () => {
    const rawBlock = [
        'ss://YWVzLTEyOC1nY206bm90aWNl@127.0.0.1:1#%E2%8F%B3%20%E5%88%B0%E6%9C%9F%202026-12-23',
        'ss://2022-blake3-aes-128-gcm:KvwXW%2Fq%2F77N%2FBRRBvaaKDg%3D%3D%3AvkVwd4yC5%2Bx66r550EhVZQ%3D%3D@home.example.net:30001#ISP-1',
        'vless://uuid-1@vless.example.com:443#VLESS-1',
    ].join('\n');
    const encoded = b64(rawBlock, false);
    const sharePattern = /^(vmess|vless|trojan|hysteria2|hy2|ss|tuic|anytls|wireguard):\/\//i;

    const expanded = expandShareLinkInput(encoded);
    assert.equal(expanded.decodedFromBase64, true);
    assert.equal(expanded.links.length, 3);

    const split = splitImportInput(encoded, sharePattern);
    assert.equal(split.decodedFromBase64, true);
    assert.deepEqual(split.skippedNotices, ['⏳ 到期 2026-12-23']);
    assert.equal(split.links.length, 2);
    assert.ok(split.links[0].includes('home.example.net:30001'));
    assert.ok(split.links[1].startsWith('vless://'));
});

test('agents.js wires external outbound link recognizer and aes-128-gcm support', () => {
    const agentsSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');
    assert.ok(agentsSrc.includes('_createOutboundLinkRecognizer'));
    assert.ok(agentsSrc.includes('deployment-outbound-link-slot'));
    assert.ok(agentsSrc.includes('aes-128-gcm'));
    assert.ok(indexHtml.includes('/static/share-link-utils.js?v='));
});
