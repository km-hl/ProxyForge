const test = require('node:test');
const assert = require('node:assert/strict');
const network = require('../static/network-settings.js');
const cases = require('./fixtures/network_config_cases.json');

test('Bootstrap shortcuts only generate IP-host endpoints without changing regular choices', () => {
    assert.equal(network.providerOptions('AliDNS').DoH, 'https://dns.alidns.com/dns-query');
    assert.deepEqual(network.providerOptions('AliDNS', true), { UDP: '223.5.5.5' });
    assert.equal(network.providerOptions('Cloudflare', true).DoH, 'https://1.1.1.1/dns-query');
    assert.deepEqual(network.providerOptions('自定义', true), {});
});

test('presets preserve unknown fields and never mutate the input', () => {
    for (const item of cases) {
        const before = structuredClone(item.config);
        const next = network.applyPreset(item.config, 'protect');
        assert.deepEqual(item.config, before);
        for (const [key, value] of Object.entries(before)) if (!['dns', 'tun'].includes(key)) assert.deepEqual(next[key], value);
        assert.equal(next.dns.enable, true);
        assert.deepEqual(network.hijackState(next.tun['dns-hijack']), { udp: true, tcp: true });
    }
});
test('compatible mode only disables existing TUN and leaves absent sections absent', () => {
    assert.deepEqual(network.applyPreset({}, 'compatible'), {});
    const original = { dns: { enable: true, 'prefer-h3': true }, tun: { enable: true, mtu: 1400 } };
    assert.deepEqual(network.applyPreset(original, 'compatible'), { dns: original.dns, tun: { enable: false, mtu: 1400 } });
});
test('strict preset is idempotent, ordinary preset does not downgrade strict-route', () => {
    const strict = network.applyPreset({ tun: { 'dns-hijack': ['192.168.1.1:53'] } }, 'strict');
    assert.equal(strict.tun['strict-route'], true);
    assert.deepEqual(network.applyPreset(strict, 'strict'), strict);
    assert.deepEqual(network.applyPreset(strict, 'protect'), strict);
    assert.ok(strict.tun['dns-hijack'].includes('192.168.1.1:53'));
});
test('editing IPv6 preserves advanced DNS and all unrelated fields', () => {
    const original = cases.find(c => c.name === 'preserve_unknown').config;
    const next = network.setField(original, 'dns', 'ipv6', true);
    assert.equal(next.dns['cache-algorithm'], 'arc');
    assert.equal(next.dns['prefer-h3'], true);
    assert.deepEqual(next.tun, original.tun);
    assert.equal(original.dns.ipv6, undefined);
});

test('editing and presets preserve baseline DNS additions and future fields', () => {
    const additions = { 'fake-ip-ttl': 0, 'fake-ip-range6': 'fdfe:dcba:9876::/64',
        'ipv6-timeout': 150, 'cache-algorithm': 'arc', 'cache-max-size': 4096,
        'fallback-lazy-query': true, 'proxy-server-nameserver-policy': { '+.proxy.test': '192.0.2.53' },
        'future-option': { custom: true } };
    const original = { dns: structuredClone(additions), tun: { 'include-uid': [1000], 'future-tun': true } };
    for (const next of [network.setField(original, 'dns', 'ipv6', true), network.applyPreset(original, 'strict')]) {
        for (const [key, value] of Object.entries(additions)) assert.deepEqual(next.dns[key], value);
        assert.deepEqual(next.tun['include-uid'], [1000]);
        assert.equal(next.tun['future-tun'], true);
    }
    assert.deepEqual(original.dns, additions);
});
test('DNS CRUD preserves raw addresses, ordering and other lists', () => {
    const original = { dns: { nameserver: ['https://dns.test/dns-query#RULES', '192.168.1.1'], fallback: ['system'] } };
    let next = network.editList(original, 'dns', 'nameserver', -1, 'quic://[::1]:853');
    next = network.editList(next, 'dns', 'nameserver', 1, 'dhcp://eth0');
    next = network.editList(next, 'dns', 'nameserver', 2, undefined);
    assert.deepEqual(next.dns.nameserver, ['https://dns.test/dns-query#RULES', 'dhcp://eth0']);
    assert.deepEqual(next.dns.fallback, original.dns.fallback);
});
test('Hijack defaults, UDP aliases and custom ranges are handled separately', () => {
    assert.deepEqual(network.hijackState(undefined), { udp: true, tcp: false });
    const input = { tun: { 'dns-hijack': ['udp://any:53', '192.168.1.1:53', 'tcp://192.168.1.1:53'] } };
    const off = network.setHijack(input, 'udp', false);
    assert.deepEqual(off.tun['dns-hijack'], input.tun['dns-hijack'].slice(1));
    assert.deepEqual(network.hijackState(off.tun['dns-hijack']), { udp: false, tcp: false });
    assert.deepEqual(network.setHijack({}, 'udp', false).tun['dns-hijack'], []);
});
test('switching mode retains filter and unknown filter modes', () => {
    const input = { dns: { 'enhanced-mode': 'fake-ip', 'fake-ip-filter-mode': 'rule', 'fake-ip-filter': ['MATCH,real-ip'] } };
    const output = network.setField(input, 'dns', 'enhanced-mode', 'redir-host');
    assert.equal(output.dns['fake-ip-filter-mode'], 'rule');
    assert.deepEqual(output.dns['fake-ip-filter'], ['MATCH,real-ip']);
});
test('recommendations skip collisions and preserve scalar policies and order', () => {
    const input = { dns: { 'nameserver-policy': { 'geosite:cn': 'system', '+.internal': ['192.168.1.1'] } } };
    const next = network.recommendPolicies(input);
    assert.equal(next.dns['nameserver-policy']['geosite:cn'], 'system');
    assert.deepEqual(Object.keys(next.dns['nameserver-policy']), ['geosite:cn', '+.internal', 'geosite:geolocation-!cn']);
    assert.deepEqual(network.recommendPolicies(next), next);
});
test('policy rename preserves position and refuses collisions', () => {
    const input = { dns: { 'nameserver-policy': { a: 'system', b: ['1.1.1.1'], c: 'system' } } };
    const output = network.editPolicy(input, 'b', 'd', ['8.8.8.8']);
    assert.deepEqual(Object.keys(output.dns['nameserver-policy']), ['a', 'd', 'c']);
    assert.throws(() => network.editPolicy(input, 'b', 'a', ['8.8.8.8']));
});

test('recommended policies detach aliases shared with other DNS fields', () => {
    const shared = { '+.internal': 'system' };
    const original = { dns: { 'nameserver-policy': shared, 'proxy-server-nameserver-policy': shared } };
    const result = network.recommendPolicies(original);
    assert.deepEqual(result.dns['proxy-server-nameserver-policy'], { '+.internal': 'system' });
    assert.equal(original.dns['nameserver-policy']['geosite:cn'], undefined);
    assert.ok(result.dns['nameserver-policy']['geosite:cn']);
});
test('special matcher keys remain own data without prototype pollution', () => {
    let output = network.editPolicy({}, null, '__proto__', ['1.1.1.1']);
    output = network.editPolicy(output, null, 'constructor', ['8.8.8.8']);
    assert.deepEqual(output.dns['nameserver-policy'].__proto__, ['1.1.1.1']);
    assert.equal(Object.getPrototypeOf(output.dns['nameserver-policy']), Object.prototype);
    assert.equal({}.polluted, undefined);
});
test('invalid structures cannot be silently replaced', () => {
    assert.throws(() => network.applyPreset({ dns: [] }, 'protect'));
    assert.throws(() => network.applyPreset({ tun: null }, 'compatible'));
    assert.throws(() => network.editList({ dns: { nameserver: 'system' } }, 'dns', 'nameserver', 0, '1.1.1.1'));
});
test('restoring missing fields does not create sections or delete siblings', () => {
    assert.deepEqual(network.setField({}, 'dns', 'ipv6', undefined), {});
    assert.deepEqual(network.setField({ dns: { ipv6: false, 'prefer-h3': true } }, 'dns', 'ipv6', undefined), { dns: { 'prefer-h3': true } });
});
test('editing detaches YAML aliases across sections and list fields', () => {
    const shared = { ipv6: false };
    const updated = network.setField({ dns: shared, experimental: shared }, 'dns', 'ipv6', true);
    assert.equal(updated.experimental.ipv6, false);
    const list = ['1.1.1.1'];
    const lists = network.editList({ dns: { nameserver: list, fallback: list } }, 'dns', 'nameserver', -1, '8.8.8.8');
    assert.deepEqual(lists.dns.fallback, ['1.1.1.1']);
});
