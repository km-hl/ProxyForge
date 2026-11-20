const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadRegionsHelper() {
    const src = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
    const start = src.indexOf('const ProxyForgeRegions = (() => {');
    const end = src.indexOf('const getFlagEmoji = ProxyForgeRegions.getFlagEmoji;', start);
    assert.ok(start >= 0 && end > start, 'ProxyForgeRegions block missing in app.js');
    const slice = src.slice(start, end) + '\nconst getFlagEmoji = ProxyForgeRegions.getFlagEmoji;\n';
    const sandbox = {
        globalThis: {},
        document: {
            getElementById: () => null,
        },
        ProxyForgeHtmlUtils: require('../static/html-utils.js'),
    };
    vm.createContext(sandbox);
    vm.runInContext(slice, sandbox);
    return sandbox.globalThis.ProxyForgeRegions || sandbox.ProxyForgeRegions;
}

test('ProxyForgeRegions fixes false-positive flags and prefixes regions cleanly', () => {
    const regions = loadRegionsHelper();
    assert.equal(regions.hasCountryFlag('New Node'), false);
    assert.equal(regions.getFlagEmoji('New Node'), 'New Node');
    assert.equal(regions.getFlagEmoji('Landing'), 'Landing');
    assert.equal(regions.getFlagEmoji('Custom Node'), 'Custom Node');
    assert.equal(regions.getFlagEmoji('DE 01'), '🇩🇪 DE 01');
    assert.equal(regions.getFlagEmoji('Tokyo 02'), '🇯🇵 Tokyo 02');
    assert.equal(regions.applyRegionPrefix('Relay-01', 'jp'), '🇯🇵 Relay-01');
    assert.equal(regions.applyRegionPrefix('🇺🇸 Relay-01', 'sg'), '🇸🇬 Relay-01');
    assert.equal(regions.applyRegionPrefix('🇭🇰 HK Node', 'none'), 'HK Node');
});

test('NetworkSettingsPanel supports IP DoH aliases, protect preset, root ipv6, normal mode, and non-destructive oninput', () => {
    const panel = require('../static/network-settings.js');
    assert.equal(panel.provider('https://223.5.5.5/dns-query'), 'AliDNS');
    assert.equal(panel.provider('https://1.12.12.12/dns-query'), 'DNSPod');

    let draft = { ipv6: false, dns: {}, tun: {} };
    draft = panel.setField(draft, '__root__', 'ipv6', true);
    draft = panel.setField(draft, 'dns', 'fake-ip-range6', 'fc00::/18');
    draft = panel.setField(draft, 'dns', 'enhanced-mode', 'normal');
    assert.equal(draft.ipv6, true);
    assert.equal(draft.dns['fake-ip-range6'], 'fc00::/18');
    assert.equal(draft.dns['enhanced-mode'], 'normal');

    draft = panel.applyPreset(draft, 'protect');
    assert.equal(draft.dns['respect-rules'], true);
    assert.ok(Array.isArray(draft.dns['proxy-server-nameserver']) && draft.dns['proxy-server-nameserver'].length > 0);
    assert.ok(draft.dns['nameserver-policy'] && draft.dns['nameserver-policy']['geosite:cn']);
    assert.ok(draft.dns['nameserver-policy']['geosite:geolocation-!cn']);

    const netPanelSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'network-settings.js'), 'utf8');
    assert.ok(netPanelSrc.includes("container.addEventListener('input'"), 'in-place input handler required');
    assert.ok(netPanelSrc.includes('syncToolbarInPlace'), 'toolbar synced in-place without destroying Save button');
    assert.ok(netPanelSrc.includes("['normal', 'Normal"), 'normal enhanced-mode option present in UI');
    assert.ok(netPanelSrc.includes("field('__root__', 'ipv6'"), 'root ipv6 toggle present in UI');
    assert.ok(netPanelSrc.includes('id="net-range6"'), 'fake-ip-range6 input present in UI');
});

test('agents.js loads cleanly with Dub.co helpers and anti-censorship protocol helpers', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const htmlUtils = require('../static/html-utils.js');
    const icons = require('../static/icons.js');
    const dummyEl = () => ({
        addEventListener: () => {},
        innerHTML: '',
        textContent: '',
        className: '',
        title: '',
        style: {},
    });
    const sandbox = {
        ProxyForgeHtmlUtils: htmlUtils,
        ProxyForgeIcons: icons,
        ProxyForgeRegions: loadRegionsHelper(),
        modalClose: dummyEl(),
        modalCancel: dummyEl(),
        modalOverlay: dummyEl(),
        dashboard: dummyEl(),
        setInterval: () => 0,
        document: {
            getElementById: () => dummyEl(),
            querySelector: () => dummyEl(),
            querySelectorAll: () => [],
            createElement: () => dummyEl(),
            addEventListener: () => {},
        },
        console,
        Math,
        Date,
        Number,
        String,
        Array,
        Object,
        JSON,
    };
    vm.createContext(sandbox);
    vm.runInContext(src, sandbox);

    assert.equal(typeof sandbox.formatAgentBytes, 'function');
    assert.equal(typeof sandbox._formatOsSubtitle, 'function');
    assert.equal(typeof sandbox._closeAllAgentMenus, 'function');
    assert.equal(sandbox._formatOsSubtitle({
        metadata: { os: 'debian', os_version: '12', arch: 'amd64' },
        public_ipv4: '198.51.100.10',
        public_ipv6: true,
    }), 'Debian 12 · amd64 · 198.51.100.10 · IPv6');
    assert.equal(sandbox._escHtml('<script>alert(1)</script>').includes('<script>'), false);

    assert.equal(src.includes('_osBadgeElement'), false, 'Legacy OS emoji badge should be removed');
    assert.equal(src.includes('komari-traffic-box'), false, 'Traffic/quota strip should be removed from cards');
    assert.equal(src.includes('agent-expire'), false, 'Expire/quota/billing inputs should be removed from edit modal');
    assert.equal(src.includes('vless-ws'), false, 'Legacy vless-ws deployment UI should be removed');
    assert.equal(src.includes('重启该托管实例'), false, 'Misleading reboot-like copy must be gone');
    assert.ok(src.includes('重载/重启代理服务进程'), 'Clear process-reload wording required');
    assert.ok(src.includes('komari-agent-card'), 'Server agent card markup required');
    assert.ok(src.includes('pf-dropdown-menu'), 'Overflow dropdown menu required');
    assert.ok(src.includes('rewrite_subscription'), 'Per-forward rewrite_subscription control required');
});
