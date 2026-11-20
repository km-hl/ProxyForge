const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadSharedPortHelpers() {
    const src = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const start = src.indexOf('const SHARED_PORT_PROTOCOLS = new Set(');
    const end = src.indexOf('function _formatOutboundHopsSummary(', start);
    assert.ok(start >= 0 && end > start, 'Shared port helpers missing in static/agents.js');
    const slice = src.slice(start, end);
    const sandbox = {
        LANDING_PROTO_META: {
            reality: { tlsModes: [['reality', 'ext'], ['acme_http', 'http'], ['acme_dns', 'dns']] },
            hysteria2: { tlsModes: [['acme_http', 'http'], ['acme_dns', 'dns']] },
            trojan: { tlsModes: [['acme_http', 'http'], ['acme_dns', 'dns']] },
            anytls: { tlsModes: [['acme_http', 'http'], ['acme_dns', 'dns']] },
            ss2022: { tlsModes: [['none', 'none']] },
        },
    };
    vm.createContext(sandbox);
    vm.runInContext(
        slice +
        '\nthis._exports = { SHARED_PORT_PROTOCOLS, _normalizeNodeProto, _isShareableProtocol, _findSharedPortPeers, _listReusableListenerHosts, _copySharedListenerSettings, _nodeOutboundRoleText };',
        sandbox
    );
    return sandbox._exports;
}

test('Phase 8 shared-port helpers identify peers, normalize legacy vless-reality, and copy listener fields', () => {
    const h = loadSharedPortHelpers();
    const nodes = [
        {
            id: 'p1',
            is_primary: true,
            protocol: 'vless-reality',
            settings: {
                name: '🇲🇾 EVOXT - VM 0.5',
                listen_port: 443,
                server_name: 'realityevoxt.2021327.xyz',
                tls_mode: 'acme_http',
                camouflage_mode: 'template',
                camouflage_template: 'corporate',
                reality_public_key: 'PUBKEY_HOST',
                outbound_mode: 'direct',
            },
        },
        {
            id: 'e1',
            is_primary: false,
            protocol: 'reality',
            settings: {
                name: '🇸🇬 EVOXT → SG',
                listen_port: 443,
                domain: 'realityevoxt.2021327.xyz',
                tls_mode: 'acme_http',
                outbound_mode: 'chain',
                outbound_hops: [{ kind: 'managed_ss', agent_id: 'a'.repeat(32), node_id: 'sg1' }],
            },
        },
        {
            id: 'e2',
            is_primary: false,
            protocol: 'ss2022',
            settings: { name: 'SS Landing', listen_port: 8388, outbound_mode: 'direct' },
        },
        {
            id: 'e3',
            is_primary: false,
            protocol: 'hysteria2',
            settings: { name: 'Hy2 443', listen_port: 443, domain: 'hy2.example.com', tls_mode: 'acme_http', outbound_mode: 'direct' },
        },
    ];

    assert.equal(h._normalizeNodeProto('vless-reality'), 'reality');
    assert.equal(h._isShareableProtocol('reality'), true);
    assert.equal(h._isShareableProtocol('vless-reality'), true);
    assert.equal(h._isShareableProtocol('trojan'), true);
    assert.equal(h._isShareableProtocol('anytls'), true);
    assert.equal(h._isShareableProtocol('hysteria2'), true);
    assert.equal(h._isShareableProtocol('ss2022'), false);

    // Peers match same normalized protocol + port, never cross-protocol (Hy2 UDP 443 != Reality TCP 443)
    const peers = h._findSharedPortPeers(nodes, 'reality', 443, 'e1');
    assert.equal(peers.length, 1);
    assert.equal(peers[0].id, 'p1');
    assert.equal(h._findSharedPortPeers(nodes, 'ss2022', 8388).length, 0);
    assert.equal(h._findSharedPortPeers(nodes, 'trojan', 443).length, 0);

    // Reusable listener hosts deduplicate per (protocol, port) and prefer primary, excluding ss2022
    const hosts = h._listReusableListenerHosts(nodes);
    assert.equal(hosts.length, 2);
    assert.deepEqual(Array.from(hosts, x => x.id).sort(), ['e3', 'p1']);

    // Copying shared listener fields inherits domain/tls/camouflage/pubkey cleanly
    const target = { name: 'New Chain', server: '1.2.3.4', listen_port: 443, outbound_mode: 'chain' };
    h._copySharedListenerSettings(target, nodes[0]);
    assert.equal(target.domain, 'realityevoxt.2021327.xyz');
    assert.equal(target.tls_mode, 'acme_http');
    assert.equal(target.camouflage_mode, 'template');
    assert.equal(target.camouflage_template, 'corporate');
    assert.equal(target.reality_public_key, 'PUBKEY_HOST');

    // Outbound role labels
    assert.equal(h._nodeOutboundRoleText(nodes[0]), '直连');
    assert.equal(h._nodeOutboundRoleText(nodes[1]), '链式×1');
});

test('Phase 8 static UI exposes shared-port selector in chain modal and shared notice in deployment modal safely', () => {
    const agentsSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');

    assert.ok(agentsSrc.includes('chain-listener-mode'), 'Chain modal must include port/listener sharing mode selector');
    assert.ok(agentsSrc.includes('chain-share-banner'), 'Chain modal must show shared listener banner');
    assert.ok(agentsSrc.includes('deployment-share-notice'), 'Deployment modal must show shared listener notice');
    assert.ok(agentsSrc.includes('♻️ 复用已有端口'), 'Chain modal must offer one-click reuse option');
    assert.ok(agentsSrc.includes('auth_user'), 'UI hints must explain sing-box auth_user split routing');
    assert.ok(indexHtml.includes('agents.js?v=phase8-'), 'index.html must bust cache for Phase 8 agents.js');
    assert.ok(indexHtml.includes('app.js?v=phase8-'), 'index.html must bust cache for Phase 8 app.js');
});

test('ProxyForgeRegions supports CN / 中国 quick selection without misclassifying CN2 or 深港IX', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
    const start = src.indexOf('const ProxyForgeRegions = (() => {');
    const end = src.indexOf('const getFlagEmoji = ProxyForgeRegions.getFlagEmoji;', start);
    const htmlUtils = require('../static/html-utils.js');
    const sandbox = {
        globalThis: {},
        document: { getElementById: () => null },
        ProxyForgeHtmlUtils: htmlUtils,
        escapeHtml: htmlUtils.escapeHtml,
    };
    vm.createContext(sandbox);
    vm.runInContext(src.slice(start, end) + '\nconst getFlagEmoji = ProxyForgeRegions.getFlagEmoji;\n', sandbox);
    const regions = sandbox.globalThis.ProxyForgeRegions || sandbox.ProxyForgeRegions;

    assert.equal(regions.matchRegion('cn')?.code, 'CN');
    assert.equal(regions.matchRegion('中国')?.flag, '🇨🇳');
    assert.equal(regions.getFlagEmoji('Aliyun 深圳'), '🇨🇳 Aliyun 深圳');
    assert.equal(regions.getFlagEmoji('vps.soy - 深港IX'), '🇭🇰 vps.soy - 深港IX');
    assert.equal(regions.getFlagEmoji('LA CN2 GIA'), 'LA CN2 GIA');
    assert.ok(regions.renderRegionPickerHtml('p-cn', '').includes('🇨🇳 中国'));
});
