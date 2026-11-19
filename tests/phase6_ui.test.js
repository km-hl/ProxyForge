const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadAgentsSandbox() {
    const src = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const htmlUtils = require('../static/html-utils.js');
    function makeEl(tag = 'div') {
        return {
            tagName: tag.toUpperCase(),
            value: '',
            textContent: '',
            innerHTML: '',
            className: '',
            type: '',
            placeholder: '',
            autocomplete: '',
            disabled: false,
            hidden: false,
            checked: false,
            style: {},
            children: [],
            childNodes: [],
            append(...items) {
                this.children.push(...items);
                this.childNodes.push(...items);
            },
            replaceChildren(...items) {
                this.children = [...items];
                this.childNodes = [...items];
            },
            addEventListener() {},
            setAttribute() {},
            getAttribute() { return ''; },
        };
    }
    const sandbox = {
        ProxyForgeHtmlUtils: htmlUtils,
        modalClose: makeEl(),
        modalCancel: makeEl(),
        modalOverlay: makeEl(),
        dashboard: makeEl(),
        setInterval: () => 0,
        document: {
            getElementById: () => makeEl(),
            querySelector: () => makeEl(),
            querySelectorAll: () => [],
            createElement: tag => makeEl(tag),
        },
        console,
        Math,
        Date,
        Number,
        String,
        Array,
        Object,
        JSON,
        Map,
        Set,
    };
    vm.createContext(sandbox);
    vm.runInContext(src, sandbox);
    return { sandbox, src, makeEl };
}

test('Phase 6 UI helpers format outbound hops summary and validate hop collection without leaking passwords', () => {
    const { sandbox, makeEl } = loadAgentsSandbox();
    const landings = [
        { agent_id: 'a_ix', agent_name: 'IX', node_id: 'n_ix', node_name: 'IX-SS', server: '1.2.3.4', listen_port: 8388, method: '2022-blake3-aes-256-gcm' },
        { agent_id: 'a_sg', agent_name: 'SG', node_id: 'n_sg', node_name: 'SG-SS', server: '8.8.8.8', listen_port: 9388, method: '2022-blake3-aes-256-gcm' },
    ];
    const summary = sandbox._formatOutboundHopsSummary({
        outbound_mode: 'chain',
        outbound_hops: [
            { kind: 'managed_ss', agent_id: 'a_ix', node_id: 'n_ix' },
            { kind: 'managed_ss', agent_id: 'a_sg', node_id: 'n_sg' },
            { kind: 'socks5', server: '9.9.9.9', port: 1080 },
        ],
    }, landings);
    assert.match(summary, /IX\/IX-SS/);
    assert.match(summary, /SG\/SG-SS/);
    assert.match(summary, /SOCKS5 9\.9\.9\.9:1080/);

    const container = makeEl('div');
    const editor = sandbox._createOutboundHopsEditor({
        container,
        initialHops: [
            { kind: 'managed_ss', agent_id: 'a_sg', node_id: 'n_sg' },
            { kind: 'socks5', server: '9.9.9.9', port: 1080, username: 'u1' },
        ],
        ssLandings: landings,
        currentAgentId: 'a_ix',
    });
    const collected = JSON.parse(JSON.stringify(editor.collect()));
    assert.equal(collected.outbound_hops.length, 2);
    assert.deepEqual(collected.outbound_hops[0], { kind: 'managed_ss', agent_id: 'a_sg', node_id: 'n_sg' });
    assert.equal('password' in collected.outbound_hops[1], false);
    assert.equal('_password' in collected.outbound_hops[1], false);
});

test('Phase 6 static assets include Caddy auxiliary label, chain outbound mode, multi-chain UI and relay+tcp preset', () => {
    const { src } = loadAgentsSandbox();
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');
    assert.ok(src.includes('关联伪装站（运行中，无需单独接管）'), 'Caddy auxiliary badge label required');
    assert.ok(src.includes('has_xray_xver'), 'Xray xver compatibility hint required');
    assert.ok(src.includes('value="chain"'), 'chain outbound_mode option required in deployment modal');
    assert.ok(src.includes('/agents/deployments/ss-landings'), 'ss-landings API fetch required');
    assert.ok(src.includes('TUNNEL_TRANSPORT_PRESETS'), 'go-gost tunnel transport presets required');
    assert.ok(src.includes('relay+tcp (国内↔IX 推荐'), 'CN-to-IX relay+tcp preset required');
    assert.ok(indexHtml.includes('agents.js?v=phase6-'), 'agents.js cache-bust version must be bumped');
});
