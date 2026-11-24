const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function makeMockEl(tag = 'div') {
    const classes = new Set();
    const el = {
        tagName: tag.toUpperCase(),
        value: '',
        textContent: '',
        innerHTML: '',
        className: '',
        type: '',
        placeholder: '',
        disabled: false,
        hidden: false,
        checked: false,
        isConnected: true,
        style: {},
        children: [],
        childNodes: [],
        options: [],
        append(...items) {
            this.children.push(...items);
            this.childNodes.push(...items);
            if (this.tagName === 'SELECT') this.options.push(...items);
        },
        replaceChildren(...items) {
            this.children = [...items];
            this.childNodes = [...items];
            if (this.tagName === 'SELECT') this.options = [...items];
        },
        addEventListener() {},
        setAttribute() {},
        getAttribute() { return ''; },
        closest() { return makeMockEl('div'); },
        focus() { this.focused = true; },
        scrollIntoView() {},
        classList: {
            add(c) { classes.add(c); },
            remove(c) { classes.delete(c); },
            contains(c) { return classes.has(c); },
            toggle(c, force) {
                if (force === undefined) {
                    if (classes.has(c)) classes.delete(c);
                    else classes.add(c);
                } else if (force) classes.add(c);
                else classes.delete(c);
            },
        },
    };
    return el;
}

function createModalHarness(fetchAuthImpl) {
    const nodes = new Map();
    const modalBody = makeMockEl('div');
    Object.defineProperty(modalBody, 'innerHTML', {
        set(html) {
            for (const n of nodes.values()) n.isConnected = false;
            nodes.clear();
            for (const m of html.matchAll(/<([a-z0-9-]+)([^>]*)>/gi)) {
                const attrs = m[2];
                const idMatch = attrs.match(/\bid="([^"]+)"/);
                if (!idMatch) continue;
                const el = makeMockEl(m[1]);
                const valMatch = attrs.match(/\bvalue="([^"]*)"/);
                if (valMatch) el.value = valMatch[1];
                if (/\bhidden\b/.test(attrs)) el.hidden = true;
                nodes.set(idMatch[1], el);
            }
        },
        get() { return ''; },
    });
    modalBody.querySelector = () => null;
    const modalConfirm = makeMockEl('button');
    const modalCancel = makeMockEl('button');
    const modalClose = makeMockEl('button');
    const modalOverlay = makeMockEl('div');
    const modalTitle = makeMockEl('span');
    const toasts = [];

    const ctx = vm.createContext({
        fetchAuth: fetchAuthImpl,
        confirm: () => true,
        showToast: (msg, type) => toasts.push({ msg, type }),
        refreshAgents: async () => {},
        setTimeout: fn => fn(),
        crypto: { getRandomValues: arr => { for (let i = 0; i < arr.length; i++) arr[i] = i + 1; return arr; } },
        ProxyForgeHtmlUtils: require('../static/html-utils.js'),
        modalBody,
        modalTitle,
        modalOverlay,
        modalConfirm,
        modalCancel,
        modalClose,
        modalConfirmAction: null,
        modalReturnFocus: null,
        console, Math, Date, Number, String, Array, Object, JSON, Map, Set, Promise, Error, RegExp, encodeURIComponent,
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8'), ctx);
    ctx.document = {
        getElementById: id => nodes.get(id) || null,
        createElement: tag => makeMockEl(tag),
        querySelector: () => null,
        querySelectorAll: () => [],
        addEventListener: () => {},
    };
    const app = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
    vm.runInContext(
        app.slice(app.indexOf('function openModal('), app.indexOf("modalOverlay.addEventListener('keydown'")),
        ctx
    );
    return { ctx, nodes, modalConfirm, modalCancel, modalOverlay, toasts };
}

test('Phase 10.1: deployment modal bottom confirm submits, saves and auto-closes on success', async () => {
    const calls = [];
    const agent = {
        id: 'a'.repeat(32),
        name: 'HK-01',
        status: 'online',
        compatible: true,
        public_ipv4: '1.2.3.4',
        metadata: {
            supported: true,
            job_protocol_version: 1,
            runtime_protocol_version: 1,
            landing_protocol_version: 1,
            deployment_protocol_version: 1,
        },
    };
    const h = createModalHarness(async (url, opts) => {
        calls.push({ url, opts });
        if (url.endsWith('/nodes') && (!opts || !opts.method)) {
            return { ok: true, status: 200, json: async () => ({ nodes: [], public_ipv4: '1.2.3.4', public_ipv6: '' }) };
        }
        if (url.endsWith('/ss-landings')) {
            return { ok: true, status: 200, json: async () => ({ landings: [] }) };
        }
        if (url.endsWith('/nodes') && opts && opts.method === 'POST') {
            return { ok: true, status: 200, json: async () => ({ id: 'n1', restarted: true }) };
        }
        return { ok: true, status: 200, json: async () => ({}) };
    });

    await h.ctx.showAgentDeployment(agent, '__new__');
    assert.equal(h.modalConfirm.textContent, '保存并应用');
    assert.equal(h.modalCancel.textContent, '关闭');
    assert.equal(h.modalCancel.hidden, false);

    // Clicking confirm with blank node name must stay open and show error banner
    await h.ctx.modalConfirmAction();
    assert.equal(h.modalOverlay.classList.contains('active'), true);
    assert.equal(h.nodes.get('deployment-state').hidden, false);
    assert.match(h.nodes.get('deployment-state').textContent, /请填写节点名称/);

    // Filling SS2022 node and clicking bottom confirm saves and auto-closes
    h.nodes.get('deployment-protocol').value = 'ss2022';
    h.nodes.get('deployment-name').value = 'HK SS2022';
    h.nodes.get('deployment-port').value = '8388';
    h.nodes.get('deployment-server').value = '1.2.3.4';
    h.nodes.get('deployment-ss2022-method').value = '2022-blake3-aes-256-gcm';
    h.nodes.get('deployment-ss2022-publish').checked = true;
    await h.ctx.modalConfirmAction();

    const postCall = calls.find(c => c.opts && c.opts.method === 'POST' && c.url.endsWith('/nodes'));
    assert.ok(postCall, 'Bottom confirm button must POST /agents/{id}/nodes');
    const body = JSON.parse(postCall.opts.body);
    assert.equal(body.protocol, 'ss2022');
    assert.equal(body.settings.name, 'HK SS2022');
    assert.equal(body.settings.publish_to_subscription, true);
    assert.equal(h.modalOverlay.classList.contains('active'), false, 'Modal should auto-close after save');
    assert.ok(h.toasts.some(t => t.type === 'success'), 'Success toast expected');
});

test('Phase 10.1: forwards modal separates close-only list view from confirmable create view', async () => {
    const calls = [];
    const agent = {
        id: 'b'.repeat(32),
        name: 'SZ-01',
        status: 'online',
        compatible: true,
        metadata: {
            supported: true,
            job_protocol_version: 1,
            runtime_protocol_version: 1,
            gost_protocol_version: 1,
        },
    };
    const h = createModalHarness(async (url, opts) => {
        calls.push({ url, opts });
        if (url.endsWith('/traffic')) return { ok: true, status: 200, json: async () => ({ total_bytes: 0, tx_bytes: 0, rx_bytes: 0 }) };
        if (url.endsWith('/forwards') && (!opts || !opts.method)) return { ok: true, status: 200, json: async () => ({ forwards: [] }) };
        if (url.endsWith('/forwards') && opts && opts.method === 'POST') return { ok: true, status: 200, json: async () => ({ id: 'f1' }) };
        return { ok: true, status: 200, json: async () => ({}) };
    });

    await h.ctx.showAgentForwards(agent);
    assert.equal(h.modalConfirm.textContent, '关闭');
    assert.equal(h.modalCancel.hidden, true);
    assert.equal(h.nodes.get('fwd-list-view').hidden, false);
    assert.equal(h.nodes.get('fwd-create-view').hidden, true);

    // Switching to create view binds footer to confirm creation
    h.nodes.get('fwd-new-btn').onclick();
    assert.equal(h.nodes.get('fwd-list-view').hidden, true);
    assert.equal(h.nodes.get('fwd-create-view').hidden, false);
    assert.equal(h.modalConfirm.textContent, '确认创建');
    assert.equal(h.modalCancel.textContent, '返回列表');
    assert.equal(h.modalCancel.hidden, false);

    h.nodes.get('fwd-name').value = 'hk-443';
    h.nodes.get('fwd-port').value = '12200';
    h.nodes.get('fwd-proto').value = 'tcp+udp';
    h.nodes.get('fwd-pp').value = '0';
    h.nodes.get('fwd-targets').value = '1.2.3.4:443';
    h.nodes.get('fwd-rewrite-sub').checked = true;

    await h.ctx.modalConfirmAction();
    const postCall = calls.find(c => c.opts && c.opts.method === 'POST' && c.url.endsWith('/forwards'));
    assert.ok(postCall, 'Bottom confirm button must POST forward rule');
    const body = JSON.parse(postCall.opts.body);
    assert.equal(body.mode, 'direct');
    assert.equal(body.name, 'hk-443');
    assert.equal(body.listen_port, 12200);
    assert.equal(body.rewrite_subscription, true);
    assert.equal(h.nodes.get('fwd-list-view').hidden, false, 'Should return to list view after creation');
    assert.equal(h.modalConfirm.textContent, '关闭');
});

test('Phase 10.1: redundant chain & tunnels UI removed and SS2022 inline checkbox layout fixed', () => {
    const agentsSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const styleSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'style.css'), 'utf8');
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');

    assert.equal(agentsSrc.includes('function showAgentChain('), false, 'showAgentChain must be removed');
    assert.equal(agentsSrc.includes('function showGlobalTunnelsModal('), false, 'showGlobalTunnelsModal must be removed');
    assert.equal(agentsSrc.includes('best-exit-list'), false, 'Best Exit UI block must be removed from forwards modal');
    assert.equal(agentsSrc.includes('deployment-apply'), false, 'Duplicate in-body deployment save button must be removed');
    assert.equal(agentsSrc.includes("align-items:flex-end"), false, 'Broken vertical flex-end alignment must be gone');
    assert.ok(agentsSrc.includes('deploy-inline-field'), 'SS2022 checkbox must use .deploy-inline-field');
    assert.ok(styleSrc.includes('.deploy-inline-field'), 'style.css must define .deploy-inline-field');
    assert.match(styleSrc, /\.inline-check\s*\{[^}]*white-space:\s*normal/s, '.inline-check must allow wrapping');
    assert.match(styleSrc, /\.komari-card-actions\s*\{[^}]*repeat\(3,\s*minmax\(0,\s*1fr\)\)/s, 'Server card actions must use 3 columns');
    assert.equal(indexHtml.includes('agent-tunnels-btn'), false, 'Tunnels button must be removed from index.html');
});

test('Phase 10.5: dedicated multi-user panel removes dead inputs, escapes node picker HTML, and creates user cleanly', async () => {
    const subUsersSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'sub-users.js'), 'utf8');
    const appSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');

    for (const deadId of ['m-su-conns', 'm-su-rate', 'm-su-groups', 'm-su-rules']) {
        assert.equal(subUsersSrc.includes(deadId), false, `dead field ${deadId} must not exist in sub-users.js`);
        assert.equal(appSrc.includes(deadId), false, `dead field ${deadId} must not exist in app.js`);
    }
    assert.doesNotMatch(subUsersSrc, /class="hint"|class="panel-subtitle"/, 'Rule 7: no static hint copy');

    const calls = [];
    const copied = [];
    const h = createModalHarness(async (url, opts) => {
        calls.push({ url, opts });
        if (url === '/sub-users/available-nodes') {
            return {
                ok: true,
                status: 200,
                json: async () => ({
                    nodes: [
                        {
                            key: 'agent::a1::n1',
                            name: 'HK <img src=x onerror=alert(1)>',
                            source: 'managed',
                            protocol: 'reality',
                            agent_name: 'HK-01',
                            supports_independent_creds: true,
                            has_relay_rewrite: true,
                        },
                        {
                            key: 'manual::SG-1',
                            name: 'SG-1',
                            source: 'manual',
                            protocol: 'ss',
                            agent_name: '手工节点',
                            supports_independent_creds: false,
                            has_relay_rewrite: false,
                        },
                    ],
                }),
            };
        }
        if (url === '/sub-users' && opts && opts.method === 'POST') {
            return { ok: true, status: 200, json: async () => ({ id: 'u1', username: 'alice', token: 'pfsub_newtoken1234567890' }) };
        }
        if (url === '/sub-users') {
            return { ok: true, status: 200, json: async () => ({ users: [] }) };
        }
        return { ok: true, status: 200, json: async () => ({}) };
    });

    h.ctx.ProxyForgeSubscription = require('../static/subscription-utils.js');
    h.ctx.window = { location: { origin: 'https://panel.example' } };
    h.ctx.state = { subUsers: [] };
    h.ctx.copyTextToClipboard = async (text, msg) => copied.push({ text, msg });
    vm.runInContext(subUsersSrc, h.ctx);

    // Check XSS escaping & badges in node picker renderer
    const renderedPicker = h.ctx.ProxyForgeSubUsers.renderNodePickerList(
        [
            { key: 'agent::a1::n1', name: 'HK <script>x</script>', protocol: 'reality', agent_name: 'HK-01', supports_independent_creds: true, has_relay_rewrite: true },
            { key: 'manual::SG-1', name: 'SG-1', protocol: 'ss', agent_name: '手工节点', supports_independent_creds: false, has_relay_rewrite: false },
        ],
        new Set(['agent::a1::n1']),
        ''
    );
    assert.equal(renderedPicker.includes('<script>'), false, 'Node name must be HTML escaped');
    assert.ok(renderedPicker.includes('&lt;script&gt;'));
    assert.ok(renderedPicker.includes('独立凭据'));
    assert.ok(renderedPicker.includes('共用凭据'));
    assert.ok(renderedPicker.includes('中转'));

    // Open create modal, select all nodes, submit, verify clean payload + universal auto link copied
    await h.ctx.ProxyForgeSubUsers.openSubUserModal(null);
    assert.equal(h.modalConfirm.textContent, '创建用户');
    h.nodes.get('m-su-username').value = 'alice';
    h.nodes.get('m-su-quota-gb').value = '100';
    h.nodes.get('m-su-reset-day').value = '15';
    h.nodes.get('m-su-info-nodes').checked = true;
    h.nodes.get('m-su-enabled').checked = true;

    // Trigger select-all via captured listener
    const selAll = h.nodes.get('m-su-select-all');
    assert.ok(selAll);
    await h.ctx.modalConfirmAction();

    const postCall = calls.find(c => c.url === '/sub-users' && c.opts && c.opts.method === 'POST');
    assert.ok(postCall, 'Must POST /sub-users');
    const body = JSON.parse(postCall.opts.body);
    assert.equal(body.username, 'alice');
    assert.equal(body.quota_bytes, 100 * 1024 * 1024 * 1024);
    assert.equal(body.reset_day, 15);
    assert.equal(body.info_nodes, true);
    assert.equal(body.enabled, true);
    assert.ok(Array.isArray(body.allowed_nodes));
    assert.equal('max_connections' in body, false);
    assert.equal('rate_limit_kbps' in body, false);
    assert.equal('allowed_groups' in body, false);
    assert.equal('forward_rule_ids' in body, false);
    assert.equal(copied.length, 1);
    assert.match(copied[0].text, /^https:\/\/panel\.example\/sub\/pfsub_newtoken1234567890\?name=ProxyForge-alice$/);
});
