const test = require('node:test');
const assert = require('node:assert/strict');
const { agentStatusLabel, agentCanRunJobs, agentCanManageRuntime, agentCanDeploy, agentCanLand, agentCanChain } = require('../static/agents.js');

test('chain changes require explicit upgraded capability', () => {
    const agent = { status: 'online', compatible: true, metadata: { job_protocol_version: 1, runtime_protocol_version: 1, supported: true } };
    assert.equal(agentCanChain(agent), false);
    agent.metadata.chain_protocol_version = 1;
    assert.equal(agentCanChain(agent), true);
    agent.status = 'revoked';
    assert.equal(agentCanChain(agent), false);
});

test('inventory separates online state, compatibility and supported platform', () => {
    const agent = { status: 'online', compatible: true, metadata: { supported: true } };
    assert.equal(agentStatusLabel(agent), '在线');
    agent.compatible = false;
    assert.match(agentStatusLabel(agent), /协议不兼容/);
    agent.metadata.supported = false;
    assert.match(agentStatusLabel(agent), /未支持/);
    agent.status = 'revoked';
    assert.match(agentStatusLabel(agent), /已撤销/);
});

test('jobs require explicit capability and a non-revoked compatible Agent', () => {
    const agent = { status: 'online', compatible: true, metadata: {} };
    assert.equal(agentCanRunJobs(agent), false);
    agent.metadata.job_protocol_version = 1;
    assert.equal(agentCanRunJobs(agent), true);
    agent.metadata.job_protocol_version = 2;
    assert.equal(agentCanRunJobs(agent), false);
    agent.metadata.job_protocol_version = 1;
    agent.status = 'revoked';
    assert.equal(agentCanRunJobs(agent), false);
    agent.status = 'online'; agent.compatible = false;
    assert.equal(agentCanRunJobs(agent), false);
});

test('runtime changes additionally require supported platform and local helper capability', () => {
    const agent = { status: 'online', compatible: true, metadata: { job_protocol_version: 1, supported: true } };
    assert.equal(agentCanManageRuntime(agent), false);
    agent.metadata.runtime_protocol_version = 1;
    assert.equal(agentCanManageRuntime(agent), true);
    agent.metadata.supported = false;
    assert.equal(agentCanManageRuntime(agent), false);
    agent.metadata.supported = true; agent.status = 'revoked';
    assert.equal(agentCanManageRuntime(agent), false);
});

test('deployment requires its own upgraded helper capability', () => {
    const agent = { status: 'online', compatible: true, metadata: { job_protocol_version: 1, runtime_protocol_version: 1, supported: true } };
    assert.equal(agentCanDeploy(agent), false);
    agent.metadata.deployment_protocol_version = 1;
    assert.equal(agentCanDeploy(agent), true);
    agent.status = 'revoked';
    assert.equal(agentCanDeploy(agent), false);
});

test('landing capability is independent from Reality and requires the runtime', () => {
    const agent = { status: 'online', compatible: true, metadata: { job_protocol_version: 1, runtime_protocol_version: 1, deployment_protocol_version: 1, supported: true } };
    assert.equal(agentCanLand(agent), false);
    agent.metadata.landing_protocol_version = 1;
    agent.metadata.deployment_protocol_version = 0;
    assert.equal(agentCanLand(agent), true);
    assert.equal(agentCanDeploy(agent), false);
    agent.metadata.runtime_protocol_version = 0;
    assert.equal(agentCanLand(agent), false);
});

// Exercise asynchronous enrollment against a small DOM harness, without a browser dependency.
const fs = require('node:fs');
const vm = require('node:vm');
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function installUI(fetchAuth, clipboard = async () => {}) {
    const nodes = new Map();
    function element() {
        return { value: '', textContent: '', isConnected: true, children: [], hidden: true,
            append(...items) { this.children.push(...items); }, setAttribute() {},
            focus() { this.focused = true; }, select() { this.selected = true; },
            classList: { active: false, add() { this.active = true; }, remove() { this.active = false; }, contains() { return this.active; } } };
    }
    const body = element();
    Object.defineProperty(body, 'innerHTML', { set(html) {
        for (const node of nodes.values()) node.isConnected = false;
        nodes.clear();
        for (const match of html.matchAll(/id="([^"]+)"/g)) nodes.set(match[1], element());
    } });
    const ctx = vm.createContext({ fetchAuth, navigator: { clipboard: { writeText: clipboard } },
        showToast: () => {}, setTimeout: () => {}, modalBody: body, modalTitle: element(),
        modalOverlay: element(), modalConfirm: element(), modalConfirmAction: null, modalReturnFocus: null });
    vm.runInContext(fs.readFileSync('static/agents.js', 'utf8'), ctx); // no document, skip event wiring
    ctx.document = { getElementById: id => nodes.get(id), createElement: element, querySelector: () => null };
    const app = fs.readFileSync('static/app.js', 'utf8');
    vm.runInContext(app.slice(app.indexOf('function openModal('), app.indexOf("modalOverlay.addEventListener('keydown'")), ctx);
    return { ctx, nodes, add: () => ctx.addAgent(), close: () => ctx.closeModal() };
}
const installInfo = { available: true, controller_url: 'https://controller.example', agent_version: '0.6.0',
    bootstrap_commit: 'a'.repeat(40), bootstrap_sha256: 'b'.repeat(64), source_commit: 'c'.repeat(40),
    commands: { install: 'verified install command', check: 'verified check command', runtime: 'explicit helper command' } };
const reply = data => ({ json: async () => data });

test('copy flow preserves commands as text, requests token only on confirmation and prevents duplicate issuance', async () => {
    const pending = deferred(), calls = [], copies = [];
    const ui = installUI(async (path, options) => {
        calls.push([path, options]);
        return path.endsWith('install-command') ? reply(installInfo) : pending.promise;
    }, async value => copies.push(value));
    await ui.add();
    assert.equal(calls.length, 1);
    const [field, button] = ui.nodes.get('agent-install-commands').children;
    assert.equal(field.value, installInfo.commands.install);
    await button.onclick(); assert.deepEqual(copies, [field.value]);
    ui.nodes.get('new-agent-name').value = 'my VPS';
    const first = ui.ctx.modalConfirmAction();
    await ui.ctx.modalConfirmAction(); assert.equal(calls.length, 2);
    pending.resolve(reply({ registration_token: 'ephemeral-test-secret', expires_at: 123 })); await first;
    assert.equal(ui.nodes.get('agent-registration-token').value, 'ephemeral-test-secret');
    assert.equal(field.value, installInfo.commands.install);
    const tokenField = ui.nodes.get('agent-registration-token');
    ui.close(); assert.equal(tokenField.value, '');
});

test('closing or replacing a pending registration never resurrects its secret', async () => {
    for (const replace of [false, true]) {
        const pending = deferred();
        const ui = installUI(async path => path.endsWith('install-command') ? reply(installInfo) : pending.promise);
        await ui.add(); ui.nodes.get('new-agent-name').value = 'my VPS';
        const work = ui.ctx.modalConfirmAction();
        ui.close();
        if (replace) await ui.add();
        pending.resolve(reply({ registration_token: 'late-secret', expires_at: 123 })); await work;
        assert.equal(ui.nodes.get('agent-registration-token').value, '');
    }
});

test('late installation response cannot overwrite another dialog; missing config has no copy buttons', async () => {
    const pending = deferred(); const ui = installUI(async () => pending.promise);
    const work = ui.add(); ui.ctx.openModal('another', '<input id="another">', () => {});
    pending.resolve(reply(installInfo)); await work;
    assert.equal(ui.ctx.modalTitle.textContent, 'another');
    const unavailable = installUI(async () => reply({ available: false, message: '请配置地址' }));
    await unavailable.add();
    assert.equal(unavailable.nodes.get('agent-install-commands').children.length, 0);
    assert.equal(unavailable.ctx.modalConfirm.disabled, false);
});

test('clipboard denial selects plain command for manual copy', async () => {
    const ui = installUI(async () => reply(installInfo), async () => { throw Error('denied'); });
    await ui.add(); const [field, button] = ui.nodes.get('agent-install-commands').children;
    await button.onclick(); assert.equal(field.selected, true);
});

test('login expiry closes the real modal and clears registration secret', async () => {
    const ui = installUI(async path => reply(path.endsWith('install-command') ? installInfo :
        { registration_token: 'temporary', expires_at: 123 }));
    await ui.add(); ui.nodes.get('new-agent-name').value = 'host'; await ui.ctx.modalConfirmAction();
    Object.assign(ui.ctx, { dashboard: { style: {} }, loginOverlay: { classList: { add() {} } },
        tokenInput: {}, loginError: { style: {} } });
    const app = fs.readFileSync('static/app.js', 'utf8');
    vm.runInContext(app.slice(app.indexOf('function showLogin()'), app.indexOf('async function logout()')), ui.ctx);
    ui.ctx.showLogin(); assert.equal(ui.nodes.get('agent-registration-token').value, '');
    assert.equal(ui.ctx.modalOverlay.classList.contains('active'), false);
});
