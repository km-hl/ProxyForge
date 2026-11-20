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
        document: { getElementById: () => null },
        ProxyForgeHtmlUtils: require('../static/html-utils.js'),
    };
    vm.createContext(sandbox);
    vm.runInContext(slice, sandbox);
    return sandbox.globalThis.ProxyForgeRegions || sandbox.ProxyForgeRegions;
}

test('ProxyForgeRegions does not misclassify in-3 or reality-in as India while keeping explicit IN / India', () => {
    const regions = loadRegionsHelper();
    assert.equal(regions.getFlagEmoji('in-3 [sing-box:8443]'), 'in-3 [sing-box:8443]');
    assert.equal(regions.getFlagEmoji('reality-in [xray:4431]'), 'reality-in [xray:4431]');
    assert.equal(regions.getFlagEmoji('node-id-01'), 'node-id-01');
    assert.equal(regions.getFlagEmoji('no-tls'), 'no-tls');
    assert.equal(regions.getFlagEmoji('IN 01'), '🇮🇳 IN 01');
    assert.equal(regions.getFlagEmoji('Mumbai 02'), '🇮🇳 Mumbai 02');
    assert.equal(regions.matchRegion('in')?.code, 'IN');
    assert.equal(regions.getFlagEmoji('Evoxt MY'), '🇲🇾 Evoxt MY');
});

test('Phase 7 static assets include adoption lifecycle actions, auxiliary drawer, manual dedup, and 3-mode Caddy camouflage', () => {
    const agentsSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const managedSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'managed-nodes.js'), 'utf8');
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');

    assert.ok(agentsSrc.includes('deployment-camouflage-mode'), '3-mode Caddy camouflage selector required');
    assert.ok(agentsSrc.includes('deployment-camouflage-template'), 'built-in camouflage template selector required');
    assert.ok(agentsSrc.includes('deployment-camouflage-dir'), 'custom static dir input required');
    assert.ok(agentsSrc.includes('deployment-caddy-summary'), 'Caddy camouflage status summary required');
    assert.ok(agentsSrc.includes('/ignore'), 'adoption ignore action required');
    assert.ok(agentsSrc.includes('/disable'), 'adoption disable host service action required');
    assert.ok(agentsSrc.includes('matched_manual_name'), 'manual node duplicate detection badge required');
    assert.ok(agentsSrc.includes('辅助 / 分流组件'), 'collapsible auxiliary components section required');
    assert.ok(managedSrc.includes("node.adopted_status === 'adopted'"), 'managed-nodes panel must hide un-adopted scan clutter');
    assert.match(indexHtml, /agents\.js\?v=phase[78]-/, 'agents.js cache-bust version must be bumped to phase7+');
    assert.match(indexHtml, /app\.js\?v=phase[78]-/, 'app.js cache-bust version must be bumped to phase7+');
    assert.ok(indexHtml.includes('style.css?v=phase7-'), 'style.css cache-bust version must be bumped to phase7');
});

test('Server cards display prominent per-machine node inventory panel and deployment form pre-validates inputs', () => {
    const agentsSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'agents.js'), 'utf8');
    const styleSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'style.css'), 'utf8');

    assert.ok(agentsSrc.includes("'/agents/deployments/overview'"), 'refreshAgents must fetch per-agent overview');
    assert.ok(agentsSrc.includes('komari-nodes-panel'), 'server cards must render dedicated per-machine nodes panel');
    assert.ok(agentsSrc.includes('komari-node-row'), 'server cards must render clickable per-node rows');
    assert.ok(agentsSrc.includes('komari-scan-summary'), 'server cards must render host scan summary link');
    assert.ok(agentsSrc.includes('请填写节点名称'), 'deployment form must pre-validate missing node name');
    assert.ok(agentsSrc.includes('停用并释放端口'), 'auxiliary drawer must allow disabling host services');
    assert.ok(agentsSrc.includes('acme_certbot_missing'), 'UI must translate allowlisted runtime error codes');
    assert.ok(agentsSrc.includes('acme_port80_in_use'), 'UI must explain port 80 ACME conflict clearly');
    assert.ok(styleSrc.includes('.komari-nodes-panel'), 'style.css must style .komari-nodes-panel');
    assert.ok(styleSrc.includes('.komari-node-row'), 'style.css must style .komari-node-row');
});
