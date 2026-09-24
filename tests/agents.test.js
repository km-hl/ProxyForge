const test = require('node:test');
const assert = require('node:assert/strict');
const { agentStatusLabel } = require('../static/agents.js');

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
