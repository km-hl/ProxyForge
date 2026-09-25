const test = require('node:test');
const assert = require('node:assert/strict');
const { agentStatusLabel, agentCanRunJobs, agentCanManageRuntime, agentCanDeploy } = require('../static/agents.js');

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
