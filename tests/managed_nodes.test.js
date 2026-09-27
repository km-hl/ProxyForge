const test = require('node:test');
const assert = require('node:assert/strict');
const { matches, statusLabel, managementAction } = require('../static/managed-nodes.js');

const node = { name: 'Tokyo via Singapore', server: 'entry.example.com', kind: 'chain', status: 'success', publishable: true,
    agent: { name: 'Entry A', status: 'online' }, landing: { name: 'Landing B', status: 'offline' } };

test('search covers node, server, entry and landing without excluding offline but published nodes', () => {
    for (const query of ['TOKYO', ' example.com ', 'entry a', 'landing b']) assert.equal(matches(node, query, 'all'), true);
    assert.equal(matches(node, 'missing', 'all'), false);
    assert.equal(matches(node, '', 'published'), true);
    assert.equal(matches(node, '', 'unpublished'), false);
    assert.equal(matches({ ...node, publishable: false }, '', 'unpublished'), true);
});

test('job result, removal and revocation are distinguished from connectivity', () => {
    assert.equal(statusLabel(node), '配置已应用');
    assert.equal(statusLabel({ ...node, status: 'failed' }), '执行失败');
    assert.equal(statusLabel({ ...node, status: 'pending' }), '等待执行');
    assert.equal(statusLabel({ ...node, removed: true }), '已移除监听');
    assert.equal(statusLabel({ ...node, landing: { status: 'revoked' } }), '落地已撤销');
    assert.equal(statusLabel({ ...node, agent: { status: 'revoked' } }), '入口已撤销');
});

test('managed nodes route editing through the correct owner', () => {
    assert.equal(managementAction(node), 'chain');
    assert.equal(managementAction({ ...node, kind: 'direct' }), 'deployment');
});
