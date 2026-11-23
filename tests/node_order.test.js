const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
    SOURCE_LABELS,
    moveOrderItem,
    sortOrderItemsByRegion,
    sortOrderItemsByName,
    sortOrderItemsManagedFirst,
} = require('../static/node-order-utils.js');

test('moveOrderItem moves items without mutating the source array', () => {
    const items = [{ key: 'a' }, { key: 'b' }, { key: 'c' }];
    const moved = moveOrderItem(items, 2, 0);
    assert.deepEqual(moved.map(x => x.key), ['c', 'a', 'b']);
    assert.deepEqual(items.map(x => x.key), ['a', 'b', 'c']);
    assert.deepEqual(moveOrderItem(items, 0, 99).map(x => x.key), ['a', 'b', 'c']);
});

test('sortOrderItemsByRegion prioritizes configured regions then natural name', () => {
    const fakeMatch = name => {
        if (name.includes('SG')) return { code: 'SG' };
        if (name.includes('HK')) return { code: 'HK' };
        if (name.includes('JP')) return { code: 'JP' };
        return null;
    };
    const items = [
        { key: '1', name: 'Unknown Node' },
        { key: '2', name: 'SG-2' },
        { key: '3', name: 'JP-1' },
        { key: '4', name: 'HK-10' },
        { key: '5', name: 'HK-2' },
    ];
    const sorted = sortOrderItemsByRegion(items, fakeMatch);
    assert.deepEqual(sorted.map(x => x.name), [
        'HK-2',
        'HK-10',
        'JP-1',
        'SG-2',
        'Unknown Node',
    ]);
});

test('sortOrderItemsByName sorts naturally and sortOrderItemsManagedFirst groups managed ahead of manual', () => {
    const items = [
        { key: 'm1', name: 'Node-10', source: 'manual' },
        { key: 'a1', name: 'Node-2', source: 'agent' },
        { key: 'c1', name: 'Node-1', source: 'chain' },
    ];
    assert.deepEqual(sortOrderItemsByName(items).map(x => x.key), ['c1', 'a1', 'm1']);
    assert.deepEqual(sortOrderItemsManagedFirst(items).map(x => x.key), ['a1', 'c1', 'm1']);
    assert.equal(SOURCE_LABELS.agent, '托管');
});

test('index.html and app.js wire node-order-btn and node-order-utils safely', () => {
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');
    const appSrc = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
    assert.ok(indexHtml.includes('id="node-order-btn"'));
    assert.ok(indexHtml.includes('/static/node-order-utils.js?v='));
    assert.ok(appSrc.includes('openNodeOrderModal'));
    assert.ok(appSrc.includes("fetchAuth('/nodes/order'"));
});
