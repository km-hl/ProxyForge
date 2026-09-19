const test = require('node:test');
const assert = require('node:assert/strict');

const { filterRules, getRuleType, insertNewRule } = require('../static/rule-utils.js');

test('new routing rules are inserted at the highest priority', () => {
    const rules = [
        'DOMAIN-SUFFIX,existing.example,Proxy',
        'MATCH,Proxy',
    ];

    insertNewRule(rules, 'DOMAIN-SUFFIX,direct.example,DIRECT');

    assert.deepEqual(rules, [
        'DOMAIN-SUFFIX,direct.example,DIRECT',
        'DOMAIN-SUFFIX,existing.example,Proxy',
        'MATCH,Proxy',
    ]);
});

test('new MATCH rules remain at the bottom', () => {
    const rules = ['DOMAIN-SUFFIX,direct.example,DIRECT'];

    insertNewRule(rules, 'MATCH,Proxy');

    assert.deepEqual(rules, [
        'DOMAIN-SUFFIX,direct.example,DIRECT',
        'MATCH,Proxy',
    ]);
});

test('rule type detection tolerates whitespace and case', () => {
    assert.equal(getRuleType('  match,Proxy'), 'MATCH');
});

test('rule search is case-insensitive and preserves original indices', () => {
    const rules = [
        'DOMAIN-SUFFIX,example.com,DIRECT',
        'IP-CIDR,1.1.1.1/32,Proxy',
        'DOMAIN-KEYWORD,GitHub,Proxy',
    ];

    assert.deepEqual(filterRules(rules, 'github'), [
        { rule: 'DOMAIN-KEYWORD,GitHub,Proxy', index: 2 },
    ]);
});

test('rule search supports multiple terms and matches all rule fields', () => {
    const rules = [
        'DOMAIN-SUFFIX,example.com,DIRECT',
        'DOMAIN-SUFFIX,example.org,Proxy',
        'MATCH,Proxy',
    ];

    assert.deepEqual(filterRules(rules, 'example direct'), [
        { rule: 'DOMAIN-SUFFIX,example.com,DIRECT', index: 0 },
    ]);
});

test('blank rule search returns every rule', () => {
    const rules = ['DOMAIN,example.com,DIRECT', 'MATCH,Proxy'];

    assert.deepEqual(filterRules(rules, '   '), [
        { rule: 'DOMAIN,example.com,DIRECT', index: 0 },
        { rule: 'MATCH,Proxy', index: 1 },
    ]);
});
