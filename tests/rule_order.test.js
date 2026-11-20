const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildRuleString,
    filterRules,
    getRuleTarget,
    getRuleType,
    insertNewRule,
    parseRuleParts,
    removeProxyGroups,
    renameProxyGroupReferences,
} = require('../static/rule-utils.js');

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

test('deleting a proxy group cleans references across proxy-groups and rules', () => {
    const tpl = {
        'proxy-groups': [
            {
                name: '🚀 节点选择',
                type: 'select',
                default: '🇭🇰 香港自动',
                proxies: ['♻️ 自动选择', '🇭🇰 香港自动', '🇯🇵 日本自动', 'DIRECT'],
            },
            {
                name: '🇭🇰 香港自动',
                type: 'url-test',
                include_all: true,
                url: 'http://www.gstatic.com/generate_204',
            },
            {
                name: '🌍 国外流量',
                type: 'select',
                proxies: ['🇭🇰 香港自动', '🇯🇵 日本自动'],
            },
            {
                name: '🍎 仅香港兜底',
                type: 'select',
                proxies: ['🇭🇰 香港自动'],
            },
            {
                name: '✈️ 机场自动过滤',
                type: 'url-test',
                use: ['MyAirport'],
                proxies: ['🇭🇰 香港自动'],
            },
            {
                name: '🇯🇵 日本自动',
                type: 'url-test',
                'include-all': true,
            },
        ],
        rules: [
            'RULE-SET,hk_media,🇭🇰 香港自动,no-resolve',
            'DOMAIN-SUFFIX,google.com,🌍 国外流量',
            'AND,((DOMAIN,a.example),(NETWORK,tcp)),🇭🇰 香港自动',
            'MATCH,🚀 节点选择',
        ],
    };

    const res = removeProxyGroups(tpl, 1);

    assert.deepEqual(res.removedNames, ['🇭🇰 香港自动']);
    assert.equal(res.cleanedGroupRefs, 5);
    assert.equal(res.cleanedRuleRefs, 2);
    assert.equal(res.cleanedTotal, 7);

    assert.deepEqual(
        tpl['proxy-groups'].map(g => g.name),
        ['🚀 节点选择', '🌍 国外流量', '🍎 仅香港兜底', '✈️ 机场自动过滤', '🇯🇵 日本自动']
    );
    assert.equal('default' in tpl['proxy-groups'][0], false);
    assert.deepEqual(tpl['proxy-groups'][0].proxies, ['♻️ 自动选择', '🇯🇵 日本自动', 'DIRECT']);
    assert.deepEqual(tpl['proxy-groups'][1].proxies, ['🇯🇵 日本自动']);
    assert.deepEqual(tpl['proxy-groups'][2].proxies, ['DIRECT']);
    assert.equal('proxies' in tpl['proxy-groups'][3], false);
    assert.deepEqual(tpl.rules, [
        'DOMAIN-SUFFIX,google.com,🌍 国外流量',
        'MATCH,🚀 节点选择',
    ]);
});

test('bulk deleting proxy groups ignores index order and rewrites MATCH fallback', () => {
    const tpl = {
        'proxy-groups': [
            { name: 'GroupA', type: 'select', proxies: ['GroupB', 'DIRECT'] },
            { name: 'GroupB', type: 'select', proxies: ['DIRECT'] },
            { name: 'GroupC', type: 'select', proxies: ['GroupA', 'GroupB'] },
        ],
        rules: [
            'DOMAIN-SUFFIX,a.com,GroupA',
            'MATCH,GroupB',
        ],
    };

    // Pass indices in ascending order as well as duplicates/out-of-range.
    const res = removeProxyGroups(tpl, [0, 1, 1, 99]);

    assert.deepEqual(res.removedNames, ['GroupA', 'GroupB']);
    assert.deepEqual(tpl['proxy-groups'], [
        { name: 'GroupC', type: 'select', proxies: ['DIRECT'] },
    ]);
    assert.deepEqual(tpl.rules, ['MATCH,GroupC']);
});

test('renaming a proxy group updates references in proxy-groups and rules without duplicates', () => {
    const tpl = {
        'proxy-groups': [
            { name: '🚀 主选择', type: 'select', default: '🇭🇰 香港自动', proxies: ['🇭🇰 香港自动', 'HK-Fast'] },
            { name: 'HK-Fast', type: 'url-test', proxies: ['🇭🇰 香港自动', 'DIRECT'] },
        ],
        rules: [
            'DOMAIN-SUFFIX,example.com,🇭🇰 香港自动',
            'IP-CIDR,1.1.1.1/32,🇭🇰 香港自动,no-resolve',
            'MATCH,🇭🇰 香港自动',
        ],
    };

    tpl['proxy-groups'][1].name = 'HK-Fast';
    const res = renameProxyGroupReferences(tpl, '🇭🇰 香港自动', 'HK-Fast');

    assert.equal(res.cleanedGroupRefs, 3);
    assert.equal(res.cleanedRuleRefs, 3);
    assert.equal(tpl['proxy-groups'][0].default, 'HK-Fast');
    assert.deepEqual(tpl['proxy-groups'][0].proxies, ['HK-Fast']);
    assert.deepEqual(tpl['proxy-groups'][1].proxies, ['DIRECT']);
    assert.deepEqual(tpl.rules, [
        'DOMAIN-SUFFIX,example.com,HK-Fast',
        'IP-CIDR,1.1.1.1/32,HK-Fast,no-resolve',
        'MATCH,HK-Fast',
    ]);
    assert.equal(getRuleTarget('IP-CIDR,1.1.1.1/32,HK-Fast,no-resolve'), 'HK-Fast');
});

test('parseRuleParts and buildRuleString handle GEOSITE, options, and logical rules', () => {
    const geo = parseRuleParts('GEOSITE,openai,🚀 节点选择');
    assert.deepEqual(geo, {
        type: 'GEOSITE',
        payload: 'openai',
        target: '🚀 节点选择',
        noResolve: false,
        extraArgs: [],
        isLogical: false,
        raw: 'GEOSITE,openai,🚀 节点选择',
    });

    const cidr = parseRuleParts('IP-CIDR6,2001:db8::/32,DIRECT,no-resolve');
    assert.deepEqual(cidr, {
        type: 'IP-CIDR6',
        payload: '2001:db8::/32',
        target: 'DIRECT',
        noResolve: true,
        extraArgs: [],
        isLogical: false,
        raw: 'IP-CIDR6,2001:db8::/32,DIRECT,no-resolve',
    });

    assert.equal(
        buildRuleString({ type: 'GEOSITE', payload: 'geolocation-!cn', target: '🚀 节点选择', noResolve: false }),
        'GEOSITE,geolocation-!cn,🚀 节点选择'
    );
    assert.equal(
        buildRuleString({ type: 'GEOIP', payload: 'cn', target: 'DIRECT', noResolve: true }),
        'GEOIP,cn,DIRECT,no-resolve'
    );
    assert.equal(
        buildRuleString({ type: 'MATCH', target: '🚀 节点选择' }),
        'MATCH,🚀 节点选择'
    );
    assert.equal(getRuleTarget('IP-CIDR6,2001:db8::/32,DIRECT,no-resolve'), 'DIRECT');
});
