(function (root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    root.ProxyForgeRuleUtils = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function getRuleType(rule) {
        return String(rule || '').split(',', 1)[0].trim().toUpperCase();
    }

    function insertNewRule(rules, newRule) {
        if (!Array.isArray(rules)) {
            throw new TypeError('rules must be an array');
        }
        if (getRuleType(newRule) === 'MATCH') {
            rules.push(newRule);
        } else {
            rules.unshift(newRule);
        }
        return rules;
    }

    function filterRules(rules, query) {
        if (!Array.isArray(rules)) {
            throw new TypeError('rules must be an array');
        }

        const terms = String(query || '')
            .trim()
            .toLocaleLowerCase()
            .split(/\s+/)
            .filter(Boolean);

        return rules.reduce((matches, rule, index) => {
            const normalizedRule = String(rule || '').toLocaleLowerCase();
            if (!terms.length || terms.every(term => normalizedRule.includes(term))) {
                matches.push({ rule, index });
            }
            return matches;
        }, []);
    }

    return Object.freeze({ getRuleType, insertNewRule, filterRules });
}));
