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

    const LOGICAL_RULE_TYPES = new Set(['AND', 'OR', 'NOT', 'SUB-RULE']);

    function getRuleTarget(rule) {
        if (typeof rule !== 'string') return '';
        const type = getRuleType(rule);
        if (LOGICAL_RULE_TYPES.has(type)) {
            const match = rule.match(/\)\s*,\s*([^,]+?)\s*$/);
            return match ? match[1].trim() : '';
        }
        const parts = rule.split(',');
        const targetIndex = type === 'MATCH' ? 1 : 2;
        return parts.length > targetIndex ? parts[targetIndex].trim() : '';
    }

    function rewriteRuleTarget(rule, targetPolicy) {
        if (typeof rule !== 'string') return rule;
        const type = getRuleType(rule);
        if (LOGICAL_RULE_TYPES.has(type)) {
            return rule.replace(/(\)\s*,\s*)([^,]+?)(\s*)$/, `$1${targetPolicy}$3`);
        }
        const parts = rule.split(',');
        const targetIndex = type === 'MATCH' ? 1 : 2;
        if (parts.length <= targetIndex) return rule;
        parts[targetIndex] = targetPolicy;
        return parts.join(',');
    }

    function hasGroupMembers(group) {
        return (Array.isArray(group.proxies) && group.proxies.length > 0)
            || (Array.isArray(group.use) && group.use.length > 0)
            || Boolean(group['include-all']);
    }

    function removeProxyGroups(templateObj, indices) {
        const empty = { removedNames: [], cleanedGroupRefs: 0, cleanedRuleRefs: 0, cleanedTotal: 0 };
        if (!templateObj || typeof templateObj !== 'object') return empty;
        const groups = templateObj['proxy-groups'];
        if (!Array.isArray(groups)) return empty;

        const rawIndices = Array.isArray(indices) ? indices : [indices];
        const indexSet = new Set(
            rawIndices.filter(i => Number.isInteger(i) && i >= 0 && i < groups.length)
        );
        if (!indexSet.size) return empty;

        const candidateNames = new Set();
        const keptGroups = [];
        groups.forEach((group, idx) => {
            if (indexSet.has(idx)) {
                if (group && typeof group.name === 'string' && group.name) {
                    candidateNames.add(group.name);
                }
            } else {
                keptGroups.push(group);
            }
        });
        templateObj['proxy-groups'] = keptGroups;

        const keptNames = new Set(
            keptGroups
                .filter(g => g && typeof g.name === 'string' && g.name)
                .map(g => g.name)
        );
        const removed = new Set(Array.from(candidateNames).filter(name => !keptNames.has(name)));
        if (!removed.size) return empty;

        let cleanedGroupRefs = 0;
        let cleanedRuleRefs = 0;

        for (const group of keptGroups) {
            if (!group || typeof group !== 'object') continue;
            let touched = false;
            if (Array.isArray(group.proxies)) {
                const keptProxies = group.proxies.filter(ref => {
                    if (typeof ref === 'string' && removed.has(ref)) {
                        cleanedGroupRefs += 1;
                        touched = true;
                        return false;
                    }
                    return true;
                });
                if (keptProxies.length) group.proxies = keptProxies;
                else delete group.proxies;
            }
            if (typeof group.default === 'string' && removed.has(group.default)) {
                delete group.default;
                cleanedGroupRefs += 1;
                touched = true;
            }
            if (touched && !hasGroupMembers(group)) {
                group.proxies = ['DIRECT'];
            }
        }

        if (Array.isArray(templateObj.rules)) {
            const firstKeptGroup = keptGroups.find(g => g && typeof g.name === 'string' && g.name);
            const fallbackTarget = firstKeptGroup ? firstKeptGroup.name : 'DIRECT';
            const nextRules = [];
            for (const rule of templateObj.rules) {
                const target = getRuleTarget(rule);
                if (target && removed.has(target)) {
                    cleanedRuleRefs += 1;
                    if (getRuleType(rule) === 'MATCH') {
                        nextRules.push(rewriteRuleTarget(rule, fallbackTarget));
                    }
                    continue;
                }
                nextRules.push(rule);
            }
            templateObj.rules = nextRules;
        }

        return {
            removedNames: Array.from(removed),
            cleanedGroupRefs,
            cleanedRuleRefs,
            cleanedTotal: cleanedGroupRefs + cleanedRuleRefs,
        };
    }

    function renameProxyGroupReferences(templateObj, oldName, newName) {
        const empty = { cleanedGroupRefs: 0, cleanedRuleRefs: 0, cleanedTotal: 0 };
        if (!templateObj || typeof templateObj !== 'object' || !oldName || !newName || oldName === newName) {
            return empty;
        }
        let cleanedGroupRefs = 0;
        let cleanedRuleRefs = 0;

        const groups = templateObj['proxy-groups'];
        if (Array.isArray(groups)) {
            for (const group of groups) {
                if (!group || typeof group !== 'object') continue;
                let touched = false;
                if (Array.isArray(group.proxies)) {
                    const nextProxies = [];
                    for (const ref of group.proxies) {
                        if (ref === oldName) {
                            cleanedGroupRefs += 1;
                            touched = true;
                            if (group.name !== newName && !nextProxies.includes(newName)) {
                                nextProxies.push(newName);
                            }
                        } else if (!nextProxies.includes(ref)) {
                            nextProxies.push(ref);
                        }
                    }
                    if (nextProxies.length) group.proxies = nextProxies;
                    else delete group.proxies;
                }
                if (group.default === oldName) {
                    if (group.name !== newName) group.default = newName;
                    else delete group.default;
                    cleanedGroupRefs += 1;
                    touched = true;
                }
                if (touched && !hasGroupMembers(group)) {
                    group.proxies = ['DIRECT'];
                }
            }
        }

        if (Array.isArray(templateObj.rules)) {
            templateObj.rules = templateObj.rules.map(rule => {
                if (getRuleTarget(rule) === oldName) {
                    cleanedRuleRefs += 1;
                    return rewriteRuleTarget(rule, newName);
                }
                return rule;
            });
        }

        return {
            cleanedGroupRefs,
            cleanedRuleRefs,
            cleanedTotal: cleanedGroupRefs + cleanedRuleRefs,
        };
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

    return Object.freeze({
        getRuleType,
        getRuleTarget,
        insertNewRule,
        filterRules,
        removeProxyGroups,
        renameProxyGroupReferences,
    });
}));
