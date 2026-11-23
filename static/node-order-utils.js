(function (root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    root.ProxyForgeNodeOrder = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    const REGION_PRIORITY = [
        'CN', 'HK', 'MO', 'TW', 'JP', 'SG', 'KR', 'US', 'GB', 'DE', 'FR', 'NL',
        'MY', 'TH', 'VN', 'PH', 'ID', 'IN', 'CA', 'AU', 'CH', 'SE', 'FI', 'NO',
        'IE', 'IT', 'ES', 'PL', 'AT', 'TR', 'RU', 'AE', 'BR', 'AR', 'CL', 'MX', 'ZA',
    ];
    const REGION_RANK = new Map(REGION_PRIORITY.map((code, idx) => [code, idx]));
    const SOURCE_LABELS = Object.freeze({
        agent: '托管',
        chain: '链路',
        adopted: '接管',
        manual: '手工',
    });

    function moveOrderItem(items, fromIndex, toIndex) {
        if (!Array.isArray(items)) return [];
        const next = items.slice();
        if (!Number.isInteger(fromIndex) || !Number.isInteger(toIndex)) return next;
        if (fromIndex < 0 || fromIndex >= next.length || toIndex < 0 || toIndex >= next.length || fromIndex === toIndex) {
            return next;
        }
        const [moved] = next.splice(fromIndex, 1);
        next.splice(toIndex, 0, moved);
        return next;
    }

    function compareNamesNatural(a, b) {
        return String(a || '').localeCompare(String(b || ''), 'zh-Hans-CN', { numeric: true, sensitivity: 'base' });
    }

    function sortOrderItemsByRegion(items, matchRegionFn) {
        if (!Array.isArray(items)) return [];
        const matcher = typeof matchRegionFn === 'function' ? matchRegionFn : () => null;
        return items
            .map((item, idx) => {
                const reg = matcher(item && item.name);
                const code = reg && reg.code ? reg.code : '';
                const rank = code && REGION_RANK.has(code) ? REGION_RANK.get(code) : REGION_PRIORITY.length;
                return { item, idx, rank };
            })
            .sort((a, b) => (
                a.rank - b.rank ||
                compareNamesNatural(a.item && a.item.name, b.item && b.item.name) ||
                a.idx - b.idx
            ))
            .map(entry => entry.item);
    }

    function sortOrderItemsByName(items) {
        if (!Array.isArray(items)) return [];
        return items
            .map((item, idx) => ({ item, idx }))
            .sort((a, b) => compareNamesNatural(a.item && a.item.name, b.item && b.item.name) || a.idx - b.idx)
            .map(entry => entry.item);
    }

    function sortOrderItemsManagedFirst(items) {
        if (!Array.isArray(items)) return [];
        const isManaged = item => Boolean(item && item.source && item.source !== 'manual');
        return [
            ...items.filter(isManaged),
            ...items.filter(item => !isManaged(item)),
        ];
    }

    return Object.freeze({
        SOURCE_LABELS,
        moveOrderItem,
        sortOrderItemsByRegion,
        sortOrderItemsByName,
        sortOrderItemsManagedFirst,
    });
}));
