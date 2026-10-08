(function (root) {
    function buildUrl(origin, token, name, format = 'clash') {
        const url = new URL('/sub', origin);
        url.searchParams.set('token', token);
        url.searchParams.set('name', name.trim() || 'ProxyForge');
        if (format === 'egern') url.searchParams.set('format', 'egern');
        else if (format !== 'clash') throw new Error('不支持的订阅格式');
        return url.toString();
    }
    const api = { buildUrl };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.ProxyForgeSubscription = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
