(function (root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    root.ProxyForgeShareLinks = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    const SCHEME_LINE_RE = /^([a-z][a-z0-9+.-]*):\/\//i;
    const BASE64_BODY_RE = /^[A-Za-z0-9+/_-]+=*$/;
    const STATUS_NAME_RE = /(?:到期|剩余|流量|过期|重置|套餐|官网|网址|通知|expire|remaining|traffic|reset|notice)/i;
    const LOOPBACK_HOSTS = new Set(['127.0.0.1', '0.0.0.0', '::1', '[::1]', 'localhost']);

    function safeDecodeUri(value) {
        const text = String(value ?? '');
        try {
            return decodeURIComponent(text);
        } catch (_) {
            return text;
        }
    }

    function decodeBase64Utf8(raw) {
        const cleaned = String(raw || '').replace(/\s+/g, '');
        if (!cleaned || cleaned.length < 4 || !BASE64_BODY_RE.test(cleaned)) {
            return null;
        }
        let normalized = cleaned.replace(/-/g, '+').replace(/_/g, '/');
        const remainder = normalized.length % 4;
        if (remainder === 1) return null;
        if (remainder > 0) normalized += '='.repeat(4 - remainder);

        let bytes;
        try {
            if (typeof atob === 'function') {
                const binary = atob(normalized);
                bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i += 1) {
                    bytes[i] = binary.charCodeAt(i);
                }
            } else if (typeof Buffer !== 'undefined') {
                bytes = Uint8Array.from(Buffer.from(normalized, 'base64'));
            } else {
                return null;
            }
        } catch (_) {
            return null;
        }

        let decoded;
        if (typeof TextDecoder !== 'undefined') {
            decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        } else if (typeof Buffer !== 'undefined') {
            decoded = Buffer.from(bytes).toString('utf8');
        } else {
            return null;
        }
        if (/[\x00-\x08\x0b\x0c\x0e-\x1f\uFFFD]/.test(decoded)) {
            return null;
        }
        return decoded;
    }

    function parseHostPort(hostPortText) {
        const text = String(hostPortText || '').trim().replace(/\/+$/, '');
        if (!text) return null;
        let server = '';
        let portText = '';
        if (text.startsWith('[')) {
            const closeIdx = text.indexOf(']');
            if (closeIdx <= 1 || text[closeIdx + 1] !== ':') return null;
            server = text.slice(1, closeIdx).trim();
            portText = text.slice(closeIdx + 2).trim();
        } else {
            const colonIdx = text.lastIndexOf(':');
            if (colonIdx <= 0) return null;
            server = text.slice(0, colonIdx).trim();
            portText = text.slice(colonIdx + 1).trim();
        }
        if (!server || !/^\d{1,5}$/.test(portText)) return null;
        const port = Number(portText);
        if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
        return { server, port };
    }

    function splitFragmentAndQuery(rawBody) {
        const hashIdx = rawBody.indexOf('#');
        const name = hashIdx >= 0 ? safeDecodeUri(rawBody.slice(hashIdx + 1)).trim() : '';
        const beforeHash = hashIdx >= 0 ? rawBody.slice(0, hashIdx) : rawBody;
        const queryIdx = beforeHash.indexOf('?');
        const query = queryIdx >= 0 ? beforeHash.slice(queryIdx + 1) : '';
        const authority = (queryIdx >= 0 ? beforeHash.slice(0, queryIdx) : beforeHash).replace(/\/+$/, '');
        return { authority, query, name };
    }

    function extractQueryParam(query, targetKey) {
        if (!query) return '';
        for (const pair of query.split('&')) {
            if (!pair) continue;
            const eqIdx = pair.indexOf('=');
            const k = safeDecodeUri(eqIdx >= 0 ? pair.slice(0, eqIdx) : pair);
            if (k === targetKey) {
                return eqIdx >= 0 ? safeDecodeUri(pair.slice(eqIdx + 1)) : '';
            }
        }
        return '';
    }

    function parseSsLink(rawLink) {
        const link = String(rawLink || '').trim();
        if (!/^ss:\/\//i.test(link)) return null;
        const { authority, query, name } = splitFragmentAndQuery(link.slice(5));
        if (!authority) return null;

        let method = '';
        let password = '';
        let hostPort = '';

        const atIdx = authority.lastIndexOf('@');
        if (atIdx >= 0) {
            const rawUserInfo = authority.slice(0, atIdx);
            hostPort = authority.slice(atIdx + 1);
            const colonIdx = rawUserInfo.indexOf(':');
            if (colonIdx >= 0) {
                method = safeDecodeUri(rawUserInfo.slice(0, colonIdx)).trim();
                password = safeDecodeUri(rawUserInfo.slice(colonIdx + 1));
            } else {
                const decodedUserInfo = decodeBase64Utf8(safeDecodeUri(rawUserInfo));
                if (!decodedUserInfo || !decodedUserInfo.includes(':')) return null;
                const dColon = decodedUserInfo.indexOf(':');
                method = decodedUserInfo.slice(0, dColon).trim();
                password = decodedUserInfo.slice(dColon + 1);
            }
        } else {
            const decodedAll = decodeBase64Utf8(authority);
            if (!decodedAll) return null;
            const dAt = decodedAll.lastIndexOf('@');
            if (dAt <= 0) return null;
            const userInfo = decodedAll.slice(0, dAt);
            hostPort = decodedAll.slice(dAt + 1);
            const dColon = userInfo.indexOf(':');
            if (dColon <= 0) return null;
            method = userInfo.slice(0, dColon).trim();
            password = userInfo.slice(dColon + 1);
        }

        const addr = parseHostPort(hostPort);
        if (!addr || !method || !password) return null;
        const plugin = extractQueryParam(query, 'plugin');
        return {
            kind: 'ss',
            name: name || `${addr.server}:${addr.port}`,
            server: addr.server,
            port: addr.port,
            method,
            password,
            plugin,
        };
    }

    function parseSocks5Link(rawLink) {
        const link = String(rawLink || '').trim();
        const match = link.match(/^socks5?:\/\//i);
        if (!match) return null;
        const { authority, name } = splitFragmentAndQuery(link.slice(match[0].length));
        if (!authority) return null;

        let username = '';
        let password = '';
        let hostPort = authority;
        const atIdx = authority.lastIndexOf('@');
        if (atIdx >= 0) {
            const rawUserInfo = authority.slice(0, atIdx);
            hostPort = authority.slice(atIdx + 1);
            if (rawUserInfo.includes(':')) {
                const colonIdx = rawUserInfo.indexOf(':');
                username = safeDecodeUri(rawUserInfo.slice(0, colonIdx));
                password = safeDecodeUri(rawUserInfo.slice(colonIdx + 1));
            } else if (rawUserInfo) {
                const decoded = decodeBase64Utf8(safeDecodeUri(rawUserInfo));
                if (decoded && decoded.includes(':')) {
                    const dColon = decoded.indexOf(':');
                    username = decoded.slice(0, dColon);
                    password = decoded.slice(dColon + 1);
                } else {
                    username = safeDecodeUri(rawUserInfo);
                }
            }
        }

        const addr = parseHostPort(hostPort);
        if (!addr) return null;
        return {
            kind: 'socks5',
            name: name || `${addr.server}:${addr.port}`,
            server: addr.server,
            port: addr.port,
            username,
            password,
        };
    }

    function isStatusPlaceholderNode(node) {
        if (!node || typeof node !== 'object') return false;
        const server = String(node.server || '').trim().toLowerCase();
        if (LOOPBACK_HOSTS.has(server)) return true;
        const port = Number(node.port || 0);
        const name = String(node.name || '');
        if (port <= 1 && (STATUS_NAME_RE.test(name) || node.password === 'notice')) {
            return true;
        }
        return false;
    }

    function expandShareLinkInput(rawText, depth = 0) {
        const text = String(rawText || '').trim();
        if (!text) {
            return { links: [], otherLines: [], decodedFromBase64: false };
        }
        let decodedFromBase64 = false;
        const links = [];
        const otherLines = [];

        if (!text.includes('://') && depth < 2) {
            const decoded = decodeBase64Utf8(text);
            if (decoded && decoded.includes('://')) {
                const inner = expandShareLinkInput(decoded, depth + 1);
                return {
                    links: inner.links,
                    otherLines: inner.otherLines,
                    decodedFromBase64: true,
                };
            }
        }

        for (const rawLine of text.split(/\r?\n/)) {
            const line = rawLine.trim();
            if (!line) continue;
            if (SCHEME_LINE_RE.test(line)) {
                links.push(line);
                continue;
            }
            if (depth < 2) {
                const decoded = decodeBase64Utf8(line);
                if (decoded && decoded.includes('://')) {
                    decodedFromBase64 = true;
                    const inner = expandShareLinkInput(decoded, depth + 1);
                    links.push(...inner.links);
                    otherLines.push(...inner.otherLines);
                    continue;
                }
            }
            otherLines.push(line);
        }
        return { links, otherLines, decodedFromBase64 };
    }

    function parseExternalOutboundInput(rawText, options = {}) {
        const allowedKinds = new Set(options.allowedKinds || ['ss', 'socks5']);
        const expanded = expandShareLinkInput(rawText);
        const nodes = [];
        const notices = [];
        const unsupportedSchemes = [];
        let invalidCount = 0;
        const seenNodes = new Set();
        const seenNotices = new Set();

        for (const line of expanded.links) {
            const schemeMatch = line.match(SCHEME_LINE_RE);
            const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : '';
            let parsed = null;
            if (scheme === 'ss' && allowedKinds.has('ss')) {
                parsed = parseSsLink(line);
                if (!parsed) invalidCount += 1;
            } else if ((scheme === 'socks' || scheme === 'socks5') && allowedKinds.has('socks5')) {
                parsed = parseSocks5Link(line);
                if (!parsed) invalidCount += 1;
            } else {
                if (scheme && !unsupportedSchemes.includes(scheme)) {
                    unsupportedSchemes.push(scheme);
                }
                continue;
            }
            if (!parsed) continue;
            if (isStatusPlaceholderNode(parsed)) {
                if (parsed.name && !seenNotices.has(parsed.name)) {
                    seenNotices.add(parsed.name);
                    notices.push(parsed.name);
                }
                continue;
            }
            const dedupeKey = [
                parsed.kind, parsed.server, parsed.port,
                parsed.method || '', parsed.username || '', parsed.password || '',
            ].join('|');
            if (!seenNodes.has(dedupeKey)) {
                seenNodes.add(dedupeKey);
                nodes.push(parsed);
            }
        }

        return {
            nodes,
            notices,
            unsupportedSchemes,
            invalidCount,
            decodedFromBase64: expanded.decodedFromBase64,
        };
    }

    function splitImportInput(rawText, shareLinkPattern) {
        const expanded = expandShareLinkInput(rawText);
        const links = [];
        const skippedNotices = [];
        const seenNotices = new Set();

        for (const line of expanded.links) {
            if (/^ss:\/\//i.test(line)) {
                const parsed = parseSsLink(line);
                if (parsed && isStatusPlaceholderNode(parsed)) {
                    if (parsed.name && !seenNotices.has(parsed.name)) {
                        seenNotices.add(parsed.name);
                        skippedNotices.push(parsed.name);
                    }
                    continue;
                }
            }
            if (!shareLinkPattern || shareLinkPattern.test(line)) {
                links.push(line);
            }
        }

        return {
            links,
            nonLinksText: expanded.otherLines.join('\n'),
            skippedNotices,
            decodedFromBase64: expanded.decodedFromBase64,
        };
    }

    return Object.freeze({
        decodeBase64Utf8,
        parseHostPort,
        parseSsLink,
        parseSocks5Link,
        isStatusPlaceholderNode,
        expandShareLinkInput,
        parseExternalOutboundInput,
        splitImportInput,
    });
}));
