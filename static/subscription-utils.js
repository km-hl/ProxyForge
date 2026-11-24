(function (root) {
    const SUPPORTED_FORMATS = new Set(['clash', 'egern', 'singbox', 'surge', 'uri']);
    const USER_SUPPORTED_FORMATS = new Set(['auto', 'clash', 'egern', 'singbox', 'surge', 'uri']);

    function buildUrl(origin, token, name, format = 'clash', options = {}) {
        if (!SUPPORTED_FORMATS.has(format)) throw new Error('不支持的订阅格式');
        const url = new URL('/sub', origin);
        url.searchParams.set('token', token);
        url.searchParams.set('name', (name || '').trim() || 'ProxyForge');
        if (format === 'egern') url.searchParams.set('format', 'egern');
        else if (format !== 'clash') url.searchParams.set('target', format);
        if (options && options.preferRelay) url.searchParams.set('prefer_relay', 'true');
        return url.toString();
    }

    function buildUserUrl(origin, userToken, name, format = 'auto', options = {}) {
        if (!USER_SUPPORTED_FORMATS.has(format)) throw new Error('不支持的订阅格式');
        const url = new URL('/sub/' + encodeURIComponent(String(userToken || '')), origin);
        url.searchParams.set('name', (name || '').trim() || 'ProxyForge');
        if (format === 'egern') url.searchParams.set('format', 'egern');
        else if (format === 'clash') url.searchParams.set('target', 'mihomo');
        else if (format !== 'auto') url.searchParams.set('target', format);
        if (options && options.preferRelay) url.searchParams.set('prefer_relay', 'true');
        return url.toString();
    }

    // Minimal self-contained ISO/IEC 18004 Byte-mode QR encoder (EC level L, versions 1..10, <= 271 bytes)
    const QR_CAP_L = [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271];
    const QR_TOTAL_CW = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346];
    const QR_EC_PER_BLK = [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18];
    const QR_BLOCKS = [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4];
    const QR_ALIGN = [[], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

    const GF_EXP = new Uint8Array(512);
    const GF_LOG = new Uint8Array(256);
    {
        let x = 1;
        for (let i = 0; i < 255; i++) {
            GF_EXP[i] = x; GF_LOG[x] = i;
            x <<= 1; if (x & 0x100) x ^= 0x11d;
        }
        for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
    }

    function gfMul(a, b) {
        return (a === 0 || b === 0) ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]];
    }

    function rsPoly(ecCount) {
        let poly = [1];
        for (let i = 0; i < ecCount; i++) {
            const next = new Array(poly.length + 1).fill(0);
            const root = GF_EXP[i];
            for (let j = 0; j < poly.length; j++) {
                next[j] ^= poly[j];
                next[j + 1] ^= gfMul(poly[j], root);
            }
            poly = next;
        }
        return poly;
    }

    function rsEncode(data, ecCount) {
        const gen = rsPoly(ecCount);
        const res = new Uint8Array(data.length + ecCount);
        res.set(data);
        for (let i = 0; i < data.length; i++) {
            const coef = res[i];
            if (coef !== 0) {
                for (let j = 0; j < gen.length; j++) res[i + j] ^= gfMul(gen[j], coef);
            }
        }
        return res.slice(data.length);
    }

    function bchFormat(mask) {
        const raw = (1 << 3) | mask;
        let d = raw << 10;
        for (let i = 4; i >= 0; i--) if ((d >> (i + 10)) & 1) d ^= 0x537 << i;
        return ((raw << 10) | d) ^ 0x5412;
    }

    function bchVersion(ver) {
        let d = ver << 12;
        for (let i = 5; i >= 0; i--) if ((d >> (i + 12)) & 1) d ^= 0x1f25 << i;
        return (ver << 12) | d;
    }

    function encodeQrMatrix(text) {
        const bytes = typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(String(text)) : Buffer.from(String(text), 'utf8');
        let ver = 1;
        while (ver < QR_CAP_L.length && bytes.length > QR_CAP_L[ver]) ver++;
        if (ver >= QR_CAP_L.length) throw new Error('QR 内容过长');

        const dataCap = QR_TOTAL_CW[ver] - QR_EC_PER_BLK[ver] * QR_BLOCKS[ver];
        const bits = [];
        const pushBits = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
        pushBits(0b0100, 4);
        pushBits(bytes.length, ver >= 10 ? 16 : 8);
        for (const b of bytes) pushBits(b, 8);
        pushBits(0, Math.min(4, dataCap * 8 - bits.length));
        while (bits.length % 8 !== 0) bits.push(0);
        const codewords = [];
        for (let i = 0; i < bits.length; i += 8) {
            let v = 0; for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
            codewords.push(v);
        }
        for (let i = 0; codewords.length < dataCap; i++) codewords.push(i % 2 === 0 ? 0xec : 0x11);

        const blocks = QR_BLOCKS[ver];
        const ecLen = QR_EC_PER_BLK[ver];
        const shortLen = Math.floor(dataCap / blocks);
        const longCount = dataCap % blocks;
        const shortCount = blocks - longCount;
        const dataBlocks = [], ecBlocks = [];
        let offset = 0;
        for (let b = 0; b < blocks; b++) {
            const len = shortLen + (b >= shortCount ? 1 : 0);
            const slice = Uint8Array.from(codewords.slice(offset, offset + len));
            offset += len;
            dataBlocks.push(slice);
            ecBlocks.push(rsEncode(slice, ecLen));
        }

        const stream = [];
        const maxDataLen = shortLen + (longCount > 0 ? 1 : 0);
        for (let i = 0; i < maxDataLen; i++) for (const blk of dataBlocks) if (i < blk.length) stream.push(blk[i]);
        for (let i = 0; i < ecLen; i++) for (const ec of ecBlocks) stream.push(ec[i]);

        const size = 17 + ver * 4;
        const grid = Array.from({ length: size }, () => new Int8Array(size).fill(-1));
        const func = Array.from({ length: size }, () => new Uint8Array(size));
        const setFunc = (r, c, v) => { if (r >= 0 && r < size && c >= 0 && c < size) { grid[r][c] = v ? 1 : 0; func[r][c] = 1; } };
        const finder = (r, c) => {
            for (let dr = -1; dr <= 7; dr++) for (let dc = -1; dc <= 7; dc++) {
                const rr = r + dr, cc = c + dc;
                if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
                const on = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 && (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
                setFunc(rr, cc, on);
            }
        };
        finder(0, 0); finder(0, size - 7); finder(size - 7, 0);
        for (let i = 8; i < size - 8; i++) { setFunc(6, i, i % 2 === 0); setFunc(i, 6, i % 2 === 0); }
        setFunc(size - 8, 8, 1);

        const align = QR_ALIGN[ver];
        for (const r of align) for (const c of align) {
            if (func[r][c]) continue;
            for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) {
                setFunc(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
            }
        }
        for (let i = 0; i < 9; i++) { if (i !== 6) { setFunc(8, i, 0); setFunc(i, 8, 0); } }
        for (let i = 0; i < 8; i++) { setFunc(8, size - 1 - i, 0); setFunc(size - 1 - i, 8, 0); }
        if (ver >= 7) {
            const vb = bchVersion(ver);
            for (let i = 0; i < 18; i++) {
                const bit = (vb >> i) & 1, r = Math.floor(i / 3), c = size - 11 + (i % 3);
                setFunc(r, c, bit); setFunc(c, r, bit);
            }
        }

        const streamBits = [];
        for (const cw of stream) for (let b = 7; b >= 0; b--) streamBits.push((cw >> b) & 1);
        let bitIdx = 0, dir = -1;
        for (let col = size - 1; col > 0; col -= 2) {
            if (col === 6) col--;
            for (let step = 0; step < size; step++) {
                const row = dir === -1 ? (size - 1 - step) : step;
                for (let dx = 0; dx < 2; dx++) {
                    const c = col - dx;
                    if (!func[row][c]) {
                        const bit = bitIdx < streamBits.length ? streamBits[bitIdx++] : 0;
                        grid[row][c] = bit ^ (((row + c) % 2 === 0) ? 1 : 0);
                    }
                }
            }
            dir *= -1;
        }
        const fmt = bchFormat(0);
        for (let i = 0; i < 15; i++) {
            const bit = (fmt >> i) & 1;
            const r1 = i < 6 ? i : (i < 8 ? i + 1 : size - 15 + i);
            const c1 = 8;
            grid[r1][c1] = bit;
            const c2 = i < 8 ? (size - 1 - i) : (i === 8 ? 7 : 14 - i);
            grid[8][c2] = bit;
        }
        return grid;
    }

    function renderQrSvg(text, quiet = 2) {
        const grid = encodeQrMatrix(text);
        const total = grid.length + quiet * 2;
        let path = '';
        for (let r = 0; r < grid.length; r++) {
            for (let c = 0; c < grid.length; c++) {
                if (grid[r][c] === 1) path += `M${c + quiet},${r + quiet}h1v1h-1z`;
            }
        }
        return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="200" height="200" shape-rendering="crispEdges" role="img" aria-label="订阅二维码"><rect width="${total}" height="${total}" fill="#ffffff"/><path d="${path}" fill="#111827"/></svg>`;
    }

    const api = { buildUrl, buildUserUrl, encodeQrMatrix, renderQrSvg };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.ProxyForgeSubscription = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
