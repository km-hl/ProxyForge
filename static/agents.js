/* Inventory and explicitly allowlisted read-only jobs. */
const pendingAgentJobRequests = new Map();

function agentCanRunJobs(agent) {
    return agent.status !== 'revoked' && agent.compatible && agent.metadata.job_protocol_version === 1;
}

function agentCanManageRuntime(agent) {
    return agentCanRunJobs(agent) && agent.metadata.supported && agent.metadata.runtime_protocol_version === 1;
}

function agentCanDeploy(agent) {
    return agentCanManageRuntime(agent) && agent.metadata.deployment_protocol_version === 1;
}

function agentCanLand(agent) {
    return agentCanManageRuntime(agent) && agent.metadata.landing_protocol_version === 1;
}

function agentCanChain(agent) {
    return agentCanManageRuntime(agent) && agent.metadata.chain_protocol_version === 1;
}

function agentCanGost(agent) {
    return agentCanManageRuntime(agent) && agent.metadata.gost_protocol_version === 1;
}

function randomRequestId() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
}

async function fetchAgentJson(url, options) {
    const res = await fetchAuth(url, options);
    const data = res.status === 204 ? null : await res.json().catch(() => ({}));
    if (res.ok === false) throw new Error((data && data.detail) || 'HTTP ' + res.status);
    return data;
}

function _escHtml(v) {
    if (typeof ProxyForgeHtmlUtils !== 'undefined' && typeof ProxyForgeHtmlUtils.escapeHtml === 'function') {
        return ProxyForgeHtmlUtils.escapeHtml(v);
    }
    return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function formatAgentBytes(bytes) {
    const val = Number(bytes || 0);
    if (!val) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(val) / Math.log(1024)));
    return +(val / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

function _agentRegionPickerHtml(id, currentVal, label) {
    if (typeof ProxyForgeRegions !== 'undefined' && typeof ProxyForgeRegions.renderRegionPickerHtml === 'function') {
        return ProxyForgeRegions.renderRegionPickerHtml(id, currentVal, label);
    }
    return '';
}

function _bindAgentRegionPicker(pickerId, targetInputId) {
    if (typeof ProxyForgeRegions === 'undefined' || typeof ProxyForgeRegions.bindRegionPicker !== 'function') return;
    ProxyForgeRegions.bindRegionPicker(pickerId, (regionObj, rawVal) => {
        const nameEl = document.getElementById(targetInputId);
        if (!nameEl || nameEl.readOnly) return;
        const base = nameEl.value.trim() || (regionObj ? `${regionObj.code} Node` : '');
        if (base) {
            nameEl.value = ProxyForgeRegions.applyRegionPrefix(base, regionObj ? regionObj.code : rawVal);
        }
    });
}

const SHARED_PORT_PROTOCOLS = new Set(['reality', 'trojan', 'anytls', 'hysteria2']);
const _SHARED_LISTENER_COPY_KEYS = [
    'tls_mode', 'domain', 'camouflage_mode', 'camouflage_template', 'camouflage_url', 'camouflage_dir',
    'acme_email', 'dns_provider', 'dns_zone_id', 'dns_propagation_seconds',
    'reality_public_key', 'padding_scheme', 'obfs', 'up_mbps', 'down_mbps', 'mport', 'hop_interval',
];

function _normalizeNodeProto(proto) {
    return proto === 'vless-reality' ? 'reality' : String(proto || 'reality');
}

function _isShareableProtocol(proto) {
    return SHARED_PORT_PROTOCOLS.has(_normalizeNodeProto(proto));
}

function _findSharedPortPeers(agentNodes, proto, port, excludeId = null) {
    const normProto = _normalizeNodeProto(proto);
    const portNum = Number(port);
    if (!SHARED_PORT_PROTOCOLS.has(normProto) || !Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        return [];
    }
    return (agentNodes || []).filter(n => {
        if (!n || (excludeId && n.id === excludeId)) return false;
        const p = _normalizeNodeProto(n.protocol);
        const np = Number((n.settings || {}).listen_port);
        return p === normProto && np === portNum;
    });
}

function _listReusableListenerHosts(agentNodes, excludeId = null) {
    const byKey = new Map();
    for (const n of (agentNodes || [])) {
        if (!n || (excludeId && n.id === excludeId)) continue;
        const p = _normalizeNodeProto(n.protocol);
        const portNum = Number((n.settings || {}).listen_port);
        if (!SHARED_PORT_PROTOCOLS.has(p) || !Number.isInteger(portNum) || portNum < 1 || portNum > 65535) continue;
        const key = `${p}:${portNum}`;
        const existing = byKey.get(key);
        if (!existing || (n.is_primary && !existing.is_primary)) {
            byKey.set(key, n);
        }
    }
    return [...byKey.values()];
}

function _copySharedListenerSettings(targetSettings, hostNode) {
    const hs = (hostNode && hostNode.settings) || {};
    const proto = _normalizeNodeProto(hostNode && hostNode.protocol);
    for (const k of _SHARED_LISTENER_COPY_KEYS) {
        if (hs[k] !== undefined && hs[k] !== null && hs[k] !== '') {
            targetSettings[k] = hs[k];
        } else {
            delete targetSettings[k];
        }
    }
    if (!targetSettings.domain && hs.server_name) {
        targetSettings.domain = hs.server_name;
    }
    if (!targetSettings.tls_mode && proto !== 'ss2022') {
        const meta = typeof LANDING_PROTO_META !== 'undefined' && LANDING_PROTO_META[proto];
        targetSettings.tls_mode = meta ? meta.tlsModes[0][0] : 'reality';
    }
    return targetSettings;
}

function _nodeOutboundRoleText(node) {
    const s = (node && node.settings) || {};
    const mode = s.outbound_mode || 'direct';
    if (mode === 'chain') return `链式×${Array.isArray(s.outbound_hops) ? s.outbound_hops.length : 1}`;
    if (mode === 'socks5' || mode === 'ss') return '外部出站';
    return '直连';
}

function _formatOutboundHopsSummary(settings, ssLandings) {
    const s = settings || {};
    const mode = s.outbound_mode || 'direct';
    if (mode === 'direct') return '直连出站 (Direct)';
    if (mode === 'socks5') return `外部 Socks5 → ${s.outbound_server || '?'}:${s.outbound_port || '?'}`;
    if (mode === 'ss') return `外部 SS → ${s.outbound_server || '?'}:${s.outbound_port || '?'}`;
    if (mode === 'chain') {
        const hops = Array.isArray(s.outbound_hops) ? s.outbound_hops : [];
        if (!hops.length) return '链式多跳 (未配置跳数)';
        const landingIndex = new Map((ssLandings || []).map(l => [`${l.agent_id}::${l.node_id}`, l]));
        return hops.map((h, idx) => {
            if (h.kind === 'managed_ss') {
                const match = landingIndex.get(`${h.agent_id}::${h.node_id}`);
                const label = match ? `${match.agent_name}/${match.node_name || match.name}` : `${h.agent_id}:${h.node_id}`;
                return `跳${idx + 1}[SS2022 ${label}]`;
            }
            return `跳${idx + 1}[${String(h.kind || '').toUpperCase()} ${h.server || '?'}:${h.port || '?'}]`;
        }).join(' → ');
    }
    return mode;
}

const SUPPORTED_EXTERNAL_SS_METHODS = [
    '2022-blake3-aes-256-gcm',
    '2022-blake3-aes-128-gcm',
    'aes-256-gcm',
    'aes-128-gcm',
    'chacha20-ietf-poly1305',
];

function _createOutboundLinkRecognizer({ allowedKinds = ['ss', 'socks5'], onApplyNode }) {
    const parser = typeof ProxyForgeShareLinks !== 'undefined' ? ProxyForgeShareLinks : null;
    const wrap = document.createElement('div');
    wrap.className = 'form-group full-width';
    wrap.style.marginBottom = '6px';

    const labelRow = document.createElement('div');
    labelRow.style.display = 'flex';
    labelRow.style.alignItems = 'center';
    labelRow.style.justifyContent = 'space-between';
    labelRow.style.gap = '8px';

    const lbl = document.createElement('label');
    lbl.textContent = '分享链接 / Base64 自动识别';
    lbl.style.marginBottom = '0';

    const parseBtn = document.createElement('button');
    parseBtn.type = 'button';
    parseBtn.className = 'btn btn-sm';
    parseBtn.textContent = '识别填入';
    labelRow.append(lbl, parseBtn);

    const textarea = document.createElement('textarea');
    textarea.rows = 2;
    textarea.autocomplete = 'off';
    textarea.className = 'pf-ephemeral-secret';
    textarea.style.fontFamily = 'monospace';
    textarea.style.fontSize = '0.82rem';
    textarea.placeholder = '粘贴 ss:// / socks5:// / Base64 或多行含到期流量提示的内容';

    const nodeSel = document.createElement('select');
    nodeSel.hidden = true;
    nodeSel.style.marginTop = '6px';

    const statusEl = document.createElement('div');
    statusEl.className = 'hint';
    statusEl.hidden = true;
    statusEl.style.marginTop = '4px';

    let currentNodes = [];

    function applyChosen(node, result) {
        const warnings = [];
        if (node.kind === 'ss' && !SUPPORTED_EXTERNAL_SS_METHODS.includes(node.method)) {
            warnings.push(`sing-box 出站不支持加密方式 ${node.method}`);
        }
        if (node.plugin) {
            warnings.push(`未兼容 SIP003 plugin (${node.plugin})`);
        }
        onApplyNode(node);

        const parts = [`已识别 ${node.kind.toUpperCase()}${node.method ? ' (' + node.method + ')' : ''} · ${node.server}:${node.port}`];
        if (result.decodedFromBase64) parts.push('Base64 已解码');
        if (result.notices.length) parts.push(`已过滤信息：${result.notices.join(' · ')}`);
        if (result.unsupportedSchemes.length) parts.push(`已跳过协议：${result.unsupportedSchemes.join(', ')}`);
        if (warnings.length) parts.push(`⚠️ ${warnings.join('；')}`);
        statusEl.hidden = false;
        statusEl.textContent = parts.join(' | ');
    }

    function recognize(explicit) {
        const raw = textarea.value.trim();
        nodeSel.hidden = true;
        nodeSel.replaceChildren();
        currentNodes = [];
        if (!raw) {
            statusEl.hidden = true;
            statusEl.textContent = '';
            return;
        }
        if (!parser) {
            statusEl.hidden = false;
            statusEl.textContent = '链接解析模块未加载，请刷新页面重试';
            return;
        }
        const result = parser.parseExternalOutboundInput(raw, { allowedKinds });
        if (!result.nodes.length) {
            if (!explicit && !raw.includes('://') && raw.length < 16) {
                statusEl.hidden = true;
                return;
            }
            const errParts = ['未识别到可用的 SS / Socks5 节点'];
            if (result.notices.length) errParts.push(`仅包含信息行：${result.notices.join(' · ')}`);
            if (result.unsupportedSchemes.length) errParts.push(`暂不支持作为外部出站：${result.unsupportedSchemes.join(', ')}`);
            statusEl.hidden = false;
            statusEl.textContent = errParts.join(' | ');
            return;
        }

        currentNodes = result.nodes;
        if (result.nodes.length > 1) {
            result.nodes.forEach((n, idx) => {
                const opt = document.createElement('option');
                opt.value = String(idx);
                opt.textContent = `${n.name} (${n.kind.toUpperCase()} · ${n.server}:${n.port})`;
                nodeSel.append(opt);
            });
            nodeSel.hidden = false;
            nodeSel.onchange = () => {
                const picked = currentNodes[Number(nodeSel.value) || 0];
                if (picked) applyChosen(picked, result);
            };
        }
        applyChosen(result.nodes[0], result);
    }

    parseBtn.onclick = () => recognize(true);
    textarea.addEventListener('input', () => recognize(false));

    wrap.append(labelRow, textarea, nodeSel, statusEl);
    return {
        el: wrap,
        clear() {
            textarea.value = '';
            nodeSel.hidden = true;
            nodeSel.replaceChildren();
            statusEl.hidden = true;
            statusEl.textContent = '';
            currentNodes = [];
        },
    };
}

function _createOutboundHopsEditor({ container, initialHops = [], ssLandings = [], currentAgentId = '' }) {
    const availableLandings = (ssLandings || []).filter(item => item.agent_id !== currentAgentId);
    const MAX_HOPS = 4;
    let hops = [];

    function normalizeInitial(list) {
        return (Array.isArray(list) ? list : []).slice(0, MAX_HOPS).map(h => {
            if (h && h.kind === 'managed_ss') {
                return { kind: 'managed_ss', agent_id: String(h.agent_id || ''), node_id: String(h.node_id || '') };
            }
            if (h && h.kind === 'socks5') {
                return {
                    kind: 'socks5',
                    server: String(h.server || ''),
                    port: Number(h.port) || 1080,
                    username: String(h.username || ''),
                    _password: '',
                };
            }
            return {
                kind: 'ss',
                server: String((h && h.server) || ''),
                port: Number(h && h.port) || 8388,
                method: String((h && h.method) || '2022-blake3-aes-256-gcm'),
                _password: '',
            };
        });
    }

    hops = normalizeInitial(initialHops);

    function renderEditor() {
        container.replaceChildren();

        if (hops.length) {
            const flow = document.createElement('div');
            flow.className = 'hint';
            flow.style.marginBottom = '8px';
            flow.style.padding = '6px 8px';
            flow.style.borderRadius = '6px';
            flow.style.background = 'var(--surface-2, rgba(148,163,184,0.12))';
            flow.textContent = '链路路径：本机入口 → ' + _formatOutboundHopsSummary({ outbound_mode: 'chain', outbound_hops: hops }, availableLandings) + ' → 目标网站';
            container.append(flow);
        }

        hops.forEach((hop, idx) => {
            const card = document.createElement('div');
            card.className = 'sub-user-card';
            card.style.marginBottom = '8px';

            const head = document.createElement('div');
            head.style.display = 'flex';
            head.style.gap = '6px';
            head.style.alignItems = 'center';
            head.style.flexWrap = 'wrap';
            head.style.marginBottom = '6px';

            const badge = document.createElement('strong');
            badge.textContent = `第 ${idx + 1} 跳`;

            const kindSel = document.createElement('select');
            kindSel.style.maxWidth = '240px';
            for (const [val, lbl] of [
                ['managed_ss', '受管 SS2022 落地 (自动关联)'],
                ['ss', '外部 Shadowsocks (SS / SS2022)'],
                ['socks5', '外部 Socks5 (住宅家宽 ISP)'],
            ]) {
                const o = document.createElement('option');
                o.value = val; o.textContent = lbl;
                kindSel.append(o);
            }
            kindSel.value = hop.kind;
            kindSel.onchange = () => {
                const nextKind = kindSel.value;
                if (nextKind === 'managed_ss') {
                    const first = availableLandings[0];
                    hops[idx] = { kind: 'managed_ss', agent_id: first ? first.agent_id : '', node_id: first ? first.node_id : '' };
                } else if (nextKind === 'socks5') {
                    hops[idx] = { kind: 'socks5', server: '', port: 1080, username: '', _password: '' };
                } else {
                    hops[idx] = { kind: 'ss', server: '', port: 8388, method: '2022-blake3-aes-256-gcm', _password: '' };
                }
                renderEditor();
            };

            const spacer = document.createElement('span');
            spacer.style.flex = '1';

            const upBtn = document.createElement('button');
            upBtn.type = 'button'; upBtn.className = 'btn btn-sm'; upBtn.textContent = '↑';
            upBtn.disabled = idx === 0;
            upBtn.onclick = () => { [hops[idx - 1], hops[idx]] = [hops[idx], hops[idx - 1]]; renderEditor(); };

            const downBtn = document.createElement('button');
            downBtn.type = 'button'; downBtn.className = 'btn btn-sm'; downBtn.textContent = '↓';
            downBtn.disabled = idx === hops.length - 1;
            downBtn.onclick = () => { [hops[idx + 1], hops[idx]] = [hops[idx], hops[idx + 1]]; renderEditor(); };

            const delBtn = document.createElement('button');
            delBtn.type = 'button'; delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = '✕';
            delBtn.onclick = () => { hops.splice(idx, 1); renderEditor(); };

            head.append(badge, kindSel, spacer, upBtn, downBtn, delBtn);
            card.append(head);

            const grid = document.createElement('div');
            grid.className = 'form-grid';

            if (hop.kind === 'managed_ss') {
                const fg = document.createElement('div');
                fg.className = 'form-group full-width';
                const lbl = document.createElement('label');
                lbl.textContent = '选择目标 Agent 的 SS2022 落地节点';
                const sel = document.createElement('select');
                if (!availableLandings.length) {
                    const empty = document.createElement('option');
                    empty.value = ''; empty.textContent = '暂无其他 Agent 的 SS2022 落地（请先在落地机部署 SS2022）';
                    sel.append(empty);
                } else {
                    for (const l of availableLandings) {
                        const o = document.createElement('option');
                        o.value = `${l.agent_id}::${l.node_id}`;
                        o.textContent = `${l.agent_name} / ${l.node_name || l.name} (${l.server}:${l.listen_port} · ${l.method})`;
                        sel.append(o);
                    }
                }
                const currentVal = hop.agent_id && hop.node_id ? `${hop.agent_id}::${hop.node_id}` : '';
                if (currentVal && !availableLandings.some(l => `${l.agent_id}::${l.node_id}` === currentVal)) {
                    const missing = document.createElement('option');
                    missing.value = currentVal;
                    missing.textContent = `${hop.agent_id}/${hop.node_id} (当前落地不可用或已删除)`;
                    sel.append(missing);
                }
                if (currentVal) {
                    sel.value = currentVal;
                } else if (availableLandings.length) {
                    hop.agent_id = availableLandings[0].agent_id;
                    hop.node_id = availableLandings[0].node_id;
                    sel.value = `${hop.agent_id}::${hop.node_id}`;
                }
                sel.onchange = () => {
                    const [aid, nid] = String(sel.value || '').split('::');
                    hop.agent_id = aid || '';
                    hop.node_id = nid || '';
                    renderEditor();
                };
                fg.append(lbl, sel);
                grid.append(fg);
            } else {
                const fgSrv = document.createElement('div');
                fgSrv.className = 'form-group';
                const lSrv = document.createElement('label'); lSrv.textContent = '落地服务器地址';
                const iSrv = document.createElement('input');
                iSrv.placeholder = '1.2.3.4 或 landing.example.com';
                iSrv.value = hop.server || '';
                iSrv.oninput = () => { hop.server = iSrv.value.trim(); };
                fgSrv.append(lSrv, iSrv);

                const fgPort = document.createElement('div');
                fgPort.className = 'form-group';
                const lPort = document.createElement('label'); lPort.textContent = '端口';
                const iPort = document.createElement('input');
                iPort.type = 'number'; iPort.min = '1'; iPort.max = '65535';
                iPort.value = String(hop.port || (hop.kind === 'socks5' ? 1080 : 8388));
                iPort.oninput = () => { hop.port = Number(iPort.value) || 0; };
                fgPort.append(lPort, iPort);

                let sMethod = null;
                let iUser = null;
                const fgPass = document.createElement('div');
                fgPass.className = 'form-group';
                const lPass = document.createElement('label'); lPass.textContent = '密码 (仅写入不回显)';
                const iPass = document.createElement('input');
                iPass.type = 'password'; iPass.autocomplete = 'off';
                iPass.className = 'pf-ephemeral-secret';
                iPass.placeholder = '留空保持原密码';
                iPass.value = hop._password || '';
                iPass.oninput = () => { hop._password = iPass.value; };
                fgPass.append(lPass, iPass);

                const linkRecognizer = _createOutboundLinkRecognizer({
                    allowedKinds: ['ss', 'socks5'],
                    onApplyNode(parsed) {
                        const prevKind = hop.kind;
                        hop.server = parsed.server;
                        hop.port = parsed.port;
                        hop._password = parsed.password || '';
                        if (parsed.kind === 'ss') {
                            hop.kind = 'ss';
                            hop.method = SUPPORTED_EXTERNAL_SS_METHODS.includes(parsed.method)
                                ? parsed.method
                                : (hop.method || '2022-blake3-aes-256-gcm');
                            delete hop.username;
                        } else {
                            hop.kind = 'socks5';
                            hop.username = parsed.username || '';
                            delete hop.method;
                        }
                        if (prevKind !== hop.kind) {
                            renderEditor();
                            return;
                        }
                        iSrv.value = hop.server;
                        iPort.value = String(hop.port);
                        iPass.value = hop._password;
                        if (sMethod) sMethod.value = hop.method;
                        if (iUser) iUser.value = hop.username || '';
                    },
                });
                grid.append(linkRecognizer.el, fgSrv, fgPort);

                if (hop.kind === 'ss') {
                    const fgMethod = document.createElement('div');
                    fgMethod.className = 'form-group';
                    const lMethod = document.createElement('label'); lMethod.textContent = 'SS 加密方式';
                    sMethod = document.createElement('select');
                    for (const m of SUPPORTED_EXTERNAL_SS_METHODS) {
                        const o = document.createElement('option'); o.value = m; o.textContent = m; sMethod.append(o);
                    }
                    sMethod.value = hop.method || '2022-blake3-aes-256-gcm';
                    sMethod.onchange = () => { hop.method = sMethod.value; };
                    fgMethod.append(lMethod, sMethod);
                    grid.append(fgMethod);
                } else {
                    const fgUser = document.createElement('div');
                    fgUser.className = 'form-group';
                    const lUser = document.createElement('label'); lUser.textContent = 'Socks5 用户名 (可选)';
                    iUser = document.createElement('input');
                    iUser.placeholder = 'username';
                    iUser.value = hop.username || '';
                    iUser.oninput = () => { hop.username = iUser.value.trim(); };
                    fgUser.append(lUser, iUser);
                    grid.append(fgUser);
                }

                grid.append(fgPass);
            }
            card.append(grid);
            container.append(card);
        });

        const addRow = document.createElement('div');
        addRow.style.display = 'flex';
        addRow.style.gap = '6px';
        addRow.style.flexWrap = 'wrap';

        const addManagedBtn = document.createElement('button');
        addManagedBtn.type = 'button'; addManagedBtn.className = 'btn btn-sm';
        addManagedBtn.textContent = '➕ 添加受管 SS2022 跳';
        addManagedBtn.disabled = hops.length >= MAX_HOPS;
        addManagedBtn.onclick = () => {
            if (hops.length >= MAX_HOPS) return;
            const used = new Set(hops.filter(h => h.kind === 'managed_ss').map(h => `${h.agent_id}::${h.node_id}`));
            const pick = availableLandings.find(l => !used.has(`${l.agent_id}::${l.node_id}`)) || availableLandings[0];
            hops.push({ kind: 'managed_ss', agent_id: pick ? pick.agent_id : '', node_id: pick ? pick.node_id : '' });
            renderEditor();
        };

        const addExtBtn = document.createElement('button');
        addExtBtn.type = 'button'; addExtBtn.className = 'btn btn-sm';
        addExtBtn.textContent = '➕ 添加外部 SS / Socks5 跳';
        addExtBtn.disabled = hops.length >= MAX_HOPS;
        addExtBtn.onclick = () => {
            if (hops.length >= MAX_HOPS) return;
            hops.push({ kind: 'socks5', server: '', port: 1080, username: '', _password: '' });
            renderEditor();
        };

        addRow.append(addManagedBtn, addExtBtn);
        container.append(addRow);
    }

    renderEditor();

    return {
        setHops(nextHops) {
            hops = normalizeInitial(nextHops);
            renderEditor();
        },
        collect() {
            if (!hops.length) {
                throw new Error('链式多跳出站模式至少需要添加 1 个落地跳');
            }
            const outbound_hops = [];
            const hop_passwords = {};
            hops.forEach((h, idx) => {
                if (h.kind === 'managed_ss') {
                    if (!h.agent_id || !h.node_id) {
                        throw new Error(`第 ${idx + 1} 跳未选择有效的受管 SS2022 落地节点`);
                    }
                    outbound_hops.push({ kind: 'managed_ss', agent_id: h.agent_id, node_id: h.node_id });
                } else if (h.kind === 'ss') {
                    if (!h.server || !h.port) {
                        throw new Error(`第 ${idx + 1} 跳外部 SS 必须填写服务器地址与端口`);
                    }
                    outbound_hops.push({ kind: 'ss', server: h.server, port: Number(h.port), method: h.method || '2022-blake3-aes-256-gcm' });
                    if (h._password && h._password.trim()) hop_passwords[String(idx)] = h._password.trim();
                } else {
                    if (!h.server || !h.port) {
                        throw new Error(`第 ${idx + 1} 跳外部 Socks5 必须填写服务器地址与端口`);
                    }
                    const entry = { kind: 'socks5', server: h.server, port: Number(h.port) };
                    if (h.username) entry.username = h.username;
                    outbound_hops.push(entry);
                    if (h._password && h._password.trim()) hop_passwords[String(idx)] = h._password.trim();
                }
            });
            return { outbound_hops, hop_passwords };
        },
        clearSecrets() {
            hops.forEach(h => { if ('_password' in h) h._password = ''; });
            renderEditor();
        },
    };
}

const LANDING_PROTO_META = {
    reality: {
        label: 'VLESS Reality',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['reality', '外部目标 SNI (免域名)'],
            ['acme_http', '自建回环 (HTTP-01 + Caddy)'],
            ['acme_dns', '自建回环 (DNS-01 + Caddy)'],
        ],
        canKeygen: true,
    },
    hysteria2: {
        label: 'Hysteria2',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['acme_http', 'ACME HTTP-01'],
            ['acme_dns', 'ACME DNS-01'],
        ],
        canKeygen: true,
    },
    ss2022: {
        label: 'Shadowsocks 2022',
        defaultPort: 8388,
        landing: true,
        tlsModes: [['none', '无 TLS']],
        canKeygen: true,
    },
    anytls: {
        label: 'AnyTLS',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['acme_http', 'ACME HTTP-01'],
            ['acme_dns', 'ACME DNS-01'],
        ],
        canKeygen: true,
    },
    trojan: {
        label: 'Trojan',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['acme_http', 'ACME HTTP-01 + Caddy 回落'],
            ['acme_dns', 'ACME DNS-01 + Caddy 回落'],
        ],
        canKeygen: true,
    },
};

async function showAgentDeployment(agent, initialNodeId = null) {
    const nodesUrl = '/agents/' + agent.id + '/nodes';
    const [nodesData, ssData] = await Promise.all([
        fetchAgentJson(nodesUrl),
        fetchAgentJson('/agents/deployments/ss-landings').catch(() => ({ landings: [] })),
    ]);
    let nodesPayload = nodesData;
    let ssLandings = ssData.landings || [];
    let agentNodes = nodesPayload.nodes || [];
    let pubIpv4 = nodesPayload.public_ipv4 || agent.public_ipv4 || agent.observed_ip || '';
    let pubIpv6 = nodesPayload.public_ipv6 || agent.public_ipv6 || '';
    let currentNodeId = initialNodeId === '__new__'
        ? null
        : (initialNodeId && agentNodes.some(n => n.id === initialNodeId)
            ? initialNodeId
            : (agentNodes.length ? agentNodes[0].id : null));
    let generatedKeyRef = null;
    let submitting = false;

    function pickNextFreePort(preferred = 443) {
        const used = new Set(agentNodes.map(x => Number(x.settings?.listen_port)));
        for (const p of [preferred, 443, 8443, 2053, 20001, 20002, 8388]) {
            if (!used.has(p)) return p;
        }
        let p = 20003;
        while (used.has(p) && p < 60000) p += 1;
        return p;
    }

    openModal('节点部署 · ' + agent.name,
        '<div class="deploy-nodes-header">' +
        '<div id="deployment-nodes-bar" class="deploy-nodes-tabs"></div>' +
        '<div class="deploy-nodes-actions">' +
        '<button type="button" class="btn btn-sm" id="deployment-refresh">刷新</button>' +
        '<button type="button" class="btn btn-danger btn-sm" id="deployment-remove">删除节点</button>' +
        '</div></div>' +
        '<div id="deployment-state" class="deploy-status-bar" hidden></div>' +
        '<div class="deploy-section">' +
        '<div class="deploy-section-title">基础配置</div>' +
        '<div class="form-grid">' +
        '<div class="form-group full-width" id="deployment-listener-mode-wrap" hidden><label for="deployment-listener-mode">监听方式</label><select id="deployment-listener-mode"></select></div>' +
        '<div class="form-group"><label for="deployment-protocol">协议类型</label><select id="deployment-protocol">' +
        '<option value="reality">VLESS Reality</option>' +
        '<option value="hysteria2">Hysteria2 (QUIC / UDP)</option>' +
        '<option value="ss2022">Shadowsocks 2022</option>' +
        '<option value="anytls">AnyTLS</option>' +
        '<option value="trojan">Trojan</option></select></div>' +
        '<div class="form-group"><label for="deployment-port">监听端口</label><input id="deployment-port" type="number" min="1" max="65535" value="443"></div>' +
        '<div class="form-group"><label for="deployment-name">节点名称</label><input id="deployment-name" maxlength="64" placeholder="如 🇭🇰 HK Reality"></div>' +
        '<div class="form-group"><label for="deployment-server">连接地址 (IP / 域名)</label><input id="deployment-server" placeholder="公网 IP 或域名"></div>' +
        '</div>' +
        ((pubIpv4 || pubIpv6)
            ? '<div class="deploy-ip-row" id="deployment-ip-quick">' +
              (pubIpv4 ? `<button type="button" class="btn btn-sm" data-ip-val="${_escHtml(pubIpv4)}">填入 IPv4 (${_escHtml(pubIpv4)})</button>` : '') +
              (pubIpv6 ? `<button type="button" class="btn btn-sm" data-ip-val="${_escHtml(pubIpv6)}">填入 IPv6 (${_escHtml(pubIpv6)})</button>` : '') +
              '</div>'
            : '') +
        _agentRegionPickerHtml('deployment-region', agent.region || '', '地区 / 国旗') +
        '<div id="deployment-share-notice" class="deploy-share-banner" hidden></div>' +
        '</div>' +
        '<div class="deploy-section" id="deployment-proto-section">' +
        '<div class="deploy-section-title">协议与伪装</div>' +
        '<div id="deployment-tls-section"><div class="form-grid">' +
        '<div class="form-group"><label for="deployment-tls-mode">TLS / 伪装模式</label><select id="deployment-tls-mode"></select></div>' +
        '<div class="form-group"><label id="deployment-domain-label" for="deployment-domain">域名 / SNI</label><input id="deployment-domain" placeholder="www.amazon.com 或自有域名"></div>' +
        '<div class="form-group" id="deployment-cam-mode-wrap" hidden><label for="deployment-camouflage-mode">回环伪装内容 (Caddy)</label><select id="deployment-camouflage-mode">' +
        '<option value="template">内置静态站模板</option>' +
        '<option value="proxy">反代外部 HTTPS 站点</option>' +
        '<option value="static_dir">自定义静态目录</option></select></div>' +
        '<div class="form-group" id="deployment-cam-tpl-wrap" hidden><label for="deployment-camouflage-template">静态伪装模板</label><select id="deployment-camouflage-template">' +
        '<option value="corporate">企业科技官网 (corporate)</option>' +
        '<option value="blog">极简技术博客 (blog)</option>' +
        '<option value="status">状态监测页 (status)</option>' +
        '<option value="nginx">极简欢迎页 (nginx)</option></select></div>' +
        '<div class="form-group full-width" id="deployment-cam-url-wrap"><label id="deployment-cam-url-label" for="deployment-camouflage">伪装目标 URL (可选)</label><input id="deployment-camouflage" placeholder="https://www.apple.com"></div>' +
        '<div class="form-group full-width" id="deployment-cam-dir-wrap" hidden><label for="deployment-camouflage-dir">宿主机静态目录</label><input id="deployment-camouflage-dir" placeholder="/var/www/site"></div>' +
        '</div>' +
        '<div id="deployment-caddy-summary" class="deploy-status-bar" hidden style="margin-top:8px;"></div></div>' +
        '<div id="deployment-reality-ext-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label for="deployment-fingerprint">uTLS 指纹</label><select id="deployment-fingerprint"><option value="chrome">chrome</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="edge">edge</option><option value="ios">ios</option><option value="android">android</option><option value="random">random</option></select></div>' +
        '<div class="form-group"><label for="deployment-reality-pubkey">Reality Public Key</label><input id="deployment-reality-pubkey" placeholder="留空自动生成"></div>' +
        '<div class="form-group full-width"><label for="deployment-reality-shortids">Short IDs (逗号分隔 hex)</label><input id="deployment-reality-shortids" placeholder="留空自动生成"></div>' +
        '</div></div>' +
        '<div id="deployment-ss2022-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label for="deployment-ss2022-method">SS2022 加密套件</label><select id="deployment-ss2022-method"><option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option><option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option></select></div>' +
        '<div class="form-group deploy-inline-field"><label class="inline-check"><input type="checkbox" id="deployment-ss2022-publish"> 同时投影至客户端订阅</label></div>' +
        '</div></div>' +
        '<div id="deployment-hy2-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label for="deployment-hy2-mport">端口跳跃 mport</label><input id="deployment-hy2-mport" placeholder="20000-50000"></div>' +
        '<div class="form-group"><label for="deployment-hy2-hop">跳跃间隔 (秒)</label><input id="deployment-hy2-hop" type="number" min="5" max="3600" placeholder="30"></div>' +
        '<div class="form-group"><label for="deployment-hy2-up">上行带宽 (Mbps)</label><input id="deployment-hy2-up" type="number" min="1" max="100000" placeholder="100"></div>' +
        '<div class="form-group"><label for="deployment-hy2-down">下行带宽 (Mbps)</label><input id="deployment-hy2-down" type="number" min="1" max="100000" placeholder="500"></div>' +
        '<div class="form-group"><label for="deployment-hy2-obfs">QUIC 混淆</label><select id="deployment-hy2-obfs"><option value="none">none</option><option value="salamander">salamander</option></select></div>' +
        '</div></div>' +
        '<div id="deployment-acme-fields" hidden><div class="form-grid">' +
        '<div class="form-group full-width"><label for="deployment-acme-email">ACME 联系邮箱 (可选)</label><input id="deployment-acme-email" type="email" placeholder="admin@example.com"></div>' +
        '</div></div>' +
        '<div id="deployment-dns-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label for="deployment-dns-provider">DNS 服务商</label><select id="deployment-dns-provider"><option value="cloudflare">cloudflare</option><option value="alidns">alidns</option><option value="dnspod">dnspod</option></select></div>' +
        '<div class="form-group"><label for="deployment-dns-zone">DNS Zone ID</label><input id="deployment-dns-zone" placeholder="32 位 hex (Cloudflare)"></div>' +
        '<div class="form-group"><label for="deployment-dns-prop">传播等待 (秒)</label><input id="deployment-dns-prop" type="number" min="10" max="600" value="60"></div>' +
        '<div class="form-group"><label for="deployment-dns-token">DNS API Token</label><input id="deployment-dns-token" type="password" autocomplete="off" placeholder="留空保持原有凭据"></div>' +
        '</div></div>' +
        '<div class="deploy-keygen-row"><button type="button" class="btn btn-sm" id="deployment-keygen-btn">预生成密钥对</button><span id="deployment-keyref-status" class="hint"></span></div>' +
        '</div>' +
        '<details id="deployment-outbound-details"><summary>出站策略与多跳落地</summary>' +
        '<div class="form-grid" style="margin-top:10px;">' +
        '<div class="form-group"><label for="deployment-outbound-strategy">出站 IP 协议栈</label><select id="deployment-outbound-strategy">' +
        '<option value="prefer_ipv4">双栈 IPv4 优先 (prefer_ipv4)</option>' +
        '<option value="prefer_ipv6">双栈 IPv6 优先 (prefer_ipv6)</option>' +
        '<option value="ipv4_only">仅 IPv4 (ipv4_only)</option>' +
        '<option value="ipv6_only">仅 IPv6 (ipv6_only)</option></select></div>' +
        '<div class="form-group"><label for="deployment-outbound-mode">出站方式</label><select id="deployment-outbound-mode">' +
        '<option value="direct">本机直连 (Direct)</option>' +
        '<option value="chain">链式多跳落地 (1~4 跳)</option>' +
        '<option value="socks5">外部 Socks5 落地</option>' +
        '<option value="ss">外部 Shadowsocks 落地</option></select></div>' +
        '</div>' +
        '<div id="deployment-outbound-proxy-fields" hidden style="margin-top:10px;"><div id="deployment-outbound-link-slot"></div><div class="form-grid">' +
        '<div class="form-group"><label for="deployment-out-server">落地服务器地址</label><input id="deployment-out-server" placeholder="isp.example.com 或 IP"></div>' +
        '<div class="form-group"><label for="deployment-out-port">落地端口</label><input id="deployment-out-port" type="number" min="1" max="65535" placeholder="1080"></div>' +
        '<div class="form-group" id="deployment-out-user-wrap"><label for="deployment-out-user">Socks5 用户名 (可选)</label><input id="deployment-out-user" placeholder="username"></div>' +
        '<div class="form-group" id="deployment-out-method-wrap" hidden><label for="deployment-out-method">SS 加密方式</label><select id="deployment-out-method">' +
        '<option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>' +
        '<option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>' +
        '<option value="aes-256-gcm">aes-256-gcm</option>' +
        '<option value="aes-128-gcm">aes-128-gcm</option>' +
        '<option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option></select></div>' +
        '<div class="form-group"><label for="deployment-out-pass">落地密码</label><input id="deployment-out-pass" type="password" autocomplete="off" class="pf-ephemeral-secret" placeholder="留空保持原密码"></div>' +
        '</div></div>' +
        '<div id="deployment-outbound-chain-fields" hidden style="margin-top:10px;"></div></details>',
        () => submit(false),
        { confirmText: '保存并应用', cancelText: '关闭' }
    );

    _bindAgentRegionPicker('deployment-region', 'deployment-name');
    const status = document.getElementById('deployment-state');
    const remove = document.getElementById('deployment-remove');
    const listenerModeEl = document.getElementById('deployment-listener-mode');
    const listenerModeWrap = document.getElementById('deployment-listener-mode-wrap');
    const protocol = document.getElementById('deployment-protocol');
    const portInputEl = document.getElementById('deployment-port');
    const shareNoticeEl = document.getElementById('deployment-share-notice');
    const tlsModeEl = document.getElementById('deployment-tls-mode');
    const camModeEl = document.getElementById('deployment-camouflage-mode');
    const camTplEl = document.getElementById('deployment-camouflage-template');
    const outModeEl = document.getElementById('deployment-outbound-mode');
    const keygenBtn = document.getElementById('deployment-keygen-btn');
    const keyrefStatus = document.getElementById('deployment-keyref-status');
    const nodesBar = document.getElementById('deployment-nodes-bar');
    const outDetailsEl = document.getElementById('deployment-outbound-details');
    let lastSyncedSharedHostKey = '';

    function setStatusBanner(message, tone = 'neutral') {
        if (!status) return;
        const text = String(message || '').trim();
        status.hidden = !text;
        status.textContent = text;
        status.className = 'deploy-status-bar' + (tone === 'error' ? ' is-error' : (tone === 'warn' ? ' is-warn' : ''));
        if (text && tone === 'error' && typeof status.scrollIntoView === 'function') {
            status.scrollIntoView({ block: 'nearest' });
        }
    }

    const hopEditor = _createOutboundHopsEditor({
        container: document.getElementById('deployment-outbound-chain-fields'),
        initialHops: [],
        ssLandings,
        currentAgentId: agent.id,
    });
    const outLinkSlot = document.getElementById('deployment-outbound-link-slot');
    const outLinkRecognizer = _createOutboundLinkRecognizer({
        allowedKinds: ['ss', 'socks5'],
        onApplyNode(parsed) {
            outModeEl.value = parsed.kind;
            document.getElementById('deployment-out-server').value = parsed.server;
            document.getElementById('deployment-out-port').value = String(parsed.port);
            document.getElementById('deployment-out-pass').value = parsed.password || '';
            if (parsed.kind === 'ss') {
                if (SUPPORTED_EXTERNAL_SS_METHODS.includes(parsed.method)) {
                    document.getElementById('deployment-out-method').value = parsed.method;
                }
            } else {
                document.getElementById('deployment-out-user').value = parsed.username || '';
            }
            render(false);
        },
    });
    if (outLinkSlot) outLinkSlot.append(outLinkRecognizer.el);

    document.querySelectorAll('#deployment-ip-quick button[data-ip-val]').forEach(btn => {
        btn.onclick = () => {
            document.getElementById('deployment-server').value = btn.getAttribute('data-ip-val') || '';
        };
    });

    function getSelectedNode() {
        return agentNodes.find(n => n.id === currentNodeId) || null;
    }

    function getSharedListenerContext() {
        const current = getSelectedNode();
        const proto = _normalizeNodeProto(protocol.value);
        const portVal = Number(portInputEl.value);
        const peers = _findSharedPortPeers(agentNodes, proto, portVal, current ? current.id : null);
        if (!peers.length) {
            return { peers: [], host: null, alreadySharing: false, joiningShared: false };
        }
        const host = peers.find(n => n.is_primary) || peers[0];
        const alreadySharing = Boolean(
            current
            && _normalizeNodeProto(current.protocol) === proto
            && Number((current.settings || {}).listen_port) === portVal
        );
        return { peers, host, alreadySharing, joiningShared: !alreadySharing };
    }

    function rebuildListenerOptions() {
        if (!listenerModeEl || !listenerModeWrap) return;
        const current = getSelectedNode();
        const hosts = _listReusableListenerHosts(agentNodes, current ? current.id : null);
        listenerModeEl.replaceChildren();
        const standaloneOpt = document.createElement('option');
        standaloneOpt.value = 'standalone';
        standaloneOpt.textContent = '独立监听端口';
        listenerModeEl.append(standaloneOpt);
        for (const h of hosts) {
            const hs = h.settings || {};
            const sni = hs.domain || hs.server_name || '-';
            const opt = document.createElement('option');
            opt.value = `share::${h.id}`;
            opt.textContent = `复用已有端口：${hs.name || h.protocol} (${_formatCardProto(h.protocol)} :${hs.listen_port} · ${sni})`;
            listenerModeEl.append(opt);
        }
        listenerModeWrap.hidden = hosts.length === 0;
        const sharedCtx = getSharedListenerContext();
        const matchedVal = sharedCtx.host ? `share::${sharedCtx.host.id}` : 'standalone';
        if ([...listenerModeEl.options].some(o => o.value === matchedVal)) {
            listenerModeEl.value = matchedVal;
        } else {
            listenerModeEl.value = 'standalone';
        }
    }

    function applyHostFieldsToDeploymentForm(host) {
        if (!host) return;
        const s = host.settings || {};
        const p = _normalizeNodeProto(host.protocol);
        syncTlsOptions(p, s.tls_mode);
        document.getElementById('deployment-domain').value = s.domain ?? s.server_name ?? '';
        document.getElementById('deployment-camouflage').value = s.camouflage_url ?? '';
        document.getElementById('deployment-camouflage-dir').value = s.camouflage_dir ?? '';
        const inferredCamMode = s.camouflage_mode || (s.camouflage_dir ? 'static_dir' : (s.camouflage_url ? 'proxy' : 'template'));
        if (camModeEl) camModeEl.value = inferredCamMode;
        if (camTplEl) camTplEl.value = s.camouflage_template || 'corporate';
        document.getElementById('deployment-reality-pubkey').value = s.reality_public_key ?? '';
        document.getElementById('deployment-acme-email').value = s.acme_email ?? '';
        document.getElementById('deployment-dns-provider').value = s.dns_provider ?? 'cloudflare';
        document.getElementById('deployment-dns-zone').value = s.dns_zone_id ?? '';
        document.getElementById('deployment-dns-prop').value = s.dns_propagation_seconds ?? 60;
        document.getElementById('deployment-hy2-up').value = s.up_mbps ?? '';
        document.getElementById('deployment-hy2-down').value = s.down_mbps ?? '';
        document.getElementById('deployment-hy2-obfs').value = s.obfs ?? 'none';
        document.getElementById('deployment-hy2-mport').value = s.mport ?? '';
        document.getElementById('deployment-hy2-hop').value = s.hop_interval ?? '';
    }

    function setListenerFieldsDisabled(disabled) {
        for (const id of [
            'deployment-tls-mode', 'deployment-domain', 'deployment-camouflage-mode',
            'deployment-camouflage-template', 'deployment-camouflage', 'deployment-camouflage-dir',
            'deployment-reality-pubkey', 'deployment-acme-email', 'deployment-dns-provider',
            'deployment-dns-zone', 'deployment-dns-prop', 'deployment-dns-token',
            'deployment-hy2-obfs', 'deployment-hy2-up', 'deployment-hy2-down',
            'deployment-hy2-mport', 'deployment-hy2-hop',
        ]) {
            const el = document.getElementById(id);
            if (el) el.disabled = Boolean(disabled);
        }
    }

    function syncTlsOptions(proto, preferred) {
        const meta = LANDING_PROTO_META[proto] || LANDING_PROTO_META.reality;
        tlsModeEl.replaceChildren();
        for (const [modeVal, modeLabel] of meta.tlsModes) {
            const opt = document.createElement('option');
            opt.value = modeVal;
            opt.textContent = modeLabel;
            tlsModeEl.append(opt);
        }
        const validValues = meta.tlsModes.map(m => m[0]);
        if (preferred && validValues.includes(preferred)) tlsModeEl.value = preferred;
        else tlsModeEl.value = validValues[0];
    }

    function renderNodesBar() {
        nodesBar.replaceChildren();
        for (const n of agentNodes) {
            const btn = document.createElement('button');
            btn.type = 'button';
            const isSel = n.id === currentNodeId;
            btn.className = isSel ? 'btn btn-primary btn-sm' : 'btn btn-sm';
            const s = n.settings || {};
            const roleText = _nodeOutboundRoleText(n);
            btn.textContent = `${s.name || n.protocol} (${_formatCardProto(n.protocol)} :${s.listen_port || '?'} · ${roleText})`;
            btn.onclick = () => {
                currentNodeId = n.id;
                generatedKeyRef = null;
                lastSyncedSharedHostKey = '';
                outLinkRecognizer.clear();
                render(true);
            };
            nodesBar.append(btn);
        }
        const addBtn = document.createElement('button');
        addBtn.type = 'button';
        addBtn.className = currentNodeId === null ? 'btn btn-primary btn-sm' : 'btn btn-sm';
        addBtn.textContent = '+ 新增节点';
        addBtn.onclick = () => {
            currentNodeId = null;
            generatedKeyRef = null;
            lastSyncedSharedHostKey = '';
            outLinkRecognizer.clear();
            protocol.value = 'reality';
            syncTlsOptions('reality', 'reality');
            document.getElementById('deployment-name').value = '';
            document.getElementById('deployment-port').value = String(pickNextFreePort(443));
            document.getElementById('deployment-server').value = pubIpv4 || pubIpv6 || '';
            document.getElementById('deployment-domain').value = 'www.amazon.com';
            document.getElementById('deployment-camouflage').value = '';
            document.getElementById('deployment-camouflage-dir').value = '';
            if (camModeEl) camModeEl.value = 'template';
            if (camTplEl) camTplEl.value = 'corporate';
            document.getElementById('deployment-reality-pubkey').value = '';
            document.getElementById('deployment-reality-shortids').value = '';
            document.getElementById('deployment-hy2-mport').value = '';
            document.getElementById('deployment-hy2-hop').value = '';
            document.getElementById('deployment-ss2022-publish').checked = false;
            document.getElementById('deployment-outbound-strategy').value = 'prefer_ipv4';
            outModeEl.value = 'direct';
            hopEditor.setHops([]);
            render(false);
        };
        nodesBar.append(addBtn);
        if (typeof window !== 'undefined' && window.twemoji) {
            window.twemoji.parse(nodesBar, { folder: 'svg', ext: '.svg' });
        }
    }

    function render(fill) {
        renderNodesBar();
        const current = getSelectedNode();
        if (fill) {
            if (current) {
                const p = LANDING_PROTO_META[_normalizeNodeProto(current.protocol)] ? _normalizeNodeProto(current.protocol) : 'reality';
                protocol.value = p;
                const s = current.settings || {};
                syncTlsOptions(p, s.tls_mode);
                document.getElementById('deployment-name').value = s.name ?? '';
                document.getElementById('deployment-server').value = s.server ?? (pubIpv4 || pubIpv6 || '');
                document.getElementById('deployment-port').value = s.listen_port ?? 443;
                document.getElementById('deployment-domain').value = s.domain ?? s.server_name ?? '';
                document.getElementById('deployment-camouflage').value = s.camouflage_url ?? '';
                document.getElementById('deployment-camouflage-dir').value = s.camouflage_dir ?? '';
                const inferredCamMode = s.camouflage_mode || (s.camouflage_dir ? 'static_dir' : (s.camouflage_url ? 'proxy' : 'template'));
                if (camModeEl) camModeEl.value = inferredCamMode;
                if (camTplEl) camTplEl.value = s.camouflage_template || 'corporate';
                document.getElementById('deployment-fingerprint').value = s.fingerprint ?? 'chrome';
                document.getElementById('deployment-reality-pubkey').value = s.reality_public_key ?? '';
                document.getElementById('deployment-reality-shortids').value = Array.isArray(s.reality_short_ids) ? s.reality_short_ids.join(', ') : '';
                document.getElementById('deployment-ss2022-method').value = s.method ?? '2022-blake3-aes-256-gcm';
                document.getElementById('deployment-ss2022-publish').checked = Boolean(s.publish_to_subscription);
                document.getElementById('deployment-hy2-up').value = s.up_mbps ?? '';
                document.getElementById('deployment-hy2-down').value = s.down_mbps ?? '';
                document.getElementById('deployment-hy2-obfs').value = s.obfs ?? 'none';
                document.getElementById('deployment-hy2-mport').value = s.mport ?? '';
                document.getElementById('deployment-hy2-hop').value = s.hop_interval ?? '';
                document.getElementById('deployment-acme-email').value = s.acme_email ?? '';
                document.getElementById('deployment-dns-provider').value = s.dns_provider ?? 'cloudflare';
                document.getElementById('deployment-dns-zone').value = s.dns_zone_id ?? '';
                document.getElementById('deployment-dns-prop').value = s.dns_propagation_seconds ?? 60;
                document.getElementById('deployment-outbound-strategy').value = s.outbound_strategy ?? 'prefer_ipv4';
                outModeEl.value = s.outbound_mode ?? 'direct';
                document.getElementById('deployment-out-server').value = s.outbound_server ?? '';
                document.getElementById('deployment-out-port').value = s.outbound_port ?? '';
                document.getElementById('deployment-out-user').value = s.outbound_username ?? '';
                document.getElementById('deployment-out-method').value = s.outbound_method ?? '2022-blake3-aes-256-gcm';
                hopEditor.setHops(Array.isArray(s.outbound_hops) ? s.outbound_hops : []);
                if (outDetailsEl && s.outbound_mode && s.outbound_mode !== 'direct') {
                    outDetailsEl.open = true;
                }
            } else if (!document.getElementById('deployment-server').value) {
                document.getElementById('deployment-server').value = pubIpv4 || pubIpv6 || '';
                document.getElementById('deployment-port').value = String(pickNextFreePort(443));
                syncTlsOptions(protocol.value);
                if (protocol.value === 'reality' && tlsModeEl.value === 'reality' && !document.getElementById('deployment-domain').value) {
                    document.getElementById('deployment-domain').value = 'www.amazon.com';
                }
            }
        }
        const proto = protocol.value;
        const meta = LANDING_PROTO_META[proto] || LANDING_PROTO_META.reality;
        const sharedCtx = getSharedListenerContext();
        rebuildListenerOptions();
        if (sharedCtx.joiningShared && sharedCtx.host) {
            const syncKey = `${sharedCtx.host.id}:${proto}:${portInputEl.value}`;
            if (lastSyncedSharedHostKey !== syncKey) {
                applyHostFieldsToDeploymentForm(sharedCtx.host);
                generatedKeyRef = null;
                lastSyncedSharedHostKey = syncKey;
            }
            setListenerFieldsDisabled(true);
            if (shareNoticeEl) {
                const peerNames = sharedCtx.peers.map(p => (p.settings || {}).name || p.protocol).join('、');
                shareNoticeEl.hidden = false;
                shareNoticeEl.textContent = `同端口复用：将与「${peerNames}」共用 ${_formatCardProto(proto)} :${portInputEl.value} 监听器，独立凭据按 auth_user 分流。`;
            }
        } else {
            lastSyncedSharedHostKey = '';
            setListenerFieldsDisabled(false);
            if (sharedCtx.alreadySharing && sharedCtx.peers.length) {
                const pubInput = document.getElementById('deployment-reality-pubkey');
                if (pubInput && proto === 'reality') pubInput.disabled = true;
                if (shareNoticeEl) {
                    const peerNames = sharedCtx.peers.map(p => (p.settings || {}).name || p.protocol).join('、');
                    shareNoticeEl.hidden = false;
                    shareNoticeEl.textContent = `同端口复用：与「${peerNames}」共用 ${_formatCardProto(proto)} :${portInputEl.value}（auth_user 独立分流），修改监听器参数将同步生效。`;
                }
            } else if (shareNoticeEl) {
                shareNoticeEl.hidden = true;
                shareNoticeEl.textContent = '';
            }
        }
        const tlsMode = tlsModeEl.value || meta.tlsModes[0][0];
        document.getElementById('deployment-tls-section').hidden = proto === 'ss2022';
        document.getElementById('deployment-reality-ext-fields').hidden = proto === 'ss2022' || proto === 'hysteria2' || proto === 'trojan';
        document.getElementById('deployment-reality-pubkey').closest('.form-group').hidden = proto !== 'reality';
        document.getElementById('deployment-reality-shortids').closest('.form-group').hidden = proto !== 'reality';
        document.getElementById('deployment-ss2022-fields').hidden = proto !== 'ss2022';
        document.getElementById('deployment-hy2-fields').hidden = proto !== 'hysteria2';
        const usesAcme = tlsMode === 'acme_http' || tlsMode === 'acme_dns';
        document.getElementById('deployment-acme-fields').hidden = !usesAcme;
        document.getElementById('deployment-dns-fields').hidden = tlsMode !== 'acme_dns';
        document.getElementById('deployment-domain-label').textContent =
            (proto === 'reality' && tlsMode === 'reality') ? '目标 SNI 域名' : '证书域名 / SNI';

        const usesCaddyCamo = (proto === 'reality' && usesAcme) || proto === 'trojan';
        const camMode = (camModeEl && camModeEl.value) || 'template';
        const camModeWrap = document.getElementById('deployment-cam-mode-wrap');
        const camTplWrap = document.getElementById('deployment-cam-tpl-wrap');
        const camUrlWrap = document.getElementById('deployment-cam-url-wrap');
        const camDirWrap = document.getElementById('deployment-cam-dir-wrap');
        const camUrlLabel = document.getElementById('deployment-cam-url-label');
        const caddySummary = document.getElementById('deployment-caddy-summary');
        if (camModeWrap) camModeWrap.hidden = !usesCaddyCamo;
        if (camTplWrap) camTplWrap.hidden = !(usesCaddyCamo && camMode === 'template');
        if (camDirWrap) camDirWrap.hidden = !(usesCaddyCamo && camMode === 'static_dir');
        if (camUrlWrap) {
            const showUrl = (usesCaddyCamo && camMode === 'proxy') || (proto === 'reality' && tlsMode === 'reality') || proto === 'hysteria2';
            camUrlWrap.hidden = !showUrl;
        }
        if (camUrlLabel) {
            camUrlLabel.textContent = usesCaddyCamo
                ? '反代上游 HTTPS URL'
                : (proto === 'hysteria2' ? 'Masquerade 伪装 URL (可选)' : '自定义回落 URL (可选)');
        }
        if (caddySummary) {
            if (usesCaddyCamo) {
                const domPreview = document.getElementById('deployment-domain').value.trim() || '待填域名';
                const tplNames = { corporate: '企业科技官网', blog: '极简技术博客', status: '状态监测页', nginx: '极简欢迎页' };
                const modeDesc = camMode === 'template'
                    ? `内置模板「${tplNames[(camTplEl && camTplEl.value) || 'corporate'] || 'corporate'}」`
                    : (camMode === 'proxy'
                        ? `反代 ${document.getElementById('deployment-camouflage').value.trim() || '待填 URL'}`
                        : `静态目录 ${document.getElementById('deployment-camouflage-dir').value.trim() || '待填路径'}`);
                const roleLabel = proto === 'trojan' ? 'Trojan 回落' : 'Reality 回环';
                caddySummary.hidden = false;
                caddySummary.textContent = `Caddy ${roleLabel} · ${domPreview} (${tlsMode}) · ${modeDesc}`;
            } else {
                caddySummary.hidden = true;
            }
        }

        const outMode = outModeEl.value || 'direct';
        document.getElementById('deployment-outbound-proxy-fields').hidden = !(outMode === 'socks5' || outMode === 'ss');
        document.getElementById('deployment-outbound-chain-fields').hidden = outMode !== 'chain';
        document.getElementById('deployment-out-user-wrap').hidden = outMode !== 'socks5';
        document.getElementById('deployment-out-method-wrap').hidden = outMode !== 'ss';

        keygenBtn.hidden = !meta.canKeygen || sharedCtx.joiningShared;
        keyrefStatus.textContent = sharedCtx.joiningShared
            ? '同端口复用将自动继承已有监听器的密钥对'
            : (generatedKeyRef ? '已预生成服务端密钥，提交时自动注入' : '');

        const capable = agentCanLand(agent) || agentCanDeploy(agent);
        const busy = agentNodes.some(n => ['pending', 'assigned', 'running'].includes(n.status));
        const blocked = submitting || !capable || busy;
        if (typeof modalConfirm !== 'undefined' && modalConfirm) {
            modalConfirm.disabled = blocked;
        }
        remove.hidden = !current;
        remove.disabled = blocked || !current;

        if (!capable) {
            setStatusBanner('请先升级此服务器 Agent 与 Runtime 辅助服务以支持节点部署。', 'warn');
        } else if (busy) {
            setStatusBanner('当前有正在执行的部署任务，完成后再提交修改。', 'warn');
        } else if (current && current.error) {
            setStatusBanner(`版本 ${current.revision} · ${current.status}：${_formatRuntimeError(current.error)}`, 'error');
        } else if (current) {
            setStatusBanner(`[${current.is_primary ? '主节点' : '共存节点'}] 版本 ${current.revision} · ${current.status}`, 'neutral');
        } else {
            setStatusBanner('', 'neutral');
        }
    }

    async function refresh() {
        generatedKeyRef = null;
        nodesPayload = await fetchAgentJson(nodesUrl);
        agentNodes = nodesPayload.nodes || [];
        if (currentNodeId && !agentNodes.some(n => n.id === currentNodeId)) {
            currentNodeId = agentNodes.length ? agentNodes[0].id : null;
        } else if (!currentNodeId && agentNodes.length) {
            currentNodeId = agentNodes[0].id;
        }
        render(true);
    }

    keygenBtn.onclick = async () => {
        try {
            keygenBtn.disabled = true;
            const res = await fetchAgentJson('/agents/deployments/generate-keys', {
                method: 'POST',
                body: JSON.stringify({ protocol: protocol.value }),
            });
            generatedKeyRef = res.key_ref || null;
            if (res.reality_public_key) document.getElementById('deployment-reality-pubkey').value = res.reality_public_key;
            if (Array.isArray(res.reality_short_ids)) document.getElementById('deployment-reality-shortids').value = res.reality_short_ids.join(', ');
            render(false);
        } catch (error) {
            setStatusBanner('生成密钥失败：' + error.message, 'error');
        } finally {
            keygenBtn.disabled = false;
        }
    };

    function buildPayloadSettings(isCreating = false) {
        const proto = protocol.value;
        let nodeName = document.getElementById('deployment-name').value.trim();
        if (!nodeName) throw new Error('请填写节点名称');
        if (nodeName.length > 64) throw new Error('节点名称不能超过 64 个字符');
        const regionVal = document.getElementById('deployment-region')?.value?.trim() || '';
        if (regionVal && typeof ProxyForgeRegions !== 'undefined') {
            nodeName = ProxyForgeRegions.applyRegionPrefix(nodeName, regionVal);
            document.getElementById('deployment-name').value = nodeName;
        }
        const serverVal = document.getElementById('deployment-server').value.trim();
        if (!serverVal) throw new Error('请填写公网 IP 或域名（客户端连接地址）');
        const portVal = Number(document.getElementById('deployment-port').value);
        if (!Number.isInteger(portVal) || portVal < 1 || portVal > 65535) {
            throw new Error('监听端口必须为 1–65535 之间的整数');
        }
        const tlsMode = proto === 'ss2022' ? 'none' : tlsModeEl.value;
        const settings = {
            name: nodeName,
            server: serverVal,
            listen_port: portVal,
            protocol: proto,
            tls_mode: tlsMode,
            outbound_strategy: document.getElementById('deployment-outbound-strategy').value || 'prefer_ipv4',
            outbound_mode: outModeEl.value || 'direct',
        };
        if (regionVal) settings.region = regionVal;
        const domain = document.getElementById('deployment-domain').value.trim();
        const needsDomain = proto !== 'ss2022' && (['reality', 'trojan', 'anytls', 'hysteria2'].includes(proto) || tlsMode === 'acme_http' || tlsMode === 'acme_dns');
        if (needsDomain && !domain) {
            throw new Error(proto === 'reality' && tlsMode === 'reality'
                ? '请填写目标 SNI 域名（如 www.amazon.com）'
                : '当前协议/证书模式必须填写证书域名 / SNI');
        }
        const cam = document.getElementById('deployment-camouflage').value.trim();
        const camDir = document.getElementById('deployment-camouflage-dir')?.value?.trim() || '';
        const usesCaddyCamo = (proto === 'reality' && (tlsMode === 'acme_http' || tlsMode === 'acme_dns')) || proto === 'trojan';
        if (domain) settings.domain = domain;
        if (usesCaddyCamo) {
            const cMode = (camModeEl && camModeEl.value) || 'template';
            settings.camouflage_mode = cMode;
            if (cMode === 'template') {
                settings.camouflage_template = (camTplEl && camTplEl.value) || 'corporate';
            } else if (cMode === 'proxy') {
                if (!cam) throw new Error('选择反代模式时必须填写反代上游 URL');
                settings.camouflage_url = cam;
            } else if (cMode === 'static_dir') {
                if (!camDir) throw new Error('选择静态目录模式时必须填写宿主机绝对路径');
                settings.camouflage_dir = camDir;
            }
        } else if (cam) {
            settings.camouflage_url = cam;
        }
        if (proto === 'ss2022') {
            settings.method = document.getElementById('deployment-ss2022-method').value;
            settings.publish_to_subscription = Boolean(document.getElementById('deployment-ss2022-publish').checked);
        }
        if (proto === 'reality') {
            settings.fingerprint = document.getElementById('deployment-fingerprint').value;
            const pub = document.getElementById('deployment-reality-pubkey').value.trim();
            const sids = document.getElementById('deployment-reality-shortids').value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
            if (pub) settings.reality_public_key = pub;
            if (sids.length) settings.reality_short_ids = sids;
        }
        if (proto === 'anytls') {
            settings.fingerprint = document.getElementById('deployment-fingerprint').value;
        }
        if (proto === 'hysteria2') {
            const up = Number(document.getElementById('deployment-hy2-up').value);
            const down = Number(document.getElementById('deployment-hy2-down').value);
            if (up > 0) settings.up_mbps = Math.round(up);
            if (down > 0) settings.down_mbps = Math.round(down);
            settings.obfs = document.getElementById('deployment-hy2-obfs').value;
            const mport = document.getElementById('deployment-hy2-mport').value.trim();
            if (mport) settings.mport = mport;
            const hop = Number(document.getElementById('deployment-hy2-hop').value);
            if (hop >= 5) settings.hop_interval = Math.round(hop);
        }
        const secrets = {};
        if (tlsMode === 'acme_http' || tlsMode === 'acme_dns') {
            const email = document.getElementById('deployment-acme-email').value.trim();
            if (email) settings.acme_email = email;
        }
        if (tlsMode === 'acme_dns') {
            const sharedCtx = getSharedListenerContext();
            settings.dns_provider = document.getElementById('deployment-dns-provider').value;
            const zone = document.getElementById('deployment-dns-zone').value.trim();
            if (settings.dns_provider === 'cloudflare' && !/^[0-9a-fA-F]{32}$/.test(zone)) {
                throw new Error('Cloudflare DNS-01 必须填写 32 位十六进制 Zone ID');
            }
            if (zone) settings.dns_zone_id = zone;
            const prop = Number(document.getElementById('deployment-dns-prop').value);
            if (prop >= 10) settings.dns_propagation_seconds = Math.round(prop);
            const tok = document.getElementById('deployment-dns-token').value.trim();
            if (isCreating && !sharedCtx.joiningShared && tok.length < 12) {
                throw new Error('首次配置 DNS-01 需填写至少 12 位 DNS API Token');
            }
            if (tok) secrets.dns_api_token = tok;
        }
        if (settings.outbound_mode === 'socks5' || settings.outbound_mode === 'ss') {
            const outSrv = document.getElementById('deployment-out-server').value.trim();
            const outPort = Number(document.getElementById('deployment-out-port').value);
            if (!outSrv) throw new Error('请填写外部落地服务器地址');
            if (!Number.isInteger(outPort) || outPort < 1 || outPort > 65535) {
                throw new Error('外部落地端口必须为 1–65535 之间的整数');
            }
            settings.outbound_server = outSrv;
            settings.outbound_port = outPort;
            if (settings.outbound_mode === 'socks5') {
                const u = document.getElementById('deployment-out-user').value.trim();
                if (u) settings.outbound_username = u;
            } else {
                settings.outbound_method = document.getElementById('deployment-out-method').value;
            }
            const outPw = document.getElementById('deployment-out-pass').value.trim();
            if (isCreating && settings.outbound_mode === 'ss' && !outPw) {
                throw new Error('外部 Shadowsocks 落地出站必须填写密码');
            }
            if (outPw) secrets.outbound_password = outPw;
        } else if (settings.outbound_mode === 'chain') {
            const collected = hopEditor.collect();
            if (!collected.outbound_hops || !collected.outbound_hops.length) {
                throw new Error('链式多跳出站至少需要添加 1 跳落地节点');
            }
            settings.outbound_hops = collected.outbound_hops;
            if (Object.keys(collected.hop_passwords).length) {
                secrets.hop_passwords = collected.hop_passwords;
            }
        }
        return { settings, secrets: Object.keys(secrets).length ? secrets : null };
    }

    async function submit(removing) {
        if (submitting) return;
        const current = getSelectedNode();
        if (removing && !current) return;
        let built = null;
        if (!removing) {
            try {
                built = buildPayloadSettings(!current);
            } catch (err) {
                setStatusBanner('配置校验未通过：' + err.message, 'error');
                return;
            }
        }
        if (!confirm(removing ? `确认删除节点 ${current.settings?.name || ''} 并重载代理服务进程？` : '确认保存配置并重载/重启代理服务进程（不会重启服务器）？')) return;
        submitting = true;
        if (typeof modalConfirm !== 'undefined' && modalConfirm) modalConfirm.disabled = true;
        remove.disabled = true;
        try {
            let savedNoRestart = false;
            if (removing) {
                await fetchAgentJson('/agents/' + agent.id + '/nodes/' + encodeURIComponent(current.id), {
                    method: 'DELETE',
                    body: JSON.stringify({ request_id: randomRequestId() }),
                });
                currentNodeId = null;
                showToast('节点已删除并下发重载', 'success');
                await refresh();
                if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
                refreshAgents().catch(() => {});
                return;
            }
            const body = {
                request_id: randomRequestId(),
                protocol: protocol.value,
                settings: built.settings,
            };
            const sharedCtx = getSharedListenerContext();
            if (built.secrets) body.secrets = built.secrets;
            if (generatedKeyRef && !sharedCtx.joiningShared) body.key_ref = generatedKeyRef;
            const endpoint = current
                ? '/agents/' + agent.id + '/nodes/' + encodeURIComponent(current.id)
                : '/agents/' + agent.id + '/nodes';
            const res = await fetchAgentJson(endpoint, {
                method: current ? 'PUT' : 'POST',
                body: JSON.stringify(body),
            });
            savedNoRestart = Boolean(res && res.restarted === false);
            const tokField = document.getElementById('deployment-dns-token');
            if (tokField) tokField.value = '';
            const outPassField = document.getElementById('deployment-out-pass');
            if (outPassField) outPassField.value = '';
            hopEditor.clearSecrets();
            outLinkRecognizer.clear();
            generatedKeyRef = null;
            closeModal();
            showToast(savedNoRestart ? '已保存（无需重启服务）' : '节点配置已保存并下发', 'success');
            if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
            refreshAgents().catch(() => {});
        } catch (error) {
            submitting = false;
            render(false);
            const msg = String(error.message || '');
            if (/conflict|409/i.test(msg)) {
                setStatusBanner(`保存失败 (${msg})：当前有未完成的任务，或端口与已有节点冲突。`, 'error');
            } else {
                setStatusBanner(`保存失败：${msg}`, 'error');
            }
        } finally {
            submitting = false;
            if (remove && remove.isConnected) {
                const capable = agentCanLand(agent) || agentCanDeploy(agent);
                const busy = agentNodes.some(n => ['pending', 'assigned', 'running'].includes(n.status));
                if (typeof modalConfirm !== 'undefined' && modalConfirm) modalConfirm.disabled = !capable || busy;
                remove.disabled = !capable || busy || !getSelectedNode();
            }
        }
    }

    if (listenerModeEl) {
        listenerModeEl.onchange = () => {
            const val = listenerModeEl.value || 'standalone';
            if (val.startsWith('share::')) {
                const targetId = val.slice('share::'.length);
                const host = agentNodes.find(n => n.id === targetId);
                if (host) {
                    const hs = host.settings || {};
                    const hp = _normalizeNodeProto(host.protocol);
                    protocol.value = hp;
                    portInputEl.value = String(hs.listen_port || '');
                    if (!document.getElementById('deployment-server').value.trim() && hs.server) {
                        document.getElementById('deployment-server').value = hs.server;
                    }
                    lastSyncedSharedHostKey = '';
                    render(false);
                }
                return;
            }
            const current = getSelectedNode();
            if (!current && _findSharedPortPeers(agentNodes, protocol.value, portInputEl.value, null).length) {
                const meta = LANDING_PROTO_META[protocol.value] || LANDING_PROTO_META.reality;
                portInputEl.value = String(pickNextFreePort(meta.defaultPort));
                syncTlsOptions(protocol.value, protocol.value === 'reality' ? 'reality' : undefined);
                if (protocol.value === 'reality') document.getElementById('deployment-domain').value = 'www.amazon.com';
            }
            lastSyncedSharedHostKey = '';
            render(false);
        };
    }

    remove.onclick = () => submit(true);
    protocol.onchange = () => {
        const meta = LANDING_PROTO_META[protocol.value] || LANDING_PROTO_META.reality;
        if (!getSelectedNode()) {
            document.getElementById('deployment-port').value = String(pickNextFreePort(meta.defaultPort));
        }
        syncTlsOptions(protocol.value);
        generatedKeyRef = null;
        lastSyncedSharedHostKey = '';
        render(false);
    };
    portInputEl.oninput = () => render(false);
    tlsModeEl.onchange = () => render(false);
    if (camModeEl) camModeEl.onchange = () => render(false);
    if (camTplEl) camTplEl.onchange = () => render(false);
    outModeEl.onchange = () => render(false);
    document.getElementById('deployment-refresh').onclick = () => refresh().catch(error => { setStatusBanner(error.message, 'error'); });
    const firstProto = _normalizeNodeProto(getSelectedNode()?.protocol || protocol.value);
    syncTlsOptions(LANDING_PROTO_META[firstProto] ? firstProto : 'reality', getSelectedNode()?.settings?.tls_mode);
    render(true);
}

async function showAgentJobs(agent) {
    const release = await fetchAgentJson('/agents/runtime/release');
    const owned = (await fetchAgentJson('/agents/' + agent.id + '/deployment')).deployment;
    openModal('Agent 任务 · ' + agent.name,
        '<div class="field-row" style="align-items:center;">' +
        '<select id="agent-job-action"><option value="singbox.status">查询状态 (singbox.status)</option><option value="adopt_scan">扫描存量节点 (adopt_scan)</option></select>' +
        '<button type="button" class="btn btn-primary" id="agent-job-create">创建任务</button>' +
        '<button type="button" class="btn" id="agent-job-refresh">刷新</button></div>' +
        '<p id="agent-runtime-notice" class="hint"></p>' +
        '<p id="agent-job-notice" class="hint"></p>' +
        '<div id="agent-job-list"></div>', closeModal, { closeOnly: true });
    const target = document.getElementById('agent-job-list');
    const notice = document.getElementById('agent-job-notice');
    const create = document.getElementById('agent-job-create');
    const selector = document.getElementById('agent-job-action');
    if (agentCanManageRuntime(agent)) {
        const actions = [];
        if (!owned) {
            actions.push(['singbox.install', 'sing-box 安装 / 更新至 ' + release.version],
                ['singbox.start', 'sing-box 启动'], ['singbox.stop', 'sing-box 停止'],
                ['singbox.restart', 'sing-box 重启'], ['singbox.rollback', 'sing-box 回滚']);
        } else {
            document.getElementById('agent-runtime-notice').textContent = 'sing-box 已有托管部署，请通过“部署”应用或移除监听。';
        }
        if (agentCanLand(agent)) {
            actions.push(['caddy.install', 'Caddy 安装 / 更新至 ' + (release.caddy_version || 'pinned')],
                ['caddy.start', 'Caddy 启动'], ['caddy.stop', 'Caddy 停止'], ['caddy.restart', 'Caddy 重启'], ['caddy.rollback', 'Caddy 回滚']);
        }
        if (agentCanGost(agent)) {
            actions.push(['gost.install', 'go-gost 安装 / 更新至 ' + (release.gost_version || 'pinned')],
                ['gost.start', 'go-gost 启动'], ['gost.stop', 'go-gost 停止'], ['gost.restart', 'go-gost 重启'], ['gost.rollback', 'go-gost 回滚']);
        }
        for (const [value, label] of actions) {
            const option = document.createElement('option'); option.value = value; option.textContent = label; selector.append(option);
        }
    } else {
        document.getElementById('agent-runtime-notice').textContent = '运行环境管理需要升级 Agent，并在目标机器本地启用辅助服务。';
    }
    create.disabled = !agentCanRunJobs(agent);
    if (create.disabled) notice.textContent = '此 Agent 尚不支持任务或已撤销，请先升级 Agent。';
    async function refresh() {
        const { jobs } = await fetchAgentJson('/agents/' + agent.id + '/jobs');
        target.replaceChildren();
        if (!jobs.length) { target.textContent = '暂无任务'; return; }
        for (const job of jobs) {
            const row = document.createElement('div');
            const text = document.createElement('pre'); text.style.whiteSpace = 'pre-wrap';
            text.textContent = job.id + ' · ' + job.type + ' · ' + job.status + ' · 尝试 ' + job.attempts + '\n' +
                new Date(job.created_at * 1000).toLocaleString() +
                (job.result ? '\n' + JSON.stringify(job.result, null, 2) : '') + (job.error ? '\n⚠️ ' + _formatRuntimeError(job.error) : '');
            row.append(text);
            if (['pending', 'assigned', 'running'].includes(job.status)) {
                const cancel = document.createElement('button'); cancel.className = 'btn'; cancel.textContent = '取消任务';
                cancel.onclick = async () => {
                    cancel.disabled = true;
                    try {
                        await fetchAgentJson('/agents/' + agent.id + '/jobs/' + job.id + '/cancel', { method: 'POST' });
                        await refresh();
                    } catch (error) { notice.textContent = error.message; cancel.disabled = false; }
                };
                row.append(cancel);
            }
            target.append(row);
        }
    }
    create.onclick = async () => {
        const type = selector.value;
        if (!['singbox.status', 'adopt_scan'].includes(type) && !confirm('确认对该 Agent 的托管实例执行“' + selector.selectedOptions[0].textContent + '”？启停或重启可能中断连接。')) return;
        create.disabled = true;
        try {
            let payload = {};
            if (type === 'singbox.install') payload = { version: release.version };
            else if (type === 'caddy.install') payload = { version: release.caddy_version };
            else if (type === 'gost.install') payload = { version: release.gost_version };
            const key = agent.id + ':' + type + ':' + JSON.stringify(payload);
            let requestId = pendingAgentJobRequests.get(key);
            if (!requestId) {
                requestId = randomRequestId();
                pendingAgentJobRequests.set(key, requestId);
            }
            await fetchAgentJson('/agents/' + agent.id + '/jobs', { method: 'POST', body: JSON.stringify({
                request_id: requestId, type, payload, deployment_revision: null
            }) });
            pendingAgentJobRequests.delete(key);
            notice.textContent = '任务已创建；等待 Agent 下次同步。';
            await refresh().catch(error => { notice.textContent = '任务已创建，刷新列表失败：' + error.message; });
        } catch (error) { notice.textContent = error.message + '；可重试，同一请求不会重复创建任务。'; }
        finally { create.disabled = !agentCanRunJobs(agent); }
    };
    document.getElementById('agent-job-refresh').onclick = () => refresh().catch(error => { notice.textContent = error.message; });
    await refresh();
}
function agentRuntimeSummary(m) {
    const sb = m.singbox?.installed ? (m.singbox.running ? 'sb✓' : 'sb■') : 'sb-';
    const parts = [m.agent_version || '?', sb];
    if (m.caddy?.installed) parts.push(m.caddy.running ? 'caddy✓' : 'caddy■');
    if (m.gost?.installed) parts.push(m.gost.running ? 'gost✓' : 'gost■');
    return parts.join(' / ');
}

function parseForwardTargetsInput(raw) {
    return String(raw || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean).map(entry => {
        const idx = entry.indexOf('|');
        if (idx > 0) return { name: entry.slice(0, idx).trim(), addr: entry.slice(idx + 1).trim() };
        return { addr: entry };
    });
}

async function showAgentAdoptions(agent) {
    let pollTimer = null;
    let showIgnored = false;
    openModal('存量节点接管与清理 · ' + agent.name,
        '<div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:10px;">' +
        '<button type="button" class="btn btn-primary btn-sm" id="adopt-scan-trigger">🔍 一键特权扫描 (adopt_scan)</button>' +
        '<button type="button" class="btn btn-sm" id="adopt-scan-refresh">刷新扫描结果</button>' +
        '<label class="inline-check" style="margin-left:auto; font-size:0.85rem;"><input type="checkbox" id="adopt-show-ignored"> <span id="adopt-ignored-label">显示已忽略 (0)</span></label></div>' +
        '<p id="adopt-scan-status" class="hint"></p><div id="adopt-scan-list"></div>', () => {
            if (pollTimer) clearInterval(pollTimer);
            closeModal();
        }, { closeOnly: true });
    const statusEl = document.getElementById('adopt-scan-status');
    const listEl = document.getElementById('adopt-scan-list');
    const triggerBtn = document.getElementById('adopt-scan-trigger');
    const showIgnoredEl = document.getElementById('adopt-show-ignored');
    const ignoredLblEl = document.getElementById('adopt-ignored-label');
    triggerBtn.disabled = !agentCanRunJobs(agent);
    if (showIgnoredEl) {
        showIgnoredEl.onchange = () => {
            showIgnored = Boolean(showIgnoredEl.checked);
            loadAdoptions().catch(e => { statusEl.textContent = e.message; });
        };
    }

    function _isAuxiliaryItem(item) {
        return Boolean(item.is_auxiliary) || item.core === 'caddy' || ['caddy-site', 'dokodemo-door'].includes(item.protocol);
    }

    function _describeServiceImpact(allItems, serviceName) {
        if (!serviceName) return '';
        const shared = allItems.filter(x => x.service_name === serviceName);
        if (!shared.length) return '';
        return shared.map(x => `[${x.core}] ${x.tag || x.protocol} (${x.listen}:${x.listen_port})`).join('、');
    }

    async function loadAdoptions() {
        const { adoptions } = await fetchAgentJson('/agents/' + agent.id + '/adoptions');
        listEl.replaceChildren();
        const allItems = adoptions || [];
        if (!allItems.length) {
            if (ignoredLblEl) ignoredLblEl.textContent = '显示已忽略 (0)';
            listEl.textContent = '暂无接管扫描记录，点击上方「一键特权扫描」下发探测任务（扫描完成后将自动刷新）。';
            return;
        }
        const proxyItems = allItems.filter(item => !_isAuxiliaryItem(item));
        const auxItems = allItems.filter(item => _isAuxiliaryItem(item));
        const ignoredCount = proxyItems.filter(item => item.adopted_status === 'ignored').length;
        if (ignoredLblEl) ignoredLblEl.textContent = `显示已忽略 (${ignoredCount})`;

        const visibleProxies = proxyItems.filter(item => showIgnored || item.adopted_status !== 'ignored');
        if (!visibleProxies.length) {
            const emptyHint = document.createElement('div');
            emptyHint.className = 'hint';
            emptyHint.style.marginBottom = '10px';
            emptyHint.textContent = ignoredCount > 0
                ? `当前无待处理代理节点（已隐藏 ${ignoredCount} 条忽略记录，勾选右上角「显示已忽略」可恢复查看）。`
                : '当前主机未发现可接管的存量代理节点。';
            listEl.append(emptyHint);
        }

        for (const item of visibleProxies) {
            const card = document.createElement('div');
            card.className = 'sub-user-card';
            card.style.marginBottom = '10px';
            const head = document.createElement('div');
            head.className = 'sub-user-header';
            const title = document.createElement('strong');
            title.textContent = `[${item.core}] ${item.custom_name || item.tag || item.service_name} (${item.protocol} :${item.listen_port})`;
            const badge = document.createElement('span');
            const isAdopted = item.adopted_status === 'adopted';
            const isDisabled = item.adopted_status === 'disabled';
            const isIgnored = item.adopted_status === 'ignored';
            badge.className = `status-pill ${isAdopted ? 'is-online' : ((isDisabled || isIgnored) ? 'is-offline' : (item.has_credentials ? 'is-degraded' : 'is-offline'))}`;
            badge.textContent = isAdopted
                ? '已完全接管 · 已入订阅'
                : (isDisabled
                    ? '已停用原服务 · 端口已释放'
                    : (isIgnored
                        ? '已忽略（原服务未改动）'
                        : (item.has_credentials ? '已提取凭据 · 可一键接管' : (item.adoptable ? '待特权提取凭据' : '仅观测'))));
            head.append(title, badge);

            const meta = document.createElement('div');
            meta.className = 'hint';
            meta.textContent = `监听: ${item.listen}:${item.listen_port} · TLS: ${item.tls_mode || 'none'}` +
                (item.sni ? ` · SNI: ${item.sni}` : '') + (item.ws_path ? ` · WS: ${item.ws_path}` : '') +
                (item.service_name ? ` · 原服务: ${item.service_name}` : '');
            const cfg = document.createElement('div');
            cfg.className = 'hint';
            cfg.textContent = `原配置: ${item.config_path}`;

            const notes = [];
            if (item.matched_manual_name && !isAdopted) {
                const dupNote = document.createElement('div');
                dupNote.className = 'hint';
                dupNote.style.marginTop = '4px';
                dupNote.style.padding = '5px 8px';
                dupNote.style.borderRadius = '6px';
                dupNote.style.background = 'rgba(59, 130, 246, 0.12)';
                const reasonLbl = item.matched_manual_reason === 'credential' ? '凭据指纹匹配' : '地址端口匹配';
                dupNote.textContent = `🔗 已在手工节点中：「${item.matched_manual_name}」(${reasonLbl})。点击「接管并替换手工节点」将自动继承原名称、删除重复手工条目并同步迁移模板策略组引用；若保持原服务运行请直接点「忽略」。`;
                notes.push(dupNote);
            }
            if (item.has_xray_xver) {
                const xverNote = document.createElement('div');
                xverNote.className = 'hint';
                xverNote.style.marginTop = '4px';
                xverNote.textContent = '⚠️ 原 Xray Reality 启用了 xver PROXY Protocol；若宿主机回环 Caddy 强制 proxy_protocol fallback_policy=REJECT，迁入 sing-box 后回落探测可能被拒（可将 Caddy 改为 IGNORE 或直接停用旧服务并用 ProxyForge 新建节点）。';
                notes.push(xverNote);
            }

            const actions = document.createElement('div');
            actions.className = 'item-actions';
            actions.style.marginTop = '8px';
            actions.style.display = 'flex';
            actions.style.gap = '6px';
            actions.style.flexWrap = 'wrap';

            if (isAdopted || isDisabled) {
                const retBtn = document.createElement('button');
                retBtn.type = 'button';
                retBtn.className = isAdopted ? 'btn btn-danger btn-sm' : 'btn btn-primary btn-sm';
                retBtn.textContent = isAdopted ? '↩️ 归还原服务' : '↩️ 恢复原服务';
                retBtn.onclick = async () => {
                    const confirmText = isAdopted
                        ? `确认从 proxyforge-singbox 移除 ${item.tag || item.listen_port} 并恢复启动原服务 ${item.service_name || ''}？`
                        : `确认从备份恢复并重新启动原服务 ${item.service_name || ''}？`;
                    if (!confirm(confirmText)) return;
                    retBtn.disabled = true;
                    try {
                        await fetchAgentJson(`/agents/${agent.id}/adoptions/${encodeURIComponent(item.source_key)}/return`, {
                            method: 'POST',
                            body: JSON.stringify({ request_id: randomRequestId() }),
                        });
                        statusEl.textContent = isAdopted
                            ? '已下发归还原服务任务，代理服务重载后原服务将自动恢复运行。'
                            : '已下发恢复原服务任务，原服务将自动重新启动。';
                        await loadAdoptions();
                        if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
                        refreshAgents().catch(() => {});
                    } catch (e) {
                        statusEl.textContent = '操作失败：' + e.message;
                        retBtn.disabled = false;
                    }
                };
                actions.append(retBtn);
            } else {
                if (item.adoptable && !isIgnored) {
                    const adoptBtn = document.createElement('button');
                    adoptBtn.type = 'button';
                    adoptBtn.className = 'btn btn-primary btn-sm';
                    adoptBtn.disabled = !item.has_credentials;
                    adoptBtn.textContent = !item.has_credentials
                        ? '请先点击上方特权扫描提取凭据'
                        : (item.matched_manual_name ? '🚀 接管并替换手工节点' : '🚀 完全接管 (停用原服务并加入订阅)');
                    adoptBtn.onclick = async () => {
                        const replaceHint = item.matched_manual_name
                            ? `\n\n同时将自动删除重复的手工节点「${item.matched_manual_name}」并无缝迁移模板策略组引用。`
                            : '';
                        if (!confirm(`确认完全接管 [${item.core}] :${item.listen_port}？系统将备份并停止原服务 ${item.service_name || ''}，将其无缝并入 proxyforge-singbox 并直接加入客户端订阅。${replaceHint}`)) return;
                        adoptBtn.disabled = true;
                        try {
                            const defaultName = item.matched_manual_name || item.custom_name || `${agent.name}-${item.protocol}-${item.listen_port}`;
                            const finalName = (!item.matched_manual_name && typeof ProxyForgeRegions !== 'undefined' && agent.region)
                                ? ProxyForgeRegions.applyRegionPrefix(defaultName, agent.region)
                                : defaultName;
                            const res = await fetchAgentJson(`/agents/${agent.id}/adoptions/${encodeURIComponent(item.source_key)}/adopt`, {
                                method: 'POST',
                                body: JSON.stringify({
                                    request_id: randomRequestId(),
                                    custom_name: finalName,
                                    server_override: agent.public_ipv4 || agent.public_ipv6 || agent.observed_ip || '',
                                    replace_manual: Boolean(item.matched_manual_name),
                                }),
                            });
                            const rep = res && res.manual_replacement;
                            statusEl.textContent = (rep && rep.replaced)
                                ? `已下发完全接管任务，并已自动替换手工节点「${rep.old_name}」（同步迁移 ${rep.migrated_groups || 0} 个策略组引用）！`
                                : '已下发完全接管任务，该存量节点已加入受管清单与客户端订阅！';
                            await loadAdoptions();
                            if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
                            refreshAgents().catch(() => {});
                            if (rep && rep.replaced && typeof loadData === 'function') loadData();
                        } catch (e) {
                            statusEl.textContent = '接管失败：' + e.message;
                            adoptBtn.disabled = false;
                        }
                    };
                    actions.append(adoptBtn);
                }

                const ignBtn = document.createElement('button');
                ignBtn.type = 'button';
                ignBtn.className = 'btn btn-sm';
                ignBtn.textContent = isIgnored ? '👁️ 取消忽略' : '🙈 忽略';
                ignBtn.onclick = async () => {
                    ignBtn.disabled = true;
                    try {
                        await fetchAgentJson(`/agents/${agent.id}/adoptions/${encodeURIComponent(item.source_key)}/ignore`, {
                            method: 'POST',
                            body: JSON.stringify({ ignored: !isIgnored }),
                        });
                        statusEl.textContent = isIgnored ? '已恢复显示该扫描记录。' : '已忽略该记录（宿主机原服务未做任何改动）。';
                        await loadAdoptions();
                        refreshAgents().catch(() => {});
                    } catch (e) {
                        statusEl.textContent = '更新忽略状态失败：' + e.message;
                        ignBtn.disabled = false;
                    }
                };
                actions.append(ignBtn);

                if (item.service_name) {
                    const disBtn = document.createElement('button');
                    disBtn.type = 'button';
                    disBtn.className = 'btn btn-danger btn-sm';
                    disBtn.textContent = '🗑️ 停用并清理原服务';
                    disBtn.onclick = async () => {
                        const impact = _describeServiceImpact(allItems, item.service_name);
                        const warnMsg = `确认备份配置并停用禁用宿主机原服务「${item.service_name}」以释放端口？\n\n受该服务影响的监听端口：${impact || (':' + item.listen_port)}\n\n（系统将自动备份原配置至 /var/lib/proxyforge-runtime/adoptions/，后续可随时点「恢复原服务」回滚。）`;
                        if (!confirm(warnMsg)) return;
                        disBtn.disabled = true;
                        try {
                            await fetchAgentJson(`/agents/${agent.id}/adoptions/${encodeURIComponent(item.source_key)}/disable`, {
                                method: 'POST',
                                body: JSON.stringify({ request_id: randomRequestId() }),
                            });
                            statusEl.textContent = `已下发停用任务，原服务 ${item.service_name} 备份停用后将释放对应端口！`;
                            await loadAdoptions();
                            refreshAgents().catch(() => {});
                        } catch (e) {
                            statusEl.textContent = '停用原服务失败：' + e.message;
                            disBtn.disabled = false;
                        }
                    };
                    actions.append(disBtn);
                }
            }
            card.append(head, meta, cfg, ...notes);
            if (actions.childNodes && actions.childNodes.length) card.append(actions);
            else if (actions.children && actions.children.length) card.append(actions);
            listEl.append(card);
        }

        if (auxItems.length) {
            const auxDetails = document.createElement('details');
            auxDetails.style.marginTop = '12px';
            const auxSummary = document.createElement('summary');
            auxSummary.style.cursor = 'pointer';
            auxSummary.style.fontWeight = '600';
            auxSummary.textContent = `🛠️ 辅助 / 分流组件 (${auxItems.length}) — 无需单独接管（可按需停用释放端口）`;
            auxDetails.append(auxSummary);

            const auxWrap = document.createElement('div');
            auxWrap.style.marginTop = '8px';
            for (const item of auxItems) {
                const card = document.createElement('div');
                card.className = 'sub-user-card';
                card.style.marginBottom = '8px';
                const head = document.createElement('div');
                head.className = 'sub-user-header';
                const title = document.createElement('strong');
                title.textContent = `[${item.core}] ${item.tag || item.service_name} (${item.protocol} ${item.listen}:${item.listen_port})`;
                const badge = document.createElement('span');
                const isCaddy = item.core === 'caddy' || item.protocol === 'caddy-site';
                const isAuxDisabled = item.adopted_status === 'disabled';
                badge.className = `status-pill ${isAuxDisabled ? 'is-offline' : 'is-online'}`;
                badge.textContent = isAuxDisabled
                    ? '已停用原服务 · 端口已释放'
                    : (isCaddy ? '关联伪装站（运行中，无需单独接管）' : '分流入口组件（只读观测）');
                head.append(title, badge);

                const meta = document.createElement('div');
                meta.className = 'hint';
                meta.textContent = `真实监听: ${item.listen}:${item.listen_port} · TLS: ${item.tls_mode || 'none'}` +
                    (item.sni ? ` · SNI: ${item.sni}` : '') + (item.service_name ? ` · 原服务: ${item.service_name}` : '');
                const cfg = document.createElement('div');
                cfg.className = 'hint';
                cfg.textContent = `原配置: ${item.config_path}`;
                card.append(head, meta, cfg);
                if (item.service_name) {
                    const auxActions = document.createElement('div');
                    auxActions.className = 'item-actions';
                    auxActions.style.marginTop = '8px';
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = isAuxDisabled ? 'btn btn-primary btn-sm' : 'btn btn-danger btn-sm';
                    btn.textContent = isAuxDisabled ? '↩️ 恢复原服务' : '🗑️ 停用并释放端口';
                    btn.onclick = async () => {
                        const impact = _describeServiceImpact(allItems, item.service_name);
                        const q = isAuxDisabled
                            ? `确认从备份恢复并重启宿主机服务「${item.service_name}」？`
                            : `确认备份并停用宿主机辅助服务「${item.service_name}」？\n\n受影响监听：${impact || (':' + item.listen_port)}\n\n（后续可随时点「恢复原服务」回滚。）`;
                        if (!confirm(q)) return;
                        btn.disabled = true;
                        try {
                            const endpoint = isAuxDisabled ? 'return' : 'disable';
                            await fetchAgentJson(`/agents/${agent.id}/adoptions/${encodeURIComponent(item.source_key)}/${endpoint}`, {
                                method: 'POST',
                                body: JSON.stringify({ request_id: randomRequestId() }),
                            });
                            statusEl.textContent = isAuxDisabled
                                ? `已下发恢复任务，服务 ${item.service_name} 将重新启动。`
                                : `已下发停用任务，辅助服务 ${item.service_name} 停用后将释放对应端口。`;
                            await loadAdoptions();
                            refreshAgents().catch(() => {});
                        } catch (e) {
                            statusEl.textContent = '操作失败：' + e.message;
                            btn.disabled = false;
                        }
                    };
                    auxActions.append(btn);
                    card.append(auxActions);
                }
                auxWrap.append(card);
            }
            auxDetails.append(auxWrap);
            listEl.append(auxDetails);
        }
        if (typeof window !== 'undefined' && window.twemoji) {
            window.twemoji.parse(listEl, { folder: 'svg', ext: '.svg' });
        }
    }

    function startPollingForScan(jobId) {
        if (pollTimer) clearInterval(pollTimer);
        let rounds = 0;
        pollTimer = setInterval(async () => {
            rounds += 1;
            if (!listEl.isConnected || !modalOverlay.classList.contains('active') || rounds > 15) {
                clearInterval(pollTimer);
                pollTimer = null;
                return;
            }
            try {
                await loadAdoptions();
                const { jobs } = await fetchAgentJson('/agents/' + agent.id + '/jobs');
                const matched = (jobs || []).find(j => j.id === jobId);
                if (matched && ['success', 'failed', 'cancelled'].includes(matched.status)) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    await loadAdoptions();
                    if (matched.status === 'success') {
                        setTimeout(() => { loadAdoptions().catch(() => {}); }, 800);
                    }
                    statusEl.textContent = matched.status === 'success'
                        ? '✅ 存量节点特权扫描与凭据提取已完成！'
                        : `扫描任务结束：${matched.status} ${matched.error || ''}`;
                }
            } catch (_) {}
        }, 2000);
    }

    triggerBtn.onclick = async () => {
        try {
            triggerBtn.disabled = true;
            const created = await fetchAgentJson('/agents/' + agent.id + '/adopt-scan', {
                method: 'POST', body: JSON.stringify({ request_id: randomRequestId() })
            });
            statusEl.textContent = '⏳ 已下发存量特权扫描任务，正在自动轮询等待 Agent 上报结果…';
            startPollingForScan(created.id);
        } catch (error) {
            statusEl.textContent = '扫描下发失败：' + error.message;
        } finally {
            triggerBtn.disabled = !agentCanRunJobs(agent);
        }
    };
    document.getElementById('adopt-scan-refresh').onclick = () => loadAdoptions().catch(e => { statusEl.textContent = e.message; });
    await loadAdoptions();
}

async function showAgentForwards(agent) {
    let creating = false;
    let submitting = false;

    openModal('端口转发 · ' + agent.name,
        '<div id="fwd-list-view">' +
        '<div class="fwd-toolbar">' +
        '<div id="fwd-traffic-summary" class="hint">正在读取流量计数…</div>' +
        '<div class="fwd-toolbar-actions">' +
        '<button type="button" class="btn btn-sm" id="fwd-refresh-btn">刷新</button>' +
        '<button type="button" class="btn btn-primary btn-sm" id="fwd-new-btn">+ 新建转发</button>' +
        '</div></div>' +
        '<div id="fwd-notice" class="deploy-status-bar" hidden></div>' +
        '<div id="fwd-list" style="margin-top:10px;"></div>' +
        '</div>' +
        '<div id="fwd-create-view" hidden>' +
        '<div class="fwd-form-header"><span class="fwd-form-title">新建端口转发</span></div>' +
        '<div id="fwd-form-error" class="deploy-status-bar is-error" hidden style="margin-top:10px;"></div>' +
        '<div class="form-grid" style="margin-top:10px;">' +
        '<div class="form-group"><label for="fwd-name">规则名称</label><input id="fwd-name" placeholder="hk-relay-443"></div>' +
        '<div class="form-group"><label for="fwd-port">入口监听端口</label><input id="fwd-port" type="number" min="1" max="65535" value="10000"></div>' +
        '<div class="form-group"><label for="fwd-proto">协议</label><select id="fwd-proto"><option value="tcp+udp">tcp+udp</option><option value="tcp">tcp</option><option value="udp">udp</option></select></div>' +
        '<div class="form-group"><label for="fwd-pp">Proxy Protocol</label><select id="fwd-pp"><option value="0">0 (关闭)</option><option value="1">1 (v1)</option><option value="2">2 (v2)</option></select></div>' +
        '<div class="form-group full-width"><label for="fwd-targets">目标地址 (每行 host:port)</label><textarea id="fwd-targets" rows="3" placeholder="198.51.100.10:443"></textarea></div>' +
        '<div class="form-group full-width"><label class="inline-check"><input type="checkbox" id="fwd-rewrite-sub"> 订阅自动走此中转</label></div>' +
        '</div></div>',
        closeModal,
        { closeOnly: true }
    );

    const listView = document.getElementById('fwd-list-view');
    const createView = document.getElementById('fwd-create-view');
    const notice = document.getElementById('fwd-notice');
    const formError = document.getElementById('fwd-form-error');
    const newBtn = document.getElementById('fwd-new-btn');
    const capable = agentCanGost(agent);
    newBtn.disabled = !capable;

    function setNotice(msg, tone = 'neutral') {
        const text = String(msg || '').trim();
        notice.hidden = !text;
        notice.textContent = text;
        notice.className = 'deploy-status-bar' + (tone === 'error' ? ' is-error' : (tone === 'warn' ? ' is-warn' : ''));
    }

    function setFormError(msg) {
        const text = String(msg || '').trim();
        formError.hidden = !text;
        formError.textContent = text;
    }

    if (!capable) setNotice('当前 Agent 尚未启用 go-gost 能力，仅可查看现有规则。', 'warn');

    function showListView() {
        creating = false;
        setFormError('');
        listView.hidden = false;
        createView.hidden = true;
        if (typeof setModalFooter === 'function') {
            setModalFooter({ closeOnly: true, onConfirm: closeModal, onCancel: null });
        }
    }

    function showCreateView() {
        if (!capable) return;
        creating = true;
        setFormError('');
        listView.hidden = true;
        createView.hidden = false;
        if (typeof setModalFooter === 'function') {
            setModalFooter({
                closeOnly: false,
                cancelText: '返回列表',
                confirmText: '确认创建',
                confirmDisabled: submitting,
                onCancel: showListView,
                onConfirm: submitCreateForward,
            });
        }
        document.getElementById('fwd-name')?.focus();
    }

    async function loadAll() {
        const [traffic, fwdRes] = await Promise.all([
            fetchAgentJson('/agents/' + agent.id + '/traffic'),
            fetchAgentJson('/agents/' + agent.id + '/forwards'),
        ]);
        document.getElementById('fwd-traffic-summary').textContent =
            `本机累计流量 ${formatAgentBytes(traffic.total_bytes)} (↑${formatAgentBytes(traffic.tx_bytes)} / ↓${formatAgentBytes(traffic.rx_bytes)})`;

        const fwdList = document.getElementById('fwd-list');
        fwdList.replaceChildren();
        const forwards = fwdRes.forwards || [];
        if (!forwards.length) {
            const empty = document.createElement('div');
            empty.className = 'empty-state';
            empty.textContent = '暂无端口转发规则';
            fwdList.append(empty);
            return;
        }
        for (const f of forwards) {
            const card = document.createElement('div'); card.className = 'sub-user-card'; card.style.marginBottom = '8px';
            const head = document.createElement('div'); head.className = 'sub-user-header';
            const title = document.createElement('strong');
            title.textContent = `${f.name} · :${f.listen_port} (${f.protocol})`;
            const pillGroup = document.createElement('div'); pillGroup.style.display = 'flex'; pillGroup.style.gap = '6px'; pillGroup.style.alignItems = 'center';
            if (f.rewrite_subscription) {
                const subPill = document.createElement('span'); subPill.className = 'status-pill is-online';
                subPill.textContent = '订阅中转';
                pillGroup.append(subPill);
            }
            const pill = document.createElement('span'); pill.className = `status-pill ${f.enabled ? 'is-online' : 'is-offline'}`;
            pill.textContent = f.enabled ? '运行中' : '已停用';
            pillGroup.append(pill);
            head.append(title, pillGroup);
            const info = document.createElement('div'); info.className = 'hint';
            const targetText = (f.targets || []).map(t => t.addr).join(', ') || (f.exit_group_id ? 'BestExit:' + f.exit_group_id : f.chain_id || '-');
            info.textContent = `目标: ${targetText} · 流量: ${formatAgentBytes(f.total_bytes)} (↓${formatAgentBytes(f.rx_bytes)} / ↑${formatAgentBytes(f.tx_bytes)})` +
                (f.job_status ? ` · ${f.job_status}` : '');
            const acts = document.createElement('div'); acts.className = 'item-actions';
            const subBtn = document.createElement('button'); subBtn.type = 'button';
            subBtn.className = `btn btn-sm ${f.rewrite_subscription ? 'btn-primary' : ''}`.trim();
            subBtn.textContent = f.rewrite_subscription ? '订阅走此中转 ✓' : '订阅走此中转';
            subBtn.onclick = async () => {
                try {
                    await fetchAgentJson('/agents/' + agent.id + '/forwards/' + f.id + '/subscription', {
                        method: 'POST', body: JSON.stringify({ rewrite_subscription: !f.rewrite_subscription })
                    });
                    await loadAll();
                    refreshAgents().catch(() => {});
                } catch (e) { setNotice(e.message, 'error'); }
            };
            const toggleBtn = document.createElement('button'); toggleBtn.type = 'button'; toggleBtn.className = 'btn btn-sm';
            toggleBtn.textContent = f.enabled ? '停用' : '启用';
            toggleBtn.onclick = async () => {
                try {
                    await fetchAgentJson('/agents/' + agent.id + '/forwards/' + f.id + '/toggle', {
                        method: 'POST', body: JSON.stringify({ request_id: randomRequestId(), enabled: !f.enabled })
                    });
                    await loadAll();
                    refreshAgents().catch(() => {});
                } catch (e) { setNotice(e.message, 'error'); }
            };
            const delBtn = document.createElement('button'); delBtn.type = 'button'; delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = '删除';
            delBtn.onclick = async () => {
                if (!confirm(`确认删除转发规则 ${f.name}？`)) return;
                try {
                    await fetchAgentJson('/agents/' + agent.id + '/forwards/' + f.id + '?request_id=' + encodeURIComponent(randomRequestId()), { method: 'DELETE' });
                    await loadAll();
                    refreshAgents().catch(() => {});
                } catch (e) { setNotice(e.message, 'error'); }
            };
            acts.append(subBtn, toggleBtn, delBtn);
            card.append(head, info, acts);
            fwdList.append(card);
        }
    }

    async function submitCreateForward() {
        if (!creating || submitting) return;
        const nameVal = document.getElementById('fwd-name').value.trim();
        const portVal = Math.round(Number(document.getElementById('fwd-port').value));
        const targets = parseForwardTargetsInput(document.getElementById('fwd-targets').value);
        if (!nameVal) { setFormError('请填写规则名称'); return; }
        if (!Number.isInteger(portVal) || portVal < 1 || portVal > 65535) { setFormError('监听端口必须为 1–65535 之间的整数'); return; }
        if (!targets.length) { setFormError('请填写至少一个目标地址 (host:port)'); return; }

        submitting = true;
        if (typeof modalConfirm !== 'undefined' && modalConfirm) modalConfirm.disabled = true;
        try {
            const body = {
                request_id: randomRequestId(),
                name: nameVal,
                listen_port: portVal,
                protocol: document.getElementById('fwd-proto').value,
                mode: 'direct',
                proxy_protocol: Number(document.getElementById('fwd-pp').value) || 0,
                rewrite_subscription: Boolean(document.getElementById('fwd-rewrite-sub')?.checked),
                targets,
            };
            await fetchAgentJson('/agents/' + agent.id + '/forwards', { method: 'POST', body: JSON.stringify(body) });
            document.getElementById('fwd-name').value = '';
            document.getElementById('fwd-targets').value = '';
            const rw = document.getElementById('fwd-rewrite-sub');
            if (rw) rw.checked = false;
            showListView();
            showToast('转发规则已创建并下发', 'success');
            await loadAll();
            refreshAgents().catch(() => {});
        } catch (e) {
            setFormError('创建转发失败：' + e.message);
        } finally {
            submitting = false;
            if (creating && typeof modalConfirm !== 'undefined' && modalConfirm) modalConfirm.disabled = false;
        }
    }

    newBtn.onclick = showCreateView;
    document.getElementById('fwd-refresh-btn').onclick = () => loadAll().catch(e => setNotice(e.message, 'error'));
    await loadAll();
}

function agentStatusLabel(agent) {
    const labels = { online: '在线', degraded: '心跳延迟', offline: '离线', never_seen: '等待首次心跳', revoked: '已撤销' };
    return (labels[agent.status] || '未知') + (!agent.compatible ? ' · 协议不兼容' : '') +
        (!agent.metadata.supported ? ' · 未支持的系统' : '');
}

function _iconOrText(name, fallbackText, size = 15) {
    if (typeof ProxyForgeIcons !== 'undefined' && ProxyForgeIcons && typeof ProxyForgeIcons.el === 'function') {
        try {
            const node = ProxyForgeIcons.el(name, size);
            if (node) return node;
        } catch (_) {}
    }
    const span = document.createElement('span');
    span.textContent = fallbackText;
    return span;
}

function _formatOsSubtitle(agent) {
    const m = agent.metadata || {};
    const osRaw = String(m.os || 'linux');
    const osLower = osRaw.toLowerCase();
    const osMap = {
        debian: 'Debian',
        ubuntu: 'Ubuntu',
        alpine: 'Alpine',
        centos: 'CentOS',
        rocky: 'Rocky',
        almalinux: 'AlmaLinux',
        fedora: 'Fedora',
        arch: 'Arch',
    };
    const osLabel = osMap[osLower] || (osLower === 'linux' ? 'Linux' : osRaw);
    const osFull = m.os_version ? `${osLabel} ${m.os_version}` : osLabel;
    const primaryIp = agent.public_ipv4 || agent.observed_ip || m.hostname || '';
    return [osFull, m.arch || '', primaryIp, agent.public_ipv6 ? 'IPv6' : '']
        .filter(Boolean)
        .join(' · ');
}

function _closeAllAgentMenus(exceptWrap = null) {
    if (typeof document === 'undefined' || typeof document.querySelectorAll !== 'function') return;
    document.querySelectorAll('.pf-menu-wrap').forEach(wrap => {
        if (exceptWrap && wrap === exceptWrap) return;
        const menu = wrap.querySelector('.pf-dropdown-menu');
        const btn = wrap.querySelector('.pf-icon-btn');
        if (menu) menu.hidden = true;
        if (btn) btn.setAttribute('aria-expanded', 'false');
    });
}

function _formatRuntimeError(code) {
    if (!code) return '';
    const map = {
        acme_certbot_missing: '宿主机未安装 certbot（ACME 证书签发需先安装 certbot，如 apt install -y certbot）',
        acme_dns_plugin_missing: '宿主机缺少 certbot DNS 插件（如 python3-certbot-dns-cloudflare）',
        acme_port80_in_use: '80 端口被占用，ACME HTTP-01 无法绑定（请停用占用 80 的 nginx/caddy，或改用 DNS-01）',
        acme_dns_mismatch: '域名 DNS A/AAAA 解析未指向本机公网 IP',
        acme_failed: 'ACME 证书申请或校验失败（请检查域名解析、80 端口放行或 DNS API Token）',
        port_conflict: '监听端口冲突（与本机其他服务或已部署节点冲突）',
        caddy_failed: '本机 Caddy 回环伪装站配置或启动失败',
        config_check_failed: '内核配置校验失败（sing-box / caddy check 未通过）',
        health_check_failed: '服务启动后健康检查失败（常见原因：监听端口被宿主机其他进程占用）',
        download_failed: '内核二进制下载或 SHA256 校验失败（请检查 VPS 访问 GitHub 网络连通性）',
        runtime_unavailable: '本地特权辅助服务 (proxyforge-runtime.socket) 不可用',
        runtime_cancelled: '任务超时或租约已取消',
        rollback_failed: '回滚失败，请登录宿主机排查 /var/lib/proxyforge-runtime',
        lease_expired: '任务执行租约过期',
    };
    return map[code] ? `${code} — ${map[code]}` : String(code);
}

function _formatCardProto(proto) {
    const p = String(proto || '').toLowerCase();
    if (p === 'vless-reality' || p === 'reality') return 'REALITY';
    if (p === 'hysteria2') return 'HY2';
    if (p === 'ss2022') return 'SS2022';
    if (p === 'shadowsocks') return 'SS';
    if (p === 'anytls') return 'ANYTLS';
    if (p === 'trojan') return 'TROJAN';
    if (p === 'vless') return 'VLESS';
    if (p === 'chain') return 'CHAIN';
    return (proto || 'NODE').toUpperCase();
}

function _nodeRoleBadge(n) {
    if (n.status === 'failed' || n.status === 'cancelled') {
        return { text: '部署失败', cls: 'is-err' };
    }
    if (['pending', 'assigned', 'running'].includes(n.status)) {
        return { text: '部署中', cls: 'is-warn' };
    }
    if (n.kind === 'adopted') return { text: '已接管', cls: 'is-amber' };
    if (n.kind === 'ss2022_internal') return { text: '内部落地', cls: 'is-cyan' };
    if (n.kind === 'chain') {
        return { text: n.landing_agent_name ? `链路→${n.landing_agent_name}` : '单跳链路', cls: 'is-purple' };
    }
    if (n.outbound_mode === 'chain') return { text: `多跳×${n.hop_count || 1}`, cls: 'is-purple' };
    if (n.outbound_mode === 'socks5' || n.outbound_mode === 'ss') return { text: '外部出站', cls: 'is-cyan' };
    return { text: '直连', cls: 'is-slate' };
}

async function refreshAgents() {
    const target = document.getElementById('agent-list');
    try {
        const [agentsRes, overviewRes] = await Promise.all([
            fetchAuth('/agents'),
            fetchAuth('/agents/deployments/overview').catch(() => null),
        ]);
        const agentsPayload = await agentsRes.json();
        const agents = agentsPayload.agents || [];
        const latestBundleSha = String(agentsPayload.latest_bundle_sha256 || '');
        const overviewData = overviewRes && overviewRes.ok !== false ? await overviewRes.json().catch(() => ({})) : {};
        const overviewByAgent = overviewData.agents || {};

        target.replaceChildren();
        if (!agents.length) {
            const emptyState = document.createElement('div');
            emptyState.className = 'manual-nodes-empty-bar';
            emptyState.textContent = '尚无托管服务器，点击右上角「添加服务器」获取安装命令。';
            target.append(emptyState);
            return;
        }

        const grid = document.createElement('div');
        grid.className = 'komari-agent-grid';

        for (const agent of agents) {
            const m = agent.metadata || {};
            const ov = overviewByAgent[agent.id] || {
                nodes: [],
                forwards: [],
                adoptions: { discovered: 0, adopted: 0, disabled: 0, ignored: 0, auxiliary: 0 },
                active_job: null,
                last_failed_job: null,
            };
            const agentNodes = ov.nodes || [];
            const agentForwards = ov.forwards || [];
            const adoptCounts = ov.adoptions || {};

            const card = document.createElement('article');
            card.className = 'komari-agent-card';

            // Header row: single flag + cleaned name + status dot + ⋯ menu
            const head = document.createElement('div');
            head.className = 'komari-card-head';
            const headLeft = document.createElement('div');
            headLeft.className = 'komari-head-left';

            let flagChar = '';
            if (typeof ProxyForgeRegions !== 'undefined') {
                const reg = ProxyForgeRegions.matchRegion(agent.region || agent.name);
                if (reg && reg.flag) flagChar = reg.flag;
            }
            const flagEl = document.createElement('span');
            flagEl.className = 'komari-flag';
            if (flagChar) {
                flagEl.textContent = flagChar;
            } else {
                flagEl.append(_iconOrText('globe', '🌐', 15));
            }

            const titleEl = document.createElement('span');
            titleEl.className = 'komari-card-title';
            const strippedName = (typeof ProxyForgeRegions !== 'undefined' && typeof ProxyForgeRegions.stripLeadingFlag === 'function')
                ? ProxyForgeRegions.stripLeadingFlag(agent.name)
                : '';
            titleEl.textContent = strippedName || agent.name;

            headLeft.append(flagEl, titleEl);

            const headRight = document.createElement('div');
            headRight.className = 'komari-head-right';
            const dot = document.createElement('span');
            dot.className = `komari-status-dot is-${agent.status || 'offline'}`;
            dot.title = agentStatusLabel(agent);

            const menuWrap = document.createElement('div');
            menuWrap.className = 'pf-menu-wrap';
            const menuBtn = document.createElement('button');
            menuBtn.type = 'button';
            menuBtn.className = 'pf-icon-btn';
            menuBtn.title = '更多操作';
            menuBtn.setAttribute('aria-label', '更多操作');
            menuBtn.setAttribute('aria-expanded', 'false');
            menuBtn.append(_iconOrText('more', '⋯', 16));

            const menu = document.createElement('div');
            menu.className = 'pf-dropdown-menu';
            menu.hidden = true;
            for (const item of [
                { label: '任务日志', action: 'jobs', icon: 'history' },
                { label: '编辑服务器', action: 'edit', icon: 'edit' },
                { label: '查看详情', action: 'details', icon: 'eye' },
                { divider: true },
                { label: '撤销凭据', action: 'revoke', icon: 'key' },
                { label: '移除服务器', action: 'remove', icon: 'trash', danger: true },
            ]) {
                if (item.divider) {
                    const div = document.createElement('div');
                    div.className = 'pf-menu-divider';
                    menu.append(div);
                    continue;
                }
                const mBtn = document.createElement('button');
                mBtn.type = 'button';
                mBtn.className = `pf-menu-item${item.danger ? ' is-danger' : ''}`;
                mBtn.append(_iconOrText(item.icon, '', 14));
                const lbl = document.createElement('span');
                lbl.textContent = item.label;
                mBtn.append(lbl);
                mBtn.onclick = ev => {
                    ev.stopPropagation();
                    _closeAllAgentMenus();
                    agentAction(agent, item.action).catch(error => showToast(error.message, 'error'));
                };
                menu.append(mBtn);
            }
            menuBtn.onclick = ev => {
                ev.stopPropagation();
                const willOpen = menu.hidden;
                _closeAllAgentMenus(menuWrap);
                menu.hidden = !willOpen;
                menuBtn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
            };
            menuWrap.append(menuBtn, menu);

            headRight.append(dot, menuWrap);
            head.append(headLeft, headRight);
            card.append(head);

            // Subtitle: OS Version · Arch · IP
            const sub = document.createElement('div');
            sub.className = 'komari-card-sub';
            sub.textContent = _formatOsSubtitle(agent);
            card.append(sub);

            // Managed cores strip
            const coreStrip = document.createElement('div');
            coreStrip.className = 'komari-core-strip';
            const sbPill = document.createElement('span');
            sbPill.className = `komari-core-pill ${m.singbox?.running ? 'is-running' : ''}`;
            sbPill.textContent = m.singbox?.installed ? (m.singbox.running ? 'sing-box 运行中' : 'sing-box 已停') : 'sing-box 未装';
            coreStrip.append(sbPill);
            if (m.caddy?.installed) {
                const cPill = document.createElement('span');
                cPill.className = `komari-core-pill ${m.caddy.running ? 'is-running' : ''}`;
                cPill.textContent = m.caddy.running ? 'caddy 运行中' : 'caddy 已停';
                coreStrip.append(cPill);
            }
            if (m.gost?.installed) {
                const gPill = document.createElement('span');
                gPill.className = `komari-core-pill ${m.gost.running ? 'is-running' : ''}`;
                gPill.textContent = m.gost.running ? 'go-gost 运行中' : 'go-gost 已停';
                coreStrip.append(gPill);
            }
            if (agent.status !== 'revoked' && agent.status !== 'never_seen') {
                if (!m.self_upgrade_protocol_version) {
                    const upBtn = document.createElement('button');
                    upBtn.type = 'button';
                    upBtn.className = 'komari-core-pill';
                    upBtn.style.cursor = 'pointer';
                    upBtn.textContent = '引导升级 →';
                    upBtn.onclick = async () => {
                        try {
                            const info = await fetchAgentJson('/agents/install-command');
                            if (!info.available || !info.quick_install_url) {
                                showToast(info.message || '请先配置 PROXYFORGE_PUBLIC_URL', 'error');
                                return;
                            }
                            const cmd = buildQuickInstallCommand(info, { mode: 'upgrade', runtime: true });
                            openModal('引导升级 · ' + agent.name,
                                '<div class="form-group"><label for="upgrade-bootstrap-cmd">在目标 VPS 终端执行一次（之后将自动静默升级）</label>' +
                                '<textarea id="upgrade-bootstrap-cmd" class="quick-cmd-preview" readonly rows="3"></textarea></div>',
                                () => {
                                    const field = document.getElementById('upgrade-bootstrap-cmd');
                                    if (field) copyAgentCommand(field);
                                },
                                { confirmText: '复制命令', cancelText: '关闭' }
                            );
                            const field = document.getElementById('upgrade-bootstrap-cmd');
                            if (field) field.value = cmd;
                        } catch (err) {
                            showToast(err.message, 'error');
                        }
                    };
                    coreStrip.append(upBtn);
                } else if (latestBundleSha && m.bundle_sha256 && m.bundle_sha256 !== latestBundleSha) {
                    const syncPill = document.createElement('span');
                    syncPill.className = 'komari-core-pill';
                    syncPill.textContent = '待静默升级';
                    coreStrip.append(syncPill);
                }
            }
            card.append(coreStrip);

            // Prominent per-machine nodes & forwards inventory panel
            const nodesPanel = document.createElement('div');
            nodesPanel.className = 'komari-nodes-panel';

            const panelHead = document.createElement('div');
            panelHead.className = 'komari-nodes-head';
            const panelTitle = document.createElement('span');
            panelTitle.className = 'komari-nodes-title';
            panelTitle.textContent = agentForwards.length
                ? `本机节点 (${agentNodes.length}) · 转发 (${agentForwards.length})`
                : `本机节点 (${agentNodes.length})`;
            const quickAdd = document.createElement('button');
            quickAdd.type = 'button';
            quickAdd.className = 'komari-nodes-add-btn';
            quickAdd.textContent = '+ 新建';
            quickAdd.onclick = () => agentAction(agent, 'deployment', { nodeId: '__new__' }).catch(error => showToast(error.message, 'error'));
            panelHead.append(panelTitle, quickAdd);
            nodesPanel.append(panelHead);

            if (ov.active_job) {
                const jobBar = document.createElement('button');
                jobBar.type = 'button';
                jobBar.className = 'komari-job-banner is-busy';
                jobBar.textContent = `⏳ 正在执行任务: ${ov.active_job.type} (${ov.active_job.status}) · 点击查看`;
                jobBar.onclick = () => agentAction(agent, 'jobs').catch(error => showToast(error.message, 'error'));
                nodesPanel.append(jobBar);
            } else if (ov.last_failed_job) {
                const jobBar = document.createElement('button');
                jobBar.type = 'button';
                jobBar.className = 'komari-job-banner is-err';
                jobBar.textContent = `⚠️ 最近任务失败: ${ov.last_failed_job.type} (${_formatRuntimeError(ov.last_failed_job.error) || 'failed'}) · 点击排查`;
                jobBar.onclick = () => agentAction(agent, 'jobs').catch(error => showToast(error.message, 'error'));
                nodesPanel.append(jobBar);
            }

            if (agentNodes.length || agentForwards.length) {
                const list = document.createElement('div');
                list.className = 'komari-nodes-list';
                for (const n of agentNodes) {
                    const row = document.createElement('button');
                    row.type = 'button';
                    row.className = 'komari-node-row';
                    const roleInfo = _nodeRoleBadge(n);
                    row.title = `${n.name} · ${_formatCardProto(n.protocol)} :${n.port}` +
                        (n.sni ? ` · SNI ${n.sni}` : '') +
                        (n.error ? ` · 错误: ${n.error}` : '');

                    const left = document.createElement('span');
                    left.className = 'komari-node-row-left';
                    const nDot = document.createElement('span');
                    const dotState = (n.status === 'failed' || n.status === 'cancelled')
                        ? 'is-err'
                        : (['pending', 'assigned', 'running'].includes(n.status) ? 'is-busy' : 'is-ok');
                    nDot.className = `komari-node-dot ${dotState}`;
                    const nName = document.createElement('span');
                    nName.className = 'komari-node-name';
                    nName.textContent = n.name;
                    left.append(nDot, nName);

                    const right = document.createElement('span');
                    right.className = 'komari-node-row-right';
                    const protoEl = document.createElement('span');
                    protoEl.className = 'komari-node-proto';
                    protoEl.textContent = `${_formatCardProto(n.protocol)} :${n.port}`;
                    const badgeEl = document.createElement('span');
                    badgeEl.className = `komari-node-badge ${roleInfo.cls}`;
                    badgeEl.textContent = roleInfo.text;
                    right.append(protoEl, badgeEl);

                    row.append(left, right);
                    row.onclick = () => {
                        if (n.kind === 'adopted') {
                            agentAction(agent, 'adoptions').catch(error => showToast(error.message, 'error'));
                        } else if (n.kind === 'chain') {
                            agentAction(agent, 'chain').catch(error => showToast(error.message, 'error'));
                        } else {
                            agentAction(agent, 'deployment', { nodeId: n.id }).catch(error => showToast(error.message, 'error'));
                        }
                    };
                    list.append(row);
                }
                for (const fw of agentForwards) {
                    const row = document.createElement('button');
                    row.type = 'button';
                    row.className = 'komari-node-row';
                    row.title = `go-gost 转发 ${fw.name} (${fw.protocol} :${fw.listen_port} · ${fw.mode})`;
                    const left = document.createElement('span');
                    left.className = 'komari-node-row-left';
                    const nDot = document.createElement('span');
                    nDot.className = `komari-node-dot ${fw.enabled ? 'is-ok' : 'is-off'}`;
                    const nName = document.createElement('span');
                    nName.className = 'komari-node-name';
                    nName.textContent = fw.name;
                    left.append(nDot, nName);

                    const right = document.createElement('span');
                    right.className = 'komari-node-row-right';
                    const protoEl = document.createElement('span');
                    protoEl.className = 'komari-node-proto';
                    protoEl.textContent = `${String(fw.protocol || 'tcp').toUpperCase()} :${fw.listen_port}`;
                    const badgeEl = document.createElement('span');
                    badgeEl.className = `komari-node-badge ${fw.enabled ? 'is-cyan' : 'is-slate'}`;
                    badgeEl.textContent = fw.enabled ? `转发·${fw.mode}` : '已停用';
                    right.append(protoEl, badgeEl);

                    row.append(left, right);
                    row.onclick = () => agentAction(agent, 'forwards').catch(error => showToast(error.message, 'error'));
                    list.append(row);
                }
                nodesPanel.append(list);
            } else {
                const empty = document.createElement('div');
                empty.className = 'komari-nodes-empty';
                empty.textContent = '暂无托管节点';
                nodesPanel.append(empty);
            }

            const scanParts = [];
            if (adoptCounts.discovered > 0) scanParts.push(`${adoptCounts.discovered} 待接管`);
            if (adoptCounts.disabled > 0) scanParts.push(`${adoptCounts.disabled} 已停用原服务`);
            if (adoptCounts.auxiliary > 0) scanParts.push(`${adoptCounts.auxiliary} 辅助组件`);
            if (adoptCounts.ignored > 0) scanParts.push(`${adoptCounts.ignored} 已忽略`);
            if (scanParts.length) {
                const scanFooter = document.createElement('button');
                scanFooter.type = 'button';
                scanFooter.className = 'komari-scan-summary';
                scanFooter.textContent = `宿主机存量: ${scanParts.join(' · ')} →`;
                scanFooter.onclick = () => agentAction(agent, 'adoptions').catch(error => showToast(error.message, 'error'));
                nodesPanel.append(scanFooter);
            }
            card.append(nodesPanel);

            // Tags row (only role + custom tags)
            const pillList = [];
            if (agent.role && agent.role !== 'unassigned') {
                pillList.push({ text: agent.role, cls: 'is-purple' });
            }
            for (const t of (agent.tags || [])) {
                pillList.push({ text: t, cls: 'is-cyan' });
            }
            if (pillList.length) {
                const tagsRow = document.createElement('div');
                tagsRow.className = 'komari-tags-row';
                pillList.forEach((p, idx) => {
                    const el = document.createElement('span');
                    const cycle = ['is-purple', 'is-cyan', 'is-slate'];
                    el.className = `komari-tag-pill ${p.cls || cycle[idx % cycle.length]}`;
                    el.textContent = p.text;
                    tagsRow.append(el);
                });
                card.append(tagsRow);
            }

            // 3 core bottom action buttons
            const actionsRow = document.createElement('div');
            actionsRow.className = 'komari-card-actions';
            for (const [label, action, extraCls] of [
                ['部署', 'deployment', 'komari-btn-primary'],
                ['转发', 'forwards', ''],
                ['接管', 'adoptions', ''],
            ]) {
                const button = document.createElement('button');
                button.type = 'button';
                button.textContent = label;
                button.className = `komari-btn ${extraCls}`.trim();
                button.onclick = () => agentAction(agent, action).catch(error => showToast(error.message, 'error'));
                actionsRow.append(button);
            }
            card.append(actionsRow);
            grid.append(card);
        }
        target.append(grid);
        if (typeof window !== 'undefined' && window.twemoji) {
            window.twemoji.parse(grid, { folder: 'svg', ext: '.svg' });
        }
    } catch (error) { target.textContent = '读取 Agent 失败：' + error.message; }
}

async function agentAction(agent, action, opts = {}) {
    if (action === 'chain' || action === 'deployment') {
        await showAgentDeployment(await (await fetchAuth('/agents/' + agent.id)).json(), opts?.nodeId ?? null);
        return;
    }
    if (action === 'forwards') {
        await showAgentForwards(await (await fetchAuth('/agents/' + agent.id)).json());
        return;
    }
    if (action === 'adoptions') {
        await showAgentAdoptions(await (await fetchAuth('/agents/' + agent.id)).json());
        return;
    }
    if (action === 'jobs') {
        await showAgentJobs(await (await fetchAuth('/agents/' + agent.id)).json());
        return;
    }
    if (action === 'details') {
        const current = await (await fetchAuth('/agents/' + agent.id)).json();
        openModal('Agent 详情 · ' + agent.name, '<pre id="agent-detail" style="white-space:pre-wrap"></pre>', closeModal, { closeOnly: true });
        document.getElementById('agent-detail').textContent = JSON.stringify(current, null, 2);
        return;
    }
    if (action === 'edit') {
        openModal('编辑 Agent · ' + agent.name,
            _agentRegionPickerHtml('agent-edit-region', agent.region || agent.name, '地区 / 国旗') +
            '<div class="form-grid">' +
            '<div class="form-group"><label>名称</label><input id="agent-name"></div>' +
            '<div class="form-group"><label>角色</label><select id="agent-role"><option>unassigned</option><option>node</option><option>landing</option><option>both</option></select></div>' +
            '<div class="form-group full-width"><label>标签（逗号分隔）</label><input id="agent-tags" placeholder="如 CN2 GIA, 家宽"></div>' +
            '</div>', async () => {
                try {
                    const regionInput = (document.getElementById('agent-edit-region')?.value || '').trim();
                    let regionCode = '';
                    if (typeof ProxyForgeRegions !== 'undefined' && regionInput) {
                        const matched = ProxyForgeRegions.matchRegion(regionInput);
                        regionCode = matched ? matched.code : regionInput.slice(0, 32);
                    } else {
                        regionCode = regionInput.slice(0, 32);
                    }
                    await fetchAuth('/agents/' + agent.id, { method: 'PATCH', body: JSON.stringify({
                        name: document.getElementById('agent-name').value,
                        role: document.getElementById('agent-role').value,
                        tags: document.getElementById('agent-tags').value.split(',').map(s => s.trim()).filter(Boolean),
                        region: regionCode,
                    }) });
                    closeModal(); await refreshAgents();
                } catch (error) { showToast(error.message, 'error'); }
            });
        document.getElementById('agent-name').value = agent.name;
        document.getElementById('agent-role').value = agent.role;
        document.getElementById('agent-tags').value = (agent.tags || []).join(', ');
        if (typeof ProxyForgeRegions !== 'undefined') ProxyForgeRegions.bindRegionPicker('agent-edit-region');
        return;
    }
    if (!confirm(action === 'remove' ? '移除会撤销凭据并删除控制台记录。远端服务不会卸载。继续？' :
        '撤销后 Agent 将停止同步；不会停止远端 sing-box。继续？')) return;
    await fetchAuth('/agents/' + agent.id + (action === 'revoke' ? '/revoke' : ''),
        { method: action === 'revoke' ? 'POST' : 'DELETE' });
    await refreshAgents();
}

async function copyAgentCommand(field) {
    try {
        await navigator.clipboard.writeText(field.value);
        showToast('安装命令已复制，请在目标 VPS 终端执行', 'success');
    } catch (_) {
        if (field.isConnected && modalOverlay.classList.contains('active')) {
            field.focus(); field.select();
            showToast('无法访问剪贴板，已选中命令，请手动复制', 'error');
        }
    }
}

function safeShellArg(value) {
    const clean = String(value ?? '').replace(/[\r\n\0]/g, '').trim();
    if (!clean) return "''";
    if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(clean)) return clean;
    return "'" + clean.replace(/'/g, "'\\''") + "'";
}

function buildQuickInstallCommand(info, opts = {}) {
    if (!info || !info.quick_install_url || !info.controller_url) return '';
    const args = ['-e', safeShellArg(info.controller_url)];
    if (opts.token) args.push('-t', safeShellArg(opts.token));
    const allCores = Boolean(opts.withSingbox && opts.withCaddy && opts.withGost);
    if (allCores) {
        args.push('--with-all');
    } else {
        if (opts.runtime) args.push('--runtime');
        if (opts.withSingbox) args.push('--with-singbox');
        if (opts.withCaddy) args.push('--with-caddy');
        if (opts.withGost) args.push('--with-gost');
    }
    if (opts.adoptScan) args.push('--adopt-scan');
    if (opts.mode === 'upgrade') args.push('--upgrade');
    else if (opts.mode === 'reinstall') args.push('--reinstall');
    if (opts.insecure) args.push('-k');
    if (opts.caFile && String(opts.caFile).trim()) args.push('--ca-file', safeShellArg(opts.caFile));
    if (opts.ghProxy && String(opts.ghProxy).trim()) args.push('--gh-proxy', safeShellArg(opts.ghProxy));
    if (opts.noDeps) args.push('--no-deps');

    const curlFlags = opts.insecure ? '-fsSLk' : '-fsSL';
    const scriptUrl = safeShellArg(info.quick_install_url);
    const argStr = args.join(' ');
    if (opts.useSudo) {
        return 'curl ' + curlFlags + ' ' + scriptUrl + ' | sudo bash -s -- ' + argStr;
    }
    return 'bash <(curl ' + curlFlags + ' ' + scriptUrl + ') ' + argStr;
}

async function addAgent() {
    let busy = false, issued = false, quickInfo = null, issuedToken = '';
    openModal('添加服务器',
        '<div id="agent-quick-box" class="quick-install-box" hidden>' +
        _agentRegionPickerHtml('new-agent-region', '', '服务器地区 / 国旗 (可选)') +
        '<div class="form-group"><label for="new-agent-name">服务器名称</label><input id="new-agent-name" maxlength="128" autocomplete="off" placeholder="例如: 🇭🇰 hk-landing-01"></div>' +
        '<div class="quick-option-chips">' +
        '<label class="inline-check"><input type="checkbox" id="qi-runtime" checked> 启用托管 Runtime</label>' +
        '<label class="inline-check"><input type="checkbox" id="qi-inline-token" checked> 内联一次性凭据</label>' +
        '<label class="inline-check"><input type="checkbox" id="qi-adopt-scan" checked> 自动接管扫描</label>' +
        '<label class="inline-check"><input type="checkbox" id="qi-with-gost"> 预装 go-gost</label>' +
        '<label class="inline-check"><input type="checkbox" id="qi-with-singbox"> 预装 sing-box</label>' +
        '<label class="inline-check"><input type="checkbox" id="qi-with-caddy"> 预装 Caddy</label>' +
        '<label class="inline-check"><input type="checkbox" id="qi-sudo"> 非 root 加 sudo</label>' +
        '<label class="inline-check"><input type="checkbox" id="qi-insecure"> 跳过 TLS 校验 (-k)</label>' +
        '</div>' +
        '<div class="form-grid">' +
        '<div class="form-group"><label for="qi-mode">安装模式</label><select id="qi-mode"><option value="install">首次安装（默认）</option><option value="upgrade">原地升级（保留凭据）</option><option value="reinstall">强制覆盖重装</option></select></div>' +
        '<div class="form-group"><label for="qi-gh-proxy">GitHub 加速镜像 (可选)</label><input id="qi-gh-proxy" placeholder="例如 https://ghfast.top"></div>' +
        '<div class="form-group full-width"><label for="qi-ca-file">自定义 CA 证书路径 (可选)</label><input id="qi-ca-file" placeholder="/etc/ssl/custom-ca.pem"></div>' +
        '</div>' +
        '<div class="form-group"><label for="agent-quick-command">一键安装命令（在目标 Debian / Ubuntu 终端粘贴执行）</label>' +
        '<textarea id="agent-quick-command" class="quick-cmd-preview" readonly rows="3" autocomplete="off"></textarea></div>' +
        '<div class="panel-actions"><button type="button" class="btn btn-primary" id="agent-quick-copy-btn">🚀 生成并复制一键命令</button></div>' +
        '<p id="agent-quick-hint" class="hint"></p>' +
        '</div>' +
        '<p id="agent-install-status" class="hint">正在读取安装信息…</p>' +
        '<details id="agent-legacy-details"><summary>手动安装 / 固定 Commit 命令</summary>' +
        '<div id="agent-install-commands"></div>' +
        '<div id="agent-registration-result" hidden><p>一次性注册凭据（10 分钟有效，仅可消费一次）：</p>' +
        '<input id="agent-registration-token" aria-label="一次性注册凭据" readonly autocomplete="off">' +
        '<p id="agent-registration-expiry"></p></div>' +
        '</details>', async () => {
            if (!current() || busy) return;
            if (issued) { closeModal(); return; }
            await issueRegistrationAndSync(false);
        });

    const name = document.getElementById('new-agent-name');
    _bindAgentRegionPicker('new-agent-region', 'new-agent-name');
    const quickBox = document.getElementById('agent-quick-box');
    const quickCmdField = document.getElementById('agent-quick-command');
    const quickCopyBtn = document.getElementById('agent-quick-copy-btn');
    const quickHint = document.getElementById('agent-quick-hint');
    const current = () => name.isConnected && modalOverlay.classList.contains('active');

    function readQuickOptions() {
        const inline = document.getElementById('qi-inline-token');
        const modeEl = document.getElementById('qi-mode');
        const modeVal = modeEl ? modeEl.value : 'install';
        return {
            runtime: Boolean(document.getElementById('qi-runtime')?.checked),
            adoptScan: Boolean(document.getElementById('qi-adopt-scan')?.checked),
            withGost: Boolean(document.getElementById('qi-with-gost')?.checked),
            withSingbox: Boolean(document.getElementById('qi-with-singbox')?.checked),
            withCaddy: Boolean(document.getElementById('qi-with-caddy')?.checked),
            useSudo: Boolean(document.getElementById('qi-sudo')?.checked),
            insecure: Boolean(document.getElementById('qi-insecure')?.checked),
            mode: modeVal,
            caFile: document.getElementById('qi-ca-file')?.value.trim() || '',
            ghProxy: document.getElementById('qi-gh-proxy')?.value.trim() || '',
            token: (inline && inline.checked && modeVal !== 'upgrade' && issuedToken) ? issuedToken : '',
        };
    }

    function updateQuickCommandPreview() {
        if (!quickInfo || !quickCmdField) return;
        const opts = readQuickOptions();
        quickCmdField.value = buildQuickInstallCommand(quickInfo, opts);
        const needToken = Boolean(document.getElementById('qi-inline-token')?.checked) && opts.mode !== 'upgrade';
        if (quickCopyBtn) {
            quickCopyBtn.textContent = (needToken && !issuedToken) ? '🚀 生成凭据并复制命令' : '📋 复制一键命令';
        }
        if (quickHint) {
            if (opts.mode === 'upgrade') quickHint.textContent = '原地升级会保留现有 /etc/proxyforge-agent/config.json 与密钥，无需重新生成注册凭据。';
            else if (needToken && !issuedToken) quickHint.textContent = '填写服务器名称后点击上方按钮，将自动生成 10 分钟有效的一次性凭据并嵌入命令。';
            else if (needToken && issuedToken) quickHint.textContent = '已内联一次性注册凭据（10 分钟单次有效），关闭窗口即从页面清除；勾选上方选项仍可实时微调命令。';
            else quickHint.textContent = '当前命令不含任何密钥；在目标终端执行后可从交互提示中隐藏输入注册凭据。';
        }
    }

    async function issueRegistrationAndSync(copyAfter) {
        if (!current() || busy) return false;
        if (!name.value.trim()) { showToast('请填写服务器名称', 'error'); name.focus(); return false; }
        busy = true; modalConfirm.disabled = true;
        if (quickCopyBtn) quickCopyBtn.disabled = true;
        try {
            const registration = await (await fetchAuth('/agents/registration-tokens', {
                method: 'POST', body: JSON.stringify({ name: name.value.trim() })
            })).json();
            if (!current()) return false;
            issuedToken = registration.registration_token || '';
            document.getElementById('agent-registration-token').value = issuedToken;
            document.getElementById('agent-registration-expiry').textContent =
                '有效期至 ' + new Date(registration.expires_at * 1000).toLocaleString() + '；只能成功注册一次。';
            document.getElementById('agent-registration-result').hidden = false;
            name.readOnly = true; issued = true; modalConfirm.textContent = '关闭';
            updateQuickCommandPreview();
            if (copyAfter && quickCmdField && quickCmdField.value) {
                await copyAgentCommand(quickCmdField);
            }
            return true;
        } catch (error) {
            if (current()) showToast(error.message, 'error');
            return false;
        } finally {
            busy = false;
            if (current()) {
                modalConfirm.disabled = false;
                if (quickCopyBtn) quickCopyBtn.disabled = false;
            }
        }
    }

    for (const optId of ['qi-runtime', 'qi-inline-token', 'qi-adopt-scan', 'qi-with-gost', 'qi-with-singbox', 'qi-with-caddy', 'qi-sudo', 'qi-insecure', 'qi-mode']) {
        const el = document.getElementById(optId);
        if (el) el.onchange = updateQuickCommandPreview;
    }
    for (const optId of ['qi-gh-proxy', 'qi-ca-file']) {
        const el = document.getElementById(optId);
        if (el) el.oninput = updateQuickCommandPreview;
    }
    if (quickCopyBtn) {
        quickCopyBtn.onclick = async () => {
            const opts = readQuickOptions();
            const needToken = Boolean(document.getElementById('qi-inline-token')?.checked) && opts.mode !== 'upgrade';
            if (needToken && !issuedToken) {
                await issueRegistrationAndSync(true);
            } else if (quickCmdField) {
                updateQuickCommandPreview();
                await copyAgentCommand(quickCmdField);
            }
        };
    }

    modalConfirm.textContent = '生成注册凭据';
    modalConfirm.disabled = true;
    try {
        const info = await (await fetchAuth('/agents/install-command')).json();
        if (!current()) return;
        const status = document.getElementById('agent-install-status');
        if (!info.available) {
            status.textContent = info.message + ' 当前可按中文指南手动安装并生成注册凭据。';
            return;
        }
        status.textContent = 'Controller：' + info.controller_url + '；Agent ' + info.agent_version +
            (info.package_sha256 ? '；包校验：' + info.package_sha256.slice(0, 16) + '…' :
                '；源码提交：' + info.source_commit + '；Bootstrap：' + info.bootstrap_commit + '；SHA256：' + info.bootstrap_sha256);

        if (info.quick_install_url && quickBox) {
            quickInfo = info;
            quickBox.hidden = false;
            updateQuickCommandPreview();
        }
        const container = document.getElementById('agent-install-commands');
        for (const [action, label] of [['install', '复制 Agent 安装命令'], ['check', '复制只读下载校验命令'],
            ['runtime', '复制启用托管 runtime 命令（可选，root 辅助服务）']]) {
            let parent = container;
            if (action !== 'install') {
                parent = document.createElement('details');
                const summary = document.createElement('summary'); summary.textContent = label;
                parent.append(summary); container.append(parent);
            }
            const field = document.createElement('textarea'); field.readOnly = true; field.rows = 6;
            field.setAttribute('aria-label', label); field.value = info.commands[action];
            const button = document.createElement('button'); button.type = 'button'; button.className = 'btn';
            button.textContent = label; button.onclick = () => copyAgentCommand(field);
            parent.append(field, button);
        }
    } catch (error) {
        if (current()) document.getElementById('agent-install-status').textContent =
            '安装信息读取失败，可按中文指南手动安装：' + error.message;
    } finally {
        if (current()) modalConfirm.disabled = false;
    }
}

function clearRegistrationToken() {
    for (const id of ['agent-registration-token', 'agent-quick-command', 'deployment-dns-token', 'deployment-out-pass', 'tunnel-relay-pass']) {
        const field = document.getElementById(id);
        if (field) field.value = '';
    }
    if (typeof document !== 'undefined' && typeof document.querySelectorAll === 'function') {
        document.querySelectorAll('.pf-ephemeral-secret').forEach(el => { el.value = ''; });
    }
}

if (typeof document !== 'undefined') {
    document.getElementById('agent-add-btn').addEventListener('click', addAgent);
    document.getElementById('agent-refresh-btn').addEventListener('click', refreshAgents);
    document.querySelector('[data-panel="panel-agents"]').addEventListener('click', refreshAgents);
    document.addEventListener('click', () => _closeAllAgentMenus());
    document.addEventListener('keydown', event => { if (event.key === 'Escape') _closeAllAgentMenus(); });
    modalClose.addEventListener('click', clearRegistrationToken);
    modalCancel.addEventListener('click', clearRegistrationToken);
    modalOverlay.addEventListener('keydown', event => { if (event.key === 'Escape') clearRegistrationToken(); });
    setInterval(() => {
        if (document.getElementById('panel-agents').classList.contains('active') && dashboard.style.display !== 'none')
            refreshAgents();
    }, 30000);
}
if (typeof module !== 'undefined' && module.exports) module.exports = { agentStatusLabel, agentCanRunJobs, agentCanManageRuntime, agentCanDeploy, agentCanLand, agentCanChain, agentCanGost, buildQuickInstallCommand };
