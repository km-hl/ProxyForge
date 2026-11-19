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
        const intro = document.createElement('div');
        intro.className = 'hint';
        intro.style.marginBottom = '8px';
        intro.textContent = '按顺序级联出站 (本机入口 → 第 1 跳 → 第 2 跳 → … → 最终落地，原生 sing-box detour，完整支持 TCP + UDP，最多 4 跳)。受管 SS2022 跳会自动读取最新端口与密钥，无需手工复制密码。';
        container.append(intro);

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

                grid.append(fgSrv, fgPort);

                if (hop.kind === 'ss') {
                    const fgMethod = document.createElement('div');
                    fgMethod.className = 'form-group';
                    const lMethod = document.createElement('label'); lMethod.textContent = 'SS 加密方式';
                    const sMethod = document.createElement('select');
                    for (const m of ['2022-blake3-aes-256-gcm', '2022-blake3-aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305']) {
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
                    const iUser = document.createElement('input');
                    iUser.placeholder = 'username';
                    iUser.value = hop.username || '';
                    iUser.oninput = () => { hop.username = iUser.value.trim(); };
                    fgUser.append(lUser, iUser);
                    grid.append(fgUser);
                }

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

async function showAgentChain(agent) {
    const nodesUrl = '/agents/' + agent.id + '/nodes';
    const [nodesPayload, ssPayload, legacyPayload] = await Promise.all([
        fetchAgentJson(nodesUrl),
        fetchAgentJson('/agents/deployments/ss-landings').catch(() => ({ landings: [] })),
        fetchAgentJson('/agents/' + agent.id + '/chain').catch(() => ({ chain: null })),
    ]);
    let agentNodes = nodesPayload.nodes || [];
    let ssLandings = ssPayload.landings || [];
    let legacyChain = legacyPayload.chain || null;
    const pubIpv4 = nodesPayload.public_ipv4 || agent.public_ipv4 || agent.observed_ip || '';
    const pubIpv6 = nodesPayload.public_ipv6 || agent.public_ipv6 || '';
    let editingNodeId = null;

    function pickNextChainPort() {
        const used = new Set(agentNodes.map(n => Number(n.settings?.listen_port)));
        for (const p of [20001, 20002, 20003, 20004, 8443, 8444, 2053]) {
            if (!used.has(p)) return p;
        }
        let p = 20005;
        while (used.has(p) && p < 60000) p += 1;
        return p;
    }

    openModal('多落地 / 多跳链式出站 · ' + agent.name,
        '<p class="hint">同一台入口 Agent 可同时挂载多条独立链式节点（不同监听端口对应不同落地机或 1~4 跳级联链路，基于 sing-box 原生 detour，完整支持 TCP + UDP）。例如：20001 → 新加坡 SS2022，20002 → 日本 SS2022，20003 → IX SS2022 → SG SS2022 → 家宽 Socks5。</p>' +
        '<div id="chain-legacy-banner" hidden style="margin-bottom:10px;"></div>' +
        '<h4 style="margin:8px 0 6px;">本机已有链式出站节点</h4>' +
        '<div id="chain-nodes-list" style="margin-bottom:12px;"></div>' +
        '<div style="display:flex; align-items:center; justify-content:space-between; gap:8px; margin:8px 0 6px;">' +
        '<h4 id="chain-form-heading" style="margin:0;">➕ 新增链式落地节点</h4>' +
        '<button type="button" class="btn btn-sm" id="chain-new-mode-btn" hidden>切换为新建</button></div>' +
        _agentRegionPickerHtml('chain-node-region', agent.region || '', '节点地区 / 国旗 (自动添加在节点名称前)') +
        '<div class="form-grid">' +
        '<div class="form-group"><label>入口协议</label><select id="chain-node-protocol">' +
        '<option value="reality">VLESS Reality (TCP+UDP 推荐)</option>' +
        '<option value="hysteria2">Hysteria2 (QUIC/UDP)</option>' +
        '<option value="anytls">AnyTLS (TLS 1.3)</option>' +
        '<option value="trojan">Trojan (TLS 1.3 + Caddy)</option>' +
        '<option value="ss2022">Shadowsocks 2022 (中继跳板)</option></select></div>' +
        '<div class="form-group"><label>监听端口 (每条链路独立端口)</label><input id="chain-node-port" type="number" min="1" max="65535" value="' + _escHtml(String(pickNextChainPort())) + '"></div>' +
        '<div class="form-group"><label>节点名称</label><input id="chain-node-name" maxlength="64" placeholder="如 🇸🇬 SG 链式落地"></div>' +
        '<div class="form-group"><label>客户端连接地址 (IP / 域名)</label><input id="chain-node-server" value="' + _escHtml(pubIpv4 || pubIpv6) + '" placeholder="自动填入公网 IP 或域名"></div>' +
        '<div class="form-group" id="chain-node-tls-wrap"><label>入口 TLS / 伪装模式</label><select id="chain-node-tls-mode"></select></div>' +
        '<div class="form-group" id="chain-node-domain-wrap"><label>入口 SNI / 证书域名</label><input id="chain-node-domain" value="www.amazon.com" placeholder="www.amazon.com 或自有域名"></div>' +
        '<div class="form-group"><label>出站 IP 协议栈</label><select id="chain-node-out-strategy">' +
        '<option value="prefer_ipv4">双栈 IPv4 优先 (prefer_ipv4)</option>' +
        '<option value="prefer_ipv6">双栈 IPv6 优先 (prefer_ipv6)</option>' +
        '<option value="ipv4_only">仅 IPv4 (ipv4_only)</option>' +
        '<option value="ipv6_only">仅 IPv6 (ipv6_only)</option></select></div>' +
        '<div class="form-group" id="chain-node-sspub-wrap" hidden style="display:flex; align-items:flex-end;"><label class="inline-check"><input type="checkbox" id="chain-node-sspub"> 同时加入客户端订阅</label></div>' +
        '</div>' +
        '<div id="chain-node-hops-box" style="margin:10px 0;"></div>' +
        '<p class="hint">应用仅重载/重启代理服务进程（不会重启服务器），不中断宿主机及其他共存直连节点。</p>' +
        '<div style="display:flex; gap:8px; flex-wrap:wrap;">' +
        '<button type="button" class="btn btn-primary" id="chain-node-save">保存并应用链式节点</button>' +
        '<button type="button" class="btn" id="chain-node-refresh">刷新列表</button></div>' +
        '<pre id="chain-state" style="white-space:pre-wrap; margin-top:8px;"></pre>', closeModal);

    _bindAgentRegionPicker('chain-node-region', 'chain-node-name');
    const protoEl = document.getElementById('chain-node-protocol');
    const tlsModeEl = document.getElementById('chain-node-tls-mode');
    const domainEl = document.getElementById('chain-node-domain');
    const nameEl = document.getElementById('chain-node-name');
    const portEl = document.getElementById('chain-node-port');
    const serverEl = document.getElementById('chain-node-server');
    const stratEl = document.getElementById('chain-node-out-strategy');
    const sspubEl = document.getElementById('chain-node-sspub');
    const statusEl = document.getElementById('chain-state');
    const saveBtn = document.getElementById('chain-node-save');
    const headingEl = document.getElementById('chain-form-heading');
    const newModeBtn = document.getElementById('chain-new-mode-btn');

    const defaultHops = ssLandings.filter(l => l.agent_id !== agent.id).length
        ? [{ kind: 'managed_ss', agent_id: ssLandings.filter(l => l.agent_id !== agent.id)[0].agent_id, node_id: ssLandings.filter(l => l.agent_id !== agent.id)[0].node_id }]
        : [];
    const hopEditor = _createOutboundHopsEditor({
        container: document.getElementById('chain-node-hops-box'),
        initialHops: defaultHops,
        ssLandings,
        currentAgentId: agent.id,
    });

    function syncChainTls(proto, preferred) {
        const meta = LANDING_PROTO_META[proto] || LANDING_PROTO_META.reality;
        tlsModeEl.replaceChildren();
        for (const [val, lbl] of meta.tlsModes) {
            const o = document.createElement('option');
            o.value = val; o.textContent = lbl;
            tlsModeEl.append(o);
        }
        const valid = meta.tlsModes.map(m => m[0]);
        tlsModeEl.value = (preferred && valid.includes(preferred)) ? preferred : valid[0];
        document.getElementById('chain-node-tls-wrap').hidden = proto === 'ss2022';
        document.getElementById('chain-node-domain-wrap').hidden = proto === 'ss2022';
        document.getElementById('chain-node-sspub-wrap').hidden = proto !== 'ss2022';
    }

    function resetToCreate() {
        editingNodeId = null;
        headingEl.textContent = '➕ 新增链式落地节点';
        newModeBtn.hidden = true;
        protoEl.value = 'reality';
        syncChainTls('reality', 'reality');
        nameEl.value = '';
        portEl.value = String(pickNextChainPort());
        serverEl.value = pubIpv4 || pubIpv6 || '';
        domainEl.value = 'www.amazon.com';
        stratEl.value = 'prefer_ipv4';
        sspubEl.checked = false;
        const otherLandings = ssLandings.filter(l => l.agent_id !== agent.id);
        hopEditor.setHops(otherLandings.length ? [{ kind: 'managed_ss', agent_id: otherLandings[0].agent_id, node_id: otherLandings[0].node_id }] : []);
    }

    function loadNodeIntoForm(node) {
        editingNodeId = node.id;
        const s = node.settings || {};
        headingEl.textContent = `✏️ 编辑链式节点：${s.name || node.id}`;
        newModeBtn.hidden = false;
        const p = LANDING_PROTO_META[node.protocol] ? node.protocol : 'reality';
        protoEl.value = p;
        syncChainTls(p, s.tls_mode);
        nameEl.value = s.name || '';
        portEl.value = String(s.listen_port || pickNextChainPort());
        serverEl.value = s.server || pubIpv4 || pubIpv6 || '';
        domainEl.value = s.domain || s.server_name || '';
        stratEl.value = s.outbound_strategy || 'prefer_ipv4';
        sspubEl.checked = Boolean(s.publish_to_subscription);
        if (s.outbound_mode === 'chain' && Array.isArray(s.outbound_hops)) {
            hopEditor.setHops(s.outbound_hops);
        } else if (s.outbound_mode === 'ss' || s.outbound_mode === 'socks5') {
            hopEditor.setHops([{
                kind: s.outbound_mode,
                server: s.outbound_server || '',
                port: s.outbound_port || (s.outbound_mode === 'socks5' ? 1080 : 8388),
                username: s.outbound_username || '',
                method: s.outbound_method || '2022-blake3-aes-256-gcm',
            }]);
        } else {
            hopEditor.setHops([]);
        }
    }

    function renderLegacyBanner() {
        const box = document.getElementById('chain-legacy-banner');
        box.replaceChildren();
        if (!legacyChain) { box.hidden = true; return; }
        box.hidden = false;
        box.className = 'sub-user-card';
        const p = document.createElement('div');
        p.className = 'hint';
        p.textContent = `检测到一条旧版单链路记录 (${legacyChain.settings?.name || ''} :${legacyChain.settings?.listen_port || ''})，可点击移除后改用下方新版多链式节点。`;
        const btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'btn btn-danger btn-sm'; btn.style.marginTop = '6px';
        btn.textContent = '移除旧版单链路';
        btn.onclick = async () => {
            if (!confirm('确认移除旧版单链路并保留直连？')) return;
            try {
                await fetchAgentJson('/agents/' + agent.id + '/chain', {
                    method: 'PUT',
                    body: JSON.stringify({
                        request_id: randomRequestId(),
                        expected_revision: legacyChain.revision,
                        landing_agent_id: legacyChain.landing_agent_id,
                        settings: legacyChain.settings,
                        remove: true,
                    }),
                });
                legacyChain = null;
                renderLegacyBanner();
                statusEl.textContent = '已下发移除旧版单链路任务。';
            } catch (e) { statusEl.textContent = '移除旧版链路失败：' + e.message; }
        };
        box.append(p, btn);
    }

    function renderList() {
        renderLegacyBanner();
        const listEl = document.getElementById('chain-nodes-list');
        listEl.replaceChildren();
        const chained = agentNodes.filter(n => ['chain', 'ss', 'socks5'].includes((n.settings || {}).outbound_mode));
        const directCount = agentNodes.length - chained.length;
        if (!chained.length) {
            const empty = document.createElement('div');
            empty.className = 'hint';
            empty.textContent = `当前暂无链式出站节点（本机共有 ${directCount} 个直连节点，互不干扰）。在下方选择目标 SS2022 落地即可快速添加多条链路。`;
            listEl.append(empty);
        } else {
            for (const n of chained) {
                const s = n.settings || {};
                const card = document.createElement('div');
                card.className = 'sub-user-card';
                card.style.marginBottom = '8px';
                const head = document.createElement('div');
                head.className = 'sub-user-header';
                const title = document.createElement('strong');
                title.textContent = `${s.name || n.protocol} (${n.protocol} :${s.listen_port || '?'})`;
                const pill = document.createElement('span');
                pill.className = `status-pill ${n.status === 'success' ? 'is-online' : (n.status === 'failed' ? 'is-offline' : 'is-degraded')}`;
                pill.textContent = `${n.status || 'unknown'} · v${n.revision || 1}`;
                head.append(title, pill);

                const routeLine = document.createElement('div');
                routeLine.className = 'hint';
                routeLine.textContent = `路径：入口 :${s.listen_port || '?'} → ${_formatOutboundHopsSummary(s, ssLandings)}`;

                const acts = document.createElement('div');
                acts.className = 'item-actions';
                acts.style.marginTop = '6px';
                const editBtn = document.createElement('button');
                editBtn.type = 'button'; editBtn.className = 'btn btn-sm'; editBtn.textContent = '编辑';
                editBtn.onclick = () => loadNodeIntoForm(n);

                const delBtn = document.createElement('button');
                delBtn.type = 'button'; delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = '删除';
                delBtn.onclick = async () => {
                    if (!confirm(`确认删除链式节点 ${s.name || n.id} 并重载代理服务进程？`)) return;
                    try {
                        await fetchAgentJson('/agents/' + agent.id + '/nodes/' + encodeURIComponent(n.id), {
                            method: 'DELETE',
                            body: JSON.stringify({ request_id: randomRequestId() }),
                        });
                        if (editingNodeId === n.id) resetToCreate();
                        await refreshAll();
                        if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
                    } catch (e) { statusEl.textContent = '删除失败：' + e.message; }
                };
                acts.append(editBtn, delBtn);
                card.append(head, routeLine, acts);
                listEl.append(card);
            }
        }
        const capable = agentCanLand(agent) || agentCanDeploy(agent);
        const busy = agentNodes.some(n => ['pending', 'assigned', 'running'].includes(n.status));
        saveBtn.disabled = !capable || busy;
        if (!capable) statusEl.textContent = '请升级此入口 Agent 和本地辅助服务以支持多节点链式出站。';
        else if (busy) statusEl.textContent = '当前有正在执行中的部署任务，请稍候刷新。';
    }

    async function refreshAll() {
        const [np, sp] = await Promise.all([
            fetchAgentJson(nodesUrl),
            fetchAgentJson('/agents/deployments/ss-landings').catch(() => ({ landings: [] })),
        ]);
        agentNodes = np.nodes || [];
        ssLandings = sp.landings || [];
        renderList();
    }

    protoEl.onchange = () => syncChainTls(protoEl.value);
    newModeBtn.onclick = () => resetToCreate();
    document.getElementById('chain-node-refresh').onclick = () => refreshAll().catch(e => { statusEl.textContent = e.message; });
    saveBtn.onclick = async () => {
        try {
            const collected = hopEditor.collect();
            let nodeName = nameEl.value.trim();
            const regionVal = document.getElementById('chain-node-region')?.value?.trim() || '';
            if (regionVal && typeof ProxyForgeRegions !== 'undefined') {
                nodeName = ProxyForgeRegions.applyRegionPrefix(nodeName, regionVal);
                nameEl.value = nodeName;
            }
            if (!nodeName) throw new Error('请填写链式节点名称');
            const proto = protoEl.value;
            const tlsMode = proto === 'ss2022' ? 'none' : tlsModeEl.value;
            const settings = {
                name: nodeName,
                server: serverEl.value.trim(),
                listen_port: Number(portEl.value),
                protocol: proto,
                tls_mode: tlsMode,
                outbound_strategy: stratEl.value || 'prefer_ipv4',
                outbound_mode: 'chain',
                outbound_hops: collected.outbound_hops,
            };
            if (regionVal) settings.region = regionVal;
            if (proto !== 'ss2022') {
                const dom = domainEl.value.trim();
                if (dom) settings.domain = dom;
                if (proto === 'reality' || proto === 'anytls') settings.fingerprint = 'chrome';
            } else {
                settings.method = '2022-blake3-aes-256-gcm';
                settings.publish_to_subscription = Boolean(sspubEl.checked);
            }
            if (!confirm('确认保存链式节点并重载/重启代理服务进程（不会重启服务器）？')) return;
            saveBtn.disabled = true;
            const body = { request_id: randomRequestId(), protocol: proto, settings };
            if (Object.keys(collected.hop_passwords).length) {
                body.secrets = { hop_passwords: collected.hop_passwords };
            }
            const endpoint = editingNodeId
                ? '/agents/' + agent.id + '/nodes/' + encodeURIComponent(editingNodeId)
                : '/agents/' + agent.id + '/nodes';
            await fetchAgentJson(endpoint, { method: editingNodeId ? 'PUT' : 'POST', body: JSON.stringify(body) });
            hopEditor.clearSecrets();
            statusEl.textContent = '链式节点已下发至代理服务进程！';
            resetToCreate();
            await refreshAll();
            if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
        } catch (e) {
            statusEl.textContent = '保存失败：' + e.message;
        } finally {
            renderList();
        }
    };

    syncChainTls(protoEl.value, 'reality');
    renderList();
}

const LANDING_PROTO_META = {
    reality: {
        label: 'VLESS Reality (XTLS-Vision · 自建回环偷自己 / 外部目标)',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['reality', '外部目标模式 (免域名 · 借用大厂 TLS 1.3 SNI)'],
            ['acme_http', '自建回环“偷自己” (HTTP-01 自动证书 + Caddy 伪装)'],
            ['acme_dns', '自建回环“偷自己” (DNS-01 自动证书 + Caddy 伪装)'],
        ],
        canKeygen: true,
    },
    hysteria2: {
        label: 'Hysteria2 (QUIC/UDP · ACME 自动证书 · 端口跳跃)',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['acme_http', 'ACME HTTP-01 自动证书'],
            ['acme_dns', 'ACME DNS-01 自动证书'],
        ],
        canKeygen: true,
    },
    ss2022: {
        label: 'Shadowsocks 2022 (2022-blake3 · 内部落地 / 直连订阅)',
        defaultPort: 8388,
        landing: true,
        tlsModes: [['none', '无 TLS (SS2022 AEAD 原生加密)']],
        canKeygen: true,
    },
    anytls: {
        label: 'AnyTLS (TLS 1.3 + 原生 Padding 消除 TLS-in-TLS 特征)',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['acme_http', 'ACME HTTP-01 自动证书'],
            ['acme_dns', 'ACME DNS-01 自动证书'],
        ],
        canKeygen: true,
    },
    trojan: {
        label: 'Trojan (TLS 1.3 + 本机 Caddy 防主动探测 Fallback)',
        defaultPort: 443,
        landing: true,
        tlsModes: [
            ['acme_http', 'ACME HTTP-01 自动证书 + Caddy 回环伪装'],
            ['acme_dns', 'ACME DNS-01 自动证书 + Caddy 回环伪装'],
        ],
        canKeygen: true,
    },
};

async function showAgentDeployment(agent) {
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
    let currentNodeId = agentNodes.length ? agentNodes[0].id : null;
    let generatedKeyRef = null;

    openModal('节点 / 落地部署 · ' + agent.name,
        '<p class="hint">单台 Agent 支持多协议节点共存（例如 TCP 443 VLESS Reality + UDP 443 Hysteria2 + AnyTLS + Trojan + SS2022），统一编译至本机 proxyforge-singbox 实例。</p>' +
        '<div id="deployment-nodes-bar" style="margin-bottom:12px;"></div>' +
        '<div class="form-grid">' +
        '<div class="form-group full-width"><label>部署协议类型 (五大抗封锁协议)</label><select id="deployment-protocol">' +
        '<option value="reality">VLESS Reality (XTLS-Vision · 自建回环偷自己 / 外部目标)</option>' +
        '<option value="hysteria2">Hysteria2 (QUIC/UDP · ACME 自动证书 · 端口跳跃)</option>' +
        '<option value="ss2022">Shadowsocks 2022 (2022-blake3 · 内部落地 / 直连订阅)</option>' +
        '<option value="anytls">AnyTLS (TLS 1.3 · 消除 TLS-in-TLS 特征)</option>' +
        '<option value="trojan">Trojan (TLS 1.3 + 本机 Caddy 防探测回落)</option></select></div>' +
        '</div>' +
        '<p id="deployment-help" class="hint"></p>' +
        _agentRegionPickerHtml('deployment-region', agent.region || '', '节点地区 / 国旗 (可输入搜索或选择，自动添加在节点名称前)') +
        '<div class="form-grid">' +
        '<div class="form-group"><label>节点名称</label><input id="deployment-name" maxlength="64" placeholder="如 🇭🇰 HK Reality"></div>' +
        '<div class="form-group"><label>监听端口</label><input id="deployment-port" type="number" min="1" max="65535" value="443"></div>' +
        '<div class="form-group full-width"><label>公网 IP / 域名 (客户端连接地址)</label>' +
        '<div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:6px;" id="deployment-ip-quick">' +
        (pubIpv4 ? `<button type="button" class="btn btn-sm" data-ip-val="${_escHtml(pubIpv4)}">📡 自动 IPv4 (${_escHtml(pubIpv4)})</button>` : '') +
        (pubIpv6 ? `<button type="button" class="btn btn-sm" data-ip-val="${_escHtml(pubIpv6)}">🌐 自动 IPv6 (${_escHtml(pubIpv6)})</button>` : '') +
        '</div>' +
        '<input id="deployment-server" placeholder="自动填入公网 IP 或手动输入绑定域名"></div>' +
        '</div>' +
        '<div id="deployment-tls-section"><div class="form-grid">' +
        '<div class="form-group"><label>TLS / 伪装模式</label><select id="deployment-tls-mode"></select></div>' +
        '<div class="form-group"><label id="deployment-domain-label">证书域名 / SNI</label><input id="deployment-domain" placeholder="如 www.amazon.com 或自有时效域名"></div>' +
        '<div class="form-group full-width"><label>伪装目标 / 反代上游 URL (可选，需 https://)</label><input id="deployment-camouflage" placeholder="https://www.apple.com (留空使用内置静态伪装页或 SNI 域名)"></div>' +
        '</div></div>' +
        '<div id="deployment-reality-ext-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>uTLS 客户端指纹</label><select id="deployment-fingerprint"><option value="chrome">chrome (推荐)</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="edge">edge</option><option value="ios">ios</option><option value="android">android</option><option value="random">random</option></select></div>' +
        '<div class="form-group"><label>Reality Public Key</label><input id="deployment-reality-pubkey" placeholder="留空自动生成或点击下方按钮预生成"></div>' +
        '<div class="form-group full-width"><label>Short IDs (逗号分隔 hex，留空自动生成)</label><input id="deployment-reality-shortids" placeholder="如 a1b2c3d4"></div>' +
        '</div></div>' +
        '<div id="deployment-ss2022-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>SS2022 加密套件</label><select id="deployment-ss2022-method"><option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option><option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option></select></div>' +
        '<div class="form-group" style="display:flex; align-items:flex-end;"><label class="inline-check"><input type="checkbox" id="deployment-ss2022-publish"> 同时投影至客户端订阅 (允许客户端直连此 SS2022 节点)</label></div>' +
        '</div></div>' +
        '<div id="deployment-hy2-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>端口跳跃范围 mport (可选)</label><input id="deployment-hy2-mport" placeholder="如 20000-50000"></div>' +
        '<div class="form-group"><label>跳跃间隔秒数 (5-3600)</label><input id="deployment-hy2-hop" type="number" min="5" max="3600" placeholder="30"></div>' +
        '<div class="form-group"><label>上行带宽 Mbps (可选)</label><input id="deployment-hy2-up" type="number" min="1" max="100000" placeholder="100"></div>' +
        '<div class="form-group"><label>下行带宽 Mbps (可选)</label><input id="deployment-hy2-down" type="number" min="1" max="100000" placeholder="500"></div>' +
        '<div class="form-group"><label>QUIC 混淆 (Salamander)</label><select id="deployment-hy2-obfs"><option value="none">none (推荐依靠端口跳跃)</option><option value="salamander">salamander</option></select></div>' +
        '</div></div>' +
        '<div id="deployment-acme-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>ACME 联系邮箱 (可选)</label><input id="deployment-acme-email" type="email" placeholder="admin@example.com"></div>' +
        '</div></div>' +
        '<div id="deployment-dns-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>DNS 服务商</label><select id="deployment-dns-provider"><option value="cloudflare">cloudflare</option><option value="alidns">alidns</option><option value="dnspod">dnspod</option></select></div>' +
        '<div class="form-group"><label>DNS Zone ID (Cloudflare 需 32 位 hex)</label><input id="deployment-dns-zone" placeholder="0123456789abcdef0123456789abcdef"></div>' +
        '<div class="form-group"><label>DNS 传播等待秒数</label><input id="deployment-dns-prop" type="number" min="10" max="600" value="60"></div>' +
        '<div class="form-group"><label>DNS API Token (仅写入不回显)</label><input id="deployment-dns-token" type="password" autocomplete="off" placeholder="留空表示保持原有凭据"></div>' +
        '</div></div>' +
        '<details id="deployment-outbound-details" style="margin:10px 0;"><summary>🌐 出站双栈策略、链式多跳 SS 落地与外部家宽 Socks5 出站</summary>' +
        '<div class="form-grid" style="margin-top:8px;">' +
        '<div class="form-group"><label>出站 IP 协议栈策略</label><select id="deployment-outbound-strategy">' +
        '<option value="prefer_ipv4">双栈 IPv4 优先 (prefer_ipv4 · 默认)</option>' +
        '<option value="prefer_ipv6">双栈 IPv6 优先 (prefer_ipv6)</option>' +
        '<option value="ipv4_only">仅 IPv4 出站 (ipv4_only)</option>' +
        '<option value="ipv6_only">仅 IPv6 出站 (ipv6_only)</option></select></div>' +
        '<div class="form-group"><label>节点出站方式</label><select id="deployment-outbound-mode">' +
        '<option value="direct">本机直连出站 (Direct)</option>' +
        '<option value="chain">链式多跳 SS / 家宽出站 (sing-box detour · 1~4 跳 TCP+UDP)</option>' +
        '<option value="socks5">外部 Socks5 落地出站 (对接第三方住宅家宽)</option>' +
        '<option value="ss">外部 Shadowsocks 落地出站</option></select></div>' +
        '</div>' +
        '<div id="deployment-outbound-proxy-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>外部落地服务器地址</label><input id="deployment-out-server" placeholder="isp.example.com 或 IP"></div>' +
        '<div class="form-group"><label>外部落地端口</label><input id="deployment-out-port" type="number" min="1" max="65535" placeholder="1080"></div>' +
        '<div class="form-group" id="deployment-out-user-wrap"><label>Socks5 用户名 (可选)</label><input id="deployment-out-user" placeholder="username"></div>' +
        '<div class="form-group" id="deployment-out-method-wrap" hidden><label>SS 加密方式</label><select id="deployment-out-method">' +
        '<option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>' +
        '<option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>' +
        '<option value="aes-256-gcm">aes-256-gcm</option>' +
        '<option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option></select></div>' +
        '<div class="form-group"><label>外部落地密码 (仅写入不回显)</label><input id="deployment-out-pass" type="password" autocomplete="off" class="pf-ephemeral-secret" placeholder="留空保持原密码"></div>' +
        '</div></div>' +
        '<div id="deployment-outbound-chain-fields" hidden style="margin-top:8px;"></div></details>' +
        '<div style="margin:8px 0;"><button type="button" class="btn btn-sm" id="deployment-keygen-btn">🔑 服务端预生成密钥对</button> <span id="deployment-keyref-status" class="hint"></span></div>' +
        '<p class="hint">应用仅重载/重启代理服务进程（不会重启服务器），可能短暂中断当前节点连接。</p>' +
        '<button type="button" class="btn btn-primary" id="deployment-apply">保存并应用节点</button> ' +
        '<button type="button" class="btn btn-danger" id="deployment-remove">删除当前节点</button> ' +
        '<button type="button" class="btn" id="deployment-refresh">刷新状态</button><pre id="deployment-state" style="white-space:pre-wrap; margin-top:8px;"></pre>', closeModal);

    _bindAgentRegionPicker('deployment-region', 'deployment-name');
    const status = document.getElementById('deployment-state');
    const apply = document.getElementById('deployment-apply');
    const remove = document.getElementById('deployment-remove');
    const protocol = document.getElementById('deployment-protocol');
    const tlsModeEl = document.getElementById('deployment-tls-mode');
    const outModeEl = document.getElementById('deployment-outbound-mode');
    const keygenBtn = document.getElementById('deployment-keygen-btn');
    const keyrefStatus = document.getElementById('deployment-keyref-status');
    const nodesBar = document.getElementById('deployment-nodes-bar');
    const outDetailsEl = document.getElementById('deployment-outbound-details');
    const hopEditor = _createOutboundHopsEditor({
        container: document.getElementById('deployment-outbound-chain-fields'),
        initialHops: [],
        ssLandings,
        currentAgentId: agent.id,
    });

    document.querySelectorAll('#deployment-ip-quick button[data-ip-val]').forEach(btn => {
        btn.onclick = () => {
            document.getElementById('deployment-server').value = btn.getAttribute('data-ip-val') || '';
        };
    });

    function getSelectedNode() {
        return agentNodes.find(n => n.id === currentNodeId) || null;
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
        const wrap = document.createElement('div');
        wrap.style.display = 'flex';
        wrap.style.flexWrap = 'wrap';
        wrap.style.gap = '6px';
        wrap.style.alignItems = 'center';
        for (const n of agentNodes) {
            const btn = document.createElement('button');
            btn.type = 'button';
            const isSel = n.id === currentNodeId;
            btn.className = isSel ? 'btn btn-primary btn-sm' : 'btn btn-sm';
            const s = n.settings || {};
            btn.textContent = `${s.name || n.protocol} (${n.protocol} :${s.listen_port || '?'})`;
            btn.onclick = () => {
                currentNodeId = n.id;
                generatedKeyRef = null;
                render(true);
            };
            wrap.append(btn);
        }
        const addBtn = document.createElement('button');
        addBtn.type = 'button';
        addBtn.className = currentNodeId === null ? 'btn btn-primary btn-sm' : 'btn btn-sm';
        addBtn.textContent = '➕ 新增共存节点';
        addBtn.onclick = () => {
            currentNodeId = null;
            generatedKeyRef = null;
            protocol.value = 'reality';
            syncTlsOptions('reality', 'reality');
            const usedPorts = new Set(agentNodes.map(x => Number(x.settings?.listen_port)));
            const defaultP = !usedPorts.has(443) ? 443 : (!usedPorts.has(8443) ? 8443 : 2053);
            document.getElementById('deployment-name').value = '';
            document.getElementById('deployment-port').value = String(defaultP);
            document.getElementById('deployment-server').value = pubIpv4 || pubIpv6 || '';
            document.getElementById('deployment-domain').value = 'www.amazon.com';
            document.getElementById('deployment-camouflage').value = '';
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
        wrap.append(addBtn);
        nodesBar.append(wrap);
        if (typeof window !== 'undefined' && window.twemoji) {
            window.twemoji.parse(nodesBar, { folder: 'svg', ext: '.svg' });
        }
    }

    function render(fill) {
        renderNodesBar();
        const current = getSelectedNode();
        if (fill) {
            if (current) {
                const p = LANDING_PROTO_META[current.protocol] ? current.protocol : 'reality';
                protocol.value = p;
                const s = current.settings || {};
                syncTlsOptions(p, s.tls_mode);
                document.getElementById('deployment-name').value = s.name ?? '';
                document.getElementById('deployment-server').value = s.server ?? (pubIpv4 || pubIpv6 || '');
                document.getElementById('deployment-port').value = s.listen_port ?? 443;
                document.getElementById('deployment-domain').value = s.domain ?? s.server_name ?? '';
                document.getElementById('deployment-camouflage').value = s.camouflage_url ?? '';
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
                syncTlsOptions(protocol.value);
            }
        }
        const proto = protocol.value;
        const meta = LANDING_PROTO_META[proto] || LANDING_PROTO_META.reality;
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
            (proto === 'reality' && tlsMode === 'reality') ? '偷取目标域名 SNI (需支持 TLS 1.3 + H2，如 www.amazon.com)' : '证书域名 / SNI (需解析到本机或配置 DNS-01)';

        const outMode = outModeEl.value || 'direct';
        document.getElementById('deployment-outbound-proxy-fields').hidden = !(outMode === 'socks5' || outMode === 'ss');
        document.getElementById('deployment-outbound-chain-fields').hidden = outMode !== 'chain';
        document.getElementById('deployment-out-user-wrap').hidden = outMode !== 'socks5';
        document.getElementById('deployment-out-method-wrap').hidden = outMode !== 'ss';

        keygenBtn.hidden = !meta.canKeygen;
        keyrefStatus.textContent = generatedKeyRef ? '已生成服务端密钥引用，提交部署时将自动注入（私钥不落地浏览器）。' : '';
        const helpMap = {
            reality: 'VLESS + XTLS-Vision + REALITY（开启 max_time_difference 1m）。可选“自建回环偷自己”（Caddy 在 127.0.0.1 提供真实 TLS 1.3 证书与伪装站）或“外部目标模式”（免域名）。',
            hysteria2: 'Hysteria2 (QUIC/UDP + TLS 1.3 ALPN h3)，支持 ACME 自动证书、上下行带宽提示与多端口跳跃 (mport) 防 UDP QoS 限速。',
            ss2022: 'Shadowsocks 2022 AEAD (TCP+UDP)，既可作为中转/链式代理的高性能内部落地，也可勾选直接加入客户端订阅。',
            anytls: 'sing-box 原生 AnyTLS 入站 + TLS 1.3 自动证书，内置分段填充方案 (padding_scheme) 彻底消除 TLS-in-TLS 长度特征。',
            trojan: 'Trojan + TLS 1.3 自动证书，自动编排本机回环 Caddy 提供真实网页 Fallback，抵御主动探测。',
        };
        document.getElementById('deployment-help').textContent = helpMap[proto] || '';
        const capable = agentCanLand(agent) || agentCanDeploy(agent);
        const busy = agentNodes.some(n => ['pending', 'assigned', 'running'].includes(n.status));
        apply.disabled = !capable || busy;
        remove.disabled = apply.disabled || !current;
        status.textContent = !capable ? '请升级 Agent 和本地运行环境辅助服务以支持节点部署。' :
            current ? `[${current.is_primary ? '主节点' : '共存节点'}] 版本 ${current.revision} · ${current.action} · ${current.status}` +
                (current.error ? '\n' + current.error : '') : '正在创建新节点（保存后将与本机已有节点共同运行）。';
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
            status.textContent = '生成密钥失败：' + error.message;
        } finally {
            keygenBtn.disabled = false;
        }
    };

    function buildPayloadSettings() {
        const proto = protocol.value;
        let nodeName = document.getElementById('deployment-name').value.trim();
        const regionVal = document.getElementById('deployment-region')?.value?.trim() || '';
        if (regionVal && typeof ProxyForgeRegions !== 'undefined') {
            nodeName = ProxyForgeRegions.applyRegionPrefix(nodeName, regionVal);
            document.getElementById('deployment-name').value = nodeName;
        }
        const tlsMode = proto === 'ss2022' ? 'none' : tlsModeEl.value;
        const settings = {
            name: nodeName,
            server: document.getElementById('deployment-server').value.trim(),
            listen_port: Number(document.getElementById('deployment-port').value),
            protocol: proto,
            tls_mode: tlsMode,
            outbound_strategy: document.getElementById('deployment-outbound-strategy').value || 'prefer_ipv4',
            outbound_mode: outModeEl.value || 'direct',
        };
        if (regionVal) settings.region = regionVal;
        const domain = document.getElementById('deployment-domain').value.trim();
        const cam = document.getElementById('deployment-camouflage').value.trim();
        if (domain) settings.domain = domain;
        if (cam) settings.camouflage_url = cam;
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
            settings.dns_provider = document.getElementById('deployment-dns-provider').value;
            const zone = document.getElementById('deployment-dns-zone').value.trim();
            if (zone) settings.dns_zone_id = zone;
            const prop = Number(document.getElementById('deployment-dns-prop').value);
            if (prop >= 10) settings.dns_propagation_seconds = Math.round(prop);
            const tok = document.getElementById('deployment-dns-token').value.trim();
            if (tok) secrets.dns_api_token = tok;
        }
        if (settings.outbound_mode === 'socks5' || settings.outbound_mode === 'ss') {
            settings.outbound_server = document.getElementById('deployment-out-server').value.trim();
            settings.outbound_port = Number(document.getElementById('deployment-out-port').value);
            if (settings.outbound_mode === 'socks5') {
                const u = document.getElementById('deployment-out-user').value.trim();
                if (u) settings.outbound_username = u;
            } else {
                settings.outbound_method = document.getElementById('deployment-out-method').value;
            }
            const outPw = document.getElementById('deployment-out-pass').value.trim();
            if (outPw) secrets.outbound_password = outPw;
        } else if (settings.outbound_mode === 'chain') {
            const collected = hopEditor.collect();
            settings.outbound_hops = collected.outbound_hops;
            if (Object.keys(collected.hop_passwords).length) {
                secrets.hop_passwords = collected.hop_passwords;
            }
        }
        return { settings, secrets: Object.keys(secrets).length ? secrets : null };
    }

    async function submit(removing) {
        const current = getSelectedNode();
        if (removing && !current) return;
        if (!confirm(removing ? `确认删除节点 ${current.settings?.name || ''} 并重载代理服务进程？` : '确认保存配置并重载/重启代理服务进程（不会重启服务器）？')) return;
        apply.disabled = true; remove.disabled = true;
        try {
            if (removing) {
                await fetchAgentJson('/agents/' + agent.id + '/nodes/' + encodeURIComponent(current.id), {
                    method: 'DELETE',
                    body: JSON.stringify({ request_id: randomRequestId() }),
                });
                currentNodeId = null;
            } else {
                const built = buildPayloadSettings();
                const body = {
                    request_id: randomRequestId(),
                    protocol: protocol.value,
                    settings: built.settings,
                };
                if (built.secrets) body.secrets = built.secrets;
                if (generatedKeyRef) body.key_ref = generatedKeyRef;
                const endpoint = current
                    ? '/agents/' + agent.id + '/nodes/' + encodeURIComponent(current.id)
                    : '/agents/' + agent.id + '/nodes';
                await fetchAgentJson(endpoint, {
                    method: current ? 'PUT' : 'POST',
                    body: JSON.stringify(body),
                });
                const tokField = document.getElementById('deployment-dns-token');
                if (tokField) tokField.value = '';
                const outPassField = document.getElementById('deployment-out-pass');
                if (outPassField) outPassField.value = '';
                hopEditor.clearSecrets();
                generatedKeyRef = null;
            }
            await refresh();
            if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
        } catch (error) {
            render(false);
            status.textContent = error.message + '；请检查端口冲突或字段格式后重试。';
        }
    }
    apply.onclick = () => submit(false);
    remove.onclick = () => submit(true);
    protocol.onchange = () => {
        const meta = LANDING_PROTO_META[protocol.value] || LANDING_PROTO_META.reality;
        if (!getSelectedNode()) {
            document.getElementById('deployment-port').value = String(meta.defaultPort);
        }
        syncTlsOptions(protocol.value);
        generatedKeyRef = null;
        render(false);
    };
    tlsModeEl.onchange = () => render(false);
    outModeEl.onchange = () => render(false);
    document.getElementById('deployment-refresh').onclick = () => refresh().catch(error => { status.textContent = error.message; });
    const firstProto = getSelectedNode()?.protocol || protocol.value;
    syncTlsOptions(LANDING_PROTO_META[firstProto] ? firstProto : 'reality', getSelectedNode()?.settings?.tls_mode);
    render(true);
}

async function showAgentJobs(agent) {
    const release = await fetchAgentJson('/agents/runtime/release');
    const owned = (await fetchAgentJson('/agents/' + agent.id + '/deployment')).deployment;
    openModal('Agent 任务', '<p>管理 ProxyForge 独立 sing-box / Caddy / go-gost 实例，及触发存量节点扫描（adopt_scan）。</p>' +
        '<p>取消任务不能保证中止已开始的服务变更，请刷新状态核实结果。</p>' +
        '<select id="agent-job-action"><option value="singbox.status">查询状态 (singbox.status)</option><option value="adopt_scan">扫描存量节点 (adopt_scan)</option></select>' +
        '<p id="agent-runtime-notice"></p><button type="button" class="btn btn-primary" id="agent-job-create">创建任务</button> ' +
        '<button type="button" class="btn" id="agent-job-refresh">刷新任务</button><p id="agent-job-notice"></p>' +
        '<div id="agent-job-list"></div>', closeModal);
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
                (job.result ? '\n' + JSON.stringify(job.result, null, 2) : '') + (job.error ? '\n' + job.error : '');
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
    openModal('存量节点完全接管 · ' + agent.name,
        '<p class="hint">经由 root 权限 runtime_helper 扫描目标主机已运行的 sing-box / xray / caddy 服务，自动提取认证凭据（UUID、密码、私钥推导 Reality 公钥、shortId）。点击「完全接管」将备份并停止原服务，无缝迁入 proxyforge-singbox 统一托管并直接加入客户端订阅（支持一键归还原服务）。</p>' +
        '<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px;">' +
        '<button type="button" class="btn btn-primary btn-sm" id="adopt-scan-trigger">🔍 一键特权扫描 (adopt_scan)</button>' +
        '<button type="button" class="btn btn-sm" id="adopt-scan-refresh">刷新扫描结果</button></div>' +
        '<p id="adopt-scan-status" class="hint"></p><div id="adopt-scan-list"></div>', () => {
            if (pollTimer) clearInterval(pollTimer);
            closeModal();
        });
    const statusEl = document.getElementById('adopt-scan-status');
    const listEl = document.getElementById('adopt-scan-list');
    const triggerBtn = document.getElementById('adopt-scan-trigger');
    triggerBtn.disabled = !agentCanRunJobs(agent);

    async function loadAdoptions() {
        const { adoptions } = await fetchAgentJson('/agents/' + agent.id + '/adoptions');
        listEl.replaceChildren();
        if (!adoptions || !adoptions.length) {
            listEl.textContent = '暂无接管扫描记录，点击上方「一键特权扫描」下发探测任务（扫描完成后将自动刷新）。';
            return;
        }
        for (const item of adoptions) {
            const card = document.createElement('div');
            card.className = 'sub-user-card';
            card.style.marginBottom = '10px';
            const head = document.createElement('div');
            head.className = 'sub-user-header';
            const title = document.createElement('strong');
            title.textContent = `[${item.core}] ${item.custom_name || item.tag || item.service_name} (${item.protocol} :${item.listen_port})`;
            const badge = document.createElement('span');
            const isAdopted = item.adopted_status === 'adopted';
            const isAuxCaddy = item.core === 'caddy' || item.protocol === 'caddy-site';
            badge.className = `status-pill ${isAdopted ? 'is-online' : (isAuxCaddy ? 'is-online' : (item.has_credentials ? 'is-degraded' : 'is-offline'))}`;
            badge.textContent = isAdopted
                ? '已完全接管 · 已入订阅'
                : (isAuxCaddy
                    ? '关联伪装站（运行中，无需单独接管）'
                    : (item.has_credentials ? '已提取凭据 · 可一键接管' : (item.adoptable ? '待特权提取凭据' : '仅观测')));
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
            if (isAuxCaddy) {
                const auxNote = document.createElement('div');
                auxNote.className = 'hint';
                auxNote.style.marginTop = '4px';
                auxNote.textContent = 'ℹ️ 宿主机回环 TLS / 伪装站辅助服务（如 NodePilot Caddy）。接管上方代理节点时将保持本服务原样运行，无需单独接管。';
                notes.push(auxNote);
            }
            if (item.has_xray_xver) {
                const xverNote = document.createElement('div');
                xverNote.className = 'hint';
                xverNote.style.marginTop = '4px';
                xverNote.textContent = '⚠️ 原 Xray Reality 启用了 xver PROXY Protocol；若宿主机回环 Caddy 强制 proxy_protocol fallback_policy=REJECT，迁入 sing-box 后回落探测可能被拒（可将 Caddy 改为 IGNORE 或改用 ProxyForge 新建节点）。';
                notes.push(xverNote);
            }

            const actions = document.createElement('div');
            actions.className = 'item-actions';
            actions.style.marginTop = '6px';
            if (isAdopted) {
                const retBtn = document.createElement('button');
                retBtn.type = 'button';
                retBtn.className = 'btn btn-danger btn-sm';
                retBtn.textContent = '↩️ 归还原服务';
                retBtn.onclick = async () => {
                    if (!confirm(`确认从 proxyforge-singbox 移除 ${item.tag || item.listen_port} 并恢复启动原服务 ${item.service_name || ''}？`)) return;
                    retBtn.disabled = true;
                    try {
                        await fetchAgentJson(`/agents/${agent.id}/adoptions/${encodeURIComponent(item.source_key)}/return`, {
                            method: 'POST',
                            body: JSON.stringify({ request_id: randomRequestId() }),
                        });
                        statusEl.textContent = '已下发归还原服务任务，代理服务重载后原服务将自动恢复运行。';
                        await loadAdoptions();
                        if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
                    } catch (e) {
                        statusEl.textContent = '归还失败：' + e.message;
                        retBtn.disabled = false;
                    }
                };
                actions.append(retBtn);
            } else if (!isAuxCaddy && item.adoptable) {
                const adoptBtn = document.createElement('button');
                adoptBtn.type = 'button';
                adoptBtn.className = 'btn btn-primary btn-sm';
                adoptBtn.disabled = !item.has_credentials;
                adoptBtn.textContent = item.has_credentials ? '🚀 完全接管 (停用原服务并加入订阅)' : '请先点击上方特权扫描提取凭据';
                adoptBtn.onclick = async () => {
                    if (!confirm(`确认完全接管 [${item.core}] :${item.listen_port}？系统将备份并停止原服务 ${item.service_name || ''}，将其无缝并入 proxyforge-singbox 并直接加入客户端订阅。`)) return;
                    adoptBtn.disabled = true;
                    try {
                        const defaultName = item.custom_name || `${agent.name}-${item.protocol}-${item.listen_port}`;
                        const finalName = typeof ProxyForgeRegions !== 'undefined' && agent.region
                            ? ProxyForgeRegions.applyRegionPrefix(defaultName, agent.region)
                            : defaultName;
                        await fetchAgentJson(`/agents/${agent.id}/adoptions/${encodeURIComponent(item.source_key)}/adopt`, {
                            method: 'POST',
                            body: JSON.stringify({
                                request_id: randomRequestId(),
                                custom_name: finalName,
                                server_override: agent.public_ipv4 || agent.public_ipv6 || agent.observed_ip || '',
                            }),
                        });
                        statusEl.textContent = '已下发完全接管任务，该存量节点已加入受管清单与客户端订阅！';
                        await loadAdoptions();
                        if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
                    } catch (e) {
                        statusEl.textContent = '接管失败：' + e.message;
                        adoptBtn.disabled = false;
                    }
                };
                actions.append(adoptBtn);
            }
            card.append(head, meta, cfg, ...notes);
            if (actions.childNodes && actions.childNodes.length) card.append(actions);
            else if (actions.children && actions.children.length) card.append(actions);
            listEl.append(card);
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
    openModal('go-gost 转发 / Best Exit / 流量 · ' + agent.name,
        '<div id="fwd-traffic-summary" class="hint" style="margin-bottom:10px;">正在读取流量计数…</div>' +
        '<p id="fwd-notice" class="hint"></p>' +
        '<h4 style="margin:8px 0 4px;">端口转发规则</h4><div id="fwd-list"></div>' +
        '<details style="margin:10px 0;"><summary>➕ 新建端口转发规则</summary><div class="form-grid" style="margin-top:8px;">' +
        '<div class="form-group"><label>规则名称</label><input id="fwd-name" placeholder="hk-relay-443"></div>' +
        '<div class="form-group"><label>入口监听端口</label><input id="fwd-port" type="number" min="1" max="65535" value="10000"></div>' +
        '<div class="form-group"><label>协议</label><select id="fwd-proto"><option value="tcp+udp">tcp+udp</option><option value="tcp">tcp</option><option value="udp">udp</option></select></div>' +
        '<div class="form-group"><label>模式</label><select id="fwd-mode"><option value="direct">直连转发 (direct)</option><option value="chain">多跳隧道 (chain)</option><option value="best_exit">Best Exit 优选组</option></select></div>' +
        '<div class="form-group"><label>Proxy Protocol</label><select id="fwd-pp"><option value="0">0 (关闭)</option><option value="1">1 (v1)</option><option value="2">2 (v2)</option></select></div>' +
        '<div class="form-group"><label>关联多跳隧道 (chain 模式可选)</label><select id="fwd-chain-id"><option value="">无</option></select></div>' +
        '<div class="form-group"><label>关联 Best Exit 组 (best_exit 模式)</label><select id="fwd-exit-group"><option value="">无</option></select></div>' +
        '<div class="form-group full-width"><label>目标地址列表 (direct 模式，每行 host:port 或 名称|host:port)</label><textarea id="fwd-targets" rows="2" placeholder="198.51.100.10:443"></textarea></div>' +
        '</div><button type="button" class="btn btn-primary btn-sm" id="fwd-create-btn">创建转发</button></details>' +
        '<h4 style="margin:12px 0 4px;">Best Exit 自动优选组</h4><div id="best-exit-list"></div>' +
        '<details style="margin-top:8px;"><summary>➕ 新建 Best Exit 出口组</summary><div class="form-grid" style="margin-top:8px;">' +
        '<div class="form-group"><label>出口组名称</label><input id="be-name" placeholder="jp-exits"></div>' +
        '<div class="form-group"><label>连续确认轮数</label><input id="be-rounds" type="number" min="1" max="20" value="3"></div>' +
        '<div class="form-group"><label>冷却秒数</label><input id="be-cooldown" type="number" min="0" max="3600" value="30"></div>' +
        '<div class="form-group full-width"><label>候选出口列表 (每行 id,名称,host:port)</label><textarea id="be-exits" rows="3" placeholder="ex1,Tokyo-1,192.0.2.101:443\nex2,Tokyo-2,192.0.2.102:443"></textarea></div>' +
        '</div><button type="button" class="btn btn-primary btn-sm" id="be-create-btn">创建出口组</button></details>' +
        '<div style="margin-top:10px;"><button type="button" class="btn btn-sm" id="fwd-refresh-btn">刷新面板</button></div>', closeModal);

    const notice = document.getElementById('fwd-notice');
    const capable = agentCanGost(agent);
    document.getElementById('fwd-create-btn').disabled = !capable;
    document.getElementById('be-create-btn').disabled = !capable;
    if (!capable) notice.textContent = '当前 Agent 尚未启用 go-gost 协议能力 (gost_protocol_version=1)，仅可查看现有记录。';

    async function loadAll() {
        const [traffic, fwdRes, beRes, chainRes] = await Promise.all([
            fetchAgentJson('/agents/' + agent.id + '/traffic'),
            fetchAgentJson('/agents/' + agent.id + '/forwards'),
            fetchAgentJson('/agents/' + agent.id + '/best-exits'),
            fetchAgentJson('/agents/tunnels/chains'),
        ]);
        document.getElementById('fwd-traffic-summary').textContent =
            `累计流量: 总计 ${formatAgentBytes(traffic.total_bytes)} (上行 ${formatAgentBytes(traffic.tx_bytes)} / 下行 ${formatAgentBytes(traffic.rx_bytes)})`;

        const chainSel = document.getElementById('fwd-chain-id');
        chainSel.replaceChildren();
        const cEmpty = document.createElement('option'); cEmpty.value = ''; cEmpty.textContent = '无'; chainSel.append(cEmpty);
        for (const ch of (chainRes.chains || [])) {
            const opt = document.createElement('option'); opt.value = ch.id; opt.textContent = ch.name; chainSel.append(opt);
        }
        const beSel = document.getElementById('fwd-exit-group');
        beSel.replaceChildren();
        const bEmpty = document.createElement('option'); bEmpty.value = ''; bEmpty.textContent = '无'; beSel.append(bEmpty);
        for (const grp of (beRes.groups || [])) {
            const opt = document.createElement('option'); opt.value = grp.id; opt.textContent = grp.name; beSel.append(opt);
        }

        const fwdList = document.getElementById('fwd-list');
        fwdList.replaceChildren();
        const forwards = fwdRes.forwards || [];
        if (!forwards.length) {
            fwdList.textContent = '暂无转发规则。';
        } else {
            for (const f of forwards) {
                const card = document.createElement('div'); card.className = 'sub-user-card'; card.style.marginBottom = '8px';
                const head = document.createElement('div'); head.className = 'sub-user-header';
                const title = document.createElement('strong');
                title.textContent = `${f.name} · :${f.listen_port} (${f.protocol} / ${f.mode})`;
                const pill = document.createElement('span'); pill.className = `status-pill ${f.enabled ? 'is-online' : 'is-offline'}`;
                pill.textContent = f.enabled ? '运行中' : '已停用';
                head.append(title, pill);
                const info = document.createElement('div'); info.className = 'hint';
                const targetText = (f.targets || []).map(t => t.addr).join(', ') || (f.exit_group_id ? 'BestExit:' + f.exit_group_id : f.chain_id || '-');
                info.textContent = `出口: ${targetText} · 流量: ${formatAgentBytes(f.total_bytes)} (↓${formatAgentBytes(f.rx_bytes)} / ↑${formatAgentBytes(f.tx_bytes)})` +
                    (f.job_status ? ` · 任务: ${f.job_status}` : '');
                const acts = document.createElement('div'); acts.className = 'item-actions';
                const toggleBtn = document.createElement('button'); toggleBtn.type = 'button'; toggleBtn.className = 'btn btn-sm';
                toggleBtn.textContent = f.enabled ? '停用' : '启用';
                toggleBtn.onclick = async () => {
                    try {
                        await fetchAgentJson('/agents/' + agent.id + '/forwards/' + f.id + '/toggle', {
                            method: 'POST', body: JSON.stringify({ request_id: randomRequestId(), enabled: !f.enabled })
                        });
                        await loadAll();
                    } catch (e) { notice.textContent = e.message; }
                };
                const delBtn = document.createElement('button'); delBtn.type = 'button'; delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = '删除';
                delBtn.onclick = async () => {
                    if (!confirm(`确认删除转发规则 ${f.name}？`)) return;
                    try {
                        await fetchAgentJson('/agents/' + agent.id + '/forwards/' + f.id + '?request_id=' + encodeURIComponent(randomRequestId()), { method: 'DELETE' });
                        await loadAll();
                    } catch (e) { notice.textContent = e.message; }
                };
                acts.append(toggleBtn, delBtn);
                card.append(head, info, acts);
                fwdList.append(card);
            }
        }

        const beList = document.getElementById('best-exit-list');
        beList.replaceChildren();
        const groups = beRes.groups || [];
        if (!groups.length) {
            beList.textContent = '暂无 Best Exit 出口组。';
        } else {
            for (const g of groups) {
                const card = document.createElement('div'); card.className = 'sub-user-card'; card.style.marginBottom = '8px';
                const title = document.createElement('strong');
                title.textContent = `${g.name} · 当前生效: ${g.active_exit_id || '-'}` +
                    (g.candidate_exit_id ? ` · 候选: ${g.candidate_exit_id} (${g.candidate_rounds}/${g.confirmation_rounds})` : '');
                const desc = document.createElement('div'); desc.className = 'hint';
                desc.textContent = (g.exits || []).map(ex => {
                    const m = (g.metrics || {})[ex.id];
                    return `${ex.id}(${ex.addr})` + (m && m.score != null ? ` score=${Number(m.score).toFixed(1)}ms` : '');
                }).join(' | ');
                const evalRow = document.createElement('div'); evalRow.className = 'item-actions';
                const probeInputs = new Map();
                for (const ex of (g.exits || [])) {
                    const inp = document.createElement('input');
                    inp.type = 'number'; inp.min = '0'; inp.style.width = '78px';
                    inp.title = ex.id + ' 延迟 (ms)';
                    inp.placeholder = ex.id + ' ms';
                    inp.value = '50';
                    probeInputs.set(ex.id, inp);
                    evalRow.append(inp);
                }
                const evalBtn = document.createElement('button'); evalBtn.type = 'button'; evalBtn.className = 'btn btn-sm'; evalBtn.textContent = '提交延迟评测';
                evalBtn.onclick = async () => {
                    const probes = {};
                    for (const [eid, inp] of probeInputs.entries()) {
                        const ms = Math.max(0, Number(inp.value) || 0);
                        probes[eid] = { entry_latency_ms: ms, exit_latency_ms: ms, entry_loss_pct: 0, exit_loss_pct: 0 };
                    }
                    try {
                        const res = await fetchAgentJson('/agents/best-exits/' + g.id + '/evaluate', {
                            method: 'POST', body: JSON.stringify({ request_id: randomRequestId(), probes })
                        });
                        notice.textContent = res.decision?.switched ? `已切换至最优出口 ${res.group.active_exit_id}` :
                            `已评估 ${g.name}（候选轮次 ${res.decision?.candidate_rounds || 0}/${g.confirmation_rounds}）`;
                        await loadAll();
                    } catch (e) { notice.textContent = e.message; }
                };
                const delBtn = document.createElement('button'); delBtn.type = 'button'; delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = '删除';
                delBtn.onclick = async () => {
                    if (!confirm(`确认删除 Best Exit 组 ${g.name}？`)) return;
                    try {
                        await fetchAgentJson('/agents/best-exits/' + g.id + '?request_id=' + encodeURIComponent(randomRequestId()), { method: 'DELETE' });
                        await loadAll();
                    } catch (e) { notice.textContent = e.message; }
                };
                evalRow.append(evalBtn, delBtn);
                card.append(title, desc, evalRow);
                beList.append(card);
            }
        }
    }

    document.getElementById('fwd-create-btn').onclick = async () => {
        try {
            const mode = document.getElementById('fwd-mode').value;
            const body = {
                request_id: randomRequestId(),
                name: document.getElementById('fwd-name').value.trim(),
                listen_port: Math.round(Number(document.getElementById('fwd-port').value)),
                protocol: document.getElementById('fwd-proto').value,
                mode,
                proxy_protocol: Number(document.getElementById('fwd-pp').value) || 0,
            };
            const targets = parseForwardTargetsInput(document.getElementById('fwd-targets').value);
            if (targets.length) body.targets = targets;
            const chainId = document.getElementById('fwd-chain-id').value;
            if (chainId) body.chain_id = chainId;
            const grpId = document.getElementById('fwd-exit-group').value;
            if (grpId) body.exit_group_id = grpId;
            await fetchAgentJson('/agents/' + agent.id + '/forwards', { method: 'POST', body: JSON.stringify(body) });
            notice.textContent = '转发规则已下发。';
            await loadAll();
        } catch (e) { notice.textContent = '创建转发失败：' + e.message; }
    };

    document.getElementById('be-create-btn').onclick = async () => {
        try {
            const exits = String(document.getElementById('be-exits').value || '').split(/\n+/).map(s => s.trim()).filter(Boolean).map((line, idx) => {
                const parts = line.split(',').map(p => p.trim());
                if (parts.length >= 3) return { id: parts[0], name: parts[1], addr: parts[2] };
                if (parts.length === 2) return { id: 'ex' + (idx + 1), name: parts[0], addr: parts[1] };
                return { id: 'ex' + (idx + 1), name: 'exit-' + (idx + 1), addr: parts[0] };
            });
            await fetchAgentJson('/agents/' + agent.id + '/best-exits', {
                method: 'POST',
                body: JSON.stringify({
                    request_id: randomRequestId(),
                    name: document.getElementById('be-name').value.trim(),
                    confirmation_rounds: Math.max(1, Math.round(Number(document.getElementById('be-rounds').value) || 3)),
                    cooldown_seconds: Math.max(0, Math.round(Number(document.getElementById('be-cooldown').value) || 30)),
                    exits,
                }),
            });
            notice.textContent = 'Best Exit 出口组已创建。';
            await loadAll();
        } catch (e) { notice.textContent = '创建出口组失败：' + e.message; }
    };

    document.getElementById('fwd-refresh-btn').onclick = () => loadAll().catch(e => { notice.textContent = e.message; });
    await loadAll();
}

const TUNNEL_TRANSPORT_PRESETS = [
    ['tcp', 'relay+tcp (国内↔IX 推荐 · 免证书 · 支持 TCP+UDP)', 'tcp', false],
    ['tls_insecure', 'relay+tls (自签加密 · 跳过证书校验 · 托管中继推荐)', 'tls', true],
    ['tls', 'relay+tls (TLS 加密 · 严格域名证书校验)', 'tls', false],
    ['wss', 'relay+wss (WebSocket TLS 隧道)', 'wss', false],
    ['quic', 'relay+quic (QUIC UDP 隧道)', 'quic', false],
];

async function showGlobalTunnelsModal() {
    openModal('多跳隧道链 & 全网流量总览',
        '<div id="global-traffic-box" style="margin-bottom:12px;">正在统计全网流量…</div>' +
        '<h4 style="margin:8px 0 4px;">已配置的 go-gost 多跳隧道链</h4><div id="global-chains-list"></div>' +
        '<details open style="margin-top:10px;"><summary>➕ 创建多跳隧道链 (支持 1~8 跳 · TCP+UDP)</summary>' +
        '<p class="hint" style="margin:6px 0;">适用于「国内中转机 → 深港 IX → 多台落地机」场景：在此定义国内入口到 IX（或更多级中继）的 go-gost 隧道，然后在入口机「转发」中选「多跳隧道链 (chain)」并按落地机分配独立入口端口即可。</p>' +
        '<div class="form-grid" style="margin-top:8px;">' +
        '<div class="form-group"><label>隧道名称 (字母/数字/短横线)</label><input id="tunnel-name" placeholder="如 cn-ix-relay"></div>' +
        '<div class="form-group"><label>入口 Agent (客户端直连的机器，如国内机)</label><select id="tunnel-entry-agent"></select></div>' +
        '</div>' +
        '<div id="tunnel-hops-editor" style="margin:8px 0;"></div>' +
        '<div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:8px;">' +
        '<button type="button" class="btn btn-sm" id="tunnel-add-hop-btn">➕ 添加下一跳 (最多 8 跳)</button>' +
        '<button type="button" class="btn btn-primary btn-sm" id="tunnel-create-btn">创建隧道链</button></div></details>' +
        '<p id="global-tunnels-notice" class="hint" style="margin-top:8px;"></p>', closeModal);

    const notice = document.getElementById('global-tunnels-notice');
    const hopsContainer = document.getElementById('tunnel-hops-editor');
    const addHopBtn = document.getElementById('tunnel-add-hop-btn');
    let cachedAgents = [];
    let tunnelHops = [
        { agent_id: '', addr: '', transport: 'tcp', server_name: '', username: 'relay', password: '' },
    ];

    function renderTunnelHopsEditor() {
        hopsContainer.replaceChildren();
        tunnelHops.forEach((hop, idx) => {
            const card = document.createElement('div');
            card.className = 'sub-user-card';
            card.style.marginBottom = '8px';

            const head = document.createElement('div');
            head.style.display = 'flex';
            head.style.gap = '6px';
            head.style.alignItems = 'center';
            head.style.marginBottom = '6px';
            const title = document.createElement('strong');
            title.textContent = `第 ${idx + 1} 跳中继`;
            const spacer = document.createElement('span');
            spacer.style.flex = '1';
            const upBtn = document.createElement('button');
            upBtn.type = 'button'; upBtn.className = 'btn btn-sm'; upBtn.textContent = '↑';
            upBtn.disabled = idx === 0;
            upBtn.onclick = () => { [tunnelHops[idx - 1], tunnelHops[idx]] = [tunnelHops[idx], tunnelHops[idx - 1]]; renderTunnelHopsEditor(); };
            const downBtn = document.createElement('button');
            downBtn.type = 'button'; downBtn.className = 'btn btn-sm'; downBtn.textContent = '↓';
            downBtn.disabled = idx === tunnelHops.length - 1;
            downBtn.onclick = () => { [tunnelHops[idx + 1], tunnelHops[idx]] = [tunnelHops[idx], tunnelHops[idx + 1]]; renderTunnelHopsEditor(); };
            const delBtn = document.createElement('button');
            delBtn.type = 'button'; delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = '✕';
            delBtn.disabled = tunnelHops.length <= 1;
            delBtn.onclick = () => { tunnelHops.splice(idx, 1); renderTunnelHopsEditor(); };
            head.append(title, spacer, upBtn, downBtn, delBtn);
            card.append(head);

            const grid = document.createElement('div');
            grid.className = 'form-grid';

            const fgAgent = document.createElement('div');
            fgAgent.className = 'form-group';
            const lAgent = document.createElement('label'); lAgent.textContent = '托管中继 Agent (选中将自动启动监听)';
            const sAgent = document.createElement('select');
            const optNone = document.createElement('option'); optNone.value = ''; optNone.textContent = '外部中继 (不托管监听)';
            sAgent.append(optNone);
            for (const a of cachedAgents) {
                const o = document.createElement('option');
                o.value = a.id;
                const ipHint = a.public_ipv4 || a.observed_ip || a.public_ipv6 || '';
                o.textContent = ipHint ? `${a.name} (${ipHint})` : a.name;
                sAgent.append(o);
            }
            sAgent.value = hop.agent_id || '';
            sAgent.onchange = () => {
                hop.agent_id = sAgent.value;
                if (hop.agent_id && !hop.addr) {
                    const picked = cachedAgents.find(a => a.id === hop.agent_id);
                    const host = picked && (picked.public_ipv4 || picked.observed_ip || picked.public_ipv6);
                    if (host) {
                        const fmtHost = host.includes(':') ? `[${host}]` : host;
                        hop.addr = `${fmtHost}:18443`;
                        renderTunnelHopsEditor();
                    }
                }
            };
            fgAgent.append(lAgent, sAgent);

            const fgAddr = document.createElement('div');
            fgAddr.className = 'form-group';
            const lAddr = document.createElement('label'); lAddr.textContent = '中继地址 host:port (如 IX_IP:18443)';
            const iAddr = document.createElement('input');
            iAddr.placeholder = '203.0.113.10:18443 或 ix.example.com:18443';
            iAddr.value = hop.addr || '';
            iAddr.oninput = () => { hop.addr = iAddr.value.trim(); };
            fgAddr.append(lAddr, iAddr);

            const fgTrans = document.createElement('div');
            fgTrans.className = 'form-group full-width';
            const lTrans = document.createElement('label'); lTrans.textContent = '隧道传输协议';
            const sTrans = document.createElement('select');
            for (const [val, lbl] of TUNNEL_TRANSPORT_PRESETS) {
                const o = document.createElement('option'); o.value = val; o.textContent = lbl; sTrans.append(o);
            }
            sTrans.value = hop.transport || 'tcp';
            sTrans.onchange = () => { hop.transport = sTrans.value; renderTunnelHopsEditor(); };
            fgTrans.append(lTrans, sTrans);

            const fgUser = document.createElement('div');
            fgUser.className = 'form-group';
            const lUser = document.createElement('label'); lUser.textContent = '认证用户名 (可选)';
            const iUser = document.createElement('input');
            iUser.value = hop.username || '';
            iUser.placeholder = 'relay';
            iUser.oninput = () => { hop.username = iUser.value.trim(); };
            fgUser.append(lUser, iUser);

            const fgPass = document.createElement('div');
            fgPass.className = 'form-group';
            const lPass = document.createElement('label'); lPass.textContent = '认证密码 (仅写入)';
            const iPass = document.createElement('input');
            iPass.type = 'password'; iPass.autocomplete = 'off';
            iPass.className = 'pf-ephemeral-secret';
            iPass.placeholder = '建议设置强密码';
            iPass.value = hop.password || '';
            iPass.oninput = () => { hop.password = iPass.value; };
            fgPass.append(lPass, iPass);

            grid.append(fgAgent, fgAddr, fgTrans, fgUser, fgPass);

            const preset = TUNNEL_TRANSPORT_PRESETS.find(p => p[0] === hop.transport) || TUNNEL_TRANSPORT_PRESETS[0];
            if (preset[2] === 'tls' || preset[2] === 'wss' || preset[2] === 'quic') {
                const fgSni = document.createElement('div');
                fgSni.className = 'form-group full-width';
                const lSni = document.createElement('label'); lSni.textContent = 'TLS SNI 域名 (可选)';
                const iSni = document.createElement('input');
                iSni.placeholder = 'relay.example.com';
                iSni.value = hop.server_name || '';
                iSni.oninput = () => { hop.server_name = iSni.value.trim(); };
                fgSni.append(lSni, iSni);
                grid.append(fgSni);
            }

            card.append(grid);
            hopsContainer.append(card);
        });
        addHopBtn.disabled = tunnelHops.length >= 8;
    }

    addHopBtn.onclick = () => {
        if (tunnelHops.length >= 8) return;
        tunnelHops.push({ agent_id: '', addr: '', transport: 'tcp', server_name: '', username: 'relay', password: '' });
        renderTunnelHopsEditor();
    };

    async function load() {
        const [summary, chainData, agentData] = await Promise.all([
            fetchAgentJson('/agents/traffic/summary'),
            fetchAgentJson('/agents/tunnels/chains'),
            fetchAgentJson('/agents'),
        ]);
        const tBox = document.getElementById('global-traffic-box');
        tBox.replaceChildren();
        const totalEl = document.createElement('strong');
        totalEl.textContent = `全网累计流量：${formatAgentBytes(summary.total_bytes)}（下行 ${formatAgentBytes(summary.rx_bytes)} / 上行 ${formatAgentBytes(summary.tx_bytes)}）`;
        tBox.append(totalEl);
        for (const row of (summary.agents || [])) {
            const p = document.createElement('div'); p.className = 'hint';
            p.textContent = `${row.agent_name}：总 ${formatAgentBytes(row.total_bytes)}（↓${formatAgentBytes(row.rx_bytes)} / ↑${formatAgentBytes(row.tx_bytes)}）`;
            tBox.append(p);
        }

        cachedAgents = agentData.agents || [];
        const entrySel = document.getElementById('tunnel-entry-agent');
        const prevEntry = entrySel.value;
        entrySel.replaceChildren();
        for (const a of cachedAgents) {
            const o1 = document.createElement('option');
            const ipHint = a.public_ipv4 || a.observed_ip || a.public_ipv6 || '';
            o1.value = a.id;
            o1.textContent = ipHint ? `${a.name} (${ipHint})` : a.name;
            entrySel.append(o1);
        }
        if (prevEntry && cachedAgents.some(a => a.id === prevEntry)) entrySel.value = prevEntry;
        renderTunnelHopsEditor();

        const chainsEl = document.getElementById('global-chains-list');
        chainsEl.replaceChildren();
        const chains = chainData.chains || [];
        if (!chains.length) {
            chainsEl.textContent = '暂无隧道链。';
        } else {
            for (const c of chains) {
                const card = document.createElement('div'); card.className = 'sub-user-card'; card.style.marginBottom = '8px';
                const entryName = cachedAgents.find(a => a.id === c.entry_agent_id)?.name || c.entry_agent_id;
                const title = document.createElement('strong');
                title.textContent = `${c.name} · 入口: ${entryName} · 版本 ${c.revision}`;
                const desc = document.createElement('div'); desc.className = 'hint';
                desc.textContent = '跳数: ' + (c.hops || []).map(h => {
                    const n0 = (h.nodes && h.nodes[0]) || null;
                    if (!n0) return h.name;
                    const proto = `${n0.connector || 'relay'}+${n0.dialer || 'tcp'}`;
                    return `${h.name}(${proto} ${n0.addr || ''})`;
                }).join(' → ');
                const delBtn = document.createElement('button'); delBtn.type = 'button'; delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = '删除';
                delBtn.onclick = async () => {
                    if (!confirm(`确认删除多跳隧道链 ${c.name}？`)) return;
                    try {
                        await fetchAgentJson('/agents/tunnels/chains/' + c.id + '?request_id=' + encodeURIComponent(randomRequestId()), { method: 'DELETE' });
                        await load();
                    } catch (e) { notice.textContent = e.message; }
                };
                card.append(title, desc, delBtn);
                chainsEl.append(card);
            }
        }
    }

    document.getElementById('tunnel-create-btn').onclick = async () => {
        try {
            const nameVal = document.getElementById('tunnel-name').value.trim();
            if (!nameVal) throw new Error('请填写隧道名称');
            const entryId = document.getElementById('tunnel-entry-agent').value;
            if (!entryId) throw new Error('请选择入口 Agent');
            const hops = [];
            tunnelHops.forEach((h, idx) => {
                const addr = (h.addr || '').trim();
                if (!addr) throw new Error(`第 ${idx + 1} 跳未填写中继地址 host:port`);
                const preset = TUNNEL_TRANSPORT_PRESETS.find(p => p[0] === h.transport) || TUNNEL_TRANSPORT_PRESETS[0];
                const node = {
                    name: `hop${idx + 1}_node`,
                    addr,
                    connector: 'relay',
                    dialer: preset[2],
                    insecure: Boolean(preset[3]),
                };
                if (h.username) node.username = h.username;
                if (h.password) node.password = h.password;
                if (h.server_name) node.server_name = h.server_name;
                if (h.agent_id) {
                    node.agent_id = h.agent_id;
                    node.serve_on_agent = true;
                }
                hops.push({ name: `hop_${idx + 1}`, nodes: [node] });
            });
            await fetchAgentJson('/agents/tunnels/chains', {
                method: 'POST',
                body: JSON.stringify({
                    request_id: randomRequestId(),
                    name: nameVal,
                    entry_agent_id: entryId,
                    hops,
                }),
            });
            tunnelHops.forEach(h => { h.password = ''; });
            renderTunnelHopsEditor();
            notice.textContent = '隧道链已创建，请前往入口 Agent「转发」中按落地机绑定端口！';
            await load();
        } catch (e) { notice.textContent = '创建隧道链失败：' + e.message; }
    };

    await load();
}

function agentStatusLabel(agent) {
    const labels = { online: '在线', degraded: '心跳延迟', offline: '离线', never_seen: '等待首次心跳', revoked: '已撤销' };
    return (labels[agent.status] || '未知') + (!agent.compatible ? ' · 协议不兼容' : '') +
        (!agent.metadata.supported ? ' · 未支持的系统' : '');
}

function _osBadgeElement(osName) {
    const osLower = String(osName || '').toLowerCase();
    const badge = document.createElement('span');
    badge.className = 'komari-os-badge';
    if (osLower.includes('debian')) badge.title = 'Debian';
    else if (osLower.includes('ubuntu')) badge.title = 'Ubuntu';
    else if (osLower.includes('alpine')) badge.title = 'Alpine Linux';
    else badge.title = osName || 'Linux';
    const label = osLower.includes('debian') ? '🌀' : (osLower.includes('ubuntu') ? '🟠' : (osLower.includes('alpine') ? '🏔️' : '🐧'));
    badge.textContent = label;
    return badge;
}

function _formatUptimeCompact(seconds) {
    const s = Math.max(0, Number(seconds || 0));
    if (s >= 86400) return `${Math.floor(s / 86400)} 天`;
    if (s >= 3600) return `${Math.floor(s / 3600)} 小时`;
    return `${Math.max(1, Math.floor(s / 60))} 分钟`;
}

function _formatExpireDays(expireAt) {
    if (!expireAt || Number(expireAt) <= 0) return '长期有效';
    const days = Math.ceil((Number(expireAt) - Date.now() / 1000) / 86400);
    return days > 0 ? `${days} 天` : '已到期';
}

function _buildSegBar(ratio, active) {
    const bar = document.createElement('div');
    bar.className = 'komari-seg-bar';
    const litCount = ratio > 0 ? Math.max(1, Math.min(20, Math.round(ratio * 20))) : 0;
    const toneClass = ratio >= 0.9 ? 'is-danger' : (ratio >= 0.7 ? 'is-warn' : 'is-good');
    for (let i = 0; i < 20; i += 1) {
        const seg = document.createElement('span');
        seg.className = 'komari-seg' + (active && i < litCount ? ' ' + toneClass : '');
        bar.append(seg);
    }
    return bar;
}

function _buildTrafficDots(active, colorClass) {
    const row = document.createElement('div');
    row.className = 'komari-dot-track';
    for (let i = 0; i < 12; i += 1) {
        const d = document.createElement('span');
        d.className = 'komari-mini-dot' + (active && i >= 6 ? ' ' + colorClass : '');
        row.append(d);
    }
    return row;
}

async function refreshAgents() {
    const target = document.getElementById('agent-list');
    try {
        const [agentsRes, trafficRes, nodesRes] = await Promise.all([
            fetchAuth('/agents'),
            fetchAuth('/agents/traffic/summary').catch(() => null),
            fetchAuth('/agents/managed/nodes').catch(() => null),
        ]);
        const { agents } = await agentsRes.json();
        const trafficData = trafficRes && trafficRes.ok !== false ? await trafficRes.json().catch(() => ({})) : {};
        const nodesData = nodesRes && nodesRes.ok !== false ? await nodesRes.json().catch(() => ({})) : {};
        const trafficByAgent = new Map((trafficData.agents || []).map(item => [item.agent_id, item]));
        const nodesByAgent = new Map();
        for (const node of (nodesData.nodes || [])) {
            const aid = node?.agent?.id;
            if (!aid || node.removed) continue;
            if (!nodesByAgent.has(aid)) nodesByAgent.set(aid, []);
            nodesByAgent.get(aid).push(node);
        }

        target.replaceChildren();
        if (!agents.length) { target.textContent = '尚无 Agent。点击「添加服务器」获取安装命令，在目标机器执行。'; return; }

        const grid = document.createElement('div');
        grid.className = 'komari-agent-grid';

        for (const agent of agents) {
            const m = agent.metadata || {};
            const tr = trafficByAgent.get(agent.id) || { rx_bytes: 0, tx_bytes: 0, total_bytes: 0 };
            const agentNodes = nodesByAgent.get(agent.id) || [];

            const card = document.createElement('article');
            card.className = 'komari-agent-card';

            // Header row: flag + os + name + status dot + expand detail button
            const head = document.createElement('div');
            head.className = 'komari-card-head';
            const headLeft = document.createElement('div');
            headLeft.className = 'komari-head-left';

            let flagChar = '🌐';
            if (typeof ProxyForgeRegions !== 'undefined') {
                const reg = ProxyForgeRegions.matchRegion(agent.region || agent.name);
                if (reg) flagChar = reg.flag;
            }
            const flagEl = document.createElement('span');
            flagEl.className = 'komari-flag';
            flagEl.textContent = flagChar;

            const titleEl = document.createElement('span');
            titleEl.className = 'komari-card-title';
            titleEl.textContent = agent.name;

            headLeft.append(flagEl, _osBadgeElement(m.os), titleEl);

            const headRight = document.createElement('div');
            headRight.className = 'komari-head-right';
            const dot = document.createElement('span');
            dot.className = `komari-status-dot is-${agent.status || 'offline'}`;
            dot.title = agentStatusLabel(agent);
            const expandBtn = document.createElement('button');
            expandBtn.type = 'button';
            expandBtn.className = 'komari-expand-btn';
            expandBtn.title = '查看 Agent 详情';
            expandBtn.textContent = '↗';
            expandBtn.onclick = () => agentAction(agent, 'details').catch(error => showToast(error.message, 'error'));
            headRight.append(dot, expandBtn);
            head.append(headLeft, headRight);
            card.append(head);

            // Subtitle: OS Version · Arch · IP
            const sub = document.createElement('div');
            sub.className = 'komari-card-sub';
            const primaryIp = agent.public_ipv4 || agent.observed_ip || m.hostname || '';
            sub.textContent = `${m.os || 'linux'} ${m.os_version || ''} · ${m.arch || ''}` +
                (primaryIp ? ` · ${primaryIp}` : '') +
                (agent.public_ipv6 ? ' · IPv6' : '');
            card.append(sub);

            // Traffic section (Komari style without hardware bars)
            const trafficBox = document.createElement('div');
            trafficBox.className = 'komari-traffic-box';
            const tRow = document.createElement('div');
            tRow.className = 'komari-traffic-cols';

            const upCol = document.createElement('div');
            upCol.className = 'komari-traffic-col';
            const upHead = document.createElement('div');
            upHead.className = 'komari-traffic-line';
            const upLbl = document.createElement('span'); upLbl.className = 'komari-lbl-up'; upLbl.textContent = '↑ 出站';
            const upVal = document.createElement('span'); upVal.className = 'komari-val-up'; upVal.textContent = formatAgentBytes(tr.tx_bytes);
            upHead.append(upLbl, upVal);
            upCol.append(upHead, _buildTrafficDots(agent.status === 'online', 'is-up'));

            const dnCol = document.createElement('div');
            dnCol.className = 'komari-traffic-col';
            const dnHead = document.createElement('div');
            dnHead.className = 'komari-traffic-line';
            const dnLbl = document.createElement('span'); dnLbl.className = 'komari-lbl-dn'; dnLbl.textContent = '↓ 入站';
            const dnVal = document.createElement('span'); dnVal.className = 'komari-val-dn'; dnVal.textContent = formatAgentBytes(tr.rx_bytes);
            dnHead.append(dnLbl, dnVal);
            dnCol.append(dnHead, _buildTrafficDots(agent.status === 'online', 'is-dn'));

            tRow.append(upCol, dnCol);
            trafficBox.append(tRow);

            const sumRow = document.createElement('div');
            sumRow.className = 'komari-traffic-summary';
            const totalLeft = document.createElement('span');
            totalLeft.textContent = `🌐 总计 ${formatAgentBytes(tr.total_bytes)}`;
            const statRight = document.createElement('span');
            statRight.textContent = agentStatusLabel(agent);
            sumRow.append(totalLeft, statRight);
            trafficBox.append(sumRow);
            card.append(trafficBox);

            // Managed cores & active nodes badges
            const coreStrip = document.createElement('div');
            coreStrip.className = 'komari-core-strip';
            const sbPill = document.createElement('span');
            sbPill.className = `komari-core-pill ${m.singbox?.running ? 'is-running' : ''}`;
            sbPill.textContent = m.singbox?.installed ? (m.singbox.running ? 'sing-box 运行中' : 'sing-box 已停') : 'sing-box 未装';
            coreStrip.append(sbPill);
            if (m.caddy?.installed) {
                const cPill = document.createElement('span');
                cPill.className = `komari-core-pill ${m.caddy.running ? 'is-running' : ''}`;
                cPill.textContent = m.caddy.running ? 'caddy ✓' : 'caddy ■';
                coreStrip.append(cPill);
            }
            if (m.gost?.installed) {
                const gPill = document.createElement('span');
                gPill.className = `komari-core-pill ${m.gost.running ? 'is-running' : ''}`;
                gPill.textContent = m.gost.running ? 'go-gost ✓' : 'go-gost ■';
                coreStrip.append(gPill);
            }
            for (const n of agentNodes.slice(0, 4)) {
                const nPill = document.createElement('span');
                nPill.className = `komari-node-pill ${n.kind === 'adopted' ? 'is-adopted' : ''}`;
                const pLabel = n.protocol ? n.protocol.toUpperCase() : (n.kind === 'chain' ? 'CHAIN' : 'NODE');
                nPill.textContent = `${pLabel} :${n.port}`;
                nPill.title = n.name;
                coreStrip.append(nPill);
            }
            if (agentNodes.length > 4) {
                const morePill = document.createElement('span');
                morePill.className = 'komari-node-pill';
                morePill.textContent = `+${agentNodes.length - 4}`;
                coreStrip.append(morePill);
            }
            card.append(coreStrip);

            // Expiry + Uptime + Quota segmented bar (matching Komari screenshot bottom)
            const metaBox = document.createElement('div');
            metaBox.className = 'komari-meta-box';
            const lifeRow = document.createElement('div');
            lifeRow.className = 'komari-life-row';
            const expSpan = document.createElement('span');
            expSpan.innerHTML = '';
            const expLbl = document.createElement('span'); expLbl.className = 'komari-muted'; expLbl.textContent = '📅 到期 ';
            const expVal = document.createElement('strong'); expVal.className = 'komari-green'; expVal.textContent = _formatExpireDays(agent.expire_at);
            expSpan.append(expLbl, expVal);

            const upSpan = document.createElement('span');
            const uLbl = document.createElement('span'); uLbl.className = 'komari-muted'; uLbl.textContent = '🔄 在线 ';
            const uVal = document.createElement('strong'); uVal.className = 'komari-blue'; uVal.textContent = _formatUptimeCompact(m.uptime);
            upSpan.append(uLbl, uVal);
            lifeRow.append(expSpan, upSpan);
            metaBox.append(lifeRow);

            const qHead = document.createElement('div');
            qHead.className = 'komari-quota-head';
            const quotaBytes = Number(agent.quota_bytes || 0);
            const usedBytes = Number(tr.total_bytes || 0);
            const qLeft = document.createElement('span');
            const qRight = document.createElement('span');
            qRight.className = 'komari-muted';
            let segRatio = 0;
            if (quotaBytes > 0) {
                const remain = Math.max(0, quotaBytes - usedBytes);
                qLeft.textContent = `🗄️ 剩余流量 ${formatAgentBytes(remain)}`;
                qRight.textContent = `${formatAgentBytes(usedBytes)} / ${formatAgentBytes(quotaBytes)}`;
                segRatio = Math.min(1, usedBytes / quotaBytes);
            } else {
                qLeft.textContent = '🗄️ 流量配额 不限';
                qRight.textContent = `已用 ${formatAgentBytes(usedBytes)}`;
                segRatio = usedBytes > 0 ? 0.1 : 0;
            }
            qHead.append(qLeft, qRight);
            metaBox.append(qHead, _buildSegBar(segRatio, usedBytes > 0 || quotaBytes > 0));
            card.append(metaBox);

            // Tags row (colored pills matching Komari)
            const tagsRow = document.createElement('div');
            tagsRow.className = 'komari-tags-row';
            const pillList = [];
            if (agent.role && agent.role !== 'unassigned') {
                pillList.push({ text: agent.role, cls: 'is-purple' });
            }
            for (const t of (agent.tags || [])) {
                pillList.push({ text: t, cls: 'is-cyan' });
            }
            if (agent.billing_label) {
                pillList.push({ text: agent.billing_label, cls: 'is-green' });
            }
            if (!pillList.length) {
                pillList.push({ text: m.agent_version ? `Agent v${m.agent_version}` : 'ProxyForge', cls: 'is-slate' });
            }
            pillList.forEach((p, idx) => {
                const el = document.createElement('span');
                const cycle = ['is-purple', 'is-cyan', 'is-green'];
                el.className = `komari-tag-pill ${p.cls || cycle[idx % cycle.length]}`;
                el.textContent = p.text;
                tagsRow.append(el);
            });
            card.append(tagsRow);

            // Card action buttons
            const actionsRow = document.createElement('div');
            actionsRow.className = 'komari-card-actions';
            for (const [label, action, extraCls] of [
                ['部署', 'deployment', 'komari-btn-primary'],
                ['转发', 'forwards', ''],
                ['接管', 'adoptions', ''],
                ['链路', 'chain', ''],
                ['任务', 'jobs', ''],
                ['编辑', 'edit', ''],
                ['撤销', 'revoke', ''],
                ['移除', 'remove', 'komari-btn-danger'],
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

async function agentAction(agent, action) {
    if (action === 'chain') {
        await showAgentChain(await (await fetchAuth('/agents/' + agent.id)).json());
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
    if (action === 'deployment') {
        await showAgentDeployment(await (await fetchAuth('/agents/' + agent.id)).json());
        return;
    }
    if (action === 'jobs') {
        await showAgentJobs(await (await fetchAuth('/agents/' + agent.id)).json());
        return;
    }
    if (action === 'details') {
        const current = await (await fetchAuth('/agents/' + agent.id)).json();
        openModal('Agent 详情', '<pre id="agent-detail" style="white-space:pre-wrap"></pre>', closeModal);
        document.getElementById('agent-detail').textContent = JSON.stringify(current, null, 2);
        return;
    }
    if (action === 'edit') {
        const expDateStr = agent.expire_at ? new Date(Number(agent.expire_at) * 1000).toISOString().slice(0, 10) : '';
        const quotaGbStr = agent.quota_bytes ? String(+(Number(agent.quota_bytes) / (1024 * 1024 * 1024)).toFixed(2)) : '';
        openModal('编辑 Agent · ' + agent.name,
            _agentRegionPickerHtml('agent-edit-region', agent.region || agent.name, '地区 / 国旗 (用于卡片国旗与部署节点自动前缀)') +
            '<div class="form-grid">' +
            '<div class="form-group"><label>名称</label><input id="agent-name"></div>' +
            '<div class="form-group"><label>角色（仅标签）</label><select id="agent-role"><option>unassigned</option><option>node</option><option>landing</option><option>both</option></select></div>' +
            '<div class="form-group"><label>到期日期 (可选)</label><input type="date" id="agent-expire" value="' + _escHtml(expDateStr) + '"></div>' +
            '<div class="form-group"><label>月流量配额 GiB (可选，留空不限)</label><input type="number" min="0" step="1" id="agent-quota-gb" value="' + _escHtml(quotaGbStr) + '" placeholder="如 2000"></div>' +
            '<div class="form-group"><label>账单 / 费用标签 (可选)</label><input id="agent-billing" value="' + _escHtml(agent.billing_label || '') + '" placeholder="如 $6.75 / 年付"></div>' +
            '<div class="form-group"><label>标签（逗号分隔）</label><input id="agent-tags" placeholder="如 CN2 GIA, 家宽"></div>' +
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
                    const expVal = document.getElementById('agent-expire')?.value?.trim() || '';
                    const expireAt = expVal ? Math.floor(Date.parse(expVal + 'T23:59:59Z') / 1000) : null;
                    const quotaGbRaw = document.getElementById('agent-quota-gb')?.value?.trim() || '';
                    const quotaBytes = quotaGbRaw && Number(quotaGbRaw) > 0 ? Math.round(Number(quotaGbRaw) * 1024 * 1024 * 1024) : null;
                    const billingLabel = document.getElementById('agent-billing')?.value?.trim() || '';
                    await fetchAuth('/agents/' + agent.id, { method: 'PATCH', body: JSON.stringify({
                        name: document.getElementById('agent-name').value,
                        role: document.getElementById('agent-role').value,
                        tags: document.getElementById('agent-tags').value.split(',').map(s => s.trim()).filter(Boolean),
                        region: regionCode,
                        expire_at: expireAt,
                        quota_bytes: quotaBytes,
                        billing_label: billingLabel,
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
        '<p class="hint">支持 Komari 风格一条命令完成下载校验、安装与自动注册，并按需勾选 Runtime / 预装内核 / 存量接管。</p>' +
        '<div id="agent-quick-box" class="quick-install-box" hidden>' +
        _agentRegionPickerHtml('new-agent-region', '', '服务器地区 / 国旗 (可选，自动添加到名称前)') +
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
        '<details id="agent-legacy-details"><summary>传统 GitHub 固定 Commit 手动校验与交互凭据（兼容旧流程）</summary>' +
        '<p class="hint">要求：Debian 12/13 或 Ubuntu 22.04/24.04，amd64/arm64，systemd、Python 3.9+。</p>' +
        '<div id="agent-install-commands"></div>' +
        '<p><a href="https://github.com/km-hl/ProxyForge/blob/master/docs/AGENT_INSTALL.md" target="_blank" rel="noopener noreferrer">中文安装、升级与恢复指南</a></p>' +
        '<div id="agent-registration-result" hidden><p>一次性注册凭据（10 分钟有效，仅可消费一次）：</p>' +
        '<input id="agent-registration-token" aria-label="一次性注册凭据" readonly autocomplete="off">' +
        '<p id="agent-registration-expiry"></p>' +
        '<p class="hint">关闭后不再显示。安装结束后关闭此窗口并刷新服务器列表，确认状态为在线。</p></div>' +
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
    document.getElementById('agent-tunnels-btn')?.addEventListener('click', () => showGlobalTunnelsModal().catch(error => showToast(error.message, 'error')));
    document.getElementById('agent-refresh-btn').addEventListener('click', refreshAgents);
    document.querySelector('[data-panel="panel-agents"]').addEventListener('click', refreshAgents);
    modalClose.addEventListener('click', clearRegistrationToken);
    modalCancel.addEventListener('click', clearRegistrationToken);
    modalOverlay.addEventListener('keydown', event => { if (event.key === 'Escape') clearRegistrationToken(); });
    setInterval(() => {
        if (document.getElementById('panel-agents').classList.contains('active') && dashboard.style.display !== 'none')
            refreshAgents();
    }, 30000);
}
if (typeof module !== 'undefined' && module.exports) module.exports = { agentStatusLabel, agentCanRunJobs, agentCanManageRuntime, agentCanDeploy, agentCanLand, agentCanChain, agentCanGost, buildQuickInstallCommand };
