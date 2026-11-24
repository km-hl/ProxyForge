/* Multi-user subscription management panel & visual node authorization picker. */
(function (root) {
    'use strict';

    const esc = (v) => (typeof ProxyForgeHtmlUtils !== 'undefined' ? ProxyForgeHtmlUtils.escapeHtml(v) : String(v ?? ''));

    const DISABLED_REASON_LABELS = {
        expired: '已过期',
        quota_exceeded: '流量已用尽',
        disabled: '已停用',
    };

    const PROTO_LABELS = {
        reality: 'REALITY',
        'vless-reality': 'REALITY',
        vless: 'VLESS',
        trojan: 'TROJAN',
        anytls: 'ANYTLS',
        hysteria2: 'HY2',
        ss2022: 'SS2022',
        ss: 'SS',
        vmess: 'VMESS',
        tuic: 'TUIC',
    };

    function formatSubBytes(bytes) {
        const val = Math.max(0, Number(bytes) || 0);
        if (val === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let idx = Math.floor(Math.log(val) / Math.log(1024));
        if (idx >= units.length) idx = units.length - 1;
        return `${parseFloat((val / Math.pow(1024, idx)).toFixed(2))} ${units[idx]}`;
    }

    function formatExpireAt(expireAt) {
        if (!expireAt || Number(expireAt) <= 0) return '长期有效';
        const d = new Date(Number(expireAt) * 1000);
        if (Number.isNaN(d.getTime())) return '长期有效';
        const pad = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
    }

    function toLocalDatetimeInputValue(unixSeconds) {
        if (!unixSeconds || Number(unixSeconds) <= 0) return '';
        const d = new Date(Number(unixSeconds) * 1000);
        if (Number.isNaN(d.getTime())) return '';
        const pad = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    }

    function selectedFormat() {
        const sel = document.getElementById('sub-users-format');
        return (sel && sel.value) ? sel.value : 'auto';
    }

    function buildUserSubUrl(token, user, fmtOverride) {
        const baseName = (document.getElementById('sub-name')?.value || '').trim() || 'ProxyForge';
        const name = user?.username ? `${baseName}-${user.username}` : baseName;
        const fmt = fmtOverride || selectedFormat();
        const opts = user?.prefer_relay ? { preferRelay: true } : {};
        return ProxyForgeSubscription.buildUserUrl(window.location.origin, token, name, fmt, opts);
    }

    async function fetchUserTokenAndAct(user, mode) {
        const res = await fetchAuth(`/sub-users/${encodeURIComponent(user.id)}/token`);
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
        const data = await res.json();
        const url = buildUserSubUrl(data.token, user);
        if (mode === 'qr') openSubscriptionQrModal(url, `${user.username} 订阅二维码`);
        else await copyTextToClipboard(url, `已复制 ${user.username} 的订阅链接`);
    }

    function statusBadgeInfo(user) {
        if (user.enabled) return { cls: 'is-online', label: '启用中' };
        const label = DISABLED_REASON_LABELS[user.disabled_reason] || '已停用';
        return { cls: 'is-offline', label };
    }

    function renderSubUsers() {
        const container = document.getElementById('sub-users-list');
        if (!container) return;
        container.replaceChildren();
        const users = (typeof state !== 'undefined' && Array.isArray(state.subUsers)) ? state.subUsers : [];
        if (!users.length) {
            const empty = document.createElement('div');
            empty.className = 'empty-state';
            empty.textContent = '暂无订阅用户';
            container.appendChild(empty);
            return;
        }

        const grid = document.createElement('div');
        grid.className = 'sub-users-grid';
        for (const user of users) {
            const card = document.createElement('div');
            card.className = 'sub-user-card';

            const header = document.createElement('div');
            header.className = 'sub-user-header';
            const titleWrap = document.createElement('div');
            titleWrap.className = 'sub-user-title-wrap';
            const nameEl = document.createElement('strong');
            nameEl.textContent = user.username;
            titleWrap.appendChild(nameEl);
            if (user.mark_id) {
                const markEl = document.createElement('span');
                markEl.className = 'sub-user-id-tag';
                markEl.textContent = `#${user.mark_id}`;
                titleWrap.appendChild(markEl);
            }
            const prefixEl = document.createElement('span');
            prefixEl.className = 'sub-user-meta';
            prefixEl.textContent = user.token_prefix || '';
            titleWrap.appendChild(prefixEl);

            const st = statusBadgeInfo(user);
            const badge = document.createElement('span');
            badge.className = `status-pill ${st.cls}`;
            badge.textContent = st.label;
            header.append(titleWrap, badge);
            card.appendChild(header);

            const used = Math.max(0, Number(user.used_bytes || 0));
            const quota = Math.max(0, Number(user.quota_bytes || 0));
            const pct = quota > 0 ? Math.min(100, Math.round((used / quota) * 100)) : 0;

            const barTrack = document.createElement('div');
            barTrack.className = 'quota-bar-track';
            const barFill = document.createElement('div');
            barFill.className = `quota-bar-fill${(quota > 0 && pct >= 90) ? ' danger' : ''}`;
            barFill.style.width = quota > 0 ? `${pct}%` : '0%';
            barTrack.appendChild(barFill);
            card.appendChild(barTrack);

            const usageLine = document.createElement('div');
            usageLine.className = 'sub-user-meta';
            if (quota > 0) {
                const rem = Math.max(0, quota - used);
                usageLine.textContent = `已用 ${formatSubBytes(used)} / ${formatSubBytes(quota)} (${pct}%) · 剩余 ${formatSubBytes(rem)}`;
            } else {
                usageLine.textContent = `已用 ${formatSubBytes(used)} / 不限`;
            }
            card.appendChild(usageLine);

            const splitLine = document.createElement('div');
            splitLine.className = 'sub-user-meta';
            splitLine.textContent = `上行 ${formatSubBytes(user.upload_bytes)} · 下行 ${formatSubBytes(user.download_bytes)}`;
            card.appendChild(splitLine);

            const metaLine = document.createElement('div');
            metaLine.className = 'sub-user-meta';
            const nodeCount = Array.isArray(user.allowed_nodes) ? user.allowed_nodes.length : 0;
            const tags = [
                `到期 ${formatExpireAt(user.expire_at)}`,
                `节点 ${nodeCount}`,
            ];
            if (user.reset_day > 0) tags.push(`每月 ${user.reset_day} 日重置`);
            if (user.info_nodes) tags.push('顶部状态节点');
            metaLine.textContent = tags.join(' · ');
            card.appendChild(metaLine);

            const actions = document.createElement('div');
            actions.className = 'sub-user-actions';
            const addBtn = (label, cls, handler) => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = cls;
                btn.textContent = label;
                btn.addEventListener('click', handler);
                actions.appendChild(btn);
            };
            addBtn('复制链接', 'btn btn-primary btn-sm', () => fetchUserTokenAndAct(user, 'copy').catch(e => showToast(e.message, 'error')));
            addBtn('二维码', 'btn btn-sm', () => fetchUserTokenAndAct(user, 'qr').catch(e => showToast(e.message, 'error')));
            addBtn('编辑', 'btn btn-sm', () => openSubUserModal(user));
            addBtn(user.enabled ? '停用' : '启用', 'btn btn-sm', () => toggleSubUser(user));
            addBtn('重置流量', 'btn btn-sm', () => resetSubUserTraffic(user));
            addBtn('轮换密钥', 'btn btn-sm', () => rotateSubUser(user));
            addBtn('删除', 'btn btn-danger btn-sm', () => deleteSubUser(user));
            card.appendChild(actions);

            grid.appendChild(card);
        }
        container.appendChild(grid);
    }

    async function loadSubUsers() {
        const container = document.getElementById('sub-users-list');
        if (!container) return;
        try {
            const res = await fetchAuth('/sub-users');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            if (typeof state !== 'undefined') state.subUsers = data.users || [];
            renderSubUsers();
        } catch (e) {
            container.textContent = `加载订阅用户失败：${e.message}`;
        }
    }

    function buildResetDayOptions(selectedDay) {
        const current = Number(selectedDay) || 0;
        let html = `<option value="0"${current === 0 ? ' selected' : ''}>不自动重置</option>`;
        for (let d = 1; d <= 28; d++) {
            html += `<option value="${d}"${current === d ? ' selected' : ''}>每月 ${d} 日</option>`;
        }
        return html;
    }

    function renderNodePickerList(nodes, selectedSet, query) {
        const q = String(query || '').trim().toLowerCase();
        const filtered = nodes.filter(n => {
            if (!q) return true;
            const hay = `${n.agent_name || ''} ${n.name || ''} ${n.protocol || ''} ${n.server || ''}`.toLowerCase();
            return hay.includes(q);
        });
        if (!filtered.length) {
            return `<div class="su-node-empty">${nodes.length ? '无匹配节点' : '暂无可用节点'}</div>`;
        }
        const groups = new Map();
        for (const n of filtered) {
            const gName = n.agent_name || (n.source === 'manual' ? '手工节点' : '其他');
            if (!groups.has(gName)) groups.set(gName, []);
            groups.get(gName).push(n);
        }
        let html = '';
        for (const [groupName, items] of groups.entries()) {
            html += `<div class="su-node-group-title">${esc(groupName)}</div>`;
            for (const n of items) {
                const checked = selectedSet.has(n.key) ? ' checked' : '';
                const protoText = PROTO_LABELS[String(n.protocol || '').toLowerCase()] || String(n.protocol || '').toUpperCase();
                const credBadge = n.supports_independent_creds
                    ? '<span class="su-cred-pill is-indep">独立凭据</span>'
                    : '<span class="su-cred-pill is-shared">共用凭据</span>';
                const relayBadge = n.has_relay_rewrite
                    ? '<span class="su-cred-pill is-relay">中转</span>'
                    : '';
                html += `
                    <label class="su-node-row">
                        <input type="checkbox" class="su-node-cb" value="${esc(n.key)}"${checked}>
                        <span class="su-node-name">${esc(n.name)}</span>
                        <span class="su-node-badges">
                            ${protoText ? `<span class="su-cred-pill">${esc(protoText)}</span>` : ''}
                            ${credBadge}
                            ${relayBadge}
                        </span>
                    </label>
                `;
            }
        }
        return html;
    }

    async function openSubUserModal(existing = null) {
        const isNew = !existing;
        let availableNodes = [];
        let loadError = '';
        try {
            const res = await fetchAuth('/sub-users/available-nodes');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            availableNodes = Array.isArray(data.nodes) ? data.nodes : [];
        } catch (e) {
            loadError = `节点列表加载失败：${e.message}`;
        }

        const selectedSet = new Set(Array.isArray(existing?.allowed_nodes) ? existing.allowed_nodes : []);
        const quotaGbInit = existing?.quota_bytes ? +(existing.quota_bytes / (1024 * 1024 * 1024)).toFixed(2) : 0;
        const expireInit = existing ? toLocalDatetimeInputValue(existing.expire_at) : '';
        const infoNodesInit = existing ? Boolean(existing.info_nodes) : true;
        const enabledInit = existing ? Boolean(existing.enabled) : true;

        const html = `
            <div id="m-su-error" class="su-error-banner"${loadError ? '' : ' hidden'}>${esc(loadError)}</div>
            <div class="deploy-section">
                <div class="deploy-section-title">基本信息与配额</div>
                <div class="form-grid">
                    <div class="form-group">
                        <label for="m-su-username">用户名</label>
                        <input type="text" id="m-su-username" value="${esc(existing?.username || '')}" placeholder="alice"${isNew ? '' : ' disabled'}>
                    </div>
                    <div class="form-group">
                        <label for="m-su-quota-gb">总流量配额 (GiB，0 为不限)</label>
                        <input type="number" id="m-su-quota-gb" min="0" step="0.5" value="${esc(quotaGbInit)}">
                    </div>
                    <div class="form-group">
                        <label for="m-su-expire">到期时间</label>
                        <input type="datetime-local" id="m-su-expire" value="${esc(expireInit)}">
                    </div>
                    <div class="form-group">
                        <label for="m-su-reset-day">每月自动重置日</label>
                        <select id="m-su-reset-day">${buildResetDayOptions(existing?.reset_day || 0)}</select>
                    </div>
                </div>
                <div class="form-grid" style="margin-top: 8px;">
                    <div class="deploy-inline-field">
                        <label class="inline-check">
                            <input type="checkbox" id="m-su-info-nodes"${infoNodesInit ? ' checked' : ''}>
                            <span>节点列表顶部显示到期和剩余流量</span>
                        </label>
                    </div>
                    <div class="deploy-inline-field">
                        <label class="inline-check">
                            <input type="checkbox" id="m-su-enabled"${enabledInit ? ' checked' : ''}>
                            <span>启用该用户</span>
                        </label>
                    </div>
                </div>
            </div>
            <div class="deploy-section">
                <div class="deploy-section-title">授权节点</div>
                <div class="su-node-toolbar">
                    <input type="search" id="m-su-node-search" placeholder="搜索服务器或节点名称" autocomplete="off">
                    <button type="button" class="btn btn-sm" id="m-su-select-all">全选</button>
                    <button type="button" class="btn btn-sm" id="m-su-clear-all">清空</button>
                    <span class="su-node-count" id="m-su-selected-count"></span>
                </div>
                <div class="su-node-list" id="m-su-node-list"></div>
            </div>
        `;

        const showErr = (msg) => {
            const box = document.getElementById('m-su-error');
            if (!box) return;
            box.textContent = msg;
            box.hidden = !msg;
        };

        openModal(
            isNew ? '新建订阅用户' : `编辑用户 · ${existing.username}`,
            html,
            async () => {
                showErr('');
                const username = (document.getElementById('m-su-username')?.value || '').trim();
                if (isNew && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(username)) {
                    showErr('用户名须为字母/数字开头，仅含字母、数字、._-');
                    return;
                }
                const quotaGb = Math.max(0, Number(document.getElementById('m-su-quota-gb')?.value) || 0);
                const expireRaw = (document.getElementById('m-su-expire')?.value || '').trim();
                const expireAt = expireRaw ? Math.floor(Date.parse(expireRaw) / 1000) : 0;
                if (expireRaw && (!Number.isFinite(expireAt) || expireAt <= 0)) {
                    showErr('到期时间格式无效');
                    return;
                }
                const resetDay = Math.max(0, Math.min(28, Number(document.getElementById('m-su-reset-day')?.value) || 0));
                const payload = {
                    quota_bytes: Math.max(0, Math.round(quotaGb * 1024 * 1024 * 1024)),
                    expire_at: expireAt,
                    enabled: Boolean(document.getElementById('m-su-enabled')?.checked),
                    allowed_nodes: Array.from(selectedSet),
                    info_nodes: Boolean(document.getElementById('m-su-info-nodes')?.checked),
                    reset_day: resetDay,
                };
                if (isNew) payload.username = username;

                try {
                    const reqPath = isNew ? '/sub-users' : `/sub-users/${encodeURIComponent(existing.id)}`;
                    const res = await fetchAuth(reqPath, {
                        method: isNew ? 'POST' : 'PATCH',
                        body: JSON.stringify(payload),
                    });
                    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
                    const result = await res.json();
                    closeModal();
                    await loadSubUsers();
                    if (isNew && result.token) {
                        const url = buildUserSubUrl(result.token, result, 'auto');
                        await copyTextToClipboard(url, `已创建 ${result.username} 并复制通用订阅链接`);
                    } else {
                        showToast('订阅用户已保存');
                    }
                } catch (e) {
                    showErr(`保存失败：${e.message}`);
                }
            },
            { confirmText: isNew ? '创建用户' : '保存修改', cancelText: '取消' }
        );

        const listEl = document.getElementById('m-su-node-list');
        const searchEl = document.getElementById('m-su-node-search');
        const countEl = document.getElementById('m-su-selected-count');
        const updateCount = () => {
            if (countEl) countEl.textContent = `已选 ${selectedSet.size} / ${availableNodes.length}`;
        };
        const paintNodes = () => {
            if (!listEl) return;
            listEl.innerHTML = renderNodePickerList(availableNodes, selectedSet, searchEl?.value || '');
            if (typeof listEl.querySelectorAll === 'function') {
                listEl.querySelectorAll('.su-node-cb').forEach(cb => {
                    cb.addEventListener('change', () => {
                        if (cb.checked) selectedSet.add(cb.value);
                        else selectedSet.delete(cb.value);
                        updateCount();
                    });
                });
            }
            updateCount();
        };
        paintNodes();

        if (searchEl) searchEl.addEventListener('input', paintNodes);
        const selAllBtn = document.getElementById('m-su-select-all');
        if (selAllBtn) {
            selAllBtn.addEventListener('click', () => {
                const q = String(searchEl?.value || '').trim().toLowerCase();
                for (const n of availableNodes) {
                    const hay = `${n.agent_name || ''} ${n.name || ''} ${n.protocol || ''} ${n.server || ''}`.toLowerCase();
                    if (!q || hay.includes(q)) selectedSet.add(n.key);
                }
                paintNodes();
            });
        }
        const clearBtn = document.getElementById('m-su-clear-all');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                selectedSet.clear();
                paintNodes();
            });
        }
    }

    async function toggleSubUser(user) {
        try {
            const res = await fetchAuth(`/sub-users/${encodeURIComponent(user.id)}`, {
                method: 'PATCH',
                body: JSON.stringify({ enabled: !user.enabled }),
            });
            if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
            showToast(user.enabled ? `已停用 ${user.username}` : `已启用 ${user.username}`);
            await loadSubUsers();
        } catch (e) {
            showToast(`操作失败：${e.message}`, 'error');
        }
    }

    async function resetSubUserTraffic(user) {
        if (!confirm(`确认将 ${user.username} 的累计流量归零？若因超额停用，归零后将自动恢复。`)) return;
        try {
            const res = await fetchAuth(`/sub-users/${encodeURIComponent(user.id)}/reset-traffic`, { method: 'POST' });
            if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
            showToast(`已重置 ${user.username} 的流量计数`);
            await loadSubUsers();
        } catch (e) {
            showToast(`重置失败：${e.message}`, 'error');
        }
    }

    async function rotateSubUser(user) {
        if (!confirm(`确认轮换 ${user.username} 的订阅链接与节点凭据？旧链接和旧节点连接将立即失效。`)) return;
        try {
            const res = await fetchAuth(`/sub-users/${encodeURIComponent(user.id)}/rotate`, { method: 'POST' });
            if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
            const data = await res.json();
            await loadSubUsers();
            if (data.token) {
                const url = buildUserSubUrl(data.token, user);
                await copyTextToClipboard(url, `已轮换 ${user.username} 的链接与凭据并复制`);
            }
        } catch (e) {
            showToast(`轮换失败：${e.message}`, 'error');
        }
    }

    async function deleteSubUser(user) {
        if (!confirm(`确认删除订阅用户 ${user.username}？该操作不可撤销。`)) return;
        try {
            const res = await fetchAuth(`/sub-users/${encodeURIComponent(user.id)}`, { method: 'DELETE' });
            if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
            showToast(`已删除订阅用户 ${user.username}`);
            await loadSubUsers();
        } catch (e) {
            showToast(`删除失败：${e.message}`, 'error');
        }
    }

    if (typeof document !== 'undefined') {
        document.getElementById('btn-refresh-sub-users')?.addEventListener('click', loadSubUsers);
        document.getElementById('btn-add-sub-user')?.addEventListener('click', () => openSubUserModal(null));
        document.querySelectorAll('.sidebar-item[data-panel="panel-sub-users"]').forEach(btn => {
            btn.addEventListener('click', () => loadSubUsers());
        });
    }

    const api = {
        loadSubUsers,
        renderSubUsers,
        openSubUserModal,
        formatSubBytes,
        renderNodePickerList,
    };
    root.ProxyForgeSubUsers = api;
    root.loadSubUsers = loadSubUsers;
})(typeof globalThis !== 'undefined' ? globalThis : this);
