const API_BASE = '/api';
const { escapeHtml } = ProxyForgeHtmlUtils;
const SHARE_LINK_PATTERN = /^(vmess|vless|trojan|hysteria2|hy2|ss|tuic|anytls|wireguard):\/\//i;

// Data State
let state = {
    config: {},
    airports: [],
    airportsInfo: [],
    nodes: [],
    allProxies: [], // Contains all custom and airport proxies
    templateRaw: '',
    templateObj: {}
};

// DOM Elements
const loginOverlay = document.getElementById('login-overlay');
const dashboard = document.getElementById('dashboard');
const tokenInput = document.getElementById('token-input');
const loginBtn = document.getElementById('login-btn');
const loginError = document.getElementById('login-error');
const logoutBtn = document.getElementById('logout-btn');
const sidebarItems = document.querySelectorAll('.sidebar-item');
const sectionPanels = document.querySelectorAll('.section-panel');
const toast = document.getElementById('toast');

// Modal Elements
const modalOverlay = document.getElementById('modal-overlay');
const modalTitle = document.getElementById('modal-title');
const modalBody = document.getElementById('modal-body');
const modalClose = document.getElementById('modal-close');
const modalCancel = document.getElementById('modal-cancel');
const modalConfirm = document.getElementById('modal-confirm');
let modalConfirmAction = null;

// Form Elements
const subLink = document.getElementById('sub-link');
const copyBtn = document.getElementById('copy-btn');
const secretToken = document.getElementById('secret-token');
const saveConfigBtn = document.getElementById('save-config-btn');
const newAdminToken = document.getElementById('new-admin-token');
const saveAdminTokenBtn = document.getElementById('save-admin-token-btn');
const rulesEditor = document.getElementById('rules-editor');
const saveRulesBtn = document.getElementById('save-rules-btn');
const ruleSearchInput = document.getElementById('rule-search-input');
const ruleSearchCount = document.getElementById('rule-search-count');
const clearRuleSearchBtn = document.getElementById('btn-clear-rule-search');
let savedTemplateObj = null;
let templateParseError = '';
let externalTemplateBusy = false;
let modalReturnFocus = null;
function parseTemplate(content) {
    const parsed = jsyaml.load(content);
    if (!ProxyForgeNetwork.mapping(parsed)) throw new Error('模板根节点必须是 YAML 对象');
    return parsed;
}
function rawIsDirty() { return rulesEditor.value !== state.templateRaw; }
function templateGuard(source = 'other') {
    if (templateSession.isBusy() || externalTemplateBusy) throw new Error('正在保存，请稍候');
    if (source !== 'raw' && templateParseError) throw new Error('请先在底层配置中修复 YAML');
    if (source !== 'raw' && rawIsDirty()) throw new Error('底层配置有未保存文本，请先保存或放弃修改');
    if (source !== 'network' && ProxyForgeNetwork.isDirty()) throw new Error('网络设置有未保存草稿，请先保存或放弃修改');
}
function renderTemplateViews() {
    if (!state.templateObj) return;
    // Malformed legacy sections should not prevent access to the Raw editor.
    for (const render of [renderGroups, renderRules, renderRuleProviders]) {
        try { render(); } catch (_) { /* Raw YAML remains available for repair. */ }
    }
}
function installTemplate(snapshot) {
    const { content, revision } = snapshot;
    state.templateRevision = revision;
    templateSession.setBaseline(snapshot);
    state.templateRaw = content;
    rulesEditor.value = content;
    try {
        const parsed = parseTemplate(content);
        state.templateObj = parsed;
        savedTemplateObj = ProxyForgeNetwork.clone(parsed);
        templateParseError = '';
    } catch (error) {
        state.templateObj = null;
        savedTemplateObj = null;
        templateParseError = error.message;
        showToast(`模板读取失败：${error.message}，请修复底层配置`, 'error');
    }
    renderTemplateViews();
    ProxyForgeNetwork.render(state.templateObj, true);
}
async function readTemplate() {
    return (await fetchAuth('/template')).json();
}
async function validateTemplateText(content) {
    return (await fetchAuth('/template/validate', {
        method: 'POST', body: JSON.stringify({ content })
    })).json();
}
const templateSession = ProxyForgeTemplateSession.create({
    parse: parseTemplate, read: readTemplate, validate: validateTemplateText,
    write: async (content, expected_revision) => (await fetchAuth('/template', { method: 'POST', body: JSON.stringify({ content, expected_revision }) })).json(),
    install: installTemplate,
});
ProxyForgeNetwork.init({
    escape: escapeHtml, dump: value => jsyaml.dump(value), validate: validateTemplateText,
    save: candidate => saveTemplateObj(candidate, 'network'),
    isBusy: () => templateSession.isBusy() || externalTemplateBusy,
    openModal, closeModal, toast: showToast,
    openRaw: () => document.querySelector('[data-panel="panel-raw"]').click(),
});
// Block conflicting interactions before legacy handlers mutate shared state.
document.addEventListener('click', event => {
    const target = event.target.closest('button, [onclick]');
    if (!target || target.id === 'logout-btn' || target.closest('#login-overlay')) return;
    if (target.id === 'modal-cancel' || target.id === 'modal-close') return;
    let message = '';
    if (templateSession.isBusy() || externalTemplateBusy) message = '正在保存，请稍候';
    else if (templateParseError && target.closest('#panel-groups, #panel-rules')) message = '请先修复底层 YAML';
    else if (target.closest('#panel-groups, #panel-rules, #panel-nodes, #panel-airports') || target.id === 'global-import-btn') {
        if (rawIsDirty() || ProxyForgeNetwork.isDirty()) message = '请先保存或放弃底层配置/网络草稿';
    }
    if (message) { event.preventDefault(); event.stopImmediatePropagation(); showToast(message, 'warning'); }
}, true);
document.addEventListener('dragstart', event => {
    if (templateSession.isBusy() || externalTemplateBusy || templateParseError || rawIsDirty() || ProxyForgeNetwork.isDirty()) event.preventDefault();
}, true);
document.getElementById('discard-raw-btn').addEventListener('click', () => { rulesEditor.value = state.templateRaw; });

function showToast(msg, type = 'success') {
    toast.textContent = msg;
    toast.className = `toast toast-${type} active`;
    setTimeout(() => { toast.classList.remove('active'); }, 3000);
}

// === Modal Logic ===
function openModal(title, htmlContent, onConfirm) {
    modalConfirm.textContent = '确认';
    modalReturnFocus = document.activeElement;
    modalTitle.textContent = title;
    modalBody.innerHTML = htmlContent;
    modalConfirmAction = onConfirm;
    modalOverlay.classList.add('active');
    setTimeout(() => (modalBody.querySelector('input, select, textarea, button') || modalConfirm).focus(), 0);
}
function closeModal() {
    modalOverlay.classList.remove('active');
    modalConfirmAction = null;
    if (modalReturnFocus?.isConnected) modalReturnFocus.focus();
    else document.querySelector('.section-panel.active button:not(:disabled)')?.focus();
}
modalOverlay.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeModal();
    if (event.key === 'Tab') {
        const items = [...modalOverlay.querySelectorAll('button, input, select, textarea, [tabindex="0"]')].filter(el => !el.disabled);
        const first = items[0], last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
});
modalClose.addEventListener('click', closeModal);
modalCancel.addEventListener('click', closeModal);
modalConfirm.addEventListener('click', () => {
    if (modalConfirmAction) modalConfirmAction();
});

// === Auth Logic ===
async function fetchAuth(url, options = {}) {
    if (!options.headers) options.headers = {};
    options.headers['Content-Type'] = 'application/json';
    options.credentials = 'same-origin';
    const res = await fetch(`${API_BASE}${url}`, options);
    if (res.status === 401) {
        showLogin();
        throw Object.assign(new Error('登录已过期，请重新登录'), { status: 401 });
    }
    if (!res.ok) {
        let message = `HTTP ${res.status}`;
        let detail;
        try {
            const payload = await res.clone().json();
            detail = payload.detail;
            if (typeof detail === 'string') {
                message = detail;
            } else if (detail && Array.isArray(detail.errors)) {
                message = `${detail.message || '配置校验失败'}：\n${detail.errors.join('\n')}`;
            }
        } catch (_) {
            const text = await res.text();
            if (text) message = text;
        }
        throw Object.assign(new Error(message), { status: res.status, detail });
    }
    return res;
}

async function reloadTemplateState() {
    if (rawIsDirty() || ProxyForgeNetwork.isDirty()) throw new Error('草稿尚未保存，未覆盖本地编辑');
    installTemplate(await readTemplate());
}

async function login() {
    const token = tokenInput.value.trim();
    if (!token) return;
    try {
        const res = await fetch(`${API_BASE}/auth`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });
        if (res.ok) {
            loginOverlay.classList.remove('active');
            dashboard.style.display = 'flex';
            dashboard.classList.remove('hidden');
            tokenInput.value = '';
            loadData();
        } else throw new Error('Invalid');
    } catch (err) {
        loginError.style.display = 'block';
        document.querySelector('.login-card').classList.add('shake');
        setTimeout(() => { document.querySelector('.login-card').classList.remove('shake'); }, 400);
    }
}

function showLogin() {
    dashboard.style.display = 'none';
    loginOverlay.classList.add('active');
    tokenInput.value = '';
    loginError.style.display = 'none';
}

async function logout() {
    try {
        await fetch(`${API_BASE}/logout`, {
            method: 'POST',
            credentials: 'same-origin'
        });
    } finally {
        showLogin();
    }
}

loginBtn.addEventListener('click', login);
tokenInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') login(); });
logoutBtn.addEventListener('click', logout);

fetch(`${API_BASE}/auth`, { credentials: 'same-origin' }).then(res => {
    if (res.ok) {
        loginOverlay.classList.remove('active');
        dashboard.style.display = 'flex';
        dashboard.classList.remove('hidden');
        loadData();
    } else {
        showLogin();
    }
}).catch(showLogin);

// === Navigation ===
sidebarItems.forEach(item => {
    item.addEventListener('click', () => {
        sidebarItems.forEach(i => i.classList.remove('active'));
        sectionPanels.forEach(p => p.classList.remove('active'));
        item.classList.add('active');
        document.getElementById(item.getAttribute('data-panel')).classList.add('active');
    });
});

// === Data Loading & Rendering ===
async function loadData() {
    try {
        const configRes = await fetchAuth('/config');
        state.config = await configRes.json();
        secretToken.value = state.config.SUBSCRIPTION_TOKEN;
        const updateSubLink = () => {
            const name = encodeURIComponent(document.getElementById('sub-name').value.trim() || 'ProxyForge');
            subLink.value = `${window.location.origin}/sub?token=${state.config.SUBSCRIPTION_TOKEN}&name=${name}`;
        };
        updateSubLink();
        document.getElementById('sub-name').addEventListener('input', updateSubLink);

        const airportsRes = await fetchAuth('/airports');
        let rawAirports = (await airportsRes.json()).urls || [];
        state.airports = rawAirports.map(u => typeof u === 'string' ? {url: u} : u);

        const nodesRes = await fetchAuth('/nodes');
        state.nodes = (await nodesRes.json()).nodes || [];
        
        const allProxiesRes = await fetchAuth('/proxies');
        state.allProxies = (await allProxiesRes.json()).proxies || [];
        
        renderAirports();
        renderNodes();
        // Reauthentication must not erase an unsaved draft.
        if (!rawIsDirty() && !ProxyForgeNetwork.isDirty()) installTemplate(await readTemplate());

        // Async fetch airport info
        fetchAuth('/airports/info').then(res => res.json()).then(data => {
            state.airportsInfo = data.info || [];
            renderAirports();
        }).catch(e => console.error("Fetch info failed:", e));

    } catch (e) {
        console.error("Failed to load data", e);
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(timestamp) {
    if (!timestamp) return '未知';
    const d = new Date(timestamp * 1000);
    return d.toLocaleDateString();
}

function getFlagEmoji(name) {
    if (!name) return name;
    if (/[\uD83C-\uDBFF\uDC00-\uDFFF]+/.test(name)) return name; // Already has emoji
    const flags = {
        'hk': '🇭🇰', '香港': '🇭🇰',
        'jp': '🇯🇵', '日本': '🇯🇵',
        'us': '🇺🇸', '美国': '🇺🇸', '美': '🇺🇸',
        'sg': '🇸🇬', '新加坡': '🇸🇬', '狮城': '🇸🇬',
        'tw': '🇹🇼', '台湾': '🇹🇼', '台': '🇹🇼',
        'uk': '🇬🇧', '英国': '🇬🇧',
        'kr': '🇰🇷', '韩国': '🇰🇷',
        'de': '🇩🇪', '德国': '🇩🇪',
        'fr': '🇫🇷', '法国': '🇫🇷',
        'ru': '🇷🇺', '俄罗斯': '🇷🇺',
        'in': '🇮🇳', '印度': '🇮🇳'
    };
    let found = null;
    let lowerName = name.toLowerCase();
    for (const [key, flag] of Object.entries(flags)) {
        if (lowerName.includes(key)) {
            found = flag;
            break;
        }
    }
    return found ? `${found} ${name}` : name;
}

// Helper for checkboxes
function getCheckboxHTML(cls, idx) {
    return `<input type="checkbox" class="${cls}" data-idx="${idx}" style="margin-right:10px; width:16px; height:16px; cursor:pointer;">`;
}

function getCheckedIndices(cls) {
    const checkboxes = document.querySelectorAll(`.${cls}:checked`);
    let indices = Array.from(checkboxes).map(cb => parseInt(cb.getAttribute('data-idx')));
    return indices.sort((a, b) => b - a); // Sort descending to splice safely
}

// === Render: Airports ===
function renderAirports() {
    const list = document.getElementById('airports-list');
    if (!state.airports.length) {
        list.innerHTML = `<div class="empty-state">暂无机场订阅，请点击上方按钮添加</div>`;
        return;
    }
    let html = '';
    state.airports.forEach((item, index) => {
        let url = typeof item === 'string' ? item : item.url;
        let customName = typeof item === 'object' ? item.name : '';
        let info = state.airportsInfo && state.airportsInfo.find(i => i.url === url);
        
        if (info) {
            let usageStr = "获取失败";
            if (!info.error) {
                if (info.total > 0) {
                    let used = info.download + info.upload;
                    usageStr = `${formatBytes(used)} / ${formatBytes(info.total)}`;
                } else {
                    usageStr = "未知流量";
                }
            }
            let displayName = customName || info.name || '机场';
            let safeDisplayName = escapeHtml(displayName);
            let safeUrl = escapeHtml(url);
            let safeError = escapeHtml(info.error || '');
            html += `
                <div class="list-item" style="flex-direction:column; align-items:flex-start;">
                    <div style="display:flex; width:100%; align-items:center;">
                        ${getCheckboxHTML('cb-airport', index)}
                        <span class="type-badge badge-select" style="margin-right:8px; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${safeDisplayName}</span>
                        <div class="item-info" style="flex:1; word-break:break-all; font-size:0.8rem; color:#666;">${safeUrl}</div>
                        <div class="item-actions">
                            <button class="btn btn-sm btn-primary" onclick="editAirport(${index})">编辑</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteAirport(${index})">删除</button>
                        </div>
                    </div>
                    <div style="display:flex; gap:15px; margin-left:34px; margin-top:8px; font-size:0.8rem; flex-wrap:wrap;">
                        <span style="color:#2e7d32;"><b>📦 节点:</b> ${info.error ? '?' : info.nodesCount}</span>
                        <span style="color:#1565c0;"><b>📊 流量:</b> ${usageStr}</span>
                        <span style="color:#e65100;"><b>⏳ 到期:</b> ${info.expire ? formatDate(info.expire) : '长期有效'}</span>
                        <span style="color:#607d8b;"><b>🔄 刷新:</b> ${info._timestamp ? new Date(info._timestamp * 1000).toLocaleString('zh-CN', {month: 'numeric', day: 'numeric', hour: '2-digit', minute:'2-digit'}) : '未知'}</span>
                    </div>
                    ${info.error ? `<div style="color:red; font-size:0.75rem; margin-left:34px; margin-top:4px;">抓取失败: ${safeError}</div>` : ''}
                </div>
            `;
        } else {
            let displayName = customName || '机场';
            let safeDisplayName = escapeHtml(displayName);
            let safeUrl = escapeHtml(url);
            html += `
                <div class="list-item">
                    ${getCheckboxHTML('cb-airport', index)}
                    <span class="type-badge badge-select" style="margin-right:8px;">${safeDisplayName}</span>
                    <div class="item-info" style="word-break:break-all;">${safeUrl}</div>
                    <span style="font-size:0.8rem; color:#999;">动态数据加载中...</span>
                    <div class="item-actions">
                        <button class="btn btn-sm btn-primary" onclick="editAirport(${index})">编辑</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteAirport(${index})">删除</button>
                    </div>
                </div>
            `;
        }
    });
    list.innerHTML = html;
    if (window.twemoji) twemoji.parse(list, { folder: 'svg', ext: '.svg' });
}

// === Render: Proxy Groups ===
function renderGroups() {
    const list = document.getElementById('groups-list');
    let groups = state.templateObj['proxy-groups'] || [];
    if (!groups.length) {
        list.innerHTML = `<div class="empty-state">暂无代理组，请点击上方按钮添加</div>`;
        return;
    }
    let html = '';
    groups.forEach((g, index) => {
        let badgeCls = 'badge-default';
        if (g.type === 'select') badgeCls = 'badge-select';
        else if (g.type === 'url-test') badgeCls = 'badge-url-test';
        else if (g.type === 'fallback') badgeCls = 'badge-fallback';
        else if (g.type === 'load-balance') badgeCls = 'badge-load-balance';
        
        let pCount = Array.isArray(g.proxies) ? g.proxies.length : 0;
        let uCount = Array.isArray(g.use) ? g.use.length : 0;
        let proxyGroupNames = state.templateObj['proxy-groups'].map(x => x.name);
        let nestedGroups = Array.isArray(g.proxies) ? g.proxies.filter(p => proxyGroupNames.includes(p)) : [];
        
        let summaries = [];
        if (g['include-all']) {
            summaries.push('全部 (机场+自建)');
        } else if (uCount > 0) {
            let sources = g.use.map(s => s === '_custom_nodes_' ? '🌐自建' : `✈️${s}`);
            summaries.push(`${sources.join(', ')}`);
        } 
        
        if (g.filter) {
            summaries.push(`正则: ${g.filter}`);
        }
        
        if (nestedGroups.length > 0) {
            summaries.push(`嵌套: ${nestedGroups.join(', ')}`);
        }
        
        if (!g['include-all'] && uCount === 0 && !g.filter && nestedGroups.length === 0 && pCount > 0) {
            let manuals = g.proxies.filter(p => p !== 'DIRECT' && p !== 'REJECT' && !nestedGroups.includes(p));
            if (manuals.length === 0) manuals = g.proxies;
            summaries.push(`手动节点: ${manuals.slice(0, 3).join(', ')}${manuals.length > 3 ? '...' : ''}`);
        }
        
        let proxiesPreview = summaries.length > 0 ? summaries.join(' | ') : '无';
        
        let displayName = getFlagEmoji(g.name);

        html += `
            <div class="list-item" draggable="true" data-index="${index}"
                 ondragstart="handleGroupDragStart(event, ${index})"
                 ondragover="handleGroupDragOver(event)"
                 ondragenter="handleGroupDragEnter(event)"
                 ondragleave="handleGroupDragLeave(event)"
                 ondrop="handleGroupDrop(event, ${index})"
                 ondragend="handleGroupDragEnd(event)">
                <span class="drag-handle" style="cursor: grab; margin-right: 10px; color: #999;">⠿</span>
                ${getCheckboxHTML('cb-group', index)}
                <span class="type-badge ${badgeCls}">${escapeHtml(g.type || 'unknown')}</span>
                <div class="item-info">
                    <div class="item-name">${escapeHtml(displayName)}</div>
                    <div class="item-detail" style="color: #666; font-size: 0.8rem; margin-top: 4px;">包含: ${escapeHtml(proxiesPreview)}</div>
                </div>
                <div class="item-actions">
                    <button class="btn btn-sm" onclick="editGroup(${index})">编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteGroup(${index})">删除</button>
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
    if (window.twemoji) twemoji.parse(list, { folder: 'svg', ext: '.svg' });
}

// === Render: Custom Nodes ===
function renderNodes() {
    const list = document.getElementById('nodes-list');
    if (!state.nodes.length) {
        list.innerHTML = `<div class="empty-state">暂无自建节点</div>`;
        return;
    }
    let html = '';
    state.nodes.forEach((n, index) => {
        let displayName = getFlagEmoji(n.name);
        html += `
            <div class="list-item" draggable="true" data-index="${index}" 
                 ondragstart="handleDragStart(event, ${index})" 
                 ondragover="handleDragOver(event)"
                 ondragenter="handleDragEnter(event)"
                 ondragleave="handleDragLeave(event)"
                 ondrop="handleDrop(event, ${index})"
                 ondragend="handleDragEnd(event)">
                <span class="drag-handle" style="cursor: grab; margin-right: 10px; color: #999;">⠿</span>
                ${getCheckboxHTML('cb-node', index)}
                <span class="type-badge badge-node">${escapeHtml(n.type || 'unknown')}</span>
                <div class="item-info">
                    <div class="item-name">${escapeHtml(displayName)}</div>
                    <div class="item-detail">${escapeHtml(n.server || '')} ${escapeHtml(n.port ? ':'+n.port : '')}</div>
                </div>
                <div class="item-actions">
                    ${index > 0 ? `<button class="btn btn-sm" onclick="moveNodeUp(${index})" title="上移">⬆️</button>` : ''}
                    ${index < state.nodes.length - 1 ? `<button class="btn btn-sm" onclick="moveNodeDown(${index})" title="下移">⬇️</button>` : ''}
                    <button class="btn btn-sm" onclick="editNode(${index})">编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteNode(${index})">删除</button>
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
    if (window.twemoji) twemoji.parse(list, { folder: 'svg', ext: '.svg' });
}

// === Render: Rule Providers ===
function renderRuleProviders() {
    const list = document.getElementById('rule-providers-list');
    let providers = state.templateObj['rule-providers'] || {};
    let keys = Object.keys(providers);
    if (!keys.length) {
        list.innerHTML = `<div class="empty-state">暂无规则集</div>`;
        return;
    }
    let html = '';
    keys.forEach((key, providerIndex) => {
        let p = providers[key];
        html += `
            <div class="list-item">
                <span class="type-badge badge-node">${escapeHtml(p.type || 'http')}</span>
                <div class="item-info">
                    <div class="item-name">${escapeHtml(key)}</div>
                    <div class="item-detail">${escapeHtml(p.url ? p.url : (p.path || ''))}</div>
                </div>
                <div class="item-actions">
                    <button class="btn btn-sm" onclick="editRuleProviderByIndex(${providerIndex})">编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteRuleProviderByIndex(${providerIndex})">删除</button>
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
}

// === Render: Rules ===
function renderRules() {
    const list = document.getElementById('rules-list');
    let rules = state.templateObj['rules'] || [];
    const searchQuery = ruleSearchInput.value.trim();
    const visibleRules = ProxyForgeRuleUtils.filterRules(rules, searchQuery);
    const isFiltering = searchQuery.length > 0;

    ruleSearchCount.textContent = isFiltering
        ? `显示 ${visibleRules.length} / 共 ${rules.length} 条`
        : `共 ${rules.length} 条`;
    clearRuleSearchBtn.disabled = !isFiltering;

    if (!rules.length) {
        list.innerHTML = `<div class="empty-state">暂无路由规则</div>`;
        return;
    }
    if (!visibleRules.length) {
        list.innerHTML = `<div class="empty-state">没有找到匹配的路由规则</div>`;
        return;
    }
    let html = '';
    visibleRules.forEach(({ rule: r, index }) => {
        let parts = r.split(',');
        let type = parts[0] || '';
        
        let typeColor = '#6c757d';
        if (type.startsWith('DOMAIN')) typeColor = '#007bff';
        else if (type.startsWith('IP-')) typeColor = '#28a745';
        else if (type === 'GEOIP') typeColor = '#17a2b8';
        else if (type === 'MATCH') typeColor = '#dc3545';
        else if (type === 'RULE-SET') typeColor = '#fd7e14';
        
        html += `
            <div class="list-item" draggable="${isFiltering ? 'false' : 'true'}" data-index="${index}"
                 ondragstart="handleRuleDragStart(event, ${index})"
                 ondragover="handleRuleDragOver(event)"
                 ondragenter="handleRuleDragEnter(event)"
                 ondragleave="handleRuleDragLeave(event)"
                 ondrop="handleRuleDrop(event, ${index})"
                 ondragend="handleRuleDragEnd(event)">
                <span class="drag-handle" title="${isFiltering ? '清空搜索后可拖拽排序' : '拖拽排序'}"
                      style="cursor: ${isFiltering ? 'not-allowed' : 'grab'}; margin-right: 10px; color: #999;">⠿</span>
                ${getCheckboxHTML('cb-rule', index)}
                <span class="type-badge" style="background:${typeColor}; min-width: 90px; text-align: center;">${escapeHtml(type)}</span>
                <div class="item-info" style="font-family: monospace; display:flex; align-items:center;">
                    <span style="font-weight:600; color:#333; margin-right:8px;">${escapeHtml(parts.slice(1, -1).join(','))}</span>
                    <span style="color:#888; font-size:0.85em;">➔ ${escapeHtml(parts[parts.length-1] || '')}</span>
                </div>
                <div class="item-actions">
                    <button class="btn btn-sm" onclick="editRule(${index})">编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteRule(${index})">删除</button>
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
    if (window.twemoji) twemoji.parse(list, { folder: 'svg', ext: '.svg' });
}

ruleSearchInput.addEventListener('input', renderRules);
clearRuleSearchBtn.addEventListener('click', () => {
    ruleSearchInput.value = '';
    renderRules();
    ruleSearchInput.focus();
});

// === Actions: Airports ===
document.getElementById('btn-add-airport').addEventListener('click', () => {
    const html = `
        <div class="form-group full-width">
            <label>添加多个机场链接 (一行一个，支持: 机场名称,链接)</label>
            <textarea id="m-airport-input" style="min-height:150px;" placeholder="名称,https://... (名称可选)"></textarea>
        </div>
    `;
    openModal('添加机场', html, async () => {
        let lines = document.getElementById('m-airport-input').value.split('\n').map(s=>s.trim()).filter(s=>s);
        if(lines.length) {
            let toAdd = lines.map(line => {
                let parts = line.split(',');
                if (parts.length > 1 && parts[1].trim().startsWith('http')) {
                    return { name: parts[0].trim(), url: parts.slice(1).join(',').trim() };
                }
                return { url: line };
            });
            state.airports = state.airports.concat(toAdd);
            closeModal();
            await saveAirportsObj();
        }
    });
});

window.editAirport = (idx) => {
    let item = state.airports[idx];
    let customName = typeof item === 'object' ? (item.name || '') : '';
    let url = typeof item === 'object' ? item.url : item;
    
    const html = `
        <div class="form-group full-width">
            <label>机场名称 (可选)</label>
            <input type="text" id="m-airport-name" value="${escapeHtml(customName)}" placeholder="比如: 良心云">
        </div>
        <div class="form-group full-width">
            <label>订阅链接</label>
            <input type="text" id="m-airport-url" value="${escapeHtml(url)}" placeholder="https://...">
        </div>
    `;
    openModal('编辑机场', html, async () => {
        let nName = document.getElementById('m-airport-name').value.trim();
        let nUrl = document.getElementById('m-airport-url').value.trim();
        if(nUrl) {
            state.airports[idx] = nName ? { name: nName, url: nUrl } : { url: nUrl };
            closeModal();
            await saveAirportsObj();
        }
    });
};

window.deleteAirport = async (idx) => {
    state.airports.splice(idx, 1);
    await saveAirportsObj();
};

document.getElementById('btn-bulk-delete-airports').addEventListener('click', async () => {
    let indices = getCheckedIndices('cb-airport');
    if(!indices.length) return alert('请先勾选要删除的项');
    if(confirm(`确定删除这 ${indices.length} 项吗？`)) {
        indices.forEach(i => state.airports.splice(i, 1));
        await saveAirportsObj();
    }
});

document.getElementById('btn-refresh-airports').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-airport');
    if(!indices.length) return alert('请先在左侧勾选需要强制刷新的机场！');
    
    let btn = document.getElementById('btn-refresh-airports');
    btn.disabled = true;
    btn.textContent = '🔄 刷新中...';
    
    indices.forEach(idx => {
        let card = document.querySelectorAll('#airports-list .airport-card')[idx];
        if (card) {
            let statsDiv = card.querySelector('.airport-stats');
            if (statsDiv) {
                statsDiv.innerHTML = `<span style="color:#666; font-size:0.9rem;">⏳ 正在强制拉取最新数据...</span>`;
            }
        }
    });

    fetchAuth(`/airports/info?force_indices=${indices.join(',')}`).then(res => res.json()).then(data => {
        state.airportsInfo = data.info || [];
        renderAirports();
        showToast('选中的机场数据已刷新');
    }).catch(e => {
        showToast('刷新失败', 'error');
        renderAirports();
    }).finally(() => {
        btn.disabled = false;
        btn.textContent = '🔄 强制刷新';
    });
});

async function saveAirportsObj() {
    renderAirports();
    let locked = false;
    try {
        templateGuard();
        externalTemplateBusy = true; locked = true; rulesEditor.readOnly = true;
        const response = await fetchAuth('/airports', {
            method: 'POST',
            body: JSON.stringify({ urls: state.airports })
        });
        const result = await response.json();
        if (result.cleanedReferences > 0) {
            await reloadTemplateState();
            showToast(`机场配置已保存，并清理 ${result.cleanedReferences} 处失效引用`);
        } else {
            showToast('机场配置已保存');
        }
        // Refresh info after saving
        fetchAuth('/airports/info?force_indices=all').then(res => res.json()).then(data => {
            state.airportsInfo = data.info || [];
            renderAirports();
        });
    } catch(e) { showToast(`保存失败：${e.message}`, 'error'); }
    finally { if (locked) { externalTemplateBusy = false; rulesEditor.readOnly = false; } }
}

// === Actions: Proxy Groups ===
window.editGroup = function(index) {
    let g = index >= 0 ? state.templateObj['proxy-groups'][index] : { name: '', type: 'select', proxies: [] };
    
    const regions = [
        {key: 'hk|香港', label: '🇭🇰 香港'},
        {key: 'jp|日本', label: '🇯🇵 日本'},
        {key: 'us|美国|美', label: '🇺🇸 美国'},
        {key: 'sg|新加坡|狮城', label: '🇸🇬 新加坡'},
        {key: 'tw|台湾|台', label: '🇹🇼 台湾'},
        {key: 'kr|韩国', label: '🇰🇷 韩国'},
        {key: 'uk|英国', label: '🇬🇧 英国'}
    ];
    
    const airportNames = new Set();
    state.airports.forEach(a => {
        let name = typeof a === 'object' ? a.name : a;
        if (name) airportNames.add(name);
    });
    
    let manualProxies = Array.isArray(g.proxies) ? g.proxies : [];
    
    const html = `
        <div class="form-group full-width">
            <label>名称 (Name)</label>
            <input type="text" id="m-group-name" value="${escapeHtml(g.name || '')}">
        </div>
        <div class="form-group full-width">
            <label>类型 (Type)</label>
            <select id="m-group-type">
                <option value="select" ${g.type==='select'?'selected':''}>select (手动选择)</option>
                <option value="url-test" ${g.type==='url-test'?'selected':''}>url-test (自动测速)</option>
                <option value="fallback" ${g.type==='fallback'?'selected':''}>fallback (可用性切换)</option>
                <option value="load-balance" ${g.type==='load-balance'?'selected':''}>load-balance (负载均衡)</option>
            </select>
        </div>
        
        <div class="form-group full-width" id="wrap-group-url" style="${g.type==='select'?'display:none':''}">
            <label>测试链接 (URL)</label>
            <input type="text" id="m-group-url" value="${escapeHtml(g.url || 'http://www.gstatic.com/generate_204')}">
        </div>
        <div class="form-group full-width" id="wrap-group-interval" style="${g.type==='select'?'display:none':''}">
            <label>测试间隔 (Interval / s)</label>
            <input type="number" id="m-group-interval" value="${escapeHtml(g.interval || 300)}">
        </div>
        <div class="form-group full-width" id="wrap-group-default" style="${g.type!=='select'?'display:none':''}">
            <label>默认选中项 (例如: 🚀 节点选择)</label>
            <input type="text" id="m-group-default" value="${escapeHtml(g.default || '')}" placeholder="留空则默认选中第一项">
        </div>
        
        <div class="form-group full-width" style="margin-top: 10px; border-top: 1px dashed #ddd; padding-top: 15px;">
            <label style="color:var(--primary); font-size:0.9rem; font-weight: 600;">✨ 智能节点筛选器</label>
            
            <label style="display:flex; align-items:center; cursor:pointer; font-size:0.9rem; margin-bottom:10px; color:#333;">
                <input type="checkbox" id="m-group-include-all" style="margin-right:8px; width:16px; height:16px;" ${g['include-all'] ? 'checked' : ''}> 
                自动包含全部节点 (后续新增节点也会自动加入)
            </label>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:#666; font-weight: 600;">1. 快速选择地区:</div>
            <div class="filter-tags" id="tags-regions">
                ${regions.map(r => `<div class="filter-tag" data-val="${r.key}">${r.label}</div>`).join('')}
            </div>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:#666; font-weight: 600;">2. 快速选择节点来源:</div>
            <div class="filter-tags" id="tags-sources">
                ${Array.from(airportNames).map(name => `<div class="filter-tag" data-val="${escapeHtml(name)}">✈️ ${escapeHtml(name)}</div>`).join('')}
                <div class="filter-tag" data-val="_custom_nodes_">🌐 自建节点</div>
            </div>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:#666; font-weight: 600;">底层正则表达式 (可手动修改):</div>
            <input type="text" id="m-group-filter" value="${escapeHtml(g.filter || '')}" placeholder="例如: (?i)hk|香港">
        </div>
        
        <div class="form-group full-width">
            <label style="display:flex; justify-content:space-between; align-items:center;">
                <span>3. 包含节点预览 (手动微调)</span>
                <span id="preview-count" style="color:var(--primary);"></span>
            </label>
            <div class="preview-list" id="m-group-preview">
            </div>
        </div>
    `;
    openModal(index >= 0 ? '编辑代理组' : '新建代理组', html, () => {
        g.name = document.getElementById('m-group-name').value.trim();
        g.type = document.getElementById('m-group-type').value;
        if (g.type !== 'select') {
            g.url = document.getElementById('m-group-url').value.trim();
            g.interval = parseInt(document.getElementById('m-group-interval').value) || 300;
            delete g.default;
        } else {
            delete g.url;
            delete g.interval;
            let defVal = document.getElementById('m-group-default');
            if (defVal) {
                g.default = defVal.value.trim();
                if (!g.default) delete g.default;
            }
        }
        
        g.filter = document.getElementById('m-group-filter').value.trim();
        if (!g.filter) delete g.filter;
        
        g['include-all'] = document.getElementById('m-group-include-all').checked;
        if (!g['include-all']) delete g['include-all'];
        
        let checked = [];
        document.querySelectorAll('#m-group-preview input[type="checkbox"]').forEach(cb => {
            if (cb.checked) checked.push(cb.value);
        });
        
        // Exclude nodes that are automatically matched by the filter/use combination
        let manualOnly = [];
        
        let filterRe = null;
        if (g.filter) {
            try { filterRe = new RegExp(g.filter, 'i'); } catch(e) {}
        }
        
        checked.forEach(name => {
            let p = state.allProxies.find(x => x.name === name);
            let isAutoMatched = false;
            
            if (p) {
                // If the group has use, node must be from one of the use sources
                let matchesSource = true;
                if (activeSources.size > 0) {
                    let src = p._airport_name || '_custom_nodes_';
                    if (!activeSources.has(src)) matchesSource = false;
                }
                
                let matchesRegion = true;
                if (filterRe) {
                    if (!filterRe.test(name)) matchesRegion = false;
                }
                
                if (matchesSource && matchesRegion && (activeSources.size > 0 || filterRe)) {
                    isAutoMatched = true;
                }
            }
            
            if (!isAutoMatched) manualOnly.push(name);
        });
        
        g.proxies = manualOnly.length ? manualOnly : [];
        if (!g.proxies.length && !g.filter && activeSources.size === 0) delete g.proxies;
        
        g.use = Array.from(activeSources);
        if (g.use.length === 0) delete g.use;
        
        if (!state.templateObj['proxy-groups']) state.templateObj['proxy-groups'] = [];
        if (index >= 0) state.templateObj['proxy-groups'][index] = g;
        else state.templateObj['proxy-groups'].push(g);
        
        closeModal();
        saveTemplateObj();
    });

    document.getElementById('m-group-type').addEventListener('change', (e) => {
        let isSelect = e.target.value === 'select';
        document.getElementById('wrap-group-url').style.display = isSelect ? 'none' : 'block';
        document.getElementById('wrap-group-interval').style.display = isSelect ? 'none' : 'block';
        let defaultWrap = document.getElementById('wrap-group-default');
        if (defaultWrap) defaultWrap.style.display = isSelect ? 'block' : 'none';
    });
    
    const filterInput = document.getElementById('m-group-filter');
    const previewBox = document.getElementById('m-group-preview');
    const previewCount = document.getElementById('preview-count');
    
    let activeRegions = new Set();
    let activeSources = new Set();
    
    if (g.use && Array.isArray(g.use)) {
        g.use.forEach(u => activeSources.add(u));
    }
    
    if (g.filter) {
        regions.forEach(r => {
            if (g.filter.includes(r.key)) {
                activeRegions.add(r.key);
                let tag = document.querySelector(`#tags-regions .filter-tag[data-val="${r.key}"]`);
                if (tag) tag.classList.add('active');
            }
        });
    }

    if (g['include-all'] && activeSources.size === 0) {
        document.querySelectorAll('#tags-sources .filter-tag').forEach(t => {
            activeSources.add(t.getAttribute('data-val'));
        });
    }

    document.querySelectorAll('#tags-sources .filter-tag').forEach(tag => {
        if (activeSources.has(tag.getAttribute('data-val'))) tag.classList.add('active');
    });
    
    function updateFilterInput() {
        let parts = [];
        if (activeRegions.size > 0) parts.push(`(${Array.from(activeRegions).join('|')})`);
        
        let finalRe = '';
        if (parts.length > 0) finalRe = `(?i)${parts[0]}`;
        
        filterInput.value = finalRe;
        renderPreview();
    }
    
    document.querySelectorAll('#tags-regions .filter-tag').forEach(tag => {
        tag.addEventListener('click', () => {
            tag.classList.toggle('active');
            let val = tag.getAttribute('data-val');
            if (tag.classList.contains('active')) {
                activeRegions.add(val);
                if (activeSources.size === 0) {
                    document.querySelectorAll('#tags-sources .filter-tag').forEach(t => {
                        t.classList.add('active');
                        activeSources.add(t.getAttribute('data-val'));
                    });
                }
            } else {
                activeRegions.delete(val);
            }
            updateFilterInput();
        });
    });
    
    document.querySelectorAll('#tags-sources .filter-tag').forEach(tag => {
        tag.addEventListener('click', () => {
            tag.classList.toggle('active');
            let val = tag.getAttribute('data-val');
            if (tag.classList.contains('active')) activeSources.add(val);
            else activeSources.delete(val);
            updateFilterInput();
        });
    });
    
    filterInput.addEventListener('input', () => {
        document.querySelectorAll('.filter-tag').forEach(t => t.classList.remove('active'));
        activeRegions.clear();
        activeSources.clear();
        renderPreview();
    });
    
    document.getElementById('m-group-include-all').addEventListener('change', (e) => {
        if (e.target.checked) {
            document.querySelectorAll('#tags-sources .filter-tag').forEach(t => {
                t.classList.add('active');
                activeSources.add(t.getAttribute('data-val'));
            });
            updateFilterInput();
        }
        renderPreview();
    });
    
    function renderPreview() {
        let filterRe = null;
        if (filterInput.value.trim()) {
            try { filterRe = new RegExp(filterInput.value.trim(), 'i'); } 
            catch(e) {}
        }
        
        let proxyNamesGroups = ['DIRECT', 'REJECT'];
        let proxyGroups = state.templateObj['proxy-groups'] || [];
        proxyGroups.forEach(pg => {
            if (pg.name && pg.name !== g.name && !proxyNamesGroups.includes(pg.name)) {
                proxyNamesGroups.push(pg.name);
            }
        });
        
        let proxyNamesNodes = [];
        state.allProxies.forEach(p => { if (!proxyNamesGroups.includes(p.name) && !proxyNamesNodes.includes(p.name)) proxyNamesNodes.push(p.name); });
        
        let html = '';
        let matchedCount = 0;
        
        // Render Proxy Groups Section
        html += `<div style="padding: 5px 10px; background: #f8f9fa; font-weight: bold; font-size: 0.85em; color: #666;">代理组 (不可被智能筛选，需手动微调)</div>`;
        proxyNamesGroups.forEach(name => {
            let isManuallySelected = manualProxies.includes(name);
            if (isManuallySelected) matchedCount++;
            let emojiName = getFlagEmoji(name);
            html += `
                <label class="preview-item">
                    <input type="checkbox" value="${escapeHtml(name)}" ${isManuallySelected ? 'checked' : ''}>
                    <span>${escapeHtml(emojiName)}</span>
                </label>
            `;
        });
        
        // Render Nodes Section
        html += `<div style="padding: 5px 10px; background: #e3f2fd; font-weight: bold; font-size: 0.85em; color: #0056b3;">节点 (由智能筛选器自动匹配)</div>`;
        proxyNamesNodes.forEach(name => {
            let p = state.allProxies.find(x => x.name === name);
            let isMatchedByFilter = false;
            
            if (p) {
                let matchesSource = true;
                if (activeSources.size > 0) {
                    let src = p._airport_name || '_custom_nodes_';
                    if (!activeSources.has(src)) matchesSource = false;
                }
                
                let matchesRegion = true;
                if (filterRe) {
                    if (!filterRe.test(name)) matchesRegion = false;
                }
                
                let includeAllChecked = document.getElementById('m-group-include-all').checked;
                
                if (includeAllChecked && activeSources.size === 0 && !filterRe) {
                    isMatchedByFilter = true;
                } else if ((activeSources.size > 0 || filterRe || includeAllChecked) && matchesSource && matchesRegion) {
                    isMatchedByFilter = true;
                }
            }
            
            let isManuallySelected = manualProxies.includes(name);
            let isChecked = isMatchedByFilter || isManuallySelected;
            
            if (isChecked) matchedCount++;
            
            let labelStyle = isMatchedByFilter ? 'color: var(--primary); font-weight:600;' : '';
            let emojiName = getFlagEmoji(name);
            
            html += `
                <label class="preview-item">
                    <input type="checkbox" value="${escapeHtml(name)}" ${isChecked ? 'checked' : ''} ${isMatchedByFilter ? 'disabled title="已由智能筛选器自动包含"' : ''}>
                    <span style="${labelStyle}">${escapeHtml(emojiName)}</span>
                </label>
            `;
        });
        
        previewBox.innerHTML = html;
        previewCount.innerText = `选中 ${matchedCount} 个`;
        if (window.twemoji) twemoji.parse(previewBox, { folder: 'svg', ext: '.svg' });
    }
    
    renderPreview();
};
document.getElementById('btn-add-group').addEventListener('click', () => editGroup(-1));

window.deleteGroup = function(index) {
    state.templateObj['proxy-groups'].splice(index, 1);
    saveTemplateObj();
};

document.getElementById('btn-bulk-delete-groups').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-group');
    if(!indices.length) return alert('请先勾选要删除的项');
    if(confirm(`确定删除这 ${indices.length} 项吗？`)) {
        indices.forEach(i => state.templateObj['proxy-groups'].splice(i, 1));
        saveTemplateObj();
    }
});

document.getElementById('btn-bulk-add-nodes').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-group');
    if(!indices.length) return alert('请先勾选左侧要操作的目标代理组');
    
    let proxyNames = ['DIRECT', 'REJECT'];
    let proxyGroups = state.templateObj['proxy-groups'] || [];
    proxyGroups.forEach(pg => {
        if (pg.name && !proxyNames.includes(pg.name)) {
            proxyNames.push(pg.name);
        }
    });
    state.allProxies.forEach(p => { if (!proxyNames.includes(p.name)) proxyNames.push(p.name); });
    
    let html = `
        <div class="form-group full-width">
            <label style="margin-bottom: 15px; display: block; color: var(--primary);">请选择要批量添加到选中代理组的节点或代理组：</label>
            <div class="preview-list" style="max-height: 400px;" id="bulk-add-preview-box">
    `;
    
    proxyNames.forEach(name => {
        let emojiName = getFlagEmoji(name);
        html += `
            <label class="preview-item">
                <input type="checkbox" value="${escapeHtml(name)}" class="bulk-add-cb">
                <span>${escapeHtml(emojiName)}</span>
            </label>
        `;
    });
    
    html += `</div></div>`;
    
    openModal('批量添加内容', html, () => {
        let toAdd = [];
        document.querySelectorAll('.bulk-add-cb:checked').forEach(cb => toAdd.push(cb.value));
        if (toAdd.length === 0) return closeModal();
        
        indices.forEach(idx => {
            let g = state.templateObj['proxy-groups'][idx];
            if (!Array.isArray(g.proxies)) g.proxies = [];
            toAdd.forEach(item => {
                if (item !== g.name && !g.proxies.includes(item)) {
                    g.proxies.push(item);
                }
            });
        });
        saveTemplateObj();
        closeModal();
    });
    
    // Parse emojis in the modal
    if (window.twemoji) {
        setTimeout(() => {
            let box = document.getElementById('bulk-add-preview-box');
            if (box) twemoji.parse(box, { folder: 'svg', ext: '.svg' });
        }, 10);
    }
});

document.getElementById('btn-bulk-smart-filter').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-group');
    if(!indices.length) return alert('请先勾选左侧要操作的目标代理组');
    
    const regions = [
        {key: 'hk|香港', label: '🇭🇰 香港'},
        {key: 'jp|日本', label: '🇯🇵 日本'},
        {key: 'us|美国|美', label: '🇺🇸 美国'},
        {key: 'sg|新加坡|狮城', label: '🇸🇬 新加坡'},
        {key: 'tw|台湾|台', label: '🇹🇼 台湾'},
        {key: 'kr|韩国', label: '🇰🇷 韩国'},
        {key: 'uk|英国', label: '🇬🇧 英国'}
    ];
    
    const airportNames = new Set();
    state.airports.forEach(a => {
        let name = typeof a === 'object' ? a.name : a;
        if (name) airportNames.add(name);
    });
    
    let html = `
        <div class="form-group full-width" style="margin-top: 10px;">
            <label style="color:var(--primary); font-size:0.9rem; font-weight: 600;">✨ 批量设置智能筛选器</label>
            <div style="font-size:0.8rem; color:#888; margin-bottom:10px;">此操作将覆盖选中代理组的智能筛选配置，不会影响手动勾选的节点或嵌套代理组。</div>
            
            <label style="display:flex; align-items:center; cursor:pointer; font-size:0.9rem; margin-bottom:15px; color:#333;">
                <input type="checkbox" id="bulk-group-include-all" style="margin-right:8px; width:16px; height:16px;"> 
                自动包含全部节点 (后续新增节点也会自动加入)
            </label>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:#666; font-weight: 600;">1. 快速选择地区 (覆盖正则):</div>
            <div class="filter-tags" id="bulk-tags-regions">
                ${regions.map(r => `<div class="filter-tag" data-val="${r.key}">${r.label}</div>`).join('')}
            </div>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:#666; font-weight: 600;">2. 快速选择节点来源 (覆盖来源):</div>
            <div class="filter-tags" id="bulk-tags-sources">
                ${Array.from(airportNames).map(name => `<div class="filter-tag" data-val="${escapeHtml(name)}">✈️ ${escapeHtml(name)}</div>`).join('')}
                <div class="filter-tag" data-val="_custom_nodes_">🌐 自建节点</div>
            </div>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:#666; font-weight: 600;">底层正则表达式 (可手动修改):</div>
            <input type="text" id="bulk-group-filter" value="" placeholder="例如: (?i)hk|香港">
        </div>
    `;
    
    openModal('批量智能筛选', html, () => {
        let includeAll = document.getElementById('bulk-group-include-all').checked;
        let filterInput = document.getElementById('bulk-group-filter').value.trim();
        let sources = [];
        document.querySelectorAll('#bulk-tags-sources .filter-tag.active').forEach(t => sources.push(t.getAttribute('data-val')));
        
        indices.forEach(idx => {
            let g = state.templateObj['proxy-groups'][idx];
            if (includeAll) g['include-all'] = true;
            else delete g['include-all'];
            
            if (filterInput) g.filter = filterInput;
            else delete g.filter;
            
            if (sources.length > 0) g.use = sources;
            else delete g.use;
        });
        saveTemplateObj();
        closeModal();
    });
    
    // Wire up the bulk modal logic
    let bulkActiveRegions = new Set();
    let bulkActiveSources = new Set();
    let bulkFilterInput = document.getElementById('bulk-group-filter');
    
    function updateBulkFilterInput() {
        if (bulkActiveRegions.size === 0) {
            bulkFilterInput.value = '';
        } else {
            bulkFilterInput.value = '(?i)' + Array.from(bulkActiveRegions).join('|');
        }
    }
    
    document.querySelectorAll('#bulk-tags-regions .filter-tag').forEach(tag => {
        tag.addEventListener('click', () => {
            tag.classList.toggle('active');
            let val = tag.getAttribute('data-val');
            if (tag.classList.contains('active')) {
                bulkActiveRegions.add(val);
                if (bulkActiveSources.size === 0) {
                    document.querySelectorAll('#bulk-tags-sources .filter-tag').forEach(t => {
                        t.classList.add('active');
                        bulkActiveSources.add(t.getAttribute('data-val'));
                    });
                }
            } else {
                bulkActiveRegions.delete(val);
            }
            updateBulkFilterInput();
        });
    });
    
    document.querySelectorAll('#bulk-tags-sources .filter-tag').forEach(tag => {
        tag.addEventListener('click', () => {
            tag.classList.toggle('active');
            let val = tag.getAttribute('data-val');
            if (tag.classList.contains('active')) bulkActiveSources.add(val);
            else bulkActiveSources.delete(val);
        });
    });
    
    bulkFilterInput.addEventListener('input', () => {
        document.querySelectorAll('#bulk-tags-regions .filter-tag').forEach(t => t.classList.remove('active'));
        bulkActiveRegions.clear();
    });
});

// === Actions: Nodes ===
window.editNode = function(index) {
    let isNew = index < 0;
    let yamlStr = isNew ? "name: New Node\ntype: vmess\nserver: 1.1.1.1\nport: 443" : jsyaml.dump(state.nodes[index]);
    const html = `
        <div class="form-group full-width">
            <label>节点配置 (YAML格式) - 或者直接粘贴 vless://、tuic://、anytls://、wireguard:// 等分享链接</label>
            <textarea id="m-node-raw" style="min-height:250px; font-family:monospace;">${escapeHtml(yamlStr)}</textarea>
        </div>
    `;
    openModal(isNew ? '新建自建节点' : '编辑自建节点', html, async () => {
        try {
            let val = document.getElementById('m-node-raw').value.trim();
            let parsed;
            if (SHARE_LINK_PATTERN.test(val)) {
                const res = await fetchAuth('/parse-links', {
                    method: 'POST',
                    body: JSON.stringify({ links: [val] })
                });
                const data = await res.json();
                if (data.nodes && data.nodes.length) {
                    parsed = data.nodes[0];
                } else {
                    return alert('分享链接解析失败，不支持的协议或格式有误');
                }
            } else {
                parsed = jsyaml.load(val);
            }
            if(isNew) state.nodes.push(parsed);
            else state.nodes[index] = parsed;
            closeModal();
            saveNodesObj();
        } catch(e) { alert('YAML 解析失败'); }
    });
};
document.getElementById('btn-add-node').addEventListener('click', () => editNode(-1));

document.getElementById('btn-import-nodes').addEventListener('click', () => {
    const html = `
        <div class="form-group full-width">
            <label>选择 YAML 文件上传，或在下方直接粘贴 (支持 YAML / JSON / 分享链接 vless:// 等)</label>
            <input type="file" id="m-nodes-file" accept=".yaml,.yml,.txt,.json" style="margin-bottom: 10px; cursor: pointer;">
            <textarea id="m-nodes-import" style="min-height:250px;" placeholder="支持粘贴标准 YAML 节点列表，或者直接粘贴 vless:// vmess:// hysteria2:// tuic:// anytls:// wireguard:// 链接 (每行一个)"></textarea>
        </div>
    `;
    openModal('批量导入自建节点', html, async () => {
        try {
            let text = document.getElementById('m-nodes-import').value;
            let lines = text.split('\n').map(s=>s.trim()).filter(s=>s);
            let links = lines.filter(s => SHARE_LINK_PATTERN.test(s));
            let nonLinksText = lines.filter(s => !SHARE_LINK_PATTERN.test(s)).join('\n');
            
            let toAdd = [];
            if(nonLinksText) {
                let parsed = jsyaml.load(nonLinksText);
                if (parsed) {
                    toAdd = Array.isArray(parsed) ? parsed : (parsed.proxies || []);
                }
            }
            
            if (links.length > 0) {
                const res = await fetchAuth('/parse-links', {
                    method: 'POST',
                    body: JSON.stringify({ links })
                });
                const data = await res.json();
                if (data.nodes && data.nodes.length) {
                    toAdd = toAdd.concat(data.nodes);
                }
            }
            
            if (toAdd.length) {
                state.nodes = state.nodes.concat(toAdd);
                closeModal();
                saveNodesObj();
                showToast(`成功导入 ${toAdd.length} 个节点`);
            } else {
                alert('没有解析到任何有效节点');
            }
        } catch(e) { alert('解析失败: ' + e.message); }
    });

    document.getElementById('m-nodes-file').addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
            document.getElementById('m-nodes-import').value = ev.target.result;
        };
        reader.readAsText(file);
    });
});

window.deleteNode = function(index) {
    state.nodes.splice(index, 1);
    saveNodesObj();
};

window.moveNodeUp = function(index) {
    if (index > 0) {
        let temp = state.nodes[index];
        state.nodes[index] = state.nodes[index - 1];
        state.nodes[index - 1] = temp;
        saveNodesObj();
    }
};

window.moveNodeDown = function(index) {
    if (index < state.nodes.length - 1) {
        let temp = state.nodes[index];
        state.nodes[index] = state.nodes[index + 1];
        state.nodes[index + 1] = temp;
        saveNodesObj();
    }
};

let draggedNodeIndex = null;

window.handleDragStart = function(e, index) {
    draggedNodeIndex = index;
    e.dataTransfer.effectAllowed = 'move';
    e.currentTarget.classList.add('dragging');
};

window.handleDragOver = function(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    return false;
};

window.handleDragEnter = function(e) {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
};

window.handleDragLeave = function(e) {
    e.currentTarget.classList.remove('drag-over');
};

window.handleDrop = function(e, dropIndex) {
    e.stopPropagation();
    e.currentTarget.classList.remove('drag-over');
    if (draggedNodeIndex !== null && draggedNodeIndex !== dropIndex) {
        let draggedItem = state.nodes.splice(draggedNodeIndex, 1)[0];
        state.nodes.splice(dropIndex, 0, draggedItem);
        saveNodesObj();
    }
    draggedNodeIndex = null;
    return false;
};

window.handleDragEnd = function(e) {
    e.currentTarget.classList.remove('dragging');
    document.querySelectorAll('.list-item').forEach(el => el.classList.remove('drag-over'));
};

document.getElementById('btn-bulk-delete-nodes').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-node');
    if(!indices.length) return alert('请先勾选要删除的项');
    if(confirm(`确定删除这 ${indices.length} 项吗？`)) {
        indices.forEach(i => state.nodes.splice(i, 1));
        saveNodesObj();
    }
});

async function saveNodesObj() {
    renderNodes();
    let locked = false;
    try {
        templateGuard();
        externalTemplateBusy = true; locked = true; rulesEditor.readOnly = true;
        const response = await fetchAuth('/nodes', {
            method: 'POST',
            body: JSON.stringify({ nodes: state.nodes })
        });
        const result = await response.json();
        if (result.cleanedReferences > 0) {
            await reloadTemplateState();
            showToast(`节点已保存，并清理 ${result.cleanedReferences} 处失效引用`);
        } else {
            showToast('节点已保存');
        }
        const allProxiesRes = await fetchAuth('/proxies');
        state.allProxies = (await allProxiesRes.json()).proxies || [];
    } catch(e) { showToast(`保存失败：${e.message}`, 'error'); }
    finally { if (locked) { externalTemplateBusy = false; rulesEditor.readOnly = false; } }
}

// === Actions: Rules ===
document.getElementById('btn-add-rule').addEventListener('click', () => {
    const html = `
        <div class="form-group full-width">
            <label>单条路由规则</label>
            <input type="text" id="m-rule-input" placeholder="DOMAIN-SUFFIX,google.com,Proxy">
        </div>
    `;
    openModal('添加路由规则', html, () => {
        let val = document.getElementById('m-rule-input').value.trim();
        if(val) {
            if (!state.templateObj['rules']) state.templateObj['rules'] = [];
            state.templateObj['rules'].unshift(val);
            closeModal();
            saveTemplateObj();
        }
    });
});

document.getElementById('btn-import-rules').addEventListener('click', () => {
    const html = `
        <div class="form-group full-width">
            <label>批量粘贴路由规则 (每行一条)</label>
            <textarea id="m-rules-import" style="min-height:250px;"></textarea>
        </div>
    `;
    openModal('批量导入规则', html, () => {
        let lines = document.getElementById('m-rules-import').value.split('\n').map(s=>s.trim()).filter(s=>s);
        if(lines.length) {
            if (!state.templateObj['rules']) state.templateObj['rules'] = [];
            state.templateObj['rules'] = lines.concat(state.templateObj['rules']);
            closeModal();
            saveTemplateObj();
            showToast(`成功导入 ${lines.length} 条规则`);
        }
    });
});

window.deleteRule = function(index) {
    state.templateObj['rules'].splice(index, 1);
    saveTemplateObj();
};

document.getElementById('btn-bulk-delete-rules').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-rule');
    if(!indices.length) return alert('请先勾选要删除的项');
    if(confirm(`确定删除这 ${indices.length} 项吗？`)) {
        indices.forEach(i => state.templateObj['rules'].splice(i, 1));
        saveTemplateObj();
    }
});

async function saveTemplateObj(candidate = state.templateObj, source = 'other', raw = null) {
    try {
        templateGuard(source);
        const content = raw === null ? jsyaml.dump(candidate) : raw;
        // Legacy actions mutate state before calling this function. Keep the
        // authoritative state at the last confirmed snapshot until commit.
        state.templateObj = ProxyForgeNetwork.clone(savedTemplateObj);
        renderTemplateViews();
        rulesEditor.readOnly = true;
        const result = await templateSession.save(content);
        if (!result.ok && source === 'other') rulesEditor.value = content;
        if (result.conflict) showTemplateConflict(result.conflict);
        showToast(result.message || (result.report?.warnings.length ? '已保存，存在配置建议，请查看 DNS 与网络' : '已保存底层模板'), result.ok ? result.report?.warnings.length ? 'warning' : 'success' : 'error');
        return result.ok;
    } catch (error) {
        state.templateObj = ProxyForgeNetwork.clone(savedTemplateObj);
        renderTemplateViews();
        showToast(`保存失败：${error.message}`, 'error');
        return false;
    } finally { rulesEditor.readOnly = false; }
}

// === Action: Global Import ===
const globalImportBtn = document.getElementById('global-import-btn');
if (globalImportBtn) {
    globalImportBtn.addEventListener('click', () => {
        const html = `
            <div class="form-group full-width">
                <label>选择 YAML 文件上传，或在下方直接粘贴</label>
                <input type="file" id="m-global-file" accept=".yaml,.yml,.txt" style="margin-bottom: 10px; cursor: pointer;">
                <textarea id="m-global-yaml" style="min-height:300px; font-family:monospace;" placeholder="proxies: ...\nproxy-groups: ...\nrules: ..."></textarea>
                <span class="hint">系统会自动提取 proxies 合并到您的“自建节点”，并将 proxy-groups 和 rules 等覆盖到“底层配置”。</span>
            </div>
        `;
        openModal('📥 全局 YAML 智能导入', html, async () => {
            let locked = false;
            try {
                templateGuard();
                let raw = document.getElementById('m-global-yaml').value;
                let parsed = parseTemplate(raw);
                externalTemplateBusy = true; locked = true; rulesEditor.readOnly = true;

                let importedNodes = [];
                let importedAirports = [];
                let nodeCount = 0;
                if (parsed.proxies && Array.isArray(parsed.proxies)) {
                    importedNodes = parsed.proxies;
                    nodeCount = parsed.proxies.length;
                    delete parsed.proxies;
                } else {
                    importedNodes = [];
                }

                let airportCount = 0;
                importedAirports = [];
                if (parsed['proxy-providers'] && typeof parsed['proxy-providers'] === 'object') {
                    for (const key in parsed['proxy-providers']) {
                        const provider = parsed['proxy-providers'][key];
                        if (provider && provider.type === 'http' && provider.url) {
                            if (!importedAirports.find(a => a.url === provider.url)) {
                                importedAirports.push({ name: key, url: provider.url });
                                airportCount++;
                            }
                        }
                    }
                    delete parsed['proxy-providers'];
                }
                const importedTemplateRaw = jsyaml.dump(parsed);

                const response = await fetchAuth('/template/import', {
                    method: 'POST', body: JSON.stringify({ content: importedTemplateRaw,
                        expected_revision: state.templateRevision, nodes: importedNodes, urls: importedAirports })
                });
                installTemplate(await response.json());
                state.nodes = importedNodes;
                state.airports = importedAirports;
                renderNodes(); renderAirports();
                closeModal();
                showToast(`全局导入覆盖成功！提取 ${nodeCount} 个节点，${airportCount} 个机场，并更新底层配置。`);
            } catch (e) {
                // Keep the import textarea and every existing draft on errors.
                alert('导入未确认，已保留草稿。请重新读取服务器状态后核对：' + e.message);
            } finally { if (locked) { externalTemplateBusy = false; rulesEditor.readOnly = false; } }
        });

        document.getElementById('m-global-file').addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (ev) => {
                document.getElementById('m-global-yaml').value = ev.target.result;
            };
            reader.readAsText(file);
        });
    });
}

// === Action: Config & Raw Save ===
copyBtn.addEventListener('click', () => {
    subLink.select();
    document.execCommand('copy');
    showToast('链接已复制到剪贴板');
});

saveConfigBtn.addEventListener('click', async () => {
    try {
        const newToken = secretToken.value.trim();
        if (newToken.length < 16) {
            showToast('密钥至少需要 16 个字符', 'error');
            return;
        }
        const payload = { SUBSCRIPTION_TOKEN: newToken };
        await fetchAuth('/config', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        state.config.SUBSCRIPTION_TOKEN = newToken;
        showToast('订阅密钥已保存');
        const name = encodeURIComponent(document.getElementById('sub-name').value.trim() || 'ProxyForge');
        subLink.value = `${window.location.origin}/sub?token=${payload.SUBSCRIPTION_TOKEN}&name=${name}`;
    } catch (e) { showToast(`保存密钥失败：${e.message}`, 'error'); }
});

saveAdminTokenBtn.addEventListener('click', async () => {
    try {
        const token = newAdminToken.value.trim();
        if (token.length < 16) {
            showToast('管理密钥至少需要 16 个字符', 'error');
            return;
        }
        await fetchAuth('/admin-token', {
            method: 'POST',
            body: JSON.stringify({ ADMIN_TOKEN: token })
        });
        newAdminToken.value = '';
        showToast('管理密钥已更新，其他登录会话已失效');
    } catch (e) { showToast(`更新管理密钥失败：${e.message}`, 'error'); }
});

saveRulesBtn.addEventListener('click', async () => {
    await saveTemplateObj(null, 'raw', rulesEditor.value);
});

// === Actions: Rules & Rule Providers ===
window.deleteRule = function(index) {
    state.templateObj['rules'].splice(index, 1);
    saveTemplateObj();
};

document.getElementById('btn-bulk-delete-rules').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-rule');
    if(!indices.length) return alert('请先勾选要删除的规则');
    if(confirm(`确定删除这 ${indices.length} 项吗？`)) {
        indices.forEach(i => state.templateObj['rules'].splice(i, 1));
        saveTemplateObj();
    }
});

window.deleteRuleProvider = function(key) {
    if(confirm(`确定删除规则集 [${key}] 吗？`)) {
        delete state.templateObj['rule-providers'][key];
        saveTemplateObj();
    }
};

window.editRuleProviderByIndex = function(index) {
    const key = Object.keys(state.templateObj['rule-providers'] || {})[index];
    if (key !== undefined) editRuleProvider(key);
};

window.deleteRuleProviderByIndex = function(index) {
    const key = Object.keys(state.templateObj['rule-providers'] || {})[index];
    if (key !== undefined) deleteRuleProvider(key);
};

const RULE_TYPES = ['DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN', 'IP-CIDR', 'GEOIP', 'MATCH', 'RULE-SET'];

window.editRule = function(index) {
    let isNew = index < 0;
    let r = isNew ? '' : state.templateObj['rules'][index];
    let parts = r ? r.split(',') : [];
    
    let type = parts[0] || 'DOMAIN-SUFFIX';
    let payload = '';
    let target = '';
    if (type === 'MATCH') {
        target = parts[1] || '';
    } else {
        payload = parts[1] || '';
        target = parts[2] || '';
    }
    
    let targetsHtml = ['DIRECT', 'REJECT'];
    let proxyGroups = state.templateObj['proxy-groups'] || [];
    proxyGroups.forEach(g => { if(g.name) targetsHtml.push(g.name); });
    
    let html = `
        <div class="form-group full-width">
            <label>规则类型 (Type)</label>
            <select id="m-rule-type">
                ${RULE_TYPES.map(t => `<option value="${t}" ${t===type?'selected':''}>${t}</option>`).join('')}
            </select>
        </div>
        <div class="form-group full-width" id="m-rule-payload-group" style="${type==='MATCH' ? 'display:none;' : ''}">
            <label>匹配内容 (Payload)</label>
            <input type="text" id="m-rule-payload" value="${escapeHtml(payload)}" placeholder="如 google.com 或 reject_list">
        </div>
        <div class="form-group full-width">
            <label>目标策略 (Target)</label>
            <select id="m-rule-target">
                ${targetsHtml.map(t => `<option value="${escapeHtml(t)}" ${t===target?'selected':''}>${escapeHtml(t)}</option>`).join('')}
            </select>
        </div>
    `;
    openModal(isNew ? '新建规则' : '编辑规则', html, () => {
        let nType = document.getElementById('m-rule-type').value;
        let nPayload = document.getElementById('m-rule-payload').value.trim();
        let nTarget = document.getElementById('m-rule-target').value;
        
        let newRule = '';
        if (nType === 'MATCH') {
            newRule = `${nType},${nTarget}`;
        } else {
            if(!nPayload) return alert('请输入匹配内容');
            newRule = `${nType},${nPayload},${nTarget}`;
        }
        
        if (!state.templateObj['rules']) state.templateObj['rules'] = [];
        if (isNew) {
            // New routing rules take highest priority; MATCH remains the final fallback.
            ProxyForgeRuleUtils.insertNewRule(state.templateObj['rules'], newRule);
        } else {
            state.templateObj['rules'][index] = newRule;
        }
        saveTemplateObj();
        closeModal();
    });
    
    document.getElementById('m-rule-type').addEventListener('change', function() {
        if(this.value === 'MATCH') document.getElementById('m-rule-payload-group').style.display = 'none';
        else document.getElementById('m-rule-payload-group').style.display = 'block';
    });
};

document.getElementById('btn-add-rule').addEventListener('click', () => editRule(-1));

window.editRuleProvider = function(keyToEdit) {
    let isNew = !keyToEdit;
    let p = isNew ? { type: 'http', behavior: 'domain', interval: 86400 } : state.templateObj['rule-providers'][keyToEdit];
    
    let html = `
        <div class="form-group full-width">
            <label>规则集名称 (Name)</label>
            <input type="text" id="m-rp-name" value="${escapeHtml(isNew ? '' : keyToEdit)}" ${isNew ? '' : 'readonly'} placeholder="英文，如 reject_list">
        </div>
        <div class="form-group">
            <label>类型 (Type)</label>
            <select id="m-rp-type">
                <option value="http" ${p.type==='http'?'selected':''}>http (远程)</option>
                <option value="file" ${p.type==='file'?'selected':''}>file (本地)</option>
            </select>
        </div>
        <div class="form-group">
            <label>行为 (Behavior)</label>
            <select id="m-rp-behavior">
                <option value="domain" ${p.behavior==='domain'?'selected':''}>domain</option>
                <option value="ipcidr" ${p.behavior==='ipcidr'?'selected':''}>ipcidr</option>
                <option value="classical" ${p.behavior==='classical'?'selected':''}>classical</option>
            </select>
        </div>
        <div class="form-group full-width" id="m-rp-url-group" style="${p.type==='file'?'display:none;':''}">
            <label>下载地址 (URL)</label>
            <input type="text" id="m-rp-url" value="${escapeHtml(p.url || '')}" placeholder="https://...">
        </div>
        <div class="form-group full-width">
            <label>本地路径 (Path)</label>
            <input type="text" id="m-rp-path" value="${escapeHtml(p.path || './ruleset/' + (isNew ? 'my_ruleset.yaml' : keyToEdit + '.yaml'))}" placeholder="./ruleset/...">
        </div>
        <div class="form-group full-width" id="m-rp-interval-group" style="${p.type==='file'?'display:none;':''}">
            <label>更新间隔 (Interval 单位:秒)</label>
            <input type="number" id="m-rp-interval" value="${escapeHtml(p.interval || 86400)}">
        </div>
    `;
    openModal(isNew ? '添加规则集' : '编辑规则集', html, () => {
        let nName = document.getElementById('m-rp-name').value.trim();
        if(!nName) return alert('请输入名称');
        
        let nType = document.getElementById('m-rp-type').value;
        let nBehavior = document.getElementById('m-rp-behavior').value;
        let nPath = document.getElementById('m-rp-path').value.trim();
        
        if (!state.templateObj['rule-providers']) state.templateObj['rule-providers'] = {};
        let obj = {
            type: nType,
            behavior: nBehavior,
            path: nPath
        };
        
        if (nType === 'http') {
            obj.url = document.getElementById('m-rp-url').value.trim();
            obj.interval = parseInt(document.getElementById('m-rp-interval').value) || 86400;
        }
        
        state.templateObj['rule-providers'][nName] = obj;
        saveTemplateObj();
        closeModal();
    });
    
    document.getElementById('m-rp-type').addEventListener('change', function() {
        let isHttp = this.value === 'http';
        document.getElementById('m-rp-url-group').style.display = isHttp ? 'block' : 'none';
        document.getElementById('m-rp-interval-group').style.display = isHttp ? 'block' : 'none';
    });
};

document.getElementById('btn-add-rule-provider').addEventListener('click', () => editRuleProvider(null));

document.getElementById('btn-import-rules').addEventListener('click', () => {
    let html = `
        <div class="form-group full-width">
            <label>粘贴分流规则 (一行一个)</label>
            <textarea id="m-import-rules" style="height:200px" placeholder="DOMAIN-SUFFIX,google.com,🚀 节点选择\nIP-CIDR,1.1.1.1/32,DIRECT"></textarea>
        </div>
    `;
    openModal('批量导入规则', html, () => {
        let lines = document.getElementById('m-import-rules').value.split('\n').map(l=>l.trim()).filter(l=>l && l.includes(','));
        if(lines.length) {
            if (!state.templateObj['rules']) state.templateObj['rules'] = [];
            state.templateObj['rules'] = lines.concat(state.templateObj['rules']);
            saveTemplateObj();
        }
        closeModal();
    });
});

// === Rule Drag and Drop ===
let draggedRuleIndex = -1;

window.handleRuleDragStart = (e, index) => {
    draggedRuleIndex = index;
    e.dataTransfer.effectAllowed = 'move';
    e.currentTarget.style.opacity = '0.4';
};

window.handleRuleDragOver = (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    return false;
};

window.handleRuleDragEnter = (e) => {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
};

window.handleRuleDragLeave = (e) => {
    e.currentTarget.classList.remove('drag-over');
};

window.handleRuleDrop = (e, targetIndex) => {
    e.stopPropagation();
    e.currentTarget.classList.remove('drag-over');
    if (draggedRuleIndex !== targetIndex && draggedRuleIndex !== -1) {
        let rules = state.templateObj['rules'];
        const item = rules.splice(draggedRuleIndex, 1)[0];
        rules.splice(targetIndex, 0, item);
        saveTemplateObj();
    }
    return false;
};

window.handleRuleDragEnd = (e) => {
    e.currentTarget.style.opacity = '1';
    document.querySelectorAll('#rules-list .list-item').forEach(item => {
        item.classList.remove('drag-over');
    });
    draggedRuleIndex = -1;
};

// === Final Preview ===
const previewEditor = document.getElementById('preview-editor');
const refreshPreviewBtn = document.getElementById('refresh-preview-btn');

async function loadFinalPreview() {
    previewEditor.value = '正在从后端生成最终订阅配置...\n如果数据量大可能会需要几秒钟，请稍候...';
    try {
        let res = await fetch(`/sub?token=${encodeURIComponent(state.config.SUBSCRIPTION_TOKEN)}`);
        if (!res.ok) {
            let errText = await res.text();
            throw new Error(`HTTP ${res.status}: ${errText}`);
        }
        let text = await res.text();
        previewEditor.value = text;
    } catch(e) {
        previewEditor.value = `获取最终订阅失败:\n\n${e.message}`;
        showToast('获取最终订阅失败', 'error');
    }
}

refreshPreviewBtn.addEventListener('click', loadFinalPreview);

// Hook into sidebar click to auto-load when switching to preview
document.querySelectorAll('.sidebar-item').forEach(el => {
    el.addEventListener('click', () => {
        if (el.getAttribute('data-panel') === 'panel-preview') {
            loadFinalPreview();
        }
    });
});

// === Proxy Group Drag and Drop ===
let draggedGroupIndex = -1;

window.handleGroupDragStart = (e, index) => {
    draggedGroupIndex = index;
    e.dataTransfer.effectAllowed = 'move';
    e.currentTarget.style.opacity = '0.4';
};

window.handleGroupDragOver = (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    return false;
};

window.handleGroupDragEnter = (e) => {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
};

window.handleGroupDragLeave = (e) => {
    e.currentTarget.classList.remove('drag-over');
};

window.handleGroupDrop = (e, targetIndex) => {
    e.stopPropagation();
    e.currentTarget.classList.remove('drag-over');
    if (draggedGroupIndex !== targetIndex && draggedGroupIndex !== -1) {
        let groups = state.templateObj['proxy-groups'];
        const item = groups.splice(draggedGroupIndex, 1)[0];
        groups.splice(targetIndex, 0, item);
        saveTemplateObj();
        renderGroups();
    }
    return false;
};

window.handleGroupDragEnd = (e) => {
    e.currentTarget.style.opacity = '1';
    document.querySelectorAll('#groups-list .list-item').forEach(item => {
        item.classList.remove('drag-over');
    });
    draggedGroupIndex = -1;
};
