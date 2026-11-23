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
    subUsers: [],
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
const mobileCopyBtn = document.getElementById('mobile-copy-btn');
const mobileNavToggle = document.getElementById('mobile-nav-toggle');
const sidebarEl = document.getElementById('sidebar');
const sidebarBackdrop = document.getElementById('sidebar-backdrop');
const subscriptionFormat = document.getElementById('sub-format');
const subQrBtn = document.getElementById('sub-qr-btn');
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
    else if (target.closest('#panel-groups, #panel-rules, #manual-nodes-section, #panel-airports') || target.id === 'global-import-btn') {
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

async function copyTextToClipboard(text, successMsg = '链接已复制到剪贴板') {
    const value = String(text || '');
    if (!value) { showToast('没有可复制的内容', 'warning'); return; }
    try {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            await navigator.clipboard.writeText(value);
            showToast(successMsg);
            return;
        }
    } catch {}
    const helper = document.createElement('textarea');
    helper.value = value;
    helper.setAttribute('readonly', '');
    helper.style.position = 'fixed';
    helper.style.opacity = '0';
    document.body.appendChild(helper);
    helper.select();
    try {
        document.execCommand('copy');
        showToast(successMsg);
    } finally {
        helper.remove();
    }
}

function openSubscriptionQrModal(url, label = '订阅二维码') {
    openModal('订阅二维码', '<div class="qr-preview-box" id="qr-preview-box"></div>', closeModal);
    modalConfirm.textContent = '关闭';
    const box = document.getElementById('qr-preview-box');
    const titleEl = document.createElement('div');
    titleEl.style.fontWeight = '600';
    titleEl.textContent = label || '订阅二维码';
    box.appendChild(titleEl);
    const svgWrap = document.createElement('div');
    try {
        svgWrap.innerHTML = ProxyForgeSubscription.renderQrSvg(url);
    } catch (e) {
        const msg = document.createElement('p');
        msg.className = 'hint';
        msg.textContent = `无法生成二维码（${e.message || '内容过长'}），请直接复制下方链接。`;
        svgWrap.appendChild(msg);
    }
    box.appendChild(svgWrap);
    const urlInput = document.createElement('input');
    urlInput.type = 'text';
    urlInput.readOnly = true;
    urlInput.value = url;
    urlInput.style.width = '100%';
    box.appendChild(urlInput);
    const qrCopyBtn = document.createElement('button');
    qrCopyBtn.type = 'button';
    qrCopyBtn.className = 'btn btn-primary btn-sm';
    qrCopyBtn.textContent = '复制订阅链接';
    qrCopyBtn.addEventListener('click', () => copyTextToClipboard(url, '链接已复制到剪贴板'));
    box.appendChild(qrCopyBtn);
}

// === Modal Logic ===
function openModal(title, htmlContent, onConfirm) {
    if (typeof clearRegistrationToken === 'function') clearRegistrationToken();
    modalConfirm.disabled = false;
    modalConfirm.textContent = '确认';
    modalReturnFocus = document.activeElement;
    modalTitle.textContent = title;
    modalBody.innerHTML = htmlContent;
    if (typeof window !== 'undefined' && window.twemoji) window.twemoji.parse(modalBody, { folder: 'svg', ext: '.svg' });
    modalConfirmAction = onConfirm;
    modalOverlay.classList.add('active');
    setTimeout(() => (modalBody.querySelector('input, select, textarea, button') || modalConfirm).focus(), 0);
}
function closeModal() {
    if (typeof clearRegistrationToken === 'function') clearRegistrationToken();
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
    closeModal();
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

function setMobileSidebarOpen(open) {
    if (!sidebarEl) return;
    sidebarEl.classList.toggle('open', Boolean(open));
    if (sidebarBackdrop) sidebarBackdrop.hidden = !open;
    if (mobileNavToggle) mobileNavToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
}

if (mobileNavToggle) {
    mobileNavToggle.addEventListener('click', () => {
        const nextOpen = !sidebarEl?.classList.contains('open');
        setMobileSidebarOpen(nextOpen);
    });
}
if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener('click', () => setMobileSidebarOpen(false));
}

// === Navigation ===
sidebarItems.forEach(item => {
    item.addEventListener('click', () => {
        sidebarItems.forEach(i => {
            i.classList.remove('active');
            i.removeAttribute('aria-current');
        });
        sectionPanels.forEach(p => p.classList.remove('active'));
        item.classList.add('active');
        item.setAttribute('aria-current', 'page');
        item.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        document.getElementById(item.getAttribute('data-panel')).classList.add('active');
        setMobileSidebarOpen(false);
    });
});

// === Data Loading & Rendering ===
function subscriptionOptions() {
    return {};
}

function updateSubLink() {
    subLink.value = ProxyForgeSubscription.buildUrl(
        window.location.origin,
        state.config.SUBSCRIPTION_TOKEN,
        document.getElementById('sub-name').value,
        subscriptionFormat.value,
        subscriptionOptions(),
    );
}
document.getElementById('sub-name').addEventListener('input', updateSubLink);
subscriptionFormat.addEventListener('change', () => {
    updateSubLink();
    if (document.getElementById('panel-preview').classList.contains('active')) loadFinalPreview();
});
if (subQrBtn) {
    subQrBtn.addEventListener('click', () => {
        openSubscriptionQrModal(subLink.value, document.getElementById('sub-name').value || 'ProxyForge');
    });
}

async function loadData() {
    try {
        const configRes = await fetchAuth('/config');
        state.config = await configRes.json();
        secretToken.value = state.config.SUBSCRIPTION_TOKEN;
        updateSubLink();

        const airportsRes = await fetchAuth('/airports');
        let rawAirports = (await airportsRes.json()).urls || [];
        state.airports = rawAirports.map(u => typeof u === 'string' ? {url: u} : u);

        const nodesRes = await fetchAuth('/nodes');
        state.nodes = (await nodesRes.json()).nodes || [];
        
        const allProxiesRes = await fetchAuth('/proxies');
        state.allProxies = (await allProxiesRes.json()).proxies || [];
        
        renderAirports();
        renderNodes();
        if (typeof ProxyForgeManagedNodes !== 'undefined') ProxyForgeManagedNodes.refresh();
        loadSubUsers();
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

// === Multi-User Subscriptions & Quota ===
function formatExpireAt(expireAt) {
    if (!expireAt || Number(expireAt) <= 0) return '永不过期';
    const d = new Date(Number(expireAt) * 1000);
    return Number.isNaN(d.getTime()) ? '永不过期' : d.toLocaleString();
}

function toLocalDatetimeInputValue(unixSeconds) {
    if (!unixSeconds || Number(unixSeconds) <= 0) return '';
    const d = new Date(Number(unixSeconds) * 1000);
    if (Number.isNaN(d.getTime())) return '';
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function buildUserSubUrlForCurrentFormat(token, user) {
    const baseName = (document.getElementById('sub-name')?.value || '').trim() || 'ProxyForge';
    const name = user?.username ? `${baseName}-${user.username}` : baseName;
    const opts = user?.prefer_relay ? { preferRelay: true } : {};
    return ProxyForgeSubscription.buildUserUrl(window.location.origin, token, name, subscriptionFormat.value, opts);
}

async function fetchUserTokenAndAct(user, mode) {
    const res = await fetchAuth(`/sub-users/${encodeURIComponent(user.id)}/token`);
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
    const data = await res.json();
    const url = buildUserSubUrlForCurrentFormat(data.token, user);
    if (mode === 'qr') openSubscriptionQrModal(url, `${user.username} 订阅二维码`);
    else await copyTextToClipboard(url, `已复制 ${user.username} 的订阅链接`);
}

function renderSubUsers() {
    const container = document.getElementById('sub-users-list');
    if (!container) return;
    container.replaceChildren();
    const users = Array.isArray(state.subUsers) ? state.subUsers : [];
    if (!users.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = '暂无订阅用户，点击右上角「新建订阅用户」分配独立配额与订阅 Token。';
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
        const nameEl = document.createElement('strong');
        nameEl.textContent = user.username;
        titleWrap.appendChild(nameEl);
        const prefixEl = document.createElement('span');
        prefixEl.className = 'sub-user-meta';
        prefixEl.style.marginLeft = '8px';
        prefixEl.textContent = `${user.token_prefix || ''}…`;
        titleWrap.appendChild(prefixEl);

        const badge = document.createElement('span');
        badge.className = `status-pill ${user.enabled ? 'is-online' : 'is-offline'}`;
        if (user.enabled) {
            badge.textContent = '启用中';
        } else {
            badge.textContent = user.disabled_reason ? `已停用 (${user.disabled_reason})` : '已停用';
        }
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
        usageLine.textContent = quota > 0
            ? `已用 ${formatBytes(used)} / ${formatBytes(quota)} (${pct}%) · 上行 ${formatBytes(user.upload_bytes)} / 下行 ${formatBytes(user.download_bytes)}`
            : `已用 ${formatBytes(used)} / 不限配额 · 上行 ${formatBytes(user.upload_bytes)} / 下行 ${formatBytes(user.download_bytes)}`;
        card.appendChild(usageLine);

        const metaLine = document.createElement('div');
        metaLine.className = 'sub-user-meta';
        const tags = [`到期: ${formatExpireAt(user.expire_at)}`];
        if (Array.isArray(user.allowed_groups) && user.allowed_groups.length) tags.push(`分组: ${user.allowed_groups.join(', ')}`);
        if (Array.isArray(user.forward_rule_ids) && user.forward_rule_ids.length) tags.push(`绑定转发: ${user.forward_rule_ids.length} 条`);
        if (user.max_connections > 0) tags.push(`并发: ${user.max_connections}`);
        if (user.rate_limit_kbps > 0) tags.push(`限速: ${user.rate_limit_kbps} KB/s`);
        metaLine.textContent = tags.join(' · ');
        card.appendChild(metaLine);

        const actions = document.createElement('div');
        actions.className = 'item-actions';
        const addActionBtn = (label, cls, handler) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = cls;
            btn.textContent = label;
            btn.addEventListener('click', handler);
            actions.appendChild(btn);
        };
        addActionBtn('复制链接', 'btn btn-primary btn-sm', () => fetchUserTokenAndAct(user, 'copy').catch(e => showToast(e.message, 'error')));
        addActionBtn('二维码', 'btn btn-sm', () => fetchUserTokenAndAct(user, 'qr').catch(e => showToast(e.message, 'error')));
        addActionBtn('编辑', 'btn btn-sm', () => openSubUserModal(user));
        addActionBtn(user.enabled ? '停用' : '启用', 'btn btn-sm', () => toggleSubUser(user));
        addActionBtn('重置流量', 'btn btn-sm', () => resetSubUserTraffic(user));
        addActionBtn('轮换密钥', 'btn btn-sm', () => rotateSubUser(user));
        addActionBtn('删除', 'btn btn-danger btn-sm', () => deleteSubUser(user));
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
        state.subUsers = data.users || [];
        renderSubUsers();
    } catch (e) {
        container.textContent = `加载订阅用户失败：${e.message}`;
    }
}

function parseListInput(raw) {
    return String(raw || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
}

function openSubUserModal(existing = null) {
    const isNew = !existing;
    const html = `
        <div class="form-group">
            <label>用户名 (字母/数字/._-)</label>
            <input type="text" id="m-su-username" placeholder="alice">
        </div>
        <div class="form-grid">
            <div class="form-group">
                <label>总流量配额 (GiB，0 为不限)</label>
                <input type="number" id="m-su-quota-gb" min="0" step="0.5" value="0">
            </div>
            <div class="form-group">
                <label>到期时间 (留空永不过期)</label>
                <input type="datetime-local" id="m-su-expire">
            </div>
        </div>
        <div class="form-grid">
            <div class="form-group">
                <label>最大连接数 (0 为不限)</label>
                <input type="number" id="m-su-conns" min="0" value="0">
            </div>
            <div class="form-group">
                <label>速率上限 (KB/s，0 为不限)</label>
                <input type="number" id="m-su-rate" min="0" value="0">
            </div>
        </div>
        <div class="form-group">
            <label>允许的代理组 (逗号分隔，留空不限)</label>
            <input type="text" id="m-su-groups" placeholder="例如: Proxy, HK">
        </div>
        <div class="form-group">
            <label>绑定转发规则 ID (32 位 hex，逗号分隔，可选；超限自动停用)</label>
            <input type="text" id="m-su-rules" placeholder="留空表示不绑定特定转发端口">
        </div>
        <div class="form-grid">
            <label class="inline-check" style="display:flex; align-items:center; gap:6px;"><input type="checkbox" id="m-su-enabled" checked> 启用该用户</label>
        </div>
    `;
    openModal(isNew ? '新建订阅用户' : '编辑订阅用户', html, async () => {
        const username = document.getElementById('m-su-username').value.trim();
        if (isNew && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(username)) {
            showToast('用户名格式不合法', 'error');
            return;
        }
        const quotaGb = Math.max(0, Number(document.getElementById('m-su-quota-gb').value) || 0);
        const expireRaw = document.getElementById('m-su-expire').value.trim();
        const expireAt = expireRaw ? Math.floor(Date.parse(expireRaw) / 1000) : 0;
        if (expireRaw && (!Number.isFinite(expireAt) || expireAt <= 0)) {
            showToast('到期时间格式无效', 'error');
            return;
        }
        const payload = {
            quota_bytes: Math.max(0, Math.round(quotaGb * 1024 * 1024 * 1024)),
            expire_at: expireAt,
            enabled: document.getElementById('m-su-enabled').checked,
            prefer_relay: Boolean(existing?.prefer_relay),
            allowed_groups: parseListInput(document.getElementById('m-su-groups').value),
            forward_rule_ids: parseListInput(document.getElementById('m-su-rules').value),
            max_connections: Math.max(0, Math.round(Number(document.getElementById('m-su-conns').value) || 0)),
            rate_limit_kbps: Math.max(0, Math.round(Number(document.getElementById('m-su-rate').value) || 0)),
        };
        if (isNew) payload.username = username;
        try {
            const path = isNew ? '/sub-users' : `/sub-users/${encodeURIComponent(existing.id)}`;
            const res = await fetchAuth(path, {
                method: isNew ? 'POST' : 'PATCH',
                body: JSON.stringify(payload),
            });
            if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
            const result = await res.json();
            closeModal();
            await loadSubUsers();
            if (isNew && result.token) {
                const url = buildUserSubUrlForCurrentFormat(result.token, result);
                await copyTextToClipboard(url, `用户 ${result.username} 已创建，订阅链接已复制`);
            } else {
                showToast('订阅用户已保存');
            }
        } catch (e) {
            showToast(`保存失败：${e.message}`, 'error');
        }
    });

    const userEl = document.getElementById('m-su-username');
    if (existing) {
        userEl.value = existing.username || '';
        userEl.disabled = true;
        const gb = existing.quota_bytes ? +(existing.quota_bytes / (1024 * 1024 * 1024)).toFixed(2) : 0;
        document.getElementById('m-su-quota-gb').value = String(gb);
        document.getElementById('m-su-expire').value = toLocalDatetimeInputValue(existing.expire_at);
        document.getElementById('m-su-conns').value = String(existing.max_connections || 0);
        document.getElementById('m-su-rate').value = String(existing.rate_limit_kbps || 0);
        document.getElementById('m-su-groups').value = (existing.allowed_groups || []).join(', ');
        document.getElementById('m-su-rules').value = (existing.forward_rule_ids || []).join(', ');
        document.getElementById('m-su-enabled').checked = Boolean(existing.enabled);
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
    if (!confirm(`确认将 ${user.username} 的累计上下行流量归零？若因超额停用，归零后可恢复启用。`)) return;
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
    if (!confirm(`确认轮换 ${user.username} 的订阅 Token？旧订阅链接将立即失效。`)) return;
    try {
        const res = await fetchAuth(`/sub-users/${encodeURIComponent(user.id)}/rotate`, { method: 'POST' });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
        const data = await res.json();
        await loadSubUsers();
        if (data.token) {
            const url = buildUserSubUrlForCurrentFormat(data.token, user);
            await copyTextToClipboard(url, `已轮换 ${user.username} 的新订阅链接并复制`);
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

document.getElementById('btn-refresh-sub-users')?.addEventListener('click', loadSubUsers);
document.getElementById('btn-add-sub-user')?.addEventListener('click', () => openSubUserModal(null));

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

const ProxyForgeRegions = (() => {
    const REGIONS = [
        { code: 'HK', flag: '🇭🇰', label: '香港', keywords: ['hk', 'hkg', 'hong kong', 'hongkong', '香港', '港'] },
        { code: 'MO', flag: '🇲🇴', label: '澳门', keywords: ['mo', 'macau', 'macao', '澳门', '澳門'] },
        { code: 'TW', flag: '🇹🇼', label: '台湾', keywords: ['tw', 'twn', 'taiwan', 'taipei', '台湾', '台灣', '台北', '新北', '台中', '高雄'] },
        { code: 'JP', flag: '🇯🇵', label: '日本', keywords: ['jp', 'jpn', 'japan', 'tokyo', 'osaka', 'nagoya', '日本', '东京', '東京', '大阪', '名古屋'] },
        { code: 'SG', flag: '🇸🇬', label: '新加坡', keywords: ['sg', 'sgp', 'singapore', '新加坡', '狮城', '獅城'] },
        { code: 'US', flag: '🇺🇸', label: '美国', keywords: ['us', 'usa', 'united states', 'america', 'los angeles', 'san jose', 'seattle', 'silicon valley', 'new york', 'dallas', 'chicago', '美国', '美國', '洛杉矶', '洛杉磯', '圣何塞', '聖何塞', '西雅图', '硅谷', '纽约'] },
        { code: 'KR', flag: '🇰🇷', label: '韩国', keywords: ['kr', 'kor', 'korea', 'seoul', 'busan', '韩国', '韓國', '首尔', '首爾', '釜山'] },
        { code: 'GB', flag: '🇬🇧', label: '英国', keywords: ['uk', 'gb', 'gbr', 'united kingdom', 'britain', 'england', 'london', 'manchester', '英国', '英國', '伦敦', '倫敦'] },
        { code: 'DE', flag: '🇩🇪', label: '德国', keywords: ['de', 'deu', 'germany', 'frankfurt', 'berlin', 'munich', '德国', '德國', '法兰克福', '法蘭克福', '柏林'] },
        { code: 'FR', flag: '🇫🇷', label: '法国', keywords: ['fr', 'fra', 'france', 'paris', 'marseille', '法国', '法國', '巴黎'] },
        { code: 'NL', flag: '🇳🇱', label: '荷兰', keywords: ['nl', 'nld', 'netherlands', 'holland', 'amsterdam', '荷兰', '荷蘭', '阿姆斯特丹'] },
        { code: 'RU', flag: '🇷🇺', label: '俄罗斯', keywords: ['ru', 'rus', 'russia', 'moscow', '俄罗斯', '俄羅斯', '莫斯科'] },
        { code: 'IN', flag: '🇮🇳', label: '印度', keywords: ['in', 'ind', 'india', 'mumbai', '印度', '孟买'] },
        { code: 'CA', flag: '🇨🇦', label: '加拿大', keywords: ['ca', 'can', 'canada', 'toronto', 'vancouver', '加拿大', '多伦多', '温哥华'] },
        { code: 'AU', flag: '🇦🇺', label: '澳大利亚', keywords: ['au', 'aus', 'australia', 'sydney', 'melbourne', '澳大利亚', '澳洲', '悉尼', '墨尔本'] },
        { code: 'CH', flag: '🇨🇭', label: '瑞士', keywords: ['ch', 'che', 'switzerland', 'zurich', 'geneva', '瑞士', '苏黎世'] },
        { code: 'SE', flag: '🇸🇪', label: '瑞典', keywords: ['se', 'swe', 'sweden', 'stockholm', '瑞典', '斯德哥尔摩'] },
        { code: 'TR', flag: '🇹🇷', label: '土耳其', keywords: ['tr', 'tur', 'turkey', 'istanbul', '土耳其', '伊斯坦布尔'] },
        { code: 'BR', flag: '🇧🇷', label: '巴西', keywords: ['br', 'bra', 'brazil', 'sao paulo', '巴西', '圣保罗'] },
        { code: 'MY', flag: '🇲🇾', label: '马来西亚', keywords: ['my', 'mys', 'malaysia', 'kuala lumpur', '马来西亚', '馬來西亞', '吉隆坡'] },
        { code: 'TH', flag: '🇹🇭', label: '泰国', keywords: ['th', 'tha', 'thailand', 'bangkok', '泰国', '泰國', '曼谷'] },
        { code: 'VN', flag: '🇻🇳', label: '越南', keywords: ['vn', 'vnm', 'vietnam', 'hanoi', '越南', '河内', '胡志明'] },
        { code: 'PH', flag: '🇵🇭', label: '菲律宾', keywords: ['ph', 'phl', 'philippines', 'manila', '菲律宾', '菲律賓', '马尼拉'] },
        { code: 'ID', flag: '🇮🇩', label: '印尼', keywords: ['id', 'idn', 'indonesia', 'jakarta', '印尼', '印度尼西亚', '雅加达'] },
        { code: 'AE', flag: '🇦🇪', label: '阿联酋', keywords: ['ae', 'are', 'uae', 'dubai', '阿联酋', '阿聯酋', '迪拜'] },
        { code: 'ZA', flag: '🇿🇦', label: '南非', keywords: ['za', 'zaf', 'south africa', 'johannesburg', '南非'] },
        { code: 'IT', flag: '🇮🇹', label: '意大利', keywords: ['it', 'ita', 'italy', 'milan', 'rome', '意大利', '米兰', '罗马'] },
        { code: 'ES', flag: '🇪🇸', label: '西班牙', keywords: ['es', 'esp', 'spain', 'madrid', '西班牙', '马德里'] },
        { code: 'PL', flag: '🇵🇱', label: '波兰', keywords: ['pl', 'pol', 'poland', 'warsaw', '波兰', '波蘭', '华沙'] },
        { code: 'FI', flag: '🇫🇮', label: '芬兰', keywords: ['fi', 'fin', 'finland', 'helsinki', '芬兰', '芬蘭', '赫尔辛基'] },
        { code: 'NO', flag: '🇳🇴', label: '挪威', keywords: ['no', 'nor', 'norway', 'oslo', '挪威', '奥斯陆'] },
        { code: 'AT', flag: '🇦🇹', label: '奥地利', keywords: ['at', 'aut', 'austria', 'vienna', '奥地利', '奧地利', '维也纳'] },
        { code: 'IE', flag: '🇮🇪', label: '爱尔兰', keywords: ['ie', 'irl', 'ireland', 'dublin', '爱尔兰', '愛爾蘭', '都柏林'] },
        { code: 'AR', flag: '🇦🇷', label: '阿根廷', keywords: ['ar', 'arg', 'argentina', 'buenos aires', '阿根廷'] },
        { code: 'CL', flag: '🇨🇱', label: '智利', keywords: ['cl', 'chl', 'chile', 'santiago', '智利'] },
        { code: 'MX', flag: '🇲🇽', label: '墨西哥', keywords: ['mx', 'mex', 'mexico', '墨西哥'] },
        { code: 'CN', flag: '🇨🇳', label: '中国', keywords: ['cn', 'chn', 'china', 'shenzhen', 'shanghai', 'beijing', 'guangzhou', 'hangzhou', '中国', '中國', '国内', '國內', '深圳', '上海', '北京', '广州', '廣州', '杭州'] },
    ];
    const QUICK_CODES = ['CN', 'HK', 'JP', 'US', 'SG', 'TW', 'KR', 'GB', 'DE'];
    const FLAG_PAIR_RE = /[\u{1F1E6}-\u{1F1FF}]{2}/u;
    const LEADING_FLAG_RE = /^\s*([\u{1F1E6}-\u{1F1FF}]{2})\s*/u;

    function hasCountryFlag(text) {
        return FLAG_PAIR_RE.test(String(text || ''));
    }

    const CASE_SENSITIVE_SHORT_CODES = new Set(['in', 'id', 'no', 'at', 'it']);

    function keywordMatchesName(rawName, lowerName, keyword) {
        if (/[^\x00-\x7F]/.test(keyword)) return lowerName.includes(keyword);
        if (CASE_SENSITIVE_SHORT_CODES.has(keyword)) {
            const upper = keyword.toUpperCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            return new RegExp(`(?<![A-Za-z0-9])${upper}(?![A-Za-z0-9])`).test(rawName);
        }
        const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`, 'i').test(lowerName);
    }

    function matchRegion(text) {
        const raw = String(text || '').trim();
        if (!raw) return null;
        const flagMatch = raw.match(FLAG_PAIR_RE);
        if (flagMatch) {
            const byFlag = REGIONS.find(r => r.flag === flagMatch[0]);
            if (byFlag) return byFlag;
        }
        const lower = raw.toLowerCase();
        for (const r of REGIONS) {
            if (r.code.toLowerCase() === lower || r.label === raw) return r;
        }
        for (const r of REGIONS) {
            if (r.keywords.some(kw => keywordMatchesName(raw, lower, kw))) return r;
        }
        return null;
    }

    function stripLeadingFlag(name) {
        return String(name || '').replace(LEADING_FLAG_RE, '').trim();
    }

    function applyRegionPrefix(name, regionInput) {
        const clean = stripLeadingFlag(name);
        const matched = matchRegion(regionInput);
        if (!matched) return clean;
        return clean ? `${matched.flag} ${clean}` : matched.flag;
    }

    function getFlagEmoji(name) {
        if (!name) return name;
        if (hasCountryFlag(name)) return name;
        const matched = matchRegion(name);
        return matched ? `${matched.flag} ${name}` : name;
    }

    function renderRegionPickerHtml(pickerId, currentVal = '', label = '地区 / 国旗 (可输入搜索或直接选择)') {
        const matched = matchRegion(currentVal);
        const initialText = matched ? `${matched.flag} ${matched.code} · ${matched.label}` : String(currentVal || '');
        const quickHtml = QUICK_CODES.map(code => {
            const r = REGIONS.find(item => item.code === code);
            return r ? `<button type="button" class="btn btn-sm region-quick-btn" data-region-code="${escapeHtml(r.code)}" style="padding:2px 8px; font-size:0.78rem;">${r.flag} ${escapeHtml(r.label)}</button>` : '';
        }).join('');
        const optionsHtml = REGIONS.map(r =>
            `<option value="${escapeHtml(`${r.flag} ${r.code} · ${r.label}`)}">${escapeHtml(r.keywords.slice(0, 4).join(' / '))}</option>`
        ).join('');
        return `
            <div class="form-group full-width region-picker-group" data-picker-id="${escapeHtml(pickerId)}">
                <label for="${escapeHtml(pickerId)}">${escapeHtml(label)}</label>
                <div style="display:flex; gap:8px; align-items:center;">
                    <input type="text" id="${escapeHtml(pickerId)}" list="${escapeHtml(pickerId)}-datalist" value="${escapeHtml(initialText)}" placeholder="输入国家/地区或代码 (如 HK / 香港 / US / 日本 / NL) 自动添加小国旗" style="flex:1;">
                    <button type="button" class="btn btn-sm region-clear-btn" data-clear-for="${escapeHtml(pickerId)}" title="清除国旗前缀">清除</button>
                </div>
                <datalist id="${escapeHtml(pickerId)}-datalist">${optionsHtml}</datalist>
                <div class="region-quick-bar" style="display:flex; flex-wrap:wrap; gap:6px; margin-top:6px;">${quickHtml}</div>
            </div>
        `;
    }

    function bindRegionPicker(pickerId, onRegionChange) {
        const input = document.getElementById(pickerId);
        if (!input) return;
        const wrap = input.closest('.region-picker-group') || input.parentElement;
        const notify = (rawVal) => {
            const r = matchRegion(rawVal);
            if (typeof onRegionChange === 'function') onRegionChange(r, rawVal);
            if (window.twemoji && wrap) twemoji.parse(wrap, { folder: 'svg', ext: '.svg' });
        };
        input.addEventListener('input', () => notify(input.value));
        input.addEventListener('change', () => notify(input.value));
        if (wrap) {
            wrap.querySelectorAll('.region-quick-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const code = btn.getAttribute('data-region-code');
                    const r = matchRegion(code);
                    if (r) {
                        input.value = `${r.flag} ${r.code} · ${r.label}`;
                        notify(r.code);
                    }
                });
            });
            const clearBtn = wrap.querySelector('.region-clear-btn');
            if (clearBtn) {
                clearBtn.addEventListener('click', () => {
                    input.value = '';
                    notify('');
                });
            }
            if (window.twemoji) twemoji.parse(wrap, { folder: 'svg', ext: '.svg' });
        }
    }

    return {
        REGIONS,
        hasCountryFlag,
        matchRegion,
        stripLeadingFlag,
        applyRegionPrefix,
        getFlagEmoji,
        renderRegionPickerHtml,
        bindRegionPicker,
    };
})();
globalThis.ProxyForgeRegions = ProxyForgeRegions;
const getFlagEmoji = ProxyForgeRegions.getFlagEmoji;

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
        list.innerHTML = `<div class="empty-state">暂无机场订阅</div>`;
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
                    usageStr = "不限";
                }
            }
            let displayName = customName || info.name || '机场';
            let safeDisplayName = escapeHtml(displayName);
            let safeUrl = escapeHtml(url);
            let safeError = escapeHtml(info.error || '');
            html += `
                <div class="list-item" style="flex-direction:column; align-items:flex-start;">
                    <div style="display:flex; width:100%; align-items:center; gap:8px;">
                        ${getCheckboxHTML('cb-airport', index)}
                        <span class="type-badge badge-select" style="max-width: 160px; overflow: hidden; text-overflow: ellipsis;">${safeDisplayName}</span>
                        <div class="item-info item-detail" style="margin-top:0; flex:1;">${safeUrl}</div>
                        <div class="item-actions">
                            <button class="btn btn-sm" onclick="editAirport(${index})">编辑</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteAirport(${index})">删除</button>
                        </div>
                    </div>
                    <div class="sub-user-meta" style="display:flex; gap:14px; margin-left:28px; margin-top:4px; flex-wrap:wrap;">
                        <span>节点 ${info.error ? '?' : info.nodesCount}</span>
                        <span>流量 ${usageStr}</span>
                        <span>到期 ${info.expire ? formatDate(info.expire) : '长期'}</span>
                        <span>刷新 ${info._timestamp ? new Date(info._timestamp * 1000).toLocaleString('zh-CN', {month: 'numeric', day: 'numeric', hour: '2-digit', minute:'2-digit'}) : '未知'}</span>
                    </div>
                    ${info.error ? `<div style="color:var(--danger); font-size:0.76rem; margin-left:28px; margin-top:2px;">抓取失败: ${safeError}</div>` : ''}
                </div>
            `;
        } else {
            let displayName = customName || '机场';
            let safeDisplayName = escapeHtml(displayName);
            let safeUrl = escapeHtml(url);
            html += `
                <div class="list-item">
                    ${getCheckboxHTML('cb-airport', index)}
                    <span class="type-badge badge-select">${safeDisplayName}</span>
                    <div class="item-info item-detail" style="margin-top:0;">${safeUrl}</div>
                    <span class="sub-user-meta">加载中…</span>
                    <div class="item-actions">
                        <button class="btn btn-sm" onclick="editAirport(${index})">编辑</button>
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
        list.innerHTML = `<div class="empty-state">暂无代理组</div>`;
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
            summaries.push('全部节点');
        } else if (uCount > 0) {
            let sources = g.use.map(s => s === '_custom_nodes_' ? '自建节点' : s);
            summaries.push(`${sources.join(', ')}`);
        }
        if (g.filter) summaries.push(`正则: ${g.filter}`);
        if (nestedGroups.length > 0) summaries.push(`嵌套: ${nestedGroups.join(', ')}`);
        if (!g['include-all'] && uCount === 0 && !g.filter && nestedGroups.length === 0 && pCount > 0) {
            let manuals = g.proxies.filter(p => p !== 'DIRECT' && p !== 'REJECT' && !nestedGroups.includes(p));
            if (manuals.length === 0) manuals = g.proxies;
            summaries.push(`${manuals.slice(0, 3).join(', ')}${manuals.length > 3 ? '…' : ''}`);
        }

        let proxiesPreview = summaries.length > 0 ? summaries.join(' · ') : '无';
        let displayName = getFlagEmoji(g.name);

        html += `
            <div class="list-item" draggable="true" data-index="${index}"
                 ondragstart="handleGroupDragStart(event, ${index})"
                 ondragover="handleGroupDragOver(event)"
                 ondragenter="handleGroupDragEnter(event)"
                 ondragleave="handleGroupDragLeave(event)"
                 ondrop="handleGroupDrop(event, ${index})"
                 ondragend="handleGroupDragEnd(event)">
                <span class="drag-handle" style="cursor: grab; color: var(--text-muted);">⠿</span>
                ${getCheckboxHTML('cb-group', index)}
                <span class="type-badge ${badgeCls}">${escapeHtml(g.type || 'unknown')}</span>
                <div class="item-info">
                    <div class="item-name">${escapeHtml(displayName)}</div>
                    <div class="item-detail">${escapeHtml(proxiesPreview)}</div>
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
    const countBadge = document.getElementById('manual-nodes-count');
    const bulkDeleteBtn = document.getElementById('btn-bulk-delete-nodes');
    const manual = state.nodes.map((node, index) => ({ node, index })).filter(item => !item.node._managed_by);
    if (countBadge) countBadge.textContent = String(manual.length);
    if (bulkDeleteBtn) bulkDeleteBtn.hidden = manual.length === 0;
    if (!manual.length) {
        list.innerHTML = `<div class="manual-nodes-empty-bar"><span>暂无手工节点</span></div>`;
        return;
    }
    const upIcon = typeof ProxyForgeIcons !== 'undefined' ? ProxyForgeIcons.svg('arrowUp', 13) : '↑';
    const downIcon = typeof ProxyForgeIcons !== 'undefined' ? ProxyForgeIcons.svg('arrowDown', 13) : '↓';
    let html = '';
    manual.forEach(({ node: n, index }, position) => {
        let displayName = getFlagEmoji(n.name);
        html += `
            <div class="list-item" draggable="true" data-index="${index}" 
                 ondragstart="handleDragStart(event, ${index})" 
                 ondragover="handleDragOver(event)"
                 ondragenter="handleDragEnter(event)"
                 ondragleave="handleDragLeave(event)"
                 ondrop="handleDrop(event, ${index})"
                 ondragend="handleDragEnd(event)">
                <span class="drag-handle" style="cursor: grab; color: var(--text-muted);">⠿</span>
                ${getCheckboxHTML('cb-node', index)}
                <span class="type-badge badge-default">${escapeHtml(n.type || 'unknown')}</span>
                <div class="item-info">
                    <div class="item-name">${escapeHtml(displayName)}</div>
                    <div class="item-detail">${escapeHtml(n.server || '')}${escapeHtml(n.port ? ':' + n.port : '')}</div>
                </div>
                <div class="item-actions">
                    ${position > 0 ? `<button class="btn btn-sm" onclick="moveNodeUp(${index})" title="上移" aria-label="上移">${upIcon}</button>` : ''}
                    ${position < manual.length - 1 ? `<button class="btn btn-sm" onclick="moveNodeDown(${index})" title="下移" aria-label="下移">${downIcon}</button>` : ''}
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
                <span class="type-badge badge-default">${escapeHtml(p.type || 'http')}</span>
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
        ? `${visibleRules.length} / ${rules.length}`
        : `${rules.length} 条`;
    clearRuleSearchBtn.disabled = !isFiltering;

    if (!rules.length) {
        list.innerHTML = `<div class="empty-state">暂无路由规则</div>`;
        return;
    }
    if (!visibleRules.length) {
        list.innerHTML = `<div class="empty-state">无匹配规则</div>`;
        return;
    }
    let html = '';
    visibleRules.forEach(({ rule: r, index }) => {
        const parsed = ProxyForgeRuleUtils.parseRuleParts(r);
        const type = parsed.type;
        let badgeCls = 'rule-badge-other';
        if (type.startsWith('DOMAIN')) badgeCls = 'rule-badge-domain';
        else if (type.startsWith('IP-')) badgeCls = 'rule-badge-ip';
        else if (type === 'GEOSITE') badgeCls = 'rule-badge-geosite';
        else if (type === 'GEOIP') badgeCls = 'rule-badge-geoip';
        else if (type === 'MATCH') badgeCls = 'rule-badge-match';
        else if (type === 'RULE-SET') badgeCls = 'rule-badge-ruleset';

        const payloadLabel = parsed.isLogical
            ? parsed.payload.replace(/\)\s*,\s*[^,]+?\s*$/, ')')
            : parsed.payload;

        html += `
            <div class="list-item" draggable="${isFiltering ? 'false' : 'true'}" data-index="${index}"
                 ondragstart="handleRuleDragStart(event, ${index})"
                 ondragover="handleRuleDragOver(event)"
                 ondragenter="handleRuleDragEnter(event)"
                 ondragleave="handleRuleDragLeave(event)"
                 ondrop="handleRuleDrop(event, ${index})"
                 ondragend="handleRuleDragEnd(event)">
                <span class="drag-handle" title="${isFiltering ? '清空搜索后可拖拽排序' : '拖拽排序'}"
                      style="cursor: ${isFiltering ? 'not-allowed' : 'grab'}; color: var(--text-muted);">⠿</span>
                ${getCheckboxHTML('cb-rule', index)}
                <span class="type-badge ${badgeCls}" style="min-width: 96px; justify-content: center;">${escapeHtml(type)}</span>
                <div class="item-info" style="font-family: var(--font-mono); font-size: 0.82rem; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                    ${payloadLabel ? `<span style="font-weight:500; color:var(--text);">${escapeHtml(payloadLabel)}</span>` : ''}
                    ${parsed.noResolve ? '<span class="type-badge badge-default">no-resolve</span>' : ''}
                    <span style="color:var(--text-muted);">→ ${escapeHtml(parsed.target)}</span>
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
    const previousName = index >= 0 && typeof g?.name === 'string' ? g.name : '';
    
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
                ${Array.from(airportNames).map(name => `<div class="filter-tag" data-val="${escapeHtml(name)}">${escapeHtml(name)}</div>`).join('')}
                <div class="filter-tag" data-val="_custom_nodes_">自建节点</div>
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

        let successMessage = '';
        if (index >= 0 && previousName && g.name && previousName !== g.name) {
            const duplicateTarget = state.templateObj['proxy-groups'].some(
                (item, idx) => idx !== index && item && item.name === g.name
            );
            if (!duplicateTarget) {
                const renamed = ProxyForgeRuleUtils.renameProxyGroupReferences(state.templateObj, previousName, g.name);
                if (renamed.cleanedTotal > 0) {
                    successMessage = `已保存代理组，并更新 ${renamed.cleanedTotal} 处引用`;
                }
            }
        }

        closeModal();
        saveTemplateObj(state.templateObj, 'other', null, successMessage);
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
    const cleanup = ProxyForgeRuleUtils.removeProxyGroups(state.templateObj, index);
    const msg = cleanup.cleanedTotal > 0
        ? `已删除代理组，并清理 ${cleanup.cleanedTotal} 处引用`
        : '已删除代理组';
    saveTemplateObj(state.templateObj, 'other', null, msg);
};

document.getElementById('btn-bulk-delete-groups').addEventListener('click', () => {
    let indices = getCheckedIndices('cb-group');
    if(!indices.length) return alert('请先勾选要删除的项');
    if(confirm(`确定删除这 ${indices.length} 项吗？`)) {
        const cleanup = ProxyForgeRuleUtils.removeProxyGroups(state.templateObj, indices);
        const msg = cleanup.cleanedTotal > 0
            ? `已删除 ${indices.length} 个代理组，并清理 ${cleanup.cleanedTotal} 处引用`
            : `已删除 ${indices.length} 个代理组`;
        saveTemplateObj(state.templateObj, 'other', null, msg);
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
        <div class="form-group full-width" style="margin-top: 4px;">
            <label style="display:flex; align-items:center; cursor:pointer; font-size:0.88rem; margin-bottom:12px;">
                <input type="checkbox" id="bulk-group-include-all" style="margin-right:8px; width:16px; height:16px;"> 
                自动包含全部节点
            </label>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:var(--text-secondary); font-weight: 600;">快速选择地区:</div>
            <div class="filter-tags" id="bulk-tags-regions">
                ${regions.map(r => `<div class="filter-tag" data-val="${r.key}">${r.label}</div>`).join('')}
            </div>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:var(--text-secondary); font-weight: 600;">快速选择节点来源:</div>
            <div class="filter-tags" id="bulk-tags-sources">
                ${Array.from(airportNames).map(name => `<div class="filter-tag" data-val="${escapeHtml(name)}">${escapeHtml(name)}</div>`).join('')}
                <div class="filter-tag" data-val="_custom_nodes_">自建节点</div>
            </div>
            
            <div style="font-size:0.8rem; margin:8px 0 4px 0; color:var(--text-secondary); font-weight: 600;">正则表达式:</div>
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
    if (index >= 0 && state.nodes[index]._managed_by) return showToast('请在 Agent 的部署页面修改此节点', 'error');
    let isNew = index < 0;
    let currentObj = isNew ? { name: 'New Node', type: 'vmess', server: '1.1.1.1', port: 443 } : state.nodes[index];
    let yamlStr = isNew ? "name: New Node\ntype: vmess\nserver: 1.1.1.1\nport: 443" : jsyaml.dump(currentObj);
    const initialRegion = currentObj && currentObj.name ? (ProxyForgeRegions.matchRegion(currentObj.name)?.code || '') : '';
    const html = `
        ${ProxyForgeRegions.renderRegionPickerHtml('m-node-region', initialRegion, '选择地区 (可输入搜索或直接选择，自动在节点名称前添加小国旗)')}
        <div class="form-group full-width">
            <label>节点配置 (YAML格式) - 或者直接粘贴 vless://、tuic://、anytls://、wireguard:// 等分享链接</label>
            <textarea id="m-node-raw" style="min-height:250px; font-family:monospace;">${escapeHtml(yamlStr)}</textarea>
        </div>
    `;
    openModal(isNew ? '新建自建节点' : '编辑自建节点', html, async () => {
        try {
            let val = document.getElementById('m-node-raw').value.trim();
            const regionRaw = (document.getElementById('m-node-region')?.value || '').trim();
            let parsed;
            if (typeof ProxyForgeShareLinks !== 'undefined' && !val.includes('\n') && !SHARE_LINK_PATTERN.test(val) && !val.includes(':')) {
                const expandedSingle = ProxyForgeShareLinks.expandShareLinkInput(val);
                if (expandedSingle.links.length === 1 && SHARE_LINK_PATTERN.test(expandedSingle.links[0])) {
                    val = expandedSingle.links[0];
                }
            }
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
            if (parsed && parsed.name && regionRaw) {
                parsed.name = ProxyForgeRegions.applyRegionPrefix(parsed.name, regionRaw);
            }
            if(isNew) state.nodes.push(parsed);
            else state.nodes[index] = parsed;
            closeModal();
            saveNodesObj();
        } catch(e) { alert('YAML 解析失败'); }
    });
    ProxyForgeRegions.bindRegionPicker('m-node-region', (regionObj, rawVal) => {
        const rawEl = document.getElementById('m-node-raw');
        if (!rawEl || SHARE_LINK_PATTERN.test(rawEl.value.trim())) return;
        try {
            const obj = jsyaml.load(rawEl.value);
            if (obj && typeof obj === 'object' && typeof obj.name === 'string') {
                obj.name = ProxyForgeRegions.applyRegionPrefix(obj.name, regionObj ? regionObj.code : rawVal);
                rawEl.value = jsyaml.dump(obj);
            }
        } catch (_) {}
    });
};
document.getElementById('btn-add-node').addEventListener('click', () => editNode(-1));

document.getElementById('btn-import-nodes').addEventListener('click', () => {
    const html = `
        ${ProxyForgeRegions.renderRegionPickerHtml('m-nodes-import-region', '', '统一地区前缀 (可选：若所选节点未带国旗，导入时自动添加所选地区小国旗)')}
        <div class="form-group full-width">
            <label>选择 YAML 文件上传，或在下方直接粘贴 (支持 YAML / JSON / 分享链接 vless:// 等)</label>
            <input type="file" id="m-nodes-file" accept=".yaml,.yml,.txt,.json" style="margin-bottom: 10px; cursor: pointer;">
            <textarea id="m-nodes-import" style="min-height:250px;" placeholder="支持粘贴标准 YAML 节点列表，或者直接粘贴 vless:// vmess:// hysteria2:// tuic:// anytls:// wireguard:// 链接 (每行一个)"></textarea>
        </div>
    `;
    openModal('批量导入自建节点', html, async () => {
        try {
            let text = document.getElementById('m-nodes-import').value;
            const regionRaw = (document.getElementById('m-nodes-import-region')?.value || '').trim();
            let links = [];
            let nonLinksText = '';
            let skippedNotices = [];
            if (typeof ProxyForgeShareLinks !== 'undefined') {
                const splitRes = ProxyForgeShareLinks.splitImportInput(text, SHARE_LINK_PATTERN);
                links = splitRes.links;
                nonLinksText = splitRes.nonLinksText;
                skippedNotices = splitRes.skippedNotices;
            } else {
                let lines = text.split('\n').map(s=>s.trim()).filter(s=>s);
                links = lines.filter(s => SHARE_LINK_PATTERN.test(s));
                nonLinksText = lines.filter(s => !SHARE_LINK_PATTERN.test(s)).join('\n');
            }
            
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
                if (regionRaw) {
                    toAdd.forEach(item => {
                        if (item && item.name) item.name = ProxyForgeRegions.applyRegionPrefix(item.name, regionRaw);
                    });
                }
                state.nodes = state.nodes.concat(toAdd);
                closeModal();
                saveNodesObj();
                showToast(
                    skippedNotices.length
                        ? `成功导入 ${toAdd.length} 个节点（已跳过 ${skippedNotices.length} 条状态提示行）`
                        : `成功导入 ${toAdd.length} 个节点`
                );
            } else {
                alert('没有解析到任何有效节点');
            }
        } catch(e) { alert('解析失败: ' + e.message); }
    });
    ProxyForgeRegions.bindRegionPicker('m-nodes-import-region');

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
    if (state.nodes[index]._managed_by) return showToast('请在 Agent 的部署页面移除监听', 'error');
    state.nodes.splice(index, 1);
    saveNodesObj();
};

window.moveNodeUp = function(index) {
    const previous = state.nodes.map((node, i) => !node._managed_by && i < index ? i : -1).filter(i => i >= 0).pop();
    if (previous !== undefined && !state.nodes[index]._managed_by) {
        let temp = state.nodes[index];
        state.nodes[index] = state.nodes[previous];
        state.nodes[previous] = temp;
        saveNodesObj();
    }
};

window.moveNodeDown = function(index) {
    const next = state.nodes.findIndex((node, i) => i > index && !node._managed_by);
    if (next >= 0 && !state.nodes[index]._managed_by) {
        let temp = state.nodes[index];
        state.nodes[index] = state.nodes[next];
        state.nodes[next] = temp;
        saveNodesObj();
    }
};

let draggedNodeIndex = null;

window.handleDragStart = function(e, index) {
    if (state.nodes[index]._managed_by) { e.preventDefault(); return; }
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
    if (draggedNodeIndex !== null && draggedNodeIndex !== dropIndex &&
        !state.nodes[draggedNodeIndex]._managed_by && !state.nodes[dropIndex]._managed_by) {
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
            body: JSON.stringify({ nodes: state.nodes.filter(node => !node._managed_by) })
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

async function openNodeOrderModal() {
    let payload;
    try {
        payload = await (await fetchAuth('/nodes/order')).json();
    } catch (e) {
        showToast(`读取节点顺序失败：${e.message}`, 'error');
        return;
    }

    let items = Array.isArray(payload.items) ? payload.items.slice() : [];
    let hasCustomOrder = Boolean(payload.has_custom_order);
    let draggedIndex = -1;

    async function syncOrderedNodesFromServer() {
        const [nodesRes, proxiesRes] = await Promise.all([
            fetchAuth('/nodes'),
            fetchAuth('/proxies'),
        ]);
        state.nodes = (await nodesRes.json()).nodes || [];
        state.allProxies = (await proxiesRes.json()).proxies || [];
        renderNodes();
    }

    openModal(
        '订阅节点排序',
        '<div id="node-order-toolbar" class="node-order-toolbar"></div>' +
        '<div id="node-order-list" class="node-order-list"></div>',
        async () => {
            modalConfirm.disabled = true;
            try {
                await fetchAuth('/nodes/order', {
                    method: 'PUT',
                    body: JSON.stringify({ order: items.map(x => x.key) }),
                });
                await syncOrderedNodesFromServer();
                closeModal();
                showToast('已保存订阅节点排序');
            } catch (e) {
                modalConfirm.disabled = false;
                showToast(`保存排序失败：${e.message}`, 'error');
            }
        }
    );

    const toolbar = document.getElementById('node-order-toolbar');
    const listEl = document.getElementById('node-order-list');
    const statusBadge = document.createElement('span');
    statusBadge.className = 'node-order-status';

    function renderOrderList() {
        statusBadge.textContent = hasCustomOrder ? `${items.length} 个节点 · 自定义排序` : `${items.length} 个节点 · 默认顺序`;
        listEl.replaceChildren();
        if (!items.length) {
            const empty = document.createElement('div');
            empty.className = 'empty-state';
            empty.textContent = '暂无已发布到订阅的节点';
            listEl.append(empty);
            return;
        }
        const upIcon = typeof ProxyForgeIcons !== 'undefined' ? ProxyForgeIcons.svg('arrowUp', 13) : '↑';
        const downIcon = typeof ProxyForgeIcons !== 'undefined' ? ProxyForgeIcons.svg('arrowDown', 13) : '↓';
        items.forEach((item, idx) => {
            const row = document.createElement('div');
            row.className = 'node-order-row';
            row.draggable = true;

            row.addEventListener('dragstart', e => {
                draggedIndex = idx;
                e.dataTransfer.effectAllowed = 'move';
                row.classList.add('dragging');
            });
            row.addEventListener('dragover', e => {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
            });
            row.addEventListener('dragenter', e => {
                e.preventDefault();
                row.classList.add('drag-over');
            });
            row.addEventListener('dragleave', () => {
                row.classList.remove('drag-over');
            });
            row.addEventListener('drop', e => {
                e.preventDefault();
                row.classList.remove('drag-over');
                if (draggedIndex !== -1 && draggedIndex !== idx) {
                    items = ProxyForgeNodeOrder.moveOrderItem(items, draggedIndex, idx);
                    hasCustomOrder = true;
                    renderOrderList();
                }
                draggedIndex = -1;
            });
            row.addEventListener('dragend', () => {
                row.classList.remove('dragging');
                listEl.querySelectorAll('.node-order-row').forEach(el => el.classList.remove('drag-over'));
                draggedIndex = -1;
            });

            const handle = document.createElement('span');
            handle.className = 'drag-handle';
            handle.style.cursor = 'grab';
            handle.style.color = 'var(--text-muted)';
            handle.textContent = '⠿';

            const rank = document.createElement('span');
            rank.className = 'node-order-rank';
            rank.textContent = String(idx + 1);

            const sourcePill = document.createElement('span');
            const src = item.source || 'manual';
            sourcePill.className = `node-source-pill is-${src}`;
            sourcePill.textContent = ProxyForgeNodeOrder.SOURCE_LABELS[src] || '节点';

            const protoPill = document.createElement('span');
            protoPill.className = 'type-badge badge-default';
            protoPill.textContent = item.type || 'node';

            const info = document.createElement('div');
            info.className = 'item-info';
            const title = document.createElement('div');
            title.className = 'item-name';
            title.textContent = getFlagEmoji(item.name);
            const detail = document.createElement('div');
            detail.className = 'item-detail';
            detail.textContent = `${item.server || ''}${item.port ? ':' + item.port : ''}`;
            info.append(title, detail);

            const actions = document.createElement('div');
            actions.className = 'item-actions';

            const topBtn = document.createElement('button');
            topBtn.type = 'button';
            topBtn.className = 'btn btn-sm';
            topBtn.title = '置顶';
            topBtn.textContent = '⤒';
            topBtn.disabled = idx === 0;
            topBtn.onclick = () => {
                items = ProxyForgeNodeOrder.moveOrderItem(items, idx, 0);
                hasCustomOrder = true;
                renderOrderList();
            };

            const upBtn = document.createElement('button');
            upBtn.type = 'button';
            upBtn.className = 'btn btn-sm';
            upBtn.title = '上移';
            upBtn.innerHTML = upIcon;
            upBtn.disabled = idx === 0;
            upBtn.onclick = () => {
                items = ProxyForgeNodeOrder.moveOrderItem(items, idx, idx - 1);
                hasCustomOrder = true;
                renderOrderList();
            };

            const downBtn = document.createElement('button');
            downBtn.type = 'button';
            downBtn.className = 'btn btn-sm';
            downBtn.title = '下移';
            downBtn.innerHTML = downIcon;
            downBtn.disabled = idx === items.length - 1;
            downBtn.onclick = () => {
                items = ProxyForgeNodeOrder.moveOrderItem(items, idx, idx + 1);
                hasCustomOrder = true;
                renderOrderList();
            };

            actions.append(topBtn, upBtn, downBtn);
            row.append(handle, rank, sourcePill, protoPill, info, actions);
            listEl.append(row);
        });
        if (window.twemoji) twemoji.parse(listEl, { folder: 'svg', ext: '.svg' });
    }

    for (const [label, handler] of [
        ['按地区排序', () => {
            items = ProxyForgeNodeOrder.sortOrderItemsByRegion(items, ProxyForgeRegions.matchRegion);
            hasCustomOrder = true;
            renderOrderList();
        }],
        ['按名称排序', () => {
            items = ProxyForgeNodeOrder.sortOrderItemsByName(items);
            hasCustomOrder = true;
            renderOrderList();
        }],
        ['托管优先', () => {
            items = ProxyForgeNodeOrder.sortOrderItemsManagedFirst(items);
            hasCustomOrder = true;
            renderOrderList();
        }],
        ['恢复默认', async () => {
            try {
                const res = await (await fetchAuth('/nodes/order', {
                    method: 'PUT',
                    body: JSON.stringify({ order: [] }),
                })).json();
                items = Array.isArray(res.items) ? res.items.slice() : [];
                hasCustomOrder = false;
                renderOrderList();
                await syncOrderedNodesFromServer();
                showToast('已恢复默认节点顺序');
            } catch (e) {
                showToast(`重置排序失败：${e.message}`, 'error');
            }
        }],
    ]) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-sm';
        btn.textContent = label;
        btn.onclick = handler;
        toolbar.append(btn);
    }
    toolbar.append(statusBadge);

    renderOrderList();
}

document.getElementById('node-order-btn')?.addEventListener('click', openNodeOrderModal);

// === Template Save Helper ===
async function saveTemplateObj(candidate = state.templateObj, source = 'other', raw = null, successMessage = '') {
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
        showToast(
            result.message || (
                result.report?.warnings.length
                    ? '已保存，存在配置建议，请查看 DNS 与网络'
                    : (successMessage || '已保存底层模板')
            ),
            result.ok ? result.report?.warnings.length ? 'warning' : 'success' : 'error'
        );
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
            </div>
        `;
        openModal('全局 YAML 导入', html, async () => {
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
function copyCurrentSubLink() {
    subLink.select();
    copyTextToClipboard(subLink.value, '链接已复制到剪贴板');
}
copyBtn.addEventListener('click', copyCurrentSubLink);
document.getElementById('copy-link-inline-btn')?.addEventListener('click', copyCurrentSubLink);

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
        updateSubLink();
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

const RULE_TYPES = [
    'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN', 'DOMAIN-REGEX',
    'GEOSITE', 'GEOIP', 'IP-CIDR', 'IP-CIDR6',
    'DST-PORT', 'PROCESS-NAME', 'RULE-SET', 'MATCH',
];
const GEOSITE_SUGGESTIONS = [
    'cn', 'geolocation-!cn', 'openai', 'google', 'youtube',
    'netflix', 'apple', 'microsoft', 'telegram', 'github',
    'category-ads-all', 'private',
];
const NO_RESOLVE_RULE_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'GEOIP', 'RULE-SET']);

window.editRule = function(index) {
    let isNew = index < 0;
    let r = isNew ? '' : state.templateObj['rules'][index];
    const parsed = isNew
        ? { type: 'DOMAIN-SUFFIX', payload: '', target: '', noResolve: false, extraArgs: [], isLogical: false, raw: '' }
        : ProxyForgeRuleUtils.parseRuleParts(r);

    if (parsed.isLogical) {
        openModal('编辑逻辑规则', `
            <div class="form-group full-width">
                <label>逻辑规则原文</label>
                <input type="text" id="m-rule-logical-raw" value="${escapeHtml(parsed.raw)}">
            </div>
        `, () => {
            const rawVal = document.getElementById('m-rule-logical-raw').value.trim();
            if (!rawVal) return alert('请输入规则内容');
            state.templateObj['rules'][index] = rawVal;
            saveTemplateObj();
            closeModal();
        });
        return;
    }

    let targetsHtml = ['DIRECT', 'REJECT'];
    let proxyGroups = state.templateObj['proxy-groups'] || [];
    proxyGroups.forEach(g => { if (g.name) targetsHtml.push(g.name); });
    const ruleTypeChoices = RULE_TYPES.includes(parsed.type) ? RULE_TYPES : [parsed.type, ...RULE_TYPES];

    function payloadPlaceholder(t) {
        if (t === 'GEOSITE') return 'cn / geolocation-!cn / openai';
        if (t === 'GEOIP') return 'CN / LAN / private';
        if (t === 'IP-CIDR' || t === 'IP-CIDR6') return '192.168.0.0/16';
        if (t === 'DST-PORT') return '443';
        if (t === 'PROCESS-NAME') return 'curl';
        if (t === 'RULE-SET') return 'reject_list';
        return 'google.com';
    }

    let html = `
        <div class="form-group full-width">
            <label>规则类型 (Type)</label>
            <select id="m-rule-type">
                ${ruleTypeChoices.map(t => `<option value="${escapeHtml(t)}" ${t === parsed.type ? 'selected' : ''}>${escapeHtml(t)}</option>`).join('')}
            </select>
        </div>
        <div class="form-group full-width" id="m-rule-payload-group" style="${parsed.type === 'MATCH' ? 'display:none;' : ''}">
            <label>匹配内容 (Payload)</label>
            <input type="text" id="m-rule-payload" value="${escapeHtml(parsed.payload)}" placeholder="${escapeHtml(payloadPlaceholder(parsed.type))}" ${parsed.type === 'GEOSITE' ? 'list="m-rule-geosite-list"' : ''}>
            <datalist id="m-rule-geosite-list">
                ${GEOSITE_SUGGESTIONS.map(s => `<option value="${escapeHtml(s)}"></option>`).join('')}
            </datalist>
        </div>
        <div class="form-group full-width">
            <label>目标策略 (Target)</label>
            <select id="m-rule-target">
                ${targetsHtml.map(t => `<option value="${escapeHtml(t)}" ${t === parsed.target ? 'selected' : ''}>${escapeHtml(t)}</option>`).join('')}
            </select>
        </div>
        <div class="form-group full-width" id="m-rule-noresolve-group" style="${NO_RESOLVE_RULE_TYPES.has(parsed.type) ? '' : 'display:none;'}">
            <label class="inline-check">
                <input type="checkbox" id="m-rule-no-resolve" ${parsed.noResolve ? 'checked' : ''}>
                no-resolve (跳过 DNS 解析)
            </label>
        </div>
    `;
    openModal(isNew ? '新建规则' : '编辑规则', html, () => {
        let nType = document.getElementById('m-rule-type').value;
        let nPayload = document.getElementById('m-rule-payload').value.trim();
        let nTarget = document.getElementById('m-rule-target').value;
        let nNoResolve = Boolean(document.getElementById('m-rule-no-resolve')?.checked);

        if (nType !== 'MATCH' && !nPayload) return alert('请输入匹配内容');
        let newRule = ProxyForgeRuleUtils.buildRuleString({
            type: nType,
            payload: nPayload,
            target: nTarget,
            noResolve: nNoResolve,
            extraArgs: parsed.extraArgs,
        });

        if (!state.templateObj['rules']) state.templateObj['rules'] = [];
        if (isNew) {
            ProxyForgeRuleUtils.insertNewRule(state.templateObj['rules'], newRule);
        } else {
            state.templateObj['rules'][index] = newRule;
        }
        saveTemplateObj();
        closeModal();
    });

    document.getElementById('m-rule-type').addEventListener('change', function() {
        const val = this.value;
        const payloadGroup = document.getElementById('m-rule-payload-group');
        const payloadInput = document.getElementById('m-rule-payload');
        const noResolveGroup = document.getElementById('m-rule-noresolve-group');
        payloadGroup.style.display = val === 'MATCH' ? 'none' : 'block';
        noResolveGroup.style.display = NO_RESOLVE_RULE_TYPES.has(val) ? 'block' : 'none';
        if (payloadInput) {
            payloadInput.placeholder = payloadPlaceholder(val);
            if (val === 'GEOSITE') payloadInput.setAttribute('list', 'm-rule-geosite-list');
            else payloadInput.removeAttribute('list');
        }
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
let previewRequest = 0;

async function loadFinalPreview() {
    const requestId = ++previewRequest;
    previewEditor.value = '正在从后端生成最终订阅配置...\n如果数据量大可能会需要几秒钟，请稍候...';
    try {
        let res = await fetch(ProxyForgeSubscription.buildUrl(window.location.origin,
            state.config.SUBSCRIPTION_TOKEN, document.getElementById('sub-name').value, subscriptionFormat.value, subscriptionOptions()));
        if (!res.ok) {
            let errText = await res.text();
            throw new Error(`HTTP ${res.status}: ${errText}`);
        }
        let text = await res.text();
        if (requestId === previewRequest) previewEditor.value = text;
    } catch(e) {
        if (requestId !== previewRequest) return;
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
