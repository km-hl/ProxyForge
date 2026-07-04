const API_BASE = '/api';
let currentToken = localStorage.getItem('proxyforge_token') || '';

// Data State
let state = {
    config: {},
    airports: [],
    airportsInfo: [],
    nodes: [],
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
const rulesEditor = document.getElementById('rules-editor');
const saveRulesBtn = document.getElementById('save-rules-btn');

function showToast(msg, type = 'success') {
    toast.textContent = msg;
    toast.className = `toast toast-${type} active`;
    setTimeout(() => { toast.classList.remove('active'); }, 3000);
}

// === Modal Logic ===
function openModal(title, htmlContent, onConfirm) {
    modalTitle.textContent = title;
    modalBody.innerHTML = htmlContent;
    modalConfirmAction = onConfirm;
    modalOverlay.classList.add('active');
}
function closeModal() {
    modalOverlay.classList.remove('active');
    modalConfirmAction = null;
}
modalClose.addEventListener('click', closeModal);
modalCancel.addEventListener('click', closeModal);
modalConfirm.addEventListener('click', () => {
    if (modalConfirmAction) modalConfirmAction();
});

// === Auth Logic ===
async function fetchAuth(url, options = {}) {
    if (!options.headers) options.headers = {};
    options.headers['Authorization'] = `Bearer ${currentToken}`;
    options.headers['Content-Type'] = 'application/json';
    const res = await fetch(`${API_BASE}${url}`, options);
    if (res.status === 401) {
        logout();
        throw new Error('Unauthorized');
    }
    return res;
}

async function login() {
    const token = tokenInput.value.trim();
    if (!token) return;
    try {
        const res = await fetch(`${API_BASE}/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });
        if (res.ok) {
            currentToken = token;
            localStorage.setItem('proxyforge_token', token);
            loginOverlay.classList.remove('active');
            dashboard.style.display = 'flex';
            dashboard.classList.remove('hidden');
            loadData();
        } else throw new Error('Invalid');
    } catch (err) {
        loginError.style.display = 'block';
        document.querySelector('.login-card').classList.add('shake');
        setTimeout(() => { document.querySelector('.login-card').classList.remove('shake'); }, 400);
    }
}

function logout() {
    currentToken = '';
    localStorage.removeItem('proxyforge_token');
    dashboard.style.display = 'none';
    loginOverlay.classList.add('active');
    tokenInput.value = '';
    loginError.style.display = 'none';
}

loginBtn.addEventListener('click', login);
tokenInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') login(); });
logoutBtn.addEventListener('click', logout);

if (currentToken) {
    fetch(`${API_BASE}/auth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: currentToken })
    }).then(res => {
        if (res.ok) {
            loginOverlay.classList.remove('active');
            dashboard.style.display = 'flex';
            dashboard.classList.remove('hidden');
            loadData();
        } else logout();
    }).catch(logout);
}

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
        secretToken.value = state.config.SECRET_TOKEN;
        subLink.value = `${window.location.origin}/sub?token=${state.config.SECRET_TOKEN}`;

        const airportsRes = await fetchAuth('/airports');
        state.airports = (await airportsRes.json()).urls || [];

        const nodesRes = await fetchAuth('/nodes');
        state.nodes = (await nodesRes.json()).nodes || [];
        
        const rulesRes = await fetchAuth('/template');
        state.templateRaw = (await rulesRes.json()).content || '';
        try {
            state.templateObj = jsyaml.load(state.templateRaw) || {};
        } catch(e) {
            state.templateObj = {};
        }

        renderAirports();
        renderNodes();
        renderGroups();
        renderRules();
        rulesEditor.value = state.templateRaw;

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
    state.airports.forEach((url, index) => {
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
            html += `
                <div class="list-item" style="flex-direction:column; align-items:flex-start;">
                    <div style="display:flex; width:100%; align-items:center;">
                        ${getCheckboxHTML('cb-airport', index)}
                        <span class="type-badge badge-select" style="margin-right:8px; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${info.name || '机场'}</span>
                        <div class="item-info" style="flex:1; word-break:break-all; font-size:0.8rem; color:#666;">${url}</div>
                        <div class="item-actions">
                            <button class="btn btn-sm btn-danger" onclick="deleteAirport(${index})">删除</button>
                        </div>
                    </div>
                    <div style="display:flex; gap:15px; margin-left:34px; margin-top:8px; font-size:0.8rem; flex-wrap:wrap;">
                        <span style="color:#2e7d32;"><b>📦 节点:</b> ${info.error ? '?' : info.nodesCount}</span>
                        <span style="color:#1565c0;"><b>📊 流量:</b> ${usageStr}</span>
                        <span style="color:#e65100;"><b>⏳ 到期:</b> ${info.expire ? formatDate(info.expire) : '长期有效'}</span>
                    </div>
                    ${info.error ? `<div style="color:red; font-size:0.75rem; margin-left:34px; margin-top:4px;">抓取失败: ${info.error}</div>` : ''}
                </div>
            `;
        } else {
            html += `
                <div class="list-item">
                    ${getCheckboxHTML('cb-airport', index)}
                    <div class="item-info" style="word-break:break-all;">${url}</div>
                    <span style="font-size:0.8rem; color:#999;">动态数据加载中...</span>
                    <div class="item-actions">
                        <button class="btn btn-sm btn-danger" onclick="deleteAirport(${index})">删除</button>
                    </div>
                </div>
            `;
        }
    });
    list.innerHTML = html;
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
        const typeBadge = `badge-${(g.type || 'select').toLowerCase().replace(' ', '-')}`;
        const proxies = Array.isArray(g.proxies) ? g.proxies.join(', ') : '无';
        html += `
            <div class="list-item">
                ${getCheckboxHTML('cb-group', index)}
                <span class="type-badge ${typeBadge}">${g.type || 'select'}</span>
                <div class="item-info">
                    <div class="item-name">${g.name || 'Unnamed'}</div>
                    <div class="item-detail">包含: ${proxies}</div>
                </div>
                <div class="item-actions">
                    <button class="btn btn-sm" onclick="editGroup(${index})">编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteGroup(${index})">删除</button>
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
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
        const typeBadge = `badge-node`;
        html += `
            <div class="list-item">
                ${getCheckboxHTML('cb-node', index)}
                <span class="type-badge ${typeBadge}">${n.type || 'unknown'}</span>
                <div class="item-info">
                    <div class="item-name">${n.name || 'Unnamed'}</div>
                    <div class="item-detail">${n.server || 'No server'} : ${n.port || 'No port'}</div>
                </div>
                <div class="item-actions">
                    <button class="btn btn-sm" onclick="editNode(${index})">编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteNode(${index})">删除</button>
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
    if (!rules.length) {
        list.innerHTML = `<div class="empty-state">暂无路由规则</div>`;
        return;
    }
    let html = '';
    rules.forEach((r, index) => {
        html += `
            <div class="list-item">
                ${getCheckboxHTML('cb-rule', index)}
                <div class="item-info" style="font-family: monospace;">${r}</div>
                <div class="item-actions">
                    <button class="btn btn-sm btn-danger" onclick="deleteRule(${index})">删除</button>
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
}

// === Actions: Airports ===
document.getElementById('btn-add-airport').addEventListener('click', () => {
    const html = `
        <div class="form-group full-width">
            <label>添加多个机场链接 (一行一个)</label>
            <textarea id="m-airport-input" style="min-height:150px;" placeholder="https://..."></textarea>
        </div>
    `;
    openModal('添加机场', html, async () => {
        let urls = document.getElementById('m-airport-input').value.split('\n').map(s=>s.trim()).filter(s=>s);
        if(urls.length) {
            state.airports = state.airports.concat(urls);
            closeModal();
            await saveAirportsObj();
        }
    });
});

window.deleteAirport = async function(index) {
    state.airports.splice(index, 1);
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

async function saveAirportsObj() {
    renderAirports();
    try {
        await fetchAuth('/airports', {
            method: 'POST',
            body: JSON.stringify({ urls: state.airports })
        });
        showToast('机场配置已保存');
        // Refresh info after saving
        fetchAuth('/airports/info').then(res => res.json()).then(data => {
            state.airportsInfo = data.info || [];
            renderAirports();
        });
    } catch(e) { showToast('保存失败', 'error'); }
}

// === Actions: Proxy Groups ===
window.editGroup = function(index) {
    let g = index >= 0 ? state.templateObj['proxy-groups'][index] : { name: '', type: 'select', proxies: [] };
    const html = `
        <div class="form-grid">
            <div class="form-group">
                <label>名称 (Name)</label>
                <input type="text" id="m-group-name" value="${g.name || ''}">
            </div>
            <div class="form-group">
                <label>类型 (Type)</label>
                <select id="m-group-type">
                    <option value="select" ${g.type==='select'?'selected':''}>select (手动选择)</option>
                    <option value="url-test" ${g.type==='url-test'?'selected':''}>url-test (自动测速)</option>
                    <option value="fallback" ${g.type==='fallback'?'selected':''}>fallback (故障转移)</option>
                    <option value="load-balance" ${g.type==='load-balance'?'selected':''}>load-balance (负载均衡)</option>
                </select>
            </div>
            <div class="form-group full-width">
                <label>包含节点 (Proxies) - 每行一个</label>
                <textarea id="m-group-proxies" rows="4">${Array.isArray(g.proxies)?g.proxies.join('\n'):''}</textarea>
            </div>
            <div class="form-group">
                <label>测试链接 (URL)</label>
                <input type="text" id="m-group-url" value="${g.url || 'http://www.gstatic.com/generate_204'}">
            </div>
            <div class="form-group">
                <label>测试间隔 (Interval / s)</label>
                <input type="number" id="m-group-interval" value="${g.interval || 300}">
            </div>
        </div>
    `;
    openModal(index >= 0 ? '编辑代理组' : '新建代理组', html, () => {
        g.name = document.getElementById('m-group-name').value.trim();
        g.type = document.getElementById('m-group-type').value;
        g.proxies = document.getElementById('m-group-proxies').value.split('\n').map(s=>s.trim()).filter(s=>s);
        if (g.type !== 'select') {
            g.url = document.getElementById('m-group-url').value.trim();
            g.interval = parseInt(document.getElementById('m-group-interval').value) || 300;
        } else { delete g.url; delete g.interval; }
        
        if (!state.templateObj['proxy-groups']) state.templateObj['proxy-groups'] = [];
        if (index >= 0) state.templateObj['proxy-groups'][index] = g;
        else state.templateObj['proxy-groups'].push(g);
        
        closeModal();
        saveTemplateObj();
    });
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

// === Actions: Nodes ===
window.editNode = function(index) {
    let isNew = index < 0;
    let yamlStr = isNew ? "name: New Node\ntype: vmess\nserver: 1.1.1.1\nport: 443" : jsyaml.dump(state.nodes[index]);
    const html = `
        <div class="form-group full-width">
            <label>节点配置 (YAML格式)</label>
            <textarea id="m-node-raw" style="min-height:250px; font-family:monospace;">${yamlStr}</textarea>
        </div>
    `;
    openModal(isNew ? '新建自建节点' : '编辑自建节点', html, () => {
        try {
            let parsed = jsyaml.load(document.getElementById('m-node-raw').value);
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
            <textarea id="m-nodes-import" style="min-height:250px;" placeholder="支持粘贴标准 YAML 节点列表，或者直接粘贴 vless:// vmess:// hysteria2:// 链接 (每行一个)"></textarea>
        </div>
    `;
    openModal('批量导入自建节点', html, async () => {
        try {
            let text = document.getElementById('m-nodes-import').value;
            let lines = text.split('\n').map(s=>s.trim()).filter(s=>s);
            let links = lines.filter(s => s.match(/^(vmess|vless|trojan|hysteria2|hy2|ss):\/\//i));
            let nonLinksText = lines.filter(s => !s.match(/^(vmess|vless|trojan|hysteria2|hy2|ss):\/\//i)).join('\n');
            
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
    try {
        await fetchAuth('/nodes', {
            method: 'POST',
            body: JSON.stringify({ nodes: state.nodes })
        });
        showToast('节点已保存');
    } catch(e) { showToast('保存失败', 'error'); }
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

async function saveTemplateObj() {
    state.templateRaw = jsyaml.dump(state.templateObj);
    rulesEditor.value = state.templateRaw;
    renderGroups();
    renderRules();
    try {
        await fetchAuth('/template', {
            method: 'POST',
            body: JSON.stringify({ content: state.templateRaw })
        });
        showToast('已保存底层模板');
    } catch(e) { showToast('保存失败', 'error'); }
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
            try {
                let raw = document.getElementById('m-global-yaml').value;
                let parsed = jsyaml.load(raw);
                if (!parsed || typeof parsed !== 'object') throw new Error("无效的 YAML 结构");

                let nodeCount = 0;
                if (parsed.proxies && Array.isArray(parsed.proxies)) {
                    state.nodes = state.nodes.concat(parsed.proxies);
                    nodeCount = parsed.proxies.length;
                    delete parsed.proxies;
                }

                let airportCount = 0;
                if (parsed['proxy-providers'] && typeof parsed['proxy-providers'] === 'object') {
                    for (const key in parsed['proxy-providers']) {
                        const provider = parsed['proxy-providers'][key];
                        if (provider && provider.type === 'http' && provider.url) {
                            if (!state.airports.includes(provider.url)) {
                                state.airports.push(provider.url);
                                airportCount++;
                            }
                        }
                    }
                    delete parsed['proxy-providers']; // 由 ProxyForge 接管，无需保留原生 provider
                }

                if (Object.keys(parsed).length > 0) {
                    state.templateObj = Object.assign(state.templateObj, parsed);
                    state.templateRaw = jsyaml.dump(state.templateObj);
                    rulesEditor.value = state.templateRaw;
                    renderGroups();
                    renderRules();
                }

                if (nodeCount > 0) {
                    await fetchAuth('/nodes', {
                        method: 'POST',
                        body: JSON.stringify({ nodes: state.nodes })
                    });
                    renderNodes();
                }

                if (airportCount > 0) {
                    await fetchAuth('/airports', {
                        method: 'POST',
                        body: JSON.stringify({ urls: state.airports })
                    });
                    renderAirports();
                }
                
                if (Object.keys(parsed).length > 0) {
                    await fetchAuth('/template', {
                        method: 'POST',
                        body: JSON.stringify({ content: state.templateRaw })
                    });
                }

                closeModal();
                showToast(`导入成功！提取 ${nodeCount} 个节点，${airportCount} 个机场，并更新底层配置。`);
            } catch (e) { alert('解析或保存失败: ' + e.message); }
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
        const payload = { SECRET_TOKEN: secretToken.value };
        await fetchAuth('/config', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        showToast('密钥已保存');
        subLink.value = `${window.location.origin}/sub?token=${payload.SECRET_TOKEN}`;
        if (payload.SECRET_TOKEN !== currentToken) {
            currentToken = payload.SECRET_TOKEN;
            localStorage.setItem('proxyforge_token', currentToken);
        }
    } catch (e) { showToast('保存密钥失败', 'error'); }
});

saveRulesBtn.addEventListener('click', async () => {
    try {
        let newYaml = rulesEditor.value;
        state.templateObj = jsyaml.load(newYaml) || {};
        state.templateRaw = newYaml;
        renderGroups();
        renderRules();
        await fetchAuth('/template', {
            method: 'POST',
            body: JSON.stringify({ content: newYaml })
        });
        showToast('底层配置已覆盖保存');
    } catch (e) { showToast('YAML解析或保存失败', 'error'); }
});
