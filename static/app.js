const API_BASE = '/api';
let currentToken = localStorage.getItem('proxyforge_token') || '';

// Data State
let state = {
    config: {},
    airports: [],
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
const airportsEditor = document.getElementById('airports-editor');
const saveAirportsBtn = document.getElementById('save-airports-btn');
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
        state.airports = (await airportsRes.json()).urls;
        airportsEditor.value = state.airports.join('\n');

        const nodesRes = await fetchAuth('/nodes');
        state.nodes = (await nodesRes.json()).nodes || [];
        
        const rulesRes = await fetchAuth('/template');
        state.templateRaw = (await rulesRes.json()).content || '';
        try {
            state.templateObj = jsyaml.load(state.templateRaw) || {};
        } catch(e) {
            console.error("YAML 解析错误", e);
            state.templateObj = {};
        }

        renderNodes();
        renderGroups();
        renderRules();
        rulesEditor.value = state.templateRaw;
    } catch (e) {
        console.error("Failed to load data", e);
    }
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
                <div class="item-info" style="font-family: monospace;">${r}</div>
                <div class="item-actions">
                    <button class="btn btn-sm btn-danger" onclick="deleteRule(${index})">删除</button>
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
}

// === Action: Proxy Groups ===
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
        } else {
            delete g.url; delete g.interval;
        }
        
        if (!state.templateObj['proxy-groups']) state.templateObj['proxy-groups'] = [];
        if (index >= 0) state.templateObj['proxy-groups'][index] = g;
        else state.templateObj['proxy-groups'].push(g);
        
        closeModal();
        saveTemplateObj();
    });
};
document.getElementById('btn-add-group').addEventListener('click', () => editGroup(-1));

window.deleteGroup = function(index) {
    if(confirm('确定要删除该代理组吗？')) {
        state.templateObj['proxy-groups'].splice(index, 1);
        saveTemplateObj();
    }
};

// === Action: Nodes ===
window.editNode = function(index) {
    let isNew = index < 0;
    let yamlStr = isNew ? "name: New Node\ntype: vmess\nserver: 1.1.1.1\nport: 443" : jsyaml.dump(state.nodes[index]);
    const html = `
        <div class="form-group full-width">
            <label>节点配置 (YAML / JSON格式)</label>
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
        } catch(e) {
            alert('YAML 解析失败，请检查格式');
        }
    });
};
document.getElementById('btn-add-node').addEventListener('click', () => editNode(-1));

document.getElementById('btn-import-nodes').addEventListener('click', () => {
    const html = `
        <div class="form-group full-width">
            <label>粘贴包含 proxies 列表的 YAML 文本</label>
            <textarea id="m-nodes-import" style="min-height:250px;" placeholder="proxies:\n  - name: node1..."></textarea>
        </div>
    `;
    openModal('批量导入自建节点', html, () => {
        try {
            let parsed = jsyaml.load(document.getElementById('m-nodes-import').value);
            let toAdd = [];
            if(Array.isArray(parsed)) toAdd = parsed;
            else if(parsed.proxies && Array.isArray(parsed.proxies)) toAdd = parsed.proxies;
            else throw new Error("找不到 proxies 数组");
            
            state.nodes = state.nodes.concat(toAdd);
            closeModal();
            saveNodesObj();
            showToast(`成功导入 ${toAdd.length} 个节点`);
        } catch(e) {
            alert('YAML 解析失败: ' + e.message);
        }
    });
});

window.deleteNode = function(index) {
    if(confirm('确定要删除该节点吗？')) {
        state.nodes.splice(index, 1);
        saveNodesObj();
    }
};

async function saveNodesObj() {
    renderNodes();
    try {
        await fetchAuth('/nodes', {
            method: 'POST',
            body: JSON.stringify({ nodes: state.nodes })
        });
        showToast('节点已保存并生效');
    } catch(e) {
        showToast('保存节点失败', 'error');
    }
}

// === Action: Rules ===
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
            state.templateObj['rules'].unshift(val); // Insert at top
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
        showToast('路由及代理组已保存');
    } catch(e) {
        showToast('保存模板失败', 'error');
    }
}

// === Action: Others ===
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
    } catch (e) {
        showToast('保存密钥失败', 'error');
    }
});

saveAirportsBtn.addEventListener('click', async () => {
    try {
        const urls = airportsEditor.value.split('\n').map(u => u.trim()).filter(u => u);
        await fetchAuth('/airports', {
            method: 'POST',
            body: JSON.stringify({ urls })
        });
        showToast('机场列表已保存');
    } catch (e) {
        showToast('保存机场列表失败', 'error');
    }
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
    } catch (e) {
        showToast('YAML解析或保存失败', 'error');
    }
});

// === Action: Global Import ===
const globalImportBtn = document.getElementById('global-import-btn');
if (globalImportBtn) {
    globalImportBtn.addEventListener('click', () => {
        const html = `
            <div class="form-group full-width">
                <label>粘贴完整的 YAML 配置 (包含 proxies, proxy-groups, rules 等)</label>
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
                // 提取 nodes
                if (parsed.proxies && Array.isArray(parsed.proxies)) {
                    state.nodes = state.nodes.concat(parsed.proxies);
                    nodeCount = parsed.proxies.length;
                    delete parsed.proxies; // 移除 proxies，剩下的作为 template
                }

                // 剩下的内容覆盖到 template (如果还有内容)
                if (Object.keys(parsed).length > 0) {
                    state.templateObj = Object.assign(state.templateObj, parsed); // 或者完全替换？合并更安全
                    state.templateRaw = jsyaml.dump(state.templateObj);
                    rulesEditor.value = state.templateRaw;
                    renderGroups();
                    renderRules();
                }

                // 异步保存
                if (nodeCount > 0) {
                    await fetchAuth('/nodes', {
                        method: 'POST',
                        body: JSON.stringify({ nodes: state.nodes })
                    });
                    renderNodes();
                }
                
                if (Object.keys(parsed).length > 0) {
                    await fetchAuth('/template', {
                        method: 'POST',
                        body: JSON.stringify({ content: state.templateRaw })
                    });
                }

                closeModal();
                showToast(`全局导入成功！提取 ${nodeCount} 个节点，并更新底层配置。`);
            } catch (e) {
                alert('解析或保存失败: ' + e.message);
            }
        });
    });
}
