const API_BASE = '/api';
let currentToken = localStorage.getItem('proxyforge_token') || '';

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

// Form Elements
const subLink = document.getElementById('sub-link');
const copyBtn = document.getElementById('copy-btn');
const secretToken = document.getElementById('secret-token');
const saveConfigBtn = document.getElementById('save-config-btn');
const airportsEditor = document.getElementById('airports-editor');
const saveAirportsBtn = document.getElementById('save-airports-btn');
const nodesEditor = document.getElementById('nodes-editor');
const saveNodesBtn = document.getElementById('save-nodes-btn');
const rulesEditor = document.getElementById('rules-editor');
const saveRulesBtn = document.getElementById('save-rules-btn');

function showToast(msg, type = 'success') {
    toast.textContent = msg;
    toast.className = `toast toast-${type} active`;
    setTimeout(() => {
        toast.classList.remove('active');
    }, 3000);
}

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
        } else {
            throw new Error('Invalid');
        }
    } catch (err) {
        loginError.style.display = 'block';
        document.querySelector('.login-card').classList.add('shake');
        setTimeout(() => {
            document.querySelector('.login-card').classList.remove('shake');
        }, 400);
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
tokenInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') login();
});
logoutBtn.addEventListener('click', logout);

// Sidebar Logic
sidebarItems.forEach(item => {
    item.addEventListener('click', () => {
        sidebarItems.forEach(i => i.classList.remove('active'));
        sectionPanels.forEach(p => p.classList.remove('active'));
        
        item.classList.add('active');
        const panelId = item.getAttribute('data-panel');
        document.getElementById(panelId).classList.add('active');
    });
});

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
        } else {
            logout();
        }
    }).catch(logout);
}

async function loadData() {
    try {
        const configRes = await fetchAuth('/config');
        const config = await configRes.json();
        secretToken.value = config.SECRET_TOKEN;
        
        const host = window.location.origin;
        subLink.value = `${host}/sub?token=${config.SECRET_TOKEN}`;

        const airportsRes = await fetchAuth('/airports');
        const airportsData = await airportsRes.json();
        airportsEditor.value = airportsData.urls.join('\n');

        const nodesRes = await fetchAuth('/nodes');
        const nodesData = await nodesRes.json();
        nodesEditor.value = JSON.stringify(nodesData.nodes, null, 4);

        const rulesRes = await fetchAuth('/template');
        const rulesData = await rulesRes.json();
        rulesEditor.value = rulesData.content;
    } catch (e) {
        console.error("Failed to load data", e);
    }
}

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
        
        const host = window.location.origin;
        subLink.value = `${host}/sub?token=${payload.SECRET_TOKEN}`;
        
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

saveNodesBtn.addEventListener('click', async () => {
    try {
        const nodes = JSON.parse(nodesEditor.value);
        await fetchAuth('/nodes', {
            method: 'POST',
            body: JSON.stringify({ nodes })
        });
        showToast('自建节点已保存');
    } catch (e) {
        showToast('JSON 格式错误，请检查!', 'error');
    }
});

saveRulesBtn.addEventListener('click', async () => {
    try {
        await fetchAuth('/template', {
            method: 'POST',
            body: JSON.stringify({ content: rulesEditor.value })
        });
        showToast('规则模板已保存');
    } catch (e) {
        showToast('保存模板失败', 'error');
    }
});
