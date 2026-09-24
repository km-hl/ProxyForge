/* B1 inventory UI; no execution or deployment buttons. */
function agentStatusLabel(agent) {
    const labels = { online: '在线', degraded: '心跳延迟', offline: '离线', never_seen: '等待首次心跳', revoked: '已撤销' };
    return (labels[agent.status] || '未知') + (!agent.compatible ? ' · 协议不兼容' : '') +
        (!agent.metadata.supported ? ' · 未支持的系统' : '');
}

async function refreshAgents() {
    const target = document.getElementById('agent-list');
    try {
        const { agents } = await (await fetchAuth('/agents')).json();
        target.replaceChildren();
        if (!agents.length) { target.textContent = '尚无 Agent。添加服务器后，在目标机器运行参考 Agent 安装程序。'; return; }
        const table = document.createElement('table'); table.className = 'agent-table';
        const headings = document.createElement('tr');
        for (const name of ['名称 / 主机', '连接来源 IP', '系统 / 架构', 'Agent / sing-box', '状态 / 角色', '最后在线', '操作']) {
            const cell = document.createElement('th'); cell.textContent = name; headings.append(cell);
        }
        table.append(headings);
        for (const agent of agents) {
            const row = document.createElement('tr');
            const m = agent.metadata;
            for (const value of [agent.name + ' / ' + m.hostname, agent.observed_ip,
                m.os + ' ' + m.os_version + ' / ' + m.arch,
                m.agent_version + ' / ' + (m.singbox.installed ? (m.singbox.running ? '运行中' : '未运行') : '未安装'),
                agentStatusLabel(agent) + ' / ' + agent.role,
                agent.last_seen ? new Date(agent.last_seen * 1000).toLocaleString() : '—']) {
                const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
            }
            const actions = document.createElement('td');
            for (const [label, action] of [['详情', 'details'], ['编辑', 'edit'], ['撤销', 'revoke'], ['移除', 'remove']]) {
                const button = document.createElement('button'); button.textContent = label; button.className = 'btn';
                button.onclick = () => agentAction(agent, action).catch(error => showToast(error.message, 'error'));
                actions.append(button);
            }
            row.append(actions); table.append(row);
        }
        target.append(table);
    } catch (error) { target.textContent = '读取 Agent 失败：' + error.message; }
}

async function agentAction(agent, action) {
    if (action === 'details') {
        const current = await (await fetchAuth('/agents/' + agent.id)).json();
        openModal('Agent 详情', '<pre id="agent-detail" style="white-space:pre-wrap"></pre>', closeModal);
        document.getElementById('agent-detail').textContent = JSON.stringify(current, null, 2);
        return;
    }
    if (action === 'edit') {
        openModal('编辑 Agent', '<label>名称</label><input id="agent-name">' +
            '<label>角色（仅标签，不改变远端配置）</label><select id="agent-role">' +
            '<option>unassigned</option><option>node</option><option>landing</option><option>both</option></select>' +
            '<label>标签（逗号分隔）</label><input id="agent-tags">', async () => {
                try {
                    await fetchAuth('/agents/' + agent.id, { method: 'PATCH', body: JSON.stringify({
                        name: document.getElementById('agent-name').value,
                        role: document.getElementById('agent-role').value,
                        tags: document.getElementById('agent-tags').value.split(',').map(s => s.trim()).filter(Boolean)
                    }) });
                    closeModal(); await refreshAgents();
                } catch (error) { showToast(error.message, 'error'); }
            });
        document.getElementById('agent-name').value = agent.name;
        document.getElementById('agent-role').value = agent.role;
        document.getElementById('agent-tags').value = agent.tags.join(', ');
        return;
    }
    if (!confirm(action === 'remove' ? '移除会撤销凭据并删除控制台记录。远端服务不会卸载。继续？' :
        '撤销后 Agent 将停止同步；不会停止远端 sing-box。继续？')) return;
    await fetchAuth('/agents/' + agent.id + (action === 'revoke' ? '/revoke' : ''),
        { method: action === 'revoke' ? 'POST' : 'DELETE' });
    await refreshAgents();
}

async function addAgent() {
    openModal('添加服务器', '<label>服务器名称</label><input id="new-agent-name" maxlength="128">', async () => {
        try {
            const registration = await (await fetchAuth('/agents/registration-tokens', {
                method: 'POST', body: JSON.stringify({ name: document.getElementById('new-agent-name').value })
            })).json();
            openModal('一次性注册凭据',
                '<p>在目标 VPS 下载并审查固定版本的安装程序后运行，将此 token 粘贴到安装程序的隐藏输入提示中。不要放进命令行参数。</p>' +
                '<input id="agent-registration-token" readonly autocomplete="off">' +
                '<p id="agent-registration-expiry"></p>' +
                '<p>注册响应丢失时：检查并移除孤儿 Agent，生成新 token 再注册。B1 只上报状态，不部署节点。</p>',
                () => { clearRegistrationToken(); closeModal(); });
            document.getElementById('agent-registration-token').value = registration.registration_token;
            document.getElementById('agent-registration-expiry').textContent =
                '有效期至 ' + new Date(registration.expires_at * 1000).toLocaleString() + '；只能成功注册一次。';
        } catch (error) { showToast(error.message, 'error'); }
    });
}

function clearRegistrationToken() {
    const field = document.getElementById('agent-registration-token');
    if (field) field.value = '';
}

if (typeof document !== 'undefined') {
    document.getElementById('agent-add-btn').addEventListener('click', addAgent);
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
if (typeof module !== 'undefined' && module.exports) module.exports = { agentStatusLabel };
