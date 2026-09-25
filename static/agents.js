/* Inventory and explicitly allowlisted read-only jobs. */
const pendingAgentJobRequests = new Map();

function agentCanRunJobs(agent) {
    return agent.status !== 'revoked' && agent.compatible && agent.metadata.job_protocol_version === 1;
}

function agentCanManageRuntime(agent) {
    return agentCanRunJobs(agent) && agent.metadata.supported && agent.metadata.runtime_protocol_version === 1;
}

async function showAgentJobs(agent) {
    const release = await (await fetchAuth('/agents/runtime/release')).json();
    openModal('Agent 任务', '<p>管理 ProxyForge 独立 sing-box 实例。安装后默认没有公网监听；不会修改用户已有的 sing-box。</p>' +
        '<p>取消任务不能保证中止已开始的服务变更，请刷新状态核实结果。</p>' +
        '<select id="agent-job-action"><option value="singbox.status">查询状态</option></select>' +
        '<p id="agent-runtime-notice"></p><button class="btn" id="agent-job-create">创建任务</button> ' +
        '<button class="btn" id="agent-job-refresh">刷新任务</button><p id="agent-job-notice"></p>' +
        '<div id="agent-job-list"></div>', closeModal);
    const target = document.getElementById('agent-job-list');
    const notice = document.getElementById('agent-job-notice');
    const create = document.getElementById('agent-job-create');
    const selector = document.getElementById('agent-job-action');
    if (agentCanManageRuntime(agent)) {
        for (const [value, label] of [['singbox.install', '安装 / 更新至 ' + release.version],
            ['singbox.start', '启动'], ['singbox.stop', '停止'], ['singbox.restart', '重启'], ['singbox.rollback', '恢复上一次运行版本']]) {
            const option = document.createElement('option'); option.value = value; option.textContent = label; selector.append(option);
        }
    } else {
        document.getElementById('agent-runtime-notice').textContent = '运行环境管理需要升级 Agent，并在目标机器本地启用辅助服务。';
    }
    create.disabled = !agentCanRunJobs(agent);
    if (create.disabled) notice.textContent = '此 Agent 尚不支持任务或已撤销，请先升级 Agent。';
    async function refresh() {
        const { jobs } = await (await fetchAuth('/agents/' + agent.id + '/jobs')).json();
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
                        await fetchAuth('/agents/' + agent.id + '/jobs/' + job.id + '/cancel', { method: 'POST' });
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
        if (type !== 'singbox.status' && !confirm('确认对该 Agent 的 ProxyForge 独立实例执行“' + selector.selectedOptions[0].textContent + '”？启停或重启可能中断其连接。')) return;
        create.disabled = true;
        try {
            const payload = type === 'singbox.install' ? { version: release.version } : {};
            const key = agent.id + ':' + type + ':' + JSON.stringify(payload);
            let requestId = pendingAgentJobRequests.get(key);
            if (!requestId) {
                // getRandomValues also works when the admin UI is served over HTTP.
                requestId = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
                pendingAgentJobRequests.set(key, requestId);
            }
            await fetchAuth('/agents/' + agent.id + '/jobs', { method: 'POST', body: JSON.stringify({
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
            for (const [label, action] of [['详情', 'details'], ['任务', 'jobs'], ['编辑', 'edit'], ['撤销', 'revoke'], ['移除', 'remove']]) {
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
                '<p>注册响应丢失时：检查并移除孤儿 Agent，生成新 token 再注册。当前仅支持状态查询任务。</p>',
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
if (typeof module !== 'undefined' && module.exports) module.exports = { agentStatusLabel, agentCanRunJobs, agentCanManageRuntime };
