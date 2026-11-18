/* Management inventory is separate from the subscription's usable node list. */
const ProxyForgeManagedNodes = (() => {
    function statusLabel(node) {
        if (node.agent.status === 'revoked') return '入口已撤销';
        if (node.removed) return '已移除监听';
        if (node.landing && node.landing.status === 'revoked') return '落地已撤销';
        if (node.status === 'adopted' && node.adopted_status === 'adopted') return '已完全接管';
        const labels = { pending: '等待执行', assigned: '已分配', running: '执行中', success: '配置已应用', failed: '执行失败', cancelled: '已取消', adopted: '接管扫描' };
        return labels[node.status] || '状态未知';
    }
    function matches(node, query, filter) {
        if (filter === 'published' && !node.publishable) return false;
        if (filter === 'unpublished' && node.publishable) return false;
        const text = [node.name, node.agent.name, node.landing?.name, node.server, node.core, node.protocol, node.service_name, node.sni].join(' ').toLocaleLowerCase();
        return text.includes(query.trim().toLocaleLowerCase());
    }
    function managementAction(node) {
        if (node.kind === 'chain') return 'chain';
        if (node.kind === 'adopted') return 'adoptions';
        return 'deployment';
    }
    function connectionLabel(agent) {
        const labels = { online: '在线', degraded: '心跳延迟', offline: '离线', never_seen: '等待首次心跳', revoked: '已撤销' };
        return (labels[agent.status] || '未知') + (!agent.compatible ? ' · 协议不兼容' : '');
    }
    let rows = [], generation = 0;
    function render() {
        const target = document.getElementById('managed-nodes-list');
        const query = document.getElementById('managed-node-search').value;
        const filter = document.getElementById('managed-node-filter').value;
        target.replaceChildren();
        const visible = rows.filter(node => matches(node, query, filter));
        if (!visible.length) {
            target.textContent = rows.length ? '没有符合条件的托管节点。' : '暂无托管节点。请在 Agent 服务器页面部署直连节点或添加链路。';
            return;
        }
        function text(parent, tag, value, className) {
            const element = document.createElement(tag);
            element.textContent = value;
            if (className) element.className = className;
            parent.append(element);
            return element;
        }
        for (const node of visible) {
            const card = document.createElement('article'); card.className = 'managed-node-card';
            const badgeText = node.kind === 'chain' ? 'Agent 托管 · 经落地' : (node.kind === 'adopted' ? (node.adopted_status === 'adopted' ? 'Agent 接管 · 已托管' : 'Agent 接管 · 存量资产') : 'Agent 托管 · 直连');
            text(card, 'span', badgeText, 'type-badge');
            const displayTitle = typeof getFlagEmoji === 'function' ? getFlagEmoji(node.name) : node.name;
            text(card, 'h4', displayTitle);
            text(card, 'p', '预期地址：' + node.server + ':' + node.port);
            text(card, 'p', '入口：' + node.agent.name + ' · ' + connectionLabel(node.agent));
            if (node.kind === 'adopted') {
                text(card, 'p', '内核：' + (node.core || '') + ' · 协议：' + (node.protocol || '') +
                    (node.tls_mode ? ' · TLS：' + node.tls_mode : '') + (node.sni ? ' · SNI：' + node.sni : ''));
            }
            if (node.landing) text(card, 'p', '落地：' + node.landing.name + ' · ' + connectionLabel(node.landing));
            text(card, 'p', statusLabel(node) + ' · 版本 ' + node.revision + ' · ' + (node.publishable ? '可加入订阅' : '暂不加入订阅'));
            if (node.error) text(card, 'p', '任务错误：' + node.error, 'managed-node-error');
            if (node.blocked_by.length) text(card, 'p', '修改直连前请先移除链路：' + node.blocked_by.map(item => item.name).join('、'));
            const actions = document.createElement('div'); actions.className = 'managed-node-actions'; card.append(actions);
            const primaryLabel = node.kind === 'chain' ? '管理链路' : (node.kind === 'adopted' ? '查看接管' : '管理部署');
            for (const [label, action] of [[primaryLabel, managementAction(node)], ['查看任务', 'jobs'], ['入口详情', 'details']]) {
                const button = text(actions, 'button', label, 'btn btn-sm');
                button.onclick = async () => {
                    button.disabled = true;
                    try {
                        await agentAction({ id: node.agent.id }, action);
                    } catch (error) { showToast(error.message, 'error'); }
                    finally { button.disabled = false; }
                };
            }
            target.append(card);
        }
        if (typeof window !== 'undefined' && window.twemoji) {
            window.twemoji.parse(target, { folder: 'svg', ext: '.svg' });
        }
    }
    async function refresh() {
        const current = ++generation;
        const status = document.getElementById('managed-node-notice');
        status.textContent = '正在读取托管状态…';
        try {
            const data = await (await fetchAuth('/agents/managed/nodes')).json();
            if (current !== generation) return;
            rows = data.nodes; render();
            status.textContent = '连接字段由 Agent 部署管理。可加入订阅表示控制面发布条件已满足，不代表公网可达。';
        } catch (error) {
            if (current !== generation) return;
            rows = []; document.getElementById('managed-nodes-list').textContent = '暂时无法显示托管节点。';
            status.textContent = '托管状态读取失败：' + error.message + '。请刷新重试。';
        }
    }
    if (typeof document !== 'undefined') {
        document.getElementById('btn-refresh-managed-nodes').onclick = refresh;
        document.getElementById('managed-node-search').oninput = render;
        document.getElementById('managed-node-filter').onchange = render;
        document.querySelector('[data-panel="panel-nodes"]').addEventListener('click', refresh);
        setInterval(() => {
            if (document.getElementById('panel-nodes').classList.contains('active') &&
                dashboard.style.display !== 'none' && !modalOverlay.classList.contains('active')) refresh();
        }, 30000);
    }
    return { refresh, matches, statusLabel, managementAction };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = ProxyForgeManagedNodes;
