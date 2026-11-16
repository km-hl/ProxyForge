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

function formatAgentBytes(bytes) {
    const val = Number(bytes || 0);
    if (!val) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(val) / Math.log(1024)));
    return +(val / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

async function showAgentChain(agent) {
    const url = '/agents/' + agent.id + '/chain';
    let chain = (await (await fetchAuth(url)).json()).chain;
    const direct = (await (await fetchAuth('/agents/' + agent.id + '/deployment')).json()).deployment;
    const { landings } = await (await fetchAuth('/agents/deployments/landings')).json();
    openModal('入口 → SS2022 落地',
        '<p>在此入口新增独立 VLESS Reality 监听，保留原直连节点。每个入口支持一条附加链路，成功后生成第二个客户端节点。</p>' +
        '<label>链路名称（创建后固定）</label><input id="chain-name" maxlength="64">' +
        '<label>链路入口端口（不同于直连端口）</label><input id="chain-port" type="number" min="1" max="65535" value="8443">' +
        '<label>已部署的 SS2022 落地（创建后固定）</label><select id="chain-landing"></select>' +
        '<p>沿用入口公网地址和 SNI，自动生成独立凭据。关联期间如需修改入口或落地部署，先成功移除链路。应用会重启入口托管实例。</p>' +
        '<button class="btn" id="chain-apply">应用 / 重试</button> ' +
        '<button class="btn btn-danger" id="chain-remove">移除链路（保留直连）</button> ' +
        '<button class="btn" id="chain-refresh">刷新状态</button><pre id="chain-state" style="white-space:pre-wrap"></pre>', closeModal);
    const selector = document.getElementById('chain-landing');
    for (const landing of landings.filter(item => item.agent_id !== agent.id)) {
        const option = document.createElement('option');
        option.value = landing.agent_id; option.textContent = landing.name; selector.append(option);
    }
    if (chain && !landings.some(item => item.agent_id === chain.landing_agent_id)) {
        const option = document.createElement('option');
        option.value = chain.landing_agent_id; option.textContent = '原落地当前不可用（仍可移除链路）'; selector.append(option);
    }
    const status = document.getElementById('chain-state');
    const apply = document.getElementById('chain-apply'), remove = document.getElementById('chain-remove');
    function render(fill) {
        if (fill && chain) {
            document.getElementById('chain-name').value = chain.settings.name;
            document.getElementById('chain-port').value = chain.settings.listen_port;
            selector.value = chain.landing_agent_id;
        }
        selector.disabled = !!chain;
        document.getElementById('chain-name').readOnly = !!chain;
        const ready = direct && direct.protocol === 'vless-reality' && direct.action === 'deployment.apply' && direct.status === 'success';
        const busy = chain && ['pending', 'assigned', 'running'].includes(chain.status);
        const allowed = agentCanChain(agent) && ready && !busy;
        apply.disabled = !allowed || !landings.some(item => item.agent_id === selector.value);
        remove.disabled = !allowed || !chain;
        status.textContent = !agentCanChain(agent) ? '请升级此入口 Agent 和本地辅助服务以支持链路。' :
            !ready ? '请先成功部署此入口的 VLESS Reality 直连节点。' :
            chain ? '版本 ' + chain.revision + ' · ' + chain.action + ' · ' + chain.status + (chain.error ? '\n' + chain.error : '') :
            landings.length ? '选择已成功部署的落地。成功状态表示配置已应用，不代表公网端到端可达。' : '请先在另一台 Agent 成功部署 SS2022 落地。';
    }
    async function submit(removing) {
        if (!confirm(removing ? '确认移除链路监听并保留直连？' : '确认应用链路并重启入口托管实例？')) return;
        apply.disabled = true; remove.disabled = true;
        const settings = removing ? chain.settings : { name: document.getElementById('chain-name').value.trim(), listen_port: Number(document.getElementById('chain-port').value) };
        const data = { expected_revision: chain ? chain.revision : 0, landing_agent_id: selector.value, settings, remove: removing };
        const key = url + ':' + JSON.stringify(data);
        let requestId = pendingAgentJobRequests.get(key);
        if (!requestId) {
            requestId = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
            pendingAgentJobRequests.set(key, requestId);
        }
        try {
            chain = await (await fetchAuth(url, { method: 'PUT', body: JSON.stringify({ ...data, request_id: requestId }) })).json();
            pendingAgentJobRequests.delete(key); render(true);
        } catch (error) {
            render(false); status.textContent = error.message + '；可重试相同请求，版本冲突请刷新后操作。';
        }
    }
    apply.onclick = () => submit(false);
    remove.onclick = () => submit(true);
    selector.onchange = () => render(false);
    document.getElementById('chain-refresh').onclick = () => showAgentChain(agent).catch(error => { status.textContent = error.message; });
    render(true);
}

const LANDING_PROTO_META = {
    'vless-reality': { label: 'VLESS Reality 直连节点', defaultPort: 443, landing: false, tlsModes: ['reality'] },
    reality: { label: 'Reality 落地 / 直连 (新规格)', defaultPort: 443, landing: true, tlsModes: ['reality', 'acme_http', 'acme_dns'], canKeygen: true },
    ss2022: { label: 'Shadowsocks-2022 落地', defaultPort: 8388, landing: true, tlsModes: ['none'], canKeygen: true },
    trojan: { label: 'Trojan + TLS / Caddy 伪装', defaultPort: 443, landing: true, tlsModes: ['acme_http', 'acme_dns'] },
    'vless-ws': { label: 'VLESS + WebSocket (+ TLS/Caddy)', defaultPort: 443, landing: true, tlsModes: ['none', 'acme_http', 'acme_dns'] },
    hysteria2: { label: 'Hysteria2 + ACME/混淆', defaultPort: 443, landing: true, tlsModes: ['acme_http', 'acme_dns'] },
};

async function showAgentDeployment(agent) {
    const url = '/agents/' + agent.id + '/deployment';
    let deployment = (await fetchAgentJson(url)).deployment;
    let generatedKeyRef = null;
    openModal('节点 / 落地部署',
        '<p>每台 Agent 当前支持一种部署，创建后不能切换协议。支持 VLESS-Reality、SS2022、Trojan、VLESS-WS 与 Hysteria2 及 ACME / Caddy 伪装编排。</p>' +
        '<label>部署类型</label><select id="deployment-protocol">' +
        '<option value="vless-reality">VLESS Reality 直连节点</option>' +
        '<option value="reality">Reality 落地 / 直连 (Node-Pilot 规格)</option>' +
        '<option value="ss2022">SS2022 落地</option>' +
        '<option value="trojan">Trojan + TLS/Caddy</option>' +
        '<option value="vless-ws">VLESS-WS + TLS/Caddy</option>' +
        '<option value="hysteria2">Hysteria2</option></select>' +
        '<p id="deployment-help" class="hint"></p>' +
        '<div class="form-grid">' +
        '<div class="form-group"><label>名称（创建后固定）</label><input id="deployment-name" maxlength="64"></div>' +
        '<div class="form-group"><label>公网 IP / 域名</label><input id="deployment-server" placeholder="vps.example.com"></div>' +
        '<div class="form-group"><label>监听端口</label><input id="deployment-port" type="number" min="1" max="65535" value="443"></div>' +
        '</div>' +
        '<div id="deployment-vless-reality-fields"><label>Reality 握手域名 / SNI</label><input id="deployment-sni" placeholder="支持 TLS 1.3 的目标域名"></div>' +
        '<div id="deployment-tls-section" hidden><div class="form-grid">' +
        '<div class="form-group"><label>TLS 模式</label><select id="deployment-tls-mode"></select></div>' +
        '<div class="form-group"><label>域名 / SNI</label><input id="deployment-domain" placeholder="node.example.com"></div>' +
        '<div class="form-group full-width"><label>伪装回落站点 URL (可选，需 https://)</label><input id="deployment-camouflage" placeholder="https://www.apple.com"></div>' +
        '</div></div>' +
        '<div id="deployment-reality-ext-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>客户端指纹</label><select id="deployment-fingerprint"><option value="chrome">chrome</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="edge">edge</option><option value="ios">ios</option><option value="android">android</option><option value="random">random</option></select></div>' +
        '<div class="form-group"><label>Reality Public Key</label><input id="deployment-reality-pubkey" placeholder="可点击下方按钮由服务端生成"></div>' +
        '<div class="form-group full-width"><label>Short IDs (逗号分隔 hex)</label><input id="deployment-reality-shortids" placeholder="留空自动生成或填写如 a1b2c3d4"></div>' +
        '</div></div>' +
        '<div id="deployment-ss2022-fields" hidden><label>SS2022 加密套件</label><select id="deployment-ss2022-method"><option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option><option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option></select></div>' +
        '<div id="deployment-ws-fields" hidden><label>WebSocket Path</label><input id="deployment-ws-path" value="/ws" placeholder="/ws"></div>' +
        '<div id="deployment-hy2-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>上行限速 Mbps (可选)</label><input id="deployment-hy2-up" type="number" min="1" max="100000"></div>' +
        '<div class="form-group"><label>下行限速 Mbps (可选)</label><input id="deployment-hy2-down" type="number" min="1" max="100000"></div>' +
        '<div class="form-group"><label>混淆</label><select id="deployment-hy2-obfs"><option value="none">none</option><option value="salamander">salamander</option></select></div>' +
        '</div></div>' +
        '<div id="deployment-acme-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>ACME 联系邮箱 (可选)</label><input id="deployment-acme-email" type="email" placeholder="admin@example.com"></div>' +
        '</div></div>' +
        '<div id="deployment-dns-fields" hidden><div class="form-grid">' +
        '<div class="form-group"><label>DNS 服务商</label><select id="deployment-dns-provider"><option value="cloudflare">cloudflare</option><option value="alidns">alidns</option><option value="dnspod">dnspod</option></select></div>' +
        '<div class="form-group"><label>DNS Zone ID (Cloudflare 需 32 位 hex)</label><input id="deployment-dns-zone" placeholder="0123456789abcdef0123456789abcdef"></div>' +
        '<div class="form-group"><label>DNS 传播等待秒数</label><input id="deployment-dns-prop" type="number" min="10" max="600" value="60"></div>' +
        '<div class="form-group"><label>DNS API Token (仅写入不回显)</label><input id="deployment-dns-token" type="password" autocomplete="off" placeholder="留空表示保持原有凭据或无"></div>' +
        '</div></div>' +
        '<div style="margin:8px 0;"><button type="button" class="btn btn-sm" id="deployment-keygen-btn" hidden>🔑 服务端生成密钥对</button> <span id="deployment-keyref-status" class="hint"></span></div>' +
        '<p class="hint">应用会重启该托管实例，可能中断连接；失败或取消后请重新应用以核实状态。</p>' +
        '<button type="button" class="btn btn-primary" id="deployment-apply">应用 / 重试</button> ' +
        '<button type="button" class="btn btn-danger" id="deployment-remove">移除监听</button> ' +
        '<button type="button" class="btn" id="deployment-refresh">刷新状态</button><pre id="deployment-state" style="white-space:pre-wrap; margin-top:8px;"></pre>', closeModal);

    const status = document.getElementById('deployment-state');
    const apply = document.getElementById('deployment-apply');
    const remove = document.getElementById('deployment-remove');
    const protocol = document.getElementById('deployment-protocol');
    const tlsModeEl = document.getElementById('deployment-tls-mode');
    const keygenBtn = document.getElementById('deployment-keygen-btn');
    const keyrefStatus = document.getElementById('deployment-keyref-status');

    function syncTlsOptions(proto, preferred) {
        const meta = LANDING_PROTO_META[proto] || LANDING_PROTO_META['vless-reality'];
        tlsModeEl.replaceChildren();
        for (const mode of meta.tlsModes) {
            const opt = document.createElement('option');
            opt.value = mode;
            opt.textContent = mode;
            tlsModeEl.append(opt);
        }
        if (preferred && meta.tlsModes.includes(preferred)) tlsModeEl.value = preferred;
        else tlsModeEl.value = meta.tlsModes[0];
    }

    function render(fill) {
        if (fill && deployment) {
            const p = deployment.protocol || 'vless-reality';
            protocol.value = LANDING_PROTO_META[p] ? p : 'vless-reality';
            const s = deployment.settings || {};
            syncTlsOptions(protocol.value, s.tls_mode);
            document.getElementById('deployment-name').value = s.name ?? '';
            document.getElementById('deployment-server').value = s.server ?? '';
            document.getElementById('deployment-port').value = s.listen_port ?? 443;
            document.getElementById('deployment-sni').value = s.server_name ?? '';
            document.getElementById('deployment-domain').value = s.domain ?? '';
            document.getElementById('deployment-camouflage').value = s.camouflage_url ?? '';
            document.getElementById('deployment-fingerprint').value = s.fingerprint ?? 'chrome';
            document.getElementById('deployment-reality-pubkey').value = s.reality_public_key ?? '';
            document.getElementById('deployment-reality-shortids').value = Array.isArray(s.reality_short_ids) ? s.reality_short_ids.join(', ') : '';
            document.getElementById('deployment-ss2022-method').value = s.method ?? '2022-blake3-aes-256-gcm';
            document.getElementById('deployment-ws-path').value = s.ws_path ?? '/ws';
            document.getElementById('deployment-hy2-up').value = s.up_mbps ?? '';
            document.getElementById('deployment-hy2-down').value = s.down_mbps ?? '';
            document.getElementById('deployment-hy2-obfs').value = s.obfs ?? 'none';
            document.getElementById('deployment-acme-email').value = s.acme_email ?? '';
            document.getElementById('deployment-dns-provider').value = s.dns_provider ?? 'cloudflare';
            document.getElementById('deployment-dns-zone').value = s.dns_zone_id ?? '';
            document.getElementById('deployment-dns-prop').value = s.dns_propagation_seconds ?? 60;
        }
        const proto = protocol.value;
        const meta = LANDING_PROTO_META[proto] || LANDING_PROTO_META['vless-reality'];
        protocol.disabled = !!deployment;
        const tlsMode = tlsModeEl.value || meta.tlsModes[0];
        document.getElementById('deployment-vless-reality-fields').hidden = proto !== 'vless-reality';
        document.getElementById('deployment-tls-section').hidden = proto === 'vless-reality';
        document.getElementById('deployment-reality-ext-fields').hidden = proto !== 'reality';
        document.getElementById('deployment-ss2022-fields').hidden = proto !== 'ss2022';
        document.getElementById('deployment-ws-fields').hidden = proto !== 'vless-ws';
        document.getElementById('deployment-hy2-fields').hidden = proto !== 'hysteria2';
        const usesAcme = proto !== 'vless-reality' && (tlsMode === 'acme_http' || tlsMode === 'acme_dns');
        document.getElementById('deployment-acme-fields').hidden = !usesAcme;
        document.getElementById('deployment-dns-fields').hidden = proto === 'vless-reality' || tlsMode !== 'acme_dns';
        keygenBtn.hidden = !meta.canKeygen || !!deployment;
        keyrefStatus.textContent = generatedKeyRef ? '已生成服务端密钥引用，提交部署时将自动注入（私钥不落地浏览器）。' : '';
        document.getElementById('deployment-help').textContent = proto === 'ss2022'
            ? 'SS2022 落地自动保管密钥，不直接暴露到订阅；部署成功后可在“链路”或 go-gost 转发中关联。'
            : proto === 'vless-reality'
                ? '经典 Phase 0 直连部署，自动生成只读客户端节点。'
                : '支持 Caddy 自动伪装回落与 ACME 自动申请/续期 TLS 证书；部署成功后投影至客户端订阅。';
        const capable = meta.landing ? agentCanLand(agent) : agentCanDeploy(agent);
        document.getElementById('deployment-name').readOnly = !!deployment;
        const busy = deployment && ['pending', 'assigned', 'running'].includes(deployment.status);
        apply.disabled = !capable || !!busy;
        remove.disabled = apply.disabled || !deployment;
        status.textContent = !capable ? '请升级 Agent 和本地运行环境辅助服务以支持所选部署。' :
            deployment ? '版本 ' + deployment.revision + ' · ' + deployment.action + ' · ' + deployment.status +
                (deployment.error ? '\n' + deployment.error : '') : '尚未创建部署。';
    }

    async function refresh() {
        generatedKeyRef = null;
        deployment = (await fetchAgentJson(url)).deployment;
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
        const base = {
            name: document.getElementById('deployment-name').value.trim(),
            server: document.getElementById('deployment-server').value.trim(),
            listen_port: Number(document.getElementById('deployment-port').value),
        };
        if (proto === 'vless-reality') {
            base.server_name = document.getElementById('deployment-sni').value.trim();
            return { settings: base, secrets: null };
        }
        const tlsMode = tlsModeEl.value;
        const settings = { ...base, protocol: proto, tls_mode: tlsMode };
        const domain = document.getElementById('deployment-domain').value.trim();
        const cam = document.getElementById('deployment-camouflage').value.trim();
        if (domain) settings.domain = domain;
        if (cam) settings.camouflage_url = cam;
        if (proto === 'ss2022') settings.method = document.getElementById('deployment-ss2022-method').value;
        if (proto === 'reality') {
            settings.fingerprint = document.getElementById('deployment-fingerprint').value;
            const pub = document.getElementById('deployment-reality-pubkey').value.trim();
            const sids = document.getElementById('deployment-reality-shortids').value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
            if (pub) settings.reality_public_key = pub;
            if (sids.length) settings.reality_short_ids = sids;
        }
        if (proto === 'vless-ws') {
            const wp = document.getElementById('deployment-ws-path').value.trim();
            if (wp) settings.ws_path = wp;
        }
        if (proto === 'hysteria2') {
            const up = Number(document.getElementById('deployment-hy2-up').value);
            const down = Number(document.getElementById('deployment-hy2-down').value);
            if (up > 0) settings.up_mbps = Math.round(up);
            if (down > 0) settings.down_mbps = Math.round(down);
            settings.obfs = document.getElementById('deployment-hy2-obfs').value;
        }
        let secrets = null;
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
            if (tok) secrets = { dns_api_token: tok };
        }
        return { settings, secrets };
    }

    async function submit(removing) {
        if (!confirm(removing ? '确认移除该托管实例的公网监听？' : '确认应用配置并重启该托管实例？')) return;
        apply.disabled = true; remove.disabled = true;
        const built = removing ? { settings: deployment.settings, secrets: null } : buildPayloadSettings();
        const data = { expected_revision: deployment ? deployment.revision : 0, settings: built.settings, remove: removing, protocol: protocol.value };
        if (!removing && built.secrets) data.secrets = built.secrets;
        if (!removing && generatedKeyRef) data.key_ref = generatedKeyRef;
        const key = url + ':' + JSON.stringify({ expected_revision: data.expected_revision, protocol: data.protocol, remove: removing, settings: data.settings, key_ref: generatedKeyRef || '' });
        let requestId = pendingAgentJobRequests.get(key);
        if (!requestId) {
            requestId = randomRequestId();
            pendingAgentJobRequests.set(key, requestId);
        }
        try {
            deployment = await fetchAgentJson(url, { method: 'PUT', body: JSON.stringify({ ...data, request_id: requestId }) });
            const tokField = document.getElementById('deployment-dns-token');
            if (tokField) tokField.value = '';
            generatedKeyRef = null;
            pendingAgentJobRequests.delete(key);
            render(true);
        } catch (error) {
            render(false);
            status.textContent = error.message + '；可重试相同请求。若版本冲突，请刷新后再操作。';
        }
    }
    apply.onclick = () => submit(false);
    remove.onclick = () => submit(true);
    protocol.onchange = () => {
        if (!deployment) {
            const meta = LANDING_PROTO_META[protocol.value] || LANDING_PROTO_META['vless-reality'];
            document.getElementById('deployment-port').value = String(meta.defaultPort);
            syncTlsOptions(protocol.value);
            generatedKeyRef = null;
        }
        render(false);
    };
    tlsModeEl.onchange = () => render(false);
    document.getElementById('deployment-refresh').onclick = () => refresh().catch(error => { status.textContent = error.message; });
    syncTlsOptions(deployment?.protocol || protocol.value, deployment?.settings?.tls_mode);
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
    openModal('存量节点接管 · ' + agent.name,
        '<p class="hint">扫描目标主机已运行的 sing-box / xray / caddy 服务，解析端口、协议、TLS 与 SNI 并注册到控制台资产视图。</p>' +
        '<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px;">' +
        '<button type="button" class="btn btn-primary btn-sm" id="adopt-scan-trigger">🔍 一键接管扫描 (adopt_scan)</button>' +
        '<button type="button" class="btn btn-sm" id="adopt-scan-refresh">刷新扫描结果</button></div>' +
        '<p id="adopt-scan-status" class="hint"></p><div id="adopt-scan-list"></div>', closeModal);
    const statusEl = document.getElementById('adopt-scan-status');
    const listEl = document.getElementById('adopt-scan-list');
    const triggerBtn = document.getElementById('adopt-scan-trigger');
    triggerBtn.disabled = !agentCanRunJobs(agent);

    async function loadAdoptions() {
        const { adoptions } = await fetchAgentJson('/agents/' + agent.id + '/adoptions');
        listEl.replaceChildren();
        if (!adoptions || !adoptions.length) {
            listEl.textContent = '暂无接管扫描记录，点击上方「一键接管扫描」下发探测任务。';
            return;
        }
        for (const item of adoptions) {
            const card = document.createElement('div');
            card.className = 'sub-user-card';
            card.style.marginBottom = '8px';
            const title = document.createElement('strong');
            title.textContent = `[${item.core}] ${item.tag || item.service_name} (${item.protocol} :${item.listen_port})`;
            const meta = document.createElement('div');
            meta.className = 'hint';
            meta.textContent = `监听: ${item.listen}:${item.listen_port} · TLS: ${item.tls_mode || 'none'}` +
                (item.sni ? ` · SNI: ${item.sni}` : '') + (item.ws_path ? ` · WS: ${item.ws_path}` : '') +
                ` · ${item.adoptable ? '可接管' : '仅观测'}`;
            const cfg = document.createElement('div');
            cfg.className = 'hint';
            cfg.textContent = `配置: ${item.config_path}`;
            card.append(title, meta, cfg);
            listEl.append(card);
        }
    }

    triggerBtn.onclick = async () => {
        try {
            triggerBtn.disabled = true;
            await fetchAgentJson('/agents/' + agent.id + '/adopt-scan', {
                method: 'POST', body: JSON.stringify({ request_id: randomRequestId() })
            });
            statusEl.textContent = '已下发存量扫描任务，等待 Agent 上报后点击「刷新扫描结果」。';
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

async function showGlobalTunnelsModal() {
    openModal('多跳隧道链 & 全网流量总览',
        '<div id="global-traffic-box" style="margin-bottom:12px;">正在统计全网流量…</div>' +
        '<h4 style="margin:8px 0 4px;">已配置的 go-gost 多跳隧道链</h4><div id="global-chains-list"></div>' +
        '<details style="margin-top:10px;"><summary>➕ 创建多跳隧道链</summary><div class="form-grid" style="margin-top:8px;">' +
        '<div class="form-group"><label>隧道名称</label><input id="tunnel-name" placeholder="hk-sg-jp"></div>' +
        '<div class="form-group"><label>入口 Agent</label><select id="tunnel-entry-agent"></select></div>' +
        '<div class="form-group"><label>中继托管 Agent (可选第一跳)</label><select id="tunnel-relay-agent"><option value="">无托管中继 (单跳直出)</option></select></div>' +
        '<div class="form-group"><label>中继节点公网 addr (host:port)</label><input id="tunnel-relay-addr" placeholder="relay.example.com:8443"></div>' +
        '<div class="form-group"><label>中继认证用户名</label><input id="tunnel-relay-user" value="relay"></div>' +
        '<div class="form-group"><label>中继认证密码 (仅写入)</label><input id="tunnel-relay-pass" type="password" autocomplete="off"></div>' +
        '<div class="form-group full-width"><label>最终出站目标 addr (可选最后一跳 host:port)</label><input id="tunnel-final-addr" placeholder="exit.example.com:9443"></div>' +
        '</div><button type="button" class="btn btn-primary btn-sm" id="tunnel-create-btn">创建隧道链</button></details>' +
        '<p id="global-tunnels-notice" class="hint" style="margin-top:8px;"></p>', closeModal);

    const notice = document.getElementById('global-tunnels-notice');
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

        const agents = agentData.agents || [];
        const entrySel = document.getElementById('tunnel-entry-agent');
        const relaySel = document.getElementById('tunnel-relay-agent');
        entrySel.replaceChildren(); relaySel.replaceChildren();
        const rNone = document.createElement('option'); rNone.value = ''; rNone.textContent = '无托管中继'; relaySel.append(rNone);
        for (const a of agents) {
            const o1 = document.createElement('option'); o1.value = a.id; o1.textContent = a.name; entrySel.append(o1);
            const o2 = document.createElement('option'); o2.value = a.id; o2.textContent = a.name; relaySel.append(o2);
        }

        const chainsEl = document.getElementById('global-chains-list');
        chainsEl.replaceChildren();
        const chains = chainData.chains || [];
        if (!chains.length) {
            chainsEl.textContent = '暂无隧道链。';
        } else {
            for (const c of chains) {
                const card = document.createElement('div'); card.className = 'sub-user-card'; card.style.marginBottom = '8px';
                const entryName = agents.find(a => a.id === c.entry_agent_id)?.name || c.entry_agent_id;
                const title = document.createElement('strong');
                title.textContent = `${c.name} · 入口: ${entryName} · 版本 ${c.revision}`;
                const desc = document.createElement('div'); desc.className = 'hint';
                desc.textContent = '跳数: ' + (c.hops || []).map(h => h.name).join(' -> ');
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
            const hops = [];
            const relayAgentId = document.getElementById('tunnel-relay-agent').value;
            const relayAddr = document.getElementById('tunnel-relay-addr').value.trim();
            if (relayAddr) {
                const node = { name: 'relay_hop', addr: relayAddr, connector: 'relay', dialer: 'tls' };
                const u = document.getElementById('tunnel-relay-user').value.trim();
                const p = document.getElementById('tunnel-relay-pass').value;
                if (u) node.username = u;
                if (p) node.password = p;
                if (relayAgentId) { node.agent_id = relayAgentId; node.serve_on_agent = true; }
                hops.push({ name: 'hop_relay', nodes: [node] });
            }
            const finalAddr = document.getElementById('tunnel-final-addr').value.trim();
            if (finalAddr) {
                hops.push({ name: 'hop_exit', nodes: [{ name: 'final_exit', addr: finalAddr, connector: 'relay', dialer: 'tls' }] });
            }
            await fetchAgentJson('/agents/tunnels/chains', {
                method: 'POST',
                body: JSON.stringify({
                    request_id: randomRequestId(),
                    name: document.getElementById('tunnel-name').value.trim(),
                    entry_agent_id: document.getElementById('tunnel-entry-agent').value,
                    hops,
                }),
            });
            const passEl = document.getElementById('tunnel-relay-pass');
            if (passEl) passEl.value = '';
            notice.textContent = '隧道链已创建。';
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

async function refreshAgents() {
    const target = document.getElementById('agent-list');
    try {
        const { agents } = await (await fetchAuth('/agents')).json();
        target.replaceChildren();
        if (!agents.length) { target.textContent = '尚无 Agent。点击「添加服务器」获取安装命令，在目标机器执行。'; return; }
        const table = document.createElement('table'); table.className = 'agent-table';
        const headings = document.createElement('tr');
        const labels = ['名称 / 主机', '连接来源 IP', '系统 / 架构', 'Agent / 运行时', '状态 / 角色', '最后在线', '操作'];
        for (const name of labels) {
            const cell = document.createElement('th'); cell.textContent = name; cell.setAttribute('scope', 'col'); headings.append(cell);
        }
        const head = document.createElement('thead'); head.append(headings); table.append(head);
        const body = document.createElement('tbody'); table.append(body);
        for (const agent of agents) {
            const row = document.createElement('tr');
            const m = agent.metadata;
            for (const value of [agent.name + ' / ' + m.hostname, agent.observed_ip,
                m.os + ' ' + m.os_version + ' / ' + m.arch,
                agentRuntimeSummary(m),
                agentStatusLabel(agent) + ' / ' + agent.role,
                agent.last_seen ? new Date(agent.last_seen * 1000).toLocaleString() : '—']) {
                const cell = document.createElement('td'); cell.textContent = value; cell.setAttribute('data-label', labels[row.children.length]); row.append(cell);
            }
            const actions = document.createElement('td');
            actions.setAttribute('data-label', labels[6]);
            for (const [label, action] of [['详情', 'details'], ['任务', 'jobs'], ['部署', 'deployment'], ['链路', 'chain'], ['转发', 'forwards'], ['接管', 'adoptions'], ['编辑', 'edit'], ['撤销', 'revoke'], ['移除', 'remove']]) {
                const button = document.createElement('button'); button.textContent = label; button.className = 'btn';
                button.onclick = () => agentAction(agent, action).catch(error => showToast(error.message, 'error'));
                actions.append(button);
            }
            row.append(actions); body.append(row);
        }
        target.append(table);
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

async function addAgent() {
    let busy = false, issued = false;
    openModal('添加服务器',
        '<p>1. 核对 Controller 地址，在目标 VPS 执行安装命令。</p>' +
        '<p>要求：Debian 12/13 或 Ubuntu 22.04/24.04，amd64/arm64，systemd、Python 3.9+、sudo 和可信 CA。已有安装请按恢复指南操作。</p>' +
        '<p id="agent-install-status">正在读取安装信息…</p><div id="agent-install-commands"></div>' +
        '<p><a href="https://github.com/km-hl/ProxyForge/blob/master/docs/AGENT_INSTALL.md" target="_blank" rel="noopener noreferrer">中文安装、升级与恢复指南</a></p>' +
        '<p>2. 终端提示隐藏输入凭据后，填写名称并点击「生成注册凭据」。凭据仅有效 10 分钟。</p>' +
        '<label for="new-agent-name">服务器名称</label><input id="new-agent-name" maxlength="128" autocomplete="off">' +
        '<div id="agent-registration-result" hidden><p>3. 将以下凭据粘贴到终端的隐藏输入提示中。不要放入命令或 URL。</p>' +
        '<input id="agent-registration-token" aria-label="一次性注册凭据" readonly autocomplete="off">' +
        '<p id="agent-registration-expiry"></p>' +
        '<p>关闭后不再显示。安装结束后关闭此窗口并刷新服务器列表，确认状态为在线。注册响应丢失时，检查并移除孤儿 Agent，再生成新凭据恢复。</p></div>', async () => {
            if (!current() || busy) return;
            if (issued) { closeModal(); return; }
            if (!name.value.trim()) { showToast('请填写服务器名称', 'error'); name.focus(); return; }
            busy = true; modalConfirm.disabled = true;
            try {
                const registration = await (await fetchAuth('/agents/registration-tokens', {
                    method: 'POST', body: JSON.stringify({ name: name.value.trim() })
                })).json();
                if (!current()) return;
                document.getElementById('agent-registration-token').value = registration.registration_token;
                document.getElementById('agent-registration-expiry').textContent =
                    '有效期至 ' + new Date(registration.expires_at * 1000).toLocaleString() + '；只能成功注册一次。';
                document.getElementById('agent-registration-result').hidden = false;
                name.readOnly = true; issued = true; modalConfirm.textContent = '关闭';
            } catch (error) {
                if (current()) showToast(error.message, 'error');
            } finally {
                busy = false;
                if (current()) modalConfirm.disabled = false;
            }
        });
    const name = document.getElementById('new-agent-name');
    const current = () => name.isConnected && modalOverlay.classList.contains('active');
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
            '；源码提交：' + info.source_commit + '；Bootstrap：' + info.bootstrap_commit +
            '；SHA256：' + info.bootstrap_sha256;
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
    for (const id of ['agent-registration-token', 'deployment-dns-token', 'tunnel-relay-pass']) {
        const field = document.getElementById(id);
        if (field) field.value = '';
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
if (typeof module !== 'undefined' && module.exports) module.exports = { agentStatusLabel, agentCanRunJobs, agentCanManageRuntime, agentCanDeploy, agentCanLand, agentCanChain, agentCanGost };
