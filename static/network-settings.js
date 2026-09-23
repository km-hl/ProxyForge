(function (root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.ProxyForgeNetwork = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
    const mapping = value => value !== null && typeof value === 'object' && !Array.isArray(value) &&
        [Object.prototype, null].includes(Object.getPrototypeOf(value));
    const clone = value => structuredClone(value);
    const put = (obj, key, value) => Object.defineProperty(obj, key, { value, enumerable: true, configurable: true, writable: true });
    const UDP = ['any:53', 'udp://any:53', '0.0.0.0:53', 'udp://0.0.0.0:53'];
    const TCP = ['tcp://any:53', 'tcp://0.0.0.0:53'];
    const DEFAULT_HIJACK = ['0.0.0.0:53'];
    const LISTS = {
        nameserver: '默认解析 DNS', 'default-nameserver': 'Bootstrap DNS',
        'proxy-server-nameserver': '代理节点域名 DNS', 'direct-nameserver': 'Direct Nameserver',
    };
    // Only explicitly listed provider/protocol pairs are generated.
    const PROVIDERS = {
        Cloudflare: { DoH: 'https://1.1.1.1/dns-query', DoT: 'tls://1.1.1.1', UDP: '1.1.1.1', TCP: 'tcp://1.1.1.1' },
        Google: { DoH: 'https://8.8.8.8/dns-query', DoT: 'tls://8.8.8.8', UDP: '8.8.8.8', TCP: 'tcp://8.8.8.8' },
        AliDNS: { DoH: 'https://dns.alidns.com/dns-query', UDP: '223.5.5.5' },
        DNSPod: { DoH: 'https://doh.pub/dns-query', UDP: '119.29.29.29' },
        Quad9: { DoH: 'https://dns.quad9.net/dns-query', DoT: 'tls://dns.quad9.net', UDP: '9.9.9.9' },
        AdGuard: { DoH: 'https://dns.adguard-dns.com/dns-query', DoT: 'tls://dns.adguard-dns.com', UDP: '94.140.14.14' },
    };
    const RECOMMENDED = {
        'geosite:cn': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
        'geosite:geolocation-!cn': ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
    };
    function section(config, name) {
        if (!mapping(config)) throw new Error('模板根节点必须是对象，请先修复底层配置');
        if (!own(config, name)) put(config, name, {});
        if (!mapping(config[name])) throw new Error(`${name} 不是对象，请在底层配置中修复后编辑`);
        // YAML aliases may share a block with another top-level field. Detach
        // the edited block so changing DNS never changes an alias elsewhere.
        put(config, name, clone(config[name]));
        return config[name];
    }
    function setField(config, name, key, value) {
        const result = clone(config);
        if (value === undefined && !own(result, name)) return result;
        const block = section(result, name);
        if (value === undefined) delete block[key]; else put(block, key, clone(value));
        return result;
    }
    function editList(config, name, key, index, value) {
        const result = clone(config), block = section(result, name);
        const items = own(block, key) && block[key] !== null ? clone(block[key]) : [];
        if (!Array.isArray(items)) throw new Error('现有字段不是列表，请先在底层配置中修复');
        if (index < 0) items.push(value);
        else if (value === undefined) items.splice(index, 1);
        else items[index] = value;
        put(block, key, items);
        return result;
    }
    function hijackState(values) {
        values = values === undefined ? DEFAULT_HIJACK : Array.isArray(values) ? values : [];
        return { udp: values.some(v => UDP.includes(v)), tcp: values.some(v => TCP.includes(v)) };
    }
    function setHijack(config, protocol, enabled) {
        const raw = config.tun && config.tun['dns-hijack'];
        if (raw != null && !Array.isArray(raw)) throw new Error('dns-hijack 必须是列表');
        let values = clone(raw === undefined ? DEFAULT_HIJACK : raw || []);
        const forms = protocol === 'udp' ? UDP : TCP;
        if (enabled && !values.some(v => forms.includes(v))) values.push(forms[0]);
        if (!enabled) values = values.filter(v => !forms.includes(v));
        return setField(config, 'tun', 'dns-hijack', values);
    }
    function applyPreset(config, name) {
        if (!['compatible', 'protect', 'strict'].includes(name)) throw new Error('未知预设');
        let result = clone(config);
        if (name === 'compatible') return own(result, 'tun') ? setField(result, 'tun', 'enable', false) : result;
        const dns = section(result, 'dns'), tun = section(result, 'tun');
        const values = { enable: true, ipv6: false, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
            'default-nameserver': ['223.5.5.5', '1.1.1.1'],
            nameserver: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
            'proxy-server-nameserver': ['https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query'] };
        Object.entries(values).forEach(([key, value]) => put(dns, key, value));
        Object.entries({ enable: true, stack: 'mixed', 'auto-route': true, 'auto-detect-interface': true })
            .forEach(([key, value]) => put(tun, key, value));
        if (name === 'strict') put(tun, 'strict-route', true);
        if (!own(tun, 'dns-hijack')) put(tun, 'dns-hijack', []);
        result = setHijack(setHijack(result, 'udp', true), 'tcp', true);
        return result;
    }
    function editPolicy(config, oldKey, key, addresses) {
        const result = clone(config), dns = section(result, 'dns');
        const policies = own(dns, 'nameserver-policy') ? dns['nameserver-policy'] : {};
        if (!mapping(policies)) throw new Error('策略不是对象，请先修复底层配置');
        if (key !== null && key !== oldKey && own(policies, key)) throw new Error('匹配规则已存在，不能覆盖');
        const next = {};
        for (const [name, value] of Object.entries(policies)) {
            if (name === oldKey) { if (key !== null) put(next, key, addresses); }
            else put(next, name, value);
        }
        if (oldKey === null) put(next, key, addresses);
        put(dns, 'nameserver-policy', next);
        return result;
    }
    function recommendPolicies(config) {
        const result = clone(config), dns = section(result, 'dns');
        if (!own(dns, 'nameserver-policy')) put(dns, 'nameserver-policy', {});
        if (!mapping(dns['nameserver-policy'])) throw new Error('策略不是对象，请先修复底层配置');
        put(dns, 'nameserver-policy', clone(dns['nameserver-policy']));
        for (const [key, value] of Object.entries(RECOMMENDED)) {
            if (!own(dns['nameserver-policy'], key)) put(dns['nameserver-policy'], key, clone(value));
        }
        return result;
    }
    function protocol(address) {
        const prefix = String(address).split('://')[0];
        return ({ https: 'DoH', tls: 'DoT', quic: 'DoQ', udp: 'UDP', tcp: 'TCP' })[prefix] ||
            (/^[\d.[\]:]+$/.test(String(address)) ? 'UDP' : '自定义');
    }
    function provider(address) {
        return Object.keys(PROVIDERS).find(name => Object.values(PROVIDERS[name]).includes(address)) || '自定义';
    }
    function providerOptions(name, bootstrap = false) {
        return Object.fromEntries(Object.entries(PROVIDERS[name] || {}).filter(([, address]) => {
            if (!bootstrap) return true;
            const host = new URL(address.includes('://') ? address : `udp://${address}`).hostname;
            return /^[\d.]+$/.test(host) || host.startsWith('[');
        }));
    }
    function changes(before, after) {
        const result = [];
        for (const name of ['dns', 'tun']) {
            const a = before[name] || {}, b = after[name] || {};
            for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
                if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) result.push({ path: `${name}.${key}`, before: a[key], after: b[key] });
            }
        }
        return result;
    }

    let hooks, container, draft, saved, dirty = false, revision = 0, overviewRevision = 0;
    let report = null, timer, saving = false;
    const escape = value => hooks.escape(value);
    const dump = value => hooks.dump(value);
    function button(label, action, extra = '') {
        return `<button type="button" class="btn btn-sm" data-action="${action}" ${extra}>${label}</button>`;
    }
    function field(name, key, label, options) {
        const block = mapping(draft[name]) ? draft[name] : {};
        const value = own(block, key) ? block[key] : undefined;
        const invalid = value !== undefined && value !== null && !options.some(([v]) => v === String(value));
        return `<div class="form-group"><label for="net-${name}-${key}">${label}</label><select id="net-${name}-${key}" data-section="${name}" data-field="${key}">
            <option value="" ${value === undefined ? 'selected' : ''}>未设置 · 内核默认</option>
            ${value === null || invalid ? `<option value="__preserve" selected>保留原值：${escape(JSON.stringify(value))}</option>` : ''}
            ${options.map(([v, text]) => `<option value="${v}" ${String(value) === v ? 'selected' : ''}>${text}</option>`).join('')}</select></div>`;
    }
    const BOOL = [['true', '开启'], ['false', '关闭']];
    function rows(name, key, title, hint = '') {
        const block = mapping(draft[name]) ? draft[name] : {}, values = block[key];
        const malformed = values != null && !Array.isArray(values);
        return `<div class="network-list"><h3>${title}</h3><p class="hint">${hint}</p>
            ${values === undefined ? '<p class="hint">未显式设置，使用内核默认或其他 DNS 配置。</p>' : ''}
            ${malformed ? '<p class="network-status error">字段不是列表，请在底层配置中修复。</p>' : ''}
            ${(Array.isArray(values) ? values : []).map((value, index) => `<div class="network-row"><span class="network-address">${escape(value)}</span>
                ${own(LISTS, key) ? `<span class="type-badge">${escape(provider(value))} · ${escape(protocol(value))}</span>` : ''}
                ${button('编辑', 'edit-list', `data-section="${name}" data-key="${key}" data-index="${index}"`)}
                ${button('删除', 'delete-list', `data-section="${name}" data-key="${key}" data-index="${index}"`)}</div>`).join('')}
            ${button('+ 添加', 'edit-list', `data-section="${name}" data-key="${key}" data-index="-1" ${malformed ? 'disabled' : ''}`)}
            ${button('恢复未设置', 'unset', `data-section="${name}" data-key="${key}"`)}</div>`;
    }
    function statusText(value) {
        if (!value) return '尚未检查';
        if (value.errors.length) return `存在 ${value.errors.length} 项配置错误，无法保存`;
        if (value.warnings.length) return `当前模板有 ${value.warnings.length} 项配置建议`;
        if (value.status === 'neutral') return '未启用网络配置或高级字段尚未完整验证';
        return '在本次静态检查范围内未发现配置问题';
    }
    function diagnostics(target, value, failure) {
        if (!target) return;
        target.replaceChildren();
        const status = document.createElement('p');
        status.className = `network-status ${failure ? 'neutral' : value?.status || 'neutral'}`;
        status.textContent = failure || statusText(value);
        target.append(status);
        if (!value) return;
        for (const level of ['errors', 'warnings', 'info']) {
            const list = document.createElement('ul');
            list.className = `network-diagnostics ${level}`;
            for (const item of value[level]) {
                const li = document.createElement('li');
                li.textContent = `${item.path ? item.path + '：' : ''}${item.message}`;
                list.append(li);
            }
            if (list.childElementCount) target.append(list);
        }
        const details = document.createElement('details'), title = document.createElement('summary');
        title.textContent = 'DNS 加密地址统计与默认值'; details.append(title);
        for (const [key, counts] of Object.entries(value.encryption || {})) {
            const p = document.createElement('p');
            p.textContent = `${LISTS[key] || key}：${counts.encrypted}/${counts.total} 个加密地址（配置统计）`;
            details.append(p);
        }
        const note = document.createElement('p');
        note.className = 'hint';
        note.textContent = `静态校验基线：${value.baseline || '模板格式'}。采用默认值的字段：${(value.defaulted || []).join('、') || '无'}。未进行网络连通性或真实 DNS 泄露检测。`;
        details.append(note); target.append(details);
    }
    async function validate() {
        const id = ++revision;
        report = null;
        diagnostics(container.querySelector('#network-check'), null, '正在检查当前配置…');
        try {
            const value = await hooks.validate(dump(draft));
            if (id !== revision) return null;
            report = value;
            diagnostics(container.querySelector('#network-check'), report);
            return report;
        } catch (error) {
            if (id === revision) diagnostics(container.querySelector('#network-check'), null, `检查未完成：${error.message}`);
            return null;
        }
    }
    function scheduleValidation() {
        ++revision; report = null; clearTimeout(timer);
        timer = setTimeout(validate, 200);
    }
    function update(next) {
        draft = next; dirty = dump(draft) !== dump(saved);
        report = null; draw(); scheduleValidation(); hooks.onDirty?.(dirty);
    }
    function draw() {
        if (!container) return;
        const expanded = [...container.querySelectorAll('details[open]')].map(el => el.querySelector('summary')?.textContent);
        const focusedId = container.contains(document.activeElement) ? document.activeElement.id : '';
        if (!mapping(draft)) { container.innerHTML = '<p class="network-status error">模板不可编辑，请先修复底层 YAML。</p>'; return; }
        const dns = mapping(draft.dns) ? draft.dns : {};
        const bad = ['dns', 'tun'].some(key => own(draft, key) && !mapping(draft[key]));
        const hijack = hijackState(draft.tun?.['dns-hijack']);
        const filterMode = dns['fake-ip-filter-mode'] ?? 'blacklist';
        const filterEditable = ['blacklist', 'whitelist'].includes(filterMode);
        const policies = dns['nameserver-policy'];
        const policyKeys = mapping(policies) ? Object.keys(policies) : [];
        container.innerHTML = `<div class="network-heading"><div><h2>🛡️ DNS 与网络</h2><p class="hint">配置保存到订阅模板并随最终订阅下发。实际生效取决于客户端覆盖配置、内核与系统环境。</p></div></div>
            <div class="network-toolbar"><strong>${saving ? '正在保存…' : dirty ? '● 有未保存修改' : '已与模板同步'}</strong>
            ${button('保存网络设置', 'save', !dirty || saving ? 'disabled' : '')}
            ${button('放弃修改', 'discard', saving ? 'disabled' : '')}${button('前往底层配置', 'raw')}</div>
            ${bad ? '<p class="network-status error">dns/tun 包含非对象值（或 null），请先在底层配置中明确改为对象；原文保持不变。</p>' : ''}
            <fieldset class="network-fields" ${bad || saving ? 'disabled' : ''}>
            <section class="card"><h3 class="card-title">配置方案</h3><div class="network-actions">
            ${button('🟢 兼容模式', 'preset', 'data-preset="compatible"')}${button('🛡️ 防 DNS 泄露', 'preset', 'data-preset="protect"')}${button('🔒 严格防泄露', 'preset', 'data-preset="strict"')}</div>
            <p class="hint">兼容模式仅关闭订阅内 TUN，保留 DNS。防护预设只调整列出的字段，Bootstrap 默认包含明文 DNS。确认后仍需保存。</p></section>
            <section class="card"><h3 class="card-title">DNS 基础设置</h3><div class="form-grid">
            ${field('dns', 'enable', '启用 Mihomo DNS', BOOL)}${field('dns', 'ipv6', 'IPv6 DNS', BOOL)}
            ${field('dns', 'enhanced-mode', 'DNS 模式', [['fake-ip', 'Fake-IP'], ['redir-host', 'Redir-Host']])}</div>
            <p class="hint">关闭 IPv6 DNS 后不返回 AAAA 结果；不等于关闭系统 IPv6。未设置模式时，基线内核采用 Redir-Host。</p>
            <details><summary>高级 DNS 选项</summary>${field('dns', 'respect-rules', 'DNS 查询遵循路由规则', BOOL)}<p class="hint">开启 respect-rules 必须配置代理节点域名 DNS，不建议同时开启 prefer-h3。</p></details></section>
            <section class="card"><h3 class="card-title">DNS 服务器</h3>
            ${rows('dns', 'nameserver', LISTS.nameserver, '用于普通域名解析；加密地址不代表查询一定经代理。')}
            ${rows('dns', 'default-nameserver', LISTS['default-nameserver'], '用于解析 DNS 服务器域名。常用地址的主机必须是 IP，可使用加密协议。')}
            ${rows('dns', 'proxy-server-nameserver', LISTS['proxy-server-nameserver'], '用于解析代理节点服务器域名。')}
            <details><summary>Direct Nameserver</summary>${rows('dns', 'direct-nameserver', LISTS['direct-nameserver'], '用于 DIRECT 流量；是否遵循策略由下方选项决定。')}
            ${field('dns', 'direct-nameserver-follow-policy', 'Direct DNS 遵循策略', BOOL)}</details></section>
            <section class="card"><h3 class="card-title">DNS 分流策略</h3><p class="hint">直接填写 Mihomo matcher。geosite 依赖客户端数据；未命中域名由其他 DNS 配置处理。</p>
            ${policyKeys.map((key, index) => `<div class="network-row"><span class="network-address">${escape(key)} → ${escape(JSON.stringify(policies[key]))}</span>${button('编辑', 'policy', `data-index="${index}"`)}${button('删除', 'delete-policy', `data-index="${index}"`)}</div>`).join('')}
            ${policies != null && !mapping(policies) ? '<p class="network-status error">现有策略类型无效，请在底层配置中修复。</p>' : ''}
            ${button('+ 添加策略', 'policy', 'data-index="-1"')}${button('🇨🇳 国内 / 🌍 国外 DNS 分流', 'recommend')}</section>
            ${dns['enhanced-mode'] === 'fake-ip' ? `<section class="card"><h3 class="card-title">Fake-IP</h3>
            <div class="form-group"><label for="net-range">Fake-IP IPv4 网段</label><input id="net-range" data-section="dns" data-field="fake-ip-range" value="${escape(dns['fake-ip-range'] ?? '')}" placeholder="未设置 · 198.18.0.1/16">${button('恢复未设置', 'unset', 'data-section="dns" data-key="fake-ip-range"')}</div>
            ${filterEditable ? rows('dns', 'fake-ip-filter', filterMode === 'whitelist' ? 'Fake-IP 白名单' : 'Fake-IP 排除列表') + button('批量追加（每行一个）', 'import-filter') : '<p class="hint">当前为高级过滤模式，保留原值，请到 Raw YAML 编辑。</p>'}</section>` : ''}
            <section class="card"><h3 class="card-title">TUN 与 DNS 防泄露</h3><div class="form-grid">
            ${field('tun', 'enable', '启用 TUN', BOOL)}${field('tun', 'stack', 'TUN 协议栈', [['mixed', 'mixed'], ['system', 'system'], ['gvisor', 'gvisor']])}
            ${field('tun', 'auto-route', '自动配置路由', BOOL)}${field('tun', 'auto-detect-interface', '自动检测出口网卡', BOOL)}${field('tun', 'strict-route', 'Strict Route', BOOL)}</div>
            <p class="hint">Strict Route 依赖 auto-route，可降低 Windows 多网卡 DNS 绕过风险，也可能影响部分应用。多出口环境应核对出口网卡。TUN 必须由客户端支持并具备所需权限。</p>
            <div class="network-actions"><label><input type="checkbox" data-hijack="udp" ${hijack.udp ? 'checked' : ''}> 劫持 UDP 53</label><label><input type="checkbox" data-hijack="tcp" ${hijack.tcp ? 'checked' : ''}> 劫持 TCP 53</label></div>
            <p class="hint">${draft.tun?.['dns-hijack'] === undefined ? '未显式设置：显示基线默认的 UDP 映射。' : ''} 映射只作用于进入 TUN 的匹配流量；需要 DNS 与 TUN 开启，不代表全系统 DNS 都被覆盖。</p>
            <details><summary>高级 DNS Hijack 列表</summary>${rows('tun', 'dns-hijack', '全部映射（含自定义项）')}</details></section>
            </fieldset><section class="card"><h3 class="card-title">配置检查 ${dirty ? '· 当前草稿' : '· 已保存模板'}</h3><div id="network-check" aria-live="polite"></div>${button('重新检查', 'validate')}</section>
            <section class="card"><details><summary>高级 DNS / TUN YAML · ${dirty ? '未保存预览' : '已保存'}</summary><pre class="network-yaml"></pre><p class="hint">只读预览。高级字段请在底层配置页编辑。字段值会保留，YAML 注释与排版不保证保留。</p></details></section>`;
        const network = {};
        for (const key of ['dns', 'tun']) if (own(draft, key)) put(network, key, draft[key]);
        container.querySelector('.network-yaml').textContent = dump(network);
        diagnostics(container.querySelector('#network-check'), report);
        for (const details of container.querySelectorAll('details')) {
            if (expanded.includes(details.querySelector('summary')?.textContent)) details.open = true;
        }
        if (focusedId) document.getElementById(focusedId)?.focus();
    }
    function editAddress(name, key, index) {
        const values = draft[name]?.[key];
        const current = index >= 0 ? values[index] : '';
        const isDNS = own(LISTS, key);
        const html = `${isDNS ? `<div class="form-grid"><div class="form-group"><label for="net-provider">服务商</label><select id="net-provider"><option>自定义</option>${Object.keys(PROVIDERS).map(v => `<option>${v}</option>`).join('')}</select></div>
            <div class="form-group"><label for="net-protocol">协议</label><select id="net-protocol">${['自定义', 'DoH', 'DoT', 'UDP', 'TCP'].map(v => `<option>${v}</option>`).join('')}</select></div></div>` : ''}
            <div class="form-group"><label for="net-address">${isDNS ? 'DNS 地址' : '条目'}</label><input id="net-address" value="${escape(current)}"><p class="hint" id="net-address-hint">保留完整地址与参数。${key === 'default-nameserver' ? 'Bootstrap 请选择 IP 主机地址。' : ''}</p></div>`;
        hooks.openModal(index < 0 ? '添加条目' : '编辑条目', html, () => {
            try {
                const value = document.getElementById('net-address').value.trim();
                if (!value) throw new Error('条目不能为空');
                update(editList(draft, name, key, index, value)); hooks.closeModal();
            } catch (e) { hooks.toast(e.message, 'error'); }
        });
        if (isDNS) {
            const providerInput = document.getElementById('net-provider'), protocolInput = document.getElementById('net-protocol');
            protocolInput.value = protocol(current);
            const fill = () => {
                const address = providerOptions(providerInput.value, key === 'default-nameserver')[protocolInput.value];
                if (address) document.getElementById('net-address').value = address;
                document.getElementById('net-address-hint').textContent = address ? '已填写，可继续手工修改。Bootstrap 主机需为 IP。' : '该组合无内置地址，请手工填写；不自动猜测端点。';
            };
            providerInput.addEventListener('change', () => {
                const available = providerOptions(providerInput.value, key === 'default-nameserver');
                for (const option of protocolInput.options) option.disabled = providerInput.value !== '自定义' && option.value !== '自定义' && !own(available, option.value);
                if (!own(available, protocolInput.value)) protocolInput.value = Object.keys(available)[0] || '自定义';
                fill();
            });
            protocolInput.addEventListener('change', fill);
        }
    }
    function policyModal(index) {
        const policies = draft.dns?.['nameserver-policy'] || {};
        const oldKey = index < 0 ? null : Object.keys(policies)[index];
        const values = oldKey === null ? [] : policies[oldKey];
        hooks.openModal('DNS 分流策略', `<div class="form-group"><label for="net-matcher">匹配规则</label><input id="net-matcher" value="${escape(oldKey || '')}" placeholder="geosite:cn / +.google.com / rule-set:xxx"></div><div class="form-group"><label for="net-policy-addresses">DNS 地址（每行一个）</label><textarea id="net-policy-addresses">${escape(Array.isArray(values) ? values.join('\n') : values)}</textarea></div>`, () => {
            try {
                const key = document.getElementById('net-matcher').value.trim();
                const addresses = document.getElementById('net-policy-addresses').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
                if (!key || !addresses.length) throw new Error('请填写匹配规则与 DNS 地址');
                update(editPolicy(draft, oldKey, key, addresses)); hooks.closeModal();
            } catch (e) { hooks.toast(e.message, 'error'); }
        });
    }
    async function action(event) {
        const target = event.target.closest('button[data-action]');
        if (!target || !container.contains(target)) return;
        const { action, section: name, key, index } = target.dataset;
        if (saving && action !== 'raw') return;
        try {
            if (action === 'raw') { hooks.openRaw(); return; }
            if (action === 'validate') { await validate(); return; }
            if (action === 'discard') { draft = clone(saved); dirty = false; draw(); scheduleValidation(); hooks.onDirty?.(false); return; }
            if (action === 'save') {
                saving = true; draw();
                try { await hooks.save(clone(draft)); } finally { saving = false; draw(); }
                return;
            }
            if (action === 'preset' || action === 'recommend') {
                const next = action === 'preset' ? applyPreset(draft, target.dataset.preset) : recommendPolicies(draft);
                const diff = changes(draft, next);
                const html = `<p>${action === 'recommend' ? '只新增缺失策略，同名策略保留。' : '应用预设将修改当前 DNS/TUN 草稿，是否继续？'} 保存后才会下发。</p><pre class="network-yaml">${escape(diff.length ? diff.map(d => `${d.path}\n  ${JSON.stringify(d.before) ?? '未设置'}\n→ ${JSON.stringify(d.after)}`).join('\n\n') : '没有需要修改的字段（已有同名策略将跳过）。')}</pre>`;
                hooks.openModal('确认配置变更', html, () => { update(next); hooks.closeModal(); }); return;
            }
            if (action === 'edit-list') { editAddress(name, key, Number(index)); return; }
            if (action === 'delete-list') { update(editList(draft, name, key, Number(index), undefined)); return; }
            if (action === 'unset') { update(setField(draft, name, key, undefined)); return; }
            if (action === 'policy') { policyModal(Number(index)); return; }
            if (action === 'delete-policy') {
                const oldKey = Object.keys(draft.dns['nameserver-policy'])[Number(index)];
                update(editPolicy(draft, oldKey, null)); return;
            }
            if (action === 'import-filter') {
                hooks.openModal('批量追加 Fake-IP 条目', '<div class="form-group"><label for="net-filter-import">每行一个，追加到已有列表</label><textarea id="net-filter-import"></textarea></div>', () => {
                    try {
                        let next = draft;
                        for (const value of document.getElementById('net-filter-import').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean)) next = editList(next, 'dns', 'fake-ip-filter', -1, value);
                        update(next); hooks.closeModal();
                    } catch (e) { hooks.toast(e.message, 'error'); }
                });
            }
        } catch (e) { hooks.toast(e.message, 'error'); }
    }
    function init(options) {
        hooks = options; container = document.getElementById('panel-network');
        container.addEventListener('click', action);
        container.addEventListener('change', event => {
            if (saving) return;
            const el = event.target;
            try {
                if (hooks.isBusy?.()) { draw(); throw new Error('正在保存，请稍候'); }
                if (el.dataset.hijack) update(setHijack(draft, el.dataset.hijack, el.checked));
                else if (el.dataset.field && el.value !== '__preserve') {
                    const value = el.value === '' ? undefined : el.value === 'true' ? true : el.value === 'false' ? false : el.value;
                    update(setField(draft, el.dataset.section, el.dataset.field, value));
                }
            } catch (e) { hooks.toast(e.message, 'error'); }
        });
    }
    function render(config, force = false) {
        saved = clone(config);
        if (!dirty || force) { draft = clone(config); dirty = false; report = null; }
        draw(); scheduleValidation(); renderOverview(config);
    }
    async function renderOverview(config) {
        const id = ++overviewRevision, target = document.getElementById('network-overview');
        if (!target) return;
        diagnostics(target, null, '正在检查已保存模板…');
        try {
            const result = await hooks.validate(dump(config));
            if (id !== overviewRevision) return;
            diagnostics(target, result);
            const effective = result.effective;
            if (effective) {
                const summary = document.createElement('p'), h = hijackState(effective.tun['dns-hijack']);
                const active = effective.dns.enable === true && effective.tun.enable === true;
                summary.textContent = `DNS ${effective.dns.enable === true ? '已启用' : '未启用'} · ${effective.dns['enhanced-mode']} · TUN ${effective.tun.enable === true ? '已启用' : '未启用'} · Hijack ${h.udp ? 'UDP' : ''} ${h.tcp ? 'TCP' : ''}${active ? '（配置）' : '（未满足启用条件）'} · Strict Route ${effective.tun['strict-route'] === true && effective.tun['auto-route'] === true && effective.tun.enable === true ? '已配置' : '未启用'} · IPv6 DNS ${effective.dns.ipv6 === true ? '开启' : '关闭'}`;
                target.prepend(summary);
            }
        } catch (e) { if (id === overviewRevision) diagnostics(target, null, `检查未完成：${e.message}`); }
    }
    return { init, render, renderOverview, applyPreset, validate, getWarnings: () => report?.warnings || [],
        isDirty: () => dirty, getDraft: () => clone(draft), mapping, clone, setField, editList,
        hijackState, setHijack, editPolicy, recommendPolicies, changes, protocol, provider, providerOptions, PROVIDERS };
}));
