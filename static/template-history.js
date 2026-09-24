/* Template history and explicit conflict handling. Contents are always text. */
function templateDifference(before, after) {
    const a = before.split('\n'), b = after.split('\n');
    let start = 0, endA = a.length, endB = b.length;
    while (start < endA && start < endB && a[start] === b[start]) start++;
    while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
    if (start === endA && start === endB) return '内容相同';
    return ['- 当前服务器版本 / + 选中历史版本',
        ...a.slice(start, endA).map(line => '- ' + line),
        ...b.slice(start, endB).map(line => '+ ' + line)].join('\n');
}

function showTemplateConflict(snapshot) {
    openModal('配置已在其他页面发生变化',
        '<p>你的草稿仍在原编辑器中。下面显示服务器版本；重新加载会替换本页草稿。</p>' +
        '<textarea id="conflict-server" readonly style="width:100%;min-height:300px"></textarea>' +
        '<button class="btn" id="conflict-reload">重新加载服务器版本</button>',
        () => closeModal());
    document.getElementById('conflict-server').value = snapshot.content;
    modalConfirm.textContent = '保留我的草稿';
    document.getElementById('conflict-reload').onclick = async () => {
        if (!confirm('重新加载会放弃当前 Raw / DNS 编辑草稿，是否继续？')) return;
        try { installTemplate(await readTemplate()); closeModal(); }
        catch (error) { showToast(error.message, 'error'); }
    };
}

async function showTemplateHistory() {
    try {
        templateGuard('raw');
        const { entries } = await (await fetchAuth('/template/history')).json();
        openModal('模板历史',
            '<p>恢复会重新校验当前节点引用，并检查本页模板版本。时间为本地时间。</p>' +
            '<div id="history-list"></div><pre id="history-content" style="white-space:pre-wrap;max-height:45vh;overflow:auto"></pre>',
            () => closeModal());
        modalConfirm.textContent = '关闭';
        const list = document.getElementById('history-list');
        if (!entries.length) list.textContent = '尚无历史；首次修改时会保留原始版本。';
        for (const entry of entries) {
            const row = document.createElement('div');
            const label = document.createElement('span');
            label.textContent = new Date(entry.timestamp).toLocaleString() + ' · ' +
                entry.revision.slice(0, 12) + ' · ' + entry.size + ' bytes ';
            row.append(label);
            for (const [name, action] of [['查看', 'view'], ['Diff', 'diff'], ['恢复', 'restore']]) {
                const button = document.createElement('button');
                button.className = 'btn'; button.textContent = name;
                button.onclick = async () => {
                    button.disabled = true;
                    try {
                        if (action === 'restore') {
                            templateGuard('raw');
                            if (rawIsDirty() || ProxyForgeNetwork.isDirty())
                                throw new Error('请先保存或放弃当前草稿，再恢复历史版本');
                            if (!confirm('将选中历史作为一个新版本保存？')) return;
                            externalTemplateBusy = true;
                            const response = await fetchAuth('/template/history/' + entry.id + '/restore', {
                                method: 'POST', body: JSON.stringify({ expected_revision: state.templateRevision })
                            });
                            installTemplate(await response.json()); closeModal(); showToast('已恢复模板');
                        } else {
                            const snapshot = await (await fetchAuth('/template/history/' + entry.id)).json();
                            const content = action === 'view' ? snapshot.content :
                                templateDifference((await readTemplate()).content, snapshot.content);
                            document.getElementById('history-content').textContent = content;
                        }
                    } catch (error) {
                        if (error.status === 409 && error.detail?.code === 'template_conflict')
                            showTemplateConflict({ content: error.detail.current_content, revision: error.detail.current_revision });
                        else showToast(error.message, 'error');
                    } finally { button.disabled = false; externalTemplateBusy = false; }
                };
                row.append(button);
            }
            list.append(row);
        }
    } catch (error) { showToast(error.message, 'error'); }
}

if (typeof document !== 'undefined')
    document.getElementById('template-history-btn').addEventListener('click', showTemplateHistory);
if (typeof module !== 'undefined' && module.exports) module.exports = { templateDifference };
