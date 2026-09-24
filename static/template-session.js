(function (root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.ProxyForgeTemplateSession = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function create({ parse, read, write, validate, install }) {
        let busy = false, uncertain = false, baseline = null;
        function setBaseline(snapshot) { baseline = snapshot; }
        function accept(snapshot) { baseline = snapshot; install(snapshot); }
        function conflict(snapshot) {
            return { ok: false, conflict: snapshot,
                message: '配置已在其他页面发生变化；草稿已保留' };
        }
        async function save(content) {
            if (busy) return { ok: false, message: '正在保存，请稍候' };
            if (!baseline) return { ok: false, message: '请先读取服务器模板版本' };
            busy = true;
            try {
                if (uncertain) {
                    let actual;
                    try { actual = await read(); }
                    catch (_) { return { ok: false, uncertain: true, message: '仍无法读取服务器模板；草稿已保留' }; }
                    uncertain = false;
                    if (actual.content === content) { accept(actual); return { ok: true }; }
                    if (actual.revision !== baseline.revision) return conflict(actual);
                }
                parse(content);
                const report = await validate(content);
                if (report.errors.length) return { ok: false, report,
                    message: report.errors.map(e => e.path + ': ' + e.message).join('\n') };
                let saved;
                try { saved = await write(content, baseline.revision); }
                catch (error) {
                    if (error.status === 409 && error.detail?.code === 'template_conflict') {
                        return conflict({ content: error.detail.current_content, revision: error.detail.current_revision });
                    }
                    if (error.status && error.status < 500) throw error;
                    let actual;
                    try { actual = await read(); } catch (_) {
                        uncertain = true;
                        return { ok: false, uncertain: true, message: '提交结果不确定；草稿已保留，请核对后再保存' };
                    }
                    if (actual.content !== content) {
                        if (actual.revision !== baseline.revision) return conflict(actual);
                        return { ok: false, message: '保存未确认；草稿已保留' };
                    }
                    saved = actual;
                }
                accept(saved);
                return { ok: true, report };
            } catch (error) { return { ok: false, message: error.message }; }
            finally { busy = false; }
        }
        return { save, setBaseline, isBusy: () => busy };
    }
    return { create };
}));
