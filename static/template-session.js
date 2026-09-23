(function (root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.ProxyForgeTemplateSession = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    // Transport is injected so failure/uncertainty handling can be tested without DOM.
    function create({ parse, read, write, validate, install }) {
        let busy = false;
        let uncertain = false;
        async function save(content) {
            if (busy) return { ok: false, message: '正在保存，请稍候' };
            busy = true;
            try {
                // Require a fresh read before retrying an inconclusive POST.
                if (uncertain) {
                    try {
                        const actual = await read();
                        uncertain = false;
                        if (actual === content) { install(actual); return { ok: true }; }
                    } catch (_) {
                        return { ok: false, uncertain: true, message: '仍无法读取服务器模板，未重试保存；草稿已保留' };
                    }
                }
                parse(content);
                const report = await validate(content);
                if (report.errors.length) return { ok: false, report, message: report.errors.map(e => `${e.path}: ${e.message}`).join('\n') };
                try {
                    await write(content);
                } catch (error) {
                    if (error.status && error.status < 500) throw error;
                    // A dropped response does not prove the write failed.
                    let actual;
                    try { actual = await read(); } catch (_) {
                        uncertain = true;
                        return { ok: false, uncertain: true, message: '提交结果不确定，请重新读取模板后再保存；草稿已保留' };
                    }
                    if (actual !== content) return { ok: false, message: '保存未确认，请核对服务器模板；草稿已保留' };
                }
                install(content);
                try {
                    const actual = await read();
                    install(actual);
                    return { ok: true, report };
                } catch (_) {
                    return { ok: true, report, message: '已保存，重新读取失败；当前显示本次提交内容' };
                }
            } catch (error) {
                return { ok: false, message: error.message };
            } finally {
                busy = false;
            }
        }
        return { save, isBusy: () => busy };
    }
    return { create };
}));
