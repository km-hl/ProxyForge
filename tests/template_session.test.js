const test = require('node:test');
const assert = require('node:assert/strict');
const { create } = require('../static/template-session.js');
const valid = { errors: [], warnings: [], info: [] };
function setup(overrides = {}) {
    let server = '{}'; const installed = []; const writes = [];
    const session = create({ parse: JSON.parse, read: async () => ({ content: server, revision: 'r0' }),
        write: async text => { writes.push(text); server = text; return { content: text, revision: 'r1' }; },
        validate: async () => valid, install: snapshot => installed.push(snapshot.content), ...overrides });
    session.setBaseline({ content: '{}', revision: 'r0' });
    return { session, installed, writes };
}
test('save installs the snapshot and revision returned by the server', async () => {
    const s = setup();
    assert.equal((await s.session.save('{"dns":{}}')).ok, true);
    assert.deepEqual(s.installed, ['{"dns":{}}']);
});
test('validation error preserves authoritative state and never writes', async () => {
    const s = setup({ validate: async () => ({ ...valid, errors: [{ path: 'dns', message: 'invalid' }] }) });
    assert.equal((await s.session.save('{}')).ok, false);
    assert.deepEqual(s.writes, []); assert.deepEqual(s.installed, []);
});
test('warnings permit saving', async () => {
    const s = setup({ validate: async () => ({ ...valid, warnings: [{ code: 'advice' }] }) });
    assert.equal((await s.session.save('{}')).ok, true);
});
test('HTTP rejection including expired auth does not install', async () => {
    for (const status of [400, 401, 403]) {
        const s = setup({ write: async () => { throw Object.assign(new Error('rejected'), { status }); } });
        assert.equal((await s.session.save('{}')).ok, false);
        assert.deepEqual(s.installed, []);
    }
});
test('lost response reconciles successfully stored content', async () => {
    const s = setup({ write: async () => { throw new Error('connection lost'); } });
    assert.equal((await s.session.save('{}')).ok, true);
    assert.deepEqual(s.installed, ['{}']);
});
test('unconfirmed write does not overwrite saved snapshot', async () => {
    const s = setup({ write: async () => { throw new Error('connection lost'); } });
    assert.equal((await s.session.save('{"dns":{}}')).ok, false);
    assert.deepEqual(s.installed, []);
});
test('unreachable server leaves outcome uncertain and releases busy state', async () => {
    const s = setup({ write: async () => { throw new Error('lost'); }, read: async () => { throw new Error('offline'); } });
    const result = await s.session.save('{}');
    assert.equal(result.uncertain, true); assert.equal(result.ok, false);
    assert.equal(s.session.isBusy(), false); assert.deepEqual(s.installed, []);
});
test('confirmed write plus failed reload still reports saved', async () => {
    const s = setup({ read: async () => { throw new Error('offline'); } });
    assert.equal((await s.session.save('{}')).ok, true);
    assert.deepEqual(s.installed, ['{}']);
});
test('concurrent save is rejected before validation or write', async () => {
    let release;
    const s = setup({ validate: () => new Promise(resolve => { release = resolve; }) });
    const first = s.session.save('{}');
    assert.equal((await s.session.save('{"dns":{}}')).ok, false);
    release(valid); assert.equal((await first).ok, true);
    assert.deepEqual(s.writes, ['{}']);
});
test('uncertain save must reconcile before retrying any POST', async () => {
    let writes = 0;
    const s = setup({ write: async () => { writes++; throw new Error('lost'); },
        read: async () => { throw new Error('offline'); } });
    await s.session.save('{}');
    assert.equal((await s.session.save('{"dns":{}}')).uncertain, true);
    assert.equal(writes, 1);
});

test('409 preserves draft baseline across repeated saves', async () => {
    const revisions = [];
    const s = setup({ write: async (content, revision) => {
        revisions.push(revision);
        throw Object.assign(new Error('conflict'), { status: 409, detail: {
            code: 'template_conflict', current_content: '{"other":1}', current_revision: 'r2'
        }});
    }});
    assert.equal((await s.session.save('{"mine":1}')).conflict.revision, 'r2');
    await s.session.save('{"mine":2}');
    assert.deepEqual(revisions, ['r0', 'r0']);
    assert.deepEqual(s.installed, []);
});
test('uncertain retry never rebases old draft onto a concurrent update', async () => {
    let online = false, writes = 0;
    const s = setup({ write: async () => { writes++; throw new Error('lost'); },
        read: async () => { if (!online) throw new Error('offline');
            return { content: '{"other":1}', revision: 'r2' }; } });
    await s.session.save('{"mine":1}');
    online = true;
    assert.equal((await s.session.save('{"mine":1}')).conflict.revision, 'r2');
    assert.equal(writes, 1);
});
test('history diff preserves text and reports unchanged content', () => {
    const { templateDifference } = require('../static/template-history.js');
    assert.equal(templateDifference('same', 'same'), '内容相同');
    assert.ok(templateDifference('a', '<script>').includes('+ <script>'));
});
