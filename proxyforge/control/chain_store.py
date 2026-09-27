"""Transactional entry/landing association; an entry always retains its direct node."""
import json
import uuid

from agent.chain_spec import validate_settings, validate_spec
from agent.deployment_spec import client_node, node_name, spec_hash
from proxyforge.control.deployment_store import new_spec
from proxyforge.control.job_store import JobConflict, JobNotFound


def migrate_chains(db):
    db.execute('''CREATE TABLE chains (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL UNIQUE REFERENCES agents(id) ON DELETE CASCADE,
        landing_agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        settings TEXT NOT NULL, revision INTEGER NOT NULL, secret_spec TEXT NOT NULL,
        job_id TEXT NOT NULL, updated_at REAL NOT NULL)''')
    db.execute('CREATE INDEX chains_landing ON chains(landing_agent_id)')
    db.execute('INSERT INTO schema_migrations VALUES(5)')


class ChainStoreMixin:
    def _assert_no_chain(self, db, agent_id):
        # Even failed/cancelled applies may have reached the remote commit. Only a
        # successful removal releases dependencies, never a UI cancel or timeout.
        if db.execute('''SELECT 1 FROM chains c JOIN jobs j ON j.id=c.job_id
            WHERE (c.agent_id=? OR c.landing_agent_id=?)
            AND NOT (j.type='chain.remove' AND j.status='success')''', (agent_id, agent_id)).fetchone():
            raise JobConflict()

    def _chain_view(self, db, row):
        job = db.execute('SELECT type,status,error FROM jobs WHERE id=?', (row['job_id'],)).fetchone()
        return {'id': row['id'], 'agent_id': row['agent_id'], 'landing_agent_id': row['landing_agent_id'],
                'settings': json.loads(row['settings']), 'revision': row['revision'], 'job_id': row['job_id'],
                'action': job['type'], 'status': job['status'], 'error': job['error'], 'updated_at': row['updated_at']}

    def get_chain(self, agent_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent_id,)).fetchone():
                raise JobNotFound()
            self._expire_jobs(db, agent_id)
            row = db.execute('SELECT * FROM chains WHERE agent_id=?', (agent_id,)).fetchone()
            return self._chain_view(db, row) if row else None

    def chain_landings(self):
        with self.connection() as db:
            return [{'agent_id': row['agent_id'], 'name': json.loads(row['settings'])['name']}
                    for row in db.execute('''SELECT d.* FROM deployments d JOIN jobs j ON j.id=d.job_id
                        JOIN agents a ON a.id=d.agent_id WHERE d.protocol='ss2022'
                        AND j.type='landing.apply' AND j.status='success' AND a.revoked_at IS NULL''')]

    def _ready_deployment(self, db, agent_id, protocol, action):
        self._job_agent(db, agent_id)
        self._expire_jobs(db, agent_id)
        row = db.execute('''SELECT d.* FROM deployments d JOIN jobs j ON j.id=d.job_id
            WHERE d.agent_id=? AND d.protocol=? AND j.type=? AND j.status='success' ''',
                         (agent_id, protocol, action)).fetchone()
        if not row:
            raise JobConflict()
        return row

    def put_chain(self, agent_id, request_id, expected_revision, landing_agent_id, settings, remove=False):
        validate_settings(settings)
        if agent_id == landing_agent_id:
            raise JobConflict()
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent = self._job_agent(db, agent_id)
            action = 'chain.remove' if remove else 'chain.apply'
            self._runtime_capability(agent, action)
            self._expire_jobs(db, agent_id)
            row = db.execute('SELECT * FROM chains WHERE agent_id=?', (agent_id,)).fetchone()
            existing = db.execute('SELECT * FROM jobs WHERE agent_id=? AND request_id=?', (agent_id, request_id)).fetchone()
            if existing:
                if (not row or row['job_id'] != existing['id'] or existing['type'] != action or
                        row['revision'] != expected_revision + 1 or json.loads(row['settings']) != settings or
                        row['landing_agent_id'] != landing_agent_id):
                    raise JobConflict()
                return self._chain_view(db, row)
            if (row['revision'] if row else 0) != expected_revision or (remove and not row):
                raise JobConflict()
            if row and (json.loads(row['settings'])['name'] != settings['name'] or row['landing_agent_id'] != landing_agent_id):
                raise JobConflict()
            if db.execute("SELECT 1 FROM jobs WHERE agent_id=? AND type!='singbox.status' AND status IN ('pending','assigned','running')",
                          (agent_id,)).fetchone():
                raise JobConflict()
            direct = self._ready_deployment(db, agent_id, 'vless-reality', 'deployment.apply')
            direct_spec = self._decrypt_spec(db, direct['secret_spec'])
            # Removing the entry association remains possible when the landing is revoked.
            previous = self._decrypt_spec(db, row['secret_spec']) if row else None
            if remove:
                if json.loads(row['settings']) != settings:
                    raise JobConflict()
                snapshot = {'direct': direct_spec, 'chain': None}
                saved = previous  # Keep the chain's credentials for a later re-enable.
            else:
                landing = self._ready_deployment(db, landing_agent_id, 'ss2022', 'landing.apply')
                if settings['listen_port'] == direct_spec['listen_port']:
                    raise JobConflict()
                entry_settings = {**json.loads(direct['settings']), **settings}
                entry = {**(previous['chain']['entry'] if previous else new_spec(entry_settings)), **entry_settings}
                snapshot = {'direct': direct_spec, 'chain': {'entry': entry,
                            'landing': self._decrypt_spec(db, landing['secret_spec'])}}
                saved = snapshot
            validate_spec(action, snapshot)
            identifier = row['id'] if row else uuid.uuid4().hex
            payload = {'deployment_id': identifier, 'revision': expected_revision + 1, 'spec_hash': spec_hash(snapshot)}
            cipher = self._cipher(db)
            job = self._enqueue_job(db, agent_id, request_id, action, payload)
            db.execute('UPDATE jobs SET secret_payload=? WHERE id=?',
                       (cipher.encrypt(json.dumps(snapshot).encode()).decode(), job['id']))
            db.execute('''INSERT INTO chains VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                settings=excluded.settings,revision=excluded.revision,secret_spec=excluded.secret_spec,
                job_id=excluded.job_id,updated_at=excluded.updated_at''',
                       (identifier, agent_id, landing_agent_id, json.dumps(settings), expected_revision + 1,
                        cipher.encrypt(json.dumps(saved).encode()).decode(), job['id'], self.clock()))
            self._audit(db, 'chain_requested', agent_id)
            return self._chain_view(db, db.execute('SELECT * FROM chains WHERE id=?', (identifier,)).fetchone())

    def _chain_node_names(self, db):
        return [node_name(row['id'], json.loads(row['settings'])['name']) for row in db.execute('SELECT * FROM chains')]

    def _chain_nodes(self, db):
        rows = db.execute('''SELECT c.* FROM chains c JOIN jobs j ON j.id=c.job_id
            JOIN agents a ON a.id=c.agent_id JOIN agents l ON l.id=c.landing_agent_id
            WHERE j.type='chain.apply' AND j.status='success' AND a.revoked_at IS NULL AND l.revoked_at IS NULL''')
        nodes = []
        for row in rows:
            node = client_node(row['id'], row['agent_id'], self._decrypt_spec(db, row['secret_spec'])['chain']['entry'])
            node['_managed_by']['chain_id'] = row['id']
            nodes.append(node)
        return nodes
