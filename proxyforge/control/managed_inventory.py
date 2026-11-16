"""Secret-free management inventory, including deployed and adopted assets."""
import json
import uuid

from agent.adoption import valid_adopt_output
from agent.deployment_spec import node_name
from proxyforge.control.deployment_store import PROJECTABLE_LANDING_PROTOCOLS

_KIND_ORDER = {'direct': 0, 'chain': 1, 'adopted': 2}


def migrate_adoptions(db):
    db.execute('''CREATE TABLE adopted_nodes (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        source_key TEXT NOT NULL,
        core TEXT NOT NULL,
        service_name TEXT NOT NULL,
        config_path TEXT NOT NULL,
        config_sha256 TEXT NOT NULL,
        tag TEXT NOT NULL,
        protocol TEXT NOT NULL,
        listen TEXT NOT NULL,
        listen_port INTEGER NOT NULL,
        tls_mode TEXT NOT NULL,
        sni TEXT NOT NULL,
        network TEXT NOT NULL,
        ws_path TEXT NOT NULL,
        adoptable INTEGER NOT NULL DEFAULT 1,
        metadata TEXT NOT NULL DEFAULT '{}',
        discovered_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        UNIQUE(agent_id, source_key))''')
    db.execute('CREATE INDEX adopted_agent ON adopted_nodes(agent_id)')
    db.execute('INSERT INTO schema_migrations VALUES(6)')


class ManagedInventoryMixin:
    def _save_adopted_scan(self, db, agent_id, scan):
        if not valid_adopt_output(scan):
            raise ValueError('Invalid adoption scan payload')
        now = self.clock()
        seen_keys = []
        for ep in scan['endpoints']:
            seen_keys.append(ep['source_key'])
            existing = db.execute(
                'SELECT id,discovered_at FROM adopted_nodes WHERE agent_id=? AND source_key=?',
                (agent_id, ep['source_key']),
            ).fetchone()
            record_id = existing['id'] if existing else uuid.uuid4().hex
            discovered_at = existing['discovered_at'] if existing else now
            db.execute(
                '''INSERT INTO adopted_nodes(
                       id,agent_id,source_key,core,service_name,config_path,config_sha256,
                       tag,protocol,listen,listen_port,tls_mode,sni,network,ws_path,
                       adoptable,metadata,discovered_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(agent_id, source_key) DO UPDATE SET
                       core=excluded.core,service_name=excluded.service_name,
                       config_path=excluded.config_path,config_sha256=excluded.config_sha256,
                       tag=excluded.tag,protocol=excluded.protocol,listen=excluded.listen,
                       listen_port=excluded.listen_port,tls_mode=excluded.tls_mode,
                       sni=excluded.sni,network=excluded.network,ws_path=excluded.ws_path,
                       adoptable=excluded.adoptable,metadata=excluded.metadata,updated_at=excluded.updated_at''',
                (
                    record_id, agent_id, ep['source_key'], ep['core'], ep['service_name'],
                    ep['config_path'], ep['config_sha256'], ep['tag'], ep['protocol'],
                    ep['listen'], ep['listen_port'], ep['tls_mode'], ep['sni'],
                    ep['network'], ep['ws_path'], int(bool(ep['adoptable'])),
                    json.dumps({'services': scan['services']}), discovered_at, now,
                ),
            )
        if seen_keys:
            placeholders = ','.join('?' for _ in seen_keys)
            db.execute(f'DELETE FROM adopted_nodes WHERE agent_id=? AND source_key NOT IN ({placeholders})', (agent_id, *seen_keys))
        else:
            db.execute('DELETE FROM adopted_nodes WHERE agent_id=?', (agent_id,))
        self._audit(db, 'adoption_scanned', agent_id)
        return len(seen_keys)

    def record_adoption_scan(self, token, instance_id, scan):
        from proxyforge.control.control_store import UnauthorizedAgent
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent_id = self._authenticate(db, token)
            agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
            if not agent or agent['instance_id'] != instance_id:
                raise UnauthorizedAgent()
            count = self._save_adopted_scan(db, agent_id, scan)
        return {'status': 'ok', 'agent_id': agent_id, 'adopted_count': count}

    def list_adopted_nodes(self, agent_id=None):
        with self.connection() as db:
            if agent_id is not None:
                rows = db.execute('SELECT * FROM adopted_nodes WHERE agent_id=? ORDER BY listen_port,id', (agent_id,)).fetchall()
            else:
                rows = db.execute('SELECT * FROM adopted_nodes ORDER BY agent_id,listen_port,id').fetchall()
            return [
                {
                    **{k: row[k] for k in (
                        'id', 'agent_id', 'source_key', 'core', 'service_name', 'config_path',
                        'config_sha256', 'tag', 'protocol', 'listen', 'listen_port',
                        'tls_mode', 'sni', 'network', 'ws_path', 'discovered_at', 'updated_at',
                    )},
                    'adoptable': bool(row['adoptable']),
                }
                for row in rows
            ]

    def managed_inventory(self):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT DISTINCT agent_id FROM jobs WHERE status IN ('pending','assigned','running')").fetchall():
                self._expire_jobs(db, row['agent_id'])
            agents = {}
            agent_ips = {}
            for row in db.execute('SELECT * FROM agents'):
                view = self._view(row)
                agents[row['id']] = {key: view[key] for key in ('id', 'name', 'status', 'last_seen', 'compatible')}
                agent_ips[row['id']] = row['observed_ip'] or view['name']
            jobs = {row['id']: dict(row) for row in db.execute('''SELECT id,type,status,error FROM jobs
                WHERE id IN (SELECT job_id FROM deployments UNION SELECT job_id FROM chains)''')}
            # Never load or decrypt secret_spec; this page also works during key recovery.
            deployments = {row['agent_id']: dict(row) for row in db.execute(
                'SELECT id,agent_id,protocol,settings,revision,job_id,updated_at FROM deployments')}
            chains = [dict(row) for row in db.execute(
                'SELECT id,agent_id,landing_agent_id,settings,revision,job_id,updated_at FROM chains')]
            adopted = [dict(row) for row in db.execute('SELECT * FROM adopted_nodes')]
            projectable = ('vless-reality', *PROJECTABLE_LANDING_PROTOCOLS)
            items = []
            for record, kind in [(row, 'direct') for row in deployments.values() if row['protocol'] in projectable] + [
                    (row, 'chain') for row in chains]:
                agent, job = agents[record['agent_id']], jobs[record['job_id']]
                settings = json.loads(record['settings'])
                landing = agents[record['landing_agent_id']] if kind == 'chain' else None
                removed = job['type'].endswith('.remove') and job['status'] == 'success'
                publishable = (job['status'] == 'success' and job['type'].endswith('.apply') and
                               agent['status'] != 'revoked' and (landing is None or landing['status'] != 'revoked'))
                blocked_by = []
                if kind == 'direct':
                    blocked_by = [{'id': row['id'], 'name': json.loads(row['settings'])['name']}
                                  for row in chains if row['agent_id'] == agent['id'] and not (
                                      jobs[row['job_id']]['type'] == 'chain.remove' and jobs[row['job_id']]['status'] == 'success')]
                source = deployments.get(record['agent_id'])
                endpoint = json.loads(source['settings'])['server'] if source else ''
                items.append({
                    'id': record['id'], 'kind': kind, 'name': node_name(record['id'], settings['name']),
                    'agent': agent, 'landing': landing, 'server': endpoint, 'port': settings['listen_port'],
                    'revision': record['revision'], 'job_id': record['job_id'], 'action': job['type'],
                    'status': job['status'], 'error': job['error'], 'removed': removed,
                    'publishable': publishable, 'blocked_by': blocked_by, 'updated_at': record['updated_at'],
                })

            for row in adopted:
                agent = agents[row['agent_id']]
                items.append({
                    'id': row['id'], 'kind': 'adopted',
                    'name': f"{row['tag']} [{row['core']}:{row['listen_port']}]",
                    'agent': agent, 'landing': None,
                    'server': agent_ips.get(row['agent_id'], ''), 'port': row['listen_port'],
                    'core': row['core'], 'protocol': row['protocol'], 'tls_mode': row['tls_mode'],
                    'sni': row['sni'], 'network': row['network'], 'ws_path': row['ws_path'],
                    'service_name': row['service_name'], 'source_key': row['source_key'],
                    'adoptable': bool(row['adoptable']),
                    'revision': 1, 'job_id': '', 'action': 'adopt_scan',
                    'status': 'adopted', 'error': None, 'removed': False,
                    'publishable': False, 'blocked_by': [], 'updated_at': row['updated_at'],
                })
            return sorted(items, key=lambda item: (item['agent']['name'], item['agent']['id'], _KIND_ORDER[item['kind']], item['id']))
