"""Control-plane desired state and byte accounting for go-gost data plane."""
import hashlib
import json
import uuid

from agent.gost_manager import BestExitManager, GOST_CONFIG_ACTIONS, validate_host_port, validate_spec as validate_gost_spec
from agent.runtime_spec import spec_hash
from proxyforge.control.job_store import JobConflict, JobNotFound


def migrate_phase2_dataplane(db):
    db.execute('''CREATE TABLE forward_rules (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        listen TEXT NOT NULL DEFAULT '::',
        listen_port INTEGER NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'tcp+udp',
        mode TEXT NOT NULL DEFAULT 'direct',
        chain_id TEXT NOT NULL DEFAULT '',
        exit_group_id TEXT NOT NULL DEFAULT '',
        targets TEXT NOT NULL DEFAULT '[]',
        settings TEXT NOT NULL DEFAULT '{}',
        enabled INTEGER NOT NULL DEFAULT 1,
        revision INTEGER NOT NULL DEFAULT 1,
        job_id TEXT NOT NULL DEFAULT '',
        request_id TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        UNIQUE(agent_id, name))''')
    db.execute('CREATE INDEX forward_rules_agent ON forward_rules(agent_id, listen_port)')

    db.execute('''CREATE TABLE tunnel_chains (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        entry_agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        hops TEXT NOT NULL,
        summary TEXT NOT NULL,
        revision INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL)''')
    db.execute('CREATE INDEX tunnel_chains_entry ON tunnel_chains(entry_agent_id)')

    db.execute('''CREATE TABLE best_exit_groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        probe_interval INTEGER NOT NULL DEFAULT 15,
        confirmation_rounds INTEGER NOT NULL DEFAULT 3,
        cooldown_seconds INTEGER NOT NULL DEFAULT 30,
        min_advantage_ms REAL NOT NULL DEFAULT 20.0,
        min_advantage_ratio REAL NOT NULL DEFAULT 0.15,
        exits TEXT NOT NULL,
        active_exit_id TEXT NOT NULL DEFAULT '',
        last_probe_at REAL,
        last_switch_at REAL,
        metrics TEXT NOT NULL DEFAULT '{}',
        revision INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL)''')
    db.execute('CREATE INDEX best_exit_agent ON best_exit_groups(agent_id)')

    db.execute('''CREATE TABLE gost_agent_states (
        agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
        revision INTEGER NOT NULL DEFAULT 0,
        job_id TEXT NOT NULL DEFAULT '',
        secret_spec TEXT NOT NULL DEFAULT '',
        updated_at REAL NOT NULL)''')

    db.execute('''CREATE TABLE traffic_counters (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        resource_key TEXT NOT NULL,
        forward_rule_id TEXT NOT NULL DEFAULT '',
        rx_bytes INTEGER NOT NULL DEFAULT 0,
        tx_bytes INTEGER NOT NULL DEFAULT 0,
        total_bytes INTEGER NOT NULL DEFAULT 0,
        last_raw_rx INTEGER NOT NULL DEFAULT 0,
        last_raw_tx INTEGER NOT NULL DEFAULT 0,
        last_epoch TEXT NOT NULL DEFAULT '',
        updated_at REAL NOT NULL,
        UNIQUE(agent_id, resource_key))''')
    db.execute('CREATE INDEX traffic_counters_agent ON traffic_counters(agent_id, forward_rule_id)')

    db.execute('''CREATE TABLE traffic_batches (
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        batch_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        accepted_count INTEGER NOT NULL,
        created_at REAL NOT NULL,
        PRIMARY KEY(agent_id, batch_id))''')

    db.execute('INSERT INTO schema_migrations VALUES(7)')


def _normalize_transports(protocol):
    return frozenset(('tcp', 'udp')) if protocol == 'tcp+udp' else frozenset((protocol,))


def _sanitize_hops_summary(hops):
    summary = []
    for hop in hops:
        nodes = hop.get('nodes') or []
        summary.append({
            'name': hop.get('name', ''),
            'strategy': hop.get('strategy', 'fifo'),
            'node_count': len(nodes),
            'connectors': sorted({n.get('connector', 'relay') for n in nodes}),
            'dialers': sorted({n.get('dialer', 'tcp') for n in nodes}),
            'relay_agent_ids': sorted({n['agent_id'] for n in nodes if n.get('serve_on_agent') and n.get('agent_id')}),
        })
    return summary


def _chain_node_spec(node):
    allowed = ('name', 'addr', 'connector', 'dialer', 'username', 'password',
               'server_name', 'insecure', 'nodelay', 'interface')
    return {k: node[k] for k in allowed if k in node}


class GostStoreMixin:
    def _gost_capability(self, db, agent_id):
        agent = self._job_agent(db, agent_id)
        self._runtime_capability(agent, 'gost.apply')
        return agent

    def _compile_agent_gost_spec(self, db, agent_id):
        """Assemble the complete desired go-gost spec for `agent_id`."""
        forward_rows = db.execute(
            'SELECT * FROM forward_rules WHERE agent_id=? AND enabled=1 ORDER BY listen_port, id',
            (agent_id,),
        ).fetchall()

        all_chains = {
            row['id']: row
            for row in db.execute('SELECT * FROM tunnel_chains WHERE enabled=1').fetchall()
        }
        decrypted_hops = {}
        for cid, row in all_chains.items():
            decrypted_hops[cid] = self._decrypt_spec(db, row['hops'])

        group_rows = {
            row['id']: row
            for row in db.execute('SELECT * FROM best_exit_groups WHERE agent_id=?', (agent_id,)).fetchall()
        }

        referenced_chains = {}
        referenced_groups = set()
        forwards_out = []
        used_bindings = []

        # Guard against port collisions with this agent's sing-box deployment or legacy chain.
        dep_row = db.execute(
            '''SELECT d.settings FROM deployments d JOIN jobs j ON j.id=d.job_id
               WHERE d.agent_id=? AND NOT (j.type IN ('deployment.remove','landing.remove') AND j.status='success')''',
            (agent_id,),
        ).fetchone()
        if dep_row:
            dep_settings = json.loads(dep_row['settings'])
            if 'listen_port' in dep_settings:
                used_bindings.append(('tcp', dep_settings['listen_port']))
        legacy_chain = db.execute(
            '''SELECT c.settings FROM chains c JOIN jobs j ON j.id=c.job_id
               WHERE c.agent_id=? AND NOT (j.type='chain.remove' AND j.status='success')''',
            (agent_id,),
        ).fetchone()
        if legacy_chain:
            used_bindings.append(('tcp', json.loads(legacy_chain['settings'])['listen_port']))

        for row in forward_rows:
            transports = _normalize_transports(row['protocol'])
            for transport in transports:
                if (transport, row['listen_port']) in used_bindings:
                    raise JobConflict()
                used_bindings.append((transport, row['listen_port']))
            opts = json.loads(row['settings'])
            chain_name = ''
            if row['chain_id']:
                chain_row = all_chains.get(row['chain_id'])
                if not chain_row or chain_row['entry_agent_id'] != agent_id:
                    raise JobConflict()
                chain_name = chain_row['name']
                referenced_chains.setdefault(row['chain_id'], None)
            if row['exit_group_id']:
                if row['exit_group_id'] not in group_rows:
                    raise JobConflict()
                referenced_groups.add(row['exit_group_id'])
                grp = group_rows[row['exit_group_id']]
                for item in json.loads(grp['exits']):
                    if item.get('chain') and item['chain'] in all_chains:
                        referenced_chains.setdefault(item['chain'], None)
            forwards_out.append({
                'id': row['id'],
                'name': row['name'],
                'listen': row['listen'],
                'listen_port': row['listen_port'],
                'protocol': row['protocol'],
                'targets': json.loads(row['targets']),
                'chain': chain_name,
                'exit_group': row['exit_group_id'],
                'strategy': opts.get('strategy', 'fifo'),
                'max_fails': opts.get('max_fails', 1),
                'fail_timeout': opts.get('fail_timeout', 10),
                'proxy_protocol': opts.get('proxy_protocol', 0),
                'interface': opts.get('interface', ''),
                'enabled': True,
            })

        # Any tunnel_chain starting on this agent or traversing this agent as a managed middle relay
        relay_services_out = []
        for cid, row in all_chains.items():
            hops = decrypted_hops[cid]
            if row['entry_agent_id'] == agent_id:
                referenced_chains.setdefault(cid, None)
            for idx, hop in enumerate(hops):
                for node in hop.get('nodes') or []:
                    if node.get('serve_on_agent') and node.get('agent_id') == agent_id:
                        _, listen_port = validate_host_port(node['addr'], 'relay addr')
                        listener_type = node.get('dialer', 'tcp')
                        proto = 'udp' if listener_type in ('kcp', 'quic') else 'tcp'
                        if (proto, listen_port) in used_bindings:
                            raise JobConflict()
                        used_bindings.append((proto, listen_port))
                        next_chain_name = ''
                        if idx + 1 < len(hops):
                            next_chain_id = f"{cid}_rem_{idx + 1}"
                            next_chain_name = f"{row['name']}_hop{idx + 1}"
                            referenced_chains[next_chain_id] = (next_chain_name, hops[idx + 1:])
                        relay_services_out.append({
                            'id': f"{cid}_{idx}_{node['name']}"[:48],
                            'name': f"relay_{cid[:8]}_{idx}_{node['name']}"[:48],
                            'listen': node.get('listen', '::'),
                            'listen_port': listen_port,
                            'handler': node.get('connector', 'relay'),
                            'listener': listener_type,
                            'chain': next_chain_name,
                            'username': node.get('username', ''),
                            'password': node.get('password', ''),
                            'nodelay': node.get('nodelay', True),
                        })

        chains_out = []
        for ref_id, sub_val in referenced_chains.items():
            if sub_val is not None:
                sub_name, sub_hops = sub_val
                chains_out.append({
                    'id': ref_id[:48],
                    'name': sub_name[:64],
                    'hops': [{
                        'name': h['name'],
                        'interface': h.get('interface', ''),
                        'strategy': h.get('strategy', 'fifo'),
                        'max_fails': h.get('max_fails', 1),
                        'fail_timeout': h.get('fail_timeout', 10),
                        'nodes': [_chain_node_spec(n) for n in h['nodes']],
                    } for h in sub_hops],
                })
            else:
                row = all_chains[ref_id]
                chains_out.append({
                    'id': row['id'],
                    'name': row['name'],
                    'hops': [{
                        'name': h['name'],
                        'interface': h.get('interface', ''),
                        'strategy': h.get('strategy', 'fifo'),
                        'max_fails': h.get('max_fails', 1),
                        'fail_timeout': h.get('fail_timeout', 10),
                        'nodes': [_chain_node_spec(n) for n in h['nodes']],
                    } for h in decrypted_hops[ref_id]],
                })

        groups_out = []
        for row in group_rows.values():
            if row['id'] in referenced_groups or forwards_out:
                groups_out.append({
                    'id': row['id'],
                    'name': row['name'],
                    'probe_interval': row['probe_interval'],
                    'confirmation_rounds': row['confirmation_rounds'],
                    'cooldown_seconds': row['cooldown_seconds'],
                    'min_advantage_ms': row['min_advantage_ms'],
                    'min_advantage_ratio': row['min_advantage_ratio'],
                    'selected_exit_id': row['active_exit_id'],
                    'exits': json.loads(row['exits']),
                })

        return {
            'forwards': forwards_out,
            'chains': chains_out,
            'relay_services': relay_services_out,
            'best_exit_groups': groups_out,
        }

    def _sync_agent_gost(self, db, agent_id, request_id, *, require_capable=True):
        agent = self._job_agent(db, agent_id)
        metadata = json.loads(agent['metadata'])
        if require_capable:
            self._runtime_capability(agent, 'gost.apply')
        elif metadata.get('gost_protocol_version') != 1:
            return None

        spec = self._compile_agent_gost_spec(db, agent_id)
        has_items = bool(spec['forwards'] or spec['chains'] or spec['relay_services'] or spec['best_exit_groups'])
        state = db.execute('SELECT * FROM gost_agent_states WHERE agent_id=?', (agent_id,)).fetchone()
        if not has_items and not state:
            return None

        action = 'gost.apply' if has_items else 'gost.remove'
        validate_gost_spec(action, spec)
        next_rev = (state['revision'] if state else 0) + 1
        state_id = hashlib.sha256(('gost:' + agent_id).encode('utf-8')).hexdigest()[:32]
        payload = {'deployment_id': state_id, 'revision': next_rev, 'spec_hash': spec_hash(spec)}
        job = self._enqueue_job(db, agent_id, request_id, action, payload)
        cipher = self._cipher(db)
        encrypted = cipher.encrypt(json.dumps(spec).encode('utf-8')).decode('utf-8')
        db.execute('UPDATE jobs SET secret_payload=? WHERE id=?', (encrypted, job['id']))
        db.execute(
            '''INSERT INTO gost_agent_states(agent_id, revision, job_id, secret_spec, updated_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(agent_id) DO UPDATE SET
                 revision=excluded.revision, job_id=excluded.job_id,
                 secret_spec=excluded.secret_spec, updated_at=excluded.updated_at''',
            (agent_id, next_rev, job['id'], encrypted, self.clock()),
        )
        return {'job_id': job['id'], 'action': action, 'revision': next_rev}

    def _forward_view(self, db, row):
        traffic = db.execute(
            'SELECT rx_bytes,tx_bytes,total_bytes,updated_at FROM traffic_counters WHERE agent_id=? AND resource_key=?',
            (row['agent_id'], 'forward:' + row['id']),
        ).fetchone()
        job = db.execute('SELECT status,error,type FROM jobs WHERE id=?', (row['job_id'],)).fetchone() if row['job_id'] else None
        opts = json.loads(row['settings'])
        return {
            'id': row['id'],
            'agent_id': row['agent_id'],
            'name': row['name'],
            'listen': row['listen'],
            'listen_port': row['listen_port'],
            'protocol': row['protocol'],
            'mode': row['mode'],
            'chain_id': row['chain_id'],
            'exit_group_id': row['exit_group_id'],
            'targets': json.loads(row['targets']),
            'strategy': opts.get('strategy', 'fifo'),
            'max_fails': opts.get('max_fails', 1),
            'fail_timeout': opts.get('fail_timeout', 10),
            'proxy_protocol': opts.get('proxy_protocol', 0),
            'interface': opts.get('interface', ''),
            'rewrite_subscription': bool(opts.get('rewrite_subscription', False)),
            'enabled': bool(row['enabled']),
            'revision': row['revision'],
            'job_id': row['job_id'],
            'job_status': job['status'] if job else None,
            'job_error': job['error'] if job else None,
            'rx_bytes': traffic['rx_bytes'] if traffic else 0,
            'tx_bytes': traffic['tx_bytes'] if traffic else 0,
            'total_bytes': traffic['total_bytes'] if traffic else 0,
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }

    def list_forwards(self, agent_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent_id,)).fetchone():
                raise JobNotFound()
            self._expire_jobs(db, agent_id)
            rows = db.execute(
                'SELECT * FROM forward_rules WHERE agent_id=? ORDER BY listen_port, created_at, id',
                (agent_id,),
            ).fetchall()
            return [self._forward_view(db, row) for row in rows]

    def create_forward(self, agent_id, request_id, data):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._gost_capability(db, agent_id)
            self._expire_jobs(db, agent_id)
            existing_job = db.execute('SELECT id FROM jobs WHERE agent_id=? AND request_id=?', (agent_id, request_id)).fetchone()
            existing_rule = db.execute('SELECT * FROM forward_rules WHERE agent_id=? AND request_id=?', (agent_id, request_id)).fetchone()
            if existing_job and existing_rule:
                return self._forward_view(db, existing_rule)
            if existing_job or existing_rule:
                raise JobConflict()

            mode = data.get('mode', 'direct')
            chain_id = data.get('chain_id', '')
            exit_group_id = data.get('exit_group_id', '')
            if chain_id:
                ch = db.execute('SELECT entry_agent_id FROM tunnel_chains WHERE id=? AND enabled=1', (chain_id,)).fetchone()
                if not ch or ch['entry_agent_id'] != agent_id:
                    raise JobConflict()
            if mode == 'best_exit' or exit_group_id:
                grp = db.execute('SELECT agent_id FROM best_exit_groups WHERE id=?', (exit_group_id,)).fetchone()
                if not grp or grp['agent_id'] != agent_id:
                    raise JobConflict()
                mode = 'best_exit'

            now = self.clock()
            rule_id = uuid.uuid4().hex
            opts = {
                'strategy': data.get('strategy', 'fifo'),
                'max_fails': data.get('max_fails', 1),
                'fail_timeout': data.get('fail_timeout', 10),
                'proxy_protocol': data.get('proxy_protocol', 0),
                'interface': data.get('interface', ''),
                'rewrite_subscription': bool(data.get('rewrite_subscription', False)),
            }
            if db.execute('SELECT 1 FROM forward_rules WHERE agent_id=? AND name=?', (agent_id, data['name'])).fetchone():
                raise JobConflict()
            db.execute(
                '''INSERT INTO forward_rules(
                       id,agent_id,name,listen,listen_port,protocol,mode,chain_id,exit_group_id,
                       targets,settings,enabled,revision,job_id,request_id,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    rule_id, agent_id, data['name'], data.get('listen', '::'), data['listen_port'],
                    data.get('protocol', 'tcp+udp'), mode, chain_id, exit_group_id,
                    json.dumps(data.get('targets', [])), json.dumps(opts),
                    int(bool(data.get('enabled', True))), 1, '', request_id, now, now,
                ),
            )
            sync = self._sync_agent_gost(db, agent_id, request_id)
            if sync:
                db.execute('UPDATE forward_rules SET job_id=? WHERE id=?', (sync['job_id'], rule_id))
            self._audit(db, 'forward_created', agent_id)
            return self._forward_view(db, db.execute('SELECT * FROM forward_rules WHERE id=?', (rule_id,)).fetchone())

    def set_forward_enabled(self, rule_id, enabled, request_id, *, agent_id=None):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM forward_rules WHERE id=?', (rule_id,)).fetchone()
            if not row or (agent_id is not None and row['agent_id'] != agent_id):
                raise JobNotFound()
            target_agent = row['agent_id']
            self._gost_capability(db, target_agent)
            self._expire_jobs(db, target_agent)
            if bool(row['enabled']) == bool(enabled):
                return self._forward_view(db, row)
            now = self.clock()
            db.execute(
                'UPDATE forward_rules SET enabled=?,revision=revision+1,updated_at=? WHERE id=?',
                (int(bool(enabled)), now, rule_id),
            )
            sync = self._sync_agent_gost(db, target_agent, request_id)
            if sync:
                db.execute('UPDATE forward_rules SET job_id=? WHERE id=?', (sync['job_id'], rule_id))
            self._audit(db, 'forward_toggled', target_agent)
            return self._forward_view(db, db.execute('SELECT * FROM forward_rules WHERE id=?', (rule_id,)).fetchone())

    def set_forward_rewrite_subscription(self, rule_id, rewrite_subscription, *, agent_id=None):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM forward_rules WHERE id=?', (rule_id,)).fetchone()
            if not row or (agent_id is not None and row['agent_id'] != agent_id):
                raise JobNotFound()
            opts = json.loads(row['settings']) if row['settings'] else {}
            opts['rewrite_subscription'] = bool(rewrite_subscription)
            now = self.clock()
            db.execute(
                'UPDATE forward_rules SET settings=?,updated_at=? WHERE id=?',
                (json.dumps(opts), now, rule_id),
            )
            self._audit(db, 'forward_subscription_updated', row['agent_id'])
            return self._forward_view(db, db.execute('SELECT * FROM forward_rules WHERE id=?', (rule_id,)).fetchone())

    def delete_forward(self, agent_id, rule_id, request_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM forward_rules WHERE id=? AND agent_id=?', (rule_id, agent_id)).fetchone()
            if not row:
                raise JobNotFound()
            self._gost_capability(db, agent_id)
            self._expire_jobs(db, agent_id)
            db.execute('DELETE FROM forward_rules WHERE id=?', (rule_id,))
            sync = self._sync_agent_gost(db, agent_id, request_id)
            self._audit(db, 'forward_deleted', agent_id)
            return {'status': 'ok', 'deleted_id': rule_id, 'sync': sync}

    def list_active_relays(self):
        from proxyforge.control.control_store import _extract_public_ips

        with self.connection() as db:
            rows = db.execute(
                '''SELECT f.*, a.name AS agent_name, a.observed_ip, a.metadata AS agent_metadata,
                          a.last_seen, a.revoked_at
                   FROM forward_rules f JOIN agents a ON a.id=f.agent_id
                   WHERE f.enabled=1 AND a.revoked_at IS NULL
                   ORDER BY f.agent_id, f.listen_port'''
            ).fetchall()
            out = []
            for row in rows:
                try:
                    meta = json.loads(row['agent_metadata']) if row['agent_metadata'] else {}
                except Exception:
                    meta = {}
                ipv4, ipv6 = _extract_public_ips(meta.get('addresses', []), row['observed_ip'] or '')
                listen_host = ipv4 or ipv6 or row['observed_ip']
                try:
                    opts = json.loads(row['settings']) if row['settings'] else {}
                except Exception:
                    opts = {}
                entry = {
                    'id': row['id'],
                    'agent_id': row['agent_id'],
                    'agent_name': row['agent_name'],
                    'name': row['name'],
                    'listen_host': listen_host,
                    'listen_port': row['listen_port'],
                    'protocol': row['protocol'],
                    'mode': row['mode'],
                    'rewrite_subscription': bool(opts.get('rewrite_subscription', False)),
                    'targets': json.loads(row['targets']),
                }
                if row['mode'] == 'best_exit' and row['exit_group_id']:
                    grp = db.execute('SELECT exits, active_exit_id FROM best_exit_groups WHERE id=?', (row['exit_group_id'],)).fetchone()
                    if grp:
                        exits = json.loads(grp['exits'])
                        chosen = next((e for e in exits if e['id'] == grp['active_exit_id']), exits[0] if exits else None)
                        if chosen:
                            entry['targets'] = [{'addr': chosen['addr'], 'name': chosen.get('name', '')}]
                out.append(entry)
            return out

    def create_tunnel_chain(self, request_id, name, entry_agent_id, hops):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._gost_capability(db, entry_agent_id)
            if db.execute('SELECT 1 FROM tunnel_chains WHERE name=?', (name,)).fetchone():
                raise JobConflict()
            relay_agents = set()
            for hop in hops:
                for node in hop.get('nodes') or []:
                    if node.get('serve_on_agent') and node.get('agent_id'):
                        self._gost_capability(db, node['agent_id'])
                        relay_agents.add(node['agent_id'])

            chain_id = uuid.uuid4().hex
            now = self.clock()
            summary = _sanitize_hops_summary(hops)
            # Validate compiled candidate specs before persisting chain permanently
            cipher = self._cipher(db)
            encrypted_hops = cipher.encrypt(json.dumps(hops).encode('utf-8')).decode('utf-8')
            db.execute(
                '''INSERT INTO tunnel_chains(id,name,entry_agent_id,hops,summary,revision,enabled,created_at,updated_at)
                   VALUES(?,?,?,?,?,1,1,?,?)''',
                (chain_id, name, entry_agent_id, encrypted_hops, json.dumps(summary), now, now),
            )
            sync_targets = sorted({entry_agent_id, *relay_agents})
            for idx, aid in enumerate(sync_targets):
                req = request_id if aid == entry_agent_id else hashlib.sha256(f'{request_id}:{idx}:{aid}'.encode()).hexdigest()[:32]
                self._sync_agent_gost(db, aid, req)
            self._audit(db, 'tunnel_chain_created', entry_agent_id)
            return self._tunnel_chain_view(db.execute('SELECT * FROM tunnel_chains WHERE id=?', (chain_id,)).fetchone())

    def _tunnel_chain_view(self, row):
        return {
            'id': row['id'],
            'name': row['name'],
            'entry_agent_id': row['entry_agent_id'],
            'hops': json.loads(row['summary']),
            'revision': row['revision'],
            'enabled': bool(row['enabled']),
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }

    def list_tunnel_chains(self):
        with self.connection() as db:
            rows = db.execute('SELECT * FROM tunnel_chains ORDER BY created_at DESC, id').fetchall()
            return [self._tunnel_chain_view(row) for row in rows]

    def delete_tunnel_chain(self, chain_id, request_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM tunnel_chains WHERE id=?', (chain_id,)).fetchone()
            if not row:
                raise JobNotFound()
            if db.execute('SELECT 1 FROM forward_rules WHERE chain_id=?', (chain_id,)).fetchone():
                raise JobConflict()
            summary = json.loads(row['summary'])
            relay_agents = {aid for h in summary for aid in h.get('relay_agent_ids', [])}
            affected = sorted({row['entry_agent_id'], *relay_agents})
            db.execute('DELETE FROM tunnel_chains WHERE id=?', (chain_id,))
            for idx, aid in enumerate(affected):
                req = request_id if idx == 0 else hashlib.sha256(f'{request_id}:{idx}:{aid}'.encode()).hexdigest()[:32]
                self._sync_agent_gost(db, aid, req, require_capable=False)
            self._audit(db, 'tunnel_chain_deleted', row['entry_agent_id'])
            return {'status': 'ok', 'deleted_id': chain_id}

    def _best_exit_view(self, row):
        raw_metrics = json.loads(row['metrics']) if row['metrics'] else {}
        exits_metrics = raw_metrics.get('exits', raw_metrics) if isinstance(raw_metrics, dict) else {}
        state = raw_metrics.get('state', {}) if isinstance(raw_metrics, dict) else {}
        return {
            'id': row['id'],
            'name': row['name'],
            'agent_id': row['agent_id'],
            'probe_interval': row['probe_interval'],
            'confirmation_rounds': row['confirmation_rounds'],
            'cooldown_seconds': row['cooldown_seconds'],
            'min_advantage_ms': row['min_advantage_ms'],
            'min_advantage_ratio': row['min_advantage_ratio'],
            'exits': json.loads(row['exits']),
            'active_exit_id': row['active_exit_id'],
            'candidate_exit_id': state.get('candidate_exit_id', ''),
            'candidate_rounds': state.get('candidate_rounds', 0),
            'last_probe_at': row['last_probe_at'],
            'last_switch_at': row['last_switch_at'],
            'metrics': exits_metrics,
            'revision': row['revision'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }

    def list_best_exit_groups(self, agent_id=None):
        with self.connection() as db:
            if agent_id is not None:
                if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent_id,)).fetchone():
                    raise JobNotFound()
                rows = db.execute('SELECT * FROM best_exit_groups WHERE agent_id=? ORDER BY created_at DESC, id', (agent_id,)).fetchall()
            else:
                rows = db.execute('SELECT * FROM best_exit_groups ORDER BY created_at DESC, id').fetchall()
            return [self._best_exit_view(row) for row in rows]

    def create_best_exit_group(self, agent_id, request_id, data):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._gost_capability(db, agent_id)
            if db.execute('SELECT 1 FROM best_exit_groups WHERE name=?', (data['name'],)).fetchone():
                raise JobConflict()
            exits = data['exits']
            selected = data.get('selected_exit_id') or exits[0]['id']
            group_id = uuid.uuid4().hex
            now = self.clock()
            db.execute(
                '''INSERT INTO best_exit_groups(
                       id,name,agent_id,probe_interval,confirmation_rounds,cooldown_seconds,
                       min_advantage_ms,min_advantage_ratio,exits,active_exit_id,metrics,
                       revision,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    group_id, data['name'], agent_id, data.get('probe_interval', 15),
                    data.get('confirmation_rounds', 3), data.get('cooldown_seconds', 30),
                    data.get('min_advantage_ms', 20.0), data.get('min_advantage_ratio', 0.15),
                    json.dumps(exits), selected, json.dumps({'exits': {}, 'state': {
                        'current_exit_id': selected, 'candidate_exit_id': '',
                        'candidate_rounds': 0, 'last_switch_at': 0.0,
                    }}),
                    1, now, now,
                ),
            )
            self._sync_agent_gost(db, agent_id, request_id)
            self._audit(db, 'best_exit_created', agent_id)
            return self._best_exit_view(db.execute('SELECT * FROM best_exit_groups WHERE id=?', (group_id,)).fetchone())

    def evaluate_best_exit_group(self, group_id, probes, *, request_id=None, now=None):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM best_exit_groups WHERE id=?', (group_id,)).fetchone()
            if not row:
                raise JobNotFound()
            ts = float(self.clock() if now is None else now)
            stored = json.loads(row['metrics']) if row['metrics'] else {}
            prev_state = dict(stored.get('state') or {})
            if not prev_state.get('current_exit_id'):
                prev_state['current_exit_id'] = row['active_exit_id']

            manager = BestExitManager()
            manager._state[group_id] = prev_state
            group_spec = {
                'id': row['id'],
                'name': row['name'],
                'probe_interval': row['probe_interval'],
                'confirmation_rounds': row['confirmation_rounds'],
                'cooldown_seconds': row['cooldown_seconds'],
                'min_advantage_ms': row['min_advantage_ms'],
                'min_advantage_ratio': row['min_advantage_ratio'],
                'selected_exit_id': row['active_exit_id'],
                'exits': json.loads(row['exits']),
            }
            decision = manager.evaluate(group_spec, probes, now=ts)
            new_metrics = {
                'exits': decision['metrics'],
                'state': manager._state[group_id],
            }
            new_switch_at = ts if decision['switched'] else row['last_switch_at']
            db.execute(
                '''UPDATE best_exit_groups SET
                     active_exit_id=?, last_probe_at=?, last_switch_at=?, metrics=?,
                     revision=revision+CASE WHEN ? THEN 1 ELSE 0 END, updated_at=?
                   WHERE id=?''',
                (decision['selected_exit_id'], ts, new_switch_at, json.dumps(new_metrics),
                 int(decision['switched']), ts, group_id),
            )
            sync = None
            if decision['switched']:
                req = request_id or uuid.uuid4().hex
                sync = self._sync_agent_gost(db, row['agent_id'], req, require_capable=False)
                self._audit(db, 'best_exit_switched', row['agent_id'])
            updated = db.execute('SELECT * FROM best_exit_groups WHERE id=?', (group_id,)).fetchone()
            return {'decision': decision, 'group': self._best_exit_view(updated), 'sync': sync}

    def delete_best_exit_group(self, group_id, request_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM best_exit_groups WHERE id=?', (group_id,)).fetchone()
            if not row:
                raise JobNotFound()
            if db.execute('SELECT 1 FROM forward_rules WHERE exit_group_id=?', (group_id,)).fetchone():
                raise JobConflict()
            db.execute('DELETE FROM best_exit_groups WHERE id=?', (group_id,))
            self._sync_agent_gost(db, row['agent_id'], request_id, require_capable=False)
            self._audit(db, 'best_exit_deleted', row['agent_id'])
            return {'status': 'ok', 'deleted_id': group_id}

    def record_agent_traffic(self, token, instance_id, batch_id, sequence, items):
        from proxyforge.control.control_store import UnauthorizedAgent
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent_id = self._authenticate(db, token)
            agent = db.execute('SELECT instance_id FROM agents WHERE id=?', (agent_id,)).fetchone()
            if not agent or agent['instance_id'] != instance_id:
                raise UnauthorizedAgent()
            if db.execute('SELECT 1 FROM traffic_batches WHERE agent_id=? AND batch_id=?', (agent_id, batch_id)).fetchone():
                return {'status': 'ok', 'deduplicated': True, 'accepted': 0}

            now = self.clock()
            accepted = 0
            touched_rules = set()
            sub_user_deltas = {}
            for item in items:
                rx_delta = max(0, int(item['rx_delta']))
                tx_delta = max(0, int(item['tx_delta']))
                total_delta = rx_delta + tx_delta
                fwd_rule_id = item.get('forward_rule_id', '')
                if fwd_rule_id:
                    touched_rules.add(fwd_rule_id)
                rkey = str(item['resource_key'] or '')
                if rkey.startswith('subuser:'):
                    mid_text = rkey.split(':', 1)[1]
                    if mid_text.isdigit():
                        mid = int(mid_text)
                        if 1 <= mid <= 65535:
                            prev_rx, prev_tx = sub_user_deltas.get(mid, (0, 0))
                            sub_user_deltas[mid] = (prev_rx + rx_delta, prev_tx + tx_delta)
                db.execute(
                    '''INSERT INTO traffic_counters(
                           id,agent_id,resource_key,forward_rule_id,rx_bytes,tx_bytes,total_bytes,
                           last_raw_rx,last_raw_tx,last_epoch,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(agent_id, resource_key) DO UPDATE SET
                           forward_rule_id=CASE WHEN excluded.forward_rule_id!='' THEN excluded.forward_rule_id ELSE traffic_counters.forward_rule_id END,
                           rx_bytes=traffic_counters.rx_bytes + excluded.rx_bytes,
                           tx_bytes=traffic_counters.tx_bytes + excluded.tx_bytes,
                           total_bytes=traffic_counters.total_bytes + excluded.total_bytes,
                           last_raw_rx=excluded.last_raw_rx,
                           last_raw_tx=excluded.last_raw_tx,
                           last_epoch=excluded.last_epoch,
                           updated_at=excluded.updated_at''',
                    (
                        uuid.uuid4().hex, agent_id, item['resource_key'], fwd_rule_id,
                        rx_delta, tx_delta, total_delta,
                        max(0, int(item['raw_rx'])), max(0, int(item['raw_tx'])), item.get('epoch', ''), now,
                    ),
                )
                accepted += 1
            db.execute(
                'INSERT INTO traffic_batches(agent_id,batch_id,sequence,accepted_count,created_at) VALUES(?,?,?,?,?)',
                (agent_id, batch_id, sequence, accepted, now),
            )
            db.execute(
                '''DELETE FROM traffic_batches WHERE agent_id=? AND batch_id NOT IN (
                     SELECT batch_id FROM traffic_batches WHERE agent_id=? ORDER BY created_at DESC LIMIT 2000
                   )''',
                (agent_id, agent_id),
            )
            if touched_rules and hasattr(self, '_sync_user_forward_usage'):
                self._sync_user_forward_usage(db, touched_rules)
            if sub_user_deltas and hasattr(self, '_apply_sub_user_metering_deltas'):
                self._apply_sub_user_metering_deltas(db, sub_user_deltas, now)
            return {'status': 'ok', 'deduplicated': False, 'accepted': accepted}

    def get_agent_traffic(self, agent_id):
        with self.connection() as db:
            if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent_id,)).fetchone():
                raise JobNotFound()
            rows = db.execute(
                'SELECT resource_key,forward_rule_id,rx_bytes,tx_bytes,total_bytes,last_epoch,updated_at '
                'FROM traffic_counters WHERE agent_id=? ORDER BY resource_key',
                (agent_id,),
            ).fetchall()
            counters = [dict(row) for row in rows]
            return {
                'agent_id': agent_id,
                'rx_bytes': sum(c['rx_bytes'] for c in counters),
                'tx_bytes': sum(c['tx_bytes'] for c in counters),
                'total_bytes': sum(c['total_bytes'] for c in counters),
                'counters': counters,
            }

    def traffic_summary(self):
        with self.connection() as db:
            rows = db.execute(
                '''SELECT a.id AS agent_id, a.name AS agent_name,
                          COALESCE(SUM(t.rx_bytes), 0) AS rx_bytes,
                          COALESCE(SUM(t.tx_bytes), 0) AS tx_bytes,
                          COALESCE(SUM(t.total_bytes), 0) AS total_bytes
                   FROM agents a LEFT JOIN traffic_counters t ON t.agent_id=a.id
                   WHERE a.revoked_at IS NULL
                   GROUP BY a.id ORDER BY total_bytes DESC, a.name'''
            ).fetchall()
            agents = [dict(row) for row in rows]
            return {
                'rx_bytes': sum(a['rx_bytes'] for a in agents),
                'tx_bytes': sum(a['tx_bytes'] for a in agents),
                'total_bytes': sum(a['total_bytes'] for a in agents),
                'agents': agents,
            }
