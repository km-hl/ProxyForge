"""Secret-free management inventory, including deployed and adopted assets."""
import json
import uuid

from agent.adoption import valid_adopt_output
from agent.deployment_spec import node_name
from agent.landing_spec import METHOD
from proxyforge.control.deployment_store import PROJECTABLE_LANDING_PROTOCOLS
from proxyforge.control.job_store import JobConflict, JobNotFound

_KIND_ORDER = {'direct': 0, 'chain': 1, 'adopted': 2}
_AUXILIARY_PROTOCOLS = frozenset(('caddy-site', 'dokodemo-door'))
_LOOPBACK_HOSTS = frozenset(('127.0.0.1', '::1', 'localhost'))


def _match_manual_node(row, creds, agent_ips_set, manual_nodes):
    """Match a discovered/adopted host endpoint against existing manual nodes without leaking secrets."""
    if not manual_nodes:
        return '', ''
    ep_port = int(row['listen_port'] or 0)
    ep_sni = str(row['sni'] or '').strip().lower()
    ep_uuid = str((creds or {}).get('uuid') or '').strip().lower()
    ep_pw = str((creds or {}).get('password') or '').strip()
    ep_rpub = str((creds or {}).get('reality_public_key') or '').strip()
    ep_adoptable = bool(row['adoptable'])

    # Pass 1: high-precision credential fingerprint match (works even behind SNI-mux / port-forwarding).
    if ep_rpub or ep_uuid or len(ep_pw) >= 6:
        for m in manual_nodes:
            if not isinstance(m, dict):
                continue
            m_name = str(m.get('name') or '').strip()
            if not m_name:
                continue
            m_srv = str(m.get('server') or '').strip().lower()
            try:
                m_port = int(m.get('port') or 0)
            except (TypeError, ValueError):
                m_port = 0
            m_uuid = str(m.get('uuid') or '').strip().lower()
            m_pw = str(m.get('password') or '').strip()
            m_rpub = str(((m.get('reality-opts') or {}).get('public-key')) or '').strip()
            m_sni = str(m.get('servername') or m.get('sni') or '').strip().lower()
            host_or_sni_ok = (
                (m_srv and m_srv in agent_ips_set)
                or (ep_sni and (m_sni == ep_sni or m_srv == ep_sni))
                or (ep_port and m_port == ep_port)
            )
            if ep_rpub and m_rpub == ep_rpub and (not ep_uuid or m_uuid == ep_uuid):
                return m_name, 'credential'
            if ep_uuid and m_uuid == ep_uuid and host_or_sni_ok:
                return m_name, 'credential'
            if len(ep_pw) >= 6 and m_pw == ep_pw and host_or_sni_ok:
                return m_name, 'credential'

    # Pass 2: endpoint host/SNI + listen_port match for adoptable endpoints.
    if ep_adoptable and ep_port:
        for m in manual_nodes:
            if not isinstance(m, dict):
                continue
            m_name = str(m.get('name') or '').strip()
            if not m_name:
                continue
            m_srv = str(m.get('server') or '').strip().lower()
            try:
                m_port = int(m.get('port') or 0)
            except (TypeError, ValueError):
                continue
            if m_port != ep_port:
                continue
            m_sni = str(m.get('servername') or m.get('sni') or '').strip().lower()
            if (m_srv and m_srv in agent_ips_set) or (ep_sni and (m_srv == ep_sni or m_sni == ep_sni)):
                return m_name, 'endpoint'
    return '', ''


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
        active_adopted_keys = [
            row['source_key']
            for row in db.execute(
                "SELECT source_key FROM adopted_node_secrets WHERE agent_id=? AND adopted_status IN ('adopted','disabled')",
                (agent_id,),
            )
        ]
        keep_keys = list(dict.fromkeys(seen_keys + active_adopted_keys))
        if keep_keys:
            placeholders = ','.join('?' for _ in keep_keys)
            db.execute(
                f'DELETE FROM adopted_nodes WHERE agent_id=? AND source_key NOT IN ({placeholders})',
                (agent_id, *keep_keys),
            )
            db.execute(
                f'DELETE FROM adopted_node_secrets WHERE agent_id=? AND source_key NOT IN ({placeholders})',
                (agent_id, *keep_keys),
            )
        else:
            db.execute('DELETE FROM adopted_nodes WHERE agent_id=?', (agent_id,))
            db.execute('DELETE FROM adopted_node_secrets WHERE agent_id=?', (agent_id,))
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

    def record_adoption_secrets(self, token, instance_id, items):
        from proxyforge.control.control_store import UnauthorizedAgent
        if not isinstance(items, list) or len(items) > 32:
            raise ValueError('Invalid adoption secrets payload')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent_id = self._authenticate(db, token)
            agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
            if not agent or agent['instance_id'] != instance_id:
                raise UnauthorizedAgent()
            cipher = self._cipher(db)
            now = self.clock()
            saved = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                sk = str(item.get('source_key') or '').strip()
                if not sk:
                    continue
                creds = item.get('credentials') if isinstance(item.get('credentials'), dict) else {}
                inbound = item.get('inbound') if isinstance(item.get('inbound'), dict) else {}
                if not creds and not inbound:
                    continue
                secret_blob = cipher.encrypt(
                    json.dumps({'credentials': creds, 'inbound': inbound}).encode('utf-8')
                ).decode('utf-8')
                existing = db.execute(
                    'SELECT adopted_status,custom_name,server_override FROM adopted_node_secrets WHERE agent_id=? AND source_key=?',
                    (agent_id, sk),
                ).fetchone()
                status = existing['adopted_status'] if existing else 'discovered'
                custom_name = existing['custom_name'] if existing else ''
                server_override = existing['server_override'] if existing else ''
                db.execute(
                    '''INSERT INTO adopted_node_secrets(
                           agent_id,source_key,secret_spec,adopted_status,custom_name,server_override,updated_at
                       ) VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(agent_id, source_key) DO UPDATE SET
                           secret_spec=excluded.secret_spec,updated_at=excluded.updated_at''',
                    (agent_id, sk, secret_blob, status, custom_name, server_override, now),
                )
                saved += 1
            self._audit(db, 'adoption_secrets_recorded', agent_id)
        return {'status': 'ok', 'agent_id': agent_id, 'saved_count': saved}

    def adopt_endpoint(self, agent_id, source_key, request_id, *, custom_name='', server_override=''):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            ep = db.execute(
                'SELECT * FROM adopted_nodes WHERE agent_id=? AND source_key=?',
                (agent_id, source_key),
            ).fetchone()
            if not ep:
                raise JobNotFound()
            if not ep['adoptable']:
                raise ValueError('Endpoint is not adoptable')
            sec = db.execute(
                'SELECT * FROM adopted_node_secrets WHERE agent_id=? AND source_key=?',
                (agent_id, source_key),
            ).fetchone()
            if not sec or not sec['secret_spec']:
                raise ValueError('Missing extracted credentials for this endpoint; re-run privileged scan first')
            decrypted = self._decrypt_spec(db, sec['secret_spec'])
            if not isinstance(decrypted.get('inbound'), dict) or not decrypted['inbound'].get('listen_port'):
                raise ValueError('Endpoint inbound configuration cannot be merged into sing-box')
            final_custom_name = (custom_name or '').strip() or (sec['custom_name'] or '')
            db.execute(
                '''UPDATE adopted_node_secrets
                   SET adopted_status='adopted',
                       custom_name=CASE WHEN ? != '' THEN ? ELSE custom_name END,
                       server_override=CASE WHEN ? != '' THEN ? ELSE server_override END,
                       updated_at=?
                   WHERE agent_id=? AND source_key=?''',
                (custom_name, custom_name, server_override, server_override, self.clock(), agent_id, source_key),
            )
            self._audit(db, 'adoption_applied', agent_id)
            res = self._dispatch_aggregated_runtime(db, agent_id, request_id)
            if isinstance(res, dict):
                res['adopted_display_name'] = self._adopted_node_display_name(ep, final_custom_name)
            return res

    def set_adoption_ignored(self, agent_id, source_key, *, ignored=True):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            ep = db.execute(
                'SELECT * FROM adopted_nodes WHERE agent_id=? AND source_key=?',
                (agent_id, source_key),
            ).fetchone()
            if not ep:
                raise JobNotFound()
            existing = db.execute(
                'SELECT adopted_status,secret_spec,custom_name,server_override FROM adopted_node_secrets WHERE agent_id=? AND source_key=?',
                (agent_id, source_key),
            ).fetchone()
            if existing and existing['adopted_status'] in ('adopted', 'disabled'):
                raise ValueError('Cannot change ignore state of an adopted or disabled endpoint')
            next_status = 'ignored' if ignored else 'discovered'
            now = self.clock()
            if existing:
                db.execute(
                    'UPDATE adopted_node_secrets SET adopted_status=?, updated_at=? WHERE agent_id=? AND source_key=?',
                    (next_status, now, agent_id, source_key),
                )
            else:
                db.execute(
                    '''INSERT INTO adopted_node_secrets(
                           agent_id,source_key,secret_spec,adopted_status,custom_name,server_override,updated_at
                       ) VALUES(?,?,?,?,?,?,?)''',
                    (agent_id, source_key, '', next_status, '', '', now),
                )
            self._audit(db, 'adoption_ignored' if ignored else 'adoption_unignored', agent_id)
            return {'status': 'ok', 'source_key': source_key, 'adopted_status': next_status}

    def disable_adopted_endpoint(self, agent_id, source_key, request_id):
        from agent.adoption import MANAGED_UNIT_PREFIX, SYSTEMD_SERVICE_RE
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            ep = db.execute(
                'SELECT * FROM adopted_nodes WHERE agent_id=? AND source_key=?',
                (agent_id, source_key),
            ).fetchone()
            if not ep:
                raise JobNotFound()
            svc = (ep['service_name'] or '').strip()
            if (not svc or len(svc) > 100 or not SYSTEMD_SERVICE_RE.fullmatch(svc) or
                    svc in ('ssh.service', 'sshd.service') or svc.startswith(('systemd-', MANAGED_UNIT_PREFIX))):
                raise ValueError('Endpoint has no safely stoppable host systemd service')
            siblings = db.execute(
                'SELECT source_key FROM adopted_nodes WHERE agent_id=? AND service_name=?',
                (agent_id, svc),
            ).fetchall()
            sibling_keys = list(dict.fromkeys([source_key, *(r['source_key'] for r in siblings)]))
            for sk in sibling_keys:
                sec = db.execute(
                    'SELECT adopted_status FROM adopted_node_secrets WHERE agent_id=? AND source_key=?',
                    (agent_id, sk),
                ).fetchone()
                if sec and sec['adopted_status'] == 'adopted':
                    raise ValueError('Return the adopted endpoint before disabling its host service')
            now = self.clock()
            for sk in sibling_keys:
                db.execute(
                    '''INSERT INTO adopted_node_secrets(
                           agent_id,source_key,secret_spec,adopted_status,custom_name,server_override,updated_at
                       ) VALUES(?,?,'','disabled','','',?)
                       ON CONFLICT(agent_id, source_key) DO UPDATE SET
                           adopted_status='disabled',updated_at=excluded.updated_at''',
                    (agent_id, sk, now),
                )
            self._audit(db, 'adoption_disabled', agent_id)
            res = self._dispatch_aggregated_runtime(
                db,
                agent_id,
                request_id,
                disabled_adoptions=[{
                    'source_key': source_key,
                    'original_service': svc,
                    'original_config_path': ep['config_path'] or '',
                }],
            )
            if isinstance(res, dict):
                res['disabled_service'] = svc
                res['affected_keys'] = sibling_keys
            return res

    def return_adopted_endpoint(self, agent_id, source_key, request_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            ep = db.execute(
                'SELECT * FROM adopted_nodes WHERE agent_id=? AND source_key=?',
                (agent_id, source_key),
            ).fetchone()
            if not ep:
                raise JobNotFound()
            svc = (ep['service_name'] or '').strip()
            return_keys = [source_key]
            if svc:
                for sib in db.execute(
                    '''SELECT a.source_key
                       FROM adopted_nodes a
                       JOIN adopted_node_secrets s ON s.agent_id=a.agent_id AND s.source_key=a.source_key
                       WHERE a.agent_id=? AND a.service_name=? AND s.adopted_status='disabled' ''',
                    (agent_id, svc),
                ).fetchall():
                    if sib['source_key'] not in return_keys:
                        return_keys.append(sib['source_key'])
            now = self.clock()
            for sk in return_keys:
                db.execute(
                    "UPDATE adopted_node_secrets SET adopted_status='discovered', updated_at=? WHERE agent_id=? AND source_key=?",
                    (now, agent_id, sk),
                )
            self._audit(db, 'adoption_returned', agent_id)
            return self._dispatch_aggregated_runtime(
                db, agent_id, request_id, returned_adoptions=return_keys
            )

    @staticmethod
    def _adopted_node_display_name(ep_row, custom_name=''):
        base = (custom_name or '').strip() or f"{ep_row['tag'] or ep_row['protocol'].upper()}-{ep_row['listen_port']}"
        return node_name(ep_row['id'], base)

    def _adopted_node_names(self, db):
        rows = db.execute(
            '''SELECT a.id,a.tag,a.protocol,a.listen_port,s.custom_name
               FROM adopted_nodes a
               JOIN adopted_node_secrets s ON s.agent_id=a.agent_id AND s.source_key=a.source_key
               WHERE s.adopted_status='adopted' '''
        ).fetchall()
        return [self._adopted_node_display_name(r, r['custom_name']) for r in rows]

    def _adopted_client_nodes(self, db):
        rows = db.execute(
            '''SELECT a.*, s.secret_spec, s.custom_name, s.server_override,
                      ag.observed_ip, ag.metadata, ag.name AS agent_name
               FROM adopted_nodes a
               JOIN adopted_node_secrets s ON s.agent_id=a.agent_id AND s.source_key=a.source_key
               JOIN agents ag ON ag.id=a.agent_id
               WHERE s.adopted_status='adopted' AND ag.revoked_at IS NULL
               ORDER BY a.listen_port ASC, a.id ASC'''
        ).fetchall()
        nodes = []
        for row in rows:
            if not row['secret_spec']:
                continue
            try:
                sec = self._decrypt_spec(db, row['secret_spec'])
            except Exception:
                continue
            creds = sec.get('credentials') or {}
            view = self._view({
                'id': row['agent_id'],
                'name': row['agent_name'],
                'metadata': row['metadata'],
                'tags': '[]',
                'revoked_at': None,
                'last_seen': 0,
                'observed_ip': row['observed_ip'],
            })
            default_srv = view['public_ipv4'] or view['public_ipv6'] or row['observed_ip'] or row['sni']
            srv = (row['server_override'] or '').strip() or (
                row['sni'] if (row['tls_mode'] != 'reality' and row['sni']) else default_srv
            ) or default_srv
            if not srv:
                continue
            label = self._adopted_node_display_name(row, row['custom_name'])
            managed = {
                'type': 'adopted',
                'agent_id': row['agent_id'],
                'adoption_id': row['id'],
                'source_key': row['source_key'],
            }
            proto = row['protocol']
            port = row['listen_port']
            if proto == 'vless' and row['tls_mode'] == 'reality':
                if not creds.get('uuid') or not creds.get('reality_public_key'):
                    continue
                nodes.append({
                    'name': label,
                    'type': 'vless',
                    'server': srv,
                    'port': port,
                    'uuid': creds['uuid'],
                    'network': 'tcp',
                    'tls': True,
                    'udp': True,
                    'flow': creds.get('flow') or 'xtls-rprx-vision',
                    'servername': row['sni'] or srv,
                    'client-fingerprint': 'chrome',
                    'reality-opts': {
                        'public-key': creds['reality_public_key'],
                        'short-id': creds.get('reality_short_id', ''),
                    },
                    '_managed_by': managed,
                })
            elif proto == 'vless':
                if not creds.get('uuid'):
                    continue
                node = {
                    'name': label,
                    'type': 'vless',
                    'server': srv,
                    'port': port,
                    'uuid': creds['uuid'],
                    'network': row['network'] if row['network'] in ('tcp', 'ws', 'grpc') else 'tcp',
                    'tls': row['tls_mode'] != 'none',
                    'udp': True,
                    '_managed_by': managed,
                }
                if row['sni']:
                    node['servername'] = row['sni']
                if row['network'] == 'ws':
                    node['ws-opts'] = {
                        'path': row['ws_path'] or '/',
                        'headers': {'Host': row['sni'] or srv},
                    }
                nodes.append(node)
            elif proto == 'trojan':
                if not creds.get('password'):
                    continue
                nodes.append({
                    'name': label,
                    'type': 'trojan',
                    'server': srv,
                    'port': port,
                    'password': creds['password'],
                    'sni': row['sni'] or srv,
                    'udp': True,
                    '_managed_by': managed,
                })
            elif proto == 'anytls':
                if not creds.get('password'):
                    continue
                nodes.append({
                    'name': label,
                    'type': 'anytls',
                    'server': srv,
                    'port': port,
                    'password': creds['password'],
                    'sni': row['sni'] or srv,
                    'udp': True,
                    'client-fingerprint': 'chrome',
                    '_managed_by': managed,
                })
            elif proto == 'hysteria2':
                if not creds.get('password'):
                    continue
                node = {
                    'name': label,
                    'type': 'hysteria2',
                    'server': srv,
                    'port': port,
                    'password': creds['password'],
                    'sni': row['sni'] or srv,
                    '_managed_by': managed,
                }
                if creds.get('obfs') == 'salamander' and creds.get('obfs_password'):
                    node['obfs'] = 'salamander'
                    node['obfs-password'] = creds['obfs_password']
                nodes.append(node)
            elif proto == 'shadowsocks':
                if not creds.get('password'):
                    continue
                nodes.append({
                    'name': label,
                    'type': 'ss',
                    'server': srv,
                    'port': port,
                    'cipher': creds.get('method') or METHOD,
                    'password': creds['password'],
                    'udp': True,
                    '_managed_by': managed,
                })
        return nodes

    def list_adopted_nodes(self, agent_id=None, *, manual_nodes=None):
        with self.connection() as db:
            secrets_map = {
                (r['agent_id'], r['source_key']): dict(r)
                for r in db.execute(
                    'SELECT agent_id,source_key,secret_spec,adopted_status,custom_name,server_override FROM adopted_node_secrets'
                )
            }
            agent_ip_sets = {}
            for arow in db.execute('SELECT * FROM agents').fetchall():
                view = self._view(arow)
                ips = {
                    str(v).strip().lower()
                    for v in (view.get('public_ipv4'), view.get('public_ipv6'), arow['observed_ip'])
                    if v and str(v).strip()
                }
                agent_ip_sets[arow['id']] = ips
            cipher = None
            if any(info.get('secret_spec') for info in secrets_map.values()):
                try:
                    cipher = self._cipher(db)
                except Exception:
                    cipher = None
            if agent_id is not None:
                rows = db.execute('SELECT * FROM adopted_nodes WHERE agent_id=? ORDER BY listen_port,id', (agent_id,)).fetchall()
            else:
                rows = db.execute('SELECT * FROM adopted_nodes ORDER BY agent_id,listen_port,id').fetchall()
            result = []
            for row in rows:
                s_info = secrets_map.get((row['agent_id'], row['source_key'])) or {}
                creds = {}
                has_xray_xver = False
                if cipher is not None and s_info.get('secret_spec'):
                    try:
                        blob = json.loads(cipher.decrypt(s_info['secret_spec'].encode('utf-8')).decode('utf-8'))
                        creds = blob.get('credentials') if isinstance(blob, dict) and isinstance(blob.get('credentials'), dict) else (blob if isinstance(blob, dict) else {})
                        has_xray_xver = bool((creds or {}).get('xray_xver'))
                    except Exception:
                        creds = {}
                        has_xray_xver = False
                is_aux = bool(row['core'] == 'caddy' or row['protocol'] in _AUXILIARY_PROTOCOLS)
                matched_name, matched_reason = (
                    _match_manual_node(row, creds, agent_ip_sets.get(row['agent_id'], set()), manual_nodes)
                    if (manual_nodes and not is_aux)
                    else ('', '')
                )
                result.append({
                    **{k: row[k] for k in (
                        'id', 'agent_id', 'source_key', 'core', 'service_name', 'config_path',
                        'config_sha256', 'tag', 'protocol', 'listen', 'listen_port',
                        'tls_mode', 'sni', 'network', 'ws_path', 'discovered_at', 'updated_at',
                    )},
                    'adoptable': bool(row['adoptable']),
                    'is_auxiliary': is_aux,
                    'has_credentials': bool(s_info.get('secret_spec')),
                    'has_xray_xver': has_xray_xver,
                    'adopted_status': s_info.get('adopted_status', 'discovered'),
                    'custom_name': s_info.get('custom_name', ''),
                    'server_override': s_info.get('server_override', ''),
                    'matched_manual_name': matched_name,
                    'matched_manual_reason': matched_reason,
                })
            return result

    def managed_inventory(self, *, include_discovered=True):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT DISTINCT agent_id FROM jobs WHERE status IN ('pending','assigned','running')").fetchall():
                self._expire_jobs(db, row['agent_id'])
            agents = {}
            agent_ips = {}
            for row in db.execute('SELECT * FROM agents'):
                view = self._view(row)
                agents[row['id']] = {key: view[key] for key in ('id', 'name', 'status', 'last_seen', 'compatible')}
                agent_ips[row['id']] = view['public_ipv4'] or view['public_ipv6'] or row['observed_ip'] or view['name']
            jobs = {row['id']: dict(row) for row in db.execute('''SELECT id,type,status,error FROM jobs
                WHERE id IN (SELECT job_id FROM deployments UNION SELECT job_id FROM chains)''')}
            # Never load or decrypt secret_spec; this page also works during key recovery.
            deployments = {row['agent_id']: dict(row) for row in db.execute(
                'SELECT id,agent_id,protocol,settings,revision,job_id,updated_at FROM deployments')}
            extra_nodes = [dict(row) for row in db.execute(
                'SELECT id,agent_id,protocol,settings,revision,updated_at FROM agent_nodes')]
            chains = [dict(row) for row in db.execute(
                'SELECT id,agent_id,landing_agent_id,settings,revision,job_id,updated_at FROM chains')]
            adopted = [dict(row) for row in db.execute('SELECT * FROM adopted_nodes')]
            adopted_secrets = {
                (r['agent_id'], r['source_key']): dict(r)
                for r in db.execute(
                    'SELECT agent_id,source_key,secret_spec,adopted_status,custom_name,server_override FROM adopted_node_secrets'
                )
            }
            items = []
            direct_records = [
                (row, 'direct')
                for row in deployments.values()
                if self._is_projectable_record(row['protocol'], json.loads(row['settings']))
            ]
            for record, kind in direct_records + [(row, 'chain') for row in chains]:
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
                endpoint = settings.get('server') or (json.loads(source['settings'])['server'] if source else '')
                items.append({
                    'id': record['id'], 'kind': kind, 'name': node_name(record['id'], settings['name']),
                    'protocol': record.get('protocol', 'reality' if kind == 'chain' else ''),
                    'agent': agent, 'landing': landing, 'server': endpoint, 'port': settings['listen_port'],
                    'revision': record['revision'], 'job_id': record['job_id'], 'action': job['type'],
                    'status': job['status'], 'error': job['error'], 'removed': removed,
                    'publishable': publishable, 'blocked_by': blocked_by, 'updated_at': record['updated_at'],
                })

            for erow in extra_nodes:
                settings = json.loads(erow['settings'])
                if not self._is_projectable_record(erow['protocol'], settings):
                    continue
                agent = agents[erow['agent_id']]
                p_dep = deployments.get(erow['agent_id'])
                p_job = jobs.get(p_dep['job_id']) if p_dep else None
                j_status = p_job['status'] if p_job else 'success'
                j_type = p_job['type'] if p_job else 'landing.apply'
                j_err = p_job['error'] if p_job else None
                removed = bool(p_job and j_type.endswith('.remove') and j_status == 'success')
                publishable = (j_status == 'success' and j_type.endswith('.apply') and agent['status'] != 'revoked')
                items.append({
                    'id': erow['id'], 'kind': 'direct', 'name': node_name(erow['id'], settings['name']),
                    'protocol': erow['protocol'],
                    'agent': agent, 'landing': None, 'server': settings.get('server', ''), 'port': settings['listen_port'],
                    'revision': erow['revision'], 'job_id': p_dep['job_id'] if p_dep else '', 'action': j_type,
                    'status': j_status, 'error': j_err, 'removed': removed,
                    'publishable': publishable, 'blocked_by': [], 'updated_at': erow['updated_at'],
                })

            for row in adopted:
                agent = agents[row['agent_id']]
                s_info = adopted_secrets.get((row['agent_id'], row['source_key'])) or {}
                is_adopted_active = s_info.get('adopted_status') == 'adopted'
                if not include_discovered and not is_adopted_active:
                    continue
                has_creds = bool(s_info.get('secret_spec'))
                listen_addr = str(row['listen'] or '').strip()
                if not is_adopted_active and listen_addr in _LOOPBACK_HOSTS:
                    srv = listen_addr
                else:
                    srv = (s_info.get('server_override') or '').strip() or agent_ips.get(row['agent_id'], '')
                disp_name = (
                    self._adopted_node_display_name(row, s_info.get('custom_name', ''))
                    if is_adopted_active
                    else f"{row['tag']} [{row['core']}:{row['listen_port']}]"
                )
                items.append({
                    'id': row['id'], 'kind': 'adopted',
                    'name': disp_name,
                    'agent': agent, 'landing': None,
                    'server': srv, 'port': row['listen_port'],
                    'core': row['core'], 'protocol': row['protocol'], 'tls_mode': row['tls_mode'],
                    'sni': row['sni'], 'network': row['network'], 'ws_path': row['ws_path'],
                    'service_name': row['service_name'], 'source_key': row['source_key'],
                    'adoptable': bool(row['adoptable']),
                    'has_credentials': has_creds,
                    'adopted_status': s_info.get('adopted_status', 'discovered'),
                    'revision': 1, 'job_id': '', 'action': 'adopt.apply' if is_adopted_active else 'adopt_scan',
                    'status': 'adopted', 'error': None, 'removed': False,
                    'publishable': bool(is_adopted_active and has_creds and agent['status'] != 'revoked'),
                    'blocked_by': [], 'updated_at': row['updated_at'],
                })
            return sorted(items, key=lambda item: (item['agent']['name'], item['agent']['id'], _KIND_ORDER[item['kind']], item['id']))
