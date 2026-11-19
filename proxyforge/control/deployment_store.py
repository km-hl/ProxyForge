"""Desired deployments; secrets encrypted separately from public queue metadata."""
import base64
import json
import os
import secrets
import uuid

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from agent.deployment_spec import client_node, node_name, spec_hash, validate_settings
from agent.landing_spec import (
    LANDING_PROTOCOLS,
    METHOD,
    PROTOCOL_SPEC,
    SS2022_METHODS,
    client_node as landing_client_node,
    validate_settings as validate_landing_settings,
    validate_spec as validate_landing_spec,
)
from proxyforge.control.job_store import JobConflict, JobNotFound

PROJECTABLE_LANDING_PROTOCOLS = tuple(p for p in LANDING_PROTOCOLS if PROTOCOL_SPEC[p]['project_client'])
KEY_REF_TTL = 3600


class DeploymentKeyError(Exception):
    pass


def migrate_deployments(db):
    db.execute('ALTER TABLE jobs ADD COLUMN secret_payload TEXT')
    db.execute('''CREATE TABLE deployments (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL UNIQUE REFERENCES agents(id) ON DELETE CASCADE,
        settings TEXT NOT NULL, revision INTEGER NOT NULL, secret_spec TEXT NOT NULL,
        job_id TEXT NOT NULL, updated_at REAL NOT NULL)''')
    db.execute('INSERT INTO schema_migrations VALUES(3)')


def _generate_x25519_pair():
    key = X25519PrivateKey.generate()
    encode = lambda data: base64.urlsafe_b64encode(data).decode().rstrip('=')
    return (
        encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
    )


def new_spec(settings):
    private_key, public_key = _generate_x25519_pair()
    return {
        **settings,
        'uuid': str(uuid.uuid4()),
        'short_id': secrets.token_hex(8),
        'private_key': private_key,
        'public_key': public_key,
    }


def migrate_landings(db):
    db.execute("ALTER TABLE deployments ADD COLUMN protocol TEXT NOT NULL DEFAULT 'vless-reality'")
    db.execute('INSERT INTO schema_migrations VALUES(4)')


def _generate_landing_secrets(settings, protocol, *, pregenerated=None):
    generated = dict(pregenerated or {})
    if protocol == 'ss2022':
        method = settings.get('method', METHOD)
        key_bytes = SS2022_METHODS[method]
        if 'password' in generated and len(base64.b64decode(generated['password'], validate=True)) == key_bytes:
            return {'password': generated['password']}
        return {'password': base64.b64encode(secrets.token_bytes(key_bytes)).decode()}
    if protocol == 'reality':
        if 'reality_private_key' in generated and 'reality_public_key' in generated:
            private_key = generated['reality_private_key']
            public_key = generated['reality_public_key']
        else:
            private_key, public_key = _generate_x25519_pair()
        short_ids = settings.get('reality_short_ids') or generated.get('reality_short_ids') or [secrets.token_hex(8)]
        return {
            'uuid': generated.get('uuid') or str(uuid.uuid4()),
            'reality_private_key': private_key,
            'reality_public_key': public_key,
            'reality_short_ids': list(short_ids),
        }
    if protocol in ('trojan', 'anytls'):
        return {'password': generated.get('password') or secrets.token_urlsafe(32)}
    if protocol == 'vless-ws':
        return {'uuid': generated.get('uuid') or str(uuid.uuid4())}
    if protocol == 'hysteria2':
        result = {'password': generated.get('password') or secrets.token_urlsafe(32)}
        if settings.get('obfs') == 'salamander':
            result['obfs_password'] = generated.get('obfs_password') or secrets.token_urlsafe(24)
        return result
    raise ValueError('Unsupported landing protocol')


def _validate_hop_passwords(raw):
    if raw is None:
        return {}
    if not isinstance(raw, dict) or len(raw) > 4:
        raise ValueError('Invalid hop_passwords')
    cleaned = {}
    for k, v in raw.items():
        if k not in ('0', '1', '2', '3') or not isinstance(v, str) or len(v) > 256 or any(ord(c) < 32 for c in v):
            raise ValueError('Invalid hop_passwords entry')
        if v:
            cleaned[k] = v
    return cleaned


def _apply_outbound_and_secret_updates(spec, clean_settings, secrets_input):
    if secrets_input:
        if secrets_input.get('dns_api_token'):
            spec['dns_api_token'] = secrets_input['dns_api_token']
        if secrets_input.get('outbound_password'):
            spec['outbound_password'] = secrets_input['outbound_password']
        if 'hop_passwords' in secrets_input:
            existing_hp = dict(spec.get('hop_passwords') or {})
            existing_hp.update(_validate_hop_passwords(secrets_input.get('hop_passwords')))
            spec['hop_passwords'] = existing_hp
    if clean_settings.get('obfs') == 'salamander' and 'obfs_password' not in spec:
        spec['obfs_password'] = secrets.token_urlsafe(24)
    if clean_settings.get('obfs') != 'salamander':
        spec.pop('obfs_password', None)
    out_mode = clean_settings.get('outbound_mode', 'direct')
    if out_mode == 'direct':
        for k in ('outbound_server', 'outbound_port', 'outbound_username', 'outbound_method',
                  'outbound_password', 'outbound_hops', 'hop_passwords', 'resolved_outbound_hops'):
            spec.pop(k, None)
    elif out_mode in ('socks5', 'ss'):
        for k in ('outbound_hops', 'hop_passwords', 'resolved_outbound_hops'):
            spec.pop(k, None)
    elif out_mode == 'chain':
        for k in ('outbound_server', 'outbound_port', 'outbound_username', 'outbound_method', 'outbound_password'):
            spec.pop(k, None)
        max_idx = len(clean_settings.get('outbound_hops') or [])
        if isinstance(spec.get('hop_passwords'), dict):
            spec['hop_passwords'] = {
                k: v for k, v in spec['hop_passwords'].items()
                if k.isdigit() and int(k) < max_idx and v
            }
    return spec


def new_landing_spec(settings, protocol=None, *, secrets_input=None, pregenerated=None):
    resolved = protocol or settings.get('protocol', 'ss2022')
    validate_landing_settings(settings, protocol=resolved)
    generated = _generate_landing_secrets(settings, resolved, pregenerated=pregenerated)
    spec = {**settings, **generated}
    if secrets_input:
        if secrets_input.get('dns_api_token'):
            spec['dns_api_token'] = secrets_input['dns_api_token']
        if secrets_input.get('outbound_password'):
            spec['outbound_password'] = secrets_input['outbound_password']
        if 'hop_passwords' in secrets_input:
            spec['hop_passwords'] = _validate_hop_passwords(secrets_input.get('hop_passwords'))
    return spec


class DeploymentStoreMixin:
    def _cipher(self, db):
        # Called under BEGIN IMMEDIATE when creating the key: concurrent writers serialize.
        path = self.path.with_name('deployment.key')
        try:
            if not path.exists():
                if db.execute('SELECT 1 FROM deployments LIMIT 1').fetchone():
                    raise DeploymentKeyError()
                key = Fernet.generate_key()
                fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(key)
                    output.flush()
                    os.fsync(output.fileno())
                if os.name == 'posix':
                    from agent.runtime_engine import sync_directory
                    sync_directory(path.parent)
            if path.is_symlink() or (os.name == 'posix' and path.stat().st_mode & 0o077):
                raise DeploymentKeyError()
            return Fernet(path.read_bytes())
        except (OSError, ValueError):
            raise DeploymentKeyError() from None

    def _decrypt_spec(self, db, value):
        try:
            return json.loads(self._cipher(db).decrypt(value.encode()))
        except (InvalidToken, ValueError):
            raise DeploymentKeyError() from None

    def generate_landing_keys(self, protocol='reality'):
        """Generate protocol defaults and Fernet-sealed private keys without returning secrets."""
        if protocol not in LANDING_PROTOCOLS:
            raise ValueError('Unsupported landing protocol')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            cipher = self._cipher(db)
        rules = PROTOCOL_SPEC[protocol]
        payload = {'protocol': protocol}
        response = {
            'protocol': protocol,
            'tls_modes': list(rules['tls_modes']),
            'default_tls_mode': rules['default_tls'],
            'requires_domain': rules['requires_domain'],
            'server_generated': True,
        }
        if protocol == 'reality':
            private_key, public_key = _generate_x25519_pair()
            short_ids = [secrets.token_hex(8)]
            payload.update(
                reality_private_key=private_key,
                reality_public_key=public_key,
                reality_short_ids=short_ids,
                uuid=str(uuid.uuid4()),
            )
            response.update(
                reality_public_key=public_key,
                public_key=public_key,
                reality_short_ids=short_ids,
                has_private_key=True,
            )
        elif protocol == 'ss2022':
            payload['password'] = base64.b64encode(secrets.token_bytes(32)).decode()
            response['method'] = METHOD
        elif protocol in ('trojan', 'anytls'):
            payload['password'] = secrets.token_urlsafe(32)
        elif protocol == 'vless-ws':
            payload['uuid'] = str(uuid.uuid4())
            response['ws_path'] = '/ws'
        elif protocol == 'hysteria2':
            payload['password'] = secrets.token_urlsafe(32)
            payload['obfs_password'] = secrets.token_urlsafe(24)
        response['key_ref'] = cipher.encrypt(json.dumps(payload).encode('utf-8')).decode('utf-8')
        return response

    def _unseal_key_ref(self, db, cipher, key_ref, protocol):
        if not key_ref:
            return None
        if not isinstance(key_ref, str) or len(key_ref) > 4096:
            raise ValueError('Invalid key reference')
        try:
            data = json.loads(cipher.decrypt(key_ref.encode('utf-8'), ttl=KEY_REF_TTL).decode('utf-8'))
        except (InvalidToken, ValueError, UnicodeDecodeError):
            raise ValueError('Invalid or expired key reference') from None
        if not isinstance(data, dict) or data.get('protocol') != protocol:
            raise ValueError('Mismatched key reference protocol')
        return data

    def _deployment_view(self, db, row):
        job = db.execute('SELECT status,error,type FROM jobs WHERE id=?', (row['job_id'],)).fetchone()
        return {
            'id': row['id'],
            'agent_id': row['agent_id'],
            'type': 'singbox_node' if row['protocol'] == 'vless-reality' else 'singbox_landing',
            'protocol': row['protocol'],
            'settings': json.loads(row['settings']),
            'revision': row['revision'],
            'job_id': row['job_id'],
            'action': job['type'],
            'status': job['status'],
            'error': job['error'],
            'updated_at': row['updated_at'],
        }

    def get_deployment(self, agent_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent_id,)).fetchone():
                raise JobNotFound()
            self._expire_jobs(db, agent_id)
            row = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
            return self._deployment_view(db, row) if row else None

    def list_ss_landings(self):
        """List all active managed SS2022 nodes (primary deployments + extra agent_nodes) without secrets."""
        with self.connection() as db:
            agents = {}
            for row in db.execute('SELECT * FROM agents WHERE revoked_at IS NULL'):
                view = self._view(row)
                agents[row['id']] = {
                    'name': view['name'],
                    'status': view['status'],
                    'public_ipv4': view['public_ipv4'],
                    'public_ipv6': view['public_ipv6'],
                    'observed_ip': row['observed_ip'] or '',
                }
            if not agents:
                return []
            landings = []
            for row in db.execute(
                '''SELECT d.id, d.agent_id, d.settings, d.updated_at, j.type AS job_type, j.status AS job_status
                   FROM deployments d
                   JOIN jobs j ON j.id=d.job_id
                   WHERE d.protocol='ss2022' '''
            ).fetchall():
                a = agents.get(row['agent_id'])
                if not a:
                    continue
                if row['job_type'].endswith('.remove') and row['job_status'] == 'success':
                    continue
                s = json.loads(row['settings'])
                srv = s.get('server') or a['public_ipv4'] or a['observed_ip'] or a['public_ipv6']
                node_label = s.get('name') or f"{a['name']} SS2022"
                landings.append({
                    'agent_id': row['agent_id'],
                    'agent_name': a['name'],
                    'agent_status': a['status'],
                    'node_id': row['id'],
                    'name': node_label,
                    'node_name': node_label,
                    'server': srv,
                    'listen_port': s['listen_port'],
                    'method': s.get('method', METHOD),
                    'is_primary': True,
                    'status': row['job_status'],
                })
            for erow in db.execute(
                "SELECT id, agent_id, settings, updated_at FROM agent_nodes WHERE protocol='ss2022' ORDER BY updated_at ASC, id ASC"
            ).fetchall():
                a = agents.get(erow['agent_id'])
                if not a:
                    continue
                s = json.loads(erow['settings'])
                srv = s.get('server') or a['public_ipv4'] or a['observed_ip'] or a['public_ipv6']
                node_label = s.get('name') or f"{a['name']} SS2022"
                landings.append({
                    'agent_id': erow['agent_id'],
                    'agent_name': a['name'],
                    'agent_status': a['status'],
                    'node_id': erow['id'],
                    'name': node_label,
                    'node_name': node_label,
                    'server': srv,
                    'listen_port': s['listen_port'],
                    'method': s.get('method', METHOD),
                    'is_primary': False,
                    'status': 'ready',
                })
            return sorted(landings, key=lambda item: (item['agent_name'], item['listen_port'], item['node_id']))

    def _resolve_managed_ss_hop(self, db, entry_agent_id, target_agent_id, target_node_id):
        if target_agent_id == entry_agent_id:
            raise ValueError('Cannot chain an Agent to itself')
        target_agent = db.execute(
            'SELECT * FROM agents WHERE id=? AND revoked_at IS NULL',
            (target_agent_id,),
        ).fetchone()
        if not target_agent:
            raise ValueError('Referenced managed SS2022 Agent not found or revoked')
        target_view = self._view(target_agent)
        node_row = db.execute(
            '''SELECT d.settings, d.secret_spec, j.type AS job_type, j.status AS job_status
               FROM deployments d JOIN jobs j ON j.id=d.job_id
               WHERE d.id=? AND d.agent_id=? AND d.protocol='ss2022' ''',
            (target_node_id, target_agent_id),
        ).fetchone()
        if node_row:
            if node_row['job_type'].endswith('.remove') and node_row['job_status'] == 'success':
                raise ValueError('Referenced managed SS2022 node was removed')
            s = json.loads(node_row['settings'])
            dec = self._decrypt_spec(db, node_row['secret_spec'])
        else:
            extra_row = db.execute(
                "SELECT settings, secret_spec FROM agent_nodes WHERE id=? AND agent_id=? AND protocol='ss2022'",
                (target_node_id, target_agent_id),
            ).fetchone()
            if not extra_row:
                raise ValueError('Referenced managed SS2022 node not found')
            s = json.loads(extra_row['settings'])
            dec = self._decrypt_spec(db, extra_row['secret_spec'])
        server = s.get('server') or target_view['public_ipv4'] or target_agent['observed_ip'] or target_view['public_ipv6']
        if not server:
            raise ValueError('Referenced managed SS2022 node has no routable server address')
        return {
            'type': 'ss',
            'server': server,
            'port': int(s['listen_port']),
            'method': s.get('method', METHOD),
            'password': dec['password'],
        }

    def _resolve_node_outbound_hops(self, db, entry_agent_id, raw_spec):
        spec = {
            k: v for k, v in raw_spec.items()
            if k not in ('hop_passwords', 'resolved_outbound_hops')
        }
        if spec.get('outbound_mode', 'direct') != 'chain':
            return spec
        hops = spec.get('outbound_hops') or []
        hop_passwords = raw_spec.get('hop_passwords') if isinstance(raw_spec.get('hop_passwords'), dict) else {}
        resolved = []
        for idx, hop in enumerate(hops):
            kind = hop.get('kind')
            if kind == 'managed_ss':
                resolved.append(
                    self._resolve_managed_ss_hop(db, entry_agent_id, hop['agent_id'], hop['node_id'])
                )
            elif kind == 'ss':
                pw = hop_passwords.get(str(idx), '')
                if not isinstance(pw, str) or not pw:
                    raise ValueError('Missing password for external Shadowsocks hop')
                resolved.append({
                    'type': 'ss',
                    'server': hop['server'],
                    'port': int(hop['port']),
                    'method': hop.get('method', METHOD),
                    'password': pw,
                })
            elif kind == 'socks5':
                entry = {
                    'type': 'socks5',
                    'server': hop['server'],
                    'port': int(hop['port']),
                }
                if hop.get('username'):
                    entry['username'] = hop['username']
                pw = hop_passwords.get(str(idx), '')
                if pw:
                    entry['password'] = pw
                resolved.append(entry)
            else:
                raise ValueError('Unsupported outbound hop kind')
        spec['resolved_outbound_hops'] = resolved
        return spec

    def _collect_extra_and_adopted_specs(self, db, agent_id, *, returned_adoptions=None):
        extra_rows = db.execute(
            'SELECT * FROM agent_nodes WHERE agent_id=? ORDER BY updated_at ASC, id ASC',
            (agent_id,),
        ).fetchall()
        extra_specs = []
        for erow in extra_rows:
            espec = self._decrypt_spec(db, erow['secret_spec'])
            espec = {**espec, **json.loads(erow['settings']), 'node_id': erow['id'], 'protocol': erow['protocol']}
            extra_specs.append(self._resolve_node_outbound_hops(db, agent_id, espec))

        adopted_rows = db.execute(
            '''SELECT a.*, s.secret_spec, s.adopted_status
               FROM adopted_nodes a
               JOIN adopted_node_secrets s ON s.agent_id=a.agent_id AND s.source_key=a.source_key
               WHERE a.agent_id=? AND s.adopted_status='adopted'
               ORDER BY a.listen_port ASC, a.id ASC''',
            (agent_id,),
        ).fetchall()
        adopted_specs = []
        for arow in adopted_rows:
            if not arow['secret_spec']:
                continue
            secret_data = self._decrypt_spec(db, arow['secret_spec'])
            inbound = secret_data.get('inbound')
            if isinstance(inbound, dict) and inbound.get('listen_port'):
                adopted_specs.append({
                    'source_key': arow['source_key'],
                    'inbound': inbound,
                    'original_service': arow['service_name'] or '',
                    'original_config_path': arow['config_path'] or '',
                })
        return extra_specs, adopted_specs, list(returned_adoptions or [])

    def _attach_aggregated_nodes(self, db, agent_id, base_spec, *, returned_adoptions=None):
        cleaned = {k: v for k, v in base_spec.items() if k not in ('extra_nodes', 'adopted_nodes', 'returned_adoptions')}
        spec = self._resolve_node_outbound_hops(db, agent_id, cleaned)
        extras, adopted, returned = self._collect_extra_and_adopted_specs(
            db, agent_id, returned_adoptions=returned_adoptions
        )
        if extras:
            spec['extra_nodes'] = extras
        if adopted:
            spec['adopted_nodes'] = adopted
        if returned:
            spec['returned_adoptions'] = returned
        return spec

    def put_deployment(
        self,
        agent_id,
        request_id,
        expected_revision,
        settings,
        remove=False,
        protocol='vless-reality',
        *,
        secrets_input=None,
        key_ref=None,
    ):
        if protocol == 'vless-reality':
            validate_settings(settings)
        elif protocol in LANDING_PROTOCOLS:
            validate_landing_settings(settings, protocol=protocol)
        else:
            raise ValueError('Unsupported deployment protocol')

        if secrets_input is not None:
            if not isinstance(secrets_input, dict) or set(secrets_input) - {'dns_api_token', 'outbound_password', 'hop_passwords'}:
                raise ValueError('Unsupported deployment secret input')
            if 'hop_passwords' in secrets_input:
                _validate_hop_passwords(secrets_input.get('hop_passwords'))

        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent = self._job_agent(db, agent_id)
            action = ('deployment.' if protocol == 'vless-reality' else 'landing.') + ('remove' if remove else 'apply')
            self._runtime_capability(agent, action)
            self._expire_jobs(db, agent_id)
            row = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
            if row and row['protocol'] != protocol:
                raise JobConflict()  # Never replace one protocol deployment with another.
            existing = db.execute('SELECT * FROM jobs WHERE agent_id=? AND request_id=?', (agent_id, request_id)).fetchone()
            if existing:
                if (not row or row['job_id'] != existing['id'] or existing['type'] != action or
                        row['revision'] != expected_revision + 1 or json.loads(row['settings']) != settings):
                    raise JobConflict()
                return self._deployment_view(db, row)
            self._assert_no_chain(db, agent_id)
            if (row['revision'] if row else 0) != expected_revision or (remove and not row):
                raise JobConflict()
            if row and json.loads(row['settings'])['name'] != settings['name']:
                raise JobConflict()  # Keep template references stable across revisions.
            # A single runtime has one desired owner; drain all older mutations first.
            if db.execute(
                "SELECT 1 FROM jobs WHERE agent_id=? AND status IN ('pending','assigned','running') AND type!='singbox.status'",
                (agent_id,),
            ).fetchone():
                raise JobConflict()

            cipher = self._cipher(db)
            pregenerated = self._unseal_key_ref(db, cipher, key_ref, protocol) if key_ref else None
            if protocol == 'reality' and settings.get('reality_public_key'):
                if row:
                    current_pub = self._decrypt_spec(db, row['secret_spec']).get('reality_public_key')
                    if current_pub != settings['reality_public_key']:
                        raise ValueError('Cannot swap reality_public_key on existing deployment')
                elif not pregenerated or pregenerated.get('reality_public_key') != settings['reality_public_key']:
                    raise ValueError('reality_public_key requires matching server key_ref')

            identifier = row['id'] if row else uuid.uuid4().hex
            if row:
                current = self._decrypt_spec(db, row['secret_spec'])
            elif protocol == 'vless-reality':
                current = new_spec(settings)
            else:
                current = new_landing_spec(settings, protocol=protocol, secrets_input=secrets_input, pregenerated=pregenerated)

            base_spec = {
                k: v for k, v in {**current, **settings}.items()
                if k not in ('extra_nodes', 'adopted_nodes', 'returned_adoptions')
            }
            if protocol != 'vless-reality':
                _apply_outbound_and_secret_updates(base_spec, settings, secrets_input)
                if not remove:
                    spec = self._attach_aggregated_nodes(db, agent_id, base_spec)
                    validate_landing_spec('landing.apply', spec)
                else:
                    spec = base_spec
            else:
                spec = base_spec

            payload = {'deployment_id': identifier, 'revision': expected_revision + 1, 'spec_hash': spec_hash({} if remove else spec)}
            encrypted = cipher.encrypt(json.dumps(base_spec).encode()).decode()
            job = self._enqueue_job(db, agent_id, request_id, action, payload)
            db.execute(
                'UPDATE jobs SET secret_payload=? WHERE id=?',
                (cipher.encrypt(json.dumps({} if remove else spec).encode()).decode(), job['id']),
            )
            db.execute(
                '''INSERT INTO deployments(id,agent_id,settings,revision,secret_spec,job_id,updated_at,protocol)
                   VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                   settings=excluded.settings,revision=excluded.revision,secret_spec=excluded.secret_spec,
                   job_id=excluded.job_id,updated_at=excluded.updated_at''',
                (identifier, agent_id, json.dumps(settings), expected_revision + 1, encrypted, job['id'], self.clock(), protocol),
            )
            self._audit(db, 'deployment_requested', agent_id)
            return self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (identifier,)).fetchone())

    @staticmethod
    def _node_transports(protocol):
        if protocol == 'hysteria2':
            return ('udp',)
        if protocol == 'ss2022':
            return ('tcp', 'udp')
        return ('tcp',)

    def _assert_no_node_port_conflict(self, db, agent_id, candidate_protocol, candidate_port, *, exclude_id=None):
        cand_transports = set(self._node_transports(candidate_protocol))
        primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
        if primary and primary['id'] != exclude_id:
            p_job = db.execute('SELECT type,status FROM jobs WHERE id=?', (primary['job_id'],)).fetchone()
            if not (p_job and p_job['type'].endswith('.remove') and p_job['status'] == 'success'):
                p_settings = json.loads(primary['settings'])
                if p_settings.get('listen_port') == candidate_port:
                    if cand_transports & set(self._node_transports(primary['protocol'])):
                        raise ValueError('Port conflict with existing node on this Agent')
        for erow in db.execute('SELECT * FROM agent_nodes WHERE agent_id=?', (agent_id,)).fetchall():
            if erow['id'] == exclude_id:
                continue
            e_settings = json.loads(erow['settings'])
            if e_settings.get('listen_port') == candidate_port:
                if cand_transports & set(self._node_transports(erow['protocol'])):
                    raise ValueError('Port conflict with existing node on this Agent')

    def _dispatch_aggregated_runtime(self, db, agent_id, request_id, *, returned_adoptions=None):
        agent = self._job_agent(db, agent_id)
        self._expire_jobs(db, agent_id)
        if db.execute(
            "SELECT 1 FROM jobs WHERE agent_id=? AND status IN ('pending','assigned','running') AND type!='singbox.status'",
            (agent_id,),
        ).fetchone():
            raise JobConflict()
        cipher = self._cipher(db)
        primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
        primary_removed = False
        if primary:
            p_job = db.execute('SELECT type,status FROM jobs WHERE id=?', (primary['job_id'],)).fetchone()
            primary_removed = bool(p_job and p_job['type'].endswith('.remove') and p_job['status'] == 'success')

        extras, adopted, returned = self._collect_extra_and_adopted_specs(
            db, agent_id, returned_adoptions=returned_adoptions
        )
        if primary and not primary_removed:
            if primary['protocol'] == 'vless-reality':
                p_dec = self._decrypt_spec(db, primary['secret_spec'])
                base_spec = {
                    'name': p_dec['name'],
                    'server': p_dec['server'],
                    'listen_port': p_dec['listen_port'],
                    'protocol': 'reality',
                    'domain': p_dec['server_name'],
                    'tls_mode': 'reality',
                    'uuid': p_dec['uuid'],
                    'reality_private_key': p_dec['private_key'],
                    'reality_public_key': p_dec['public_key'],
                    'reality_short_ids': [p_dec['short_id']],
                }
            else:
                base_spec = {**self._decrypt_spec(db, primary['secret_spec']), **json.loads(primary['settings']), 'protocol': primary['protocol']}
            full_spec = self._attach_aggregated_nodes(db, agent_id, base_spec, returned_adoptions=returned_adoptions)
            validate_landing_spec('landing.apply', full_spec)
            action = 'landing.apply'
            rev = primary['revision'] + 1
            identifier = primary['id']
            payload = {'deployment_id': identifier, 'revision': rev, 'spec_hash': spec_hash(full_spec)}
            self._runtime_capability(agent, action)
            job = self._enqueue_job(db, agent_id, request_id, action, payload)
            db.execute(
                'UPDATE jobs SET secret_payload=? WHERE id=?',
                (cipher.encrypt(json.dumps(full_spec).encode()).decode(), job['id']),
            )
            db.execute(
                'UPDATE deployments SET revision=?,job_id=?,updated_at=?,protocol=? WHERE id=?',
                (rev, job['id'], self.clock(), 'reality' if primary['protocol'] == 'vless-reality' else primary['protocol'], identifier),
            )
            return self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (identifier,)).fetchone())

        if adopted or returned:
            full_spec = {'adopted_only': True}
            if adopted:
                full_spec['adopted_nodes'] = adopted
            if returned:
                full_spec['returned_adoptions'] = returned
            validate_landing_spec('landing.apply', full_spec)
            action = 'landing.apply'
            self._runtime_capability(agent, action)
            identifier = primary['id'] if primary else uuid.uuid4().hex
            rev = (primary['revision'] + 1) if primary else 1
            payload = {'deployment_id': identifier, 'revision': rev, 'spec_hash': spec_hash(full_spec)}
            job = self._enqueue_job(db, agent_id, request_id, action, payload)
            db.execute(
                'UPDATE jobs SET secret_payload=? WHERE id=?',
                (cipher.encrypt(json.dumps(full_spec).encode()).decode(), job['id']),
            )
            return {'job_id': job['id'], 'action': action, 'status': job['status'], 'revision': rev}

        if primary:
            action = 'landing.remove'
            self._runtime_capability(agent, action)
            rev = primary['revision'] + 1
            payload = {'deployment_id': primary['id'], 'revision': rev, 'spec_hash': spec_hash({})}
            job = self._enqueue_job(db, agent_id, request_id, action, payload)
            db.execute(
                'UPDATE jobs SET secret_payload=? WHERE id=?',
                (cipher.encrypt(json.dumps({}).encode()).decode(), job['id']),
            )
            db.execute(
                'UPDATE deployments SET revision=?,job_id=?,updated_at=? WHERE id=?',
                (rev, job['id'], self.clock(), primary['id']),
            )
            return self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (primary['id'],)).fetchone())
        return {'status': 'idle'}

    def list_agent_nodes(self, agent_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent_row = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
            if not agent_row:
                raise JobNotFound()
            self._expire_jobs(db, agent_id)
            primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
            nodes = []
            job_info = None
            if primary:
                view = self._deployment_view(db, primary)
                job_info = {'job_id': view['job_id'], 'action': view['action'], 'status': view['status'], 'error': view['error']}
                if not (view['action'].endswith('.remove') and view['status'] == 'success'):
                    nodes.append({
                        'id': view['id'],
                        'agent_id': agent_id,
                        'is_primary': True,
                        'protocol': 'reality' if view['protocol'] == 'vless-reality' else view['protocol'],
                        'raw_protocol': view['protocol'],
                        'settings': view['settings'],
                        'revision': view['revision'],
                        'status': view['status'],
                        'action': view['action'],
                        'error': view['error'],
                        'updated_at': view['updated_at'],
                    })
            for erow in db.execute('SELECT * FROM agent_nodes WHERE agent_id=? ORDER BY updated_at ASC, id ASC', (agent_id,)).fetchall():
                nodes.append({
                    'id': erow['id'],
                    'agent_id': agent_id,
                    'is_primary': False,
                    'protocol': erow['protocol'],
                    'raw_protocol': erow['protocol'],
                    'settings': json.loads(erow['settings']),
                    'revision': erow['revision'],
                    'status': job_info['status'] if job_info else 'success',
                    'action': job_info['action'] if job_info else 'landing.apply',
                    'error': job_info['error'] if job_info else None,
                    'updated_at': erow['updated_at'],
                })
            return nodes

    def upsert_agent_node(
        self,
        agent_id,
        request_id,
        protocol,
        settings,
        *,
        node_id=None,
        secrets_input=None,
        key_ref=None,
    ):
        if protocol == 'vless-reality':
            protocol = 'reality'
            if 'domain' not in settings and 'server_name' in settings:
                settings = {k: v for k, v in settings.items() if k != 'server_name'}
                settings['domain'] = settings.get('domain')
        if protocol not in LANDING_PROTOCOLS:
            raise ValueError('Unsupported landing protocol')
        clean_settings = {**settings, 'protocol': protocol}
        validate_landing_settings(clean_settings, protocol=protocol)
        if secrets_input is not None:
            if not isinstance(secrets_input, dict) or set(secrets_input) - {'dns_api_token', 'outbound_password', 'hop_passwords'}:
                raise ValueError('Unsupported deployment secret input')
            if 'hop_passwords' in secrets_input:
                _validate_hop_passwords(secrets_input.get('hop_passwords'))

        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent = self._job_agent(db, agent_id)
            self._runtime_capability(agent, 'landing.apply')
            self._expire_jobs(db, agent_id)
            self._assert_no_chain(db, agent_id)
            if db.execute(
                "SELECT 1 FROM jobs WHERE agent_id=? AND status IN ('pending','assigned','running') AND type!='singbox.status'",
                (agent_id,),
            ).fetchone():
                raise JobConflict()

            self._assert_no_node_port_conflict(
                db, agent_id, protocol, clean_settings['listen_port'], exclude_id=node_id
            )
            cipher = self._cipher(db)
            pregenerated = self._unseal_key_ref(db, cipher, key_ref, protocol) if key_ref else None
            primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
            primary_removed = False
            if primary:
                p_job = db.execute('SELECT type,status FROM jobs WHERE id=?', (primary['job_id'],)).fetchone()
                primary_removed = bool(p_job and p_job['type'].endswith('.remove') and p_job['status'] == 'success')

            is_primary_target = (primary is None or primary_removed or (node_id and primary['id'] == node_id))
            if is_primary_target:
                identifier = primary['id'] if primary else (node_id or uuid.uuid4().hex)
                if primary and not primary_removed and primary['protocol'] == protocol:
                    current = self._decrypt_spec(db, primary['secret_spec'])
                else:
                    current = new_landing_spec(clean_settings, protocol=protocol, secrets_input=secrets_input, pregenerated=pregenerated)
                base_spec = {
                    k: v for k, v in {**current, **clean_settings}.items()
                    if k not in ('extra_nodes', 'adopted_nodes', 'returned_adoptions')
                }
                _apply_outbound_and_secret_updates(base_spec, clean_settings, secrets_input)

                full_spec = self._attach_aggregated_nodes(db, agent_id, base_spec)
                validate_landing_spec('landing.apply', full_spec)
                rev = (primary['revision'] + 1) if primary else 1
                payload = {'deployment_id': identifier, 'revision': rev, 'spec_hash': spec_hash(full_spec)}
                encrypted_base = cipher.encrypt(json.dumps(base_spec).encode()).decode()
                job = self._enqueue_job(db, agent_id, request_id, 'landing.apply', payload)
                db.execute(
                    'UPDATE jobs SET secret_payload=? WHERE id=?',
                    (cipher.encrypt(json.dumps(full_spec).encode()).decode(), job['id']),
                )
                db.execute(
                    '''INSERT INTO deployments(id,agent_id,settings,revision,secret_spec,job_id,updated_at,protocol)
                       VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                       settings=excluded.settings,revision=excluded.revision,secret_spec=excluded.secret_spec,
                       job_id=excluded.job_id,updated_at=excluded.updated_at,protocol=excluded.protocol''',
                    (identifier, agent_id, json.dumps(clean_settings), rev, encrypted_base, job['id'], self.clock(), protocol),
                )
                self._audit(db, 'deployment_requested', agent_id)
                view = self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (identifier,)).fetchone())
                view['node_id'] = identifier
                return view

            # Extra node in agent_nodes
            existing_extra = db.execute(
                'SELECT * FROM agent_nodes WHERE id=? AND agent_id=?', (node_id, agent_id)
            ).fetchone() if node_id else None
            if node_id and not existing_extra:
                raise JobNotFound()
            target_id = existing_extra['id'] if existing_extra else uuid.uuid4().hex
            if existing_extra and existing_extra['protocol'] == protocol:
                current = self._decrypt_spec(db, existing_extra['secret_spec'])
            else:
                current = new_landing_spec(clean_settings, protocol=protocol, secrets_input=secrets_input, pregenerated=pregenerated)
            node_spec = {
                k: v for k, v in {**current, **clean_settings, 'node_id': target_id}.items()
                if k not in ('extra_nodes', 'adopted_nodes', 'returned_adoptions')
            }
            _apply_outbound_and_secret_updates(node_spec, clean_settings, secrets_input)
            resolved_node_spec = self._resolve_node_outbound_hops(db, agent_id, node_spec)
            validate_landing_spec('landing.apply', resolved_node_spec)

            encrypted_node = cipher.encrypt(json.dumps(node_spec).encode()).decode()
            rev = (existing_extra['revision'] + 1) if existing_extra else 1
            db.execute(
                '''INSERT INTO agent_nodes(id,agent_id,protocol,settings,secret_spec,revision,updated_at)
                   VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                   protocol=excluded.protocol,settings=excluded.settings,secret_spec=excluded.secret_spec,
                   revision=excluded.revision,updated_at=excluded.updated_at''',
                (target_id, agent_id, protocol, json.dumps(clean_settings), encrypted_node, rev, self.clock()),
            )
            self._audit(db, 'deployment_requested', agent_id)
            view = self._dispatch_aggregated_runtime(db, agent_id, request_id)
            view['node_id'] = target_id
            return view

    def delete_agent_node(self, agent_id, node_id, request_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._job_agent(db, agent_id)
            self._expire_jobs(db, agent_id)
            self._assert_no_chain(db, agent_id)
            extra = db.execute('SELECT * FROM agent_nodes WHERE id=? AND agent_id=?', (node_id, agent_id)).fetchone()
            if extra:
                db.execute('DELETE FROM agent_nodes WHERE id=?', (node_id,))
                self._audit(db, 'deployment_requested', agent_id)
                return self._dispatch_aggregated_runtime(db, agent_id, request_id)

            primary = db.execute('SELECT * FROM deployments WHERE id=? AND agent_id=?', (node_id, agent_id)).fetchone()
            if not primary:
                raise JobNotFound()
            next_extra = db.execute(
                'SELECT * FROM agent_nodes WHERE agent_id=? ORDER BY updated_at ASC, id ASC LIMIT 1',
                (agent_id,),
            ).fetchone()
            if next_extra:
                db.execute('DELETE FROM agent_nodes WHERE id=?', (next_extra['id'],))
                db.execute(
                    'UPDATE deployments SET protocol=?,settings=?,secret_spec=?,updated_at=? WHERE id=?',
                    (next_extra['protocol'], next_extra['settings'], next_extra['secret_spec'], self.clock(), primary['id']),
                )
                self._audit(db, 'deployment_requested', agent_id)
                return self._dispatch_aggregated_runtime(db, agent_id, request_id)

            # No extra nodes remain; remove primary deployment (or keep adopted_only if adopted nodes exist).
            _, adopted, _ = self._collect_extra_and_adopted_specs(db, agent_id)
            if adopted:
                cipher = self._cipher(db)
                full_spec = {'adopted_only': True, 'adopted_nodes': adopted}
                rev = primary['revision'] + 1
                payload = {'deployment_id': primary['id'], 'revision': rev, 'spec_hash': spec_hash(full_spec)}
                job = self._enqueue_job(db, agent_id, request_id, 'landing.apply', payload)
                db.execute(
                    'UPDATE jobs SET secret_payload=? WHERE id=?',
                    (cipher.encrypt(json.dumps(full_spec).encode()).decode(), job['id']),
                )
                db.execute('DELETE FROM deployments WHERE id=?', (primary['id'],))
                return {'job_id': job['id'], 'action': 'landing.apply', 'status': job['status'], 'revision': rev}

            cipher = self._cipher(db)
            action = 'deployment.remove' if primary['protocol'] == 'vless-reality' else 'landing.remove'
            rev = primary['revision'] + 1
            payload = {'deployment_id': primary['id'], 'revision': rev, 'spec_hash': spec_hash({})}
            job = self._enqueue_job(db, agent_id, request_id, action, payload)
            db.execute(
                'UPDATE jobs SET secret_payload=? WHERE id=?',
                (cipher.encrypt(json.dumps({}).encode()).decode(), job['id']),
            )
            db.execute(
                'UPDATE deployments SET revision=?,job_id=?,updated_at=? WHERE id=?',
                (rev, job['id'], self.clock(), primary['id']),
            )
            self._audit(db, 'deployment_requested', agent_id)
            return self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (primary['id'],)).fetchone())

    @staticmethod
    def _is_projectable_record(protocol, settings_dict):
        if protocol in ('vless-reality', *PROJECTABLE_LANDING_PROTOCOLS):
            return True
        if protocol == 'ss2022' and settings_dict.get('publish_to_subscription') is True:
            return True
        return False

    def managed_node_names(self):
        # Ownership outlives temporary publication (pending, failed, removed or revoked).
        # This query requires no credentials and must not depend on an active job result.
        with self.connection() as db:
            direct = []
            for row in db.execute('SELECT id,protocol,settings FROM deployments'):
                s_dict = json.loads(row['settings'])
                if self._is_projectable_record(row['protocol'], s_dict):
                    direct.append(node_name(row['id'], s_dict['name']))
            for erow in db.execute('SELECT id,protocol,settings FROM agent_nodes'):
                s_dict = json.loads(erow['settings'])
                if self._is_projectable_record(erow['protocol'], s_dict):
                    direct.append(node_name(erow['id'], s_dict['name']))
            adopted_names = self._adopted_node_names(db)
            return direct + adopted_names + self._chain_node_names(db)

    def managed_nodes(self):
        with self.connection() as db:
            rows = db.execute(
                '''SELECT d.* FROM deployments d JOIN jobs j ON j.id=d.job_id
                    JOIN agents a ON a.id=d.agent_id
                    WHERE j.status='success' AND j.type IN ('deployment.apply', 'landing.apply')
                    AND a.revoked_at IS NULL''',
            ).fetchall()
            nodes = []
            active_agents = set()
            for row in rows:
                active_agents.add(row['agent_id'])
                decrypted = self._decrypt_spec(db, row['secret_spec'])
                if row['protocol'] == 'vless-reality':
                    nodes.append(client_node(row['id'], row['agent_id'], decrypted))
                else:
                    projected = landing_client_node(row['id'], row['agent_id'], decrypted)
                    if projected is not None:
                        nodes.append(projected)
            if active_agents:
                placeholders = ','.join('?' for _ in active_agents)
                for erow in db.execute(
                    f'SELECT * FROM agent_nodes WHERE agent_id IN ({placeholders}) ORDER BY updated_at ASC, id ASC',
                    tuple(active_agents),
                ).fetchall():
                    edec = {**self._decrypt_spec(db, erow['secret_spec']), **json.loads(erow['settings']), 'protocol': erow['protocol']}
                    projected = landing_client_node(erow['id'], erow['agent_id'], edec)
                    if projected is not None:
                        nodes.append(projected)
            nodes.extend(self._adopted_client_nodes(db))
            return nodes + self._chain_nodes(db)
