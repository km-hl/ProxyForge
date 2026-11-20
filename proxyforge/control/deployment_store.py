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
    CLIENT_METADATA_ONLY_FIELDS,
    LANDING_PROTOCOLS,
    METHOD,
    PROTOCOL_SPEC,
    SHARED_PORT_PROTOCOLS,
    SS2022_METHODS,
    client_node as landing_client_node,
    normalize_protocol,
    shared_credential_field,
    shared_listener_fields,
    shared_listener_key,
    validate_settings as validate_landing_settings,
    validate_spec as validate_landing_spec,
)
from proxyforge.control.job_store import JobConflict, JobNotFound

PROJECTABLE_LANDING_PROTOCOLS = tuple(p for p in LANDING_PROTOCOLS if PROTOCOL_SPEC[p]['project_client'])
KEY_REF_TTL = 3600
_ADOPTED_UDP_TYPES = frozenset(('hysteria2', 'hysteria', 'tuic'))
_ADOPTED_DUAL_TYPES = frozenset(('shadowsocks', 'ss2022'))


class DeploymentKeyError(Exception):
    pass


class DeploymentValidationError(ValueError):
    """Validation failure whose message is a fixed, secret-free hint safe to return to admins."""


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
    cam_mode = clean_settings.get('camouflage_mode')
    if cam_mode == 'template':
        spec.pop('camouflage_url', None)
        spec.pop('camouflage_dir', None)
    elif cam_mode == 'proxy':
        spec.pop('camouflage_dir', None)
        spec.pop('camouflage_template', None)
    elif cam_mode == 'static_dir':
        spec.pop('camouflage_url', None)
        spec.pop('camouflage_template', None)
    tls_mode = clean_settings.get('tls_mode')
    if tls_mode != 'acme_dns':
        for k in ('dns_provider', 'dns_zone_id', 'dns_propagation_seconds', 'dns_api_token'):
            spec.pop(k, None)
    if tls_mode not in ('acme_http', 'acme_dns'):
        spec.pop('acme_email', None)
    if tls_mode == 'reality':
        for k in ('camouflage_mode', 'camouflage_template', 'camouflage_dir'):
            if k not in clean_settings:
                spec.pop(k, None)
        if 'camouflage_url' not in clean_settings:
            spec.pop('camouflage_url', None)
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

    @staticmethod
    def _runtime_settings_signature(settings, existing_spec=None):
        sig = {
            k: v for k, v in (settings or {}).items()
            if k not in CLIENT_METADATA_ONLY_FIELDS and k not in ('protocol', 'node_id')
        }
        sig.setdefault('outbound_mode', 'direct')
        if existing_spec is not None and sig.get('reality_public_key') == existing_spec.get('reality_public_key'):
            sig.pop('reality_public_key', None)
        return sig

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

    def _attach_aggregated_nodes(self, db, agent_id, base_spec, *, returned_adoptions=None, disabled_adoptions=None):
        cleaned = {
            k: v for k, v in base_spec.items()
            if k not in ('extra_nodes', 'adopted_nodes', 'returned_adoptions', 'disabled_adoptions')
        }
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
        if disabled_adoptions:
            spec['disabled_adoptions'] = list(disabled_adoptions)
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
                    norm_proto = normalize_protocol(protocol)
                    self._assert_no_node_port_conflict(
                        db, agent_id, norm_proto, settings['listen_port'], exclude_id=identifier
                    )
                    shared_peers = self._find_shared_listener_peers(
                        db, agent_id, norm_proto, settings['listen_port'], exclude_id=identifier
                    )
                    if shared_peers:
                        was_same_listener = bool(
                            row and normalize_protocol(row['protocol']) == norm_proto
                            and int(json.loads(row['settings']).get('listen_port') or 0) == int(settings['listen_port'])
                        )
                        if was_same_listener:
                            self._sync_shared_listener_peers(
                                db, cipher, shared_peers, norm_proto, settings, base_spec
                            )
                        else:
                            settings = self._validate_and_inherit_shared_host(norm_proto, settings, shared_peers[0])
                            base_spec = {**base_spec, **settings}
                            self._apply_shared_host_secrets(norm_proto, base_spec, shared_peers[0])
                            self._ensure_unique_shared_credential(norm_proto, base_spec, shared_peers)
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
        proto = normalize_protocol(protocol)
        if proto == 'hysteria2':
            return ('udp',)
        if proto == 'ss2022':
            return ('tcp', 'udp')
        return ('tcp',)

    @staticmethod
    def _adopted_transports(protocol):
        proto = str(protocol or '').strip().lower()
        if proto in _ADOPTED_UDP_TYPES:
            return ('udp',)
        if proto in _ADOPTED_DUAL_TYPES:
            return ('tcp', 'udp')
        return ('tcp',)

    def _normalize_primary_record(self, db, primary):
        raw_proto = primary['protocol']
        norm_proto = normalize_protocol(raw_proto)
        raw_settings = json.loads(primary['settings'])
        dec = self._decrypt_spec(db, primary['secret_spec'])
        if raw_proto == 'vless-reality':
            norm_settings = {
                'name': raw_settings['name'],
                'server': raw_settings['server'],
                'listen_port': raw_settings['listen_port'],
                'protocol': 'reality',
                'domain': raw_settings['server_name'],
                'tls_mode': 'reality',
            }
            norm_spec = {
                **norm_settings,
                'uuid': dec['uuid'],
                'reality_private_key': dec['private_key'],
                'reality_public_key': dec['public_key'],
                'reality_short_ids': [dec['short_id']],
            }
            return norm_proto, norm_settings, norm_spec
        norm_settings = {**raw_settings, 'protocol': norm_proto}
        norm_spec = {**dec, **raw_settings, 'protocol': norm_proto}
        return norm_proto, norm_settings, norm_spec

    def _assert_no_node_port_conflict(self, db, agent_id, candidate_protocol, candidate_port, *, exclude_id=None):
        cand_proto = normalize_protocol(candidate_protocol)
        cand_transports = set(self._node_transports(cand_proto))
        cand_shareable = cand_proto in SHARED_PORT_PROTOCOLS
        primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
        if primary and primary['id'] != exclude_id:
            p_job = db.execute('SELECT type,status FROM jobs WHERE id=?', (primary['job_id'],)).fetchone()
            if not (p_job and p_job['type'].endswith('.remove') and p_job['status'] == 'success'):
                p_proto = normalize_protocol(primary['protocol'])
                p_settings = json.loads(primary['settings'])
                if p_settings.get('listen_port') == candidate_port:
                    if cand_transports & set(self._node_transports(p_proto)):
                        if not (cand_shareable and p_proto == cand_proto):
                            raise DeploymentValidationError('监听端口与本机其他协议节点冲突（同端口复用仅支持相同协议）')
        for erow in db.execute('SELECT * FROM agent_nodes WHERE agent_id=?', (agent_id,)).fetchall():
            if erow['id'] == exclude_id:
                continue
            e_proto = normalize_protocol(erow['protocol'])
            e_settings = json.loads(erow['settings'])
            if e_settings.get('listen_port') == candidate_port:
                if cand_transports & set(self._node_transports(e_proto)):
                    if not (cand_shareable and e_proto == cand_proto):
                        raise DeploymentValidationError('监听端口与本机其他协议节点冲突（同端口复用仅支持相同协议）')
        for arow in db.execute(
            '''SELECT a.protocol, a.listen_port
               FROM adopted_nodes a
               JOIN adopted_node_secrets s ON s.agent_id=a.agent_id AND s.source_key=a.source_key
               WHERE a.agent_id=? AND s.adopted_status='adopted' AND a.listen_port=?''',
            (agent_id, int(candidate_port)),
        ).fetchall():
            if cand_transports & set(self._adopted_transports(arow['protocol'])):
                raise DeploymentValidationError('监听端口已被已接管的存量节点占用，无法共享复用')

    def _find_shared_listener_peers(self, db, agent_id, protocol, listen_port, *, exclude_id=None):
        key = shared_listener_key(protocol, listen_port)
        if key is None:
            return []
        target_proto, target_port = key
        peers = []
        primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
        if primary and primary['id'] != exclude_id:
            p_job = db.execute('SELECT type,status FROM jobs WHERE id=?', (primary['job_id'],)).fetchone()
            if not (p_job and p_job['type'].endswith('.remove') and p_job['status'] == 'success'):
                p_proto, p_settings, p_spec = self._normalize_primary_record(db, primary)
                if p_proto == target_proto and int(p_settings.get('listen_port') or 0) == target_port:
                    peers.append({
                        'table': 'deployments',
                        'id': primary['id'],
                        'is_primary': True,
                        'raw_protocol': primary['protocol'],
                        'settings': p_settings,
                        'spec': p_spec,
                    })
        for erow in db.execute(
            'SELECT * FROM agent_nodes WHERE agent_id=? ORDER BY id ASC',
            (agent_id,),
        ).fetchall():
            if erow['id'] == exclude_id:
                continue
            e_proto = normalize_protocol(erow['protocol'])
            e_settings = json.loads(erow['settings'])
            if e_proto == target_proto and int(e_settings.get('listen_port') or 0) == target_port:
                e_dec = self._decrypt_spec(db, erow['secret_spec'])
                e_spec = {**e_dec, **e_settings, 'protocol': e_proto}
                peers.append({
                    'table': 'agent_nodes',
                    'id': erow['id'],
                    'is_primary': False,
                    'raw_protocol': erow['protocol'],
                    'settings': {**e_settings, 'protocol': e_proto},
                    'spec': e_spec,
                })
        return peers

    @staticmethod
    def _validate_and_inherit_shared_host(protocol, clean_settings, host_peer):
        default_tls = PROTOCOL_SPEC[protocol]['default_tls']
        host_settings = host_peer['settings']
        host_spec = host_peer['spec']
        host_tls = host_settings.get('tls_mode', default_tls)
        cand_tls = clean_settings.get('tls_mode', host_tls)
        if cand_tls != host_tls:
            raise DeploymentValidationError('同端口复用节点必须与已有节点使用相同的 TLS / 伪装模式')
        host_domain = (host_settings.get('domain') or '').strip()
        cand_domain = (clean_settings.get('domain') or '').strip()
        if cand_domain and cand_domain.lower() != host_domain.lower():
            raise DeploymentValidationError('同端口复用节点必须与已有节点使用相同的域名 / SNI')
        if protocol == 'reality' and clean_settings.get('reality_public_key'):
            if clean_settings['reality_public_key'] != host_spec.get('reality_public_key'):
                raise DeploymentValidationError('同端口复用 Reality 节点必须沿用已有节点的 Reality 公私钥')
        if protocol == 'hysteria2' and 'obfs' in clean_settings:
            if (clean_settings.get('obfs') or 'none') != (host_settings.get('obfs') or 'none'):
                raise DeploymentValidationError('同端口复用 Hysteria2 节点必须与已有节点使用相同的混淆模式')

        merged = dict(clean_settings)
        pub_fields, _ = shared_listener_fields(protocol)
        for field in pub_fields:
            if field in host_settings and host_settings[field] not in (None, ''):
                merged[field] = host_settings[field]
            else:
                merged.pop(field, None)
        if protocol == 'reality' and host_spec.get('reality_public_key'):
            merged['reality_public_key'] = host_spec['reality_public_key']
        merged['tls_mode'] = host_tls
        if host_domain:
            merged['domain'] = host_domain
        return merged

    @staticmethod
    def _preserve_omitted_shared_fields(protocol, clean_settings, current_spec):
        """Preserve omitted companion listener fields when slim editors (e.g. Chain modal) update a shared node."""
        default_tls = PROTOCOL_SPEC[protocol]['default_tls']
        merged = dict(clean_settings)
        cur_tls = current_spec.get('tls_mode', default_tls)
        new_tls = merged.get('tls_mode', cur_tls)
        if new_tls == cur_tls:
            if new_tls == 'acme_dns' and not merged.get('dns_zone_id') and current_spec.get('dns_zone_id'):
                for k in ('dns_provider', 'dns_zone_id', 'dns_propagation_seconds', 'acme_email'):
                    if k not in merged and current_spec.get(k) not in (None, ''):
                        merged[k] = current_spec[k]
            if new_tls in ('acme_http', 'acme_dns') and protocol in ('reality', 'trojan'):
                if not merged.get('camouflage_mode') and current_spec.get('camouflage_mode'):
                    for k in ('camouflage_mode', 'camouflage_template', 'camouflage_url', 'camouflage_dir', 'acme_email'):
                        if k not in merged and current_spec.get(k) not in (None, ''):
                            merged[k] = current_spec[k]
            if protocol == 'hysteria2' and 'obfs' not in merged and current_spec.get('obfs'):
                for k in ('obfs', 'up_mbps', 'down_mbps', 'mport', 'hop_interval', 'acme_email'):
                    if k not in merged and current_spec.get(k) not in (None, ''):
                        merged[k] = current_spec[k]
            if protocol == 'anytls' and 'padding_scheme' not in merged and current_spec.get('padding_scheme'):
                merged['padding_scheme'] = current_spec['padding_scheme']
        return merged

    @staticmethod
    def _apply_shared_host_secrets(protocol, node_spec, host_peer):
        host_spec = host_peer['spec']
        _, secret_fields = shared_listener_fields(protocol)
        for field in secret_fields:
            if field in host_spec and host_spec[field] not in (None, ''):
                node_spec[field] = host_spec[field]
            else:
                node_spec.pop(field, None)
        if protocol == 'reality' and host_spec.get('reality_public_key'):
            node_spec['reality_public_key'] = host_spec['reality_public_key']
        return node_spec

    @staticmethod
    def _ensure_unique_shared_credential(protocol, node_spec, peers):
        cred_field = shared_credential_field(protocol)
        if not cred_field or not peers:
            return node_spec
        used = {peer['spec'].get(cred_field) for peer in peers if peer['spec'].get(cred_field)}
        while not node_spec.get(cred_field) or node_spec[cred_field] in used:
            if cred_field == 'uuid':
                node_spec[cred_field] = str(uuid.uuid4())
            else:
                node_spec[cred_field] = secrets.token_urlsafe(32)
        return node_spec

    def _sync_shared_listener_peers(self, db, cipher, peers, protocol, source_settings, source_spec):
        if not peers:
            return
        pub_fields, secret_fields = shared_listener_fields(protocol)
        now = self.clock()
        for peer in peers:
            p_settings = dict(peer['settings'])
            p_spec = dict(peer['spec'])
            p_settings['protocol'] = protocol
            p_spec['protocol'] = protocol
            for field in pub_fields:
                if field in source_settings and source_settings[field] not in (None, ''):
                    p_settings[field] = source_settings[field]
                    p_spec[field] = source_settings[field]
                else:
                    p_settings.pop(field, None)
                    p_spec.pop(field, None)
            if protocol == 'reality' and source_spec.get('reality_public_key'):
                p_settings['reality_public_key'] = source_spec['reality_public_key']
                p_spec['reality_public_key'] = source_spec['reality_public_key']
            for field in secret_fields:
                if field in source_spec and source_spec[field] not in (None, ''):
                    p_spec[field] = source_spec[field]
                else:
                    p_spec.pop(field, None)
            if p_settings.get('tls_mode') != 'acme_dns':
                for k in ('dns_provider', 'dns_zone_id', 'dns_propagation_seconds', 'dns_api_token'):
                    p_settings.pop(k, None)
                    p_spec.pop(k, None)
            if p_settings.get('obfs') != 'salamander':
                p_spec.pop('obfs_password', None)
            encrypted = cipher.encrypt(json.dumps(p_spec).encode()).decode()
            if peer['table'] == 'deployments':
                db.execute(
                    'UPDATE deployments SET protocol=?,settings=?,secret_spec=?,updated_at=? WHERE id=?',
                    (protocol, json.dumps(p_settings), encrypted, now, peer['id']),
                )
            else:
                db.execute(
                    'UPDATE agent_nodes SET protocol=?,settings=?,secret_spec=?,updated_at=? WHERE id=?',
                    (protocol, json.dumps(p_settings), encrypted, now, peer['id']),
                )

    def _dispatch_aggregated_runtime(self, db, agent_id, request_id, *, returned_adoptions=None, disabled_adoptions=None):
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
        disabled = list(disabled_adoptions or [])
        if primary and not primary_removed:
            p_proto, p_settings, base_spec = self._normalize_primary_record(db, primary)
            full_spec = self._attach_aggregated_nodes(
                db, agent_id, base_spec, returned_adoptions=returned_adoptions, disabled_adoptions=disabled
            )
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
            if primary['protocol'] == 'vless-reality':
                db.execute(
                    'UPDATE deployments SET revision=?,job_id=?,updated_at=?,protocol=?,settings=?,secret_spec=? WHERE id=?',
                    (
                        rev,
                        job['id'],
                        self.clock(),
                        p_proto,
                        json.dumps(p_settings),
                        cipher.encrypt(json.dumps(base_spec).encode()).decode(),
                        identifier,
                    ),
                )
            else:
                db.execute(
                    'UPDATE deployments SET revision=?,job_id=?,updated_at=?,protocol=? WHERE id=?',
                    (rev, job['id'], self.clock(), p_proto, identifier),
                )
            return self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (identifier,)).fetchone())

        if adopted or returned or disabled:
            full_spec = {'adopted_only': True}
            if adopted:
                full_spec['adopted_nodes'] = adopted
            if returned:
                full_spec['returned_adoptions'] = returned
            if disabled:
                full_spec['disabled_adoptions'] = disabled
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
        if not isinstance(settings, dict):
            raise ValueError('Invalid landing settings')
        if protocol == 'vless-reality':
            protocol = 'reality'
            if 'domain' not in settings and 'server_name' in settings:
                srv_name = settings['server_name']
                settings = {k: v for k, v in settings.items() if k != 'server_name'}
                settings['domain'] = srv_name
        if protocol not in LANDING_PROTOCOLS:
            raise ValueError('Unsupported landing protocol')
        clean_settings = {**settings, 'protocol': protocol}
        listen_port = clean_settings.get('listen_port')
        if type(listen_port) is not int or not 1 <= listen_port <= 65535:
            raise ValueError('Invalid listen_port')
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
                db, agent_id, protocol, listen_port, exclude_id=node_id
            )
            cipher = self._cipher(db)
            pregenerated = self._unseal_key_ref(db, cipher, key_ref, protocol) if key_ref else None
            primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
            primary_removed = False
            if primary:
                p_job = db.execute('SELECT type,status FROM jobs WHERE id=?', (primary['job_id'],)).fetchone()
                primary_removed = bool(p_job and p_job['type'].endswith('.remove') and p_job['status'] == 'success')

            is_primary_target = (primary is None or primary_removed or (node_id and primary['id'] == node_id))
            existing_extra = None
            if not is_primary_target:
                existing_extra = db.execute(
                    'SELECT * FROM agent_nodes WHERE id=? AND agent_id=?', (node_id, agent_id)
                ).fetchone() if node_id else None
                if node_id and not existing_extra:
                    raise JobNotFound()

            existing_row = (primary if (primary and not primary_removed) else None) if is_primary_target else existing_extra
            existing_proto = normalize_protocol(existing_row['protocol']) if existing_row else None
            existing_settings = None
            existing_spec = None
            if existing_row:
                if is_primary_target:
                    _, existing_settings, existing_spec = self._normalize_primary_record(db, existing_row)
                else:
                    existing_settings = json.loads(existing_row['settings'])
                    existing_spec = {**self._decrypt_spec(db, existing_row['secret_spec']), **existing_settings, 'protocol': existing_proto}

            shared_peers = self._find_shared_listener_peers(
                db, agent_id, protocol, listen_port, exclude_id=node_id
            )
            already_sharing = bool(
                existing_row
                and existing_proto == protocol
                and int(existing_settings.get('listen_port') or 0) == listen_port
            )

            if shared_peers and not already_sharing:
                clean_settings = self._validate_and_inherit_shared_host(protocol, clean_settings, shared_peers[0])
            elif shared_peers and already_sharing:
                if protocol == 'reality' and clean_settings.get('reality_public_key'):
                    if clean_settings['reality_public_key'] != existing_spec.get('reality_public_key'):
                        raise DeploymentValidationError('同端口复用 Reality 节点不可更改现有 Reality 公私钥')
                clean_settings = self._preserve_omitted_shared_fields(protocol, clean_settings, existing_spec)
            elif existing_row and existing_proto == protocol and protocol == 'reality' and clean_settings.get('reality_public_key'):
                if clean_settings['reality_public_key'] != existing_spec.get('reality_public_key'):
                    raise DeploymentValidationError('不可更换已有 Reality 节点的公私钥')

            validate_landing_settings(clean_settings, protocol=protocol)

            effective_pregenerated = pregenerated
            if shared_peers and not already_sharing and effective_pregenerated and protocol == 'reality':
                effective_pregenerated = {
                    k: v for k, v in effective_pregenerated.items()
                    if k not in ('reality_private_key', 'reality_public_key')
                }

            old_name = (existing_settings or {}).get('name') or ''
            new_name = clean_settings.get('name') or ''
            metadata_only = bool(
                existing_row is not None
                and existing_proto == protocol
                and not secrets_input
                and not key_ref
                and self._runtime_settings_signature(existing_settings, existing_spec)
                == self._runtime_settings_signature(clean_settings, existing_spec)
            )

            if is_primary_target:
                identifier = primary['id'] if primary else (node_id or uuid.uuid4().hex)
                if existing_row and existing_proto == protocol:
                    current = dict(existing_spec)
                else:
                    current = new_landing_spec(
                        clean_settings, protocol=protocol, secrets_input=secrets_input, pregenerated=effective_pregenerated
                    )
                base_spec = {
                    k: v for k, v in {**current, **clean_settings}.items()
                    if k not in ('extra_nodes', 'adopted_nodes', 'returned_adoptions')
                }
                _apply_outbound_and_secret_updates(base_spec, clean_settings, secrets_input)
                if shared_peers and not already_sharing:
                    self._apply_shared_host_secrets(protocol, base_spec, shared_peers[0])
                elif shared_peers and already_sharing:
                    if clean_settings.get('tls_mode') == 'acme_dns' and not base_spec.get('dns_api_token'):
                        if shared_peers[0]['spec'].get('dns_api_token'):
                            base_spec['dns_api_token'] = shared_peers[0]['spec']['dns_api_token']
                self._ensure_unique_shared_credential(protocol, base_spec, shared_peers)
                if shared_peers and already_sharing:
                    self._sync_shared_listener_peers(db, cipher, shared_peers, protocol, clean_settings, base_spec)

                full_spec = self._attach_aggregated_nodes(db, agent_id, base_spec)
                validate_landing_spec('landing.apply', full_spec)
                encrypted_base = cipher.encrypt(json.dumps(base_spec).encode()).decode()
                if metadata_only:
                    db.execute(
                        'UPDATE deployments SET protocol=?,settings=?,secret_spec=?,updated_at=? WHERE id=?',
                        (protocol, json.dumps(clean_settings), encrypted_base, self.clock(), identifier),
                    )
                    self._audit(db, 'deployment_metadata_updated', agent_id)
                    view = self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (identifier,)).fetchone())
                    view['node_id'] = identifier
                    view['applied'] = 'metadata_only'
                    view['restarted'] = False
                    if old_name and new_name and old_name != new_name:
                        view['renamed_from'] = old_name
                        view['renamed_to'] = new_name
                    return view

                rev = (primary['revision'] + 1) if primary else 1
                payload = {'deployment_id': identifier, 'revision': rev, 'spec_hash': spec_hash(full_spec)}
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
                view['applied'] = 'runtime_job'
                view['restarted'] = True
                if old_name and new_name and old_name != new_name:
                    view['renamed_from'] = old_name
                    view['renamed_to'] = new_name
                return view

            # Extra node in agent_nodes
            target_id = existing_extra['id'] if existing_extra else uuid.uuid4().hex
            if existing_extra and existing_proto == protocol:
                current = dict(existing_spec)
            else:
                current = new_landing_spec(
                    clean_settings, protocol=protocol, secrets_input=secrets_input, pregenerated=effective_pregenerated
                )
            node_spec = {
                k: v for k, v in {**current, **clean_settings, 'node_id': target_id}.items()
                if k not in ('extra_nodes', 'adopted_nodes', 'returned_adoptions')
            }
            _apply_outbound_and_secret_updates(node_spec, clean_settings, secrets_input)
            if shared_peers and not already_sharing:
                self._apply_shared_host_secrets(protocol, node_spec, shared_peers[0])
            elif shared_peers and already_sharing:
                if clean_settings.get('tls_mode') == 'acme_dns' and not node_spec.get('dns_api_token'):
                    if shared_peers[0]['spec'].get('dns_api_token'):
                        node_spec['dns_api_token'] = shared_peers[0]['spec']['dns_api_token']
            self._ensure_unique_shared_credential(protocol, node_spec, shared_peers)
            resolved_node_spec = self._resolve_node_outbound_hops(db, agent_id, node_spec)
            validate_landing_spec('landing.apply', resolved_node_spec)

            if shared_peers and already_sharing:
                self._sync_shared_listener_peers(db, cipher, shared_peers, protocol, clean_settings, node_spec)

            encrypted_node = cipher.encrypt(json.dumps(node_spec).encode()).decode()
            if metadata_only:
                now = self.clock()
                db.execute(
                    'UPDATE agent_nodes SET protocol=?,settings=?,secret_spec=?,updated_at=? WHERE id=?',
                    (protocol, json.dumps(clean_settings), encrypted_node, now, target_id),
                )
                self._audit(db, 'deployment_metadata_updated', agent_id)
                job_info = None
                if primary:
                    pview = self._deployment_view(db, primary)
                    job_info = {'job_id': pview['job_id'], 'action': pview['action'], 'status': pview['status'], 'error': pview['error']}
                view = {
                    'id': target_id,
                    'node_id': target_id,
                    'agent_id': agent_id,
                    'protocol': protocol,
                    'settings': clean_settings,
                    'revision': existing_extra['revision'],
                    'job_id': job_info['job_id'] if job_info else '',
                    'action': job_info['action'] if job_info else 'landing.apply',
                    'status': job_info['status'] if job_info else 'success',
                    'error': job_info['error'] if job_info else None,
                    'updated_at': now,
                    'applied': 'metadata_only',
                    'restarted': False,
                }
                if old_name and new_name and old_name != new_name:
                    view['renamed_from'] = old_name
                    view['renamed_to'] = new_name
                return view

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
            view['applied'] = 'runtime_job'
            view['restarted'] = True
            if old_name and new_name and old_name != new_name:
                view['renamed_from'] = old_name
                view['renamed_to'] = new_name
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
                cipher = self._cipher(db)
                promoted_spec = self._decrypt_spec(db, next_extra['secret_spec'])
                promoted_spec.pop('node_id', None)
                db.execute('DELETE FROM agent_nodes WHERE id=?', (next_extra['id'],))
                db.execute(
                    'UPDATE deployments SET protocol=?,settings=?,secret_spec=?,updated_at=? WHERE id=?',
                    (
                        next_extra['protocol'],
                        next_extra['settings'],
                        cipher.encrypt(json.dumps(promoted_spec).encode()).decode(),
                        self.clock(),
                        primary['id'],
                    ),
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
