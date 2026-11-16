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
    if protocol == 'trojan':
        return {'password': generated.get('password') or secrets.token_urlsafe(32)}
    if protocol == 'vless-ws':
        return {'uuid': generated.get('uuid') or str(uuid.uuid4())}
    if protocol == 'hysteria2':
        result = {'password': generated.get('password') or secrets.token_urlsafe(32)}
        if settings.get('obfs') == 'salamander':
            result['obfs_password'] = generated.get('obfs_password') or secrets.token_urlsafe(24)
        return result
    raise ValueError('Unsupported landing protocol')


def new_landing_spec(settings, protocol=None, *, secrets_input=None, pregenerated=None):
    resolved = protocol or settings.get('protocol', 'ss2022')
    validate_landing_settings(settings, protocol=resolved)
    generated = _generate_landing_secrets(settings, resolved, pregenerated=pregenerated)
    spec = {**settings, **generated}
    if secrets_input and secrets_input.get('dns_api_token'):
        spec['dns_api_token'] = secrets_input['dns_api_token']
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
        elif protocol == 'trojan':
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
            if not isinstance(secrets_input, dict) or set(secrets_input) - {'dns_api_token'}:
                raise ValueError('Unsupported deployment secret input')

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

            spec = {**current, **settings}
            if protocol != 'vless-reality':
                if secrets_input and secrets_input.get('dns_api_token'):
                    spec['dns_api_token'] = secrets_input['dns_api_token']
                if not remove:
                    if settings.get('obfs') == 'salamander' and 'obfs_password' not in spec:
                        spec['obfs_password'] = secrets.token_urlsafe(24)
                    if settings.get('obfs') != 'salamander':
                        spec.pop('obfs_password', None)
                    validate_landing_spec('landing.apply', spec)

            payload = {'deployment_id': identifier, 'revision': expected_revision + 1, 'spec_hash': spec_hash({} if remove else spec)}
            encrypted = cipher.encrypt(json.dumps(spec).encode()).decode()
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

    def managed_node_names(self):
        # Ownership outlives temporary publication (pending, failed, removed or revoked).
        # This query requires no credentials and must not depend on an active job result.
        placeholders = ','.join('?' for _ in ('vless-reality', *PROJECTABLE_LANDING_PROTOCOLS))
        with self.connection() as db:
            direct = [
                node_name(row['id'], json.loads(row['settings'])['name'])
                for row in db.execute(
                    f'SELECT id,settings FROM deployments WHERE protocol IN ({placeholders})',
                    ('vless-reality', *PROJECTABLE_LANDING_PROTOCOLS),
                )
            ]
            return direct + self._chain_node_names(db)

    def managed_nodes(self):
        placeholders = ','.join('?' for _ in ('vless-reality', *PROJECTABLE_LANDING_PROTOCOLS))
        with self.connection() as db:
            rows = db.execute(
                f'''SELECT d.* FROM deployments d JOIN jobs j ON j.id=d.job_id
                    JOIN agents a ON a.id=d.agent_id
                    WHERE j.status='success' AND j.type IN ('deployment.apply', 'landing.apply')
                    AND a.revoked_at IS NULL AND d.protocol IN ({placeholders})''',
                ('vless-reality', *PROJECTABLE_LANDING_PROTOCOLS),
            ).fetchall()
            nodes = []
            for row in rows:
                decrypted = self._decrypt_spec(db, row['secret_spec'])
                if row['protocol'] == 'vless-reality':
                    nodes.append(client_node(row['id'], row['agent_id'], decrypted))
                else:
                    projected = landing_client_node(row['id'], row['agent_id'], decrypted)
                    if projected is not None:
                        nodes.append(projected)
            return nodes + self._chain_nodes(db)
