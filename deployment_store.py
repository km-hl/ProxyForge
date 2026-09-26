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
from agent.landing_spec import validate_settings as validate_landing_settings
from job_store import JobConflict, JobNotFound


class DeploymentKeyError(Exception):
    pass


def migrate_deployments(db):
    db.execute('ALTER TABLE jobs ADD COLUMN secret_payload TEXT')
    db.execute('''CREATE TABLE deployments (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL UNIQUE REFERENCES agents(id) ON DELETE CASCADE,
        settings TEXT NOT NULL, revision INTEGER NOT NULL, secret_spec TEXT NOT NULL,
        job_id TEXT NOT NULL, updated_at REAL NOT NULL)''')
    db.execute('INSERT INTO schema_migrations VALUES(3)')


def new_spec(settings):
    key = X25519PrivateKey.generate()
    encode = lambda data: base64.urlsafe_b64encode(data).decode().rstrip('=')
    return {**settings, 'uuid': str(uuid.uuid4()), 'short_id': secrets.token_hex(8),
            'private_key': encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            'public_key': encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}


def migrate_landings(db):
    db.execute("ALTER TABLE deployments ADD COLUMN protocol TEXT NOT NULL DEFAULT 'vless-reality'")
    db.execute('INSERT INTO schema_migrations VALUES(4)')


def new_landing_spec(settings):
    validate_landing_settings(settings)
    return {**settings, 'password': base64.b64encode(secrets.token_bytes(32)).decode()}


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

    def _deployment_view(self, db, row):
        job = db.execute('SELECT status,error,type FROM jobs WHERE id=?', (row['job_id'],)).fetchone()
        return {'id': row['id'], 'agent_id': row['agent_id'],
                'type': 'singbox_landing' if row['protocol'] == 'ss2022' else 'singbox_node', 'protocol': row['protocol'],
                'settings': json.loads(row['settings']), 'revision': row['revision'], 'job_id': row['job_id'],
                'action': job['type'], 'status': job['status'], 'error': job['error'], 'updated_at': row['updated_at']}

    def get_deployment(self, agent_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent_id,)).fetchone():
                raise JobNotFound()
            self._expire_jobs(db, agent_id)
            row = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
            return self._deployment_view(db, row) if row else None

    def put_deployment(self, agent_id, request_id, expected_revision, settings, remove=False, protocol='vless-reality'):
        if protocol not in ('vless-reality', 'ss2022'):
            raise ValueError('Unsupported deployment protocol')
        (validate_landing_settings if protocol == 'ss2022' else validate_settings)(settings)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            agent = self._job_agent(db, agent_id)
            action = ('landing.' if protocol == 'ss2022' else 'deployment.') + ('remove' if remove else 'apply')
            self._runtime_capability(agent, action)
            self._expire_jobs(db, agent_id)
            row = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
            if row and row['protocol'] != protocol:
                raise JobConflict()  # Never replace a Reality entry with a landing or vice versa.
            existing = db.execute('SELECT * FROM jobs WHERE agent_id=? AND request_id=?', (agent_id, request_id)).fetchone()
            if existing:
                if (not row or row['job_id'] != existing['id'] or existing['type'] != action or
                        row['revision'] != expected_revision + 1 or json.loads(row['settings']) != settings):
                    raise JobConflict()
                return self._deployment_view(db, row)
            if (row['revision'] if row else 0) != expected_revision or (remove and not row):
                raise JobConflict()
            if row and json.loads(row['settings'])['name'] != settings['name']:
                raise JobConflict()  # Keep template references stable across revisions.
            # A single runtime has one desired owner; drain all older mutations first.
            if db.execute("SELECT 1 FROM jobs WHERE agent_id=? AND status IN ('pending','assigned','running') AND type!='singbox.status'",
                          (agent_id,)).fetchone():
                raise JobConflict()
            identifier = row['id'] if row else uuid.uuid4().hex
            generate = new_landing_spec if protocol == 'ss2022' else new_spec
            current = self._decrypt_spec(db, row['secret_spec']) if row else generate(settings)
            spec = {**current, **settings}  # Preserve client credentials across edits/retries.
            payload = {'deployment_id': identifier, 'revision': expected_revision + 1,
                       'spec_hash': spec_hash({} if remove else spec)}
            cipher = self._cipher(db)
            encrypted = cipher.encrypt(json.dumps(spec).encode()).decode()
            job = self._enqueue_job(db, agent_id, request_id, action, payload)
            db.execute('UPDATE jobs SET secret_payload=? WHERE id=?',
                       (cipher.encrypt(json.dumps({} if remove else spec).encode()).decode(), job['id']))
            db.execute('''INSERT INTO deployments(id,agent_id,settings,revision,secret_spec,job_id,updated_at,protocol)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                settings=excluded.settings,revision=excluded.revision,secret_spec=excluded.secret_spec,
                job_id=excluded.job_id,updated_at=excluded.updated_at''',
                       (identifier, agent_id, json.dumps(settings), expected_revision + 1, encrypted, job['id'], self.clock(), protocol))
            self._audit(db, 'deployment_requested', agent_id)
            return self._deployment_view(db, db.execute('SELECT * FROM deployments WHERE id=?', (identifier,)).fetchone())

    def managed_node_names(self):
        # Ownership outlives temporary publication (pending, failed, removed or revoked).
        # This query requires no credentials and must not depend on an active job result.
        with self.connection() as db:
            return [node_name(row['id'], json.loads(row['settings'])['name'])
                    for row in db.execute("SELECT id,settings FROM deployments WHERE protocol='vless-reality'")]

    def managed_nodes(self):
        with self.connection() as db:
            rows = db.execute('''SELECT d.* FROM deployments d JOIN jobs j ON j.id=d.job_id
                JOIN agents a ON a.id=d.agent_id WHERE j.status='success' AND j.type='deployment.apply'
                AND a.revoked_at IS NULL AND d.protocol='vless-reality' ''').fetchall()
            return [client_node(row['id'], row['agent_id'], self._decrypt_spec(db, row['secret_spec'])) for row in rows]
