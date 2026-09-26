"""SQLite persistence for Agent inventory and the allowlisted job queue."""
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
import uuid

from job_store import JobStoreMixin, migrate_jobs
from deployment_store import DeploymentStoreMixin, migrate_deployments, migrate_landings

PROTOCOL_VERSION = 1
ONLINE_SECONDS = 90
OFFLINE_SECONDS = 300
REGISTRATION_TTL = 600
MAX_AGENTS = 1000


class UnauthorizedAgent(Exception):
    pass


class InvalidRegistration(Exception):
    pass


class CapacityExceeded(Exception):
    pass


def digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def online_status(last_seen, now):
    if last_seen is None:
        return "never_seen"
    age = max(0, now - last_seen)
    return "online" if age < ONLINE_SECONDS else "degraded" if age < OFFLINE_SECONDS else "offline"


class ControlStore(DeploymentStoreMixin, JobStoreMixin):
    def __init__(self, path, clock=time.time):
        self.path = Path(path).resolve()
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)")
            version = db.execute("SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()[0]
            if version > 4:
                raise RuntimeError("Control database is newer than this application")
            if version == 0:
                # Individual statements stay within the migration transaction.
                for statement in [
                    """CREATE TABLE registration_tokens (
                        id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL, created_at REAL NOT NULL,
                        expires_at REAL NOT NULL, used_at REAL)""",
                    """CREATE TABLE agents (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL, instance_id TEXT NOT NULL,
                        metadata TEXT NOT NULL, observed_ip TEXT NOT NULL,
                        created_at REAL NOT NULL, last_seen REAL, revoked_at REAL,
                        role TEXT NOT NULL DEFAULT 'unassigned', tags TEXT NOT NULL DEFAULT '[]')""",
                    """CREATE TABLE agent_credentials (
                        agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
                        token_hash TEXT NOT NULL UNIQUE, created_at REAL NOT NULL, revoked_at REAL)""",
                    """CREATE TABLE audit_events (
                        id INTEGER PRIMARY KEY, event TEXT NOT NULL, agent_id TEXT,
                        created_at REAL NOT NULL)""",
                    "INSERT INTO schema_migrations(version) VALUES(1)",
                ]:
                    db.execute(statement)
            if version < 2:
                migrate_jobs(db)
            if version < 3:
                migrate_deployments(db)
            if version < 4:
                migrate_landings(db)
            db.commit()

    @contextlib.contextmanager
    def connection(self):
        db = sqlite3.connect(str(self.path), timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _audit(self, db, event, agent_id=None):
        db.execute("INSERT INTO audit_events(event,agent_id,created_at) VALUES(?,?,?)",
                   (event, agent_id, self.clock()))
        db.execute("DELETE FROM audit_events WHERE id NOT IN "
                   "(SELECT id FROM audit_events ORDER BY id DESC LIMIT 1000)")

    def issue_registration(self, name):
        now = self.clock()
        token = "pfreg_" + secrets.token_urlsafe(32)
        token_id = uuid.uuid4().hex
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM registration_tokens WHERE expires_at < ?", (now,))
            if db.execute("SELECT COUNT(*) FROM registration_tokens").fetchone()[0] >= 100:
                raise CapacityExceeded()
            db.execute("INSERT INTO registration_tokens VALUES(?,?,?,?,?,NULL)",
                       (token_id, digest(token), name, now, now + REGISTRATION_TTL))
            self._audit(db, "registration_issued")
        return {"id": token_id, "registration_token": token, "expires_at": now + REGISTRATION_TTL}

    def register(self, token, metadata, observed_ip):
        now = self.clock()
        agent_id = uuid.uuid4().hex
        agent_token = "pfagt_" + secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            record = db.execute("SELECT * FROM registration_tokens WHERE token_hash=?", (digest(token),)).fetchone()
            if not record or record["used_at"] is not None or record["expires_at"] <= now:
                raise InvalidRegistration()
            if db.execute("SELECT COUNT(*) FROM agents").fetchone()[0] >= MAX_AGENTS:
                raise CapacityExceeded()
            db.execute("UPDATE registration_tokens SET used_at=? WHERE id=?", (now, record["id"]))
            db.execute("INSERT INTO agents(id,name,instance_id,metadata,observed_ip,created_at) VALUES(?,?,?,?,?,?)",
                       (agent_id, record["name"], metadata["instance_id"], json.dumps(metadata), observed_ip, now))
            db.execute("INSERT INTO agent_credentials VALUES(?,?,?,NULL)", (agent_id, digest(agent_token), now))
            self._audit(db, "agent_registered", agent_id)
        return {"agent_id": agent_id, "agent_token": agent_token,
                "protocol_version": PROTOCOL_VERSION, "heartbeat_interval": 30}

    def _authenticate(self, db, token):
        if not token.startswith("pfagt_"):
            raise UnauthorizedAgent()
        expected = digest(token)
        record = db.execute(
            "SELECT c.agent_id,c.token_hash,c.revoked_at,a.revoked_at AS agent_revoked "
            "FROM agent_credentials c JOIN agents a ON a.id=c.agent_id WHERE c.token_hash=?",
            (expected,)).fetchone()
        if not record or record["revoked_at"] is not None or record["agent_revoked"] is not None:
            raise UnauthorizedAgent()
        if not hmac.compare_digest(record["token_hash"], expected):
            raise UnauthorizedAgent()
        return record["agent_id"]

    def heartbeat(self, token, metadata, observed_ip):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            agent_id = self._authenticate(db, token)
            previous = json.loads(db.execute("SELECT metadata FROM agents WHERE id=?", (agent_id,)).fetchone()[0])
            if metadata["instance_id"] != previous["instance_id"]:
                raise UnauthorizedAgent()
            # Authentication and update share the transaction with revocation.
            db.execute("UPDATE agents SET metadata=?,observed_ip=?,last_seen=? WHERE id=?",
                       (json.dumps(metadata), observed_ip, self.clock(), agent_id))
        return {"status": "ok", "protocol_version": PROTOCOL_VERSION,
                "job_protocol_version": 1,
                "compatible": metadata["protocol_version"] == PROTOCOL_VERSION, "heartbeat_interval": 30}

    def _view(self, row):
        item = dict(row)
        item["metadata"] = json.loads(item["metadata"])
        item["tags"] = json.loads(item["tags"])
        item["status"] = "revoked" if item["revoked_at"] is not None else online_status(item["last_seen"], self.clock())
        item["compatible"] = item["metadata"].get("protocol_version") == PROTOCOL_VERSION
        return item

    def list_agents(self):
        with self.connection() as db:
            return [self._view(row) for row in db.execute("SELECT * FROM agents ORDER BY created_at DESC")]

    def get_agent(self, agent_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
            if not row:
                raise KeyError(agent_id)
            return self._view(row)

    def revoke(self, agent_id, remove=False):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
                raise KeyError(agent_id)
            now = self.clock()
            db.execute("UPDATE agents SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", (now, agent_id))
            db.execute("UPDATE agent_credentials SET revoked_at=COALESCE(revoked_at,?) WHERE agent_id=?", (now, agent_id))
            db.execute("UPDATE jobs SET status='cancelled',finished_at=?,lease_hash=NULL,lease_until=NULL "
                       "WHERE agent_id=? AND status IN ('pending','assigned','running')", (now, agent_id))
            if remove:
                db.execute("DELETE FROM agents WHERE id=?", (agent_id,))
            self._audit(db, "agent_removed" if remove else "agent_revoked", agent_id)

    def update_agent(self, agent_id, name, role, tags):
        with self.connection() as db:
            result = db.execute("UPDATE agents SET name=?,role=?,tags=? WHERE id=?",
                                (name, role, json.dumps(tags), agent_id))
            if result.rowcount != 1:
                raise KeyError(agent_id)
            self._audit(db, "agent_updated", agent_id)
        return self.get_agent(agent_id)
