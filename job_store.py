"""Transactional, leased queue for explicitly allowlisted read-only jobs."""
import hmac
import json
import secrets
import uuid
from agent.runtime_spec import RUNTIME_ACTIONS, revision, validate_action
from agent.deployment_spec import DEPLOYMENT_ACTIONS

JOB_PROTOCOL_VERSION = 1
LEASE_SECONDS = 60
MAX_ATTEMPTS = 3
JOB_TTL = 3600
TERMINAL = {"success", "failed", "cancelled"}


class JobConflict(Exception):
    pass


class JobNotFound(Exception):
    pass


def migrate_jobs(db):
    db.execute("""CREATE TABLE jobs (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        request_id TEXT NOT NULL, type TEXT NOT NULL, payload TEXT NOT NULL,
        deployment_revision TEXT, status TEXT NOT NULL, created_at REAL NOT NULL,
        deadline REAL NOT NULL, assigned_at REAL, started_at REAL, finished_at REAL,
        attempts INTEGER NOT NULL DEFAULT 0, lease_hash TEXT, lease_until REAL,
        result TEXT, error TEXT, UNIQUE(agent_id, request_id))""")
    db.execute("CREATE INDEX jobs_queue ON jobs(agent_id,status,created_at)")
    db.execute("INSERT INTO schema_migrations VALUES(2)")


class JobStoreMixin:
    def _expire_jobs(self, db, agent_id):
        now = self.clock()
        # Server time is authoritative. Listing also reconciles timed-out jobs.
        db.execute("""UPDATE jobs SET status='failed',error='deadline_exceeded',finished_at=?,
            lease_hash=NULL,lease_until=NULL WHERE agent_id=? AND deadline<=?
            AND status IN ('pending','assigned','running')""", (now, agent_id, now))
        db.execute("""UPDATE jobs SET status=CASE WHEN attempts>=? THEN 'failed' ELSE 'pending' END,
            error=CASE WHEN attempts>=? THEN 'lease_expired' ELSE NULL END,
            finished_at=CASE WHEN attempts>=? THEN ? ELSE NULL END,lease_hash=NULL,lease_until=NULL
            WHERE agent_id=? AND status IN ('assigned','running') AND lease_until<=?""",
                   (MAX_ATTEMPTS, MAX_ATTEMPTS, MAX_ATTEMPTS, now, agent_id, now))

    def _job_view(self, row):
        item = dict(row)
        item.pop("lease_hash", None)
        item.pop('secret_payload', None)
        item["payload"] = json.loads(item["payload"])
        item["result"] = json.loads(item["result"]) if item["result"] else None
        return item

    def _job_agent(self, db, agent_id):
        row = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not row:
            raise JobNotFound()
        metadata = json.loads(row["metadata"])
        if (row["revoked_at"] is not None or metadata.get("protocol_version") != 1 or
                metadata.get("job_protocol_version") != JOB_PROTOCOL_VERSION):
            raise JobConflict()
        return row

    def create_job(self, agent_id, request_id, action='singbox.status', payload=None):
        if action in DEPLOYMENT_ACTIONS:
            raise JobConflict()  # Only the atomic desired-state API may enqueue these.
        payload = {} if payload is None else payload
        if action != 'singbox.status':
            validate_action(action, payload)
        elif payload:
            raise ValueError('Status takes no arguments')
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            agent = self._job_agent(db, agent_id)
            self._runtime_capability(agent, action)
            self._expire_jobs(db, agent_id)
            if action in RUNTIME_ACTIONS and db.execute('SELECT 1 FROM deployments WHERE agent_id=?', (agent_id,)).fetchone():
                raise JobConflict()  # Do not silently revert/stop a published managed deployment.
            return self._enqueue_job(db, agent_id, request_id, action, payload)

    def _enqueue_job(self, db, agent_id, request_id, action, payload):
        from control_store import CapacityExceeded
        now = self.clock()
        existing = db.execute("SELECT * FROM jobs WHERE agent_id=? AND request_id=?",
                              (agent_id, request_id)).fetchone()
        if existing:
            if existing['type'] != action or json.loads(existing['payload']) != payload:
                raise JobConflict()
            return self._job_view(existing)
        # Retain idempotency keys/results for seven days, with a hard global cap.
        db.execute("DELETE FROM jobs WHERE status IN ('success','failed','cancelled') AND finished_at<? AND id NOT IN (SELECT job_id FROM deployments)",
                   (now - 7 * 86400,))
        if db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= 10000 or db.execute(
                "SELECT COUNT(*) FROM jobs WHERE agent_id=? AND status IN ('pending','assigned','running')",
                (agent_id,)).fetchone()[0] >= 20:
            raise CapacityExceeded()
        job_id = uuid.uuid4().hex
        deployment_revision = revision(job_id, action, payload) if action in RUNTIME_ACTIONS else None
        db.execute("""INSERT INTO jobs(id,agent_id,request_id,type,payload,deployment_revision,status,created_at,deadline)
            VALUES(?,?,?,?,?,?,'pending',?,?)""",
                   (job_id, agent_id, request_id, action, json.dumps(payload), deployment_revision, now, now + JOB_TTL))
        self._audit(db, "job_created", agent_id)
        return self._job_view(db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def list_jobs(self, agent_id):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
                raise JobNotFound()
            self._expire_jobs(db, agent_id)
            return [self._job_view(row) for row in db.execute(
                "SELECT * FROM jobs WHERE agent_id=? ORDER BY created_at DESC,rowid DESC LIMIT 100", (agent_id,))]

    def cancel_job(self, agent_id, job_id):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire_jobs(db, agent_id)
            row = db.execute("SELECT * FROM jobs WHERE agent_id=? AND id=?", (agent_id, job_id)).fetchone()
            if not row:
                raise JobNotFound()
            if row["status"] == "cancelled":
                return self._job_view(row)
            if row["status"] in TERMINAL:
                raise JobConflict()
            db.execute("UPDATE jobs SET status='cancelled',finished_at=?,lease_hash=NULL,lease_until=NULL WHERE id=?",
                       (self.clock(), job_id))
            self._audit(db, "job_cancelled", agent_id)
            return self._job_view(db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def claim_job(self, token, instance_id):
        from control_store import digest, UnauthorizedAgent
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            agent_id = self._authenticate(db, token)
            agent = self._job_agent(db, agent_id)
            if agent["instance_id"] != instance_id:
                raise UnauthorizedAgent()
            self._expire_jobs(db, agent_id)
            if db.execute("SELECT 1 FROM jobs WHERE agent_id=? AND status IN ('assigned','running')",
                          (agent_id,)).fetchone():
                return None
            row = db.execute("SELECT * FROM jobs WHERE agent_id=? AND status='pending' ORDER BY created_at,rowid LIMIT 1",
                             (agent_id,)).fetchone()
            if not row:
                return None
            self._runtime_capability(agent, row['type'])
            lease = secrets.token_urlsafe(32)
            db.execute("""UPDATE jobs SET status='assigned',attempts=attempts+1,assigned_at=?,
                lease_hash=?,lease_until=? WHERE id=?""",
                       (self.clock(), digest(lease), min(self.clock() + LEASE_SECONDS, row["deadline"]), row["id"]))
            result = self._job_view(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())
            result["lease_token"] = lease
            result["job_protocol_version"] = JOB_PROTOCOL_VERSION
            if row['type'] in DEPLOYMENT_ACTIONS:
                result['deployment'] = self._decrypt_spec(db, row['secret_payload'])
            return result

    def _runtime_capability(self, agent, action):
        if action in RUNTIME_ACTIONS:
            metadata = json.loads(agent['metadata'])
            if metadata.get('runtime_protocol_version') != 1 or metadata.get('supported') is not True:
                raise JobConflict()
            if action in DEPLOYMENT_ACTIONS and metadata.get('deployment_protocol_version') != 1:
                raise JobConflict()

    def report_job(self, token, job_id, lease, result=None, renew=False):
        from control_store import digest
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            agent_id = self._authenticate(db, token)
            agent = self._job_agent(db, agent_id)
            row = db.execute("SELECT * FROM jobs WHERE id=? AND agent_id=?", (job_id, agent_id)).fetchone()
            if not row:
                raise JobNotFound()
            self._runtime_capability(agent, row['type'])
            if not row["lease_hash"] or not hmac.compare_digest(row["lease_hash"], digest(lease)):
                raise JobConflict()
            encoded = json.dumps(result, sort_keys=True) if result is not None else None
            if row["status"] in TERMINAL:
                # Lost result acknowledgments are safe to retry with the same lease and exact result.
                if encoded is not None and row["result"] == encoded:
                    return {"status": row["status"]}
                raise JobConflict()
            if row["lease_until"] <= self.clock() or row["deadline"] <= self.clock():
                raise JobConflict()
            if renew:
                until = min(self.clock() + LEASE_SECONDS, row['deadline'])
                db.execute('UPDATE jobs SET lease_until=? WHERE id=?', (until, job_id))
                return {'lease_until': until}
            if result is None:
                db.execute("UPDATE jobs SET status='running',started_at=COALESCE(started_at,?) WHERE id=?",
                           (self.clock(), job_id))
                return {"status": "running"}
            if row["status"] != "running":
                raise JobConflict()
            status = result["status"]
            if row['type'] in DEPLOYMENT_ACTIONS and status == 'success':
                output = result.get('output') or {}
                if output.get('installed') is not True or output.get('running') is not True:
                    raise JobConflict()
            db.execute("UPDATE jobs SET status=?,result=?,error=?,finished_at=? WHERE id=?",
                       (status, encoded, result.get("error"), self.clock(), job_id))
            self._audit(db, "job_" + status, agent_id)
            return {"status": status}
