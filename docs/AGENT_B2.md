# B2: leased Agent job protocol

This phase adds a usable structured queue, demonstrated by a read-only
`singbox.status` action. Installation, restart, deployment and arbitrary commands
are not accepted actions. No production deployment is part of this change.

## 1. Files

`job_store.py` implements the transactional queue; `control_store.py` migrates
SQLite and cancels active jobs on revocation. `job_api.py` defines strict schemas
and routes, attached by `agent_api.py`. `agent/jobs.py` implements the allowlist,
local process lock and result journal. Agent transport, loop and installer include
the new protocol. `static/agents.js` provides task creation, status and cancellation.
Tests and CI cover the protocol alongside existing configuration/Mihomo checks.

## 2. Data model

SQLite schema 2 adds `jobs`, indexed by Agent/status/time. Each job records its
UUID, target Agent, administrator request UUID, action, immutable payload and
deployment revision, state, creation/deadline/assignment/start/finish timestamps,
attempt count, hashed lease credential/expiry, structured result and fixed error
code. `(agent_id, request_id)` is unique. Agent deletion cascades jobs; revocation
retains history and cancels unfinished jobs. Existing YAML files stay unchanged.

Maximum 20 unfinished jobs per Agent, 10,000 retained jobs globally. Creation
prunes terminal records older than seven days and otherwise returns 429 at capacity.
Administrative lists return the newest 100 jobs; lease credentials/hashes are
never exposed there. Idempotent create keys survive for the record's retention
period. Reusing a removed/expired key can create another read-only query.

## 3. API

All request bodies retain the Agent API's 16 KiB limit and generic 422 errors.

| Method and path | Body / response |
| --- | --- |
| POST `/api/agents/{agent_id}/jobs` | `request_id` (32 lowercase hex), `type: "singbox.status"`, `payload: {}`, `deployment_revision: null`; returns job |
| GET `/api/agents/{agent_id}/jobs` | `{jobs: [...]}` |
| POST `/api/agents/{agent_id}/jobs/{job_id}/cancel` | Returns cancelled job; already cancelled is idempotent |
| POST `/api/agent/jobs/claim` | `instance_id`; returns `{job: null}` or `{job: {..., lease_token, job_protocol_version: 1}}` |
| POST `/api/agent/jobs/{job_id}/start` | `lease_token`; returns running state |
| POST `/api/agent/jobs/{job_id}/result` | `lease_token`, `result`; returns terminal state |

Claim uses POST because it mutates queue state; the original plan's GET-next is
not implemented. No-job uses a JSON envelope rather than 204, matching the
reference Agent's bounded JSON transport. There is no WebSocket or inbound Agent
socket. 401 rejects credentials, 404 hides jobs owned by another Agent, and 409
rejects a stale lease, incompatible capability or invalid state transition.

## 4. Authentication

Administrative routes use existing management authentication. Machine routes
require the target Agent's independent bearer credential on every call, including
replayed results. Admin cookies/tokens and registration/subscription tokens do
not authorize machine calls. Claim binds the credential to its registered instance.
Start/result require Agent ownership plus the random 256-bit per-attempt lease.
Only its SHA-256 digest is stored by the Controller. Revocation and job transitions
share SQLite write transactions, so an in-flight result cannot bypass revocation.

## 5. Protocol negotiation

Inventory protocol remains 1. Metadata adds `job_protocol_version` (default 0 for
B1 Agents). B2 Agent 0.2.0 advertises 1; the Controller heartbeat advertises its
job version. Both versions must match before creating/claiming/completing jobs.
The UI disables creation for Agents without capability. A downgraded Agent's
pending jobs wait until capability returns or their deadline expires.

Upgrade Controller first: B1 Controllers reject the new metadata field. B1 Agents
continue heartbeat/inventory on B2 Controllers and receive no executable jobs.
Unsupported Linux distributions remain visible as inventory; this read-only
probe does not install software on them. Platform gates for runtime installation
belong to the subsequent managed-runtime phase.

## 6. State machine

`pending → assigned → running → success | failed`. Pending/assigned/running can
become cancelled. A job has a one-hour deadline and a 60-second lease. One Agent
has at most one leased job at a time. Atomic claim increments attempts and issues
a fresh lease. Expiry returns assigned/running work to pending, up to three
attempts; then it fails with `lease_expired`. Deadline exhaustion fails with
`deadline_exceeded`. Reconciliation happens on claim, create or list; this uses
server time and needs no scheduler. A reported `probe_failed` is terminal.

Start is idempotent for the current live lease. Completion requires running
state. Repeating an identical completion with the same lease after a lost
acknowledgment returns the existing result, including after its original expiry.
A different result, old attempt or cancelled/revoked target is rejected.
Cancellation does not interrupt a probe already executing on the machine.

The reference Agent executes fixed read-only probes, with two subprocess timeouts
of three seconds each; no long-running actions or lease renewal are implemented.
Adding mutating actions requires separate desired-state reconciliation and renewal
design, not just adding another action name to the allowlist.

## 7. Job and result schemas / replay

Only `singbox.status` with an empty payload and null deployment revision is valid.
The revision field is reserved explicitly; deployment actions will require their
own immutable revision schema in a later phase. Success has `status: "success"`,
`error: null` and a structured output (`installed`, `running`, bounded `version`,
status enum). Failure has `status: "failed"`, `output: null`, `error: "probe_failed"`.
Arbitrary error messages, stderr, commands, paths and URLs are forbidden.

The Agent validates the envelope again and records the last 128 results in a
private atomic journal before uploading. Identity includes job ID, type and
deployment revision, plus a journal binding to Controller/Agent/instance. A
redelivered job returns its saved result using the new lease without re-probing.
The journal holds no bearer or lease credentials; one process holds the config
lock. The GUI retains a create UUID across uncertain retries until acknowledgment
(page reload loses that in-memory UUID; inspect the list before creating again).

This is bounded at-least-once delivery, not exactly-once execution. A crash after
probe execution but before journal persistence, an evicted journal entry, or a
manually deleted journal can repeat a read-only probe. A disconnect spanning all
three attempts/deadline ends in failure even if a probe locally completed.
Future destructive actions must be independently idempotent.

## 8. Validation

Tests exercise concurrent idempotent creation and claim, stale attempt rejection,
retry exhaustion, cancellation/deadlines, revocation and cross-Agent ownership,
capability mismatch, backpressure/pruning, DB upgrade and migration failure
rollback, strict API payload/result schemas and secret omission. A real reference
Agent uses an actual loopback HTTP development server for registration, heartbeat,
claim/start/result and revocation. A lost upload reclaims the same job and proves
the persisted local result avoids a second probe. Local process-lock and corrupt
journal checks fail closed. Frontend capability rules are tested.

Existing configuration concurrency/history and Mihomo parser checks remain in CI.
Full privileged OS/architecture installation and production deployment are not
claimed. Validation numbers and browser results belong in the accompanying PR.

## 9. Security boundaries

No shell action, SSH access, user-controlled subprocess arguments, script download,
root job executor, inbound socket or disabled TLS verification. The fixed probe
only inspects `/opt/proxyforge-agent/bin/sing-box` and `proxyforge-singbox.service`;
user-managed runtimes are not adopted. UI results use textContent. Fixed error
codes avoid forwarding stdout/stderr or HTTP response bodies into error logs.
Agent-reported version/inventory strings remain untrusted bounded data.

## 10. Deferred scope

sing-box install/update/restart, desired-state deployments, VLESS Reality, SS2022,
managed-node projection, upgrade distribution, long-running job renewal, metrics,
WebSockets and arbitrary execution. The next planned PR is managed runtime.

## 11. Migration and backup

Schema 1 → 2 is a single transaction and preserves Agent credentials/inventory.
Fresh databases create schema 1 and 2 transactionally. A newer schema is rejected.
Before deployment, stop the Controller and make a private consistent runtime
backup (or use SQLite's backup API for the DB). Never copy only the main database
while WAL is active. Preserve YAML, credentials and DB together. Stop Agents for
backup/upgrade when a predictable cutover is required, then upgrade Controller
before Agents. There is no automatic downgrade migration.

## 12. Rollback

An Agent-only rollback to the saved B1 package remains compatible with a B2
Controller. Preserve its private config/journal; B1 ignores the journal. For a
Controller rollback to B1, stop Agents and Controller, privately preserve the
current runtime, and restore the pre-upgrade schema-1 DB with matching code.
B1 refuses schema 2: changing its version marker or dropping tables is not a safe
rollback. Restoring a DB loses intervening jobs/enrollments/revocations; reconcile
those identities and revoke/rotate as needed before resuming. No sing-box state
was changed by B2. MEMORY.md stays gitignored/dockerignored and is never uploaded.
