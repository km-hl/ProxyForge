# Agent B1 architecture and acceptance

## 1. Changed components

`control_store.py`: new SQLite inventory store and migration.
`agent_api.py`: separate management/enrollment/heartbeat routes and bounded schemas.
`agent/`: standard-library reference client, read-only inventory, local installer
and systemd unit. `static/agents.js`: inventory management UI. `main.py` wires
these components without opening the database during import/generation. Runtime
Pydantic is explicitly constrained to major version 2 for the protocol schemas.

## 2. Data model

Local `data/proxyforge.db`, schema version 1:

| Table | Purpose |
| --- | --- |
| schema_migrations | Applied integer schema versions; newer schema rejected |
| registration_tokens | ID, SHA256 digest, assigned display name, creation/expiry/consumption times |
| agents | ID, independent instance ID, name, metadata JSON, observed IP, creation/last-seen/revocation, role, tags |
| agent_credentials | Per-Agent digest, creation and revocation, foreign key to agents |
| audit_events | Event type, optional Agent ID, time; newest 1000 only |

Credentials are generated with 256 bits of randomness. Plain tokens are returned
only at issuance/enrollment and never stored by the Controller. The Agent must
persist its own long-term credential privately. DB statements are parameterized.
Metadata is bounded and rejects unknown fields; it is self-reported inventory,
not a trusted attestation. Role is independent of any deployment.

SQLite uses foreign keys, WAL, a five-second busy timeout, per-operation
connections and short transactions. Registration consumption+Agent+credential
creation and heartbeat authentication+write are atomic relative to revocation.
Maximum 100 outstanding/unexpired registration records and 1000 Agent records;
expired registrations are pruned when issuing new ones. No metrics history.

## 3. APIs

All management routes require existing management authentication:

| Method/path | Behavior |
| --- | --- |
| POST /api/agents/registration-tokens | {name}; return token once and expiry (10 min) |
| GET /api/agents | List public inventory, derived online state and compatibility |
| GET /api/agents/{id} | Detail, no credential/digest |
| PATCH /api/agents/{id} | {name, role, tags}; inventory labels only |
| POST /api/agents/{id}/revoke | Immediately revoke Agent credential |
| DELETE /api/agents/{id} | Revoke and remove inventory; no remote uninstall |

Separate Agent routes:

- POST `/api/agent/register`: registration_token plus inventory. Returns agent_id,
  agent_token, protocol_version and heartbeat_interval. No cookie/admin
  authentication substitutes for a registration token.
- POST `/api/agent/heartbeat`: independent Agent Bearer token plus inventory.
  Returns status, compatibility, Controller protocol version and heartbeat interval.
  Identity comes from the credential; no client-supplied agent_id is accepted.

All Agent/Agent-management requests have a 16 KiB body ceiling. Invalid schemas
produce generic 422 responses with no echoed input. Invalid/revoked credentials
return 401, capacity returns 429, SQLite failure returns generic 503. Enrollment
failures use a bounded global in-memory limiter (20 failures/minute, 60s block);
it is not a distributed DDoS defense. Reverse proxy request/time limits remain
the deployment boundary. Never log Authorization or request bodies.

## 4. Authentication boundary

Management/subscription/Agent credentials are disjoint. Agent credentials cannot
read any inventory management route, templates or subscription secrets, nor
select another identity. All Agent operations check revocation. Management
cookies retain existing same-origin checks and cannot become Agent identities.

TLS verifies system/private CA; no default skip-verification option. HTTP is an
explicit development-only client setting. Client redirects and implicit proxy
environment use are disabled. The existing deployment must expose HTTPS; this
change does not reconfigure the server's reverse proxy.

## 5. Protocol

Protocol version 1 heartbeat carries instance_id, hostname, hashed machine_id
hint, OS/version, architecture, Agent version, protocol version, uptime,
addresses (currently empty in the reference client), supported flag and the
independent sing-box runtime status. No CPU/RAM metrics or deployment secrets.

Observed IP comes from the ASGI request client; configure trusted reverse proxy
forwarding correctly. It is displayed as connection origin, not automatically
used as a public node endpoint. Incompatible protocol reports are visible;
no actions are dispatched in B1.

## 6. State machines

Registration: issued → consumed, or expired. Exactly one transaction consumes a
token. A lost response is **not** idempotently replayable: inspect/remove the
orphan inventory record, issue a new token, then re-enroll. Local pending config
contains no registration/long-term token; client makes only one enrollment call.

Agent: never_seen → online (<90s) → degraded (<300s) → offline; any state may
be revoked/removed. Server receipt time drives last_seen. Heartbeat failures
use bounded exponential backoff+jitter. Authentication rejection exits 4;
systemd is configured not to restart that result.

## 7. Job schema

None in B1. There is no jobs table, polling route, exec API, deployment.apply,
service mutation, firewall action, browser terminal or Agent self-upgrade.

## 8. Tests and practical validation

Store tests cover concurrent single-use consumption, expiration, hashed storage,
clock thresholds, instance binding, persisted revocation, removal and migration
version rejection. API tests cover all credential boundaries, self/other Agent
access, cookie isolation, payload ceiling, unknown-field rejection, log/response
redaction and protocol mismatch. The actual reference Agent enrolls and sends a
heartbeat over a local development HTTP server, then stops after revocation.

Existing template concurrency/history, Python/Node and real Mihomo generator CI
remain required. Installer shell syntax is checked in CI. Actual privileged
installation across all advertised Debian/Ubuntu and arm64 targets remains a
separate deployment acceptance step; this PR does not claim that matrix ran.

## 9. Security measures

No VPS SSH credentials or inbound listener. Runtime service uses a dedicated
unprivileged account, private files, systemd hardening and fixed read-only probe
commands. Tokens are entered through hidden stdin prompts, not shell arguments.
No remote script download/exec and no installation of sing-box. UI renders
inventory with textContent, uses management auth and clears the registration
token field on modal dismissal.

## 10. Deferred work

Jobs/leases, deployment schema, key generation, VLESS Reality, SS2022 chains,
managed-node projection, signed distribution/update, full OS/architecture
installer acceptance, distributed controller replication. These are not hidden
behind stub actions and require a later reviewed phase.

## 11. Migration and backup

Only new control-plane state enters SQLite. Existing template, airports, custom
nodes and credentials are unchanged. Schema migration is transactional; no
silent downgrade of newer schemas. Database initialization is lazy when an
inventory API is first used; ordinary subscription generation needs no database.

Back up with SQLite's backup API or after stopping the service, including all
runtime state consistently. Never copy only an active WAL database's main file.
The DB, WAL/SHM and backups contain sensitive inventory, so restrict access.

## 12. Rollback

Controller code rollback leaves legacy YAML usable and Agent DB on disk; an old
Controller has no Agent endpoints. Stop Agent services until re-upgrading, or
revoke credentials before rollback. B1 changes no sing-box runtime. Preserve
Agent credentials privately if returning to the same DB; after DB restore verify
revocation state and rotate/re-enroll if necessary. Do not erase runtime data to
roll back code. Local-only MEMORY.md is never part of the release or VPS upload.

References: [SQLite WAL](https://www.sqlite.org/wal.html),
[SQLite backup API](https://www.sqlite.org/backup.html).
