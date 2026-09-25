# B3: independent sing-box managed runtime

This phase implements pinned installation, start/stop/restart and rollback of one
ProxyForge-owned sing-box instance. Initial configuration has no inbounds; it
opens no public proxy port. VLESS Reality, SS2022 and node projection remain later
phases. Existing `/etc/sing-box` and `sing-box.service` are never adopted or changed.

## 1. Files and components

The standard-library Agent adds `runtime_spec`, `runtime_download`, `runtime_engine`,
`runtime_client`, `runtime_helper` and `job_lease` modules. The reviewed release
manifest is `agent/singbox-release.json`. A separate local opt-in installer and
three systemd units provision the helper and isolated runtime. Controller schemas,
queue logic and UI expose only the new allowlist. `scripts/check_singbox_runtime.py`
tests the official binary against real systemd on a disposable host; unit tests
exercise queue fencing, permissions, crash recovery and malformed downloads.

## 2. Storage and ownership

SQLite remains schema 2: existing immutable job type/payload/revision fields hold
runtime requests. No new table or legacy YAML migration is needed. The Controller
computes `deployment_revision` as SHA-256 of canonical JSON `[job_id, type, payload]`.
Runtime requests with changed content under a previously used request ID conflict.
This is an operation revision, not yet a node deployment/config revision.

The Agent continues to own only `/etc/proxyforge-agent` and its private journal.
The root-owned helper stores immutable generations under
`/var/lib/proxyforge-runtime/releases/{job_id}` with atomic `current` and `previous`
symlinks. Each generation contains the binary, `config.json`, and release metadata.
Config is root-owned, mode 0640, readable by the dedicated `proxyforge-singbox`
group. Directories/binaries are traversable/executable but not writable by either
Agent or runtime user. Intent/receipt files are root-only. After successful changes,
only current/previous generations remain; at most 128 helper receipts are retained.

The config path deliberately differs from the initial plan's Agent-owned `/etc`
directory: a root helper must not write through Agent-controlled parent paths.
`/opt/proxyforge-agent/bin/sing-box` is an installer-created symlink for the existing
read-only inventory probe. No caller-supplied path reaches privileged code.

## 3. APIs

Management `POST /api/agents/{id}/jobs` accepts the following actions. The client
sends `deployment_revision: null`; the server assigns the immutable operation
revision. Existing idempotent `request_id`, list/cancel APIs remain unchanged.

| Type | Payload | Resulting behavior |
| --- | --- | --- |
| `singbox.status` | `{}` | Existing read-only inventory query |
| `singbox.install` | `{"version":"1.14.2"}` | Install/update pinned version, validate and ensure running |
| `singbox.start` | `{}` | Ensure installed instance is running |
| `singbox.stop` | `{}` | Ensure installed instance is stopped |
| `singbox.restart` | `{}` | Activate a new immutable generation of current binary/config |
| `singbox.rollback` | `{}` | Copy previous generation and activate it, preserving current running/stopped state |

An already healthy start or same-version install is a no-op. Explicit restart
creates a new generation. Rollback requires an existing previous generation and
may have the same binary version after a restart; the UI says “previous runtime
version” rather than promising a different upstream release.

`GET /api/agents/runtime/release` returns the pinned version. Machine
`POST /api/agent/jobs/{id}/renew` accepts the current `lease_token` and returns its
new expiry. Credentials, owner, capability, deadline and current lease are checked
transactionally; renewal cannot revive expired, cancelled or completed attempts.

## 4. Privilege and authentication boundary

Agent still runs as `proxyforge-agent`, with no new root or sudo permission.
The optional helper is activated via `/run/proxyforge-runtime.sock` (root owner,
Agent group, mode 0660). Linux SO_PEERCRED admits only the Agent UID; the client
also verifies a root peer. There is no TCP helper listener. Messages are bounded
to 8 KiB, and both sides validate action/revision/result shape. The helper accepts
no URL, executable, configuration blob, user name, shell argument or service name.

Root is confined operationally to the dedicated release tree and fixed systemd
unit. Its code/package and all parent directories must be root-owned and not
group/world writable. It runs Python in isolated mode. The helper's systemd
filesystem sandbox allows writes only in its runtime directory; systemctl uses
the system manager to act on the one fixed unit. This is an administrative trust
boundary: a compromised authorized Agent can control this managed instance, but
the interface does not provide a general root command or file-write primitive.

The sing-box process has its own unprivileged account, empty capability set,
NoNewPrivileges, ProtectSystem=strict, ProtectHome and PrivateTmp. This phase does
not support low ports, TUN, routing changes or firewall changes.

## 5. Protocol and compatibility

Agent 0.3.0 retains inventory/job protocol 1 and adds `runtime_protocol_version`.
Default 0 keeps B1/B2 Agents inventory/read-only. A B3 Agent advertises runtime 1
only when the root-owned helper socket exists. Management creation, claim and
report additionally require runtime 1 and a supported platform. Socket presence
indicates opt-in, not health; an unavailable helper produces a fixed failure.

Upgrade Controller before Agent because old Controllers reject the new metadata
field. Debian 12/13 and Ubuntu 22.04/24.04 on amd64/arm64 remain the target matrix;
the helper independently checks OS/architecture. Full installation acceptance on
all those combinations is not claimed. Unsupported Agents can report inventory.

## 6. State, leases and interruption

Existing queue states/deadlines and three-attempt cap remain. The Agent renews
every 10 seconds in a separate thread and also sends heartbeat while the helper
works. Failure to renew, rejection/revocation, or 40 seconds without confirmation
closes the helper connection. The helper checks connection liveness during download
and immediately before activation. Downloads are bounded to five minutes; helper
operations to ten minutes at guard checkpoints, with bounded subprocess timeouts.

Cancellation is best effort before activation, not distributed transactional
rollback. A cancellation arriving after the final guard can race with an already
started systemd action, which may complete before the Controller rejects its
result. Refresh runtime state before issuing another operation. Helper requests
are serialized under a local process lock; there is no concurrent file activation.

Before switching files, the helper durably records old/current/previous targets
and running state. It checks the staged configuration, switches the symlink,
starts the fixed service, and verifies both active status and `/proc/MainPID/exe`
against the expected immutable binary path. A process crash after successful
activation is recognized by that path on recovery and does not restart it again.
Incomplete activation restores old pointers and prior running/stopped state.
Failed rollback preserves its intent for local repair and blocks further mutation.

After helper receipt persistence, the operation is committed even if delivery
of its result is lost. Agent journals and helper receipts replay duplicate results.
These bounded journals and recovery checks do not promise exactly-once execution
after manual deletion, DB restore, receipt eviction or external service changes.

## 7. Schema and download trust

Version 1.14.2 is pinned from the
[official release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2).
The manifest records GitHub's published SHA-256 digests for linux-amd64 and
linux-arm64 archives. Updating it requires a reviewed code change; “latest”,
custom versions, download URLs and hashes supplied by the Controller are rejected.
HTTPS uses system CA verification and permits redirects only to GitHub's release
asset host; environment proxies are ignored. Archive/download sizes are bounded.

Hash verification happens before extraction. Only the exact expected regular
binary member is copied, without general archive extraction. Symlink/hardlink
binary entries and duplicate/missing members are rejected. `sing-box check` and
exact version checks run as the isolated runtime user before activation; official
CLI behavior is described in the [configuration documentation](https://sing-box.sagernet.org/configuration/).
Download/check/activation failures do not publish partial releases.

Results reuse the bounded status output and fixed error codes `runtime_unavailable`,
`runtime_failed`, `runtime_cancelled`, `rollback_failed`; arbitrary stderr, download
URLs, paths and config contents are not returned to the Controller or error logs.

## 8. Validation

Tests cover immutable action revisions, changed idempotency payloads, capability
gating, renewal ownership/revocation/deadline, helper peer identity, malformed
archives, checksum mismatch, no-op installs/starts, duplicate delivery, interrupted
staging/activation, failed health checks and failed rollback. Linux filesystem
tests run on Linux and skip on Windows. A dedicated CI job downloads the pinned
official amd64 binary, runs its real check and validates real systemd start,
restart, stop, replay and rollback. It refuses existing runtime accounts/units and
cleans up only its own disposable resources. The existing Mihomo CI remains.

## 9. Deployment and local opt-in

Install/update Controller first, then Agent 0.3.0 from a reviewed checkout.
Fresh `agent/install.sh` installs only the unprivileged Agent. To enable runtime
management, inspect and run locally on the target machine:

```bash
sudo bash agent/install-runtime.sh
```

The script rejects existing runtime paths/units and never overwrites another
service. It creates the isolated account, fixed units, runtime directories and
socket, but does not download sing-box. In **Agent 服务器 → 任务**, choose the
pinned installation once capability appears. Start/stop operations affect runtime
state; the systemd unit remains enabled for recovery after reboot. A stop is not
a permanent service-disable action. To keep it off across boots, disable the
dedicated unit locally. Successful install starts it with zero inbounds.

## 10. Deferred work

Node/deployment schema, secrets generation, VLESS Reality, SS2022, proxy listeners,
custom JSON editing, automatic firewall changes, arbitrary version selection,
upstream auto-upgrades, inbound Agent access and managed node projection. The
runtime baseline deliberately does not generate any subscription nodes.

## 11. Backup / upgrade

Back up Controller SQLite consistently, Agent credentials/journal privately, and
the entire root-owned runtime directory with symlinks/ownership preserved. Stop
Agent and helper before a filesystem runtime backup so no activation is in flight.
Existing runtime package upgrades require stopping both services and installing
all files from a trusted matching release; do not replace a running root helper's
code in place. No remote helper/Agent self-upgrade action is provided.

## 12. Rollback / recovery

For an ordinary runtime rollback, use its structured job; old config/binary are
checked before activation and health failure restores the previous active state.
If `rollback_failed`, stop Agent/helper locally, preserve the directory and inspect
the dedicated unit before restoring a consistent backup; do not delete the intent
or symlinks to bypass recovery. There is no broad uninstall/delete API.

Controller/Agent rollback to B2: stop Agents and helper/socket, cancel outstanding
runtime jobs, back up current state, then restore compatible Controller and Agent
packages. Schema 2 is unchanged, but B2 does not understand runtime actions or
runtime journal entries. Privately archive the B3 Agent journal before running
B2, and retain helper receipts/managed files for re-upgrade. Do not silently reset
credentials, remove runtime generations or assume a DB restore preserves revocations.
Rollback to B1 still needs the pre-schema-2 DB. MEMORY.md never enters Git or VPS.
