# Template revision and history (Phase A)

## Behavior and files

`template_store.py` coordinates template, nodes and airports with a reentrant thread lock and an OS file lock. Existing routes in `main.py`, including startup/subscription cleanup, use this lock for read/modify/write. The UI session now saves the revision it originally loaded. `template-history.js` provides history, text comparison and explicit conflict choices.

`MEMORY.md` is local-only: Git, Docker build context and the repository privacy check exclude it.

## Data and persistence

The revision is SHA256 of the exact UTF-8 content (including newline differences). GET reads content and revision from one snapshot. Identical content is a no-op. A content hash is not a monotonic sequence; each history entry has an independent random ID.

Successful changes retain a baseline and new snapshots in `data/history/template/<id>.json` (timestamp, revision, size, source, content). GET creates no snapshots. Restore is a new validated save. Default retention is 30 snapshots, configurable by `TEMPLATE_HISTORY_LIMIT` (clamped to 2–100); total retained content is bounded to 32 MiB, each configuration file to 1 MiB. History is private runtime data.

All cooperating readers acquire `data/.config.lock`. The supported storage is a local filesystem on one host. External programs that ignore the lock are not covered. Existing in-memory credential/cache behavior means this change does not advertise general multi-worker application support.

A private, fsynced redo journal, `data/.config-transaction.json`, is the durable commit point. Committed updates are atomically replaced per file, then history is published. The next locked operation replays an interrupted commit before reading. Errors before the commit point leave data unchanged; errors afterwards mean an uncertain response, not a rollback. Restore storage and read again before retrying. Do not delete a pending journal. Multi-file import is recoverable and isolated from cooperating readers, not an OS-level atomic rename of three files.

## API and authentication

All routes retain management Bearer/session authentication and same-origin checks for cookie writes.

- GET `/api/template`: `{content, revision}`.
- POST `/api/template`: `{content, expected_revision}`; returns `{status, content, revision}`.
- POST `/api/template/validate`: unchanged; no revision required.
- GET `/api/template/history`: metadata list, newest first.
- GET `/api/template/history/{id}`: metadata and content.
- POST `/api/template/history/{id}/restore`: `{expected_revision}`; validates against current nodes/providers.
- POST `/api/template/import`: `{content, expected_revision, nodes, urls}`; validates all inputs, commits all three resources under the same lock.

Missing save/restore/import revision returns 428; malformed revision 422; stale revision 409 with `detail.code=template_conflict`, `current_revision`, `current_content`. Storage failure in coordinated mutations returns 503 with an uncertain-outcome message. Existing clients must GET a baseline before saving; omission never means force overwrite. Refresh old browser pages after upgrade.

Node/airport saves retain their existing API. Reference cleanup participates in the same transaction as their resource update and returns `template_revision`. Their lists do not yet have independent optimistic revisions.

## State handling and security

UI state is loaded → editing → saving → saved/conflict/uncertain. Conflict retains the original draft baseline. Viewing current server content never silently accepts it. Reload explicitly discards drafts after confirmation. A dropped response triggers a content/revision check before retry. History contents and comparisons are rendered as text.

The global importer makes one coordinated request and retains its input on errors. It does not refresh the revision and force a stale import through. No automatic YAML merge is implemented.

History and temporary files use private creation permissions. IDs are validated rather than accepted as paths. No credentials are added to API paths or logs. Existing Mihomo static gates and parser CI remain enabled.

## Agent protocol, jobs and migrations

This PR adds no Agent protocol, job schema or remote action. Existing YAML/JSON formats are unchanged; history and lock/journal files are created lazily. There is no SQLite migration in Phase A.

## Verification and rollback

Tests cover two competing processes and HTTP requests, missing/stale revisions, no-op and retention, baseline restore, path traversal, failure before commit, replay of interrupted multi-file import, import validation, indirect node cleanup, frontend conflict retention and uncertain retries. Existing Python/Node and real Mihomo generation tests remain required.

Before rolling back, finish journal recovery with this version and take a consistent backup. Previous binaries can read the same YAML but provide neither concurrency protection nor history; older browsers cannot save through the new API without a revision. Restoring application code is separate from restoring user runtime data.

## Deferred scope

No automatic merge, independent node/airport revisions, distributed filesystem locking, database history, Agent registration or remote deployments. Phase B1 follows in a separate PR.
