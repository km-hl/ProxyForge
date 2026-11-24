"""Multi-user subscription tokens, independent credentials, byte quota accounting, and automatic cutoff."""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, StrictBool, StrictInt, constr

from agent.deployment_spec import node_name
from agent.landing_spec import SHARED_PORT_PROTOCOLS, normalize_protocol
from proxyforge.control.job_store import JobConflict, JobNotFound
from proxyforge.subscription.nodes import _normalize_host_port, _split_addr_str

INDEPENDENT_CRED_PROTOCOLS = frozenset(('reality', 'vless-reality', 'trojan', 'anytls', 'hysteria2'))
USER_MARK_MAX = 65535
_ALLOWED_NODE_PREFIXES = ('agent::', 'adopted::', 'manual::')


def migrate_sub_users(db):
    db.execute('''CREATE TABLE sub_users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        token_hash TEXT NOT NULL UNIQUE,
        token_enc TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        quota_bytes INTEGER NOT NULL DEFAULT 0,
        expire_at REAL NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        prefer_relay INTEGER NOT NULL DEFAULT 0,
        allowed_groups TEXT NOT NULL DEFAULT '[]',
        forward_rule_ids TEXT NOT NULL DEFAULT '[]',
        max_connections INTEGER NOT NULL DEFAULT 0,
        rate_limit_kbps INTEGER NOT NULL DEFAULT 0,
        disabled_reason TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL)''')
    db.execute('CREATE INDEX sub_users_token_hash ON sub_users(token_hash)')

    db.execute('''CREATE TABLE sub_user_counter_baselines (
        user_id TEXT NOT NULL REFERENCES sub_users(id) ON DELETE CASCADE,
        forward_rule_id TEXT NOT NULL,
        last_rx_bytes INTEGER NOT NULL DEFAULT 0,
        last_tx_bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(user_id, forward_rule_id))''')

    db.execute('INSERT INTO schema_migrations VALUES(8)')


def hash_sub_token(token: str) -> str:
    return hashlib.sha256(str(token).encode('utf-8')).hexdigest()


def derive_user_node_credentials(cred_seed_hex: str, node_key: str) -> dict:
    """Deterministically derive per-(user, node) UUIDv4 and 32-char URL-safe password."""
    key = bytes.fromhex(str(cred_seed_hex))
    raw_uuid = bytearray(hmac.new(key, f'uuid:{node_key}'.encode('utf-8'), hashlib.sha256).digest()[:16])
    raw_uuid[6] = (raw_uuid[6] & 0x0F) | 0x40
    raw_uuid[8] = (raw_uuid[8] & 0x3F) | 0x80
    raw_pw = hmac.new(key, f'pass:{node_key}'.encode('utf-8'), hashlib.sha256).digest()[:24]
    return {
        'uuid': str(uuid.UUID(bytes=bytes(raw_uuid))),
        'password': base64.urlsafe_b64encode(raw_pw).decode('ascii').rstrip('='),
    }


def normalize_allowed_nodes(items) -> list:
    out = []
    seen = set()
    for raw in items or ():
        val = str(raw or '').strip()
        if not val or len(val) > 256 or not val.startswith(_ALLOWED_NODE_PREFIXES):
            continue
        if val not in seen:
            seen.add(val)
            out.append(val)
        if len(out) >= 256:
            break
    return out


def _extract_agent_ids_from_nodes(allowed_nodes) -> set:
    agent_ids = set()
    for key in allowed_nodes or ():
        if isinstance(key, str) and key.startswith('agent::'):
            parts = key.split('::')
            if len(parts) == 3 and parts[1]:
                agent_ids.add(parts[1])
    return agent_ids


def _extract_spec_sub_user_signature(spec: dict) -> dict:
    if not isinstance(spec, dict) or spec.get('adopted_only') is True:
        return {'no_user_marks': False, 'primary': [], 'extras': {}}
    extras = {}
    for item in spec.get('extra_nodes') or ():
        if isinstance(item, dict) and item.get('sub_users'):
            extras[str(item.get('node_id') or '')] = list(item.get('sub_users') or [])
    return {
        'no_user_marks': bool(spec.get('no_user_marks')),
        'primary': list(spec.get('sub_users') or []),
        'extras': extras,
    }


def format_subscription_userinfo(user: dict) -> str:
    upload = max(0, int(user.get('upload_bytes', 0)))
    download = max(0, int(user.get('download_bytes', 0)))
    total = max(0, int(user.get('quota_bytes', 0)))
    expire = max(0, int(user.get('expire_at', 0)))
    return f'upload={upload}; download={download}; total={total}; expire={expire}'


class SubUserStoreMixin:
    def _next_mark_id(self, db) -> int:
        used = {int(r[0]) for r in db.execute('SELECT mark_id FROM sub_user_profiles').fetchall()}
        if not used:
            return 1
        candidate = max(used) + 1
        if candidate <= USER_MARK_MAX:
            return candidate
        for mid in range(1, USER_MARK_MAX + 1):
            if mid not in used:
                return mid
        raise ValueError('No available sub-user mark_id')

    def _ensure_sub_user_profile(self, db, user_id, *, allowed_nodes=None, info_nodes=None, reset_day=None):
        prof = db.execute('SELECT * FROM sub_user_profiles WHERE user_id=?', (user_id,)).fetchone()
        if prof is not None:
            return prof
        mark_id = self._next_mark_id(db)
        seed_hex = secrets.token_hex(32)
        seed_enc = self._cipher(db).encrypt(seed_hex.encode('ascii')).decode('ascii')
        nodes_json = json.dumps(normalize_allowed_nodes(allowed_nodes or ()))
        info_val = int(True if info_nodes is None else bool(info_nodes))
        reset_val = max(0, min(28, int(reset_day or 0)))
        db.execute(
            '''INSERT INTO sub_user_profiles(
                   user_id,mark_id,cred_seed_enc,allowed_nodes,info_nodes,reset_day,last_reset_month
               ) VALUES(?,?,?,?,?,?,?)''',
            (user_id, mark_id, seed_enc, nodes_json, info_val, reset_val, ''),
        )
        return db.execute('SELECT * FROM sub_user_profiles WHERE user_id=?', (user_id,)).fetchone()

    def _sub_user_view(self, row, profile=None, *, include_token=None):
        used = max(0, int(row['upload_bytes'])) + max(0, int(row['download_bytes']))
        quota = max(0, int(row['quota_bytes']))
        item = {
            'id': row['id'],
            'username': row['username'],
            'token_prefix': row['token_prefix'],
            'upload_bytes': row['upload_bytes'],
            'download_bytes': row['download_bytes'],
            'used_bytes': used,
            'quota_bytes': quota,
            'expire_at': row['expire_at'],
            'enabled': bool(row['enabled']),
            'prefer_relay': bool(row['prefer_relay']),
            'allowed_groups': json.loads(row['allowed_groups']),
            'forward_rule_ids': json.loads(row['forward_rule_ids']),
            'max_connections': row['max_connections'],
            'rate_limit_kbps': row['rate_limit_kbps'],
            'disabled_reason': row['disabled_reason'],
            'mark_id': int(profile['mark_id']) if profile is not None else 0,
            'allowed_nodes': json.loads(profile['allowed_nodes']) if profile is not None else [],
            'info_nodes': bool(profile['info_nodes']) if profile is not None else True,
            'reset_day': int(profile['reset_day']) if profile is not None else 0,
            'last_reset_month': str(profile['last_reset_month'] or '') if profile is not None else '',
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }
        if include_token is not None:
            item['token'] = include_token
        return item

    @staticmethod
    def _user_is_active_at(row, now: float) -> bool:
        if not row['enabled']:
            return False
        expire_at = float(row['expire_at'] or 0)
        if expire_at > 0 and now >= expire_at:
            return False
        quota = max(0, int(row['quota_bytes']))
        used = max(0, int(row['upload_bytes'])) + max(0, int(row['download_bytes']))
        if quota > 0 and used >= quota:
            return False
        return True

    def _agent_active_sub_user_map(self, db, agent_id, *, now=None):
        """Return `{node_row_id: [{'mark_id', 'uuid', 'password'}, ...]}` for active users on `agent_id`."""
        ts = self.clock() if now is None else float(now)
        prefix = f'agent::{agent_id}::'
        rows = db.execute(
            '''SELECT u.*, p.mark_id, p.cred_seed_enc, p.allowed_nodes
               FROM sub_users u
               JOIN sub_user_profiles p ON p.user_id=u.id
               WHERE u.enabled=1
               ORDER BY p.mark_id ASC'''
        ).fetchall()
        if not rows:
            return {}
        cipher = self._cipher(db)
        by_node = {}
        for row in rows:
            if not self._user_is_active_at(row, ts):
                continue
            allowed = json.loads(row['allowed_nodes'] or '[]')
            matching = [k for k in allowed if isinstance(k, str) and k.startswith(prefix)]
            if not matching:
                continue
            seed_hex = cipher.decrypt(row['cred_seed_enc'].encode('ascii')).decode('ascii')
            mark_id = int(row['mark_id'])
            for node_key in matching:
                node_row_id = node_key[len(prefix):]
                if not node_row_id or '::' in node_row_id:
                    continue
                creds = derive_user_node_credentials(seed_hex, node_key)
                by_node.setdefault(node_row_id, []).append({
                    'mark_id': mark_id,
                    'uuid': creds['uuid'],
                    'password': creds['password'],
                })
        for entries in by_node.values():
            entries.sort(key=lambda item: item['mark_id'])
        return by_node

    def derive_user_credentials_for_nodes(self, user_id: str, node_keys) -> dict:
        """Derive per-node credentials for `user_id` without exposing the underlying seed."""
        keys = [str(k) for k in (node_keys or ()) if str(k).startswith('agent::')]
        if not keys:
            return {}
        with self.connection() as db:
            prof = self._ensure_sub_user_profile(db, user_id)
            seed_hex = self._cipher(db).decrypt(prof['cred_seed_enc'].encode('ascii')).decode('ascii')
            return {k: derive_user_node_credentials(seed_hex, k) for k in keys}

    def _sync_agent_if_sub_users_drifted(self, db, agent_id: str, *, allow_only_succeeded: bool = False) -> bool:
        agent = db.execute('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL', (agent_id,)).fetchone()
        if not agent:
            return False
        meta = json.loads(agent['metadata'] or '{}')
        if meta.get('landing_protocol_version') != 1:
            return False
        primary = db.execute('SELECT * FROM deployments WHERE agent_id=?', (agent_id,)).fetchone()
        if not primary:
            return False
        self._expire_jobs(db, agent_id)
        if db.execute(
            "SELECT 1 FROM jobs WHERE agent_id=? AND status IN ('pending','assigned','running') AND type!='singbox.status'",
            (agent_id,),
        ).fetchone():
            return False
        last_job = db.execute('SELECT type,status,secret_payload FROM jobs WHERE id=?', (primary['job_id'],)).fetchone()
        if not last_job:
            return False
        if last_job['type'].endswith('.remove') and last_job['status'] == 'success':
            return False
        if allow_only_succeeded and last_job['status'] != 'success':
            return False
        if last_job['secret_payload']:
            try:
                last_spec = self._decrypt_spec(db, last_job['secret_payload'])
            except Exception:
                last_spec = {}
        else:
            last_spec = {}
        _, _, base_spec = self._normalize_primary_record(db, primary)
        desired_spec = self._attach_aggregated_nodes(db, agent_id, base_spec, primary_id=primary['id'])
        if _extract_spec_sub_user_signature(last_spec) == _extract_spec_sub_user_signature(desired_spec):
            return False
        self._dispatch_aggregated_runtime(db, agent_id, uuid.uuid4().hex)
        return True

    def _sync_agents_for_sub_users(self, db, agent_ids, *, allow_only_succeeded: bool = False) -> list:
        synced = []
        for agent_id in sorted(set(agent_ids or ())):
            try:
                if self._sync_agent_if_sub_users_drifted(db, agent_id, allow_only_succeeded=allow_only_succeeded):
                    synced.append(agent_id)
            except Exception:
                continue
        return synced

    def _seed_user_baselines(self, db, user_id, rule_ids):
        existing = {
            r['forward_rule_id']: (r['last_rx_bytes'], r['last_tx_bytes'])
            for r in db.execute(
                'SELECT forward_rule_id,last_rx_bytes,last_tx_bytes FROM sub_user_counter_baselines WHERE user_id=?',
                (user_id,),
            ).fetchall()
        }
        keep = set(rule_ids)
        for fid in list(existing):
            if fid not in keep:
                db.execute('DELETE FROM sub_user_counter_baselines WHERE user_id=? AND forward_rule_id=?', (user_id, fid))
        for fid in rule_ids:
            if fid in existing:
                continue
            row = db.execute(
                'SELECT COALESCE(SUM(rx_bytes),0) AS rx, COALESCE(SUM(tx_bytes),0) AS tx '
                'FROM traffic_counters WHERE forward_rule_id=?',
                (fid,),
            ).fetchone()
            db.execute(
                'INSERT OR IGNORE INTO sub_user_counter_baselines(user_id,forward_rule_id,last_rx_bytes,last_tx_bytes) '
                'VALUES(?,?,?,?)',
                (user_id, fid, row['rx'], row['tx']),
            )

    def _sync_user_forward_usage(self, db, touched_rule_ids=None):
        """Accumulate per-forward byte increments onto bound sub_users and enforce limits."""
        now = self.clock()
        users = db.execute('SELECT * FROM sub_users').fetchall()
        for user in users:
            bound_ids = json.loads(user['forward_rule_ids'])
            if not bound_ids:
                continue
            if touched_rule_ids is not None and not (set(bound_ids) & set(touched_rule_ids)):
                continue
            add_rx = 0
            add_tx = 0
            for fid in bound_ids:
                cur = db.execute(
                    'SELECT COALESCE(SUM(rx_bytes),0) AS rx, COALESCE(SUM(tx_bytes),0) AS tx '
                    'FROM traffic_counters WHERE forward_rule_id=?',
                    (fid,),
                ).fetchone()
                cur_rx, cur_tx = max(0, int(cur['rx'])), max(0, int(cur['tx']))
                base = db.execute(
                    'SELECT last_rx_bytes,last_tx_bytes FROM sub_user_counter_baselines '
                    'WHERE user_id=? AND forward_rule_id=?',
                    (user['id'], fid),
                ).fetchone()
                if base is None:
                    db.execute(
                        'INSERT INTO sub_user_counter_baselines(user_id,forward_rule_id,last_rx_bytes,last_tx_bytes) '
                        'VALUES(?,?,?,?)',
                        (user['id'], fid, cur_rx, cur_tx),
                    )
                    continue
                delta_rx = max(0, cur_rx - int(base['last_rx_bytes']))
                delta_tx = max(0, cur_tx - int(base['last_tx_bytes']))
                add_rx += delta_rx
                add_tx += delta_tx
                db.execute(
                    'UPDATE sub_user_counter_baselines SET last_rx_bytes=?,last_tx_bytes=? '
                    'WHERE user_id=? AND forward_rule_id=?',
                    (cur_rx, cur_tx, user['id'], fid),
                )
            if add_rx or add_tx:
                db.execute(
                    'UPDATE sub_users SET upload_bytes=upload_bytes+?,download_bytes=download_bytes+?,updated_at=? '
                    'WHERE id=?',
                    (add_rx, add_tx, now, user['id']),
                )
        return self._enforce_all_sub_user_quotas_in_db(db, now)

    def _apply_sub_user_metering_deltas(self, db, mark_deltas, now):
        """Apply kernel nftables per-user byte deltas (`uup_`->upload, `udown_`->download)."""
        if not mark_deltas:
            return []
        for mark_id, pair in mark_deltas.items():
            rx_delta, tx_delta = max(0, int(pair[0])), max(0, int(pair[1]))
            if not (rx_delta or tx_delta):
                continue
            prof = db.execute('SELECT user_id FROM sub_user_profiles WHERE mark_id=?', (int(mark_id),)).fetchone()
            if not prof:
                continue
            # nftables output hook (uup_) -> tx_delta = client upload; input hook (udown_) -> rx_delta = client download.
            db.execute(
                'UPDATE sub_users SET upload_bytes=upload_bytes+?,download_bytes=download_bytes+?,updated_at=? WHERE id=?',
                (tx_delta, rx_delta, now, prof['user_id']),
            )
        return self._enforce_all_sub_user_quotas_in_db(db, now)

    def _disable_forwards_in_db(self, db, target_rule_ids, now):
        if not target_rule_ids:
            return []
        disabled_rules = []
        affected_agents = set()
        # Only disable a forward rule if no remaining enabled sub_user relies on it.
        active_users = db.execute('SELECT forward_rule_ids FROM sub_users WHERE enabled=1').fetchall()
        still_used = {
            fid
            for u in active_users
            for fid in json.loads(u['forward_rule_ids'])
        }
        for fid in target_rule_ids:
            if fid in still_used:
                continue
            row = db.execute('SELECT id,agent_id,enabled FROM forward_rules WHERE id=?', (fid,)).fetchone()
            if row and row['enabled']:
                db.execute(
                    'UPDATE forward_rules SET enabled=0,revision=revision+1,updated_at=? WHERE id=?',
                    (now, fid),
                )
                disabled_rules.append(fid)
                affected_agents.add(row['agent_id'])
        for agent_id in sorted(affected_agents):
            sync = self._sync_agent_gost(db, agent_id, uuid.uuid4().hex, require_capable=False)
            if sync:
                db.execute(
                    'UPDATE forward_rules SET job_id=? WHERE agent_id=? AND enabled=1',
                    (sync['job_id'], agent_id),
                )
        if disabled_rules:
            self._audit(db, 'sub_user_ports_disabled')
        return disabled_rules

    def _apply_monthly_resets_in_db(self, db, now, *, only_user_id=None):
        dt = datetime.fromtimestamp(float(now), tz=timezone.utc)
        ym = dt.strftime('%Y-%m')
        day = dt.day
        if only_user_id:
            rows = db.execute(
                '''SELECT u.*, p.reset_day, p.last_reset_month, p.allowed_nodes
                   FROM sub_users u JOIN sub_user_profiles p ON p.user_id=u.id
                   WHERE u.id=? AND p.reset_day BETWEEN 1 AND 28''',
                (only_user_id,),
            ).fetchall()
        else:
            rows = db.execute(
                '''SELECT u.*, p.reset_day, p.last_reset_month, p.allowed_nodes
                   FROM sub_users u JOIN sub_user_profiles p ON p.user_id=u.id
                   WHERE p.reset_day BETWEEN 1 AND 28'''
            ).fetchall()
        reset_users = []
        affected_agents = set()
        for row in rows:
            if day < int(row['reset_day']) or str(row['last_reset_month'] or '') == ym:
                continue
            rule_ids = json.loads(row['forward_rule_ids'])
            for fid in rule_ids:
                cur = db.execute(
                    'SELECT COALESCE(SUM(rx_bytes),0) AS rx, COALESCE(SUM(tx_bytes),0) AS tx '
                    'FROM traffic_counters WHERE forward_rule_id=?',
                    (fid,),
                ).fetchone()
                db.execute(
                    '''INSERT INTO sub_user_counter_baselines(user_id,forward_rule_id,last_rx_bytes,last_tx_bytes)
                       VALUES(?,?,?,?)
                       ON CONFLICT(user_id, forward_rule_id) DO UPDATE SET
                         last_rx_bytes=excluded.last_rx_bytes, last_tx_bytes=excluded.last_tx_bytes''',
                    (row['id'], fid, cur['rx'], cur['tx']),
                )
            expire_at = float(row['expire_at'] or 0)
            should_reenable = (
                not row['enabled']
                and row['disabled_reason'] == 'quota_exceeded'
                and (expire_at <= 0 or now < expire_at)
            )
            db.execute(
                '''UPDATE sub_users SET upload_bytes=0,download_bytes=0,
                   enabled=CASE WHEN ? THEN 1 ELSE enabled END,
                   disabled_reason=CASE WHEN ? THEN '' ELSE disabled_reason END,
                   updated_at=? WHERE id=?''',
                (int(should_reenable), int(should_reenable), now, row['id']),
            )
            db.execute(
                'UPDATE sub_user_profiles SET last_reset_month=? WHERE user_id=?',
                (ym, row['id']),
            )
            self._audit(db, 'sub_user_monthly_reset')
            reset_users.append(row['id'])
            if should_reenable:
                affected_agents.update(_extract_agent_ids_from_nodes(json.loads(row['allowed_nodes'] or '[]')))
        if affected_agents:
            self._sync_agents_for_sub_users(db, affected_agents)
        return reset_users

    def _enforce_all_sub_user_quotas_in_db(self, db, now):
        disabled_total = []
        affected_agents = set()
        rows = db.execute('SELECT * FROM sub_users WHERE enabled=1').fetchall()
        for row in rows:
            used = max(0, int(row['upload_bytes'])) + max(0, int(row['download_bytes']))
            quota = max(0, int(row['quota_bytes']))
            expire_at = float(row['expire_at'] or 0)
            reason = ''
            if expire_at > 0 and now >= expire_at:
                reason = 'expired'
            elif quota > 0 and used >= quota:
                reason = 'quota_exceeded'
            if reason:
                db.execute(
                    'UPDATE sub_users SET enabled=0,disabled_reason=?,updated_at=? WHERE id=?',
                    (reason, now, row['id']),
                )
                self._audit(db, 'sub_user_' + reason)
                disabled_total.extend(
                    self._disable_forwards_in_db(db, json.loads(row['forward_rule_ids']), now)
                )
                prof = db.execute('SELECT allowed_nodes FROM sub_user_profiles WHERE user_id=?', (row['id'],)).fetchone()
                if prof:
                    affected_agents.update(_extract_agent_ids_from_nodes(json.loads(prof['allowed_nodes'] or '[]')))
        if affected_agents:
            self._sync_agents_for_sub_users(db, affected_agents)
        return disabled_total

    def reconcile_sub_users(self):
        """Periodic maintenance: monthly traffic resets, expiry/quota cutoff, and drifted Agent catch-up."""
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            now = self.clock()
            reset_users = self._apply_monthly_resets_in_db(db, now)
            disabled_rules = self._enforce_all_sub_user_quotas_in_db(db, now)
            deployed_agents = [
                r['agent_id']
                for r in db.execute(
                    'SELECT DISTINCT d.agent_id FROM deployments d JOIN agents a ON a.id=d.agent_id WHERE a.revoked_at IS NULL'
                ).fetchall()
            ]
            synced_agents = self._sync_agents_for_sub_users(db, deployed_agents, allow_only_succeeded=True)
            return {
                'reset_users': reset_users,
                'disabled_rules': disabled_rules,
                'synced_agents': synced_agents,
            }

    def list_available_sub_nodes(self, manual_nodes=()):
        """Enumerate selectable nodes for multi-user subscriptions (managed + adopted + manual, no airports)."""
        with self.connection() as db:
            agents = {}
            for arow in db.execute('SELECT * FROM agents WHERE revoked_at IS NULL ORDER BY name ASC').fetchall():
                view = self._view(arow)
                agents[arow['id']] = {
                    'name': view['name'],
                    'status': view['status'],
                    'public_ipv4': view['public_ipv4'],
                    'public_ipv6': view['public_ipv6'],
                    'observed_ip': arow['observed_ip'] or '',
                }

            rewrite_targets = set()
            for frow in db.execute(
                '''SELECT f.targets, f.settings FROM forward_rules f
                   JOIN agents a ON a.id=f.agent_id
                   WHERE f.enabled=1 AND a.revoked_at IS NULL'''
            ).fetchall():
                try:
                    opts = json.loads(frow['settings'] or '{}')
                except Exception:
                    opts = {}
                if not opts.get('rewrite_subscription'):
                    continue
                for target in json.loads(frow['targets'] or '[]'):
                    addr = target.get('addr') if isinstance(target, dict) else target
                    key = _split_addr_str(str(addr or ''))
                    if key[0] and 1 <= key[1] <= 65535:
                        rewrite_targets.add(key)

            items = []
            active_agent_ids = set()
            for row in db.execute(
                '''SELECT d.id, d.agent_id, d.protocol, d.settings, j.type AS job_type, j.status AS job_status
                   FROM deployments d JOIN jobs j ON j.id=d.job_id
                   ORDER BY d.updated_at ASC, d.id ASC'''
            ).fetchall():
                agent = agents.get(row['agent_id'])
                if not agent:
                    continue
                if row['job_type'].endswith('.remove') and row['job_status'] == 'success':
                    continue
                active_agent_ids.add(row['agent_id'])
                settings = json.loads(row['settings'])
                if not self._is_projectable_record(row['protocol'], settings):
                    continue
                norm_proto = normalize_protocol(row['protocol'])
                srv = settings.get('server') or agent['public_ipv4'] or agent['observed_ip'] or agent['public_ipv6']
                port = int(settings.get('listen_port') or 0)
                items.append({
                    'key': f"agent::{row['agent_id']}::{row['id']}",
                    'name': node_name(row['id'], settings['name']),
                    'source': 'managed',
                    'protocol': norm_proto,
                    'agent_id': row['agent_id'],
                    'agent_name': agent['name'],
                    'server': srv,
                    'port': port,
                    'supports_independent_creds': norm_proto in SHARED_PORT_PROTOCOLS,
                    'has_relay_rewrite': _normalize_host_port(srv, port) in rewrite_targets,
                })

            if active_agent_ids:
                placeholders = ','.join('?' for _ in active_agent_ids)
                for erow in db.execute(
                    f'SELECT * FROM agent_nodes WHERE agent_id IN ({placeholders}) ORDER BY updated_at ASC, id ASC',
                    tuple(active_agent_ids),
                ).fetchall():
                    agent = agents.get(erow['agent_id'])
                    if not agent:
                        continue
                    settings = json.loads(erow['settings'])
                    if not self._is_projectable_record(erow['protocol'], settings):
                        continue
                    norm_proto = normalize_protocol(erow['protocol'])
                    srv = settings.get('server') or agent['public_ipv4'] or agent['observed_ip'] or agent['public_ipv6']
                    port = int(settings.get('listen_port') or 0)
                    items.append({
                        'key': f"agent::{erow['agent_id']}::{erow['id']}",
                        'name': node_name(erow['id'], settings['name']),
                        'source': 'managed',
                        'protocol': norm_proto,
                        'agent_id': erow['agent_id'],
                        'agent_name': agent['name'],
                        'server': srv,
                        'port': port,
                        'supports_independent_creds': norm_proto in SHARED_PORT_PROTOCOLS,
                        'has_relay_rewrite': _normalize_host_port(srv, port) in rewrite_targets,
                    })

            for arow in db.execute(
                '''SELECT a.*, s.custom_name, s.server_override
                   FROM adopted_nodes a
                   JOIN adopted_node_secrets s ON s.agent_id=a.agent_id AND s.source_key=a.source_key
                   WHERE s.adopted_status='adopted'
                   ORDER BY a.listen_port ASC, a.id ASC'''
            ).fetchall():
                agent = agents.get(arow['agent_id'])
                if not agent:
                    continue
                default_srv = agent['public_ipv4'] or agent['public_ipv6'] or agent['observed_ip'] or arow['sni']
                srv = (arow['server_override'] or '').strip() or (
                    arow['sni'] if (arow['tls_mode'] != 'reality' and arow['sni']) else default_srv
                ) or default_srv
                port = int(arow['listen_port'] or 0)
                items.append({
                    'key': f"adopted::{arow['agent_id']}::{arow['source_key']}",
                    'name': self._adopted_node_display_name(arow, arow['custom_name']),
                    'source': 'adopted',
                    'protocol': str(arow['protocol'] or ''),
                    'agent_id': arow['agent_id'],
                    'agent_name': agent['name'],
                    'server': srv,
                    'port': port,
                    'supports_independent_creds': False,
                    'has_relay_rewrite': _normalize_host_port(srv, port) in rewrite_targets,
                })

            seen_manual = set()
            for node in manual_nodes or ():
                if not isinstance(node, dict):
                    continue
                mname = str(node.get('name') or '').strip()
                if not mname or mname in seen_manual:
                    continue
                seen_manual.add(mname)
                srv = str(node.get('server') or '').strip()
                try:
                    port = int(node.get('port') or 0)
                except (TypeError, ValueError):
                    port = 0
                items.append({
                    'key': f'manual::{mname}',
                    'name': mname,
                    'source': 'manual',
                    'protocol': str(node.get('type') or ''),
                    'agent_id': '',
                    'agent_name': '手工节点',
                    'server': srv,
                    'port': port,
                    'supports_independent_creds': False,
                    'has_relay_rewrite': _normalize_host_port(srv, port) in rewrite_targets,
                })
            return items

    def create_sub_user(
        self,
        username,
        *,
        quota_bytes=0,
        expire_at=0,
        enabled=True,
        prefer_relay=False,
        allowed_groups=(),
        forward_rule_ids=(),
        max_connections=0,
        rate_limit_kbps=0,
        allowed_nodes=(),
        info_nodes=True,
        reset_day=0,
    ):
        token = 'pfsub_' + secrets.token_urlsafe(32)
        user_id = uuid.uuid4().hex
        now = self.clock()
        groups_list = [str(g).strip() for g in allowed_groups if str(g).strip()]
        rules_list = [str(f).strip() for f in forward_rule_ids if str(f).strip()]
        nodes_list = normalize_allowed_nodes(allowed_nodes)
        reset_val = max(0, min(28, int(reset_day or 0)))
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM sub_users WHERE username=?', (username,)).fetchone():
                raise JobConflict()
            for fid in rules_list:
                if not db.execute('SELECT 1 FROM forward_rules WHERE id=?', (fid,)).fetchone():
                    raise JobNotFound()
            cipher = self._cipher(db)
            token_enc = cipher.encrypt(token.encode('utf-8')).decode('utf-8')
            db.execute(
                '''INSERT INTO sub_users(
                       id,username,token_hash,token_enc,token_prefix,upload_bytes,download_bytes,
                       quota_bytes,expire_at,enabled,prefer_relay,allowed_groups,forward_rule_ids,
                       max_connections,rate_limit_kbps,disabled_reason,created_at,updated_at
                   ) VALUES(?,?,?,?,?,0,0,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    user_id, username, hash_sub_token(token), token_enc, token[:10] + '...',
                    max(0, int(quota_bytes)), max(0.0, float(expire_at)), int(bool(enabled)),
                    int(bool(prefer_relay)), json.dumps(groups_list), json.dumps(rules_list),
                    max(0, int(max_connections)), max(0, int(rate_limit_kbps)), '', now, now,
                ),
            )
            prof = self._ensure_sub_user_profile(
                db, user_id, allowed_nodes=nodes_list, info_nodes=bool(info_nodes), reset_day=reset_val
            )
            self._seed_user_baselines(db, user_id, rules_list)
            self._audit(db, 'sub_user_created')
            affected_agents = _extract_agent_ids_from_nodes(nodes_list)
            if affected_agents:
                self._sync_agents_for_sub_users(db, affected_agents)
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            return self._sub_user_view(row, prof, include_token=token)

    def list_sub_users(self):
        with self.connection() as db:
            rows = db.execute('SELECT * FROM sub_users ORDER BY created_at DESC, username').fetchall()
            out = []
            for row in rows:
                prof = self._ensure_sub_user_profile(db, row['id'])
                out.append(self._sub_user_view(row, prof))
            return out

    def get_sub_user_token(self, user_id):
        with self.connection() as db:
            row = db.execute('SELECT id,username,token_enc FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
            plaintext = self._cipher(db).decrypt(row['token_enc'].encode('utf-8')).decode('utf-8')
            return {'id': row['id'], 'username': row['username'], 'token': plaintext}

    def rotate_sub_user_token(self, user_id):
        new_token = 'pfsub_' + secrets.token_urlsafe(32)
        new_seed_hex = secrets.token_hex(32)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
            prof = self._ensure_sub_user_profile(db, user_id)
            cipher = self._cipher(db)
            enc = cipher.encrypt(new_token.encode('utf-8')).decode('utf-8')
            seed_enc = cipher.encrypt(new_seed_hex.encode('ascii')).decode('ascii')
            db.execute(
                'UPDATE sub_users SET token_hash=?,token_enc=?,token_prefix=?,updated_at=? WHERE id=?',
                (hash_sub_token(new_token), enc, new_token[:10] + '...', self.clock(), user_id),
            )
            db.execute('UPDATE sub_user_profiles SET cred_seed_enc=? WHERE user_id=?', (seed_enc, user_id))
            self._audit(db, 'sub_user_token_rotated')
            affected_agents = _extract_agent_ids_from_nodes(json.loads(prof['allowed_nodes'] or '[]'))
            if affected_agents:
                self._sync_agents_for_sub_users(db, affected_agents)
            updated = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            updated_prof = db.execute('SELECT * FROM sub_user_profiles WHERE user_id=?', (user_id,)).fetchone()
            return self._sub_user_view(updated, updated_prof, include_token=new_token)

    def update_sub_user(self, user_id, **fields):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
            prof = self._ensure_sub_user_profile(db, user_id)
            old_nodes = json.loads(prof['allowed_nodes'] or '[]')
            now = self.clock()
            updates = {}
            for key in ('quota_bytes', 'max_connections', 'rate_limit_kbps', 'upload_bytes', 'download_bytes'):
                if key in fields and fields[key] is not None:
                    updates[key] = max(0, int(fields[key]))
            if 'expire_at' in fields and fields['expire_at'] is not None:
                updates['expire_at'] = max(0.0, float(fields['expire_at']))
            if 'enabled' in fields and fields['enabled'] is not None:
                updates['enabled'] = int(bool(fields['enabled']))
                if fields['enabled']:
                    updates['disabled_reason'] = ''
            if 'prefer_relay' in fields and fields['prefer_relay'] is not None:
                updates['prefer_relay'] = int(bool(fields['prefer_relay']))
            if 'allowed_groups' in fields and fields['allowed_groups'] is not None:
                updates['allowed_groups'] = json.dumps([str(g).strip() for g in fields['allowed_groups'] if str(g).strip()])
            if 'forward_rule_ids' in fields and fields['forward_rule_ids'] is not None:
                rule_ids = [str(f).strip() for f in fields['forward_rule_ids'] if str(f).strip()]
                for fid in rule_ids:
                    if not db.execute('SELECT 1 FROM forward_rules WHERE id=?', (fid,)).fetchone():
                        raise JobNotFound()
                updates['forward_rule_ids'] = json.dumps(rule_ids)
                self._seed_user_baselines(db, user_id, rule_ids)

            if updates:
                updates['updated_at'] = now
                clauses = ', '.join(f'{col}=?' for col in updates)
                db.execute(f'UPDATE sub_users SET {clauses} WHERE id=?', (*updates.values(), user_id))

            prof_updates = {}
            new_nodes = old_nodes
            if 'allowed_nodes' in fields and fields['allowed_nodes'] is not None:
                new_nodes = normalize_allowed_nodes(fields['allowed_nodes'])
                prof_updates['allowed_nodes'] = json.dumps(new_nodes)
            if 'info_nodes' in fields and fields['info_nodes'] is not None:
                prof_updates['info_nodes'] = int(bool(fields['info_nodes']))
            if 'reset_day' in fields and fields['reset_day'] is not None:
                prof_updates['reset_day'] = max(0, min(28, int(fields['reset_day'])))
            if prof_updates:
                p_clauses = ', '.join(f'{col}=?' for col in prof_updates)
                db.execute(f'UPDATE sub_user_profiles SET {p_clauses} WHERE user_id=?', (*prof_updates.values(), user_id))
                if not updates:
                    db.execute('UPDATE sub_users SET updated_at=? WHERE id=?', (now, user_id))

            self._audit(db, 'sub_user_updated')
            candidate_agents = _extract_agent_ids_from_nodes(old_nodes) | _extract_agent_ids_from_nodes(new_nodes)
            if candidate_agents:
                self._sync_agents_for_sub_users(db, candidate_agents)
            updated = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            updated_prof = db.execute('SELECT * FROM sub_user_profiles WHERE user_id=?', (user_id,)).fetchone()
            return self._sub_user_view(updated, updated_prof)

    def reset_sub_user_traffic(self, user_id, *, re_enable=True):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
            prof = self._ensure_sub_user_profile(db, user_id)
            rule_ids = json.loads(row['forward_rule_ids'])
            for fid in rule_ids:
                cur = db.execute(
                    'SELECT COALESCE(SUM(rx_bytes),0) AS rx, COALESCE(SUM(tx_bytes),0) AS tx '
                    'FROM traffic_counters WHERE forward_rule_id=?',
                    (fid,),
                ).fetchone()
                db.execute(
                    '''INSERT INTO sub_user_counter_baselines(user_id,forward_rule_id,last_rx_bytes,last_tx_bytes)
                       VALUES(?,?,?,?)
                       ON CONFLICT(user_id, forward_rule_id) DO UPDATE SET
                         last_rx_bytes=excluded.last_rx_bytes, last_tx_bytes=excluded.last_tx_bytes''',
                    (user_id, fid, cur['rx'], cur['tx']),
                )
            now = self.clock()
            db.execute(
                '''UPDATE sub_users SET upload_bytes=0,download_bytes=0,
                   enabled=CASE WHEN ? THEN 1 ELSE enabled END,
                   disabled_reason=CASE WHEN ? THEN '' ELSE disabled_reason END,
                   updated_at=? WHERE id=?''',
                (int(bool(re_enable)), int(bool(re_enable)), now, user_id),
            )
            self._audit(db, 'sub_user_traffic_reset')
            affected_agents = _extract_agent_ids_from_nodes(json.loads(prof['allowed_nodes'] or '[]'))
            if affected_agents:
                self._sync_agents_for_sub_users(db, affected_agents)
            updated = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            return self._sub_user_view(updated, prof)

    def delete_sub_user(self, user_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            prof = db.execute('SELECT allowed_nodes FROM sub_user_profiles WHERE user_id=?', (user_id,)).fetchone()
            affected_agents = _extract_agent_ids_from_nodes(json.loads(prof['allowed_nodes'] or '[]')) if prof else set()
            res = db.execute('DELETE FROM sub_users WHERE id=?', (user_id,))
            if res.rowcount != 1:
                raise JobNotFound()
            self._audit(db, 'sub_user_deleted')
            if affected_agents:
                self._sync_agents_for_sub_users(db, affected_agents)
            return {'status': 'ok', 'deleted_id': user_id}

    def authorize_sub_token(self, token):
        """Validate a per-user subscription token, enforcing resets, expiry & quota atomically."""
        if not isinstance(token, str) or len(token) < 16 or len(token) > 128:
            return None
        token_digest = hash_sub_token(token)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE token_hash=?', (token_digest,)).fetchone()
            if not row:
                return None
            self._ensure_sub_user_profile(db, row['id'])
            now = self.clock()
            self._apply_monthly_resets_in_db(db, now, only_user_id=row['id'])
            self._sync_user_forward_usage(db, json.loads(row['forward_rule_ids']) or None)
            self._enforce_all_sub_user_quotas_in_db(db, now)
            refreshed = db.execute('SELECT * FROM sub_users WHERE id=?', (row['id'],)).fetchone()
            prof = db.execute('SELECT * FROM sub_user_profiles WHERE user_id=?', (row['id'],)).fetchone()
            view = self._sub_user_view(refreshed, prof)
            if not refreshed['enabled']:
                return {
                    'authorized': False,
                    'reason': refreshed['disabled_reason'] or 'disabled',
                    'user': view,
                    'userinfo': format_subscription_userinfo(view),
                }
            return {
                'authorized': True,
                'reason': '',
                'user': view,
                'userinfo': format_subscription_userinfo(view),
            }


class SubUserCreateRequest(BaseModel):
    class Config:
        extra = 'forbid'

    username: constr(strict=True, min_length=1, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
    quota_bytes: StrictInt = Field(default=0, ge=0)
    expire_at: float = Field(default=0.0, ge=0.0)
    enabled: StrictBool = True
    prefer_relay: StrictBool = False
    allowed_groups: list[constr(strict=True, min_length=1, max_length=64)] = Field(default_factory=list, max_length=64)
    forward_rule_ids: list[constr(strict=True, pattern=r'^[a-f0-9]{32}$')] = Field(default_factory=list, max_length=64)
    max_connections: StrictInt = Field(default=0, ge=0, le=100000)
    rate_limit_kbps: StrictInt = Field(default=0, ge=0, le=10000000)
    allowed_nodes: list[constr(strict=True, min_length=3, max_length=256)] = Field(default_factory=list, max_length=256)
    info_nodes: StrictBool = True
    reset_day: StrictInt = Field(default=0, ge=0, le=28)


class SubUserUpdateRequest(BaseModel):
    class Config:
        extra = 'forbid'

    quota_bytes: Optional[StrictInt] = Field(default=None, ge=0)
    expire_at: Optional[float] = Field(default=None, ge=0.0)
    enabled: Optional[StrictBool] = None
    prefer_relay: Optional[StrictBool] = None
    allowed_groups: Optional[list[constr(strict=True, min_length=1, max_length=64)]] = Field(default=None, max_length=64)
    forward_rule_ids: Optional[list[constr(strict=True, pattern=r'^[a-f0-9]{32}$')]] = Field(default=None, max_length=64)
    upload_bytes: Optional[StrictInt] = Field(default=None, ge=0)
    download_bytes: Optional[StrictInt] = Field(default=None, ge=0)
    max_connections: Optional[StrictInt] = Field(default=None, ge=0, le=100000)
    rate_limit_kbps: Optional[StrictInt] = Field(default=None, ge=0, le=10000000)
    allowed_nodes: Optional[list[constr(strict=True, min_length=3, max_length=256)]] = Field(default=None, max_length=256)
    info_nodes: Optional[StrictBool] = None
    reset_day: Optional[StrictInt] = Field(default=None, ge=0, le=28)


def create_sub_user_router(*, verify_management, store_provider, manual_nodes_reader=None):
    """Build management router for subscription user quota, node authorization, and token CRUD."""
    router = APIRouter(prefix='/api/sub-users', dependencies=[Depends(verify_management)])

    @router.get('')
    def list_users():
        return {'users': store_provider().list_sub_users()}

    @router.get('/available-nodes')
    def available_nodes():
        manual = manual_nodes_reader() if callable(manual_nodes_reader) else ()
        return {'nodes': store_provider().list_available_sub_nodes(manual)}

    @router.post('')
    def create_user(data: SubUserCreateRequest):
        try:
            return store_provider().create_sub_user(
                data.username,
                quota_bytes=data.quota_bytes,
                expire_at=data.expire_at,
                enabled=data.enabled,
                prefer_relay=data.prefer_relay,
                allowed_groups=data.allowed_groups,
                forward_rule_ids=data.forward_rule_ids,
                max_connections=data.max_connections,
                rate_limit_kbps=data.rate_limit_kbps,
                allowed_nodes=data.allowed_nodes,
                info_nodes=data.info_nodes,
                reset_day=data.reset_day,
            )
        except JobConflict:
            raise HTTPException(status_code=409, detail='Subscription user conflict or duplicate username')
        except JobNotFound:
            raise HTTPException(status_code=404, detail='Referenced forward rule not found')

    @router.get('/{user_id}/token')
    def reveal_user_token(user_id: str):
        try:
            return store_provider().get_sub_user_token(user_id)
        except JobNotFound:
            raise HTTPException(status_code=404, detail='Subscription user not found')

    @router.post('/{user_id}/rotate')
    def rotate_user_token(user_id: str):
        try:
            return store_provider().rotate_sub_user_token(user_id)
        except JobNotFound:
            raise HTTPException(status_code=404, detail='Subscription user not found')

    @router.patch('/{user_id}')
    def update_user(user_id: str, data: SubUserUpdateRequest):
        try:
            return store_provider().update_sub_user(user_id, **data.model_dump(exclude_unset=True))
        except JobNotFound:
            raise HTTPException(status_code=404, detail='Subscription user or forward rule not found')

    @router.post('/{user_id}/reset-traffic')
    def reset_traffic(user_id: str):
        try:
            return store_provider().reset_sub_user_traffic(user_id)
        except JobNotFound:
            raise HTTPException(status_code=404, detail='Subscription user not found')

    @router.delete('/{user_id}')
    def delete_user(user_id: str):
        try:
            return store_provider().delete_sub_user(user_id)
        except JobNotFound:
            raise HTTPException(status_code=404, detail='Subscription user not found')

    return router
