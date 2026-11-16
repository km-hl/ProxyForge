"""Multi-user subscription tokens, byte quota accounting, and automatic port cutoff."""
import hashlib
import json
import secrets
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, StrictBool, StrictFloat, StrictInt, constr

from proxyforge.control.job_store import JobConflict, JobNotFound


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


def format_subscription_userinfo(user: dict) -> str:
    upload = max(0, int(user.get('upload_bytes', 0)))
    download = max(0, int(user.get('download_bytes', 0)))
    total = max(0, int(user.get('quota_bytes', 0)))
    expire = max(0, int(user.get('expire_at', 0)))
    return f'upload={upload}; download={download}; total={total}; expire={expire}'


class SubUserStoreMixin:
    def _sub_user_view(self, row, *, include_token=None):
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
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }
        if include_token is not None:
            item['token'] = include_token
        return item

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

    def _enforce_all_sub_user_quotas_in_db(self, db, now):
        disabled_total = []
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
        return disabled_total

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
    ):
        token = 'pfsub_' + secrets.token_urlsafe(32)
        user_id = uuid.uuid4().hex
        now = self.clock()
        groups_list = [str(g).strip() for g in allowed_groups if str(g).strip()]
        rules_list = [str(f).strip() for f in forward_rule_ids if str(f).strip()]
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
            self._seed_user_baselines(db, user_id, rules_list)
            self._audit(db, 'sub_user_created')
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            return self._sub_user_view(row, include_token=token)

    def list_sub_users(self):
        with self.connection() as db:
            rows = db.execute('SELECT * FROM sub_users ORDER BY created_at DESC, username').fetchall()
            return [self._sub_user_view(row) for row in rows]

    def get_sub_user_token(self, user_id):
        with self.connection() as db:
            row = db.execute('SELECT id,username,token_enc FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
            plaintext = self._cipher(db).decrypt(row['token_enc'].encode('utf-8')).decode('utf-8')
            return {'id': row['id'], 'username': row['username'], 'token': plaintext}

    def rotate_sub_user_token(self, user_id):
        new_token = 'pfsub_' + secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
            enc = self._cipher(db).encrypt(new_token.encode('utf-8')).decode('utf-8')
            db.execute(
                'UPDATE sub_users SET token_hash=?,token_enc=?,token_prefix=?,updated_at=? WHERE id=?',
                (hash_sub_token(new_token), enc, new_token[:10] + '...', self.clock(), user_id),
            )
            self._audit(db, 'sub_user_token_rotated')
            updated = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            return self._sub_user_view(updated, include_token=new_token)

    def update_sub_user(self, user_id, **fields):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
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
            self._audit(db, 'sub_user_updated')
            updated = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            return self._sub_user_view(updated)

    def reset_sub_user_traffic(self, user_id, *, re_enable=True):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise JobNotFound()
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
            return self._sub_user_view(db.execute('SELECT * FROM sub_users WHERE id=?', (user_id,)).fetchone())

    def delete_sub_user(self, user_id):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            res = db.execute('DELETE FROM sub_users WHERE id=?', (user_id,))
            if res.rowcount != 1:
                raise JobNotFound()
            self._audit(db, 'sub_user_deleted')
            return {'status': 'ok', 'deleted_id': user_id}

    def authorize_sub_token(self, token):
        """Validate a per-user subscription token, enforcing expiry & quota atomically."""
        if not isinstance(token, str) or len(token) < 16 or len(token) > 128:
            return None
        token_digest = hash_sub_token(token)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM sub_users WHERE token_hash=?', (token_digest,)).fetchone()
            if not row:
                return None
            now = self.clock()
            self._sync_user_forward_usage(db, json.loads(row['forward_rule_ids']) or None)
            self._enforce_all_sub_user_quotas_in_db(db, now)
            refreshed = db.execute('SELECT * FROM sub_users WHERE id=?', (row['id'],)).fetchone()
            view = self._sub_user_view(refreshed)
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


def create_sub_user_router(*, verify_management, store_provider):
    """Build management router for subscription user quota and token CRUD."""
    router = APIRouter(prefix='/api/sub-users', dependencies=[Depends(verify_management)])

    @router.get('')
    def list_users():
        return {'users': store_provider().list_sub_users()}

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
