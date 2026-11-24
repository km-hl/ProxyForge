"""Pure standard-library host nftables per-user socket mark byte accounting."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

NFT_TABLE = 'proxyforge_users'
USER_MARK_BASE = 0x50460000
USER_MARK_MAX = 0xFFFF


def user_mark(mark_id):
    """Map 16-bit sub-user mark_id (1..65535) to Linux fwmark (`PF` + id)."""
    if type(mark_id) is not int or not 1 <= mark_id <= USER_MARK_MAX:
        return 0
    return USER_MARK_BASE | mark_id


def mark_from_value(value):
    if type(value) is not int:
        return 0
    if (value & ~USER_MARK_MAX) != USER_MARK_BASE:
        return 0
    return value & USER_MARK_MAX


def normalize_mark_ids(mark_ids):
    out = set()
    for item in mark_ids or ():
        if type(item) is int and 1 <= item <= USER_MARK_MAX:
            out.add(item)
    return sorted(out)


def render_user_nft_script(mark_ids, *, table=NFT_TABLE):
    """Build atomic count-only nftables ruleset matching per-user fwmark/ctmark."""
    ids = normalize_mark_ids(mark_ids)
    lines = [
        f'table inet {table} {{}}',
        f'delete table inet {table}',
    ]
    if not ids:
        return '\n'.join(lines) + '\n'
    lines.append(f'table inet {table} {{')
    for mid in ids:
        lines.append(f'\tcounter uup_{mid} {{}}')
        lines.append(f'\tcounter udown_{mid} {{}}')
    lines.append('\tchain input {')
    lines.append('\t\ttype filter hook input priority -150; policy accept;')
    for mid in ids:
        mark_hex = f'0x{user_mark(mid):08x}'
        lines.append(f'\t\tct mark {mark_hex} counter name udown_{mid}')
    lines.append('\t}')
    lines.append('\tchain output {')
    lines.append('\t\ttype filter hook output priority -150; policy accept;')
    for mid in ids:
        mark_hex = f'0x{user_mark(mid):08x}'
        lines.append(f'\t\tmeta mark {mark_hex} ct mark set meta mark counter name uup_{mid}')
    lines.append('\t}')
    lines.append('}')
    return '\n'.join(lines) + '\n'


def parse_user_counters(text, *, table=NFT_TABLE):
    """Parse text output of `nft list counters table inet <table_name>` safely."""
    totals = {}
    if not isinstance(text, str):
        return totals
    cur_table = ''
    cur_counter = ''
    for raw_line in text.splitlines():
        fields = raw_line.split()
        if not fields:
            continue
        if fields[0] == 'table' and len(fields) >= 3:
            cur_table = fields[2].strip('"')
            cur_counter = ''
            continue
        if fields[0] == 'counter' and len(fields) >= 2 and fields[1] != '{':
            cur_counter = fields[1].strip('"')
            continue
        if fields[0] == '}':
            cur_counter = ''
            continue
        if cur_table != table or not cur_counter:
            continue
        for idx in range(len(fields) - 1):
            if fields[idx] != 'bytes':
                continue
            try:
                byte_val = int(fields[idx + 1])
            except ValueError:
                cur_counter = ''
                break
            if byte_val < 0:
                cur_counter = ''
                break
            parts = cur_counter.split('_')
            if len(parts) == 2 and parts[0] in ('uup', 'udown') and parts[1].isdigit():
                mid = int(parts[1])
                if 1 <= mid <= USER_MARK_MAX:
                    rkey = f'subuser:{mid}'
                    entry = totals.setdefault(rkey, {
                        'resource_key': rkey,
                        'forward_rule_id': '',
                        'rx_bytes': 0,
                        'tx_bytes': 0,
                    })
                    if parts[0] == 'udown':
                        entry['rx_bytes'] = byte_val
                    else:
                        entry['tx_bytes'] = byte_val
            cur_counter = ''
            break
    return totals


def _default_nft_runner(args, stdin_text=None, timeout=10.0):
    nft = shutil.which('nft') or '/usr/sbin/nft'
    if not Path(nft).is_file():
        return None
    return subprocess.run(
        [nft, *args],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _atomic_write_json(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.{secrets.token_hex(6)}')
    try:
        fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        if os.name == 'posix':
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


class NftUserCounters:
    """Manage `table inet proxyforge_users` counters with persistent epoch tracking."""

    def __init__(self, state_dir, *, table=NFT_TABLE, runner=None):
        self.state_dir = Path(state_dir)
        self.state_path = self.state_dir / 'nft-users.json'
        self.capable_path = self.state_dir / 'nft-capable'
        self.table = table
        self.runner = runner or _default_nft_runner
        self.state = self._load_state()

    def _load_state(self):
        try:
            data = json.loads(self.state_path.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                return {
                    'signature': str(data.get('signature') or ''),
                    'epoch': str(data.get('epoch') or ''),
                }
        except (OSError, ValueError):
            pass
        return {'signature': '', 'epoch': ''}

    def _record_capable(self, capable):
        try:
            self.capable_path.parent.mkdir(parents=True, exist_ok=True)
            self.capable_path.write_text('1\n' if capable else '0\n', encoding='utf-8')
            if os.name == 'posix':
                os.chmod(self.capable_path, 0o644)
        except OSError:
            pass

    def _table_exists(self):
        proc = self.runner(['list', 'tables'], None)
        if proc is None:
            return None, False
        if proc.returncode != 0:
            return None, False
        for line in (proc.stdout or '').splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'table' and parts[1] == 'inet' and parts[2].strip('"') == self.table:
                return True, True
        return False, True

    def sync(self, mark_ids):
        ids = normalize_mark_ids(mark_ids)
        exists, available = self._table_exists()
        if not available:
            self._record_capable(False)
            return {'ok': False, 'capable': False, 'epoch': self.state['epoch']}
        self._record_capable(True)
        script = render_user_nft_script(ids, table=self.table)
        sig = hashlib.sha256(script.encode('utf-8')).hexdigest()
        if sig == self.state['signature'] and ((not ids and not exists) or (ids and exists)):
            return {'ok': True, 'capable': True, 'changed': False, 'epoch': self.state['epoch']}
        proc = self.runner(['-f', '-'], script)
        if proc is None or proc.returncode != 0:
            return {'ok': False, 'capable': False, 'epoch': self.state['epoch']}
        epoch = 'nft-' + secrets.token_hex(8)
        self.state = {'signature': sig, 'epoch': epoch}
        _atomic_write_json(self.state_path, self.state, mode=0o600)
        return {'ok': True, 'capable': True, 'changed': True, 'epoch': epoch}

    def read(self):
        proc = self.runner(['list', 'counters', 'table', 'inet', self.table], None)
        if proc is None or proc.returncode != 0:
            return {'totals': {}, 'epoch': self.state['epoch']}
        totals = parse_user_counters(proc.stdout or '', table=self.table)
        epoch = self.state['epoch'] or 'nft-0'
        for item in totals.values():
            item['epoch'] = epoch
        return {'totals': totals, 'epoch': epoch}
