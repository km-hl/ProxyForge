"""Pure standard-library go-gost Prometheus & nftables byte counter accounting."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import urllib.parse
import urllib.request

_METRIC_LINE_RE = re.compile(
    r'^(gost_service_transfer_(?:input|output)_bytes_total)\{([^}]*)\}\s+([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$'
)
_LABEL_PAIR_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:\\.|[^"\\])*)"')
_SERVICE_FWD_RE = re.compile(r'^fwd_([A-Za-z0-9._-]{1,64})_(tcp|udp)$')
_SERVICE_RELAY_RE = re.compile(r'^relay_([A-Za-z0-9._-]{1,64})$')
_COMMENT_RE = re.compile(r'^proxyforge:(forward|relay):([A-Za-z0-9._-]{1,64}):(in|out)(?::(tcp|udp))?(?::([A-Za-z0-9_-]{1,32}))?$')


def _resource_from_service(service_name):
    match = _SERVICE_FWD_RE.fullmatch(service_name)
    if match:
        return 'forward:' + match.group(1), match.group(1)
    match = _SERVICE_RELAY_RE.fullmatch(service_name)
    if match:
        return 'relay:' + match.group(1), ''
    return 'service:' + service_name, ''


def parse_gost_prometheus_metrics(text):
    """Parse go-gost `/metrics` output into `{resource_key: {rx_bytes, tx_bytes, forward_rule_id}}`."""
    totals = {}
    if not isinstance(text, str):
        raise ValueError('Metrics body must be text')
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        match = _METRIC_LINE_RE.match(line)
        if not match:
            continue
        metric_name, labels_text, value_text = match.groups()
        labels = dict(_LABEL_PAIR_RE.findall(labels_text))
        service_name = labels.get('service', '').strip()
        if not service_name:
            continue
        value = int(float(value_text))
        if value < 0:
            continue
        resource_key, fwd_id = _resource_from_service(service_name)
        entry = totals.setdefault(resource_key, {
            'resource_key': resource_key,
            'forward_rule_id': fwd_id,
            'rx_bytes': 0,
            'tx_bytes': 0,
        })
        if metric_name.endswith('input_bytes_total'):
            entry['rx_bytes'] += value
        else:
            entry['tx_bytes'] += value
    return totals


def collect_loopback_metrics(metrics_addr, *, timeout=2.0, path='/metrics'):
    """Scrape loopback go-gost `/metrics` strictly on 127.0.0.1 or [::1]."""
    text = str(metrics_addr or '').strip()
    if not text:
        raise ValueError('Empty metrics_addr')
    url = f'http://{text}{path}'
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ''
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError('Loopback IP literal required for metrics scraping') from None
    if not addr.is_loopback:
        raise ValueError('Refusing non-loopback metrics endpoint')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={'User-Agent': 'ProxyForge-agent-metrics'})
    with opener.open(request, timeout=timeout) as response:
        if getattr(response, 'status', 200) != 200:
            raise OSError('Unexpected metrics HTTP status')
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Metrics response exceeds 1 MiB limit')
    return parse_gost_prometheus_metrics(raw.decode('utf-8'))


def parse_nftables_counters(raw_json):
    """Parse `nft -j list table inet proxyforge` rule counters keyed by resource."""
    payload = json.loads(raw_json) if isinstance(raw_json, (str, bytes)) else raw_json
    if not isinstance(payload, dict) or not isinstance(payload.get('nftables'), list):
        raise ValueError('Invalid nftables JSON structure')
    totals = {}
    for entry in payload['nftables']:
        if not isinstance(entry, dict) or 'rule' not in entry:
            continue
        rule = entry['rule']
        if not isinstance(rule, dict):
            continue
        comment = str(rule.get('comment') or '').strip()
        match = _COMMENT_RE.fullmatch(comment)
        if not match:
            continue
        kind, res_id, direction, _, _ = match.groups()
        rule_bytes = 0
        for expr in rule.get('expr') or []:
            if isinstance(expr, dict) and isinstance(expr.get('counter'), dict):
                val = expr['counter'].get('bytes', 0)
                if type(val) is int and val >= 0:
                    rule_bytes += val
        resource_key = f'{kind}:{res_id}'
        fwd_id = res_id if kind == 'forward' else ''
        item = totals.setdefault(resource_key, {
            'resource_key': resource_key,
            'forward_rule_id': fwd_id,
            'rx_bytes': 0,
            'tx_bytes': 0,
        })
        if direction == 'in':
            item['rx_bytes'] += rule_bytes
        else:
            item['tx_bytes'] += rule_bytes
    return totals


def collect_nftables_counters(*, table='proxyforge', family='inet', timeout=3.0):
    """Read kernel nftables counter JSON when `nft` binary exists."""
    nft = shutil.which('nft') or '/usr/sbin/nft'
    if not Path(nft).is_file():
        return {}
    completed = subprocess.run(
        [nft, '-j', 'list', 'table', family, table],
        capture_output=True, text=True, timeout=timeout,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return {}
    return parse_nftables_counters(completed.stdout)


def render_nftables_forward_rules(forwards, *, table='proxyforge', family='inet'):
    """Render deterministic read/count-only nftables ruleset for forward ports."""
    lines = [
        f'table {family} {table} {{',
        '  chain input_counters {',
        '    type filter hook input priority filter + 5; policy accept;',
    ]
    out_lines = [
        '  chain output_counters {',
        '    type filter hook output priority filter + 5; policy accept;',
    ]
    for fwd in forwards:
        if fwd.get('enabled', True) is False:
            continue
        port = int(fwd['listen_port'])
        proto = fwd.get('protocol', 'tcp+udp')
        protos = ('tcp', 'udp') if proto == 'tcp+udp' else (proto,)
        fid = fwd['id']
        for transport in protos:
            lines.append(f'    {transport} dport {port} counter comment "proxyforge:forward:{fid}:in:{transport}"')
            out_lines.append(f'    {transport} sport {port} counter comment "proxyforge:forward:{fid}:out:{transport}"')
    lines.append('  }')
    out_lines.append('  }')
    return '\n'.join([*lines, *out_lines, '}']) + '\n'


def _atomic_write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.{secrets.token_hex(6)}')
    try:
        fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


class TrafficCounterState:
    """Monotonic delta calculator resilient to go-gost restarts and nftables reloads."""

    def __init__(self, state_path):
        self.path = Path(state_path)
        self.sequence = 0
        self.counters = {}
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                if type(data.get('sequence')) is int and data['sequence'] >= 0:
                    self.sequence = data['sequence']
                if isinstance(data.get('counters'), dict):
                    self.counters = dict(data['counters'])
        except (OSError, ValueError):
            self.sequence = 0
            self.counters = {}

    def compute_deltas(self, current_totals, *, epoch='gost-0', max_batch_items=48):
        """Compute non-negative deltas vs last high-water baseline and chunk into compact batches."""
        items = []
        for resource_key in sorted(current_totals):
            sample = current_totals[resource_key]
            sample_epoch = str(sample.get('epoch') or epoch)
            raw_rx = max(0, int(sample.get('rx_bytes', 0)))
            raw_tx = max(0, int(sample.get('tx_bytes', 0)))
            prev = self.counters.get(resource_key)
            if prev is None or prev.get('epoch') != sample_epoch:
                rx_delta = raw_rx
                tx_delta = raw_tx
            else:
                prev_rx = max(0, int(prev.get('raw_rx', 0)))
                prev_tx = max(0, int(prev.get('raw_tx', 0)))
                # Counter shrink means daemon restart/reset; never emit negative deltas.
                rx_delta = (raw_rx - prev_rx) if raw_rx >= prev_rx else raw_rx
                tx_delta = (raw_tx - prev_tx) if raw_tx >= prev_tx else raw_tx
            self.counters[resource_key] = {
                'raw_rx': raw_rx,
                'raw_tx': raw_tx,
                'epoch': sample_epoch,
            }
            if rx_delta > 0 or tx_delta > 0:
                items.append({
                    'resource_key': resource_key,
                    'forward_rule_id': str(sample.get('forward_rule_id', '')),
                    'rx_delta': rx_delta,
                    'tx_delta': tx_delta,
                    'raw_rx': raw_rx,
                    'raw_tx': raw_tx,
                    'epoch': sample_epoch,
                })

        batches = []
        chunk_size = max(1, min(int(max_batch_items), 64))
        for idx in range(0, len(items), chunk_size):
            self.sequence += 1
            batches.append({
                'batch_id': secrets.token_hex(16),
                'sequence': self.sequence,
                'items': items[idx:idx + chunk_size],
            })
        _atomic_write_json(self.path, {'sequence': self.sequence, 'counters': self.counters})
        return batches


class ReliableTrafficSpool(TrafficCounterState):
    """Persist unacknowledged delta batches across transient upload failures."""

    def _load(self):
        self.pending = []
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                if type(data.get('sequence')) is int and data['sequence'] >= 0:
                    self.sequence = data['sequence']
                if isinstance(data.get('counters'), dict):
                    self.counters = dict(data['counters'])
                if isinstance(data.get('pending'), list):
                    self.pending = list(data['pending'])[:64]
        except (OSError, ValueError):
            self.sequence = 0
            self.counters = {}
            self.pending = []

    def _save(self):
        _atomic_write_json(self.path, {
            'sequence': self.sequence,
            'counters': self.counters,
            'pending': self.pending[-64:],
        })

    def compute_deltas(self, current_totals, *, epoch='gost-0', max_batch_items=48):
        items = []
        for resource_key in sorted(current_totals):
            sample = current_totals[resource_key]
            sample_epoch = str(sample.get('epoch') or epoch)
            raw_rx = max(0, int(sample.get('rx_bytes', 0)))
            raw_tx = max(0, int(sample.get('tx_bytes', 0)))
            prev = self.counters.get(resource_key)
            if prev is None or prev.get('epoch') != sample_epoch:
                rx_delta, tx_delta = raw_rx, raw_tx
            else:
                prev_rx = max(0, int(prev.get('raw_rx', 0)))
                prev_tx = max(0, int(prev.get('raw_tx', 0)))
                rx_delta = (raw_rx - prev_rx) if raw_rx >= prev_rx else raw_rx
                tx_delta = (raw_tx - prev_tx) if raw_tx >= prev_tx else raw_tx
            self.counters[resource_key] = {'raw_rx': raw_rx, 'raw_tx': raw_tx, 'epoch': sample_epoch}
            if rx_delta > 0 or tx_delta > 0:
                items.append({
                    'resource_key': resource_key,
                    'forward_rule_id': str(sample.get('forward_rule_id', '')),
                    'rx_delta': rx_delta,
                    'tx_delta': tx_delta,
                    'raw_rx': raw_rx,
                    'raw_tx': raw_tx,
                    'epoch': sample_epoch,
                })
        new_batches = []
        chunk_size = max(1, min(int(max_batch_items), 64))
        for idx in range(0, len(items), chunk_size):
            self.sequence += 1
            new_batches.append({
                'batch_id': secrets.token_hex(16),
                'sequence': self.sequence,
                'items': items[idx:idx + chunk_size],
            })
        if new_batches:
            self.pending = (self.pending + new_batches)[-64:]
        self._save()
        return list(self.pending)

    def ack(self, batch_id):
        before = len(self.pending)
        self.pending = [b for b in self.pending if b.get('batch_id') != batch_id]
        if len(self.pending) != before:
            self._save()


def flush_gost_traffic(client, config, config_path, *,
                       metrics_meta_path=Path('/var/lib/proxyforge-runtime/services/gost/metrics.json'),
                       include_nftables=False,
                       nft_user_reader=None):
    """Poll loopback go-gost /metrics and per-user nftables counters, uploading idempotent delta batches."""
    meta_file = Path(metrics_meta_path)
    totals = {}
    epoch = 'gost-0'
    if meta_file.is_file():
        try:
            meta = json.loads(meta_file.read_text(encoding='utf-8'))
            addr = str((meta or {}).get('metrics_addr') or '').strip()
            epoch = str((meta or {}).get('epoch') or 'gost-0')
            if addr:
                totals = collect_loopback_metrics(addr)
        except (OSError, ValueError):
            pass
    if include_nftables:
        try:
            for key, item in collect_nftables_counters().items():
                totals.setdefault(key, item)
        except (OSError, ValueError):
            pass
    try:
        if nft_user_reader is None:
            from .runtime_client import read_nft_user_counters
            nft_user_reader = read_nft_user_counters
        nft_data = nft_user_reader()
        if isinstance(nft_data, dict):
            nft_epoch = str(nft_data.get('epoch') or 'nft-0')
            for key, item in (nft_data.get('totals') or {}).items():
                if not isinstance(item, dict):
                    continue
                entry = dict(item)
                entry.setdefault('epoch', nft_epoch)
                totals[key] = entry
    except (OSError, ValueError):
        pass
    state_path = Path(config_path).with_name('traffic-state.json')
    if not totals and not state_path.exists():
        return 0
    spool = ReliableTrafficSpool(state_path)
    batches = spool.compute_deltas(totals, epoch=epoch)
    uploaded = 0
    for batch in batches:
        payload = {
            'instance_id': config['instance_id'],
            'batch_id': batch['batch_id'],
            'sequence': batch['sequence'],
            'items': batch['items'],
        }
        client.post('/api/agent/traffic', payload, config['token'])
        spool.ack(batch['batch_id'])
        uploaded += len(batch['items'])
    return uploaded
