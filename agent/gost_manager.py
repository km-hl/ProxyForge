"""Pure standard-library go-gost v3 forwarding, multi-hop chain, and Best Exit manager."""
import ipaddress
import math
import re
import socket
import time

GOST_CONFIG_ACTIONS = ('gost.apply', 'gost.remove')
FORWARD_PROTOCOLS = frozenset(('tcp', 'udp', 'tcp+udp'))
SELECTOR_STRATEGIES = frozenset(('fifo', 'round', 'random'))
CONNECTOR_TYPES = frozenset(('relay', 'socks5', 'http', 'ss', 'direct'))
DIALER_TYPES = frozenset(('tcp', 'tls', 'mtls', 'ws', 'wss', 'kcp', 'quic'))
LISTENER_TYPES = frozenset(('tcp', 'tls', 'mtls', 'ws', 'wss', 'kcp', 'quic', 'udp'))
HANDLER_TYPES = frozenset(('relay', 'socks5', 'http', 'tcp', 'udp'))

_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_SAFE_IFACE_RE = re.compile(r'^[A-Za-z0-9._-]{1,32}$')
_SAFE_HOST_RE = re.compile(r'^[A-Za-z0-9.-]{1,253}$')


def _require_id(value, label='identifier'):
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise ValueError(f'Invalid {label}')
    return value


def _require_port(value, label='port'):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f'Invalid {label}')
    return value


def _require_optional_text(value, max_len=128, label='text'):
    if value is None:
        return ''
    if not isinstance(value, str) or len(value) > max_len or any(ord(c) < 32 for c in value):
        raise ValueError(f'Invalid {label}')
    return value


def _require_listen(value):
    text = str('::' if value is None else value).strip()
    if not text:
        return '::'
    if text.startswith('[') and text.endswith(']'):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError('Listen address must be a valid IP literal') from None


def validate_host_port(addr, label='address'):
    if not isinstance(addr, str):
        raise ValueError(f'Invalid {label}')
    text = addr.strip()
    if not text or len(text) > 260 or any(ord(c) < 32 or c.isspace() for c in text):
        raise ValueError(f'Invalid {label}')
    host = ''
    port_text = ''
    if text.startswith('['):
        end = text.find(']')
        if end == -1 or end + 1 >= len(text) or text[end + 1] != ':':
            raise ValueError(f'Invalid {label}')
        host = text[1:end]
        port_text = text[end + 2:]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise ValueError(f'Invalid {label}') from None
    else:
        if text.count(':') != 1:
            raise ValueError(f'Invalid {label}')
        host, port_text = text.rsplit(':', 1)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _SAFE_HOST_RE.fullmatch(host) or '..' in host:
                raise ValueError(f'Invalid {label}') from None
    if not port_text.isdigit():
        raise ValueError(f'Invalid {label}')
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f'Invalid {label}')
    return host, port


def format_listen_addr(listen, port):
    host = _require_listen(listen)
    _require_port(port, 'listen_port')
    if host in ('::', '0:0:0:0:0:0:0:0'):
        return f':{port}'
    try:
        parsed = ipaddress.ip_address(host)
        if parsed.version == 6:
            return f'[{host}]:{port}'
    except ValueError:
        pass
    return f'{host}:{port}'


def _validate_selector(strategy='fifo', max_fails=1, fail_timeout=10):
    if strategy not in SELECTOR_STRATEGIES:
        raise ValueError('Invalid selector strategy')
    if type(max_fails) is not int or not 1 <= max_fails <= 10:
        raise ValueError('Invalid max_fails')
    if type(fail_timeout) is not int or not 1 <= fail_timeout <= 300:
        raise ValueError('Invalid fail_timeout')


def _validate_iface(value):
    if not value:
        return ''
    if not isinstance(value, str) or not _SAFE_IFACE_RE.fullmatch(value):
        raise ValueError('Invalid network interface name')
    return value


def _validate_forward(item, chain_names, exit_group_ids):
    if not isinstance(item, dict):
        raise ValueError('Invalid forward item')
    allowed = {
        'id', 'name', 'listen', 'listen_port', 'protocol', 'targets',
        'chain', 'exit_group', 'strategy', 'max_fails', 'fail_timeout',
        'proxy_protocol', 'interface', 'enabled',
    }
    if not set(item).issubset(allowed):
        raise ValueError('Unsupported forward field')
    _require_id(item.get('id'), 'forward id')
    name = _require_optional_text(item.get('name', item['id']), 128, 'forward name')
    if not name:
        raise ValueError('Forward name required')
    _require_listen(item.get('listen', '::'))
    _require_port(item.get('listen_port'), 'listen_port')
    proto = item.get('protocol', 'tcp+udp')
    if proto not in FORWARD_PROTOCOLS:
        raise ValueError('Invalid forward protocol')
    strategy = item.get('strategy', 'fifo')
    max_fails = item.get('max_fails', 1)
    fail_timeout = item.get('fail_timeout', 10)
    _validate_selector(strategy, max_fails, fail_timeout)
    proxy_proto = item.get('proxy_protocol', 0)
    if type(proxy_proto) is not int or proxy_proto not in (0, 1, 2):
        raise ValueError('Invalid proxy_protocol version')
    _validate_iface(item.get('interface', ''))
    if 'enabled' in item and type(item['enabled']) is not bool:
        raise ValueError('Invalid enabled flag')
    chain_ref = _require_optional_text(item.get('chain', ''), 64, 'chain reference')
    if chain_ref and chain_ref not in chain_names:
        raise ValueError('Forward references unknown chain')
    exit_group_ref = _require_optional_text(item.get('exit_group', ''), 64, 'exit_group reference')
    if exit_group_ref:
        if exit_group_ref not in exit_group_ids:
            raise ValueError('Forward references unknown best_exit_group')
    targets = item.get('targets', [])
    if not exit_group_ref:
        if not isinstance(targets, list) or not 1 <= len(targets) <= 16:
            raise ValueError('Forward requires 1 to 16 targets')
    elif not isinstance(targets, list) or len(targets) > 16:
        raise ValueError('Invalid forward targets')
    for target in targets:
        if not isinstance(target, dict) or not set(target).issubset({'addr', 'name', 'chain'}):
            raise ValueError('Invalid forward target')
        validate_host_port(target.get('addr'), 'target address')
        _require_optional_text(target.get('name', ''), 64, 'target name')


def _validate_chain(chain):
    if not isinstance(chain, dict):
        raise ValueError('Invalid chain item')
    if not set(chain).issubset({'id', 'name', 'hops'}):
        raise ValueError('Unsupported chain field')
    _require_id(chain.get('id'), 'chain id')
    name = _require_optional_text(chain.get('name', chain['id']), 64, 'chain name')
    if not _SAFE_ID_RE.fullmatch(name):
        raise ValueError('Invalid chain name')
    hops = chain.get('hops')
    if not isinstance(hops, list) or not 1 <= len(hops) <= 8:
        raise ValueError('Chain must contain 1 to 8 hops')
    for hop in hops:
        if not isinstance(hop, dict) or not set(hop).issubset({'name', 'interface', 'strategy', 'max_fails', 'fail_timeout', 'nodes'}):
            raise ValueError('Invalid hop specification')
        _require_id(hop.get('name'), 'hop name')
        _validate_iface(hop.get('interface', ''))
        _validate_selector(hop.get('strategy', 'fifo'), hop.get('max_fails', 1), hop.get('fail_timeout', 10))
        nodes = hop.get('nodes')
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= 16:
            raise ValueError('Hop must contain 1 to 16 nodes')
        for node in nodes:
            if not isinstance(node, dict) or not set(node).issubset({
                'name', 'addr', 'connector', 'dialer', 'username', 'password',
                'server_name', 'insecure', 'nodelay', 'interface',
            }):
                raise ValueError('Invalid hop node specification')
            _require_id(node.get('name'), 'hop node name')
            validate_host_port(node.get('addr'), 'hop node addr')
            if node.get('connector', 'relay') not in CONNECTOR_TYPES:
                raise ValueError('Unsupported connector type')
            if node.get('dialer', 'tcp') not in DIALER_TYPES:
                raise ValueError('Unsupported dialer type')
            _require_optional_text(node.get('username', ''), 128, 'connector username')
            _require_optional_text(node.get('password', ''), 256, 'connector password')
            _require_optional_text(node.get('server_name', ''), 253, 'tls server_name')
            if 'insecure' in node and type(node['insecure']) is not bool:
                raise ValueError('Invalid insecure flag')
            if 'nodelay' in node and type(node['nodelay']) is not bool:
                raise ValueError('Invalid nodelay flag')
            _validate_iface(node.get('interface', ''))
    return name


def _validate_relay_service(svc, chain_names):
    if not isinstance(svc, dict):
        raise ValueError('Invalid relay service')
    allowed = {
        'id', 'name', 'listen', 'listen_port', 'handler', 'listener',
        'chain', 'username', 'password', 'nodelay', 'cert_file', 'key_file',
    }
    if not set(svc).issubset(allowed):
        raise ValueError('Unsupported relay service field')
    _require_id(svc.get('id'), 'relay service id')
    _require_id(svc.get('name', svc['id']), 'relay service name')
    _require_listen(svc.get('listen', '::'))
    _require_port(svc.get('listen_port'), 'relay listen_port')
    if svc.get('handler', 'relay') not in HANDLER_TYPES:
        raise ValueError('Unsupported relay handler')
    if svc.get('listener', 'tcp') not in LISTENER_TYPES:
        raise ValueError('Unsupported relay listener')
    chain_ref = _require_optional_text(svc.get('chain', ''), 64, 'relay chain')
    if chain_ref and chain_ref not in chain_names:
        raise ValueError('Relay service references unknown chain')
    _require_optional_text(svc.get('username', ''), 128, 'relay username')
    _require_optional_text(svc.get('password', ''), 256, 'relay password')
    if 'nodelay' in svc and type(svc['nodelay']) is not bool:
        raise ValueError('Invalid nodelay flag')
    for path_key in ('cert_file', 'key_file'):
        val = svc.get(path_key, '')
        if val:
            if not isinstance(val, str) or len(val) > 256 or not val.startswith('/') or any(ord(c) < 32 for c in val):
                raise ValueError(f'Invalid {path_key}')


def _validate_best_exit_group(group, chain_names):
    if not isinstance(group, dict):
        raise ValueError('Invalid best_exit group')
    allowed = {
        'id', 'name', 'probe_interval', 'confirmation_rounds',
        'cooldown_seconds', 'min_advantage_ms', 'min_advantage_ratio',
        'selected_exit_id', 'exits',
    }
    if not set(group).issubset(allowed):
        raise ValueError('Unsupported best_exit field')
    _require_id(group.get('id'), 'best_exit group id')
    _require_optional_text(group.get('name', group['id']), 128, 'best_exit name')
    interval = group.get('probe_interval', 15)
    rounds = group.get('confirmation_rounds', 3)
    cooldown = group.get('cooldown_seconds', 30)
    adv_ms = group.get('min_advantage_ms', 20.0)
    adv_ratio = group.get('min_advantage_ratio', 0.15)
    if type(interval) is not int or not 5 <= interval <= 300:
        raise ValueError('Invalid probe_interval')
    if type(rounds) is not int or not 1 <= rounds <= 10:
        raise ValueError('Invalid confirmation_rounds')
    if type(cooldown) is not int or not 0 <= cooldown <= 600:
        raise ValueError('Invalid cooldown_seconds')
    if isinstance(adv_ms, bool) or not isinstance(adv_ms, (int, float)) or adv_ms < 0 or not math.isfinite(adv_ms):
        raise ValueError('Invalid min_advantage_ms')
    if isinstance(adv_ratio, bool) or not isinstance(adv_ratio, (int, float)) or not 0 <= adv_ratio <= 1:
        raise ValueError('Invalid min_advantage_ratio')
    exits = group.get('exits')
    if not isinstance(exits, list) or not 1 <= len(exits) <= 16:
        raise ValueError('best_exit group requires 1 to 16 exits')
    exit_ids = set()
    for exit_item in exits:
        if not isinstance(exit_item, dict) or not set(exit_item).issubset({
            'id', 'name', 'addr', 'chain', 'probe_host', 'probe_port',
            'target_host', 'target_port', 'weight',
        }):
            raise ValueError('Invalid exit definition')
        eid = _require_id(exit_item.get('id'), 'exit id')
        if eid in exit_ids:
            raise ValueError('Duplicate exit id')
        exit_ids.add(eid)
        _require_optional_text(exit_item.get('name', eid), 64, 'exit name')
        validate_host_port(exit_item.get('addr'), 'exit addr')
        chain_ref = _require_optional_text(exit_item.get('chain', ''), 64, 'exit chain')
        if chain_ref and chain_ref not in chain_names:
            raise ValueError('Exit references unknown chain')
        if exit_item.get('probe_host'):
            _require_optional_text(exit_item['probe_host'], 253, 'probe_host')
        if 'probe_port' in exit_item and exit_item['probe_port'] not in (0, None):
            _require_port(exit_item['probe_port'], 'probe_port')
        if exit_item.get('target_host'):
            _require_optional_text(exit_item['target_host'], 253, 'target_host')
        if 'target_port' in exit_item and exit_item['target_port'] not in (0, None):
            _require_port(exit_item['target_port'], 'target_port')
    selected = _require_optional_text(group.get('selected_exit_id', ''), 64, 'selected_exit_id')
    if selected and selected not in exit_ids:
        raise ValueError('selected_exit_id does not match group exits')
    return group['id']


def validate_spec(action, spec):
    if action not in GOST_CONFIG_ACTIONS or not isinstance(spec, dict):
        raise ValueError('Invalid go-gost job specification')
    allowed_top = {'forwards', 'chains', 'relay_services', 'best_exit_groups', 'metrics_addr'}
    if not set(spec).issubset(allowed_top):
        raise ValueError('Unsupported go-gost specification key')
    forwards = spec.get('forwards', [])
    chains = spec.get('chains', [])
    relay_services = spec.get('relay_services', [])
    best_exit_groups = spec.get('best_exit_groups', [])
    metrics_addr = spec.get('metrics_addr', '')
    for seq in (forwards, chains, relay_services, best_exit_groups):
        if not isinstance(seq, list):
            raise ValueError('go-gost sections must be lists')
    if metrics_addr:
        host, _ = validate_host_port(metrics_addr, 'metrics_addr')
        if host not in ('127.0.0.1', '::1', '[::1]'):
            raise ValueError('metrics_addr must be loopback only')
    if action == 'gost.remove':
        if forwards or chains or relay_services or best_exit_groups:
            raise ValueError('gost.remove specification must be empty')
        return
    if len(forwards) > 128 or len(chains) > 64 or len(relay_services) > 32 or len(best_exit_groups) > 32:
        raise ValueError('go-gost specification exceeds bounds')
    chain_names = set()
    for ch in chains:
        name = _validate_chain(ch)
        if name in chain_names:
            raise ValueError('Duplicate chain name')
        chain_names.add(name)
    group_ids = set()
    for group in best_exit_groups:
        gid = _validate_best_exit_group(group, chain_names)
        if gid in group_ids:
            raise ValueError('Duplicate best_exit group id')
        group_ids.add(gid)
    seen_forward_ids = set()
    for fwd in forwards:
        _validate_forward(fwd, chain_names, group_ids)
        if fwd['id'] in seen_forward_ids:
            raise ValueError('Duplicate forward id')
        seen_forward_ids.add(fwd['id'])
    seen_relay_ids = set()
    for svc in relay_services:
        _validate_relay_service(svc, chain_names)
        if svc['id'] in seen_relay_ids:
            raise ValueError('Duplicate relay service id')
        seen_relay_ids.add(svc['id'])


def _render_auth(username, password):
    if username or password:
        return {'username': username or '', 'password': password or ''}
    return None


def _render_chain_node(node):
    connector_type = node.get('connector', 'relay')
    dialer_type = node.get('dialer', 'tcp')
    connector = {'type': connector_type}
    auth = _render_auth(node.get('username', ''), node.get('password', ''))
    if auth:
        connector['auth'] = auth
    if connector_type == 'relay' and node.get('nodelay', True):
        connector['metadata'] = {'nodelay': True}
    dialer = {'type': dialer_type}
    if dialer_type in ('tls', 'mtls', 'wss') and (node.get('server_name') or node.get('insecure')):
        tls_cfg = {}
        if node.get('server_name'):
            tls_cfg['serverName'] = node['server_name']
        if node.get('insecure'):
            tls_cfg['secure'] = False
        dialer['tls'] = tls_cfg
    out = {
        'name': node['name'],
        'addr': node['addr'],
        'connector': connector,
        'dialer': dialer,
    }
    if node.get('interface'):
        out['interface'] = node['interface']
    return out


def _render_forward_service(fwd, proto, best_exit_groups, selected_exits):
    svc_name = f"fwd_{fwd['id']}_{proto}"
    addr = format_listen_addr(fwd.get('listen', '::'), fwd['listen_port'])
    handler = {'type': proto}
    if fwd.get('chain'):
        handler['chain'] = fwd['chain']
    if proto == 'udp':
        handler['metadata'] = {'keepAlive': True, 'ttl': '60s'}
    listener = {'type': proto}
    if fwd.get('proxy_protocol', 0) in (1, 2):
        listener['metadata'] = {'proxyProtocol': fwd['proxy_protocol']}

    nodes = []
    exit_group_id = fwd.get('exit_group', '')
    if exit_group_id and exit_group_id in best_exit_groups:
        group = best_exit_groups[exit_group_id]
        chosen_id = (selected_exits or {}).get(exit_group_id) or group.get('selected_exit_id') or ''
        ordered = sorted(
            group['exits'],
            key=lambda item: (0 if item['id'] == chosen_id else 1, -int(item.get('weight', 100))),
        )
        for item in ordered:
            nodes.append({'name': item.get('name') or item['id'], 'addr': item['addr']})
        strategy = 'fifo'
    else:
        for idx, target in enumerate(fwd.get('targets', [])):
            node_obj = {'name': target.get('name') or f'target-{idx}', 'addr': target['addr']}
            if target.get('chain'):
                node_obj['chain'] = target['chain']
            nodes.append(node_obj)
        strategy = fwd.get('strategy', 'fifo')

    forwarder = {
        'nodes': nodes,
        'selector': {
            'strategy': strategy,
            'maxFails': fwd.get('max_fails', 1),
            'failTimeout': f"{fwd.get('fail_timeout', 10)}s",
        },
    }
    service = {
        'name': svc_name,
        'addr': addr,
        'handler': handler,
        'listener': listener,
        'forwarder': forwarder,
    }
    if fwd.get('interface'):
        handler.setdefault('metadata', {})
        service['metadata'] = {'interface': fwd['interface']}
    return service


def _render_relay_service(svc):
    addr = format_listen_addr(svc.get('listen', '::'), svc['listen_port'])
    handler_type = svc.get('handler', 'relay')
    handler = {'type': handler_type}
    if svc.get('chain'):
        handler['chain'] = svc['chain']
    auth = _render_auth(svc.get('username', ''), svc.get('password', ''))
    if auth:
        handler['auth'] = auth
    if handler_type == 'relay' and svc.get('nodelay', True):
        handler['metadata'] = {'nodelay': True}
    listener = {'type': svc.get('listener', 'tcp')}
    if svc.get('cert_file') and svc.get('key_file'):
        listener['tls'] = {'certFile': svc['cert_file'], 'keyFile': svc['key_file']}
    return {
        'name': f"relay_{svc['id']}",
        'addr': addr,
        'handler': handler,
        'listener': listener,
    }


def render_gost_config(spec, *, metrics_addr=None, selected_exits=None):
    """Render validated forward/chain/Best-Exit specification to go-gost v3 JSON."""
    has_items = bool(spec.get('forwards') or spec.get('chains') or spec.get('relay_services') or spec.get('best_exit_groups'))
    validate_spec('gost.apply' if has_items else 'gost.remove', spec)
    if not has_items:
        return {'services': []}

    group_map = {g['id']: g for g in spec.get('best_exit_groups', [])}
    services = []
    for fwd in spec.get('forwards', []):
        if fwd.get('enabled', True) is False:
            continue
        proto = fwd.get('protocol', 'tcp+udp')
        protos = ('tcp', 'udp') if proto == 'tcp+udp' else (proto,)
        for transport in protos:
            services.append(_render_forward_service(fwd, transport, group_map, selected_exits))

    for svc in spec.get('relay_services', []):
        services.append(_render_relay_service(svc))

    rendered = {'services': services}
    chains_out = []
    for ch in spec.get('chains', []):
        hops_out = []
        for hop in ch['hops']:
            hop_obj = {
                'name': hop['name'],
                'selector': {
                    'strategy': hop.get('strategy', 'fifo'),
                    'maxFails': hop.get('max_fails', 1),
                    'failTimeout': f"{hop.get('fail_timeout', 10)}s",
                },
                'nodes': [_render_chain_node(node) for node in hop['nodes']],
            }
            if hop.get('interface'):
                hop_obj['interface'] = hop['interface']
            hops_out.append(hop_obj)
        chains_out.append({'name': ch.get('name', ch['id']), 'hops': hops_out})
    if chains_out:
        rendered['chains'] = chains_out

    effective_metrics = metrics_addr or spec.get('metrics_addr', '')
    if effective_metrics:
        validate_host_port(effective_metrics, 'metrics_addr')
        rendered['metrics'] = {'addr': effective_metrics, 'path': '/metrics'}
    return rendered


def combine_loss_percent(entry_loss, exit_loss):
    """Combine entry->exit and exit->target loss percentages accurately."""
    a = min(100.0, max(0.0, float(entry_loss)))
    b = min(100.0, max(0.0, float(exit_loss)))
    return (1.0 - (1.0 - a / 100.0) * (1.0 - b / 100.0)) * 100.0


def compute_exit_score(total_latency_ms, total_loss_pct):
    """Composite link score matching flyx Best Exit penalty semantics."""
    loss = min(100.0, max(0.0, float(total_loss_pct)))
    if loss >= 100.0:
        return math.inf
    return max(0.0, float(total_latency_ms)) + loss * 100.0


def probe_tcp_endpoint(host, port, *, samples=3, timeout=1.5):
    """Measure TCP handshake RTT (ms) and loss (%) without proxying payload."""
    _require_port(port, 'probe_port')
    if not isinstance(host, str) or not host or len(host) > 253 or any(c.isspace() for c in host):
        raise ValueError('Invalid probe host')
    success_rtts = []
    failures = 0
    count = max(1, min(int(samples), 10))
    for _ in range(count):
        start = time.monotonic()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            elapsed_ms = (time.monotonic() - start) * 1000.0
            success_rtts.append(elapsed_ms)
        except OSError:
            failures += 1
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    loss_pct = (failures / float(count)) * 100.0
    avg_rtt = (sum(success_rtts) / len(success_rtts)) if success_rtts else 0.0
    return {'latency_ms': round(avg_rtt, 3), 'loss_pct': round(loss_pct, 2), 'ok': bool(success_rtts)}


class BestExitManager:
    """Anti-flap multi-exit health evaluator and automatic primary selector."""

    def __init__(self):
        self._state = {}

    def _entry_state(self, group_id, initial_exit_id=''):
        if group_id not in self._state:
            self._state[group_id] = {
                'current_exit_id': initial_exit_id,
                'candidate_exit_id': '',
                'candidate_rounds': 0,
                'last_switch_at': 0.0,
            }
        elif not self._state[group_id]['current_exit_id'] and initial_exit_id:
            self._state[group_id]['current_exit_id'] = initial_exit_id
        return self._state[group_id]

    def evaluate(self, group, probes, *, now=None):
        """Evaluate probe results `{exit_id: {entry_latency_ms, entry_loss_pct, exit_latency_ms, exit_loss_pct}}`."""
        ts = float(time.time() if now is None else now)
        exits = list(group.get('exits') or [])
        if not exits:
            raise ValueError('best_exit group has no exits')
        group_id = _require_id(group['id'], 'group id')
        exit_ids = [item['id'] for item in exits]
        state = self._entry_state(group_id, group.get('selected_exit_id') or exit_ids[0])
        if state['current_exit_id'] not in exit_ids:
            state['current_exit_id'] = exit_ids[0]

        scored = []
        by_id = {}
        for item in exits:
            eid = item['id']
            sample = (probes or {}).get(eid) or {}
            e_lat = max(0.0, float(sample.get('entry_latency_ms', 0.0)))
            x_lat = max(0.0, float(sample.get('exit_latency_ms', 0.0)))
            e_loss = float(sample.get('entry_loss_pct', 100.0 if eid not in (probes or {}) else 0.0))
            x_loss = float(sample.get('exit_loss_pct', 0.0))
            total_loss = combine_loss_percent(e_loss, x_loss)
            total_lat = e_lat + x_lat
            score = compute_exit_score(total_lat, total_loss)
            record = {
                'exit_id': eid,
                'name': item.get('name') or eid,
                'addr': item['addr'],
                'latency_ms': round(total_lat, 3),
                'loss_pct': round(total_loss, 2),
                'score': None if math.isinf(score) else round(score, 3),
                'healthy': not math.isinf(score),
            }
            by_id[eid] = (score, record)
            scored.append((score, eid, record))

        scored.sort(key=lambda pair: (pair[0], exit_ids.index(pair[1])))
        best_score, best_id, _ = scored[0]
        current_id = state['current_exit_id']
        current_score = by_id[current_id][0]
        previous_id = current_id

        rounds_needed = max(1, int(group.get('confirmation_rounds', 3)))
        cooldown = max(0.0, float(group.get('cooldown_seconds', 30)))
        min_adv_ms = max(0.0, float(group.get('min_advantage_ms', 20.0)))
        min_adv_ratio = min(1.0, max(0.0, float(group.get('min_advantage_ratio', 0.15))))

        switched = False
        reason = 'stay_current'

        if math.isinf(best_score):
            state['candidate_exit_id'] = ''
            state['candidate_rounds'] = 0
            reason = 'all_unhealthy'
        elif best_id == current_id:
            state['candidate_exit_id'] = ''
            state['candidate_rounds'] = 0
            reason = 'current_is_best'
        elif math.isinf(current_score):
            state['current_exit_id'] = best_id
            state['candidate_exit_id'] = ''
            state['candidate_rounds'] = 0
            state['last_switch_at'] = ts
            switched = True
            reason = 'current_unreachable_failover'
        else:
            min_improvement = max(min_adv_ms, current_score * min_adv_ratio)
            improvement = current_score - best_score
            if improvement < min_improvement:
                state['candidate_exit_id'] = ''
                state['candidate_rounds'] = 0
                reason = 'below_advantage_threshold'
            else:
                if state['candidate_exit_id'] == best_id:
                    state['candidate_rounds'] += 1
                else:
                    state['candidate_exit_id'] = best_id
                    state['candidate_rounds'] = 1
                if state['candidate_rounds'] < rounds_needed:
                    reason = 'confirming'
                elif state['last_switch_at'] > 0.0 and (ts - state['last_switch_at']) < cooldown:
                    reason = 'cooldown'
                else:
                    state['current_exit_id'] = best_id
                    state['candidate_exit_id'] = ''
                    state['candidate_rounds'] = 0
                    state['last_switch_at'] = ts
                    switched = True
                    reason = 'switched_best_exit'

        return {
            'group_id': group_id,
            'previous_exit_id': previous_id,
            'selected_exit_id': state['current_exit_id'],
            'switched': switched,
            'reason': reason,
            'candidate_exit_id': state['candidate_exit_id'],
            'candidate_rounds': state['candidate_rounds'],
            'metrics': {row['exit_id']: row for _, _, row in scored},
        }
