"""Unified landing protocol specs (SS2022, Reality, Trojan, AnyTLS, VLESS-WS, Hysteria2)."""
import base64
import binascii
import os
from pathlib import Path, PurePosixPath
import re
import urllib.parse
import uuid

from .deployment_spec import host, node_name, validate_endpoint

LANDING_ACTIONS = ('landing.apply', 'landing.remove')
METHOD = '2022-blake3-aes-256-gcm'
SS2022_METHODS = {
    '2022-blake3-aes-256-gcm': 32,
    '2022-blake3-aes-128-gcm': 16,
}
OUTBOUND_SS_METHODS = (
    '2022-blake3-aes-256-gcm',
    '2022-blake3-aes-128-gcm',
    'aes-256-gcm',
    'aes-128-gcm',
    'chacha20-ietf-poly1305',
)
LANDING_PROTOCOLS = ('ss2022', 'reality', 'trojan', 'anytls', 'vless-ws', 'hysteria2')
ACTIVE_UI_PROTOCOLS = ('reality', 'hysteria2', 'ss2022', 'anytls', 'trojan')
TLS_MODES = ('none', 'reality', 'acme_http', 'acme_dns')
OUTBOUND_STRATEGIES = ('prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only')
OUTBOUND_MODES = ('direct', 'socks5', 'ss', 'chain')
OUTBOUND_HOP_KINDS = ('managed_ss', 'ss', 'socks5')
MAX_OUTBOUND_HOPS = 4
FINGERPRINTS = ('chrome', 'firefox', 'safari', 'edge', 'ios', 'android', 'random', 'randomized')
DNS_PROVIDERS = ('cloudflare', 'alidns', 'dnspod')
CAMOUFLAGE_MODES = ('template', 'proxy', 'static_dir')
CAMOUFLAGE_TEMPLATES = ('corporate', 'blog', 'status', 'nginx')
_FORBIDDEN_STATIC_PREFIXES = (
    '/etc', '/proc', '/sys', '/dev', '/run', '/root', '/boot',
    '/bin', '/sbin', '/usr', '/lib', '/lib64',
    '/var/lib/proxyforge-runtime', '/opt/proxyforge-agent',
)
CAMOUFLAGE_UNSAFE = re.compile(r'[\x00-\x1f\x7f{};"\'\\\r\n]')
EMAIL_RE = re.compile(r'[^\s@]+@[^\s@]+\.[^\s@]+\Z')
MPORT_RE = re.compile(r'\d{1,5}(?:[-:]\d{1,5})?(?:,\d{1,5}(?:[-:]\d{1,5})?)*\Z')
DEFAULT_ANYTLS_PADDING = (
    'stop=8',
    '0=30-30',
    '1=100-400',
    '2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000',
    '3=9-9,500-1000',
    '4=500-1000',
    '5=500-1000',
    '6=500-1000',
    '7=500-1000',
)

PROTOCOL_SPEC = {
    'ss2022': {
        'tls_modes': ('none',),
        'default_tls': 'none',
        'requires_domain': False,
        'secret_fields': frozenset(('password', 'outbound_password')),
        'project_client': False,
    },
    'reality': {
        'tls_modes': ('reality', 'acme_http', 'acme_dns'),
        'default_tls': 'reality',
        'requires_domain': True,
        'secret_fields': frozenset(('uuid', 'reality_private_key', 'dns_api_token', 'outbound_password')),
        'project_client': True,
    },
    'trojan': {
        'tls_modes': ('acme_http', 'acme_dns'),
        'default_tls': 'acme_http',
        'requires_domain': True,
        'secret_fields': frozenset(('password', 'dns_api_token', 'outbound_password')),
        'project_client': True,
    },
    'anytls': {
        'tls_modes': ('acme_http', 'acme_dns'),
        'default_tls': 'acme_http',
        'requires_domain': True,
        'secret_fields': frozenset(('password', 'dns_api_token', 'outbound_password')),
        'project_client': True,
    },
    'vless-ws': {
        'tls_modes': ('none', 'acme_http', 'acme_dns'),
        'default_tls': 'acme_http',
        'requires_domain': False,
        'secret_fields': frozenset(('uuid', 'dns_api_token', 'outbound_password')),
        'project_client': True,
    },
    'hysteria2': {
        'tls_modes': ('acme_http', 'acme_dns'),
        'default_tls': 'acme_http',
        'requires_domain': True,
        'secret_fields': frozenset(('password', 'obfs_password', 'dns_api_token', 'outbound_password')),
        'project_client': True,
    },
}

# Protocols whose single sing-box inbound can serve several logical nodes on one port.
# Each node keeps its own credential (uuid/password) and is routed by `auth_user`.
SHARED_PORT_PROTOCOLS = frozenset(('reality', 'trojan', 'anytls', 'hysteria2'))
_SHARED_LISTENER_COMMON = (
    'tls_mode', 'domain', 'camouflage_mode', 'camouflage_template', 'camouflage_url', 'camouflage_dir',
    'acme_email', 'dns_provider', 'dns_zone_id', 'dns_propagation_seconds',
)
_SHARED_LISTENER_PUBLIC = {
    'reality': ('reality_public_key',),
    'trojan': (),
    'anytls': ('padding_scheme',),
    'hysteria2': ('obfs', 'up_mbps', 'down_mbps', 'mport', 'hop_interval'),
}
_SHARED_LISTENER_SECRET = {
    'reality': ('reality_private_key', 'dns_api_token'),
    'trojan': ('dns_api_token',),
    'anytls': ('dns_api_token',),
    'hysteria2': ('obfs_password', 'dns_api_token'),
}
_SHARED_CREDENTIAL_FIELD = {'reality': 'uuid', 'trojan': 'password', 'anytls': 'password', 'hysteria2': 'password'}

_COMMON_OPTIONAL = {
    'protocol', 'domain', 'tls_mode',
    'camouflage_url', 'camouflage_mode', 'camouflage_template', 'camouflage_dir',
    'acme_email', 'dns_provider', 'dns_zone_id', 'dns_propagation_seconds',
    'region', 'outbound_strategy', 'outbound_mode',
    'outbound_server', 'outbound_port', 'outbound_username', 'outbound_method',
    'outbound_hops',
    'publish_to_subscription', 'node_id',
}
CLIENT_METADATA_ONLY_FIELDS = frozenset((
    'name', 'server', 'region', 'publish_to_subscription',
    'fingerprint', 'mport', 'hop_interval',
))
_PROTOCOL_ALLOWED_SETTINGS = {
    'ss2022': {'name', 'server', 'listen_port', 'method', *_COMMON_OPTIONAL},
    'reality': {'name', 'server', 'listen_port', 'reality_public_key', 'reality_short_ids', 'fingerprint', *_COMMON_OPTIONAL},
    'trojan': {'name', 'server', 'listen_port', *_COMMON_OPTIONAL},
    'anytls': {'name', 'server', 'listen_port', 'fingerprint', 'padding_scheme', *_COMMON_OPTIONAL},
    'vless-ws': {'name', 'server', 'listen_port', 'ws_path', *_COMMON_OPTIONAL},
    'hysteria2': {'name', 'server', 'listen_port', 'up_mbps', 'down_mbps', 'obfs', 'mport', 'hop_interval', *_COMMON_OPTIONAL},
}
_SECRET_INPUT_KEYS = frozenset((
    'password', 'private_key', 'reality_private_key', 'dns_api_token',
    'obfs_password', 'outbound_password', 'hop_passwords', 'resolved_outbound_hops',
))


def _validate_camouflage_url(value):
    if not value:
        return ''
    if not isinstance(value, str) or len(value) > 253 or CAMOUFLAGE_UNSAFE.search(value) or any(ch.isspace() for ch in value):
        raise ValueError('Invalid camouflage URL')
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
        raise ValueError('Invalid camouflage URL')
    host(parsed.hostname, domain_only=True)
    if parsed.hostname.lower().endswith(('.local', '.localhost', '.invalid', '.test')):
        raise ValueError('Local domain cannot be used as camouflage target')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Invalid camouflage port')
    return value


def _validate_ws_path(value):
    if not isinstance(value, str) or not value.startswith('/') or len(value) > 128:
        raise ValueError('Invalid WebSocket path')
    if CAMOUFLAGE_UNSAFE.search(value) or any(ch.isspace() for ch in value) or '?' in value or '#' in value:
        raise ValueError('Invalid WebSocket path')


def _validate_reality_key(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
        raise ValueError('Invalid Reality key')
    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(value + '=')).decode().rstrip('=') != value:
        raise ValueError('Invalid Reality key encoding')


def _validate_short_ids(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 8:
        raise ValueError('Invalid reality_short_ids list')
    for item in values:
        if not isinstance(item, str) or not re.fullmatch(r'(?:[0-9a-f]{2}){1,8}', item):
            raise ValueError('Invalid reality short_id')


def _validate_ss2022_password(password, key_bytes):
    try:
        if not isinstance(password, str):
            raise ValueError('Invalid SS2022 key')
        decoded = base64.b64decode(password, validate=True)
        if len(decoded) != key_bytes or base64.b64encode(decoded).decode() != password:
            raise ValueError('Invalid SS2022 key')
    except (binascii.Error, ValueError):
        raise ValueError('Invalid SS2022 key') from None


def _validate_mport(value):
    if value in (None, ''):
        return ''
    if not isinstance(value, str) or len(value) > 64 or not MPORT_RE.fullmatch(value):
        raise ValueError('Invalid Hysteria2 mport range')
    normalized_parts = []
    for chunk in value.split(','):
        if '-' in chunk or ':' in chunk:
            sep = '-' if '-' in chunk else ':'
            start_s, end_s = chunk.split(sep, 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start < end <= 65535):
                raise ValueError('Invalid Hysteria2 mport range')
            normalized_parts.append(f'{start}-{end}')
        else:
            port = int(chunk)
            if not 1 <= port <= 65535:
                raise ValueError('Invalid Hysteria2 mport range')
            normalized_parts.append(str(port))
    return ','.join(normalized_parts)


def _validate_hop_interval(value):
    if value is None:
        return
    if type(value) is not int or not 5 <= value <= 3600:
        raise ValueError('Invalid Hysteria2 hop_interval')


def _validate_padding_scheme(value):
    if value is None:
        return
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise ValueError('Invalid AnyTLS padding_scheme')
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 128 or CAMOUFLAGE_UNSAFE.search(item):
            raise ValueError('Invalid AnyTLS padding_scheme line')


def _validate_outbound_hops_settings(hops):
    if not isinstance(hops, list) or not 1 <= len(hops) <= MAX_OUTBOUND_HOPS:
        raise ValueError('outbound_hops must contain 1 to 4 hops')
    for hop in hops:
        if not isinstance(hop, dict):
            raise ValueError('Invalid outbound hop')
        kind = hop.get('kind')
        if kind not in OUTBOUND_HOP_KINDS:
            raise ValueError('Unsupported outbound hop kind')
        if 'password' in hop:
            raise ValueError('Outbound hop passwords must be supplied via secrets, not settings')
        label = hop.get('label', '')
        if label is not None and (not isinstance(label, str) or len(label) > 64 or CAMOUFLAGE_UNSAFE.search(label)):
            raise ValueError('Invalid outbound hop label')
        if kind == 'managed_ss':
            if set(hop) - {'kind', 'agent_id', 'node_id', 'label'}:
                raise ValueError('Unsupported managed_ss hop field')
            aid = hop.get('agent_id', '')
            nid = hop.get('node_id', '')
            if not isinstance(aid, str) or not re.fullmatch(r'[0-9a-f]{32}', aid):
                raise ValueError('Invalid managed_ss agent_id')
            if not isinstance(nid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', nid):
                raise ValueError('Invalid managed_ss node_id')
        elif kind == 'ss':
            if set(hop) - {'kind', 'server', 'port', 'method', 'label'}:
                raise ValueError('Unsupported ss hop field')
            host(hop.get('server', ''))
            p = hop.get('port')
            if type(p) is not int or not 1 <= p <= 65535:
                raise ValueError('Invalid ss hop port')
            if hop.get('method', METHOD) not in OUTBOUND_SS_METHODS:
                raise ValueError('Unsupported ss hop method')
        elif kind == 'socks5':
            if set(hop) - {'kind', 'server', 'port', 'username', 'label'}:
                raise ValueError('Unsupported socks5 hop field')
            host(hop.get('server', ''))
            p = hop.get('port')
            if type(p) is not int or not 1 <= p <= 65535:
                raise ValueError('Invalid socks5 hop port')
            u = hop.get('username', '')
            if u and (not isinstance(u, str) or len(u) > 128 or any(ord(c) < 32 for c in u)):
                raise ValueError('Invalid socks5 hop username')


def _validate_resolved_outbound_hops(hops):
    if not isinstance(hops, list) or not 1 <= len(hops) <= MAX_OUTBOUND_HOPS:
        raise ValueError('resolved_outbound_hops must contain 1 to 4 hops')
    for hop in hops:
        if not isinstance(hop, dict):
            raise ValueError('Invalid resolved outbound hop')
        htype = hop.get('type')
        if htype not in ('ss', 'socks5'):
            raise ValueError('Unsupported resolved outbound hop type')
        host(hop.get('server', ''))
        p = hop.get('port')
        if type(p) is not int or not 1 <= p <= 65535:
            raise ValueError('Invalid resolved outbound hop port')
        if htype == 'ss':
            if set(hop) - {'type', 'server', 'port', 'method', 'password'}:
                raise ValueError('Unsupported resolved ss hop field')
            if hop.get('method', METHOD) not in OUTBOUND_SS_METHODS:
                raise ValueError('Unsupported resolved ss hop method')
            pw = hop.get('password', '')
            if not isinstance(pw, str) or not 1 <= len(pw) <= 256 or any(ord(c) < 32 for c in pw):
                raise ValueError('Missing or invalid resolved ss hop password')
        else:
            if set(hop) - {'type', 'server', 'port', 'username', 'password'}:
                raise ValueError('Unsupported resolved socks5 hop field')
            u = hop.get('username', '')
            if u and (not isinstance(u, str) or len(u) > 128 or any(ord(c) < 32 for c in u)):
                raise ValueError('Invalid resolved socks5 hop username')
            pw = hop.get('password', '')
            if pw and (not isinstance(pw, str) or len(pw) > 256 or any(ord(c) < 32 for c in pw)):
                raise ValueError('Invalid resolved socks5 hop password')


def _validate_outbound_settings(mapping):
    if 'region' in mapping and mapping['region'] is not None:
        reg = mapping['region']
        if not isinstance(reg, str) or len(reg) > 32 or CAMOUFLAGE_UNSAFE.search(reg):
            raise ValueError('Invalid region')
    if 'node_id' in mapping and mapping['node_id'] is not None:
        nid = mapping['node_id']
        if not isinstance(nid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', nid):
            raise ValueError('Invalid node_id')
    if 'publish_to_subscription' in mapping and type(mapping['publish_to_subscription']) is not bool:
        raise ValueError('Invalid publish_to_subscription')
    if 'outbound_strategy' in mapping and mapping['outbound_strategy'] is not None:
        if mapping['outbound_strategy'] not in OUTBOUND_STRATEGIES:
            raise ValueError('Unsupported outbound_strategy')
    mode = mapping.get('outbound_mode', 'direct')
    if mode not in OUTBOUND_MODES:
        raise ValueError('Unsupported outbound_mode')
    if mode == 'chain':
        _validate_outbound_hops_settings(mapping.get('outbound_hops'))
        for forbidden in ('outbound_server', 'outbound_port', 'outbound_username', 'outbound_method'):
            if forbidden in mapping and mapping[forbidden] not in (None, ''):
                raise ValueError('Single outbound proxy fields cannot be combined with outbound_mode=chain')
    elif mode in ('socks5', 'ss'):
        if mapping.get('outbound_hops'):
            raise ValueError('outbound_hops requires outbound_mode=chain')
        host(mapping.get('outbound_server', ''))
        out_port = mapping.get('outbound_port')
        if type(out_port) is not int or not 1 <= out_port <= 65535:
            raise ValueError('Invalid outbound_port')
        if mode == 'socks5' and 'outbound_username' in mapping and mapping['outbound_username']:
            u = mapping['outbound_username']
            if not isinstance(u, str) or len(u) > 128 or any(ord(c) < 32 for c in u):
                raise ValueError('Invalid outbound_username')
        if mode == 'ss':
            m = mapping.get('outbound_method', METHOD)
            if m not in OUTBOUND_SS_METHODS:
                raise ValueError('Unsupported outbound_method')
    else:
        if mapping.get('outbound_hops'):
            raise ValueError('outbound_hops requires outbound_mode=chain')
        for forbidden in ('outbound_server', 'outbound_port', 'outbound_username', 'outbound_method'):
            if forbidden in mapping and mapping[forbidden] not in (None, ''):
                raise ValueError('Outbound proxy fields require outbound_mode=socks5 or ss')


def _validate_acme_fields(mapping, tls_mode):
    if 'acme_email' in mapping:
        email = mapping['acme_email']
        if not isinstance(email, str) or len(email) > 254 or (email.strip() and not EMAIL_RE.fullmatch(email.strip())):
            raise ValueError('Invalid acme_email')
    if tls_mode == 'acme_dns':
        provider = mapping.get('dns_provider', 'cloudflare')
        if provider not in DNS_PROVIDERS:
            raise ValueError('Unsupported dns_provider')
        zone_id = mapping.get('dns_zone_id', '')
        if provider == 'cloudflare' and (not isinstance(zone_id, str) or not re.fullmatch(r'[0-9a-fA-F]{32}', zone_id)):
            raise ValueError('Cloudflare DNS-01 requires a 32-hex dns_zone_id')
        seconds = mapping.get('dns_propagation_seconds', 60)
        if type(seconds) is not int or not 10 <= seconds <= 600:
            raise ValueError('Invalid dns_propagation_seconds')
    else:
        for forbidden in ('dns_provider', 'dns_zone_id', 'dns_propagation_seconds'):
            if forbidden in mapping and mapping[forbidden]:
                raise ValueError('DNS-01 fields require tls_mode=acme_dns')


def _resolved_protocol(mapping, default='ss2022'):
    protocol = mapping.get('protocol', default)
    if protocol not in PROTOCOL_SPEC:
        raise ValueError('Unsupported landing protocol')
    return protocol


def normalize_protocol(protocol):
    """Legacy `vless-reality` primaries render exactly like `reality` landings."""
    return 'reality' if protocol == 'vless-reality' else protocol


def shared_listener_key(protocol, listen_port):
    """Return the (protocol, port) listener key for shareable protocols, otherwise None."""
    protocol = normalize_protocol(protocol)
    if protocol not in SHARED_PORT_PROTOCOLS:
        return None
    return protocol, int(listen_port)


def shared_listener_fields(protocol):
    """Return (public, secret) field names owned by a shared listener rather than by one node."""
    protocol = normalize_protocol(protocol)
    if protocol not in SHARED_PORT_PROTOCOLS:
        return (), ()
    return _SHARED_LISTENER_COMMON + _SHARED_LISTENER_PUBLIC[protocol], _SHARED_LISTENER_SECRET[protocol]


def shared_credential_field(protocol):
    return _SHARED_CREDENTIAL_FIELD.get(normalize_protocol(protocol))


def shared_user_key(member_id):
    """Stable ASCII sing-box user name used by `auth_user` routing (never the display name)."""
    return 'u-primary' if member_id == 'primary' else f'u-{member_id}'


def _node_entries(spec):
    entries = [('primary', spec)]
    for idx, extra in enumerate(spec.get('extra_nodes') or [], 1):
        entries.append((str(extra.get('node_id') or idx), extra))
    return entries


def shared_listener_plan(spec):
    """Group managed nodes that share one (protocol, port) listener.

    Only groups with two or more nodes are returned. The host owns the inbound tag, certificate
    and Caddy site: the primary when it participates, otherwise the smallest node id, so editing
    a node (which reorders extras by updated_at) never moves the certificate to another site.
    """
    if not isinstance(spec, dict) or spec.get('adopted_only') is True:
        return {}
    groups = {}
    for member_id, node in _node_entries(spec):
        key = shared_listener_key(_resolved_protocol(node), node['listen_port'])
        if key is not None:
            groups.setdefault(key, []).append(member_id)
    plan = {}
    for key, members in groups.items():
        if len(members) >= 2:
            plan[key] = {'host': 'primary' if 'primary' in members else min(members), 'members': members}
    return plan


def shared_listener_guests(spec):
    """Extra node ids served by another node's listener; they need no TLS or Caddy of their own."""
    guests = set()
    for group in shared_listener_plan(spec).values():
        guests.update(member for member in group['members'] if member != group['host'])
    return guests


def _validate_shared_listeners(spec):
    entries = dict(_node_entries(spec))
    for (protocol, _port), group in shared_listener_plan(spec).items():
        nodes = [entries[member] for member in group['members']]
        default_tls = PROTOCOL_SPEC[protocol]['default_tls']
        if (len({node.get('tls_mode', default_tls) for node in nodes}) != 1 or
                len({(node.get('domain') or '').lower() for node in nodes}) != 1):
            raise ValueError('Shared listener nodes must use identical tls_mode and domain')
        if protocol == 'reality' and len({
            (node.get('reality_private_key'), node.get('reality_public_key')) for node in nodes
        }) != 1:
            raise ValueError('Shared Reality listener nodes must use one key pair')
        if protocol == 'hysteria2':
            obfs = {
                (node.get('obfs') or 'none', node.get('obfs_password') if node.get('obfs') == 'salamander' else None)
                for node in nodes
            }
            if len(obfs) != 1:
                raise ValueError('Shared Hysteria2 listener nodes must use identical obfuscation')
        credentials = [node.get(_SHARED_CREDENTIAL_FIELD[protocol]) for node in nodes]
        if len(set(credentials)) != len(credentials):
            raise ValueError('Shared listener credentials must be unique')


def _merge_shared_users(inbound, protocol, members):
    users = []
    for member_id, node in members:
        if protocol == 'reality':
            users.append({'name': shared_user_key(member_id), 'uuid': node['uuid'], 'flow': 'xtls-rprx-vision'})
        else:
            users.append({'name': shared_user_key(member_id), 'password': node['password']})
    inbound['users'] = users
    if protocol == 'reality':
        short_ids = []
        for _member_id, node in members:
            for short_id in node.get('reality_short_ids') or []:
                if short_id not in short_ids:
                    short_ids.append(short_id)
        inbound['tls']['reality']['short_id'] = short_ids


def validate_settings(settings, protocol=None):
    """Validate public, non-secret landing settings passed by Controller admins."""
    if not isinstance(settings, dict):
        raise ValueError('Invalid landing settings')
    if any(k in settings for k in _SECRET_INPUT_KEYS):
        raise ValueError('Secret credentials are not allowed in public settings')

    resolved = protocol or settings.get('protocol', 'ss2022')
    if resolved not in PROTOCOL_SPEC:
        raise ValueError('Unsupported landing protocol')
    if 'protocol' in settings and settings['protocol'] != resolved:
        raise ValueError('Mismatched landing protocol')

    # Legacy 0.6.0 ss2022 exact 4-key contract check.
    if (resolved == 'ss2022' and 'tls_mode' not in settings and 'domain' not in settings and
            'protocol' not in settings and 'publish_to_subscription' not in settings and
            'outbound_strategy' not in settings and 'outbound_mode' not in settings and 'region' not in settings):
        if set(settings) != {'name', 'server', 'listen_port', 'method'}:
            raise ValueError('Invalid landing settings')
        validate_endpoint(settings)
        if settings['method'] != METHOD:
            raise ValueError('Unsupported landing method')
        return

    allowed_keys = _PROTOCOL_ALLOWED_SETTINGS[resolved]
    if not {'name', 'server', 'listen_port'}.issubset(settings) or set(settings) - allowed_keys:
        raise ValueError('Invalid landing settings')
    validate_endpoint({k: settings[k] for k in ('name', 'server', 'listen_port')})

    rules = PROTOCOL_SPEC[resolved]
    tls_mode = settings.get('tls_mode', rules['default_tls'])
    if tls_mode not in TLS_MODES or tls_mode not in rules['tls_modes']:
        raise ValueError('Unsupported tls_mode for landing protocol')

    domain = settings.get('domain', '')
    if rules['requires_domain'] or tls_mode in ('acme_http', 'acme_dns'):
        host(domain, domain_only=True)
    elif domain:
        host(domain, domain_only=True)

    camouflage = settings.get('camouflage_url', '')
    _validate_camouflage_url(camouflage)
    cam_dir = settings.get('camouflage_dir', '')
    if cam_dir:
        if not isinstance(cam_dir, str) or len(cam_dir) > 200 or CAMOUFLAGE_UNSAFE.search(cam_dir) or any(ch.isspace() for ch in cam_dir):
            raise ValueError('Invalid camouflage_dir')
        if not cam_dir.startswith('/'):
            raise ValueError('camouflage_dir must be an absolute POSIX path')
        parsed_dir = PurePosixPath(cam_dir)
        if '..' in parsed_dir.parts or len(parsed_dir.parts) < 2:
            raise ValueError('Invalid camouflage_dir path')
        norm_dir = parsed_dir.as_posix().rstrip('/')
        if not norm_dir or norm_dir == '/' or any(
            norm_dir == pfx or norm_dir.startswith(pfx + '/') for pfx in _FORBIDDEN_STATIC_PREFIXES
        ):
            raise ValueError('Restricted camouflage_dir path')
    cam_mode = settings.get('camouflage_mode', '')
    if cam_mode:
        if cam_mode not in CAMOUFLAGE_MODES:
            raise ValueError('Unsupported camouflage_mode')
        if cam_mode == 'proxy' and not camouflage:
            raise ValueError('Proxy camouflage mode requires camouflage_url')
        if cam_mode == 'static_dir' and not cam_dir:
            raise ValueError('Static directory camouflage mode requires camouflage_dir')
    cam_tpl = settings.get('camouflage_template', '')
    if cam_tpl and cam_tpl not in CAMOUFLAGE_TEMPLATES:
        raise ValueError('Unsupported camouflage_template')
    _validate_acme_fields(settings, tls_mode)
    _validate_outbound_settings(settings)

    if resolved == 'ss2022':
        method = settings.get('method', METHOD)
        if method not in SS2022_METHODS:
            raise ValueError('Unsupported landing method')
    elif resolved == 'reality':
        if 'reality_public_key' in settings:
            _validate_reality_key(settings['reality_public_key'])
        if 'reality_short_ids' in settings:
            _validate_short_ids(settings['reality_short_ids'])
        if 'fingerprint' in settings and settings['fingerprint'] not in FINGERPRINTS:
            raise ValueError('Unsupported client fingerprint')
    elif resolved == 'anytls':
        if 'fingerprint' in settings and settings['fingerprint'] not in FINGERPRINTS:
            raise ValueError('Unsupported client fingerprint')
        if 'padding_scheme' in settings:
            _validate_padding_scheme(settings['padding_scheme'])
    elif resolved == 'vless-ws':
        if 'ws_path' in settings:
            _validate_ws_path(settings['ws_path'])
    elif resolved == 'hysteria2':
        for field in ('up_mbps', 'down_mbps'):
            if field in settings and (type(settings[field]) is not int or not 1 <= settings[field] <= 100000):
                raise ValueError('Invalid Hysteria2 bandwidth limit')
        if 'obfs' in settings and settings['obfs'] not in ('none', 'salamander'):
            raise ValueError('Unsupported Hysteria2 obfuscation')
        if 'mport' in settings:
            _validate_mport(settings['mport'])
        if 'hop_interval' in settings:
            _validate_hop_interval(settings['hop_interval'])


def _validate_single_node_spec(spec):
    if not isinstance(spec, dict):
        raise ValueError('Invalid landing specification')
    resolved = _resolved_protocol(spec, default='ss2022')
    # Legacy exact 5-key SS2022 shape for hash & test backward compatibility.
    if resolved == 'ss2022' and set(spec) == {'name', 'server', 'listen_port', 'method', 'password'}:
        validate_settings({k: spec[k] for k in ('name', 'server', 'listen_port', 'method')}, protocol='ss2022')
        _validate_ss2022_password(spec['password'], SS2022_METHODS[spec['method']])
        return

    rules = PROTOCOL_SPEC[resolved]
    allowed = (
        _PROTOCOL_ALLOWED_SETTINGS[resolved]
        | rules['secret_fields']
        | {
            'reality_public_key', 'uuid', 'extra_nodes', 'adopted_nodes',
            'returned_adoptions', 'disabled_adoptions', 'hop_passwords', 'resolved_outbound_hops',
        }
    )
    if set(spec) - allowed:
        raise ValueError('Invalid landing specification')

    public = {k: v for k, v in spec.items() if k in _PROTOCOL_ALLOWED_SETTINGS[resolved]}
    validate_settings(public, protocol=resolved)
    tls_mode = spec.get('tls_mode', rules['default_tls'])

    if tls_mode == 'acme_dns':
        token = spec.get('dns_api_token', '')
        if not isinstance(token, str) or not 12 <= len(token) <= 256 or any(ord(c) < 32 for c in token):
            raise ValueError('Missing or invalid ACME DNS API token')

    out_mode = spec.get('outbound_mode', 'direct')
    if out_mode == 'chain':
        _validate_resolved_outbound_hops(spec.get('resolved_outbound_hops'))
    elif out_mode == 'ss':
        out_pw = spec.get('outbound_password', '')
        if not isinstance(out_pw, str) or not 1 <= len(out_pw) <= 256 or any(ord(c) < 32 for c in out_pw):
            raise ValueError('Missing or invalid outbound Shadowsocks password')
    elif out_mode == 'socks5' and 'outbound_password' in spec and spec['outbound_password']:
        out_pw = spec['outbound_password']
        if not isinstance(out_pw, str) or len(out_pw) > 256 or any(ord(c) < 32 for c in out_pw):
            raise ValueError('Invalid outbound Socks5 password')

    if resolved == 'ss2022':
        method = spec.get('method', METHOD)
        _validate_ss2022_password(spec.get('password', ''), SS2022_METHODS[method])
    elif resolved == 'reality':
        if not isinstance(spec.get('uuid'), str) or str(uuid.UUID(spec['uuid'])) != spec['uuid']:
            raise ValueError('Invalid UUID')
        _validate_reality_key(spec.get('reality_private_key', ''))
        _validate_reality_key(spec.get('reality_public_key', ''))
        _validate_short_ids(spec.get('reality_short_ids', []))
    elif resolved in ('trojan', 'anytls'):
        pw = spec.get('password', '')
        if not isinstance(pw, str) or len(pw) < 16 or any(ord(c) < 32 for c in pw):
            raise ValueError(f'Invalid {resolved} password')
    elif resolved == 'vless-ws':
        if not isinstance(spec.get('uuid'), str) or str(uuid.UUID(spec['uuid'])) != spec['uuid']:
            raise ValueError('Invalid UUID')
    elif resolved == 'hysteria2':
        pw = spec.get('password', '')
        if not isinstance(pw, str) or len(pw) < 16 or any(ord(c) < 32 for c in pw):
            raise ValueError('Invalid Hysteria2 password')
        if spec.get('obfs') == 'salamander':
            obfs_pw = spec.get('obfs_password', '')
            if not isinstance(obfs_pw, str) or len(obfs_pw) < 16 or any(ord(c) < 32 for c in obfs_pw):
                raise ValueError('Invalid Hysteria2 salamander password')


def _validate_adopted_inbound(item):
    if not isinstance(item, dict):
        raise ValueError('Invalid adopted node entry')
    sk = item.get('source_key', '')
    if not isinstance(sk, str) or not re.fullmatch(r'(?:adopt-[0-9a-f]{16}|[0-9a-f]{32})', sk):
        raise ValueError('Invalid adopted source_key')
    inbound = item.get('inbound')
    if not isinstance(inbound, dict):
        raise ValueError('Invalid adopted inbound object')
    port = inbound.get('listen_port')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid adopted inbound listen_port')
    if not isinstance(inbound.get('type'), str) or not inbound['type']:
        raise ValueError('Invalid adopted inbound type')


def _validate_disabled_adoption(item):
    if not isinstance(item, dict):
        raise ValueError('Invalid disabled adoption entry')
    if set(item) - {'source_key', 'original_service', 'original_config_path'}:
        raise ValueError('Unsupported disabled adoption field')
    sk = item.get('source_key', '')
    if not isinstance(sk, str) or not re.fullmatch(r'(?:adopt-[0-9a-f]{16}|[0-9a-f]{32})', sk):
        raise ValueError('Invalid disabled adoption source_key')
    svc = item.get('original_service', '')
    if not isinstance(svc, str) or not svc or len(svc) > 100 or not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service\Z', svc):
        raise ValueError('Invalid disabled adoption original_service')
    cfg = item.get('original_config_path', '')
    if cfg and (not isinstance(cfg, str) or len(cfg) > 256):
        raise ValueError('Invalid disabled adoption original_config_path')


def validate_spec(action, spec):
    """Validate full landing specification (including encrypted secrets) sent to Agents."""
    if action == 'landing.remove':
        if spec != {}:
            raise ValueError('Removal takes no configuration')
        return
    if action != 'landing.apply' or not isinstance(spec, dict):
        raise ValueError('Invalid landing specification')

    if spec.get('adopted_only') is True:
        if set(spec) - {'adopted_only', 'adopted_nodes', 'returned_adoptions', 'disabled_adoptions'}:
            raise ValueError('Invalid adopted_only specification')
    else:
        _validate_single_node_spec(spec)

    if 'extra_nodes' in spec:
        extras = spec['extra_nodes']
        if not isinstance(extras, list) or len(extras) > 32:
            raise ValueError('Invalid extra_nodes list')
        for item in extras:
            if not isinstance(item, dict) or any(
                k in item for k in ('extra_nodes', 'adopted_nodes', 'returned_adoptions', 'disabled_adoptions')
            ):
                raise ValueError('Nested extra_nodes are not allowed')
            _validate_single_node_spec(item)

    if spec.get('adopted_only') is not True:
        _validate_shared_listeners(spec)

    if 'adopted_nodes' in spec:
        adopted = spec['adopted_nodes']
        if not isinstance(adopted, list) or len(adopted) > 32:
            raise ValueError('Invalid adopted_nodes list')
        for item in adopted:
            _validate_adopted_inbound(item)

    if 'returned_adoptions' in spec:
        returned = spec['returned_adoptions']
        if not isinstance(returned, list) or len(returned) > 32:
            raise ValueError('Invalid returned_adoptions list')
        for sk in returned:
            if not isinstance(sk, str) or not re.fullmatch(r'(?:adopt-[0-9a-f]{16}|[0-9a-f]{32})', sk):
                raise ValueError('Invalid returned source_key')

    if 'disabled_adoptions' in spec:
        disabled = spec['disabled_adoptions']
        if not isinstance(disabled, list) or len(disabled) > 16:
            raise ValueError('Invalid disabled_adoptions list')
        for item in disabled:
            _validate_disabled_adoption(item)


def deployment_tls_plan(spec, site_id='landing'):
    """Describe ACME certificate & Caddy site orchestration required for a validated landing spec."""
    validate_spec('landing.apply', spec)
    if spec.get('adopted_only') is True:
        return {
            'protocol': 'adopted',
            'tls_mode': 'none',
            'needs_cert': False,
            'needs_caddy': False,
            'caddy_role': '',
            'domain': '',
            'camouflage_url': '',
            'acme': None,
        }
    protocol = _resolved_protocol(spec)
    rules = PROTOCOL_SPEC[protocol]
    tls_mode = spec.get('tls_mode', rules['default_tls'])
    domain = spec.get('domain', '')
    camouflage = spec.get('camouflage_url', '')

    needs_cert = tls_mode in ('acme_http', 'acme_dns')
    if protocol == 'reality' and tls_mode in ('acme_http', 'acme_dns'):
        needs_caddy = True
        caddy_role = 'loopback_camouflage'
    elif protocol == 'trojan' and needs_cert:
        needs_caddy = True
        caddy_role = 'trojan_fallback'
    elif protocol == 'vless-ws' and needs_cert:
        needs_caddy = True
        caddy_role = 'frontdoor_ws'
    else:
        needs_caddy = False
        caddy_role = ''

    acme_params = None
    if needs_cert:
        acme_params = {
            'cert_name': site_id,
            'domain': domain,
            'tls_mode': tls_mode,
            'email': spec.get('acme_email', ''),
            'dns_provider': spec.get('dns_provider', 'cloudflare'),
            'dns_zone_id': spec.get('dns_zone_id', ''),
            'dns_api_token': spec.get('dns_api_token', ''),
            'propagation_seconds': spec.get('dns_propagation_seconds', 60),
        }
    return {
        'protocol': protocol,
        'tls_mode': tls_mode,
        'needs_cert': needs_cert,
        'needs_caddy': needs_caddy,
        'caddy_role': caddy_role,
        'domain': domain,
        'camouflage_url': camouflage,
        'acme': acme_params,
    }


def build_caddy_site_for_landing(spec, *, site_id='landing', listen_port=None, backend_port=None):
    """Build a CaddySiteSpec dict for deployments that require Caddy camouflage/TLS termination."""
    plan = deployment_tls_plan(spec, site_id=site_id)
    if not plan['needs_caddy']:
        return None
    if plan['caddy_role'] == 'trojan_fallback':
        return {
            'site_id': site_id,
            'domain': plan['domain'],
            'tls_mode': 'none',
            'camouflage_mode': spec.get('camouflage_mode', ''),
            'camouflage_template': spec.get('camouflage_template', 'corporate'),
            'camouflage_url': plan['camouflage_url'],
            'camouflage_dir': spec.get('camouflage_dir', ''),
            'email': spec.get('acme_email', ''),
            'listen_port': int(listen_port or 18443),
            'bind_host': '127.0.0.1',
        }
    base = {
        'site_id': site_id,
        'domain': plan['domain'],
        'tls_mode': plan['tls_mode'],
        'camouflage_mode': spec.get('camouflage_mode', ''),
        'camouflage_template': spec.get('camouflage_template', 'corporate'),
        'camouflage_url': plan['camouflage_url'],
        'camouflage_dir': spec.get('camouflage_dir', ''),
        'email': spec.get('acme_email', ''),
        'dns_provider': spec.get('dns_provider', 'cloudflare'),
        'dns_zone_id': spec.get('dns_zone_id', ''),
        'dns_api_token': spec.get('dns_api_token', ''),
        'propagation_seconds': spec.get('dns_propagation_seconds', 60),
    }
    if plan['caddy_role'] == 'loopback_camouflage':
        base['listen_port'] = int(listen_port or 18443)
        base['bind_host'] = '127.0.0.1'
        return base
    # frontdoor_ws: Caddy terminates TLS on public port and forwards WS to local sing-box backend.
    base['listen_port'] = spec['listen_port']
    base['bind_host'] = '::'
    base['backend_port'] = int(backend_port or 18444)
    base['ws_path'] = spec.get('ws_path', '/ws')
    return base


def _handshake_target(spec, caddy_port=None):
    if caddy_port is not None:
        return {'server': '127.0.0.1', 'server_port': int(caddy_port)}
    camouflage = spec.get('camouflage_url', '')
    if camouflage:
        parsed = urllib.parse.urlsplit(camouflage)
        return {'server': parsed.hostname, 'server_port': parsed.port or 443}
    return {'server': spec['domain'], 'server_port': 443}


def _default_cert_paths(site_id, cert_path=None, key_path=None):
    if cert_path and key_path:
        return str(cert_path), str(key_path)
    base = Path('/var/lib/proxyforge-runtime/certs') / site_id
    return str(base / 'fullchain.pem'), str(base / 'privkey.pem')


def _render_single_inbound(spec, *, tag='managed-landing', site_id='landing', cert_path=None, key_path=None,
                           caddy_port=None, backend_port=None):
    protocol = _resolved_protocol(spec)
    if protocol == 'ss2022':
        method = spec.get('method', METHOD)
        return {
            'type': 'shadowsocks',
            'tag': tag,
            'listen': '::',
            'listen_port': spec['listen_port'],
            'method': method,
            'password': spec['password'],
        }
    if protocol == 'reality':
        tls_mode = spec.get('tls_mode', 'reality')
        hs_caddy_port = (caddy_port or 18443) if tls_mode in ('acme_http', 'acme_dns') else caddy_port
        return {
            'type': 'vless',
            'tag': tag,
            'listen': '::',
            'listen_port': spec['listen_port'],
            'users': [{'uuid': spec['uuid'], 'flow': 'xtls-rprx-vision'}],
            'tls': {
                'enabled': True,
                'server_name': spec['domain'],
                'reality': {
                    'enabled': True,
                    'handshake': _handshake_target(spec, hs_caddy_port),
                    'private_key': spec['reality_private_key'],
                    'short_id': list(spec['reality_short_ids']),
                    'max_time_difference': '1m',
                },
            },
        }
    if protocol == 'trojan':
        cert, key = _default_cert_paths(site_id, cert_path, key_path)
        return {
            'type': 'trojan',
            'tag': tag,
            'listen': '::',
            'listen_port': spec['listen_port'],
            'users': [{'name': 'landing', 'password': spec['password']}],
            'tls': {
                'enabled': True,
                'server_name': spec['domain'],
                'min_version': '1.3',
                'alpn': ['h2', 'http/1.1'],
                'certificate_path': cert,
                'key_path': key,
            },
            'fallback': {
                'server': '127.0.0.1',
                'server_port': int(caddy_port or 18443),
            },
        }
    if protocol == 'anytls':
        cert, key = _default_cert_paths(site_id, cert_path, key_path)
        padding = spec.get('padding_scheme') or DEFAULT_ANYTLS_PADDING
        return {
            'type': 'anytls',
            'tag': tag,
            'listen': '::',
            'listen_port': spec['listen_port'],
            'users': [{'name': 'landing', 'password': spec['password']}],
            'padding_scheme': list(padding),
            'tls': {
                'enabled': True,
                'server_name': spec['domain'],
                'min_version': '1.3',
                'alpn': ['h2', 'http/1.1'],
                'certificate_path': cert,
                'key_path': key,
            },
        }
    if protocol == 'vless-ws':
        tls_mode = spec.get('tls_mode', 'acme_http')
        ws_path = spec.get('ws_path', '/ws')
        if tls_mode in ('acme_http', 'acme_dns'):
            listen_host = '127.0.0.1'
            listen_port = int(backend_port or 18444)
        else:
            listen_host = '::'
            listen_port = spec['listen_port']
        return {
            'type': 'vless',
            'tag': tag,
            'listen': listen_host,
            'listen_port': listen_port,
            'users': [{'uuid': spec['uuid']}],
            'transport': {
                'type': 'ws',
                'path': ws_path,
            },
        }
    if protocol == 'hysteria2':
        cert, key = _default_cert_paths(site_id, cert_path, key_path)
        inbound = {
            'type': 'hysteria2',
            'tag': tag,
            'listen': '::',
            'listen_port': spec['listen_port'],
            'users': [{'name': 'landing', 'password': spec['password']}],
            'tls': {
                'enabled': True,
                'server_name': spec['domain'],
                'min_version': '1.3',
                'alpn': ['h3'],
                'certificate_path': cert,
                'key_path': key,
            },
        }
        if spec.get('obfs') == 'salamander':
            inbound['obfs'] = {'type': 'salamander', 'password': spec['obfs_password']}
        for field in ('up_mbps', 'down_mbps'):
            if field in spec:
                inbound[field] = spec[field]
        if spec.get('camouflage_url'):
            inbound['masquerade'] = spec['camouflage_url']
        return inbound
    raise ValueError('Unsupported landing protocol')


# Always set prefer_go=True so sing-box reads /etc/resolv.conf directly via Go's resolver
# instead of failing on D-Bus org.freedesktop.resolve1 on servers without systemd-resolved.
_LOCAL_DNS_SERVER = {'type': 'local', 'tag': 'local', 'prefer_go': True}


def _apply_domain_resolver(out, strategy):
    if strategy:
        # sing-box 1.14+ removed outbound.domain_strategy in favor of domain_resolver.
        out['domain_resolver'] = {'server': 'local', 'strategy': strategy}


def _build_node_outbound(node_spec, tag):
    mode = node_spec.get('outbound_mode', 'direct')
    strategy = node_spec.get('outbound_strategy')
    if mode == 'socks5':
        out = {
            'type': 'socks',
            'tag': tag,
            'server': node_spec['outbound_server'],
            'server_port': node_spec['outbound_port'],
            'version': '5',
        }
        if node_spec.get('outbound_username'):
            out['username'] = node_spec['outbound_username']
        if node_spec.get('outbound_password'):
            out['password'] = node_spec['outbound_password']
        _apply_domain_resolver(out, strategy)
        return out
    if mode == 'ss':
        out = {
            'type': 'shadowsocks',
            'tag': tag,
            'server': node_spec['outbound_server'],
            'server_port': node_spec['outbound_port'],
            'method': node_spec.get('outbound_method', METHOD),
            'password': node_spec['outbound_password'],
        }
        _apply_domain_resolver(out, strategy)
        return out
    out = {'type': 'direct', 'tag': tag}
    _apply_domain_resolver(out, strategy)
    return out


def _build_node_outbounds(node_spec, base_tag):
    """Build one or more sing-box outbounds (chained via detour when outbound_mode='chain')."""
    mode = node_spec.get('outbound_mode', 'direct')
    strategy = node_spec.get('outbound_strategy')
    if mode == 'chain':
        hops = node_spec.get('resolved_outbound_hops') or []
        outs = []
        prev_tag = ''
        for idx, hop in enumerate(hops, 1):
            hop_tag = f'{base_tag}-h{idx}'
            if hop['type'] == 'ss':
                out = {
                    'type': 'shadowsocks',
                    'tag': hop_tag,
                    'server': hop['server'],
                    'server_port': hop['port'],
                    'method': hop.get('method', METHOD),
                    'password': hop['password'],
                }
            else:
                out = {
                    'type': 'socks',
                    'tag': hop_tag,
                    'server': hop['server'],
                    'server_port': hop['port'],
                    'version': '5',
                }
                if hop.get('username'):
                    out['username'] = hop['username']
                if hop.get('password'):
                    out['password'] = hop['password']
            if idx == 1:
                _apply_domain_resolver(out, strategy)
            if prev_tag:
                out['detour'] = prev_tag
            outs.append(out)
            prev_tag = hop_tag
        return outs, prev_tag
    return [_build_node_outbound(node_spec, base_tag)], base_tag


def runtime_config(spec, *, cert_path=None, key_path=None, caddy_port=None, backend_port=None, site_id='landing',
                   extra_overrides=None):
    """Render official sing-box JSON configuration for any supported landing protocol."""
    validate_spec('landing.apply', spec)
    extra_overrides = extra_overrides or {}

    if spec.get('adopted_only') is True:
        inbounds = []
        for idx, adopted in enumerate(spec.get('adopted_nodes') or [], 1):
            adopted_in = dict(adopted['inbound'])
            adopted_in.setdefault('tag', f"adopted-{str(adopted.get('source_key', idx))[-8:]}")
            inbounds.append(adopted_in)
        return {'log': {'level': 'warn'}, 'inbounds': inbounds, 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}

    def inbound_tag(member_id):
        return 'managed-landing' if member_id == 'primary' else f'managed-node-{member_id}'

    def render_inbound(member_id, node):
        if member_id == 'primary':
            return _render_single_inbound(
                node, tag=inbound_tag(member_id), site_id=site_id, cert_path=cert_path, key_path=key_path,
                caddy_port=caddy_port, backend_port=backend_port,
            )
        ov = extra_overrides.get(member_id) or {}
        return _render_single_inbound(
            node, tag=inbound_tag(member_id), site_id=f'node-{member_id}', cert_path=ov.get('cert_path'),
            key_path=ov.get('key_path'), caddy_port=ov.get('caddy_port'), backend_port=ov.get('backend_port'),
        )

    entries = _node_entries(spec)
    entry_map = dict(entries)
    shared_plan = shared_listener_plan(spec)
    member_group = {member: key for key, group in shared_plan.items() for member in group['members']}

    inbounds = []
    emitted_groups = set()
    for member_id, node in entries:
        key = member_group.get(member_id)
        if key is None:
            inbounds.append(render_inbound(member_id, node))
            continue
        if key in emitted_groups:
            continue
        # One listener per shared (protocol, port); the host supplies TLS/Caddy and every
        # member contributes a named user so `auth_user` can route it independently.
        emitted_groups.add(key)
        group = shared_plan[key]
        merged = render_inbound(group['host'], entry_map[group['host']])
        _merge_shared_users(merged, key[0], [(member, entry_map[member]) for member in group['members']])
        inbounds.append(merged)
    for idx, adopted in enumerate(spec.get('adopted_nodes') or [], 1):
        adopted_in = dict(adopted['inbound'])
        adopted_in.setdefault('tag', f"adopted-{str(adopted.get('source_key', idx))[-8:]}")
        inbounds.append(adopted_in)

    extra_nodes = spec.get('extra_nodes') or []
    primary_mode = spec.get('outbound_mode', 'direct')
    primary_strategy = spec.get('outbound_strategy')

    def has_custom_outbound(node):
        return node.get('outbound_mode', 'direct') != 'direct' or bool(node.get('outbound_strategy'))

    if primary_mode == 'direct' and not any(has_custom_outbound(item) for item in extra_nodes):
        direct_out = {'type': 'direct', 'tag': 'direct'}
        _apply_domain_resolver(direct_out, primary_strategy)
        cfg = {'log': {'level': 'warn'}, 'inbounds': inbounds, 'outbounds': [direct_out]}
        if 'domain_resolver' in direct_out:
            cfg['dns'] = {'servers': [dict(_LOCAL_DNS_SERVER)]}
        return cfg

    outbounds = []
    route_rules = []
    primary_final_tag = 'direct'
    for member_id, node in entries:
        key = member_group.get(member_id)
        if has_custom_outbound(node):
            outs, out_tag = _build_node_outbounds(node, 'out-primary' if member_id == 'primary' else f'out-node-{member_id}')
            outbounds.extend(outs)
            if member_id == 'primary':
                primary_final_tag = out_tag
        elif key is not None:
            out_tag = 'direct'  # Shared listener members are always routed explicitly.
        else:
            continue
        if key is None:
            route_rules.append({'inbound': [inbound_tag(member_id)], 'action': 'route', 'outbound': out_tag})
        else:
            route_rules.append({
                'inbound': [inbound_tag(shared_plan[key]['host'])],
                'auth_user': [shared_user_key(member_id)],
                'action': 'route',
                'outbound': out_tag,
            })
    outbounds.append({'type': 'direct', 'tag': 'direct'})
    final_tag = primary_final_tag if (primary_mode != 'direct' and not extra_nodes) else 'direct'
    cfg = {
        'log': {'level': 'warn'},
        'inbounds': inbounds,
        'outbounds': outbounds,
        'route': {'rules': route_rules, 'final': final_tag},
    }
    if any('domain_resolver' in o for o in outbounds):
        cfg['dns'] = {'servers': [dict(_LOCAL_DNS_SERVER)]}
    return cfg


def client_node(identifier, agent_id, spec):
    """Project a client-facing Mihomo node dict when the landing protocol supports direct subscriptions."""
    protocol = _resolved_protocol(spec)
    if protocol == 'ss2022':
        if not spec.get('publish_to_subscription'):
            return None
        managed = {'type': 'agent', 'agent_id': agent_id, 'deployment_id': identifier}
        label = node_name(identifier, spec['name'])
        return {
            'name': label,
            'type': 'ss',
            'server': spec['server'],
            'port': spec['listen_port'],
            'cipher': spec.get('method', METHOD),
            'password': spec['password'],
            'udp': True,
            '_managed_by': managed,
        }
    if not PROTOCOL_SPEC[protocol]['project_client']:
        return None
    managed = {'type': 'agent', 'agent_id': agent_id, 'deployment_id': identifier}
    label = node_name(identifier, spec['name'])

    if protocol == 'reality':
        return {
            'name': label,
            'type': 'vless',
            'server': spec['server'],
            'port': spec['listen_port'],
            'uuid': spec['uuid'],
            'network': 'tcp',
            'tls': True,
            'udp': True,
            'flow': 'xtls-rprx-vision',
            'servername': spec['domain'],
            'client-fingerprint': spec.get('fingerprint', 'chrome'),
            'reality-opts': {
                'public-key': spec['reality_public_key'],
                'short-id': spec['reality_short_ids'][0],
            },
            '_managed_by': managed,
        }
    if protocol == 'trojan':
        return {
            'name': label,
            'type': 'trojan',
            'server': spec['server'],
            'port': spec['listen_port'],
            'password': spec['password'],
            'sni': spec['domain'],
            'udp': True,
            '_managed_by': managed,
        }
    if protocol == 'anytls':
        return {
            'name': label,
            'type': 'anytls',
            'server': spec['server'],
            'port': spec['listen_port'],
            'password': spec['password'],
            'sni': spec['domain'],
            'udp': True,
            'client-fingerprint': spec.get('fingerprint', 'chrome'),
            '_managed_by': managed,
        }
    if protocol == 'vless-ws':
        tls_enabled = spec.get('tls_mode', 'acme_http') != 'none'
        node = {
            'name': label,
            'type': 'vless',
            'server': spec['server'],
            'port': spec['listen_port'],
            'uuid': spec['uuid'],
            'network': 'ws',
            'tls': tls_enabled,
            'udp': True,
            'ws-opts': {
                'path': spec.get('ws_path', '/ws'),
                'headers': {'Host': spec.get('domain') or spec['server']},
            },
            '_managed_by': managed,
        }
        if spec.get('domain'):
            node['servername'] = spec['domain']
        return node
    if protocol == 'hysteria2':
        node = {
            'name': label,
            'type': 'hysteria2',
            'server': spec['server'],
            'port': spec['listen_port'],
            'password': spec['password'],
            'sni': spec['domain'],
            '_managed_by': managed,
        }
        if spec.get('mport'):
            node['ports'] = _validate_mport(spec['mport'])
        if spec.get('hop_interval'):
            node['hop-interval'] = int(spec['hop_interval'])
        if spec.get('obfs') == 'salamander':
            node['obfs'] = 'salamander'
            node['obfs-password'] = spec['obfs_password']
        if spec.get('up_mbps'):
            node['up'] = spec['up_mbps']
        if spec.get('down_mbps'):
            node['down'] = spec['down_mbps']
        return node
    return None
