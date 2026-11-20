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

_COMMON_OPTIONAL = {
    'protocol', 'domain', 'tls_mode',
    'camouflage_url', 'camouflage_mode', 'camouflage_template', 'camouflage_dir',
    'acme_email', 'dns_provider', 'dns_zone_id', 'dns_propagation_seconds',
    'region', 'outbound_strategy', 'outbound_mode',
    'outbound_server', 'outbound_port', 'outbound_username', 'outbound_method',
    'outbound_hops',
    'publish_to_subscription', 'node_id',
}
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
        if strategy:
            out['domain_strategy'] = strategy
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
        if strategy:
            out['domain_strategy'] = strategy
        return out
    out = {'type': 'direct', 'tag': tag}
    if strategy:
        out['domain_strategy'] = strategy
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
            if idx == 1 and strategy:
                out['domain_strategy'] = strategy
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

    primary_inbound = _render_single_inbound(
        spec,
        tag='managed-landing',
        site_id=site_id,
        cert_path=cert_path,
        key_path=key_path,
        caddy_port=caddy_port,
        backend_port=backend_port,
    )
    inbounds = [primary_inbound]
    extra_nodes = spec.get('extra_nodes') or []
    for idx, extra in enumerate(extra_nodes, 1):
        nid = str(extra.get('node_id') or idx)
        node_site_id = f'node-{nid}'
        ov = extra_overrides.get(nid) or {}
        inbounds.append(
            _render_single_inbound(
                extra,
                tag=f'managed-node-{nid}',
                site_id=node_site_id,
                cert_path=ov.get('cert_path'),
                key_path=ov.get('key_path'),
                caddy_port=ov.get('caddy_port'),
                backend_port=ov.get('backend_port'),
            )
        )
    for idx, adopted in enumerate(spec.get('adopted_nodes') or [], 1):
        adopted_in = dict(adopted['inbound'])
        adopted_in.setdefault('tag', f"adopted-{str(adopted.get('source_key', idx))[-8:]}")
        inbounds.append(adopted_in)

    primary_mode = spec.get('outbound_mode', 'direct')
    primary_strategy = spec.get('outbound_strategy')
    has_custom_extra = any(
        (item.get('outbound_mode', 'direct') != 'direct' or item.get('outbound_strategy'))
        for item in extra_nodes
    )

    if primary_mode == 'direct' and not has_custom_extra:
        direct_out = {'type': 'direct', 'tag': 'direct'}
        if primary_strategy:
            direct_out['domain_strategy'] = primary_strategy
        return {'log': {'level': 'warn'}, 'inbounds': inbounds, 'outbounds': [direct_out]}

    outbounds = []
    route_rules = []
    primary_final_tag = 'direct'
    if primary_mode != 'direct' or primary_strategy:
        p_outs, p_tag = _build_node_outbounds(spec, 'out-primary')
        outbounds.extend(p_outs)
        route_rules.append({'inbound': ['managed-landing'], 'outbound': p_tag})
        primary_final_tag = p_tag
    for idx, extra in enumerate(extra_nodes, 1):
        nid = str(extra.get('node_id') or idx)
        e_mode = extra.get('outbound_mode', 'direct')
        e_strategy = extra.get('outbound_strategy')
        if e_mode != 'direct' or e_strategy:
            e_outs, e_tag = _build_node_outbounds(extra, f'out-node-{nid}')
            outbounds.extend(e_outs)
            route_rules.append({'inbound': [f'managed-node-{nid}'], 'outbound': e_tag})
    outbounds.append({'type': 'direct', 'tag': 'direct'})
    final_tag = primary_final_tag if (primary_mode != 'direct' and not extra_nodes) else 'direct'
    return {
        'log': {'level': 'warn'},
        'inbounds': inbounds,
        'outbounds': outbounds,
        'route': {'rules': route_rules, 'final': final_tag},
    }


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
