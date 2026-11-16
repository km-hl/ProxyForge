"""Unified landing protocol specs (SS2022, Reality, Trojan, VLESS-WS, Hysteria2)."""
import base64
import binascii
import os
from pathlib import Path
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
LANDING_PROTOCOLS = ('ss2022', 'reality', 'trojan', 'vless-ws', 'hysteria2')
TLS_MODES = ('none', 'reality', 'acme_http', 'acme_dns')
FINGERPRINTS = ('chrome', 'firefox', 'safari', 'edge', 'ios', 'android', 'random', 'randomized')
DNS_PROVIDERS = ('cloudflare', 'alidns', 'dnspod')
CAMOUFLAGE_UNSAFE = re.compile(r'[\x00-\x1f\x7f{};"\'\\\r\n]')
EMAIL_RE = re.compile(r'[^\s@]+@[^\s@]+\.[^\s@]+\Z')

PROTOCOL_SPEC = {
    'ss2022': {
        'tls_modes': ('none',),
        'default_tls': 'none',
        'requires_domain': False,
        'secret_fields': frozenset(('password',)),
        'project_client': False,
    },
    'reality': {
        'tls_modes': ('reality', 'acme_http', 'acme_dns'),
        'default_tls': 'reality',
        'requires_domain': True,
        'secret_fields': frozenset(('uuid', 'reality_private_key', 'dns_api_token')),
        'project_client': True,
    },
    'trojan': {
        'tls_modes': ('acme_http', 'acme_dns'),
        'default_tls': 'acme_http',
        'requires_domain': True,
        'secret_fields': frozenset(('password', 'dns_api_token')),
        'project_client': True,
    },
    'vless-ws': {
        'tls_modes': ('none', 'acme_http', 'acme_dns'),
        'default_tls': 'acme_http',
        'requires_domain': False,
        'secret_fields': frozenset(('uuid', 'dns_api_token')),
        'project_client': True,
    },
    'hysteria2': {
        'tls_modes': ('acme_http', 'acme_dns'),
        'default_tls': 'acme_http',
        'requires_domain': True,
        'secret_fields': frozenset(('password', 'obfs_password', 'dns_api_token')),
        'project_client': True,
    },
}

_COMMON_OPTIONAL = {
    'protocol', 'domain', 'tls_mode', 'camouflage_url',
    'acme_email', 'dns_provider', 'dns_zone_id', 'dns_propagation_seconds',
}
_PROTOCOL_ALLOWED_SETTINGS = {
    'ss2022': {'name', 'server', 'listen_port', 'method', *_COMMON_OPTIONAL},
    'reality': {'name', 'server', 'listen_port', 'reality_public_key', 'reality_short_ids', 'fingerprint', *_COMMON_OPTIONAL},
    'trojan': {'name', 'server', 'listen_port', *_COMMON_OPTIONAL},
    'vless-ws': {'name', 'server', 'listen_port', 'ws_path', *_COMMON_OPTIONAL},
    'hysteria2': {'name', 'server', 'listen_port', 'up_mbps', 'down_mbps', 'obfs', *_COMMON_OPTIONAL},
}
_SECRET_INPUT_KEYS = frozenset(('password', 'private_key', 'reality_private_key', 'dns_api_token', 'obfs_password'))


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
    if resolved == 'ss2022' and 'tls_mode' not in settings and 'domain' not in settings and 'protocol' not in settings:
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
    _validate_acme_fields(settings, tls_mode)

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
    elif resolved == 'vless-ws':
        if 'ws_path' in settings:
            _validate_ws_path(settings['ws_path'])
    elif resolved == 'hysteria2':
        for field in ('up_mbps', 'down_mbps'):
            if field in settings and (type(settings[field]) is not int or not 1 <= settings[field] <= 100000):
                raise ValueError('Invalid Hysteria2 bandwidth limit')
        if 'obfs' in settings and settings['obfs'] not in ('none', 'salamander'):
            raise ValueError('Unsupported Hysteria2 obfuscation')


def validate_spec(action, spec):
    """Validate full landing specification (including encrypted secrets) sent to Agents."""
    if action == 'landing.remove':
        if spec != {}:
            raise ValueError('Removal takes no configuration')
        return
    if action != 'landing.apply' or not isinstance(spec, dict):
        raise ValueError('Invalid landing specification')

    resolved = _resolved_protocol(spec, default='ss2022')
    # Legacy exact 5-key SS2022 shape for hash & test backward compatibility.
    if resolved == 'ss2022' and set(spec) == {'name', 'server', 'listen_port', 'method', 'password'}:
        validate_settings({k: spec[k] for k in ('name', 'server', 'listen_port', 'method')}, protocol='ss2022')
        _validate_ss2022_password(spec['password'], SS2022_METHODS[spec['method']])
        return

    rules = PROTOCOL_SPEC[resolved]
    allowed = _PROTOCOL_ALLOWED_SETTINGS[resolved] | rules['secret_fields'] | {'reality_public_key', 'uuid'}
    if set(spec) - allowed:
        raise ValueError('Invalid landing specification')

    public = {k: v for k, v in spec.items() if k in _PROTOCOL_ALLOWED_SETTINGS[resolved]}
    validate_settings(public, protocol=resolved)
    tls_mode = spec.get('tls_mode', rules['default_tls'])

    if tls_mode == 'acme_dns':
        token = spec.get('dns_api_token', '')
        if not isinstance(token, str) or not 12 <= len(token) <= 256 or any(ord(c) < 32 for c in token):
            raise ValueError('Missing or invalid ACME DNS API token')

    if resolved == 'ss2022':
        method = spec.get('method', METHOD)
        _validate_ss2022_password(spec.get('password', ''), SS2022_METHODS[method])
    elif resolved == 'reality':
        if not isinstance(spec.get('uuid'), str) or str(uuid.UUID(spec['uuid'])) != spec['uuid']:
            raise ValueError('Invalid UUID')
        _validate_reality_key(spec.get('reality_private_key', ''))
        _validate_reality_key(spec.get('reality_public_key', ''))
        _validate_short_ids(spec.get('reality_short_ids', []))
    elif resolved == 'trojan':
        pw = spec.get('password', '')
        if not isinstance(pw, str) or len(pw) < 16 or any(ord(c) < 32 for c in pw):
            raise ValueError('Invalid Trojan password')
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


def deployment_tls_plan(spec, site_id='landing'):
    """Describe ACME certificate & Caddy site orchestration required for a validated landing spec."""
    validate_spec('landing.apply', spec)
    protocol = _resolved_protocol(spec)
    rules = PROTOCOL_SPEC[protocol]
    tls_mode = spec.get('tls_mode', rules['default_tls'])
    domain = spec.get('domain', '')
    camouflage = spec.get('camouflage_url', '')

    needs_cert = tls_mode in ('acme_http', 'acme_dns')
    if protocol == 'reality' and tls_mode in ('acme_http', 'acme_dns'):
        needs_caddy = True
        caddy_role = 'loopback_camouflage'
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
    base = {
        'site_id': site_id,
        'domain': plan['domain'],
        'tls_mode': plan['tls_mode'],
        'camouflage_url': plan['camouflage_url'],
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


def runtime_config(spec, *, cert_path=None, key_path=None, caddy_port=None, backend_port=None, site_id='landing'):
    """Render official sing-box JSON configuration for any supported landing protocol."""
    validate_spec('landing.apply', spec)
    protocol = _resolved_protocol(spec)

    if protocol == 'ss2022':
        method = spec.get('method', METHOD)
        inbound = {
            'type': 'shadowsocks',
            'tag': 'managed-landing',
            'listen': '::',
            'listen_port': spec['listen_port'],
            'method': method,
            'password': spec['password'],
        }
    elif protocol == 'reality':
        tls_mode = spec.get('tls_mode', 'reality')
        hs_caddy_port = (caddy_port or 18443) if tls_mode in ('acme_http', 'acme_dns') else caddy_port
        inbound = {
            'type': 'vless',
            'tag': 'managed-landing',
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
                },
            },
        }
    elif protocol == 'trojan':
        cert, key = _default_cert_paths(site_id, cert_path, key_path)
        inbound = {
            'type': 'trojan',
            'tag': 'managed-landing',
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
        }
    elif protocol == 'vless-ws':
        tls_mode = spec.get('tls_mode', 'acme_http')
        ws_path = spec.get('ws_path', '/ws')
        if tls_mode in ('acme_http', 'acme_dns'):
            # Front-door Caddy terminates TLS and proxies WS here on loopback.
            listen_host = '127.0.0.1'
            listen_port = int(backend_port or 18444)
        else:
            listen_host = '::'
            listen_port = spec['listen_port']
        inbound = {
            'type': 'vless',
            'tag': 'managed-landing',
            'listen': listen_host,
            'listen_port': listen_port,
            'users': [{'uuid': spec['uuid']}],
            'transport': {
                'type': 'ws',
                'path': ws_path,
            },
        }
    elif protocol == 'hysteria2':
        cert, key = _default_cert_paths(site_id, cert_path, key_path)
        inbound = {
            'type': 'hysteria2',
            'tag': 'managed-landing',
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
    else:
        raise ValueError('Unsupported landing protocol')

    return {'log': {'level': 'warn'}, 'inbounds': [inbound], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}


def client_node(identifier, agent_id, spec):
    """Project a client-facing Mihomo node dict when the landing protocol supports direct subscriptions."""
    protocol = _resolved_protocol(spec)
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
        if spec.get('obfs') == 'salamander':
            node['obfs'] = 'salamander'
            node['obfs-password'] = spec['obfs_password']
        if spec.get('up_mbps'):
            node['up'] = spec['up_mbps']
        if spec.get('down_mbps'):
            node['down'] = spec['down_mbps']
        return node
    return None
