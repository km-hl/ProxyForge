"""Isolated Caddy camouflage and TLS reverse-proxy configuration manager."""
import json
import os
from pathlib import Path
import re
import urllib.parse

from .acme_manager import (
    DEFAULT_STATE_DIR as DEFAULT_ACME_DIR,
    AcmeError,
    AcmeManager,
    _private_dir,
    atomic_write_bytes,
    atomic_write_json,
    is_ip,
    validate_domain,
    validate_email,
)
from .runtime_engine import (
    CADDY_PROFILE,
    allocate_loopback_port,
    collect_active_bindings,
    normalize_bind_host,
    sync_directory,
    validate_port_allocation,
)
from .runtime_spec import SERVICE_CADDY, revision

DEFAULT_CADDY_STATE_DIR = Path('/var/lib/proxyforge-runtime/services/caddy/state')
SITE_ID_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
UNSAFE_CADDYFILE_CHARS = re.compile(r'[\x00-\x1f\x7f{};"\'\\\r\n]')
ALLOWED_TLS_MODES = frozenset(('none', 'acme_http', 'acme_dns', 'selfsigned', 'caddy_acme', 'custom'))


class CaddyError(ValueError):
    """Sanitized Caddy configuration or management error."""


def _assert_safe_token(value, label):
    if not isinstance(value, str) or not value or UNSAFE_CADDYFILE_CHARS.search(value) or any(ch.isspace() for ch in value):
        raise CaddyError(f'Unsafe Caddyfile token for {label}')
    return value


def validate_camouflage_url(url):
    """Validate optional HTTPS camouflage upstream URL against SSRF and directive injection."""
    if not url:
        return ''
    if not isinstance(url, str) or len(url) > 253 or UNSAFE_CADDYFILE_CHARS.search(url) or any(ch.isspace() for ch in url):
        raise CaddyError('Invalid camouflage URL')
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/') or
            is_ip(parsed.hostname)):
        raise CaddyError('Camouflage URL must be a plain HTTPS domain root without credentials or IP literals')
    try:
        host = validate_domain(parsed.hostname)
    except AcmeError as exc:
        raise CaddyError(str(exc)) from None
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise CaddyError('Invalid camouflage port')
    return f'https://{host}' + (f':{port}' if port and port != 443 else '')


def validate_ws_path(path):
    if not path:
        return '/'
    if (not isinstance(path, str) or len(path) > 128 or not path.startswith('/') or
            UNSAFE_CADDYFILE_CHARS.search(path) or any(ch.isspace() for ch in path) or
            '?' in path or '#' in path):
        raise CaddyError('Invalid WebSocket path')
    return path


def _validate_bind_host(value):
    if value is None:
        return '127.0.0.1'
    host = normalize_bind_host(value)
    if host not in ('127.0.0.1', '::1', '0.0.0.0', '::'):
        raise CaddyError('Caddy bind host must be 127.0.0.1, ::1, 0.0.0.0, or ::')
    return host


def validate_site_spec(spec):
    """Validate and normalize one Caddy camouflage / reverse-proxy site definition."""
    if not isinstance(spec, dict):
        raise CaddyError('Invalid Caddy site specification')
    site_id = spec.get('site_id', '')
    if not isinstance(site_id, str) or not SITE_ID_PATTERN.fullmatch(site_id) or site_id in ('.', '..'):
        raise CaddyError('Invalid Caddy site identifier')
    try:
        domain = validate_domain(spec.get('domain', ''))
    except AcmeError as exc:
        raise CaddyError(str(exc)) from None
    port = spec.get('listen_port')
    if type(port) is not int or not 1 <= port <= 65535:
        raise CaddyError('Invalid Caddy listening port')
    tls_mode = spec.get('tls_mode', 'acme_http')
    if tls_mode not in ALLOWED_TLS_MODES:
        raise CaddyError('Unsupported Caddy TLS mode')
    bind_host = _validate_bind_host(spec.get('bind_host', '127.0.0.1' if spec.get('backend_port') is None else '::'))
    backend_port = spec.get('backend_port')
    if backend_port is not None and (type(backend_port) is not int or not 1 <= backend_port <= 65535 or backend_port == port):
        raise CaddyError('Invalid Caddy reverse-proxy backend port')
    ws_path = validate_ws_path(spec.get('ws_path', '/')) if backend_port is not None else ''
    camouflage = validate_camouflage_url(spec.get('camouflage_url', ''))
    try:
        email = validate_email(spec.get('email', ''))
    except AcmeError as exc:
        raise CaddyError(str(exc)) from None
    normalized = {
        'site_id': site_id,
        'domain': domain,
        'listen_port': port,
        'bind_host': bind_host,
        'tls_mode': tls_mode,
        'backend_port': backend_port,
        'ws_path': ws_path,
        'camouflage_url': camouflage,
        'email': email,
    }
    if tls_mode == 'custom':
        cert_path = spec.get('cert_path', '')
        key_path = spec.get('key_path', '')
        if not cert_path or not key_path:
            raise CaddyError('Custom TLS mode requires certificate and key paths')
        _assert_safe_token(str(cert_path), 'cert_path')
        _assert_safe_token(str(key_path), 'key_path')
        normalized['cert_path'] = str(cert_path)
        normalized['key_path'] = str(key_path)
    if tls_mode == 'acme_dns':
        normalized['dns_provider'] = _assert_safe_token(spec.get('dns_provider', 'cloudflare'), 'dns_provider')
        normalized['dns_zone_id'] = str(spec.get('dns_zone_id', ''))
        normalized['credential_id'] = str(spec.get('credential_id', ''))
        normalized['dns_api_token'] = str(spec.get('dns_api_token', ''))
        normalized['propagation_seconds'] = int(spec.get('propagation_seconds', 60))
    return normalized


def _format_site_block(site, cert_pair=None):
    try:
        domain = validate_domain(site['domain'])
    except AcmeError as exc:
        raise CaddyError(str(exc)) from None
    port = site['listen_port']
    tls_mode = site['tls_mode']
    scheme = 'http' if tls_mode == 'none' else 'https'
    address = f'{scheme}://{domain}:{port}'
    bind_host = _validate_bind_host(site.get('bind_host'))
    bind_token = '[::1]' if bind_host == '::1' else ('[::]' if bind_host == '::' else bind_host)

    lines = [f'{address} {{', f'\tbind {bind_token}']
    if tls_mode not in ('none', 'caddy_acme'):
        if cert_pair is None:
            raise CaddyError(f'Missing resolved TLS certificate pair for site {site["site_id"]}')
        cert_file = _assert_safe_token(str(cert_pair[0]), 'cert_file')
        key_file = _assert_safe_token(str(cert_pair[1]), 'key_file')
        lines.append(f'\ttls {cert_file} {key_file}')

    camouflage_url = validate_camouflage_url(site.get('camouflage_url', ''))
    if camouflage_url:
        upstream_host = urllib.parse.urlsplit(camouflage_url).netloc
        camouflage_lines = [
            f'reverse_proxy {camouflage_url} {{',
            f'\theader_up Host {upstream_host}',
            '}',
        ]
    else:
        camouflage_lines = [
            'header Content-Type "text/html; charset=utf-8"',
            'respond "<!doctype html><html><head><meta charset=\\"utf-8\\"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>" 200',
        ]

    backend_port = site.get('backend_port')
    if backend_port is not None:
        ws_path = validate_ws_path(site.get('ws_path', '/'))
        lines.extend([
            '\t@ws {',
            f'\t\tpath {ws_path}',
            '\t}',
            '\thandle @ws {',
            f'\t\treverse_proxy 127.0.0.1:{int(backend_port)}',
            '\t}',
            '\thandle {',
            *(f'\t\t{item}' for item in camouflage_lines),
            '\t}',
        ])
    else:
        lines.extend(f'\t{item}' for item in camouflage_lines)
    lines.append('}')
    return '\n'.join(lines)


def render_caddyfile(
    sites,
    *,
    cert_pairs=None,
    admin_socket='',
    storage_dir='',
    email='',
    log_level='WARN',
):
    """Render a deterministic, injection-safe Caddyfile for all managed camouflage sites."""
    cert_pairs = cert_pairs or {}
    normalized_sites = [validate_site_spec(item) for item in sites]
    normalized_sites.sort(key=lambda item: item['site_id'])
    seen_listeners = {}
    for item in normalized_sites:
        listener_key = (item['domain'], item['listen_port'])
        if listener_key in seen_listeners:
            raise CaddyError(f'Duplicate domain/port binding in Caddyfile: {item["domain"]}:{item["listen_port"]}')
        seen_listeners[listener_key] = item['site_id']

    uses_caddy_acme = any(item['tls_mode'] == 'caddy_acme' for item in normalized_sites)
    _assert_safe_token(log_level, 'log_level')
    global_lines = ['{']
    if admin_socket:
        _assert_safe_token(str(admin_socket), 'admin_socket')
        global_lines.append(f'\tadmin unix/{admin_socket}')
    else:
        global_lines.append('\tadmin off')
    if storage_dir:
        _assert_safe_token(str(storage_dir), 'storage_dir')
        global_lines.append(f'\tstorage file_system {storage_dir}')
    if uses_caddy_acme:
        global_lines.append('\tauto_https disable_redirects')
        try:
            clean_email = validate_email(email or next((s['email'] for s in normalized_sites if s['email']), ''))
        except AcmeError as exc:
            raise CaddyError(str(exc)) from None
        if clean_email:
            _assert_safe_token(clean_email, 'email')
            global_lines.append(f'\temail {clean_email}')
    else:
        global_lines.append('\tauto_https off')
    # Disable HTTP/3 in Caddy so Hysteria2 / QUIC keeps exclusive UDP 443 ownership.
    global_lines.extend(['\tservers {', '\t\tprotocols h1 h2', '\t}', '\tlog {', f'\t\tlevel {log_level}', '\t}', '}'])

    blocks = ['\n'.join(global_lines)]
    for site in normalized_sites:
        pair = cert_pairs.get(site['site_id'])
        if pair is None and site['tls_mode'] == 'custom':
            pair = (site['cert_path'], site['key_path'])
        blocks.append(_format_site_block(site, pair))
    return '\n\n'.join(blocks) + '\n'


class CaddyManager:
    """Coordinate ACME TLS certs, Caddyfile generation and atomic runtime updates."""

    def __init__(
        self,
        state_dir=DEFAULT_CADDY_STATE_DIR,
        *,
        acme_manager=None,
        runtime_engine=None,
        service_roots=None,
        service_gid=None,
    ):
        self.state_dir = Path(state_dir)
        self.acme = acme_manager or AcmeManager(DEFAULT_ACME_DIR)
        self.runtime_engine = runtime_engine
        self.service_roots = service_roots
        self.service_gid = service_gid

    @property
    def certs_dir(self):
        return self.state_dir.parent / 'certs'

    def _sites_path(self):
        return self.state_dir / 'sites.json'

    def load_sites(self):
        path = self._sites_path()
        if path.is_symlink():
            raise CaddyError('Refusing symlinked Caddy sites metadata')
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise CaddyError('Corrupted Caddy sites metadata') from exc
        if not isinstance(data, dict):
            raise CaddyError('Invalid Caddy sites metadata')
        return {site_id: validate_site_spec(spec) for site_id, spec in data.items()}

    def _public_site_metadata(self, site):
        # Never persist transient API tokens inside Caddy sites.json.
        return {k: v for k, v in site.items() if k != 'dns_api_token'}

    def save_sites(self, sites):
        _private_dir(self.state_dir)
        cleaned = {site_id: self._public_site_metadata(spec) for site_id, spec in sorted(sites.items())}
        atomic_write_json(self._sites_path(), cleaned)

    def _stage_cert_files(self, site_id, src_cert, src_key):
        cert_dir = _private_dir(self.certs_dir)
        if os.name == 'posix':
            cert_dir.chmod(0o750)
            if self.service_gid is not None:
                os.chown(cert_dir, 0, self.service_gid)
        dest_cert = cert_dir / (site_id + '.crt')
        dest_key = cert_dir / (site_id + '.key')
        atomic_write_bytes(dest_cert, Path(src_cert).read_bytes(), mode=0o640)
        atomic_write_bytes(dest_key, Path(src_key).read_bytes(), mode=0o640)
        if os.name == 'posix' and self.service_gid is not None:
            os.chown(dest_cert, 0, self.service_gid)
            os.chown(dest_key, 0, self.service_gid)
        return dest_cert.as_posix(), dest_key.as_posix()

    def _resolve_cert_pairs(self, sites, *, renew=False):
        pairs = {}
        for site_id, site in sites.items():
            mode = site['tls_mode']
            if mode in ('none', 'caddy_acme'):
                continue
            if mode == 'custom':
                pairs[site_id] = self._stage_cert_files(site_id, site['cert_path'], site['key_path'])
                continue
            try:
                src_cert, src_key = self.acme.ensure_certificate(
                    'caddy-' + site_id,
                    site['domain'],
                    tls_mode=mode,
                    email=site.get('email', ''),
                    dns_provider=site.get('dns_provider') or 'cloudflare',
                    dns_api_token=site.get('dns_api_token', ''),
                    dns_zone_id=site.get('dns_zone_id', ''),
                    credential_id=site.get('credential_id', ''),
                    propagation_seconds=site.get('propagation_seconds', 60),
                    renew=renew,
                )
            except AcmeError as exc:
                raise CaddyError(str(exc)) from None
            pairs[site_id] = self._stage_cert_files(site_id, src_cert, src_key)
        return pairs

    def render_all(self, sites, *, renew=False):
        admin_socket = (self.state_dir / 'admin.sock').as_posix() if os.name == 'posix' else ''
        storage_dir = (self.state_dir / 'storage').as_posix()
        # Check site specs and cross-service port conflicts before requesting ACME certificates.
        placeholder_pairs = {
            site_id: ((self.certs_dir / (site_id + '.crt')).as_posix(), (self.certs_dir / (site_id + '.key')).as_posix())
            for site_id, spec in sites.items()
            if spec.get('tls_mode', 'acme_http') not in ('none', 'caddy_acme')
        }
        preflight_caddyfile = render_caddyfile(
            list(sites.values()),
            cert_pairs=placeholder_pairs,
            admin_socket=admin_socket,
            storage_dir=storage_dir,
        )
        validate_port_allocation(SERVICE_CADDY, preflight_caddyfile, service_roots=self.service_roots)

        cert_pairs = self._resolve_cert_pairs(sites, renew=renew)
        caddyfile = render_caddyfile(
            list(sites.values()),
            cert_pairs=cert_pairs,
            admin_socket=admin_socket,
            storage_dir=storage_dir,
        )
        validate_port_allocation(SERVICE_CADDY, caddyfile, service_roots=self.service_roots)
        return caddyfile

    def allocate_port(self, *, host='127.0.0.1', probe_host=True):
        used = collect_active_bindings(self.service_roots)
        return allocate_loopback_port(used, host=host, transport='tcp', probe_host=probe_host)

    def apply_caddyfile(self, job_id, caddyfile, guard=lambda: None, *, remove=False):
        if self.runtime_engine is not None:
            action = 'caddy.remove' if remove else 'caddy.apply'
            payload = {} if remove else {'caddyfile': caddyfile}
            job = {
                'id': job_id,
                'type': action,
                'payload': payload,
                'deployment_revision': revision(job_id, action, payload),
            }
            return self.runtime_engine.apply(job, guard)
        _private_dir(self.state_dir)
        config_path = self.state_dir / 'Caddyfile'
        atomic_write_bytes(config_path, caddyfile.encode('utf-8'), mode=0o640)
        return config_path

    def upsert_site(self, spec, *, job_id='', renew=False, guard=lambda: None):
        normalized = validate_site_spec(spec)
        sites = self.load_sites()
        sites[normalized['site_id']] = normalized
        caddyfile = self.render_all(sites, renew=renew)
        if job_id and self.runtime_engine is not None:
            self.apply_caddyfile(job_id, caddyfile, guard=guard)
        self.save_sites(sites)
        return caddyfile

    def remove_site(self, site_id, *, job_id='', guard=lambda: None):
        sites = self.load_sites()
        sites.pop(site_id, None)
        caddyfile = self.render_all(sites) if sites else CADDY_PROFILE.empty_config
        if job_id and self.runtime_engine is not None:
            self.apply_caddyfile(job_id, caddyfile, guard=guard, remove=(not sites))
        self.save_sites(sites)
        for suffix in ('.crt', '.key'):
            (self.certs_dir / (site_id + suffix)).unlink(missing_ok=True)
        if self.certs_dir.exists():
            sync_directory(self.certs_dir)
        return caddyfile
