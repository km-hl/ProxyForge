"""Isolated Caddy camouflage and TLS reverse-proxy configuration manager."""
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
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
CAMOUFLAGE_MODES = ('template', 'proxy', 'static_dir')
CAMOUFLAGE_TEMPLATES = ('corporate', 'blog', 'status', 'nginx')
_FORBIDDEN_STATIC_PREFIXES = (
    '/etc', '/proc', '/sys', '/dev', '/run', '/root', '/boot',
    '/bin', '/sbin', '/usr', '/lib', '/lib64',
    '/var/lib/proxyforge-runtime', '/opt/proxyforge-agent',
)


class CaddyError(ValueError):
    """Sanitized Caddy configuration or management error."""


def _assert_safe_token(value, label):
    if not isinstance(value, str) or not value or UNSAFE_CADDYFILE_CHARS.search(value) or any(ch.isspace() for ch in value):
        raise CaddyError(f'Unsafe Caddyfile token for {label}')
    return value


def validate_camouflage_dir(path):
    """Validate optional custom static site root directory against traversal and system paths."""
    if not path:
        return ''
    if not isinstance(path, str) or len(path) > 200 or UNSAFE_CADDYFILE_CHARS.search(path) or any(ch.isspace() for ch in path):
        raise CaddyError('Invalid camouflage static directory')
    if not path.startswith('/'):
        raise CaddyError('Camouflage static directory must be an absolute POSIX path')
    parsed = PurePosixPath(path)
    if '..' in parsed.parts or len(parsed.parts) < 2:
        raise CaddyError('Camouflage static directory cannot use root or parent traversal')
    normalized = parsed.as_posix().rstrip('/')
    if not normalized or normalized == '/':
        raise CaddyError('Camouflage static directory cannot be root')
    for prefix in _FORBIDDEN_STATIC_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + '/'):
            raise CaddyError('Camouflage static directory points to a restricted system path')
    return normalized


def render_camouflage_html(template_name='corporate', domain=''):
    """Generate a realistic, self-contained HTML5 camouflage page with zero external dependencies."""
    tpl = template_name if template_name in CAMOUFLAGE_TEMPLATES else 'corporate'
    safe_host = html.escape(str(domain or 'cloud-edge.local'))
    brand = html.escape((str(domain or 'Northstar Cloud').split('.')[0] or 'Northstar').replace('-', ' ').title())
    if tpl == 'nginx':
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Welcome</title><style>body{width:35em;margin:4em auto;font-family:system-ui,sans-serif;color:#222;line-height:1.6}</style>'
            '</head><body><h1>Welcome</h1><p>If you see this page, the web server is successfully installed and working.</p>'
            f'<p><small>{safe_host}</small></p></body></html>\n'
        )
    if tpl == 'status':
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{brand} Status</title>'
            '<style>body{margin:0;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,sans-serif}'
            '.wrap{max-width:760px;margin:48px auto;padding:0 20px}.banner{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46;padding:16px 20px;border-radius:10px;font-weight:600}'
            '.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;margin-top:20px;overflow:hidden}'
            '.row{display:flex;justify-content:space-between;padding:14px 20px;border-bottom:1px solid #f1f5f9}.row:last-child{border-bottom:0}'
            '.ok{color:#059669;font-weight:600;font-size:14px}footer{margin-top:28px;color:#64748b;font-size:13px}</style></head><body>'
            f'<div class="wrap"><h1>{brand} System Status</h1>'
            '<div class="banner">All Systems Operational</div>'
            '<div class="card">'
            '<div class="row"><span>Edge Routing &amp; CDN</span><span class="ok">Operational</span></div>'
            '<div class="row"><span>Public API Gateway</span><span class="ok">Operational</span></div>'
            '<div class="row"><span>Object Storage &amp; Sync</span><span class="ok">Operational</span></div>'
            '<div class="row"><span>TLS Certificate Automation</span><span class="ok">Operational</span></div>'
            '</div>'
            f'<footer>Service host: {safe_host} &middot; 99.98% 30-day uptime</footer></div></body></html>\n'
        )
    if tpl == 'blog':
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{brand} Engineering Notes</title>'
            '<style>body{margin:0;background:#fff;color:#1e293b;font-family:Georgia,serif;line-height:1.75}'
            'header{border-bottom:1px solid #e2e8f0;padding:24px 20px}main{max-width:720px;margin:32px auto;padding:0 20px}'
            'h1{margin:0;font-family:system-ui,sans-serif;font-size:26px}article{margin-bottom:28px;padding-bottom:24px;border-bottom:1px solid #f1f5f9}'
            'h2{font-family:system-ui,sans-serif;font-size:20px;margin:0 0 6px}time{color:#64748b;font-size:13px;font-family:system-ui,sans-serif}'
            'footer{max-width:720px;margin:32px auto;padding:0 20px;color:#64748b;font-size:13px;font-family:system-ui,sans-serif}</style></head><body>'
            f'<header><div style="max-width:720px;margin:0 auto"><h1>{brand} Notes</h1></div></header>'
            '<main>'
            '<article><time>November 2026</time><h2>Tuning Linux TCP BBR and Socket Buffers for High-BDP Links</h2>'
            '<p>A practical look at pacing, congestion window growth, and clean sysctl defaults across modern Debian kernels.</p></article>'
            '<article><time>October 2026</time><h2>Zero-Downtime Configuration Reloads with Atomic Symlinks</h2>'
            '<p>How staging configuration revisions into immutable directories prevents half-written state during service restarts.</p></article>'
            '<article><time>September 2026</time><h2>Notes on HTTP/2 Multiplexing and TLS 1.3 Handshake Latency</h2>'
            '<p>Measuring connection reuse and session resumption across regional points of presence.</p></article>'
            '</main>'
            f'<footer>&copy; 2026 {safe_host}</footer></body></html>\n'
        )
    # Default: 'corporate'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{brand} &mdash; Cloud Infrastructure &amp; Telemetry</title>'
        '<style>body{margin:0;background:#0f172a;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif}'
        'nav{max-width:960px;margin:0 auto;padding:20px;display:flex;justify-content:space-between;align-items:center}'
        '.hero{max-width:960px;margin:48px auto;padding:0 20px}.hero h1{font-size:36px;margin:0 0 12px;color:#f8fafc}'
        '.hero p{max-width:620px;color:#94a3b8;font-size:17px;line-height:1.65}'
        '.grid{max-width:960px;margin:36px auto;padding:0 20px;display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}'
        '.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px}.card h3{margin:0 0 8px;color:#f8fafc;font-size:17px}'
        '.card p{margin:0;color:#94a3b8;font-size:14px;line-height:1.6}footer{max-width:960px;margin:48px auto 32px;padding:0 20px;color:#64748b;font-size:13px}</style></head><body>'
        f'<nav><strong>{brand}</strong><span style="color:#94a3b8;font-size:14px">{safe_host}</span></nav>'
        '<section class="hero"><h1>Reliable Edge Compute &amp; Observability</h1>'
        '<p>Automated TLS lifecycle management, low-latency regional routing, and deterministic configuration delivery for distributed engineering teams.</p></section>'
        '<section class="grid">'
        '<div class="card"><h3>Deterministic Deployments</h3><p>Immutable release artifacts with automated health verification and instant rollback.</p></div>'
        '<div class="card"><h3>Edge Telemetry</h3><p>Lightweight host metrics and encrypted transport diagnostics with minimal overhead.</p></div>'
        '<div class="card"><h3>Zero-Trust Isolation</h3><p>Least-privilege service boundaries and strict certificate automation out of the box.</p></div>'
        '</section>'
        f'<footer>&copy; 2026 {brand} Infrastructure &middot; {safe_host}</footer></body></html>\n'
    )


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
    camouflage_dir = validate_camouflage_dir(spec.get('camouflage_dir', ''))
    raw_mode = spec.get('camouflage_mode', '')
    if raw_mode:
        if raw_mode not in CAMOUFLAGE_MODES:
            raise CaddyError('Unsupported camouflage mode')
        camouflage_mode = raw_mode
    elif camouflage_dir:
        camouflage_mode = 'static_dir'
    elif camouflage:
        camouflage_mode = 'proxy'
    else:
        camouflage_mode = 'template'
    if camouflage_mode == 'proxy' and not camouflage:
        raise CaddyError('Proxy camouflage mode requires camouflage_url')
    if camouflage_mode == 'static_dir' and not camouflage_dir:
        raise CaddyError('Static directory camouflage mode requires camouflage_dir')
    camouflage_template = spec.get('camouflage_template', 'corporate') or 'corporate'
    if camouflage_template not in CAMOUFLAGE_TEMPLATES:
        raise CaddyError('Unsupported camouflage template')
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
        'camouflage_mode': camouflage_mode,
        'camouflage_template': camouflage_template,
        'camouflage_url': camouflage if camouflage_mode == 'proxy' else '',
        'camouflage_dir': camouflage_dir if camouflage_mode == 'static_dir' else '',
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


def _format_site_block(site, cert_pair=None, *, static_root=''):
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

    camouflage_mode = site.get('camouflage_mode') or (
        'static_dir' if site.get('camouflage_dir') else ('proxy' if site.get('camouflage_url') else 'template')
    )
    camouflage_url = validate_camouflage_url(site.get('camouflage_url', ''))
    camouflage_dir = validate_camouflage_dir(site.get('camouflage_dir', ''))
    if camouflage_mode == 'proxy' and camouflage_url:
        upstream_host = urllib.parse.urlsplit(camouflage_url).netloc
        camouflage_lines = [
            f'reverse_proxy {camouflage_url} {{',
            f'\theader_up Host {upstream_host}',
            '}',
        ]
    elif camouflage_mode == 'static_dir' and camouflage_dir:
        safe_dir = _assert_safe_token(camouflage_dir, 'camouflage_dir')
        camouflage_lines = [
            f'root * {safe_dir}',
            'file_server',
        ]
    elif static_root:
        safe_root = _assert_safe_token(str(static_root), 'static_root')
        camouflage_lines = [
            f'root * {safe_root}',
            'file_server',
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
    static_roots=None,
    admin_socket='',
    storage_dir='',
    email='',
    log_level='WARN',
):
    """Render a deterministic, injection-safe Caddyfile for all managed camouflage sites."""
    cert_pairs = cert_pairs or {}
    static_roots = static_roots or {}
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
        blocks.append(_format_site_block(site, pair, static_root=static_roots.get(site['site_id'], '')))
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

    @property
    def www_dir(self):
        return self.state_dir.parent / 'www'

    def _stage_template_sites(self, sites):
        roots = {}
        for site_id, site in sites.items():
            if site.get('camouflage_mode', 'template') != 'template':
                continue
            www_root = _private_dir(self.www_dir)
            if os.name == 'posix':
                www_root.chmod(0o750)
                if self.service_gid is not None:
                    os.chown(www_root, 0, self.service_gid)
            site_dir = _private_dir(www_root / site_id)
            if os.name == 'posix':
                site_dir.chmod(0o750)
                if self.service_gid is not None:
                    os.chown(site_dir, 0, self.service_gid)
            index_file = site_dir / 'index.html'
            content = render_camouflage_html(site.get('camouflage_template', 'corporate'), domain=site.get('domain', ''))
            atomic_write_bytes(index_file, content.encode('utf-8'), mode=0o640)
            if os.name == 'posix' and self.service_gid is not None:
                os.chown(index_file, 0, self.service_gid)
            roots[site_id] = site_dir.as_posix()
        return roots

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
        placeholder_roots = {
            site_id: (self.www_dir / site_id).as_posix()
            for site_id, spec in sites.items()
            if spec.get('camouflage_mode', 'template') == 'template'
        }
        preflight_caddyfile = render_caddyfile(
            list(sites.values()),
            cert_pairs=placeholder_pairs,
            static_roots=placeholder_roots,
            admin_socket=admin_socket,
            storage_dir=storage_dir,
        )
        validate_port_allocation(SERVICE_CADDY, preflight_caddyfile, service_roots=self.service_roots)

        cert_pairs = self._resolve_cert_pairs(sites, renew=renew)
        static_roots = self._stage_template_sites(sites)
        caddyfile = render_caddyfile(
            list(sites.values()),
            cert_pairs=cert_pairs,
            static_roots=static_roots,
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
        site_www = self.www_dir / site_id
        if site_www.exists() and not site_www.is_symlink():
            shutil.rmtree(site_www, ignore_errors=True)
        if self.certs_dir.exists():
            sync_directory(self.certs_dir)
        return caddyfile
