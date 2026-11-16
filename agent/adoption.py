"""Read-only discovery and secret-safe parsing of existing sing-box, xray, and caddy instances."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

from .runtime_engine import (
    SERVICE_CADDY,
    SERVICE_SINGBOX,
    extract_config_bindings,
    normalize_bind_host,
)

CORE_XRAY = 'xray'
SUPPORTED_CORES = (SERVICE_SINGBOX, CORE_XRAY, SERVICE_CADDY)
SINGBOX_ADOPTABLE_PROTOCOLS = frozenset(('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'anytls', 'tuic'))
XRAY_ADOPTABLE_PROTOCOLS = frozenset(('vless', 'vmess', 'trojan', 'shadowsocks'))
MAX_CONFIG_BYTES = 256 * 1024
MAX_SCANNED_SERVICES = 16
MAX_SCANNED_ENDPOINTS = 32
MANAGED_UNIT_PREFIX = 'proxyforge-'
MANAGED_PATH_PREFIXES = ('/opt/proxyforge-agent/', '/var/lib/proxyforge-runtime/')
SYSTEMD_SERVICE_RE = re.compile(r'[A-Za-z0-9_.@-]+\.service\Z')


class AdoptionError(ValueError):
    """Bounded, secret-free existing service inspection failure."""


def _clean_text(value, limit=128):
    if value is None:
        return ''
    cleaned = ''.join(ch for ch in str(value) if ord(ch) >= 32 and ord(ch) != 127)
    return cleaned[:limit]


def _file_sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_jsonc(raw_bytes):
    """Parse JSON or JSONC while rejecting comments-unclosed or duplicate object keys."""
    try:
        text = raw_bytes.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise AdoptionError('Configuration is not valid UTF-8') from exc
    out = []
    i = 0
    quoted = False
    escaped = False
    length = len(text)
    while i < length:
        ch = text[i]
        if quoted:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                quoted = False
            i += 1
            continue
        if ch == '"':
            quoted = True
        elif text[i:i + 2] == '//':
            end = text.find('\n', i)
            i = length if end < 0 else end
            continue
        elif text[i:i + 2] == '/*':
            end = text.find('*/', i + 2)
            if end < 0:
                raise AdoptionError('Unclosed block comment in JSONC configuration')
            out.append(' ')
            i = end + 2
            continue
        out.append(ch)
        i += 1

    stripped = ''.join(out)
    final_chars = []
    quoted = False
    escaped = False
    for index, ch in enumerate(stripped):
        if not quoted and ch == ',':
            lookahead = index + 1
            while lookahead < len(stripped) and stripped[lookahead].isspace():
                lookahead += 1
            if lookahead < len(stripped) and stripped[lookahead] in '}]':
                continue
        final_chars.append(ch)
        if escaped:
            escaped = False
        elif quoted and ch == '\\':
            escaped = True
        elif ch == '"':
            quoted = not quoted

    def reject_duplicates(pairs):
        mapping = {}
        for key, value in pairs:
            if key in mapping:
                raise AdoptionError('Duplicate JSON key in existing configuration')
            mapping[key] = value
        return mapping

    try:
        return json.loads(''.join(final_chars), object_pairs_hook=reject_duplicates)
    except ValueError as exc:
        raise AdoptionError('Invalid JSON/JSONC configuration') from exc


def _read_bounded_file(path):
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise AdoptionError('Configuration path must be an accessible regular file')
    if target.stat().st_size > MAX_CONFIG_BYTES:
        raise AdoptionError('Configuration exceeds size limit')
    return target.read_bytes()


def derive_reality_public_key(private_key):
    """Derive X25519 Reality public key via stdin DER without putting keys into argv."""
    if not isinstance(private_key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', private_key):
        raise AdoptionError('Invalid X25519 private key format')
    raw_priv = base64.urlsafe_b64decode(private_key + '=')
    if len(raw_priv) != 32:
        raise AdoptionError('Invalid X25519 private key length')
    der = bytes.fromhex('302e020100300506032b656e04220420') + raw_priv
    try:
        proc = subprocess.run(
            ['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
            input=der,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdoptionError('Failed to derive X25519 public key') from exc
    prefix = bytes.fromhex('302a300506032b656e032100')
    if proc.returncode != 0 or len(proc.stdout) != len(prefix) + 32 or not proc.stdout.startswith(prefix):
        raise AdoptionError('OpenSSL returned invalid X25519 SPKI output')
    return base64.urlsafe_b64encode(proc.stdout[len(prefix):]).decode('ascii').rstrip('=')


def _core_from_name(name):
    lowered = Path(name).name.lower()
    if lowered in ('sing-box', 'singbox'):
        return SERVICE_SINGBOX
    if lowered.startswith('xray'):
        return CORE_XRAY
    if lowered == 'caddy':
        return SERVICE_CADDY
    return None


def _extract_config_paths_from_argv(core, arguments):
    configs = []
    index = 1
    while index < len(arguments):
        arg = arguments[index]
        if arg in ('-c', '--config') and index + 1 < len(arguments):
            configs.append(Path(arguments[index + 1]))
            index += 2
            continue
        for prefix in ('--config=', '-c='):
            if arg.startswith(prefix):
                configs.append(Path(arg[len(prefix):]))
                break
        if core == SERVICE_SINGBOX and arg in ('-C', '--config-directory') and index + 1 < len(arguments):
            directory = Path(arguments[index + 1])
            if directory.is_dir() and not directory.is_symlink():
                configs.extend(sorted(directory.glob('*.json')))
            index += 2
            continue
        index += 1
    return configs


def discover_processes(proc=Path('/proc')):
    """Scan /proc safely for unmanaged running sing-box, xray, and caddy instances."""
    found = []
    if not Path(proc).is_dir():
        return found
    for entry in sorted(Path(proc).iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 0):
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / 'comm').read_text(encoding='utf-8', errors='replace').strip()
            exe = os.readlink(entry / 'exe')
        except OSError:
            continue
        if exe.startswith(MANAGED_PATH_PREFIXES):
            continue
        core = _core_from_name(exe) or _core_from_name(comm)
        if core is None:
            continue
        service_name = ''
        try:
            cgroup = (entry / 'cgroup').read_text(encoding='utf-8', errors='replace')
            for line in cgroup.splitlines():
                for part in line.split('/'):
                    if part.endswith('.service'):
                        service_name = part
        except OSError:
            pass
        if service_name.startswith(MANAGED_UNIT_PREFIX):
            continue
        try:
            raw_cmd = (entry / 'cmdline').read_bytes()
            arguments = [item.decode('utf-8', errors='replace') for item in raw_cmd.split(b'\0') if item]
        except OSError:
            arguments = []
        configs = _extract_config_paths_from_argv(core, arguments)
        if not configs and core == SERVICE_CADDY:
            default_caddy = Path('/etc/caddy/Caddyfile')
            if default_caddy.is_file() and not default_caddy.is_symlink():
                configs = [default_caddy]
        found.append({
            'core': core,
            'pid': int(entry.name),
            'executable': _clean_text(exe, 128),
            'service_name': _clean_text(service_name, 128),
            'configs': [str(p) for p in configs],
        })
        if len(found) >= MAX_SCANNED_SERVICES:
            break
    return found


def _source_key(core, config_sha, listen, port, protocol):
    material = f'{core}:{config_sha}:{listen}:{port}:{protocol}'.encode('utf-8')
    return 'adopt-' + hashlib.sha256(material).hexdigest()[:16]


def _make_endpoint(core, service_name, config_path, config_sha, *, tag, protocol, listen, listen_port, tls_mode, sni, network, ws_path, adoptable):
    norm_listen = normalize_bind_host(listen or '::')
    proto = _clean_text(protocol.lower(), 32)
    return {
        'source_key': _source_key(core, config_sha, norm_listen, int(listen_port), proto),
        'core': core,
        'service_name': _clean_text(service_name, 128),
        'config_path': _clean_text(config_path, 128),
        'config_sha256': config_sha,
        'tag': _clean_text(tag, 64),
        'protocol': proto,
        'listen': norm_listen,
        'listen_port': int(listen_port),
        'tls_mode': tls_mode,
        'sni': _clean_text(sni, 128),
        'network': _clean_text(network or 'tcp', 32),
        'ws_path': _clean_text(ws_path, 128),
        'adoptable': bool(adoptable),
    }


def _parse_singbox_config(config, config_path, config_sha, service_name):
    if not isinstance(config, dict):
        return []
    endpoints = []
    for index, inbound in enumerate(config.get('inbounds') or []):
        if not isinstance(inbound, dict):
            continue
        proto = str(inbound.get('type') or '').lower()
        port = inbound.get('listen_port')
        if type(port) is not int or not 1 <= port <= 65535 or not proto:
            continue
        tls = inbound.get('tls') if isinstance(inbound.get('tls'), dict) else {}
        reality = tls.get('reality') if isinstance(tls.get('reality'), dict) else {}
        if tls.get('enabled') and reality.get('enabled'):
            tls_mode = 'reality'
        elif tls.get('enabled'):
            tls_mode = 'tls'
        else:
            tls_mode = 'none'
        transport = inbound.get('transport') if isinstance(inbound.get('transport'), dict) else {}
        network = str(transport.get('type') or inbound.get('network') or 'tcp').lower()
        ws_path = str(transport.get('path') or '') if network == 'ws' else ''
        endpoints.append(_make_endpoint(
            SERVICE_SINGBOX,
            service_name,
            config_path,
            config_sha,
            tag=inbound.get('tag') or f'{proto}-{index + 1}',
            protocol=proto,
            listen=inbound.get('listen') or '::',
            listen_port=port,
            tls_mode=tls_mode,
            sni=tls.get('server_name') or '',
            network=network,
            ws_path=ws_path,
            adoptable=(proto in SINGBOX_ADOPTABLE_PROTOCOLS),
        ))
    return endpoints


def _parse_xray_config(config, config_path, config_sha, service_name):
    if not isinstance(config, dict):
        return []
    endpoints = []
    for index, inbound in enumerate(config.get('inbounds') or []):
        if not isinstance(inbound, dict):
            continue
        proto = str(inbound.get('protocol') or '').lower()
        port = inbound.get('port')
        if type(port) is not int or not 1 <= port <= 65535 or not proto:
            continue
        stream = inbound.get('streamSettings') if isinstance(inbound.get('streamSettings'), dict) else {}
        security = str(stream.get('security') or 'none').lower()
        if security == 'reality':
            tls_mode = 'reality'
            reality = stream.get('realitySettings') if isinstance(stream.get('realitySettings'), dict) else {}
            names = reality.get('serverNames') or []
            sni = names[0] if isinstance(names, list) and names else ''
        elif security in ('tls', 'xtls'):
            tls_mode = 'tls'
            tls_obj = stream.get('tlsSettings') if isinstance(stream.get('tlsSettings'), dict) else {}
            sni = tls_obj.get('serverName') or ''
        else:
            tls_mode = 'none'
            sni = ''
        network = str(stream.get('network') or 'tcp').lower()
        ws_path = ''
        if network == 'ws' and isinstance(stream.get('wsSettings'), dict):
            ws_path = str(stream['wsSettings'].get('path') or '')
        elif network == 'xhttp' and isinstance(stream.get('xhttpSettings'), dict):
            ws_path = str(stream['xhttpSettings'].get('path') or '')
        endpoints.append(_make_endpoint(
            CORE_XRAY,
            service_name,
            config_path,
            config_sha,
            tag=inbound.get('tag') or f'{proto}-{index + 1}',
            protocol=proto,
            listen=inbound.get('listen') or '::',
            listen_port=port,
            tls_mode=tls_mode,
            sni=sni,
            network=network,
            ws_path=ws_path,
            adoptable=(proto in XRAY_ADOPTABLE_PROTOCOLS),
        ))
    return endpoints


def _parse_caddy_config(raw_bytes, config_path, config_sha, service_name):
    text = raw_bytes.decode('utf-8', errors='replace')
    bindings = extract_config_bindings(SERVICE_CADDY, text)
    endpoints = []
    # Also try extracting site domain headers for Caddyfile or Caddy JSON.
    domains = []
    try:
        parsed_json = json.loads(text)
    except ValueError:
        for line in text.splitlines():
            clean = line.split('#', 1)[0].strip()
            if clean.endswith('{') and not clean.startswith('{') and not clean.startswith(('handle', '@', 'log', 'tls', 'reverse_proxy')):
                token = clean[:-1].strip().split()[0].rstrip(',')
                host_part = token.split('://', 1)[-1].split(':', 1)[0]
                if host_part and not host_part.startswith('['):
                    domains.append(host_part)
    else:
        servers = ((parsed_json.get('apps') or {}).get('http') or {}).get('servers') or {}
        for server in servers.values():
            for route in server.get('routes') or []:
                for matcher in route.get('match') or []:
                    for host in matcher.get('host') or []:
                        domains.append(str(host))

    default_sni = domains[0] if domains else ''
    for index, binding in enumerate(bindings):
        sni = domains[index] if index < len(domains) else default_sni
        tls_mode = 'none' if binding.port == 80 else 'tls'
        endpoints.append(_make_endpoint(
            SERVICE_CADDY,
            service_name,
            config_path,
            config_sha,
            tag=f'caddy-{index + 1}',
            protocol='caddy-site',
            listen=binding.host,
            listen_port=binding.port,
            tls_mode=tls_mode,
            sni=sni,
            network='http',
            ws_path='',
            adoptable=True,
        ))
    return endpoints


def scan_host(*, proc=Path('/proc'), extra_configs=None):
    """Discover existing unmanaged sing-box, xray, and caddy services without exposing secrets."""
    services = []
    endpoints = []
    seen_configs = set()

    candidates = []
    for proc_info in discover_processes(proc=proc):
        for path in proc_info['configs']:
            candidates.append((proc_info['core'], path, proc_info['service_name'], proc_info['pid']))
    for item in extra_configs or ():
        candidates.append((
            item['core'],
            item['config_path'],
            item.get('service_name', ''),
            item.get('pid', 0),
        ))

    for core, config_path, service_name, pid in candidates:
        if core not in SUPPORTED_CORES:
            continue
        if len(services) >= MAX_SCANNED_SERVICES or len(endpoints) >= MAX_SCANNED_ENDPOINTS:
            break
        key = (core, str(config_path))
        if key in seen_configs:
            continue
        seen_configs.add(key)
        try:
            raw = _read_bounded_file(config_path)
            sha = _file_sha256(raw)
            if core == SERVICE_SINGBOX:
                parsed = _parse_singbox_config(parse_jsonc(raw), config_path, sha, service_name)
            elif core == CORE_XRAY:
                parsed = _parse_xray_config(parse_jsonc(raw), config_path, sha, service_name)
            else:
                parsed = _parse_caddy_config(raw, config_path, sha, service_name)
        except AdoptionError:
            continue
        services.append({
            'core': core,
            'pid': int(pid or 0),
            'service_name': _clean_text(service_name, 128),
            'config_path': _clean_text(config_path, 128),
            'config_sha256': sha,
        })
        for ep in parsed:
            if len(endpoints) >= MAX_SCANNED_ENDPOINTS:
                break
            endpoints.append(ep)

    return {
        'scanned_at': int(time.time()),
        'services': services,
        'endpoints': endpoints,
    }


def valid_adopt_output(output):
    """Validate bounded, secret-free structure of adopt_scan results."""
    if not isinstance(output, dict) or set(output) != {'scanned_at', 'services', 'endpoints'}:
        return False
    if type(output['scanned_at']) is not int or output['scanned_at'] < 0:
        return False
    services, endpoints = output['services'], output['endpoints']
    if (not isinstance(services, list) or len(services) > MAX_SCANNED_SERVICES or
            not isinstance(endpoints, list) or len(endpoints) > MAX_SCANNED_ENDPOINTS):
        return False
    service_keys = {'core', 'pid', 'service_name', 'config_path', 'config_sha256'}
    for item in services:
        if (not isinstance(item, dict) or set(item) != service_keys or
                item['core'] not in SUPPORTED_CORES or type(item['pid']) is not int or item['pid'] < 0 or
                not isinstance(item['service_name'], str) or len(item['service_name']) > 128 or
                not isinstance(item['config_path'], str) or len(item['config_path']) > 128 or
                not isinstance(item['config_sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', item['config_sha256'])):
            return False
    endpoint_keys = {
        'source_key', 'core', 'service_name', 'config_path', 'config_sha256',
        'tag', 'protocol', 'listen', 'listen_port', 'tls_mode', 'sni', 'network', 'ws_path', 'adoptable',
    }
    for ep in endpoints:
        if (not isinstance(ep, dict) or set(ep) != endpoint_keys or
                not isinstance(ep['source_key'], str) or not re.fullmatch(r'adopt-[a-f0-9]{16}', ep['source_key']) or
                ep['core'] not in SUPPORTED_CORES or
                type(ep['listen_port']) is not int or not 1 <= ep['listen_port'] <= 65535 or
                ep['tls_mode'] not in ('none', 'tls', 'reality') or
                not isinstance(ep['adoptable'], bool)):
            return False
        for str_key in ('service_name', 'config_path', 'tag', 'protocol', 'listen', 'sni', 'network', 'ws_path'):
            val = ep[str_key]
            if not isinstance(val, str) or len(val) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in val):
                return False
    return True


def inspect_systemd_unit(service, *, runner=None):
    """Safely inspect an existing systemd unit without exposing secrets in its config."""
    if not isinstance(service, str) or len(service) > 100 or not SYSTEMD_SERVICE_RE.fullmatch(service):
        raise AdoptionError('Invalid systemd unit name')
    if service in ('ssh.service', 'sshd.service') or service.startswith(('systemd-', MANAGED_UNIT_PREFIX)):
        raise AdoptionError('Refusing system-critical or already-managed systemd unit')
    properties = ('FragmentPath', 'DropInPaths', 'ExecStart', 'ExecStartPre', 'ExecStartPost',
                  'MainPID', 'ActiveState', 'UnitFileState')
    args = ['systemctl', 'show', service, '--no-pager', *[x for k in properties for x in ('-p', k)]]
    if runner is None:
        raw = subprocess.run(args, capture_output=True, text=True, timeout=10, check=True).stdout
    else:
        raw = runner(args)
    fields = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    if fields.get('ExecStartPre') or fields.get('ExecStartPost'):
        raise AdoptionError('Systemd unit has lifecycle hooks; refusing automatic adoption')
    match = re.fullmatch(r'\{ path=([^;]+?) ; argv\[\]=(.*?) ; ignore_errors=.*? \}', fields.get('ExecStart', ''))
    if not match:
        raise AdoptionError('Unrecognized systemd ExecStart layout')
    executable = Path(match[1])
    arguments = shlex.split(match[2])
    core = _core_from_name(executable.name)
    if core is None or not arguments:
        raise AdoptionError('Systemd unit is not a supported sing-box, xray, or caddy core')
    configs = _extract_config_paths_from_argv(core, arguments)
    if len(configs) != 1:
        raise AdoptionError('Systemd unit must reference exactly one configuration file')
    return {
        'service': service,
        'core': core,
        'executable': str(executable),
        'config_path': str(configs[0]),
        'active': fields.get('ActiveState') == 'active',
        'enabled': fields.get('UnitFileState', ''),
    }
