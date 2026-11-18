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
        except OSError:
            continue
        try:
            exe = os.readlink(entry / 'exe')
        except OSError:
            exe = ''
        if exe and exe.startswith(MANAGED_PATH_PREFIXES):
            continue
        try:
            raw_cmd = (entry / 'cmdline').read_bytes()
            arguments = [item.decode('utf-8', errors='replace') for item in raw_cmd.split(b'\0') if item]
        except OSError:
            arguments = []
        if arguments and arguments[0].startswith(MANAGED_PATH_PREFIXES):
            continue
        core = _core_from_name(exe) or _core_from_name(comm) or (_core_from_name(arguments[0]) if arguments else None)
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
        configs = _extract_config_paths_from_argv(core, arguments)
        if not configs:
            default_candidates = {
                SERVICE_SINGBOX: (Path('/etc/sing-box/config.json'), Path('/usr/local/etc/sing-box/config.json'), Path('/etc/s-box/sb.json')),
                CORE_XRAY: (Path('/usr/local/etc/xray/config.json'), Path('/etc/xray/config.json')),
                SERVICE_CADDY: (Path('/etc/caddy/Caddyfile'),),
            }.get(core, ())
            for default_cfg in default_candidates:
                try:
                    if default_cfg.is_file() and not default_cfg.is_symlink():
                        configs.append(default_cfg)
                        break
                except OSError:
                    continue
        found.append({
            'core': core,
            'pid': int(entry.name),
            'executable': _clean_text(exe or (arguments[0] if arguments else comm), 128),
            'service_name': _clean_text(service_name, 128),
            'configs': [str(p) for p in configs],
        })
        if len(found) >= MAX_SCANNED_SERVICES:
            break
    return found


def _discover_well_known_configs():
    """Discover standard host config files when processes omit -c or /proc is restricted."""
    discovered = []
    patterns = (
        (SERVICE_SINGBOX, Path('/etc/sing-box'), '*.json', 'sing-box.service'),
        (SERVICE_SINGBOX, Path('/usr/local/etc/sing-box'), '*.json', 'sing-box.service'),
        (CORE_XRAY, Path('/usr/local/etc/xray'), '*.json', 'xray.service'),
        (CORE_XRAY, Path('/etc/xray'), '*.json', 'xray.service'),
    )
    for core, directory, pattern, default_unit in patterns:
        try:
            if directory.is_dir() and not directory.is_symlink():
                for cfg in sorted(directory.glob(pattern))[:8]:
                    if cfg.is_file() and not cfg.is_symlink():
                        discovered.append((core, str(cfg), default_unit, 0))
        except OSError:
            continue
    nodepilot_nodes = Path('/etc/nodepilot/nodes')
    try:
        if nodepilot_nodes.is_dir() and not nodepilot_nodes.is_symlink():
            for node_dir in sorted(nodepilot_nodes.iterdir())[:16]:
                cfg = node_dir / 'current' / 'config.json'
                if cfg.is_file() and not cfg.is_symlink():
                    discovered.append((SERVICE_SINGBOX, str(cfg), f'nodepilot-{node_dir.name}.service', 0))
    except OSError:
        pass
    return discovered


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


_LAST_EXTRACTED_CREDENTIALS = {}


def last_extracted_credentials():
    return dict(_LAST_EXTRACTED_CREDENTIALS)


def clear_extracted_credentials():
    _LAST_EXTRACTED_CREDENTIALS.clear()


def scan_host(*, proc=Path('/proc'), extra_configs=None, privileged=True):
    """Discover existing unmanaged sing-box, xray, and caddy services without exposing secrets."""
    global _LAST_EXTRACTED_CREDENTIALS
    if privileged and extra_configs is None and Path(proc) == Path('/proc'):
        from .runtime_client import scan_host_privileged
        priv = scan_host_privileged()
        if isinstance(priv, dict) and valid_adopt_output(priv.get('output')):
            if isinstance(priv.get('credentials'), dict):
                _LAST_EXTRACTED_CREDENTIALS = dict(priv['credentials'])
            return priv['output']
    _LAST_EXTRACTED_CREDENTIALS = {}
    services = []
    endpoints = []
    seen_configs = set()

    candidates = []
    for proc_info in discover_processes(proc=proc):
        for path in proc_info['configs']:
            candidates.append((proc_info['core'], path, proc_info['service_name'], proc_info['pid']))
    if extra_configs is None and Path(proc) == Path('/proc'):
        candidates.extend(_discover_well_known_configs())
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
                cfg_obj = parse_jsonc(raw)
                parsed = _parse_singbox_config(cfg_obj, config_path, sha, service_name)
                _LAST_EXTRACTED_CREDENTIALS.update(_extract_singbox_inbound_credentials(cfg_obj, sha))
            elif core == CORE_XRAY:
                cfg_obj = parse_jsonc(raw)
                parsed = _parse_xray_config(cfg_obj, config_path, sha, service_name)
                _LAST_EXTRACTED_CREDENTIALS.update(_extract_xray_inbound_credentials(cfg_obj, sha))
            else:
                parsed = _parse_caddy_config(raw, config_path, sha, service_name)
        except (AdoptionError, OSError):
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


def _extract_singbox_inbound_credentials(config, config_sha, *, pubkey_deriver=None):
    if pubkey_deriver is None:
        pubkey_deriver = derive_reality_public_key
    if not isinstance(config, dict):
        return {}
    extracted = {}
    for inbound in config.get('inbounds') or []:
        if not isinstance(inbound, dict):
            continue
        proto = _clean_text(str(inbound.get('type') or '').lower(), 32)
        port = inbound.get('listen_port')
        if type(port) is not int or not 1 <= port <= 65535 or not proto:
            continue
        norm_listen = normalize_bind_host(inbound.get('listen') or '::')
        skey = _source_key(SERVICE_SINGBOX, config_sha, norm_listen, int(port), proto)
        users = inbound.get('users') if isinstance(inbound.get('users'), list) else []
        first_user = users[0] if users and isinstance(users[0], dict) else {}
        tls = inbound.get('tls') if isinstance(inbound.get('tls'), dict) else {}
        reality = tls.get('reality') if isinstance(tls.get('reality'), dict) else {}
        handshake = reality.get('handshake') if isinstance(reality.get('handshake'), dict) else {}
        cred = {'protocol': proto, 'listen_port': int(port)}
        if first_user.get('uuid') or inbound.get('uuid'):
            cred['uuid'] = str(first_user.get('uuid') or inbound.get('uuid'))
        if first_user.get('flow'):
            cred['flow'] = str(first_user['flow'])
        if first_user.get('password') or inbound.get('password'):
            cred['password'] = str(first_user.get('password') or inbound.get('password'))
        if inbound.get('method'):
            cred['method'] = str(inbound['method'])
        if tls.get('server_name'):
            cred['sni'] = str(tls['server_name'])
        if tls.get('certificate_path'):
            cred['certificate_path'] = str(tls['certificate_path'])
        if tls.get('key_path'):
            cred['key_path'] = str(tls['key_path'])
        if reality.get('enabled') and reality.get('private_key'):
            priv = str(reality['private_key'])
            cred['reality_private_key'] = priv
            try:
                cred['reality_public_key'] = pubkey_deriver(priv)
            except AdoptionError:
                if reality.get('public_key'):
                    cred['reality_public_key'] = str(reality['public_key'])
            raw_sids = reality.get('short_id')
            if isinstance(raw_sids, list):
                sids = [str(x) for x in raw_sids if isinstance(x, str)]
            elif isinstance(raw_sids, str):
                sids = [raw_sids]
            else:
                sids = []
            cred['reality_short_ids'] = sids
            cred['reality_short_id'] = sids[0] if sids else ''
            if handshake.get('server'):
                cred['handshake_server'] = str(handshake['server'])
                cred['handshake_port'] = int(handshake.get('server_port') or 443)
        obfs = inbound.get('obfs') if isinstance(inbound.get('obfs'), dict) else {}
        if obfs.get('type') == 'salamander' and obfs.get('password'):
            cred['obfs'] = 'salamander'
            cred['obfs_password'] = str(obfs['password'])
        for bw in ('up_mbps', 'down_mbps'):
            if type(inbound.get(bw)) is int and inbound[bw] > 0:
                cred[bw] = inbound[bw]
        extracted[skey] = {
            'credentials': cred,
            'inbound': _normalize_singbox_inbound(inbound, skey),
        }
    return extracted


def _normalize_singbox_inbound(inbound, source_key):
    if not isinstance(inbound, dict):
        return {}
    proto = _clean_text(str(inbound.get('type') or '').lower(), 32)
    port = inbound.get('listen_port')
    if proto not in SINGBOX_ADOPTABLE_PROTOCOLS or type(port) is not int or not 1 <= port <= 65535:
        return {}
    allowed_keys = (
        'type', 'listen', 'listen_port', 'users', 'method', 'password',
        'tls', 'transport', 'obfs', 'up_mbps', 'down_mbps',
        'padding_scheme', 'multiplex', 'sniff', 'sniff_override_destination',
        'domain_strategy',
    )
    cleaned = {k: inbound[k] for k in allowed_keys if k in inbound}
    cleaned['type'] = proto
    cleaned['listen'] = normalize_bind_host(cleaned.get('listen') or '::')
    cleaned['listen_port'] = int(port)
    cleaned['tag'] = f'adopted-{source_key}'
    return cleaned


def _xray_inbound_to_singbox(inbound, cred, source_key):
    proto = str(cred.get('protocol') or '').lower()
    port = cred.get('listen_port')
    if proto not in XRAY_ADOPTABLE_PROTOCOLS or type(port) is not int or not 1 <= port <= 65535:
        return {}
    stream = inbound.get('streamSettings') if isinstance(inbound.get('streamSettings'), dict) else {}
    network = str(stream.get('network') or 'tcp').lower()
    security = str(stream.get('security') or 'none').lower()
    out = {
        'type': proto,
        'tag': f'adopted-{source_key}',
        'listen': normalize_bind_host(inbound.get('listen') or '::'),
        'listen_port': int(port),
    }
    if proto == 'vless':
        if not cred.get('uuid'):
            return {}
        user = {'uuid': cred['uuid']}
        if cred.get('flow'):
            user['flow'] = cred['flow']
        out['users'] = [user]
    elif proto == 'trojan':
        if not cred.get('password'):
            return {}
        out['users'] = [{'name': 'adopted', 'password': cred['password']}]
    elif proto == 'shadowsocks':
        if not cred.get('password') or not cred.get('method'):
            return {}
        out['method'] = cred['method']
        out['password'] = cred['password']
    else:
        return {}

    if security == 'reality':
        priv = cred.get('reality_private_key')
        if not priv:
            return {}
        out['tls'] = {
            'enabled': True,
            'server_name': cred.get('sni') or cred.get('handshake_server') or '',
            'reality': {
                'enabled': True,
                'handshake': {
                    'server': cred.get('handshake_server') or cred.get('sni') or 'www.amazon.com',
                    'server_port': int(cred.get('handshake_port') or 443),
                },
                'private_key': priv,
                'short_id': cred.get('reality_short_ids') or [''],
            },
        }
    elif security == 'tls':
        tls_obj = stream.get('tlsSettings') if isinstance(stream.get('tlsSettings'), dict) else {}
        certs = tls_obj.get('certificates') if isinstance(tls_obj.get('certificates'), list) else []
        first_cert = certs[0] if certs and isinstance(certs[0], dict) else {}
        cert_path = first_cert.get('certificateFile') or ''
        key_path = first_cert.get('keyFile') or ''
        if not cert_path or not key_path:
            return {}
        tls_cfg = {
            'enabled': True,
            'certificate_path': str(cert_path),
            'key_path': str(key_path),
        }
        if cred.get('sni'):
            tls_cfg['server_name'] = cred['sni']
        out['tls'] = tls_cfg
    elif security != 'none':
        return {}

    if network == 'ws':
        ws_obj = stream.get('wsSettings') if isinstance(stream.get('wsSettings'), dict) else {}
        out['transport'] = {'type': 'ws', 'path': str(ws_obj.get('path') or '/')}
    elif network == 'grpc':
        grpc_obj = stream.get('grpcSettings') if isinstance(stream.get('grpcSettings'), dict) else {}
        out['transport'] = {'type': 'grpc', 'service_name': str(grpc_obj.get('serviceName') or '')}
    elif network != 'tcp':
        return {}
    return out


def _extract_xray_inbound_credentials(config, config_sha, *, pubkey_deriver=None):
    if pubkey_deriver is None:
        pubkey_deriver = derive_reality_public_key
    if not isinstance(config, dict):
        return {}
    extracted = {}
    for inbound in config.get('inbounds') or []:
        if not isinstance(inbound, dict):
            continue
        proto = _clean_text(str(inbound.get('protocol') or '').lower(), 32)
        port = inbound.get('port')
        if type(port) is not int or not 1 <= port <= 65535 or not proto:
            continue
        norm_listen = normalize_bind_host(inbound.get('listen') or '::')
        skey = _source_key(CORE_XRAY, config_sha, norm_listen, int(port), proto)
        settings = inbound.get('streamSettings') if isinstance(inbound.get('streamSettings'), dict) else {}
        in_settings = inbound.get('settings') if isinstance(inbound.get('settings'), dict) else {}
        clients = in_settings.get('clients') if isinstance(in_settings.get('clients'), list) else []
        first_client = clients[0] if clients and isinstance(clients[0], dict) else {}
        cred = {'protocol': proto, 'listen_port': int(port)}
        if first_client.get('id'):
            cred['uuid'] = str(first_client['id'])
        if first_client.get('flow'):
            cred['flow'] = str(first_client['flow'])
        if first_client.get('password') or in_settings.get('password'):
            cred['password'] = str(first_client.get('password') or in_settings.get('password'))
        if in_settings.get('method'):
            cred['method'] = str(in_settings['method'])
        security = str(settings.get('security') or 'none').lower()
        if security == 'reality':
            reality = settings.get('realitySettings') if isinstance(settings.get('realitySettings'), dict) else {}
            names = reality.get('serverNames') or []
            if isinstance(names, list) and names:
                cred['sni'] = str(names[0])
            priv = str(reality.get('privateKey') or '')
            if priv:
                cred['reality_private_key'] = priv
                try:
                    cred['reality_public_key'] = pubkey_deriver(priv)
                except AdoptionError:
                    pass
            sids = reality.get('shortIds')
            if isinstance(sids, list):
                clean_sids = [str(x) for x in sids if isinstance(x, str)]
                cred['reality_short_ids'] = clean_sids
                cred['reality_short_id'] = clean_sids[0] if clean_sids else ''
            dest = str(reality.get('dest') or reality.get('target') or '')
            if ':' in dest:
                h_part, p_part = dest.rsplit(':', 1)
                cred['handshake_server'] = h_part.strip('[]')
                if p_part.isdigit():
                    cred['handshake_port'] = int(p_part)
        extracted[skey] = {
            'credentials': cred,
            'inbound': _xray_inbound_to_singbox(inbound, cred, skey),
        }
    return extracted


def extract_host_credentials(*, proc=Path('/proc'), extra_configs=None, pubkey_deriver=None):
    """Extract endpoint credentials for adoption takeover (never written to unencrypted job journals)."""
    if pubkey_deriver is None:
        pubkey_deriver = derive_reality_public_key
    credentials = {}
    seen_configs = set()
    candidates = []
    for proc_info in discover_processes(proc=proc):
        for path in proc_info['configs']:
            candidates.append((proc_info['core'], path))
    if extra_configs is None and Path(proc) == Path('/proc'):
        for core, path, _, _ in _discover_well_known_configs():
            candidates.append((core, path))
    for item in extra_configs or ():
        candidates.append((item['core'], item['config_path']))

    for core, config_path in candidates:
        if core not in (SERVICE_SINGBOX, CORE_XRAY):
            continue
        key = (core, str(config_path))
        if key in seen_configs:
            continue
        seen_configs.add(key)
        try:
            raw = _read_bounded_file(config_path)
            sha = _file_sha256(raw)
            parsed = parse_jsonc(raw)
            if core == SERVICE_SINGBOX:
                credentials.update(_extract_singbox_inbound_credentials(parsed, sha, pubkey_deriver=pubkey_deriver))
            else:
                credentials.update(_extract_xray_inbound_credentials(parsed, sha, pubkey_deriver=pubkey_deriver))
        except (AdoptionError, OSError):
            continue
    return credentials


def adopt_host_service(service_name, config_path, source_key, *,
                       backup_root=Path('/var/lib/proxyforge-runtime/adoptions'), runner=None):
    """Back up an existing host proxy service and stop/disable it before proxyforge-singbox takeover."""
    if not isinstance(source_key, str) or not re.fullmatch(r'adopt-[a-f0-9]{16}', source_key):
        raise AdoptionError('Invalid adoption source_key')
    if service_name:
        if not isinstance(service_name, str) or len(service_name) > 100 or not SYSTEMD_SERVICE_RE.fullmatch(service_name):
            raise AdoptionError('Invalid systemd unit name')
        if service_name in ('ssh.service', 'sshd.service') or service_name.startswith(('systemd-', MANAGED_UNIT_PREFIX)):
            raise AdoptionError('Refusing system-critical or already-managed systemd unit')
    target_dir = Path(backup_root) / source_key
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    meta = {
        'source_key': source_key,
        'service_name': service_name or '',
        'config_path': str(config_path or ''),
        'adopted_at': int(time.time()),
    }
    if config_path:
        try:
            raw_cfg = _read_bounded_file(config_path)
            bak_file = target_dir / 'config.bak'
            bak_file.write_bytes(raw_cfg)
            if os.name == 'posix':
                os.chmod(bak_file, 0o600)
            meta['config_sha256'] = _file_sha256(raw_cfg)
        except (AdoptionError, OSError):
            pass
    meta_file = target_dir / 'adoption.json'
    meta_file.write_text(json.dumps(meta, sort_keys=True), encoding='utf-8')
    if os.name == 'posix':
        os.chmod(meta_file, 0o600)
    if service_name:
        cmd = ['/usr/bin/systemctl', 'disable', '--now', service_name]
        if runner is not None:
            runner(cmd)
        elif os.name == 'posix':
            subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    return meta


def return_host_service(source_key, *, service_name='',
                        backup_root=Path('/var/lib/proxyforge-runtime/adoptions'), runner=None):
    """Restore and restart a previously adopted host systemd unit."""
    if not isinstance(source_key, str) or not re.fullmatch(r'adopt-[a-f0-9]{16}', source_key):
        raise AdoptionError('Invalid adoption source_key')
    target_dir = Path(backup_root) / source_key
    meta_file = target_dir / 'adoption.json'
    unit = service_name
    if meta_file.is_file():
        try:
            saved = json.loads(meta_file.read_text(encoding='utf-8'))
            unit = saved.get('service_name') or unit
        except (OSError, ValueError):
            pass
    if unit:
        if not isinstance(unit, str) or len(unit) > 100 or not SYSTEMD_SERVICE_RE.fullmatch(unit):
            raise AdoptionError('Invalid systemd unit name')
        if unit in ('ssh.service', 'sshd.service') or unit.startswith(('systemd-', MANAGED_UNIT_PREFIX)):
            raise AdoptionError('Refusing system-critical or already-managed systemd unit')
        cmd = ['/usr/bin/systemctl', 'enable', '--now', unit]
        if runner is not None:
            runner(cmd)
        elif os.name == 'posix':
            subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    if meta_file.is_file():
        meta_file.unlink(missing_ok=True)
    return {'source_key': source_key, 'service_name': unit or '', 'returned': True}


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
