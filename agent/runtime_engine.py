"""Root-owned immutable releases, port conflict validation, and recoverable activation."""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time
from urllib.parse import urlsplit

from .runtime_download import download_binary
from .runtime_spec import (
    CADDY_CONFIG_ACTIONS,
    CADDY_RELEASE,
    CONFIG_ACTIONS,
    GOST_RELEASE,
    RELEASE,
    SERVICE_CADDY,
    SERVICE_GOST,
    SERVICE_SINGBOX,
    job_service,
    revision,
    validate_runtime_job,
)
from .deployment_spec import runtime_config, spec_hash
from .landing_spec import (
    build_caddy_site_for_landing,
    collect_spec_user_marks,
    deployment_tls_plan,
    runtime_config as landing_config,
    shared_listener_guests,
)
from .nft_users import NftUserCounters
from .chain_spec import CHAIN_ACTIONS, runtime_config as chain_config
from .gost_manager import GOST_CONFIG_ACTIONS, render_gost_config

UNIT = 'proxyforge-singbox.service'
EMPTY_CONFIG = {'log': {'level': 'warn'}, 'inbounds': [], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
STARTUP_HEALTH_TIMEOUT = 20.0
HEALTH_POLL_INTERVAL = 0.5
HEALTH_SAMPLES = 3
UDP_ONLY_INBOUNDS = frozenset(('hysteria2', 'tuic', 'wireguard'))
DUAL_TRANSPORT_INBOUNDS = frozenset(('shadowsocks', 'snell', 'socks'))


def _probe_timeout(maximum, deadline):
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Runtime readiness deadline exceeded')
    return min(maximum, remaining)


class RuntimeCancelled(Exception):
    pass


class RollbackFailed(Exception):
    pass


@dataclass(frozen=True)
class RuntimeProfile:
    service: str
    unit: str
    account: str
    binary_name: str
    config_filename: str = 'config.json'
    config_format: str = 'json'
    check_args: tuple = ('check', '-c')
    version_args: tuple = ('version',)
    version_prefix: str = ''
    empty_config: object = None
    release: object = None
    install_action: str = ''
    start_action: str = ''
    stop_action: str = ''
    rollback_action: str = ''

    def check_command(self, release_dir):
        if not self.check_args:
            return None
        return [str(release_dir / self.binary_name), *self.check_args, str(release_dir / self.config_filename)]

    def version_command(self, release_dir):
        return [str(release_dir / self.binary_name), *self.version_args]

    def version_matches(self, stdout, expected_version):
        first = stdout.splitlines()[0].strip() if stdout else ''
        if self.version_prefix:
            return first == self.version_prefix + expected_version
        return bool(re.search(r'(?<![\d.])' + re.escape(expected_version) + r'(?![\d.])', first))


SINGBOX_PROFILE = RuntimeProfile(
    service=SERVICE_SINGBOX,
    unit=UNIT,
    account='proxyforge-singbox',
    binary_name='sing-box',
    config_filename='config.json',
    config_format='json',
    check_args=('check', '-c'),
    version_args=('version',),
    version_prefix='sing-box version ',
    empty_config=EMPTY_CONFIG,
    release=RELEASE,
    install_action='singbox.install',
    start_action='singbox.start',
    stop_action='singbox.stop',
    rollback_action='singbox.rollback',
)

CADDY_PROFILE = RuntimeProfile(
    service=SERVICE_CADDY,
    unit='proxyforge-caddy.service',
    account='proxyforge-caddy',
    binary_name='caddy',
    config_filename='Caddyfile',
    config_format='text',
    check_args=('validate', '--adapter', 'caddyfile', '--config'),
    version_args=('version',),
    version_prefix='',
    empty_config='{\n\tauto_https off\n}\n',
    release=CADDY_RELEASE,
    install_action='caddy.install',
    start_action='caddy.start',
    stop_action='caddy.stop',
    rollback_action='caddy.rollback',
)

GOST_PROFILE = RuntimeProfile(
    service=SERVICE_GOST,
    unit='proxyforge-gost.service',
    account='proxyforge-gost',
    binary_name='gost',
    config_filename='config.json',
    config_format='json',
    check_args=(),
    version_args=('-V',),
    version_prefix='',
    empty_config={'services': []},
    release=GOST_RELEASE,
    install_action='gost.install',
    start_action='gost.start',
    stop_action='gost.stop',
    rollback_action='gost.rollback',
)

RUNTIME_PROFILES = {
    SINGBOX_PROFILE.service: SINGBOX_PROFILE,
    CADDY_PROFILE.service: CADDY_PROFILE,
    GOST_PROFILE.service: GOST_PROFILE,
}


@dataclass(frozen=True)
class PortBinding:
    service: str
    transport: str
    host: str
    port: int


def normalize_bind_host(value):
    text = str(value or '').strip()
    for prefix in ('tcp4/', 'tcp6/', 'udp4/', 'udp6/'):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if text in ('', '*'):
        return '::'
    if text.startswith('[') and text.endswith(']'):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


def _is_ip_literal(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def addresses_conflict(host_a, host_b):
    a = normalize_bind_host(host_a)
    b = normalize_bind_host(host_b)
    if a == b:
        return True
    if '::' in (a, b):
        return True
    if '0.0.0.0' in (a, b):
        other = b if a == '0.0.0.0' else a
        if not _is_ip_literal(other):
            return True
        return ipaddress.ip_address(other).version == 4
    return False


def bindings_conflict(first, second):
    return (first.transport == second.transport and
            first.port == second.port and
            addresses_conflict(first.host, second.host))


def _parse_addr_host_port(raw, default_port=None):
    text = str(raw or '').strip()
    for prefix in ('tcp4/', 'tcp6/', 'udp4/', 'udp6/'):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if '://' in text:
        parsed = urlsplit(text)
        host = normalize_bind_host(parsed.hostname or '::')
        if parsed.port is not None:
            return host, parsed.port
        if parsed.scheme == 'http':
            return host, 80
        if parsed.scheme == 'https':
            return host, 443
        return host, default_port
    if text.startswith('['):
        end = text.find(']')
        if end != -1:
            host = normalize_bind_host(text[1:end])
            rest = text[end + 1:]
            if rest.startswith(':') and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, default_port
    if text.startswith(':') and text[1:].isdigit():
        return '::', int(text[1:])
    if text.count(':') == 1:
        host_part, port_part = text.rsplit(':', 1)
        if port_part.isdigit():
            return normalize_bind_host(host_part), int(port_part)
    if text.isdigit():
        return '::', int(text)
    if default_port is not None and text:
        return normalize_bind_host(text), default_port
    return None, None


def _singbox_transports(inbound):
    kind = str(inbound.get('type') or '').lower()
    network = inbound.get('network')
    if isinstance(network, str) and network.lower() in ('tcp', 'udp'):
        return (network.lower(),)
    if isinstance(network, (list, tuple)):
        items = tuple(item.lower() for item in network if isinstance(item, str) and item.lower() in ('tcp', 'udp'))
        if items:
            return items
    if kind in UDP_ONLY_INBOUNDS:
        return ('udp',)
    if kind in DUAL_TRANSPORT_INBOUNDS:
        return ('tcp', 'udp')
    return ('tcp',)


def _extract_singbox_bindings(service, config):
    bindings = []
    for section, default_transports in (('inbounds', None), ('endpoints', ('udp',))):
        entries = config.get(section) or []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or 'listen_port' not in entry:
                continue
            port = entry['listen_port']
            if type(port) is not int:
                raise ValueError('Invalid listen_port')
            host = normalize_bind_host(entry.get('listen') or '::')
            transports = default_transports or _singbox_transports(entry)
            for transport in transports:
                bindings.append(PortBinding(service, transport, host, port))
    return bindings


def _extract_caddy_json_bindings(service, config):
    bindings = []
    servers = ((config.get('apps') or {}).get('http') or {}).get('servers') or {}
    if not isinstance(servers, dict):
        return bindings
    for server in servers.values():
        if not isinstance(server, dict):
            continue
        protocols = server.get('protocols')
        transports = ('tcp', 'udp') if isinstance(protocols, list) and 'h3' in protocols else ('tcp',)
        for addr in server.get('listen') or []:
            host, port = _parse_addr_host_port(addr)
            if port is None:
                continue
            for transport in transports:
                bindings.append(PortBinding(service, transport, host, port))
    return bindings


def _extract_caddyfile_bindings(service, text):
    bindings = []
    seen = set()
    depth = 0
    current_addrs = []
    bind_hosts = []
    for raw_line in text.splitlines():
        line = raw_line.split('#', 1)[0].strip()
        if not line:
            continue
        if depth == 0 and '{' in line:
            header = line.split('{', 1)[0].strip()
            if header:
                current_addrs = [token.rstrip(',') for token in header.split() if token.rstrip(',')]
            else:
                current_addrs = []
            bind_hosts = []
        elif depth == 1 and current_addrs and line.startswith('bind '):
            bind_hosts.extend(normalize_bind_host(tok) for tok in line.split()[1:])
        depth += line.count('{') - line.count('}')
        if depth <= 0:
            depth = 0
            if current_addrs:
                hosts_override = bind_hosts or [None]
                for addr in current_addrs:
                    host, port = _parse_addr_host_port(addr, default_port=443)
                    if port is None:
                        continue
                    for override in hosts_override:
                        effective_host = override if override is not None else (host if _is_ip_literal(host) or host in ('::', '0.0.0.0') else '::')
                        key = ('tcp', effective_host, port)
                        if key not in seen:
                            seen.add(key)
                            bindings.append(PortBinding(service, 'tcp', effective_host, port))
                current_addrs = []
                bind_hosts = []
    return bindings


GOST_UDP_TYPES = frozenset(('udp', 'rudp', 'quic', 'kcp'))


def _extract_gost_bindings(service, config):
    bindings = []
    for item in config.get('services') or []:
        if not isinstance(item, dict) or not item.get('addr'):
            continue
        host, port = _parse_addr_host_port(item.get('addr'))
        if port is None:
            continue
        listener_type = str(((item.get('listener') or {}).get('type')) or '').lower()
        handler_type = str(((item.get('handler') or {}).get('type')) or '').lower()
        transport = 'udp' if (listener_type in GOST_UDP_TYPES or handler_type in GOST_UDP_TYPES) else 'tcp'
        bindings.append(PortBinding(service, transport, host, port))
    metrics = config.get('metrics')
    if isinstance(metrics, dict) and metrics.get('addr'):
        m_host, m_port = _parse_addr_host_port(metrics.get('addr'))
        if m_port is not None:
            bindings.append(PortBinding(service, 'tcp', m_host, m_port))
    return bindings


_CONFIG_BINDING_EXTRACTORS = {
    SERVICE_SINGBOX: _extract_singbox_bindings,
    SERVICE_CADDY: _extract_caddy_json_bindings,
    SERVICE_GOST: _extract_gost_bindings,
}


def extract_config_bindings(service, config_data):
    """Extract normalized listening PortBindings for sing-box, caddy, or go-gost configs."""
    if isinstance(config_data, str):
        stripped = config_data.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
        except ValueError:
            if service == SERVICE_CADDY:
                return _extract_caddyfile_bindings(service, stripped)
            raise ValueError('Invalid runtime JSON configuration') from None
        config_data = parsed
    if not isinstance(config_data, dict):
        raise ValueError('Invalid runtime configuration payload')
    extractor = _CONFIG_BINDING_EXTRACTORS.get(service)
    if extractor is None:
        raise ValueError('Unsupported managed service')
    return extractor(service, config_data)


def collect_active_bindings(service_roots, *, exclude_service=None):
    bindings = []
    if not service_roots:
        return bindings
    for service, root in service_roots.items():
        if service == exclude_service:
            continue
        profile = RUNTIME_PROFILES.get(service)
        if not profile:
            continue
        config_path = Path(root) / 'current' / profile.config_filename
        if not config_path.is_file():
            continue
        text = config_path.read_text(encoding='utf-8')
        bindings.extend(extract_config_bindings(service, text))
    return bindings


def _probe_host_socket(binding):
    family = socket.AF_INET6 if ':' in binding.host else socket.AF_INET
    socktype = socket.SOCK_DGRAM if binding.transport == 'udp' else socket.SOCK_STREAM
    address = (binding.host, binding.port)
    with socket.socket(family, socktype) as probe:
        if binding.transport == 'tcp':
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6 and binding.host == '::':
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        probe.bind(address)


def validate_port_allocation(service, candidate_config, *, service_roots=None, probe_sockets=False):
    """Validate port bounds, intra-config uniqueness, and cross-service port conflicts."""
    candidate = extract_config_bindings(service, candidate_config)
    for index, binding in enumerate(candidate):
        if type(binding.port) is not int or not 1 <= binding.port <= 65535:
            raise ValueError('Listening port out of range')
        for previous in candidate[:index]:
            if bindings_conflict(binding, previous):
                raise ValueError('Duplicate listening port inside %s configuration: %s:%d/%s' % (
                    service, binding.host, binding.port, binding.transport))
    sibling_bindings = collect_active_bindings(service_roots, exclude_service=service)
    for binding in candidate:
        for other in sibling_bindings:
            if bindings_conflict(binding, other):
                raise ValueError('Port %d/%s on %s conflicts with %s' % (
                    binding.port, binding.transport, binding.host, other.service))
    if probe_sockets:
        own_active = set()
        if service_roots and service in service_roots:
            own_active = set(collect_active_bindings({service: service_roots[service]}))
        for binding in candidate:
            if binding in own_active:
                continue
            try:
                _probe_host_socket(binding)
            except OSError:
                raise ValueError('Listening port %s:%d/%s is already in use' % (
                    binding.host, binding.port, binding.transport)) from None
    return candidate


def allocate_loopback_port(used_bindings, *, start=18000, end=28000, host='127.0.0.1',
                         transport='tcp', probe_host=True):
    """Allocate a deterministic free loopback port not occupied by any managed service."""
    if start > end or not 1 <= start <= 65535 or not 1 <= end <= 65535:
        raise ValueError('Invalid port allocation range')
    normalized_host = normalize_bind_host(host)
    for port in range(start, end + 1):
        candidate = PortBinding('_allocated', transport, normalized_host, port)
        if any(bindings_conflict(candidate, existing) for existing in used_bindings):
            continue
        if probe_host:
            try:
                _probe_host_socket(candidate)
            except OSError:
                continue
        return port
    raise ValueError('No free loopback port available in range')


def sync_directory(path):
    if os.name != 'posix':
        return
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_text(path, text, mode=0o600):
    """Atomically replace a file with UTF-8 text and fsync parent directory."""
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    try:
        fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value, mode=0o600):
    write_text(path, json.dumps(value), mode)


def _probe_tcp_targets(profile, config_text):
    if profile.service == SERVICE_SINGBOX:
        config = json.loads(config_text)
        targets = []
        for inbound in config.get('inbounds', []):
            if str(inbound.get('type') or '').lower() in UDP_ONLY_INBOUNDS:
                continue
            if 'listen_port' in inbound:
                host = normalize_bind_host(inbound.get('listen') or '::')
                probe = '127.0.0.1' if host in ('127.0.0.1', '0.0.0.0') else '::1'
                targets.append((probe, inbound['listen_port']))
        return targets
    targets = []
    for binding in extract_config_bindings(profile.service, config_text):
        if binding.transport != 'tcp':
            continue
        probe = '127.0.0.1' if binding.host in ('127.0.0.1', '0.0.0.0') else '::1'
        targets.append((probe, binding.port))
    return targets


class SystemBackend:
    profile = SINGBOX_PROFILE
    uid = None
    gid = None

    def __init__(self, profile=SINGBOX_PROFILE):
        import pwd
        self.profile = profile
        account = pwd.getpwnam(profile.account)
        self.uid, self.gid = account.pw_uid, account.pw_gid

    def check(self, release):
        # Candidate config is readable by the isolated runtime user, never world-readable.
        config_path = release / self.profile.config_filename
        if self.gid is not None:
            os.chown(release, 0, self.gid)
            os.chown(config_path, 0, self.gid)
        release.chmod(0o755)
        config_path.chmod(0o640)
        run_kwargs = {'timeout': 20}
        version_kwargs = {'capture_output': True, 'text': True, 'timeout': 5}
        if self.profile.service == SERVICE_CADDY:
            state_dir = str(release.parent.parent / 'state')
            caddy_env = {**os.environ, 'HOME': state_dir, 'XDG_DATA_HOME': state_dir, 'XDG_CONFIG_HOME': state_dir}
            run_kwargs['env'] = caddy_env
            version_kwargs['env'] = caddy_env
        if self.uid is not None and self.gid is not None:
            identity = {'user': self.uid, 'group': self.gid, 'extra_groups': []}
            run_kwargs.update(identity)
            version_kwargs.update(identity)
        check_cmd = self.profile.check_command(release)
        if check_cmd is not None:
            result = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **run_kwargs)
            if result.returncode:
                raise ValueError('Runtime configuration check failed')
        result = subprocess.run(self.profile.version_command(release), **version_kwargs)
        expected = json.loads((release / 'release.json').read_text())['version']
        if result.returncode or not self.profile.version_matches(result.stdout, expected):
            raise ValueError('Runtime version check failed')

    def active(self, *, deadline=None):
        return subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', self.profile.unit],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=_probe_timeout(5, deadline)).returncode == 0

    def matches(self, release, *, deadline=None):
        if not self.active(deadline=deadline):
            return False
        value = subprocess.run(['/usr/bin/systemctl', 'show', '--property=MainPID', '--value', self.profile.unit],
                               capture_output=True, text=True, timeout=_probe_timeout(5, deadline))
        pid = value.stdout.strip()
        if value.returncode or not pid.isdigit() or int(pid) <= 1:
            return False
        try:
            if Path('/proc/' + pid + '/exe').resolve(strict=True) != (release / self.profile.binary_name).resolve(strict=True):
                return False
            config_text = (release / self.profile.config_filename).read_text()
            for host, port in _probe_tcp_targets(self.profile, config_text):
                with socket.create_connection((host, port),
                                              timeout=_probe_timeout(1, deadline)):
                    pass
            return True
        except (OSError, ValueError, KeyError):
            return False

    def stop(self):
        subprocess.run(['/usr/bin/systemctl', 'stop', self.profile.unit], check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.active():
            raise ValueError('Runtime did not stop')

    def activate(self, release):
        if self.matches(release):
            return
        # A never-started unit may have no loaded failure state yet.
        subprocess.run(['/usr/bin/systemctl', 'reset-failed', self.profile.unit], check=False, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['/usr/bin/systemctl', 'restart', self.profile.unit], check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Type=simple can report started before exec and listener readiness.
        # Allow one bounded initial grace, then keep the existing stable checks.
        deadline = time.monotonic() + STARTUP_HEALTH_TIMEOUT
        healthy = 0
        while healthy < HEALTH_SAMPLES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Runtime failed health verification')
            time.sleep(min(HEALTH_POLL_INTERVAL, remaining))
            try:
                matched = self.matches(release, deadline=deadline)
            except subprocess.TimeoutExpired:
                if healthy:
                    raise ValueError('Runtime failed health verification') from None
                continue
            except TimeoutError:
                raise ValueError('Runtime failed health verification') from None
            if time.monotonic() >= deadline or (healthy and not matched):
                raise ValueError('Runtime failed health verification')
            if matched:
                healthy += 1


class RuntimeEngine:
    def __init__(self, root, backend, arch, downloader=download_binary, *,
                 profile=SINGBOX_PROFILE, service_roots=None):
        self.root = Path(root)
        self.backend = backend
        self.arch = arch
        self.downloader = downloader
        self.profile = profile
        self.service_roots = service_roots
        (self.root / 'releases').mkdir(parents=True, exist_ok=True)

    def pointer(self, name):
        path = self.root / name
        if not path.is_symlink():
            if path.exists():
                raise ValueError('Managed pointer is not a symlink')
            return None
        target = os.readlink(path)
        if not re.fullmatch(r'releases/[a-f0-9]{32}', target):
            raise ValueError('Invalid managed release pointer')
        release = self.root / target
        if release.is_symlink() or not release.is_dir():
            raise ValueError('Invalid managed release')
        return target

    def set_pointer(self, name, target):
        path = self.root / name
        if target is None:
            path.unlink(missing_ok=True)
        else:
            temporary = self.root / ('.' + name + '.' + secrets.token_hex(8))
            try:
                os.symlink(target, temporary)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        sync_directory(self.root)

    def receipts(self):
        path = self.root / 'receipts.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def status(self):
        current = self.pointer('current')
        if not current:
            return {'installed': False, 'running': False, 'version': '', 'status': 'not_installed'}
        running = self.backend.matches(self.root / current)
        version = json.loads((self.root / current / 'release.json').read_text())['version']
        return {'installed': True, 'running': running, 'version': version, 'status': 'running' if running else 'stopped'}

    def finish(self, transaction, guard=lambda: None):
        output = self.status()
        if not output['installed'] or output['running'] != transaction['running']:
            raise ValueError('Runtime lost health before commit')
        # Health reads may also wait: fence immediately before commit mutations.
        guard()
        self.set_pointer('previous', transaction['old'] if transaction['new'] != transaction['old'] else transaction['previous'])
        result = {'status': 'success', 'output': output, 'error': None}
        receipts = self.receipts()
        receipts[transaction['job']['id']] = {'revision': transaction['job']['deployment_revision'], 'result': result}
        write_json(self.root / 'receipts.json', dict(list(receipts.items())[-128:]))
        (self.root / 'transaction.json').unlink()
        sync_directory(self.root)
        self.prune()
        return result

    def rollback(self, transaction):
        try:
            self.set_pointer('current', transaction['old'])
            self.set_pointer('previous', transaction['previous'])
            if transaction['was_running'] and transaction['old']:
                self.backend.activate(self.root / transaction['old'])
            else:
                self.backend.stop()
            (self.root / 'transaction.json').unlink()
            sync_directory(self.root)
            self.prune()
        except Exception:
            # Preserve the intent and releases for local repair; no further mutation until recovery succeeds.
            raise RollbackFailed() from None

    def recover(self):
        path = self.root / 'transaction.json'
        if not path.exists():
            return
        transaction = json.loads(path.read_text())
        validate_runtime_job(transaction['job'])
        receipts = self.receipts()
        if transaction['job']['id'] in receipts:
            path.unlink()
            sync_directory(self.root)
            return
        reached = self.pointer('current') == transaction['new'] and (
            self.backend.matches(self.root / transaction['new']) if transaction['running'] else not self.backend.active())
        if reached:
            self.finish(transaction)
        else:
            self.rollback(transaction)

    def prune(self):
        keep = {self.pointer('current'), self.pointer('previous')}
        for path in (self.root / 'releases').iterdir():
            if re.fullmatch(r'[a-f0-9]{32}', path.name) and 'releases/' + path.name not in keep:
                if path.is_symlink() or not path.is_dir():
                    raise ValueError('Invalid managed release directory')
                shutil.rmtree(path)

    def _read_config(self, release_rel):
        path = self.root / release_rel / self.profile.config_filename
        text = path.read_text(encoding='utf-8')
        return json.loads(text) if self.profile.config_format == 'json' else text

    def _write_config(self, candidate, config):
        target = candidate / self.profile.config_filename
        if self.profile.config_format == 'json':
            write_json(target, config)
        else:
            write_text(target, config)

    def _render_job_config(self, action, job, source, render_overrides=None):
        if self.profile.service == SERVICE_CADDY:
            if action in ('caddy.remove', 'caddy.stop', 'deployment.remove', 'landing.remove'):
                return self.profile.empty_config
            if action == 'caddy.apply' and isinstance(job.get('payload'), dict) and 'caddyfile' in job['payload']:
                return job['payload']['caddyfile']
        if action == 'deployment.apply':
            return runtime_config(job['deployment'])
        if action == 'landing.apply':
            return landing_config(job['deployment'], **(render_overrides or {}))
        if action in CHAIN_ACTIONS:
            return chain_config(job['deployment'])
        if action == 'gost.apply':
            return render_gost_config(job['deployment'], **(render_overrides or {}))
        if action in ('deployment.remove', 'landing.remove', 'gost.remove'):
            return self.profile.empty_config
        return self._read_config(source) if source else self.profile.empty_config

    def apply(self, job, guard=lambda: None, *, render_overrides=None):
        validate_runtime_job(job)
        self.recover()
        receipt = self.receipts().get(job['id'])
        if receipt:
            if receipt['revision'] != job['deployment_revision']:
                raise ValueError('Job identity changed')
            return receipt['result']
        guard()
        current, previous = self.pointer('current'), self.pointer('previous')
        was_running = self.backend.active()
        action = job['type']
        if action not in (self.profile.install_action, *CONFIG_ACTIONS, *CADDY_CONFIG_ACTIONS) and not current:
            raise ValueError('Runtime is not installed')
        if action == self.profile.rollback_action and not previous:
            raise ValueError('No previous release')
        new = current
        running = action != self.profile.stop_action
        if action == self.profile.rollback_action:
            running = was_running
        already_running = bool(current and self.backend.matches(self.root / current))
        pinned = self.profile.release or RELEASE
        same_version = bool(current and json.loads((self.root / current / 'release.json').read_text())['version'] == pinned['version'])
        unchanged = already_running and (action == self.profile.start_action or (action == self.profile.install_action and same_version))
        source = previous if action == self.profile.rollback_action else current
        rendered_config = None
        if action in (*CONFIG_ACTIONS, *CADDY_CONFIG_ACTIONS) and current and not unchanged:
            rendered_config = self._render_job_config(action, job, source, render_overrides=render_overrides)
            if already_running:
                current_config_path = self.root / current / self.profile.config_filename
                if current_config_path.is_file():
                    expected_text = json.dumps(rendered_config) if self.profile.config_format == 'json' else rendered_config
                    try:
                        if current_config_path.read_text(encoding='utf-8') == expected_text:
                            unchanged = True
                    except OSError:
                        pass
        if unchanged:
            self.backend.check(self.root / current)
        if action != self.profile.stop_action and not unchanged:
            new = 'releases/' + job['id']
            candidate = self.root / new
            if candidate.exists():
                # An interrupted pre-activation staging directory is never reused.
                if candidate.is_symlink() or new in (current, previous):
                    raise ValueError('Release identity collision')
                shutil.rmtree(candidate)
            candidate.mkdir(mode=0o750)
            try:
                if action == self.profile.install_action or (action in (*CONFIG_ACTIONS, *CADDY_CONFIG_ACTIONS) and not current):
                    self.downloader(candidate, self.arch, guard)
                    release_info = {'version': pinned['version']}
                else:
                    shutil.copy2(self.root / source / self.profile.binary_name, candidate / self.profile.binary_name)
                    release_info = json.loads((self.root / source / 'release.json').read_text())
                config = rendered_config if rendered_config is not None else self._render_job_config(
                    action, job, source, render_overrides=render_overrides
                )
                validate_port_allocation(self.profile.service, config, service_roots=self.service_roots)
                self._write_config(candidate, config)
                write_json(candidate / 'release.json', release_info, 0o644)
                self.backend.check(candidate)
                # Copied binaries also need durability before publishing the generation.
                with (candidate / self.profile.binary_name).open('rb') as binary:
                    os.fsync(binary.fileno())
                sync_directory(candidate)
                sync_directory(candidate.parent)
                guard()
            except BaseException:
                shutil.rmtree(candidate)
                raise
        transaction = {'job': {key: job[key] for key in ('id', 'type', 'payload', 'deployment_revision')},
                       'old': current, 'previous': previous, 'new': new, 'was_running': was_running, 'running': running}
        if action in CONFIG_ACTIONS:
            transaction['job']['deployment'] = job['deployment']
        write_json(self.root / 'transaction.json', transaction)
        try:
            guard()
            self.set_pointer('current', new)
            if running:
                if not self.backend.matches(self.root / new):
                    self.backend.activate(self.root / new)
            else:
                self.backend.stop()
            return self.finish(transaction, guard)
        except Exception:
            # If the receipt is durable, commit has happened; do not undo a successful action.
            if job['id'] not in self.receipts():
                self.rollback(transaction)
            raise


class RuntimeCoordinator:
    """Coordinate multiple isolated RuntimeEngine instances with shared port collision guards."""

    def __init__(self, engines, *, acme_manager=None, caddy_manager=None, nft_user_counters=None):
        self.engines = dict(engines)
        self.service_roots = {service: engine.root for service, engine in self.engines.items()}
        for engine in self.engines.values():
            engine.service_roots = self.service_roots
        self._acme_manager = acme_manager
        self._caddy_manager = caddy_manager
        self._nft_user_counters = nft_user_counters

    def _get_nft_user_counters(self):
        if self._nft_user_counters is None:
            sb_root = self.service_roots.get(SERVICE_SINGBOX) or Path('/var/lib/proxyforge-runtime')
            self._nft_user_counters = NftUserCounters(sb_root)
        return self._nft_user_counters

    def _sync_nft_user_counters(self, mark_ids):
        try:
            self._get_nft_user_counters().sync(mark_ids)
        except Exception:
            pass

    def _get_acme_manager(self):
        if self._acme_manager is None:
            from .acme_manager import AcmeManager
            acme_root = (self.service_roots[SERVICE_SINGBOX] / 'acme') if SERVICE_SINGBOX in self.service_roots else None
            self._acme_manager = AcmeManager(acme_root or Path('/var/lib/proxyforge-runtime/acme'))
        return self._acme_manager

    def _get_caddy_manager(self):
        if self._caddy_manager is None:
            from .caddy_manager import CaddyManager
            caddy_engine = self.engines.get(SERVICE_CADDY)
            caddy_state = (caddy_engine.root / 'state') if caddy_engine else Path('/var/lib/proxyforge-runtime/services/caddy/state')
            gid = getattr(caddy_engine.backend, 'gid', None) if caddy_engine else None
            self._caddy_manager = CaddyManager(
                caddy_state,
                acme_manager=self._get_acme_manager(),
                runtime_engine=caddy_engine,
                service_roots=self.service_roots,
                service_gid=gid,
            )
        return self._caddy_manager

    def _stage_singbox_certs(self, src_cert, src_key, site_id='landing'):
        singbox_engine = self.engines[SERVICE_SINGBOX]
        cert_dir = singbox_engine.root / 'certs' / site_id
        cert_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        dest_cert = cert_dir / 'fullchain.pem'
        dest_key = cert_dir / 'privkey.pem'
        write_text(dest_cert, Path(src_cert).read_text(encoding='utf-8'), mode=0o640)
        write_text(dest_key, Path(src_key).read_text(encoding='utf-8'), mode=0o640)
        gid = getattr(singbox_engine.backend, 'gid', None)
        if os.name == 'posix' and gid is not None:
            os.chown(cert_dir.parent, 0, gid)
            os.chown(cert_dir, 0, gid)
            os.chown(dest_cert, 0, gid)
            os.chown(dest_key, 0, gid)
            cert_dir.parent.chmod(0o750)
            cert_dir.chmod(0o750)
        return str(dest_cert), str(dest_key)

    def _derived_caddy_job_id(self, job_id):
        return hashlib.sha256(('caddy:' + job_id).encode('utf-8')).hexdigest()[:32]

    def recover(self):
        for engine in self.engines.values():
            engine.recover()

    def status(self, service=SERVICE_SINGBOX):
        if service not in self.engines:
            raise ValueError('Unsupported managed service')
        return self.engines[service].status()

    def _prepare_node_tls_and_caddy(self, node_spec, site_id, job_id, guard):
        plan = deployment_tls_plan(node_spec, site_id=site_id)
        overrides = {}
        staged_caddy_site_id = None
        deferred_caddy = None
        caddy_enabled = SERVICE_CADDY in self.engines or self._caddy_manager is not None

        if plan['needs_cert'] and plan['caddy_role'] in ('', 'trojan_fallback'):
            acme_params = plan['acme']
            acme_kwargs = {k: v for k, v in acme_params.items() if k not in ('cert_name', 'domain')}
            src_cert, src_key = self._get_acme_manager().ensure_certificate(
                acme_params['cert_name'], acme_params['domain'], **acme_kwargs,
            )
            dest_cert, dest_key = self._stage_singbox_certs(src_cert, src_key, site_id=site_id)
            overrides['cert_path'] = dest_cert
            overrides['key_path'] = dest_key

        if plan['needs_caddy']:
            if plan['caddy_role'] == 'trojan_fallback' and not caddy_enabled:
                return overrides, None, None
            if not caddy_enabled:
                raise ValueError('Caddy runtime service is not enabled')
            caddy_manager = self._get_caddy_manager()
            loopback_port = self.allocate_port(probe_host=False)
            if plan['caddy_role'] in ('loopback_camouflage', 'trojan_fallback'):
                site = build_caddy_site_for_landing(node_spec, site_id=site_id, listen_port=loopback_port)
                caddy_manager.upsert_site(site, job_id=job_id, guard=guard)
                overrides['caddy_port'] = loopback_port
                staged_caddy_site_id = site_id
            elif plan['caddy_role'] == 'frontdoor_ws':
                site = build_caddy_site_for_landing(node_spec, site_id=site_id, backend_port=loopback_port)
                sites = caddy_manager.load_sites()
                sites[site['site_id']] = site
                caddyfile = caddy_manager.render_all(sites)
                overrides['backend_port'] = loopback_port
                deferred_caddy = (job_id, caddyfile, sites)
        return overrides, staged_caddy_site_id, deferred_caddy

    def _prune_landing_sites(self, active_site_ids, caddy_job_id, guard):
        """Best-effort removal of landing Caddy sites no longer owned by any listener host.

        Runs only after sing-box committed, so a failure here never rolls back the proxy; a
        stale loopback site is harmless and is retried on the next landing apply.
        """
        if SERVICE_CADDY not in self.engines and self._caddy_manager is None:
            return
        try:
            caddy_manager = self._get_caddy_manager()
            stale = [
                sid for sid in caddy_manager.load_sites()
                if (sid == 'landing' or sid.startswith('node-')) and sid not in active_site_ids
            ]
        except Exception:
            return
        for sid in stale:
            try:
                caddy_manager.remove_site(
                    sid, job_id=self._derived_caddy_job_id(caddy_job_id + ':prune:' + sid), guard=guard,
                )
            except RuntimeCancelled:
                raise
            except Exception:
                continue

    def _apply_landing_job(self, job, guard):
        from .adoption import adopt_host_service, return_host_service
        singbox_engine = self.engines[SERVICE_SINGBOX]
        caddy_job_id = self._derived_caddy_job_id(job['id'])
        if job['type'] == 'landing.remove':
            result = singbox_engine.apply(job, guard)
            if SERVICE_CADDY in self.engines or self._caddy_manager is not None:
                caddy_mgr = self._get_caddy_manager()
                for sid in list(caddy_mgr.load_sites()):
                    if sid == 'landing' or sid.startswith('node-'):
                        caddy_mgr.remove_site(sid, job_id=self._derived_caddy_job_id(caddy_job_id + ':' + sid), guard=guard)
            self._sync_nft_user_counters([])
            return result

        spec = job['deployment']
        for item in spec.get('disabled_adoptions') or []:
            if item.get('original_service'):
                adopt_host_service(
                    item['original_service'],
                    item.get('original_config_path', ''),
                    item['source_key'],
                )
        for item in spec.get('adopted_nodes') or []:
            if item.get('original_service'):
                try:
                    adopt_host_service(
                        item['original_service'],
                        item.get('original_config_path', ''),
                        item['source_key'],
                    )
                except Exception:
                    pass

        if spec.get('adopted_only') is True and not (spec.get('adopted_nodes') or []):
            has_current = bool(getattr(singbox_engine, 'pointer', lambda _k: None)('current'))
            if has_current:
                rem_payload = {**job['payload'], 'spec_hash': spec_hash({})}
                remove_job = {
                    **job,
                    'type': 'landing.remove',
                    'payload': rem_payload,
                    'deployment': {},
                    'deployment_revision': revision(job['id'], 'landing.remove', rem_payload),
                }
                singbox_result = singbox_engine.apply(remove_job, guard)
            else:
                singbox_result = {'status': 'success', 'output': singbox_engine.status(), 'error': None}
            for sk in spec.get('returned_adoptions') or []:
                try:
                    return_host_service(sk)
                except Exception:
                    pass
            self._sync_nft_user_counters([])
            return singbox_result

        overrides, staged_primary, deferred_primary = self._prepare_node_tls_and_caddy(
            spec, 'landing', caddy_job_id, guard
        )
        staged_sites = [staged_primary] if staged_primary else []
        deferred_list = [deferred_primary] if deferred_primary else []
        active_site_ids = {'landing'} if (staged_primary or deferred_primary) else set()

        extra_nodes = spec.get('extra_nodes') or []
        if extra_nodes:
            # Guests reuse the host listener of the same (protocol, port): no certificate,
            # no Caddy site, no extra port. Only the host prepares TLS once.
            guests = shared_listener_guests(spec)
            extra_overrides = {}
            for idx, extra in enumerate(extra_nodes, 1):
                nid = str(extra.get('node_id') or idx)
                if nid in guests:
                    continue
                node_site_id = f'node-{nid}'
                node_job_id = self._derived_caddy_job_id(f"{job['id']}:{node_site_id}")
                ov, staged_extra, deferred_extra = self._prepare_node_tls_and_caddy(
                    extra, node_site_id, node_job_id, guard
                )
                if ov:
                    extra_overrides[nid] = ov
                if staged_extra:
                    staged_sites.append(staged_extra)
                if deferred_extra:
                    deferred_list.append(deferred_extra)
                if staged_extra or deferred_extra:
                    active_site_ids.add(node_site_id)
            if extra_overrides:
                overrides['extra_overrides'] = extra_overrides

        try:
            if overrides:
                singbox_result = singbox_engine.apply(job, guard, render_overrides=overrides)
            else:
                singbox_result = singbox_engine.apply(job, guard)
        except Exception:
            if staged_sites and (SERVICE_CADDY in self.engines or self._caddy_manager is not None):
                caddy_manager = self._get_caddy_manager()
                for sid in staged_sites:
                    caddy_manager.remove_site(
                        sid,
                        job_id=self._derived_caddy_job_id(caddy_job_id + ':rb:' + sid),
                        guard=lambda: None,
                    )
            raise

        if deferred_list and (SERVICE_CADDY in self.engines or self._caddy_manager is not None):
            caddy_manager = self._get_caddy_manager()
            for def_job_id, caddyfile, sites in deferred_list:
                caddy_manager.apply_caddyfile(def_job_id, caddyfile, guard=guard)
                caddy_manager.save_sites(sites)

        self._prune_landing_sites(active_site_ids, caddy_job_id, guard)
        self._sync_nft_user_counters(collect_spec_user_marks(spec))

        for sk in spec.get('returned_adoptions') or []:
            try:
                return_host_service(sk)
            except Exception:
                pass
        return singbox_result

    def _resolve_gost_metrics_addr(self, gost_engine, deployment):
        explicit = str((deployment or {}).get('metrics_addr') or '').strip()
        if explicit:
            return explicit
        prospective = render_gost_config(deployment)
        used = collect_active_bindings(self.service_roots, exclude_service=SERVICE_GOST)
        used.extend(extract_config_bindings(SERVICE_GOST, prospective))
        current_rel = gost_engine.pointer('current')
        if current_rel:
            cfg_path = gost_engine.root / current_rel / GOST_PROFILE.config_filename
            if cfg_path.is_file():
                try:
                    existing = json.loads(cfg_path.read_text(encoding='utf-8'))
                    existing_addr = str(((existing.get('metrics') or {}).get('addr')) or '').strip()
                    host, port = _parse_addr_host_port(existing_addr)
                    if port is not None and host in ('127.0.0.1', '::1'):
                        candidate_binding = PortBinding(SERVICE_GOST, 'tcp', host, port)
                        if not any(bindings_conflict(candidate_binding, b) for b in used):
                            return existing_addr
                except (OSError, ValueError):
                    pass
        port = allocate_loopback_port(used, start=18000, end=28000, host='127.0.0.1', transport='tcp', probe_host=False)
        return f'127.0.0.1:{port}'

    def _write_gost_metrics_meta(self, gost_engine, metrics_addr, epoch):
        meta_path = gost_engine.root / 'metrics.json'
        if not metrics_addr:
            meta_path.unlink(missing_ok=True)
            return
        write_json(meta_path, {'metrics_addr': metrics_addr, 'epoch': epoch}, mode=0o644)

    def _apply_gost_job(self, job, guard):
        gost_engine = self.engines[SERVICE_GOST]
        if job['type'] == 'gost.remove':
            result = gost_engine.apply(job, guard)
            self._write_gost_metrics_meta(gost_engine, '', '')
            return result
        has_items = any(job['deployment'].get(k) for k in ('forwards', 'chains', 'relay_services', 'best_exit_groups'))
        if not has_items:
            result = gost_engine.apply(job, guard)
            self._write_gost_metrics_meta(gost_engine, '', '')
            return result
        metrics_addr = self._resolve_gost_metrics_addr(gost_engine, job['deployment'])
        result = gost_engine.apply(job, guard, render_overrides={'metrics_addr': metrics_addr})
        self._write_gost_metrics_meta(gost_engine, metrics_addr, job['id'][:12])
        return result

    def apply(self, job, guard=lambda: None):
        validate_runtime_job(job)
        if job['type'] in ('landing.apply', 'landing.remove'):
            if SERVICE_SINGBOX not in self.engines:
                raise ValueError('Managed runtime service is not enabled')
            return self._apply_landing_job(job, guard)
        if job['type'] in GOST_CONFIG_ACTIONS:
            if SERVICE_GOST not in self.engines:
                raise ValueError('Managed runtime service is not enabled')
            return self._apply_gost_job(job, guard)
        service = job_service(job['type'])
        if service not in self.engines:
            raise ValueError('Managed runtime service is not enabled')
        return self.engines[service].apply(job, guard)

    def allocate_port(self, *, start=18000, end=28000, host='127.0.0.1', transport='tcp', probe_host=True):
        used = collect_active_bindings(self.service_roots)
        return allocate_loopback_port(used, start=start, end=end, host=host,
                                      transport=transport, probe_host=probe_host)
