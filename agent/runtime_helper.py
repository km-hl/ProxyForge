"""Socket-activated local helper. No network listener or caller-selected paths."""
import json
import os
from pathlib import Path
import platform
import socket
import struct
import time

from .runtime_download import (
    download_binary,
    download_caddy_binary,
    download_gost_binary,
    read_configured_mirror,
)
from .runtime_engine import (
    RUNTIME_PROFILES,
    RollbackFailed,
    RuntimeCancelled,
    RuntimeCoordinator,
    RuntimeEngine,
    SystemBackend,
)
from .runtime_spec import CONFIG_ACTIONS, RUNTIME_ERRORS, SERVICE_CADDY, SERVICE_GOST, SERVICE_SINGBOX, validate_runtime_job
from .system_info import os_release, SUPPORTED


def _classify_runtime_error(exc):
    """Map runtime exceptions to strictly allowlisted, secret-free error codes."""
    msg = str(exc or '').lower()
    exc_name = type(exc).__name__
    if 'certbot is required' in msg:
        code = 'acme_certbot_missing'
    elif 'missing certbot plugin' in msg:
        code = 'acme_dns_plugin_missing'
    elif ':80/tcp is already in use' in msg:
        code = 'acme_port80_in_use'
    elif 'do not match host public ip' in msg or 'failed to resolve acme domain' in msg:
        code = 'acme_dns_mismatch'
    elif exc_name == 'AcmeError' or 'certificate' in msg or 'acme' in msg or 'renewal' in msg:
        code = 'acme_failed'
    elif exc_name == 'CaddyError':
        code = 'caddy_failed'
    elif 'port conflict' in msg or 'conflicts with' in msg or 'already in use' in msg:
        code = 'port_conflict'
    elif 'runtime configuration check failed' in msg or 'runtime version check failed' in msg:
        code = 'config_check_failed'
    elif 'runtime failed health verification' in msg or 'runtime lost health' in msg:
        code = 'health_check_failed'
    elif exc_name in ('URLError', 'HTTPError') or 'checksum' in msg or 'sha256' in msg or 'download' in msg:
        code = 'download_failed'
    else:
        code = 'runtime_failed'
    return code if code in RUNTIME_ERRORS else 'runtime_failed'

ROOT = Path('/var/lib/proxyforge-runtime')
SOCKET = '/run/proxyforge-runtime.sock'


def trusted_directory(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or not item.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Runtime requires root-owned directories')


def receive_job(connection):
    data = b''
    connection.settimeout(5)
    while not data.endswith(b'\n'):
        block = connection.recv(1572865 - len(data))
        if not block or len(data) + len(block) > 1572864:
            raise ValueError('Invalid runtime request')
        data += block
    job = json.loads(data)
    if isinstance(job, dict) and set(job) == {'type'} and job.get('type') in ('adopt.scan_privileged', 'nft.read_user_counters'):
        return job
    if isinstance(job, dict) and set(job) == {'type', 'sha256', 'bundle_b64'} and job.get('type') == 'agent.self_upgrade':
        return job
    expected = {'id', 'type', 'payload', 'deployment_revision'}
    if isinstance(job, dict) and job.get('type') in CONFIG_ACTIONS:
        expected.add('deployment')
    if not isinstance(job, dict) or set(job) != expected:
        raise ValueError('Invalid runtime request')
    validate_runtime_job(job)
    return job


DEFAULT_DOWNLOADERS = {
    SERVICE_SINGBOX: download_binary,
    SERVICE_CADDY: download_caddy_binary,
    SERVICE_GOST: download_gost_binary,
}

SERVICE_SUBDIRS = {
    SERVICE_CADDY: 'caddy',
    SERVICE_GOST: 'gost',
}


def build_coordinator(root, arch, *, backend_factory=SystemBackend, downloaders=None,
                      services=(SERVICE_SINGBOX,), mirror_prefix=None):
    """Build a multi-service RuntimeCoordinator rooted at `root`."""
    root = Path(root)
    custom = downloaders or {}
    engines = {}
    for service in services:
        profile = RUNTIME_PROFILES[service]
        # Keep sing-box directly under `root` for backward compatibility with
        # existing systemd units and /opt/proxyforge-agent/bin/sing-box.
        # Map go-gost -> services/gost to match install-runtime.sh, units, and collector paths.
        service_root = root if service == SERVICE_SINGBOX else (root / 'services' / SERVICE_SUBDIRS.get(service, service))
        service_root.mkdir(parents=True, exist_ok=True)
        backend = backend_factory(profile) if callable(backend_factory) else backend_factory
        kwargs = {'profile': profile}
        if service in custom:
            kwargs['downloader'] = custom[service]
        elif service in DEFAULT_DOWNLOADERS:
            base_dl = DEFAULT_DOWNLOADERS[service]
            def _wrapped(directory, target_arch, guard=lambda: None, _fn=base_dl, _root=root, _mp=mirror_prefix):
                effective = _mp if _mp is not None else read_configured_mirror(_root)
                return _fn(directory, target_arch, guard, mirror_prefix=effective)
            kwargs['downloader'] = _wrapped
        engines[service] = RuntimeEngine(service_root, backend, arch, **kwargs)
    return RuntimeCoordinator(engines)


def _probe_and_record_nft_capable(root=ROOT):
    """Probe nftables permission once as root and persist a 0644 marker for Agent heartbeats."""
    import shutil
    import subprocess
    nft = shutil.which('nft') or '/usr/sbin/nft'
    capable = False
    if Path(nft).is_file():
        try:
            proc = subprocess.run([nft, 'list', 'tables'], capture_output=True, text=True, timeout=5)
            capable = proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            capable = False
    try:
        marker = Path(root) / 'nft-capable'
        marker.write_text('1\n' if capable else '0\n', encoding='utf-8')
        if os.name == 'posix':
            os.chmod(marker, 0o644)
    except OSError:
        pass
    return capable


def serve_connection(connection, engine, agent_uid):
    restart_after_reply = False
    try:
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != agent_uid:
            raise ValueError('Unauthorized local peer')
        job = receive_job(connection)
        if job.get('type') == 'adopt.scan_privileged':
            from .adoption import last_extracted_credentials, scan_host
            scan_out = scan_host(privileged=False)
            result = {
                'status': 'success',
                'output': scan_out,
                'credentials': last_extracted_credentials(),
                'error': None,
            }
        elif job.get('type') == 'nft.read_user_counters':
            from .nft_users import NftUserCounters
            state_root = (getattr(engine, 'service_roots', None) or {}).get(SERVICE_SINGBOX) or getattr(engine, 'root', None) or ROOT
            result = {
                'status': 'success',
                'output': NftUserCounters(state_root).read(),
                'error': None,
            }
        elif job.get('type') == 'agent.self_upgrade':
            import base64
            from .self_upgrade import apply_bundle
            raw = base64.b64decode(job['bundle_b64'], validate=True)
            out = apply_bundle(raw, job['sha256'])
            restart_after_reply = True
            result = {
                'status': 'success',
                'output': out,
                'error': None,
            }
        else:
            deadline = time.monotonic() + 600
            def guard():
                if time.monotonic() >= deadline:
                    raise RuntimeCancelled()
                try:
                    connection.setblocking(False)
                    if connection.recv(1, socket.MSG_PEEK) == b'':
                        raise RuntimeCancelled()
                    raise ValueError('Unexpected request data')
                except BlockingIOError:
                    pass
                finally:
                    connection.settimeout(5)
            result = engine.apply(job, guard)
    except RuntimeCancelled:
        result = {'status': 'failed', 'output': None, 'error': 'runtime_cancelled'}
    except RollbackFailed:
        result = {'status': 'failed', 'output': None, 'error': 'rollback_failed'}
    except Exception as exc:
        # Never send downloader URLs, subprocess output, paths or config contents.
        result = {'status': 'failed', 'output': None, 'error': _classify_runtime_error(exc)}
    try:
        connection.sendall(json.dumps(result).encode() + b'\n')
    except OSError:
        pass
    return restart_after_reply


def main():
    import fcntl
    import pwd
    if os.geteuid() != 0 or os_release() not in SUPPORTED:
        raise SystemExit('Unsupported runtime host')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch or os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
        raise SystemExit('Runtime helper requires systemd socket activation')
    trusted_directory(ROOT)
    _probe_and_record_nft_capable(ROOT)
    services = [SERVICE_SINGBOX]
    for optional_service in (SERVICE_CADDY, SERVICE_GOST):
        try:
            pwd.getpwnam(RUNTIME_PROFILES[optional_service].account)
            services.append(optional_service)
        except KeyError:
            pass
    coordinator = build_coordinator(ROOT, arch, services=tuple(services))
    agent_uid = pwd.getpwnam('proxyforge-agent').pw_uid
    with (ROOT / 'helper.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        coordinator.recover()
        with socket.socket(fileno=3) as listener:
            if listener.family != socket.AF_UNIX or listener.getsockname() != SOCKET:
                raise SystemExit('Unexpected runtime socket')
            while True:
                connection, _ = listener.accept()
                with connection:
                    should_restart = serve_connection(connection, coordinator, agent_uid)
                if should_restart:
                    from .self_upgrade import schedule_agent_restart
                    schedule_agent_restart()
                    break
