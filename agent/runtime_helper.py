"""Socket-activated local helper. No network listener or caller-selected paths."""
import json
import os
from pathlib import Path
import platform
import socket
import struct
import time

from .runtime_download import download_binary, download_caddy_binary
from .runtime_engine import (
    RUNTIME_PROFILES,
    RollbackFailed,
    RuntimeCancelled,
    RuntimeCoordinator,
    RuntimeEngine,
    SystemBackend,
)
from .runtime_spec import CONFIG_ACTIONS, SERVICE_CADDY, SERVICE_SINGBOX, validate_runtime_job
from .system_info import os_release, SUPPORTED

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
        block = connection.recv(8193 - len(data))
        if not block or len(data) + len(block) > 8192:
            raise ValueError('Invalid runtime request')
        data += block
    job = json.loads(data)
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
}


def build_coordinator(root, arch, *, backend_factory=SystemBackend, downloaders=None,
                      services=(SERVICE_SINGBOX,)):
    """Build a multi-service RuntimeCoordinator rooted at `root`."""
    root = Path(root)
    merged_downloaders = {**DEFAULT_DOWNLOADERS, **(downloaders or {})}
    engines = {}
    for service in services:
        profile = RUNTIME_PROFILES[service]
        # Keep sing-box directly under `root` for backward compatibility with
        # existing systemd units and /opt/proxyforge-agent/bin/sing-box.
        service_root = root if service == SERVICE_SINGBOX else (root / 'services' / service)
        service_root.mkdir(parents=True, exist_ok=True)
        backend = backend_factory(profile) if callable(backend_factory) else backend_factory
        kwargs = {'profile': profile}
        if service in merged_downloaders:
            kwargs['downloader'] = merged_downloaders[service]
        engines[service] = RuntimeEngine(service_root, backend, arch, **kwargs)
    return RuntimeCoordinator(engines)


def serve_connection(connection, engine, agent_uid):
    try:
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != agent_uid:
            raise ValueError('Unauthorized local peer')
        job = receive_job(connection)
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
    except Exception:
        # Never send downloader URLs, subprocess output, paths or config contents.
        result = {'status': 'failed', 'output': None, 'error': 'runtime_failed'}
    try:
        connection.sendall(json.dumps(result).encode() + b'\n')
    except OSError:
        pass


def main():
    import fcntl
    import pwd
    if os.geteuid() != 0 or os_release() not in SUPPORTED:
        raise SystemExit('Unsupported runtime host')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch or os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
        raise SystemExit('Runtime helper requires systemd socket activation')
    trusted_directory(ROOT)
    services = [SERVICE_SINGBOX]
    try:
        pwd.getpwnam(RUNTIME_PROFILES[SERVICE_CADDY].account)
        services.append(SERVICE_CADDY)
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
                    serve_connection(connection, coordinator, agent_uid)
