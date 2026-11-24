"""Verified silent self-upgrade for ProxyForge Agent & Runtime Helper (pure stdlib)."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tarfile
import time

MAX_BUNDLE_BYTES = 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024
COOLDOWN_SECONDS = 600

INSTALL_ROOT = Path('/opt/proxyforge-agent')
SYSTEMD_DIR = Path('/etc/systemd/system')
BUNDLE_SHA_FILE = INSTALL_ROOT / 'bundle-sha256'
SELF_UPGRADE_MARKER = INSTALL_ROOT / 'self-upgrade-protocol'

_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
_SAFE_MEMBER_RE = re.compile(
    r'^(?:[A-Za-z0-9_.-]+\.(?:py|json|sh|service|socket|md)|LICENSE)$'
)
REQUIRED_CORE_FILES = frozenset((
    '__init__.py',
    'main.py',
    'client.py',
    'system_info.py',
    'runtime_helper.py',
    'self_upgrade.py',
))
SYSTEMD_UNITS = (
    'proxyforge-agent.service',
    'proxyforge-runtime.socket',
    'proxyforge-runtime.service',
    'proxyforge-singbox.service',
    'proxyforge-caddy.service',
    'proxyforge-gost.service',
)
MANAGED_DATAPLANE_UNITS = (
    'proxyforge-singbox.service',
    'proxyforge-caddy.service',
    'proxyforge-gost.service',
)
_LF_SUFFIXES = ('.sh', '.service', '.socket')


def valid_sha256(value):
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def read_installed_bundle_sha256(path=BUNDLE_SHA_FILE):
    try:
        text = Path(path).read_text(encoding='utf-8').strip().lower()
        return text if valid_sha256(text) else ''
    except OSError:
        return ''


def _atomic_write_file(target, data, mode, *, chown_root=True):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f'.{target.name}.{secrets.token_hex(6)}')
    try:
        fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if os.name == 'posix':
            os.chmod(tmp, mode)
            if chown_root and os.geteuid() == 0:
                os.chown(tmp, 0, 0)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def verify_and_extract_bundle(bundle_bytes, expected_sha256):
    """Verify bundle SHA256 and extract strictly allowlisted flat agent/ members."""
    if not valid_sha256(expected_sha256):
        raise ValueError('Invalid expected bundle SHA256')
    if not isinstance(bundle_bytes, (bytes, bytearray)) or not bundle_bytes:
        raise ValueError('Empty bundle payload')
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        raise ValueError('Bundle exceeds maximum allowed size')
    actual = hashlib.sha256(bundle_bytes).hexdigest()
    if actual != expected_sha256:
        raise ValueError('Bundle SHA256 verification failed')

    extracted = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode='r:gz') as archive:
            members = archive.getmembers()
            if len(members) > 128:
                raise ValueError('Too many members in bundle')
            for member in members:
                if not member.isfile() or member.issym() or member.islnk():
                    raise ValueError('Unsupported non-file entry in bundle')
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise ValueError('Bundle member exceeds size limit')
                name = member.name.lstrip('./') if member.name.startswith('./') else member.name
                if '..' in name.split('/') or name.startswith('/'):
                    raise ValueError('Path traversal rejected in bundle')
                if name == 'LICENSE':
                    continue
                if not name.startswith('agent/'):
                    raise ValueError('Unexpected path outside agent/ in bundle')
                rel = name[len('agent/'):]
                if '/' in rel or not _SAFE_MEMBER_RE.fullmatch(rel):
                    raise ValueError('Disallowed agent bundle filename')
                fh = archive.extractfile(member)
                if fh is None:
                    raise ValueError('Unreadable member in bundle')
                raw = fh.read(MAX_MEMBER_BYTES + 1)
                if len(raw) > MAX_MEMBER_BYTES:
                    raise ValueError('Bundle member exceeds size limit')
                if rel.endswith(_LF_SUFFIXES):
                    raw = raw.replace(b'\r\n', b'\n')
                extracted[rel] = raw
    except tarfile.TarError as exc:
        raise ValueError('Invalid tar.gz bundle') from exc

    missing = REQUIRED_CORE_FILES - set(extracted)
    if missing:
        raise ValueError('Incomplete agent bundle')
    return extracted


def _default_systemctl(args):
    exe = shutil.which('systemctl') or '/usr/bin/systemctl'
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=15)


def apply_bundle(
    bundle_bytes,
    expected_sha256,
    *,
    install_root=INSTALL_ROOT,
    systemd_dir=SYSTEMD_DIR,
    systemctl_runner=None,
    chown_root=True,
):
    """Atomically install verified Agent code and refresh changed systemd units."""
    extracted = verify_and_extract_bundle(bundle_bytes, expected_sha256)
    install_root = Path(install_root)
    systemd_dir = Path(systemd_dir)
    agent_dir = install_root / 'agent'
    agent_dir.mkdir(parents=True, exist_ok=True)
    if os.name == 'posix':
        os.chmod(install_root, 0o755)
        os.chmod(agent_dir, 0o755)
        if chown_root and os.geteuid() == 0:
            os.chown(install_root, 0, 0)
            os.chown(agent_dir, 0, 0)

    installed_files = []
    for rel, raw in sorted(extracted.items()):
        if rel in SYSTEMD_UNITS or rel.endswith('.md'):
            continue
        mode = 0o755 if rel.endswith('.sh') else 0o644
        _atomic_write_file(agent_dir / rel, raw, mode, chown_root=chown_root)
        installed_files.append(rel)

    changed_units = []
    for unit in SYSTEMD_UNITS:
        if unit not in extracted:
            continue
        dest = systemd_dir / unit
        if not dest.exists():
            continue
        new_bytes = extracted[unit]
        try:
            old_bytes = dest.read_bytes()
        except OSError:
            old_bytes = None
        if old_bytes != new_bytes:
            _atomic_write_file(dest, new_bytes, 0o644, chown_root=chown_root)
            changed_units.append(unit)

    _atomic_write_file(
        install_root / 'bundle-sha256',
        (expected_sha256 + '\n').encode('ascii'),
        0o644,
        chown_root=chown_root,
    )
    _atomic_write_file(
        install_root / 'self-upgrade-protocol',
        b'1\n',
        0o644,
        chown_root=chown_root,
    )

    run_ctl = systemctl_runner or _default_systemctl
    restarted_dataplane = []
    if changed_units:
        res = run_ctl(['daemon-reload'])
        if getattr(res, 'returncode', 0) != 0:
            raise RuntimeError('systemctl daemon-reload failed')
        for unit in changed_units:
            if unit not in MANAGED_DATAPLANE_UNITS:
                continue
            active = run_ctl(['is-active', '--quiet', unit])
            if getattr(active, 'returncode', 1) == 0:
                restart = run_ctl(['restart', unit])
                if getattr(restart, 'returncode', 0) != 0:
                    raise RuntimeError(f'Failed to restart {unit}')
                restarted_dataplane.append(unit)

    return {
        'upgraded': True,
        'sha256': expected_sha256,
        'installed_count': len(installed_files),
        'changed_units': changed_units,
        'restarted_dataplane': restarted_dataplane,
    }


def schedule_agent_restart(*, systemctl_runner=None):
    """Trigger a non-blocking Agent restart after the helper reply has been flushed."""
    run_ctl = systemctl_runner or _default_systemctl
    try:
        run_ctl(['restart', '--no-block', 'proxyforge-agent.service'])
    except (OSError, subprocess.SubprocessError):
        pass


def _load_cooldown(state_path):
    try:
        data = json.loads(Path(state_path).read_text(encoding='utf-8'))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _save_cooldown(state_path, data):
    try:
        _atomic_write_file(
            state_path,
            json.dumps(data, sort_keys=True).encode('utf-8'),
            0o600,
            chown_root=False,
        )
    except OSError:
        pass


def maybe_auto_upgrade(
    client,
    config,
    config_path,
    heartbeat_result,
    *,
    installed_sha_path=BUNDLE_SHA_FILE,
    capability_check=None,
    executor=None,
    now_fn=time.monotonic,
):
    """Silently self-upgrade when Controller advertises a newer bundle SHA256."""
    if not isinstance(heartbeat_result, dict):
        return False
    latest = str(heartbeat_result.get('latest_bundle_sha256') or '').strip().lower()
    if not valid_sha256(latest):
        return False
    current = read_installed_bundle_sha256(installed_sha_path)
    if current == latest:
        return False

    if capability_check is None:
        from .runtime_client import self_upgrade_available
        capability_check = self_upgrade_available
    if not capability_check():
        return False

    state_path = Path(config_path).with_name('upgrade-state.json')
    now = float(now_fn())
    state = _load_cooldown(state_path)
    if (
        state.get('failed_sha256') == latest
        and isinstance(state.get('failed_at'), (int, float))
        and (now - float(state['failed_at'])) < COOLDOWN_SECONDS
    ):
        return False

    try:
        bundle_bytes = client.get_bytes('/api/agent/package.tar.gz', config.get('token'))
        if hashlib.sha256(bundle_bytes).hexdigest() != latest:
            raise ValueError('Downloaded bundle SHA256 mismatch')
        if executor is None:
            from .runtime_client import request_self_upgrade
            executor = request_self_upgrade
        result = executor(bundle_bytes, latest)
        if not isinstance(result, dict) or result.get('status') != 'success':
            raise RuntimeError('Self-upgrade helper rejected request')
        _save_cooldown(state_path, {'last_upgraded_sha256': latest, 'upgraded_at': now})
        return True
    except Exception:
        _save_cooldown(state_path, {'failed_sha256': latest, 'failed_at': now})
        return False
