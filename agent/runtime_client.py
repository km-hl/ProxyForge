"""Unprivileged Agent access to the fixed local helper with lease-loss fencing."""
import json
import os
import socket
import stat
import time
from pathlib import Path

from .runtime_engine import RuntimeCancelled
from .runtime_spec import RUNTIME_ERRORS, CONFIG_ACTIONS, valid_output

SOCKET = '/run/proxyforge-runtime.sock'


def deployment_available():
    return capability_available('deployment-protocol')


def landing_available():
    return capability_available('landing-protocol')


def chain_available():
    return capability_available('chain-protocol')


def gost_available():
    return capability_available('gost-protocol')


def self_upgrade_available():
    return capability_available('self-upgrade-protocol')


def capability_available(name):
    marker = Path('/opt/proxyforge-agent') / name
    try:
        info = marker.lstat()
        return (available() and stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022 and marker.read_text().strip() == '1')
    except OSError:
        return False


def available():
    if os.name != 'posix':
        return False
    try:
        info = os.lstat(SOCKET)
        return stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
    except OSError:
        return False


def execute(job, guard):
    if not available():
        return {'status': 'failed', 'output': None, 'error': 'runtime_unavailable'}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(SOCKET)
        # The socket file and server peer must both belong to root.
        import struct
        if struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] != 0:
            raise ValueError('Invalid runtime helper peer')
        request = {key: job[key] for key in ('id', 'type', 'payload', 'deployment_revision')}
        if job['type'] in CONFIG_ACTIONS:
            request['deployment'] = job['deployment']
        connection.sendall(json.dumps(request).encode() + b'\n')
        connection.settimeout(0.5)
        deadline, data = time.monotonic() + 620, b''
        while not data.endswith(b'\n'):
            guard()
            if time.monotonic() >= deadline:
                raise RuntimeCancelled()
            try:
                block = connection.recv(8193 - len(data))
            except socket.timeout:
                continue
            if not block or len(data) + len(block) > 8192:
                raise ValueError('Invalid runtime helper response')
            data += block
        result = json.loads(data)
        if not isinstance(result, dict) or set(result) != {'status', 'output', 'error'}:
            raise ValueError('Invalid runtime helper result')
        if result['status'] == 'success' and result['error'] is None and valid_output(result['output']):
            return result
        if result['status'] == 'failed' and result['output'] is None and result['error'] in RUNTIME_ERRORS:
            return result
        raise ValueError('Invalid runtime helper result')


def scan_host_privileged():
    """Request a privileged adoption scan and credential extraction from the root helper."""
    if not available():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(SOCKET)
            import struct
            if struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] != 0:
                return None
            connection.sendall(json.dumps({'type': 'adopt.scan_privileged'}).encode() + b'\n')
            connection.settimeout(15)
            data = b''
            while not data.endswith(b'\n'):
                block = connection.recv(65537 - len(data))
                if not block or len(data) + len(block) > 65536:
                    return None
                data += block
            result = json.loads(data)
            if isinstance(result, dict) and result.get('status') == 'success' and isinstance(result.get('output'), dict):
                return result
    except (OSError, ValueError):
        return None
    return None


def read_nft_user_counters():
    """Read per-user nftables byte counters via the privileged local runtime helper."""
    if not available():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(SOCKET)
            import struct
            if struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] != 0:
                return None
            connection.sendall(json.dumps({'type': 'nft.read_user_counters'}).encode('utf-8') + b'\n')
            connection.settimeout(10)
            data = b''
            while not data.endswith(b'\n'):
                block = connection.recv(131073 - len(data))
                if not block or len(data) + len(block) > 131072:
                    return None
                data += block
            result = json.loads(data)
            if isinstance(result, dict) and result.get('status') == 'success' and isinstance(result.get('output'), dict):
                return result['output']
    except (OSError, ValueError):
        return None
    return None


def request_self_upgrade(bundle_bytes, expected_sha256):
    """Send a SHA256-pinned Agent bundle to the root helper for atomic self-upgrade."""
    if not self_upgrade_available():
        return {'status': 'failed', 'output': None, 'error': 'runtime_unavailable'}
    import base64
    import struct
    payload = {
        'type': 'agent.self_upgrade',
        'sha256': str(expected_sha256 or '').strip().lower(),
        'bundle_b64': base64.b64encode(bundle_bytes).decode('ascii'),
    }
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(SOCKET)
            if struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] != 0:
                raise ValueError('Invalid runtime helper peer')
            connection.sendall(json.dumps(payload).encode('utf-8') + b'\n')
            connection.settimeout(60)
            data = b''
            while not data.endswith(b'\n'):
                block = connection.recv(16385 - len(data))
                if not block or len(data) + len(block) > 16384:
                    raise ValueError('Invalid runtime helper response')
                data += block
            result = json.loads(data)
            if isinstance(result, dict) and result.get('status') in ('success', 'failed'):
                return result
    except (OSError, ValueError):
        return {'status': 'failed', 'output': None, 'error': 'runtime_failed'}
    return {'status': 'failed', 'output': None, 'error': 'runtime_failed'}
