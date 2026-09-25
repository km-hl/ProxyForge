"""Unprivileged Agent access to the fixed local helper with lease-loss fencing."""
import json
import os
import socket
import stat
import time

from .runtime_engine import RuntimeCancelled
from .runtime_spec import RUNTIME_ERRORS, valid_output

SOCKET = '/run/proxyforge-runtime.sock'


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
        connection.sendall(json.dumps({key: job[key] for key in ('id', 'type', 'payload', 'deployment_revision')}).encode() + b'\n')
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
