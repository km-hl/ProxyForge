"""公网验收 VM 内的 TTY/身份探针；只能在驱动创建并标记的临时 VM 使用。"""
import hashlib
import json
import os
from pathlib import Path
import pty
import pwd
import select
import signal
import stat
import subprocess
import sys
import termios
import time

CONFIG = Path('/etc/proxyforge-agent/config.json')


def command_pty(command, token=None):
    pid, fd = pty.fork()
    if pid == 0:
        os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-c', command],
                  {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'})
    output, sent, status = bytearray(), False, None
    deadline = time.monotonic() + 180
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    block = os.read(fd, 65536)
                except OSError:
                    break
                if not block:
                    break
                output.extend(block)
                if len(output) > 1024 * 1024:
                    raise ValueError('output_limit')
            if b'One-time registration token (hidden): ' in output and not sent:
                if token is None or termios.tcgetattr(fd)[3] & termios.ECHO:
                    raise ValueError('unsafe_prompt')
                os.write(fd, token.encode() + b'\n')
                sent = True
            child, result = os.waitpid(pid, os.WNOHANG)
            if child:
                status = result
                break
        while status is None and time.monotonic() < deadline:
            child, result = os.waitpid(pid, os.WNOHANG)
            if child:
                status = result
            else:
                time.sleep(0.05)
        if status is None:
            raise TimeoutError('installer_timeout')
        if token is not None and token.encode() in output:
            raise ValueError('credential_output')
        return os.waitstatus_to_exitcode(status), bytes(output), sent
    finally:
        if status is None:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(fd)


def probe(server, output=b'', extra_secret=None):
    saved = json.loads(CONFIG.read_text())
    info = CONFIG.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != pwd.getpwnam('proxyforge-agent').pw_uid
            or saved['controller'] != server or saved['allow_insecure'] or saved['ca_file'] is not None):
        raise ValueError('identity_boundary')
    logs = subprocess.check_output(['journalctl', '-u', 'proxyforge-agent', '-u', 'proxyforge-runtime',
                                    '-u', 'proxyforge-singbox', '--no-pager'], timeout=15)
    for secret in (saved['token'].encode(), extra_secret.encode() if extra_secret else b''):
        if not secret:
            continue
        if secret in output or secret in logs:
            raise ValueError('credential_logs')
        for path in Path('/proc').glob('[0-9]*/cmdline'):
            try:
                if secret in path.read_bytes():
                    raise ValueError('credential_argv')
            except (FileNotFoundError, ProcessLookupError):
                pass
        for path in (Path('/root/.bash_history'), Path('/home/ci/.bash_history')):
            if path.exists() and secret in path.read_bytes():
                raise ValueError('credential_history')
    return {'agent_id': saved['agent_id'], 'instance_id': saved['instance_id'],
            'identity_sha256': hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
            'python': sys.version.split()[0], 'privacy': True}


def main():
    data = json.load(sys.stdin)
    if os.geteuid() != 0 or Path('/etc/proxyforge-vm-ci').read_text() != data['identity']:
        raise ValueError('unowned_vm')
    action = data['action']
    if action in ('install', 'helper'):
        before = CONFIG.read_bytes() if CONFIG.exists() else None
        if action == 'install' and before is not None:
            raise ValueError('existing_installation')
        if action == 'helper' and before is None:
            raise ValueError('missing_identity')
        status, output, sent = command_pty(data['command'], data.get('token'))
        if status != 0 or sent != (action == 'install'):
            raise ValueError('command_failed')
        result = probe(data['server'], output, data.get('token'))
        subprocess.run(['systemctl', 'is-active', '--quiet', 'proxyforge-agent'], check=True, timeout=10)
        if action == 'helper':
            if before != CONFIG.read_bytes():
                raise ValueError('identity_changed')
            subprocess.run(['systemctl', 'is-active', '--quiet', 'proxyforge-runtime.socket'], check=True, timeout=10)
        else:
            if any(os.path.lexists(path) for path in (
                    '/var/lib/proxyforge-runtime', '/run/proxyforge-runtime.sock',
                    '/etc/systemd/system/proxyforge-runtime.service', '/etc/systemd/system/proxyforge-runtime.socket')):
                raise ValueError('implicit_helper')
            status, repeat, sent = command_pty(data['command'])
            if status == 0 or sent:
                raise ValueError('repeat_installation')
            if result['identity_sha256'] != hashlib.sha256(CONFIG.read_bytes()).hexdigest():
                raise ValueError('repeat_identity_changed')
            probe(data['server'], repeat)
    elif action == 'probe':
        result = probe(data['server'])
        current = Path('/var/lib/proxyforge-runtime/current')
        if current.exists():
            if json.loads((current / 'config.json').read_text())['inbounds'] != []:
                raise ValueError('unexpected_inbound')
            pid = subprocess.check_output(['systemctl', 'show', '--property=MainPID', '--value',
                                           'proxyforge-singbox.service'], text=True, timeout=10).strip()
            if (pwd.getpwnam('proxyforge-singbox').pw_uid == 0
                    or Path('/proc/' + pid).stat().st_uid != pwd.getpwnam('proxyforge-singbox').pw_uid):
                raise ValueError('runtime_uid')
    elif action == 'revoked':
        result = probe(data['server'])
        status = subprocess.check_output(['systemctl', 'show', '--property=ExecMainStatus', '--value',
                                          'proxyforge-agent'], text=True, timeout=10).strip()
        result['revoked_exit'] = status == '4'
    else:
        raise ValueError('unsupported_probe')
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Fixed stage names only, never raw subprocess output or credentials.
        allowed = {'output_limit', 'unsafe_prompt', 'installer_timeout', 'credential_output',
                   'identity_boundary', 'credential_logs', 'credential_argv', 'credential_history',
                   'unowned_vm', 'existing_installation', 'missing_identity', 'command_failed',
                   'identity_changed', 'implicit_helper', 'repeat_installation', 'repeat_identity_changed',
                   'unexpected_inbound', 'runtime_uid', 'unsupported_probe'}
        print(json.dumps({'error': str(exc) if str(exc) in allowed else type(exc).__name__}))
        raise SystemExit(1)
